// =============================================================================
// STSH Public Solvency Signals — canonical snapshot parsing + fail-closed
// health derivation. PURE module: no network, no @dfinity imports — fully
// unit-testable.
//
// DATA CONTRACT: this parser and the canister's canonical encoding
// (canisters/smoke-alarm-monitor/src/lib.rs, documented in
// canisters/smoke-alarm-monitor/CERTIFIED_SNAPSHOT_ENCODING.md) must change
// together, never separately. The page parses the WITNESS-VERIFIED leaf bytes
// — never a locally reconstructed encoding — so canister and frontend cannot
// silently disagree.
// =============================================================================

export const DOMAIN_TAG = 'stsh-smoke-alarm-v1';
// v2 (D-2 + D-4): the monitor now carries the pool solvency delta and the
// treasury stray-funds figure. Domain tag unchanged (an append under a bumped
// schema is not an incompatible redesign); v1 bytes are rejected on BOTH length
// and schema_version below.
// v3 (R-4 / S-c): one additive flag bit — bit 4 `supply_invariant_unavailable`
// — distinguishes "the token could not COMPUTE the invariant" (an arithmetic
// error at the ledger) from "the invariant is VIOLATED". No new field bytes;
// the length is unchanged; only the schema byte and one flag bit move.
//
// TRANSITION (page-first, see MAINNET_DEPLOYMENT.md
// "## Solvency surface: schema-3 transition (R-4)"): this parser DUAL-ACCEPTS
// schema 2 and schema 3, each under its OWN reserved-bit mask, so the
// dual-accept page can be deployed and confirmed live BEFORE the monitor is
// switched to emit schema 3 — and so a monitor ROLLBACK to v2 is safe without a
// second page redeploy. Schema 4 and above are rejected unconditionally: there
// is no v4 encoding defined, and accepting one would silently parse an unknown
// future layout as v3.
export const SCHEMA_VERSION_V2 = 2;
export const SCHEMA_VERSION_V3 = 3;
/** Back-compat alias — the schema this parser was originally written against. */
export const SCHEMA_VERSION = SCHEMA_VERSION_V2;
export const ACCEPTED_SCHEMA_VERSIONS: readonly number[] = [
  SCHEMA_VERSION_V2,
  SCHEMA_VERSION_V3,
];
export const CANONICAL_LEN = 131;
export const TREE_KEY = 'solvency_snapshot';

export enum SnapshotStatus {
  Fresh = 0,
  Stale = 1,
  RefreshFailed = 2,
  SourceCallFailed = 3,
}

/** v2: per-source read outcome. Anything but Ok is fail-closed at the point of use. */
export enum SourceReadStatus {
  Ok = 0,
  CallFailed = 1,
  Malformed = 2,
  Stale = 3,
}

export interface ParsedSnapshot {
  schemaVersion: number;
  status: SnapshotStatus;
  supplyInvariantHolds: boolean;
  healthy: boolean;
  fixedMaxSupplyE8s: bigint;
  sumAllBalancesE8s: bigint;
  poolBalanceE8s: bigint;
  refreshedAtNs: bigint;
  maxStalenessNs: bigint;
  // ── v2 (D-2): the pool solvency attestation — the RED source ─────────────
  poolAttestationSourceStatus: SourceReadStatus;
  poolDeltaHealthy: boolean;
  /** min(raw_delta, 0): 0 in every healthy state, negative violation magnitude. */
  poolPublicDeltaE8s: bigint;
  poolAttestedAtNs: bigint;
  // ── v2 (D-4): treasury stray funds — YELLOW, never RED ───────────────────
  treasuryReadStatus: SourceReadStatus;
  treasuryStrayFundsE8s: bigint;
  // ── v3 (R-4): the invariant could not be COMPUTED, as distinct from
  //    VIOLATED. Hard-set `false` for a schema-2 snapshot: at that schema the
  //    field does not exist, and "not yet reportable under this schema" is not
  //    the same claim as "unknown".
  supplyInvariantUnavailable: boolean;
}

/**
 * Canonical layout (all integers big-endian, fixed width; total 89 bytes):
 *   [ 0..19]  DOMAIN_TAG "stsh-smoke-alarm-v1"
 *   [19..23]  schema_version u32
 *   [23    ]  status u8
 *   [24    ]  flags u8 (bit0 supply_invariant_holds, bit1 healthy)
 *   [25..41]  fixed_max_supply_e8s u128
 *   [41..57]  sum_all_balances_e8s u128
 *   [57..73]  pool_balance_e8s u128
 *   [73..81]  refreshed_at_ns u64
 *   [81..89]  max_staleness_ns u64
 *   [89]      pool_attestation_source_status u8   (v2)
 *   [90]      treasury_read_status u8             (v2)
 *   [91..107] pool_public_delta_e8s i128          (v2, two's complement, <= 0)
 *   [107..115] pool_attested_at_ns u64            (v2, 300 s bucketed)
 *   [115..131] treasury_stray_funds_e8s u128      (v2)
 *
 * Throws on ANY deviation — a parse failure must surface as red/unknown,
 * never as a permissive default.
 */
export function parseCanonicalSnapshot(bytes: Uint8Array): ParsedSnapshot {
  if (bytes.length !== CANONICAL_LEN) {
    throw new Error(`canonical snapshot must be ${CANONICAL_LEN} bytes, got ${bytes.length}`);
  }
  const tag = new TextDecoder().decode(bytes.subarray(0, 19));
  if (tag !== DOMAIN_TAG) {
    throw new Error(`bad domain tag: ${JSON.stringify(tag)}`);
  }
  const beUint = (start: number, len: number): bigint => {
    let v = 0n;
    for (let i = start; i < start + len; i++) {
      v = (v << 8n) | BigInt(bytes[i]);
    }
    return v;
  };
  const schemaVersion = Number(beUint(19, 4));
  if (!ACCEPTED_SCHEMA_VERSIONS.includes(schemaVersion)) {
    throw new Error(`unsupported schema_version ${schemaVersion}`);
  }
  // VERSION-SPECIFIC RESERVED MASK, checked BEFORE any other field is read for
  // this version. v2 claims bits 0-3, so bits 4-7 are reserved; v3 claims bit 4
  // as well, so only bits 5-7 are. Widening the v2 mask to tolerate bit 4 would
  // silently accept a schema-3 flag byte under a schema-2 header — the exact
  // inconsistent-monitor state the page must refuse.
  const flags = bytes[24];
  const reservedMask =
    schemaVersion === SCHEMA_VERSION_V3 ? ~0b11111 : ~0b1111;
  if ((flags & reservedMask) !== 0) {
    throw new Error(`reserved flag bits set: ${flags}`);
  }
  const status = bytes[23];
  if (status > SnapshotStatus.SourceCallFailed) {
    throw new Error(`unknown status byte ${status}`);
  }
  const beInt = (start: number, len: number): bigint => {
    const u = beUint(start, len);
    const bits = BigInt(len * 8);
    // Two's complement: values at or above 2^(bits-1) are negative.
    return u >= 1n << (bits - 1n) ? u - (1n << bits) : u;
  };
  const readStatus = (b: number): SourceReadStatus => {
    if (b > SourceReadStatus.Stale) throw new Error(`unknown source read status ${b}`);
    return b as SourceReadStatus;
  };
  const poolPublicDeltaE8s = beInt(91, 16);
  if (poolPublicDeltaE8s > 0n) {
    // The clamp guarantees <= 0. A positive value means the bytes are not what
    // this parser's contract describes — fail closed rather than render it.
    throw new Error(`pool delta must never be positive: ${poolPublicDeltaE8s}`);
  }
  return {
    schemaVersion,
    status: status as SnapshotStatus,
    supplyInvariantHolds: (flags & 0b01) !== 0,
    healthy: (flags & 0b10) !== 0,
    fixedMaxSupplyE8s: beUint(25, 16),
    sumAllBalancesE8s: beUint(41, 16),
    poolBalanceE8s: beUint(57, 16),
    refreshedAtNs: beUint(73, 8),
    maxStalenessNs: beUint(81, 8),
    poolAttestationSourceStatus: readStatus(bytes[89]),
    poolDeltaHealthy: (flags & 0b0100) !== 0,
    poolPublicDeltaE8s,
    poolAttestedAtNs: beUint(107, 8),
    treasuryReadStatus: readStatus(bytes[90]),
    treasuryStrayFundsE8s: beUint(115, 16),
    supplyInvariantUnavailable:
      schemaVersion === SCHEMA_VERSION_V3 ? (flags & 0b10000) !== 0 : false,
  };
}

/** THREE-VALUED, deliberately. Yellow is a ROW-level signal, never a badge
 *  state — see `TreasuryDisplay`. Widening this type is out of scope by L08
 *  invariant 3. */
export type HealthLight = 'green' | 'red' | 'unknown';

export type TreasuryKind = 'none' | 'stray' | 'unknown';

/**
 * The YELLOW channel (L08-01), structurally separate from `reasons`/`light`.
 *
 * `light = reasons.length === 0 ? 'green' : …` — so ANYTHING pushed onto
 * `reasons` turns the badge red. Stray funds in the treasury are foreign by
 * definition: excluded from custody accounting, from the solvency delta, and
 * from backing. They must therefore never reach `reasons` and never reach
 * `light`. Giving them their own field is what makes that structural rather
 * than a convention someone can forget.
 */
export interface TreasuryDisplay {
  kind: TreasuryKind;
  /** `null` exactly when the read did not succeed — never a zero standing in
   *  for "we could not tell". */
  amountE8s: bigint | null;
}

export interface DisplayState {
  light: HealthLight;
  /** Human-readable reasons — every non-green state names why. */
  reasons: string[];
  snapshot: ParsedSnapshot | null;
  /** Age of the snapshot relative to the certificate time (ns), if known. */
  ageNs: bigint | null;
  /** YELLOW channel — never feeds `reasons` or `light`. */
  treasury: TreasuryDisplay;
}

/** Unreadable treasury state, used whenever there is no parsed snapshot at all. */
const TREASURY_UNKNOWN: TreasuryDisplay = { kind: 'unknown', amountE8s: null };

export function deriveTreasuryDisplay(snapshot: ParsedSnapshot): TreasuryDisplay {
  if (snapshot.treasuryReadStatus !== SourceReadStatus.Ok) {
    return { kind: 'unknown', amountE8s: null };
  }
  return snapshot.treasuryStrayFundsE8s > 0n
    ? { kind: 'stray', amountE8s: snapshot.treasuryStrayFundsE8s }
    : { kind: 'none', amountE8s: 0n };
}

export interface DeriveInput {
  /** True ONLY if the certificate verified against the root of trust AND the
   *  witness root matched the certified data AND the leaf was found. */
  certificateVerified: boolean;
  /** The witness-verified leaf bytes (NOT the bare Candid snapshot). */
  canonicalBytes: Uint8Array | null;
  /** Subnet-signed time from the verified certificate (ns since epoch). */
  certTimeNs: bigint | null;
}

/**
 * Fail-closed roll-up. green requires EVERY link in the chain:
 * verified certificate → parseable canonical bytes → Fresh status → healthy
 * flag consistent with its definition → not stale relative to the
 * subnet-signed certificate time. Anything else is red/unknown — a stale or
 * unverifiable snapshot must NEVER render green.
 */
export function deriveDisplayState(input: DeriveInput): DisplayState {
  const reasons: string[] = [];
  if (!input.certificateVerified) {
    return {
      light: 'unknown',
      reasons: ['certificate did not verify — data cannot be trusted'],
      snapshot: null,
      ageNs: null,
      treasury: TREASURY_UNKNOWN,
    };
  }
  if (input.canonicalBytes === null || input.certTimeNs === null) {
    return {
      light: 'unknown',
      reasons: ['verified response is incomplete — treating as unverifiable'],
      snapshot: null,
      ageNs: null,
      treasury: TREASURY_UNKNOWN,
    };
  }

  let snapshot: ParsedSnapshot;
  try {
    snapshot = parseCanonicalSnapshot(input.canonicalBytes);
  } catch (e) {
    return {
      light: 'unknown',
      reasons: [`canonical snapshot failed to parse: ${(e as Error).message}`],
      snapshot: null,
      ageNs: null,
      treasury: TREASURY_UNKNOWN,
    };
  }

  const ageNs =
    input.certTimeNs > snapshot.refreshedAtNs ? input.certTimeNs - snapshot.refreshedAtNs : 0n;
  const stale = ageNs > snapshot.maxStalenessNs;

  if (stale) {
    reasons.push('snapshot is stale — the monitor has not refreshed within its staleness bound');
  }
  if (snapshot.status !== SnapshotStatus.Fresh) {
    reasons.push(
      `monitor status is ${SnapshotStatus[snapshot.status]} — last refresh did not succeed`,
    );
  }
  // v3 (R-4): UNAVAILABLE is a DIFFERENT claim from VIOLATED and says so.
  // Both are RED — an invariant that could not be computed is not an invariant
  // that was proven — but a reader must be able to tell "the ledger says the
  // books do not balance" from "the ledger could not add the books up".
  if (snapshot.supplyInvariantUnavailable) {
    reasons.push(
      'token supply invariant could not be computed — arithmetic error at the ledger',
    );
  } else if (!snapshot.supplyInvariantHolds) {
    reasons.push('token supply invariant is NOT proven to hold');
  }
  if (!snapshot.healthy) {
    reasons.push('monitor reports unhealthy');
  }
  // v2 (D-2): the RED source. A read that did not succeed is never treated as
  // "fine" — each non-Ok outcome names itself so the page can say WHY.
  if (snapshot.poolAttestationSourceStatus !== SourceReadStatus.Ok) {
    reasons.push(
      `pool solvency attestation not proven (${SourceReadStatus[snapshot.poolAttestationSourceStatus]})`,
    );
  } else if (!snapshot.poolDeltaHealthy) {
    reasons.push(
      `POOL BACKING BROKEN — shortfall ${formatStsh(-snapshot.poolPublicDeltaE8s)} STSH`,
    );
  }
  // Defence in depth: a healthy flag that contradicts its own definition
  // (healthy ⇒ Fresh AND invariant holds) is treated as red.
  if (snapshot.healthy && (snapshot.status !== SnapshotStatus.Fresh || !snapshot.supplyInvariantHolds)) {
    reasons.push('inconsistent snapshot: healthy flag contradicts status/invariant');
  }

  return {
    light: reasons.length === 0 ? 'green' : stale ? 'unknown' : 'red',
    reasons,
    snapshot,
    ageNs,
    // Derived AFTER `reasons` is final and never appended to it — the yellow
    // channel is structurally incapable of moving the badge.
    treasury: deriveTreasuryDisplay(snapshot),
  };
}

/** LEB128-decode an unsigned integer (used for the certificate /time leaf). */
export function decodeLeb128(bytes: Uint8Array): bigint {
  let result = 0n;
  let shift = 0n;
  for (const byte of bytes) {
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return result;
    shift += 7n;
  }
  throw new Error('LEB128: unterminated encoding');
}

/** Format e8s base units as a decimal STSH string (integer math only). */
export function formatStsh(e8s: bigint): string {
  const whole = e8s / 100_000_000n;
  const frac = e8s % 100_000_000n;
  const wholeStr = whole.toLocaleString('en-US');
  if (frac === 0n) return wholeStr;
  return `${wholeStr}.${frac.toString().padStart(8, '0').replace(/0+$/, '')}`;
}
