// =============================================================================
// The canonical-leaf fixture builder, shared by verify.test.ts (the parser and
// derivation rules) and page.test.ts (the live render seam).
//
// It lives in ONE place on purpose: two independently maintained copies of the
// 131-byte layout drift, and a page test built on a drifted copy would stop
// exercising the bytes the monitor actually emits. The layout itself is
// asserted against the real canister in
// integration-tests/tests/smoke_alarm_monitor_tests.rs (test_sam_02/test_sam_10)
// and documented in canisters/smoke-alarm-monitor/CERTIFIED_SNAPSHOT_ENCODING.md.
// =============================================================================

import { CANONICAL_LEN, DOMAIN_TAG, SnapshotStatus } from './verify';

export interface FixtureFields {
  schemaVersion?: number;
  status?: SnapshotStatus;
  supplyInvariantHolds?: boolean;
  healthy?: boolean;
  fixedMaxSupplyE8s?: bigint;
  sumAllBalancesE8s?: bigint;
  poolBalanceE8s?: bigint;
  refreshedAtNs?: bigint;
  maxStalenessNs?: bigint;
  // v2
  poolAttestationSourceStatus?: number;
  poolDeltaHealthy?: boolean;
  poolPublicDeltaE8s?: bigint;
  poolAttestedAtNs?: bigint;
  treasuryReadStatus?: number;
  treasuryStrayFundsE8s?: bigint;
  // v3
  supplyInvariantUnavailable?: boolean;
}

export const E8S_1E17 = 100_000_000_000_000_000n; // 1e9 STSH fixed supply in e8s
export const T0 = 1_700_000_000_000_000_000n;

export function canonical(fields: FixtureFields = {}): Uint8Array {
  const f = {
    schemaVersion: 2,
    status: SnapshotStatus.Fresh,
    supplyInvariantHolds: true,
    healthy: true,
    fixedMaxSupplyE8s: E8S_1E17,
    sumAllBalancesE8s: E8S_1E17,
    poolBalanceE8s: 123_456_789n,
    refreshedAtNs: T0,
    maxStalenessNs: 900_000_000_000n, // 15 min
    // v2 defaults: a fully healthy rig — pool read Ok and solvent, no stray funds.
    poolAttestationSourceStatus: 0,
    poolDeltaHealthy: true,
    poolPublicDeltaE8s: 0n,
    poolAttestedAtNs: 1_699_999_800_000_000_000n, // T0 floored to a 300 s bucket
    treasuryReadStatus: 0,
    treasuryStrayFundsE8s: 0n,
    // v3 default: no arithmetic error. Note the fixture writes bit 4 whatever
    // the schemaVersion says — that is deliberate, so the v2 mask can be shown
    // still rejecting it (M7b, the inconsistent-monitor build).
    supplyInvariantUnavailable: false,
    ...fields,
  };
  const out = new Uint8Array(CANONICAL_LEN);
  out.set(new TextEncoder().encode(DOMAIN_TAG), 0);
  const putBe = (start: number, len: number, value: bigint) => {
    for (let i = len - 1; i >= 0; i--) {
      out[start + i] = Number(value & 0xffn);
      value >>= 8n;
    }
  };
  putBe(19, 4, BigInt(f.schemaVersion));
  out[23] = f.status;
  out[24] =
    (f.supplyInvariantHolds ? 1 : 0) |
    (f.healthy ? 2 : 0) |
    (f.poolDeltaHealthy ? 4 : 0) |
    (f.treasuryStrayFundsE8s > 0n ? 8 : 0) |
    (f.supplyInvariantUnavailable ? 16 : 0);
  putBe(25, 16, f.fixedMaxSupplyE8s);
  putBe(41, 16, f.sumAllBalancesE8s);
  putBe(57, 16, f.poolBalanceE8s);
  putBe(73, 8, f.refreshedAtNs);
  putBe(81, 8, f.maxStalenessNs);
  // ── v2 tail ───────────────────────────────────────────────────────────────
  out[89] = f.poolAttestationSourceStatus;
  out[90] = f.treasuryReadStatus;
  // i128 two's complement, written as the unsigned bit pattern.
  putBe(91, 16, f.poolPublicDeltaE8s < 0n ? (1n << 128n) + f.poolPublicDeltaE8s : f.poolPublicDeltaE8s);
  putBe(107, 8, f.poolAttestedAtNs);
  putBe(115, 16, f.treasuryStrayFundsE8s);
  return out;
}
