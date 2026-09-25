// =============================================================================
// STSH Public Solvency Signals — monitor canister client.
//
// Fetches get_certified_snapshot and runs FULL client-side verification with
// @dfinity/agent's certification primitives (no hand-rolled crypto):
//
//   1. Certificate.create — BLS signature against the root of trust,
//      delegation chain, and certificate freshness (maxAgeInMinutes).
//   2. reconstruct(witness) — recompute the witness root per the IC spec.
//   3. witness root MUST equal /canister/<id>/certified_data.
//   4. The snapshot leaf is taken from the VERIFIED witness, and the
//      subnet-signed /time from the verified certificate.
//
// (@dfinity/certificate-verification composes exactly these steps but is only
// published for @dfinity/agent v1; this repo standardises on agent v2, so the
// composition is done here with the v2 APIs directly.)
//
// LAUNCH GATE (see canisters/smoke-alarm-monitor/OPERATIONS.md): production
// MUST verify against the IC root key (the HttpAgent default) and fail
// closed. fetchRootKey() is for LOCAL DEV ONLY and is gated below.
// =============================================================================

import {
  Actor,
  Cbor,
  Certificate,
  HttpAgent,
  lookup_path,
  LookupStatus,
  reconstruct,
} from '@dfinity/agent';
import type { HashTree } from '@dfinity/agent';
import { IDL } from '@dfinity/candid';
import { Principal } from '@dfinity/principal';
import { decodeLeb128, TREE_KEY } from './verify';

const MAX_CERT_AGE_MINUTES = 5;

// Candid mirror of canisters/smoke-alarm-monitor/smoke_alarm_monitor.did
const SnapshotStatusIdl = IDL.Variant({
  Fresh: IDL.Null,
  Stale: IDL.Null,
  RefreshFailed: IDL.Null,
  SourceCallFailed: IDL.Null,
});
const SolvencySnapshotIdl = IDL.Record({
  supply_invariant_holds: IDL.Bool,
  fixed_max_supply_e8s: IDL.Nat,
  sum_all_balances_e8s: IDL.Nat,
  pool_balance_e8s: IDL.Nat,
  refreshed_at_ns: IDL.Nat64,
  max_staleness_ns: IDL.Nat64,
  status: SnapshotStatusIdl,
  healthy: IDL.Bool,
  schema_version: IDL.Nat32,
});
const CertifiedSolvencySnapshotIdl = IDL.Record({
  snapshot: SolvencySnapshotIdl,
  canonical_bytes: IDL.Vec(IDL.Nat8),
  certificate: IDL.Opt(IDL.Vec(IDL.Nat8)),
  witness: IDL.Vec(IDL.Nat8),
});
const monitorIdl: IDL.InterfaceFactory = ({ IDL }) =>
  IDL.Service({
    get_certified_snapshot: IDL.Func([], [CertifiedSolvencySnapshotIdl], ['query']),
  });

export interface RawCertifiedResponse {
  canonical_bytes: Uint8Array | number[];
  certificate: [] | [Uint8Array | number[]];
  witness: Uint8Array | number[];
}

export interface VerifiedRead {
  certificateVerified: boolean;
  canonicalBytes: Uint8Array | null;
  certTimeNs: bigint | null;
  /** Why verification failed, when it did (for diagnostics display). */
  failureDetail: string | null;
}

function failClosed(detail: string): VerifiedRead {
  return { certificateVerified: false, canonicalBytes: null, certTimeNs: null, failureDetail: detail };
}

function asBytes(v: Uint8Array | number[]): Uint8Array {
  return v instanceof Uint8Array ? v : new Uint8Array(v);
}

function toArrayBuffer(v: Uint8Array): ArrayBuffer {
  return v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength) as ArrayBuffer;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

export interface MonitorConfig {
  monitorCanisterId: string;
  host: string;
  /** Local development against a replica whose root key differs from the IC's.
   *  NEVER enable in production — the IC root of trust is the whole point. */
  devFetchRootKey: boolean;
}

export async function fetchCertifiedSnapshot(cfg: MonitorConfig): Promise<VerifiedRead> {
  const agent = await HttpAgent.create({ host: cfg.host });
  if (cfg.devFetchRootKey) {
    await agent.fetchRootKey();
  }
  const canisterId = Principal.fromText(cfg.monitorCanisterId);
  const actor = Actor.createActor(monitorIdl, { agent, canisterId });

  const raw = (await actor.get_certified_snapshot()) as RawCertifiedResponse;
  if (raw.certificate.length === 0) {
    return failClosed('canister returned no certificate (replicated-context read)');
  }
  const certificateBytes = asBytes(raw.certificate[0]!);
  const witnessBytes = asBytes(raw.witness);

  const rootKey = agent.rootKey;
  if (!rootKey) {
    return failClosed('agent has no root key — cannot verify anything');
  }

  try {
    // (1) BLS signature vs root of trust + delegation chain + freshness.
    const certificate = await Certificate.create({
      certificate: toArrayBuffer(certificateBytes),
      rootKey,
      canisterId,
      maxAgeInMinutes: MAX_CERT_AGE_MINUTES,
    });

    // (2) Reconstruct the witness root per the IC spec.
    const witness = Cbor.decode<HashTree>(toArrayBuffer(witnessBytes));
    const witnessRoot = new Uint8Array(await reconstruct(witness));

    // (3) The subnet must have certified exactly this witness root.
    const certifiedData = certificate.lookup([
      'canister',
      toArrayBuffer(canisterId.toUint8Array()),
      'certified_data',
    ]);
    if (certifiedData.status !== LookupStatus.Found || !(certifiedData.value instanceof ArrayBuffer)) {
      return failClosed('certificate has no certified_data for the monitor canister');
    }
    if (!bytesEqual(witnessRoot, new Uint8Array(certifiedData.value))) {
      return failClosed('witness root does not match the subnet-certified data');
    }

    // (4a) Trusted leaf bytes come from the VERIFIED witness.
    const leaf = lookup_path([toArrayBuffer(new TextEncoder().encode(TREE_KEY))], witness);
    if (leaf.status !== LookupStatus.Found || !(leaf.value instanceof ArrayBuffer)) {
      return failClosed('verified witness does not contain the snapshot leaf');
    }

    // (4b) Subnet-signed time from the verified certificate.
    const timeLeaf = certificate.lookup(['time']);
    if (timeLeaf.status !== LookupStatus.Found || !(timeLeaf.value instanceof ArrayBuffer)) {
      return failClosed('certificate has no /time — treating as unverifiable');
    }
    const certTimeNs = decodeLeb128(new Uint8Array(timeLeaf.value));

    return {
      certificateVerified: true,
      canonicalBytes: new Uint8Array(leaf.value),
      certTimeNs,
      failureDetail: null,
    };
  } catch (e) {
    // ANY verification error fails closed.
    return failClosed(`certificate verification failed: ${(e as Error).message}`);
  }
}
