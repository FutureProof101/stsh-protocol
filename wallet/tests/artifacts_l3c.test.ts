// @vitest-environment node
/**
 * zk/artifacts.ts tests (L3c / L0-C): the build-bundled manifest contract and
 * the streaming verified loader — fetch-once, byte-cap, exact SHA-256, Blob
 * handed to the worker, revoked in finally (S-16/S-27). The attestation
 * comparison (C-DOM tuple) fails closed on every field it pins.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Principal } from "@dfinity/principal";

import {
  ManifestError,
  assertManifestAttestation,
  assertManifestStructure,
  fetchCapped,
  loadVerifiedArtifact,
  spendManifest,
  withVerifiedProverAssets,
  type DeploymentAttestationView,
} from "../src/zk/artifacts";

const here = dirname(fileURLToPath(import.meta.url));
const WASM_BYTES = readFileSync(resolve(here, "../../circuits/build/spend_js/spend.wasm"));
const ZKEY_BYTES = readFileSync(resolve(here, "../../circuits/build/spend_1.zkey"));

/** Serve the real artifacts from /zk/* (mirrors the Vite staging dir). */
function stubFetch() {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = String(input);
    const bytes = url.endsWith("spend.wasm") ? WASM_BYTES : url.endsWith("spend_1.zkey") ? ZKEY_BYTES : null;
    if (bytes === null) return new Response(null, { status: 404 });
    return new Response(bytes, { status: 200 });
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

const TUPLE = {
  pool: spendManifest.frozenPoolPrincipal,
  token: Principal.fromUint8Array(new Uint8Array(10).fill(0x01)).toText(),
  merkle: Principal.fromUint8Array(new Uint8Array(10).fill(0x02)).toText(),
  nullifier: Principal.fromUint8Array(new Uint8Array(10).fill(0x03)).toText(),
  verifier: Principal.fromUint8Array(new Uint8Array(10).fill(0x04)).toText(),
};

const ATTESTATION_OK: DeploymentAttestationView = {
  pool: spendManifest.frozenPoolPrincipal,
  token: TUPLE.token,
  merkle: TUPLE.merkle,
  nullifier: TUPLE.nullifier,
  verifier: TUPLE.verifier,
  vkHash: spendManifest.vkHash,
  circuitVersion: spendManifest.circuitVersion,
  poolVersion: spendManifest.poolVersion,
  proofSystem: spendManifest.proofSystemId,
};

describe("manifest attestation comparison (complete C-DOM tuple)", () => {
  it("accepts a matching attestation", () => {
    expect(() => assertManifestAttestation(ATTESTATION_OK, TUPLE)).not.toThrow();
  });

  it("rejects a VK hash mismatch", () => {
    expect(() =>
      assertManifestAttestation({ ...ATTESTATION_OK, vkHash: "00".repeat(32) }, TUPLE),
    ).toThrow(ManifestError);
  });

  it("rejects a circuit-version mismatch", () => {
    expect(() =>
      assertManifestAttestation({ ...ATTESTATION_OK, circuitVersion: 99 }, TUPLE),
    ).toThrow(/circuit version/);
  });

  it("rejects a proof-system mismatch (never a bare-JSON substitution)", () => {
    expect(() =>
      assertManifestAttestation({ ...ATTESTATION_OK, proofSystem: "groth16-bls12381" }, TUPLE),
    ).toThrow(/proof system/);
  });

  it("rejects a pool-principal mismatch", () => {
    expect(() =>
      assertManifestAttestation({ ...ATTESTATION_OK, pool: "aaaaa-aa" }, TUPLE),
    ).toThrow(/pool principal/);
  });

  it("rejects a wiring mismatch on EVERY dependency independently (token/merkle/nullifier/verifier)", () => {
    expect(() => assertManifestAttestation({ ...ATTESTATION_OK, token: "aaaaa-aa" }, TUPLE)).toThrow(/token/);
    expect(() => assertManifestAttestation({ ...ATTESTATION_OK, merkle: "aaaaa-aa" }, TUPLE)).toThrow(/merkle/);
    expect(() => assertManifestAttestation({ ...ATTESTATION_OK, nullifier: "aaaaa-aa" }, TUPLE)).toThrow(/nullifier/);
    expect(() => assertManifestAttestation({ ...ATTESTATION_OK, verifier: "aaaaa-aa" }, TUPLE)).toThrow(/verifier/);
  });

  it("an EMPTY tuple field is a manifest error at resolution — never an optional skip", () => {
    for (const key of ["pool", "token", "merkle", "nullifier", "verifier"] as const) {
      expect(() =>
        assertManifestAttestation(ATTESTATION_OK, { ...TUPLE, [key]: "" }),
      ).toThrow(/not fully populated|empty/);
    }
  });

  it("a wrong runtime pool with SAME dependencies fails closed (tuple.pool != frozen)", () => {
    expect(() =>
      assertManifestAttestation(ATTESTATION_OK, { ...TUPLE, pool: "aaaaa-aa" }),
    ).toThrow(/frozen manifest pool/);
  });

  it("a MALFORMED principal in the tuple fails closed at parse time", () => {
    expect(() =>
      assertManifestAttestation(ATTESTATION_OK, { ...TUPLE, verifier: "not-a-principal" }),
    ).toThrow(/not a valid principal/);
  });

  it("the bundled manifest itself passes structural validation (parse-time)", () => {
    expect(() => assertManifestStructure()).not.toThrow();
  });
});

describe("streaming verified loader (S-16/S-27)", () => {
  it("loads BOTH artifacts verified (fetch-once) and revokes the Blob URLs in finally", async () => {
    const fetchSpy = stubFetch();
    const revokeSpy = vi.spyOn(URL, "revokeObjectURL");
    let seen: string[] = [];
    await withVerifiedProverAssets(async (assets) => {
      seen = [assets.wasmUrl, assets.zkeyUrl];
      expect(seen.every((u) => u.startsWith("blob:"))).toBe(true);
      // fetch-once per artifact.
      expect(fetchSpy).toHaveBeenCalledTimes(2);
    });
    expect(revokeSpy).toHaveBeenCalledTimes(2);
    expect(revokeSpy.mock.calls.map((c) => c[0]).sort()).toEqual(seen.sort());
  });

  it("rejects a hash mismatch (tampered bytes never reach the worker)", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(WASM_BYTES, { status: 200 }));
    const pin = spendManifest.artifacts.find((a) => a.id === "spend_1.zkey")!;
    await expect(loadVerifiedArtifact(pin)).rejects.toThrow(/SHA-256|length/);
  });

  it("rejects a stream beyond the byte cap", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(ZKEY_BYTES, { status: 200 }));
    await expect(fetchCapped("/zk/spend_1.zkey", 1024)).rejects.toThrow(/cap/);
  });

  it("fails on a 404", async () => {
    stubFetch();
    await expect(loadVerifiedArtifact({ id: "missing", path: "/zk/nope", sha256: "00", bytes: 1 }))
      .rejects.toThrow(/404|fetch failed/);
  });
});
