// @vitest-environment node
/**
 * encodeGroth16Proof tests (L3c / H6-2).
 *
 * The 256-byte compact encoding (G2 c0-first, no swap, 32-byte LE Fq) pinned
 * byte-equal against the ceremony proof fixture (circuits/proof.json — valid
 * against the pinned VK). The SAME pinned hex is asserted against the Rust
 * reference `proof_json_to_bytes` AND the real production verifier Wasm in
 * integration-tests/tests/l3c_proof_encoding_tests.rs — three-way agreement:
 * TS encoder == Rust reference == what the verifier canister accepts.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  BN254_FQ_MODULUS,
  GROTH16_PROOF_BYTES,
  encodeGroth16Proof,
  fqToLe32,
} from "../src/crypto/encodeProof";

const here = dirname(fileURLToPath(import.meta.url));
const ceremonyProof = JSON.parse(
  readFileSync(resolve(here, "../../circuits/proof.json"), "utf8"),
) as unknown;

/** Pinned TS output for circuits/proof.json (captured from this encoder; the
 * integration test asserts the SAME bytes from Rust proof_json_to_bytes and
 * acceptance by the real production verifier Wasm). */
const CEREMONY_PROOF_BYTES_HEX =
  "00cd4223a51f7bca91facc4500ebc78840799425edbc18095fbdf19b595c042529e68e97efa3750f4d6f1d3114e633b27020227838c8e510d83a66a1dba8582db74cfad1f42646e8d260c475890453752f4e999733cbfce390feea22ed093d2ae51755c4302681eb4c22bbdf1bb7ea5fe9494ea340bddfcadcd3b00946536612c83f8fbf7a743f6a36a4c571115368d45bdb2d2ce4773c2d9f3400c11a9eb5067b8b80123dc46388e628e979996af797a80b08b84d64253f96fa7a27bcca431e3dea9bc890925b5eafe5794ce861392a1f99dfac262a0083a515ab329d7db811988a4b0473e84735ca625d61c764d7cd772d5ecb7102e865a7fd2d2bf9da672a";

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("encodeGroth16Proof (H6-2)", () => {
  it("emits the pinned 256-byte compact encoding for the ceremony proof fixture", () => {
    const bytes = encodeGroth16Proof(ceremonyProof);
    expect(bytes.length).toBe(GROTH16_PROOF_BYTES);
    expect(hex(bytes)).toBe(CEREMONY_PROOF_BYTES_HEX);
  });

  it("G2 pi_b is c0-FIRST (no swap): the first 64 bytes of the G2 block are x_c0 then x_c1", () => {
    const bytes = encodeGroth16Proof(ceremonyProof);
    const proof = ceremonyProof as {
      pi_b: [[string, string], [string, string], [string, string]];
    };
    expect(hex(bytes.slice(64, 96))).toBe(hex(fqToLe32(proof.pi_b[0][0], "x.c0")));
    expect(hex(bytes.slice(96, 128))).toBe(hex(fqToLe32(proof.pi_b[0][1], "x.c1")));
    expect(hex(bytes.slice(128, 160))).toBe(hex(fqToLe32(proof.pi_b[1][0], "y.c0")));
    expect(hex(bytes.slice(160, 192))).toBe(hex(fqToLe32(proof.pi_b[1][1], "y.c1")));
  });

  it("little-endian field encoding: 1 → 01 followed by 31 zero bytes", () => {
    const le = fqToLe32("1", "test");
    expect(le[0]).toBe(1);
    expect([...le.slice(1)].every((b) => b === 0)).toBe(true);
  });

  it("rejects a wrong protocol", () => {
    const p = JSON.parse(JSON.stringify(ceremonyProof));
    p.protocol = "plonk";
    expect(() => encodeGroth16Proof(p)).toThrow(/protocol/);
  });

  it("rejects a wrong curve", () => {
    const p = JSON.parse(JSON.stringify(ceremonyProof));
    p.curve = "bls12-381";
    expect(() => encodeGroth16Proof(p)).toThrow(/curve/);
  });

  it("rejects malformed pi_a arity", () => {
    const p = JSON.parse(JSON.stringify(ceremonyProof));
    p.pi_a = p.pi_a.slice(0, 2);
    expect(() => encodeGroth16Proof(p)).toThrow(/pi_a/);
  });

  it("rejects an out-of-range coordinate (>= Fq modulus)", () => {
    const p = JSON.parse(JSON.stringify(ceremonyProof));
    p.pi_a[0] = BN254_FQ_MODULUS.toString(10);
    expect(() => encodeGroth16Proof(p)).toThrow(/not a canonical BN254 Fq/);
  });

  it("rejects non-decimal coordinate strings", () => {
    const p = JSON.parse(JSON.stringify(ceremonyProof));
    p.pi_c[1] = "0x12";
    expect(() => encodeGroth16Proof(p)).toThrow(/pi_c|decimal/);
  });

  it("Fq boundary: Fq−1 is ACCEPTED (valid base-field coordinate above Fr)", () => {
    const p = JSON.parse(JSON.stringify(ceremonyProof));
    p.pi_a[0] = (BN254_FQ_MODULUS - 1n).toString(10);
    expect(() => encodeGroth16Proof(p)).not.toThrow();
  });

  it("Fq boundary: Fq itself is REJECTED (non-canonical)", () => {
    const p = JSON.parse(JSON.stringify(ceremonyProof));
    p.pi_a[0] = BN254_FQ_MODULUS.toString(10);
    expect(() => encodeGroth16Proof(p)).toThrow(/not a canonical BN254 Fq/);
  });

  it("Fq boundary: a coordinate in [Fr, Fq) is ACCEPTED (base field exceeds the scalar field)", () => {
    // Fr (scalar-field modulus) is strictly smaller than Fq; a coordinate in
    // between is a VALID proof coordinate and must not be rejected.
    const FR_SCALAR = BigInt(
      "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    );
    expect(FR_SCALAR < BN254_FQ_MODULUS).toBe(true);
    const p = JSON.parse(JSON.stringify(ceremonyProof));
    p.pi_a[1] = FR_SCALAR.toString(10); // in [Fr, Fq) — valid
    expect(() => encodeGroth16Proof(p)).not.toThrow();
  });

  it("projective constants are enforced: pi_a[2] != '1' rejected", () => {
    const p = JSON.parse(JSON.stringify(ceremonyProof));
    p.pi_a[2] = "2";
    expect(() => encodeGroth16Proof(p)).toThrow(/projective/);
  });

  it("projective constants are enforced: pi_c[2] != '1' rejected", () => {
    const p = JSON.parse(JSON.stringify(ceremonyProof));
    p.pi_c[2] = "0";
    expect(() => encodeGroth16Proof(p)).toThrow(/projective/);
  });

  it("projective constants are enforced: pi_b[2] != [\"1\",\"0\"] rejected", () => {
    const p = JSON.parse(JSON.stringify(ceremonyProof));
    p.pi_b[2] = ["1", "1"];
    expect(() => encodeGroth16Proof(p)).toThrow(/projective/);
  });
});
