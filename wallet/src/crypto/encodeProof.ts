/**
 * Groth16 proof encoding (Campaign B / L3c — H6-2).
 *
 * The prover worker returns a raw snarkjs JSON proof; the verifier canister
 * accepts ONLY the 256-byte compact encoding (verifier/src/lib.rs:501-505,
 * SNARKJS_TO_CANDID_ENCODING.md):
 *
 *   [  0.. 64) G1 pi_a:  x_LE(32) ‖ y_LE(32)
 *   [ 64..192) G2 pi_b:  x_c0_LE ‖ x_c1_LE ‖ y_c0_LE ‖ y_c1_LE   (c0-FIRST, no swap)
 *   [192..256) G1 pi_c:  x_LE(32) ‖ y_LE(32)
 *
 * All coordinates are 32-byte LITTLE-ENDIAN Fq — the BN254 BASE field
 * (arkworks `Fq`, the curve's coordinate field — NOT the scalar field `Fr`
 * used for note field elements; valid coordinates may exceed Fr). This
 * encoder validates the exact snarkjs shape (protocol "groth16", curve
 * "bn128", exact tuple arities AND projective constants pi_a[2] == "1",
 * pi_c[2] == "1", pi_b[2] == ["1","0"]) and every coordinate's canonical Fq
 * range BEFORE emitting — a malformed proof fails here, never at the canister.
 */

/** BN254 BASE-field modulus (Fq) — every proof coordinate must be < this. */
export const BN254_FQ_MODULUS = BigInt(
  "21888242871839275222246405745257275088696311157297823662689037894645226208583",
);

export const GROTH16_PROOF_BYTES = 256;

/** The exact snarkjs groth16 JSON proof shape this encoder accepts. */
export interface SnarkjsGroth16Proof {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
  protocol: string;
  curve: string;
}

function isDecimalString(v: unknown): v is string {
  return typeof v === "string" && /^[0-9]+$/.test(v);
}

/** Structural validation of the snarkjs JSON (shape + protocol + curve). */
export function assertSnarkjsProofShape(proof: unknown): asserts proof is SnarkjsGroth16Proof {
  if (typeof proof !== "object" || proof === null) {
    throw new Error("proof is not an object");
  }
  const p = proof as Record<string, unknown>;
  if (p.protocol !== "groth16") {
    throw new Error(`unsupported proof protocol: ${String(p.protocol)} (expected "groth16")`);
  }
  if (p.curve !== "bn128" && p.curve !== "bn254") {
    throw new Error(`unsupported proof curve: ${String(p.curve)} (expected "bn128")`);
  }
  const g1 = (name: string): void => {
    const v = p[name];
    if (!Array.isArray(v) || v.length !== 3 || !v.every(isDecimalString)) {
      throw new Error(`proof.${name} must be [decimal, decimal, "1"]`);
    }
    if (v[2] !== "1") {
      throw new Error(`proof.${name} is not a projective point (constant term "${v[2]}" != "1")`);
    }
  };
  g1("pi_a");
  g1("pi_c");
  const b = p.pi_b;
  if (
    !Array.isArray(b) ||
    b.length !== 3 ||
    !Array.isArray(b[0]) ||
    b[0].length !== 2 ||
    !Array.isArray(b[1]) ||
    b[1].length !== 2 ||
    !Array.isArray(b[2]) ||
    b[2].length !== 2 ||
    ![...b[0], ...b[1], ...b[2]].every(isDecimalString)
  ) {
    throw new Error("proof.pi_b must be three [c0, c1] pairs of decimal strings");
  }
  if (b[2][0] !== "1" || b[2][1] !== "0") {
    throw new Error(
      `proof.pi_b is not a projective point (constant term [${b[2][0]}, ${b[2][1]}] != ["1", "0"])`,
    );
  }
}

/** decimal string → canonical 32-byte little-endian Fq (range-checked). */
export function fqToLe32(decimal: string, label: string): Uint8Array {
  if (!isDecimalString(decimal)) {
    throw new Error(`${label}: not a decimal string`);
  }
  const v = BigInt(decimal);
  if (v < 0n || v >= BN254_FQ_MODULUS) {
    throw new Error(`${label}: coordinate is not a canonical BN254 Fq element`);
  }
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/**
 * Encode a snarkjs JSON proof to the 256-byte compact form the verifier
 * canister accepts. Byte-equal to the Rust reference `proof_json_to_bytes`
 * (pinned vector in tests).
 */
export function encodeGroth16Proof(proof: unknown): Uint8Array {
  assertSnarkjsProofShape(proof);
  const p = proof as SnarkjsGroth16Proof;
  const out = new Uint8Array(GROTH16_PROOF_BYTES);
  // G1 pi_a: x ‖ y
  out.set(fqToLe32(p.pi_a[0], "pi_a.x"), 0);
  out.set(fqToLe32(p.pi_a[1], "pi_a.y"), 32);
  // G2 pi_b: x_c0 ‖ x_c1 ‖ y_c0 ‖ y_c1 (c0-FIRST, no swap)
  out.set(fqToLe32(p.pi_b[0][0], "pi_b.x.c0"), 64);
  out.set(fqToLe32(p.pi_b[0][1], "pi_b.x.c1"), 96);
  out.set(fqToLe32(p.pi_b[1][0], "pi_b.y.c0"), 128);
  out.set(fqToLe32(p.pi_b[1][1], "pi_b.y.c1"), 160);
  // G1 pi_c: x ‖ y
  out.set(fqToLe32(p.pi_c[0], "pi_c.x"), 192);
  out.set(fqToLe32(p.pi_c[1], "pi_c.y"), 224);
  return out;
}
