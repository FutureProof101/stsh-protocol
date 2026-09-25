/**
 * Poseidon WASM arity vectors (wallet-build Commit 1).
 *
 * Pins the circomlibjs reference outputs for poseidon2/3/4/6 — the SAME hex the
 * Rust crate test (circuits/poseidon-wasm/src/lib.rs) pins, and the SAME
 * circomlib params the canister + circuit use. If any of these drift, the
 * wallet would silently produce commitments/nullifiers the circuit rejects.
 * Update the Rust vectors and these together or neither.
 *
 * Runtime note: the wasm-pack `--target web` module is initialized from its
 * .wasm bytes (node has no fetch for a file: URL) before the first hash.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";

import {
  initPoseidon,
  poseidon2,
  poseidon3,
  poseidon4,
  poseidon6,
} from "../src/crypto/poseidon";
import {
  DOMAIN_ASSET_ID,
  DOMAIN_CIRCUIT_VERSION,
  DOMAIN_NETWORK_ID,
  DOMAIN_POOL_CANISTER_ID,
  bigintToFieldLe,
} from "../src/crypto/notes";

const here = dirname(fileURLToPath(import.meta.url));
const wasmBytes = readFileSync(
  resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm"),
);

const le32 = (n: number | bigint) => bigintToFieldLe(BigInt(n), "test input");
const hex = (b: Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

beforeAll(async () => {
  await initPoseidon(wasmBytes);
});

describe("Poseidon arity vectors (circomlibjs reference)", () => {
  it("poseidon2([1,2])", async () => {
    expect(hex(await poseidon2(le32(1), le32(2)))).toBe(
      "9a1817447a60199e51453274f217362acfe962966b4cf63d4190d6e7f5c05c11",
    );
  });

  it("poseidon3([1,2,3])", async () => {
    expect(hex(await poseidon3(le32(1), le32(2), le32(3)))).toBe(
      "32d736ab34df25f768b9c59d260e23f30263ab8de5d503ffc039699ed832770e",
    );
  });

  it("poseidon4([1,2,3,4])", async () => {
    expect(hex(await poseidon4(le32(1), le32(2), le32(3), le32(4)))).toBe(
      "65042565df25a5ba3d66e01cbb0ee637980b51e440face9dd7fdc1b67d869c29",
    );
  });

  it("poseidon6([1,2,3,4,5,6])", async () => {
    expect(hex(await poseidon6(le32(1), le32(2), le32(3), le32(4), le32(5), le32(6)))).toBe(
      "e102632fca4c4a1339225fb0680a493875a4de94f0ebc8132844840085031a2d",
    );
  });
});

describe("domainHash (D2 ceremony)", () => {
  it("poseidon4(DOMAIN_POOL_CANISTER_ID, ASSET, CIRCUIT_V, NETWORK) matches D2", async () => {
    const domainHash = await poseidon4(
      bigintToFieldLe(DOMAIN_POOL_CANISTER_ID, "DOMAIN_POOL_CANISTER_ID"),
      bigintToFieldLe(DOMAIN_ASSET_ID, "DOMAIN_ASSET_ID"),
      bigintToFieldLe(DOMAIN_CIRCUIT_VERSION, "DOMAIN_CIRCUIT_VERSION"),
      bigintToFieldLe(DOMAIN_NETWORK_ID, "DOMAIN_NETWORK_ID"),
    );
    expect(hex(domainHash)).toBe(
      "b4c713664074d78bed0527155ed4c508f8e9308fb325eec76a0e2e4e34332d15",
    );
  });
});

describe("canonicality guard surfaces WASM errors", () => {
  it("rejects a non-canonical (all-0xFF) input", async () => {
    const bad = new Uint8Array(32).fill(0xff);
    await expect(poseidon2(bad, le32(1))).rejects.toThrow();
  });

  it("TS-side assert catches out-of-range before the boundary", () => {
    const BN254_FR_MODULUS = BigInt(
      "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    );
    expect(() => bigintToFieldLe(BN254_FR_MODULUS, "modulus")).toThrow();
  });
});
