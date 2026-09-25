/**
 * DEF-109-A nullifier equality checkpoint (wallet-build Commit 2).
 *
 * Pinned to the SAME Rust reference vector as commitment.test.ts
 * (canisters/vetkeys/tests/crossdevice_acceptance.rs). The nullifier's third
 * input is the INNER Poseidon(6) commitment (not the Merkle leaf), source-
 * verified at spend.circom:406. Update BOTH sides or neither.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";

import { initPoseidon } from "../src/crypto/poseidon";
import { createNote, deriveNoteSecrets, DENOMINATIONS } from "../src/crypto/notes";

const here = dirname(fileURLToPath(import.meta.url));
const wasmBytes = readFileSync(
  resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm"),
);
const hex = (b: Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

beforeAll(async () => {
  await initPoseidon(wasmBytes);
});

describe("DEF-109-A nullifier equality", () => {
  it("wallet nullifier matches the Rust reference for the pinned vector", async () => {
    const secrets = await deriveNoteSecrets(new Uint8Array(32).fill(1), 0n);
    const note = await createNote(DENOMINATIONS[0], secrets); // 1,000 STSH (DENOMINATIONS[0], A6.6)
    expect(hex(note.nullifier)).toBe(
      "3092d6df6f2c718471ba2b812321609d88292ab1890d2171a202331286834023",
    );
  });
});
