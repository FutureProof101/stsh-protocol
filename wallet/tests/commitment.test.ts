/**
 * Commitment + Merkle-leaf equality checkpoints (wallet-build Commit 2, DEF-111).
 *
 * Standalone pinned vectors — NOT relied on transitively through the nullifier.
 * Both come from the SAME pinned input (masterNoteSecret = 0x01*32, index 0) and
 * the SAME authoritative Rust reference in
 * canisters/vetkeys/tests/crossdevice_acceptance.rs
 * (test_commitment_nullifier_leaf_reference_vector), which cross-checks the leaf
 * against stsh_field_utils::merkle_leaf. Update BOTH sides or neither.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";

import { initPoseidon } from "../src/crypto/poseidon";
import { createNote, deriveNoteSecrets, merkleLeaf, DENOMINATIONS } from "../src/crypto/notes";

const here = dirname(fileURLToPath(import.meta.url));
const wasmBytes = readFileSync(
  resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm"),
);
const hex = (b: Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

const MASTER = new Uint8Array(32).fill(1);

beforeAll(async () => {
  await initPoseidon(wasmBytes);
});

describe("commitment + merkle-leaf equality (Rust reference)", () => {
  it("inner commitment matches the pinned Rust reference vector", async () => {
    const secrets = await deriveNoteSecrets(MASTER, 0n);
    const note = await createNote(DENOMINATIONS[0], secrets); // 1,000 STSH (DENOMINATIONS[0], A6.6)
    expect(hex(note.commitment)).toBe(
      "97bda10879a88de5f99e9fc6c64d979d044cf410ae7cfb8d813061d282679020",
    );
  });

  it("recipient_pk (derived) matches the pinned Rust reference vector", async () => {
    const secrets = await deriveNoteSecrets(MASTER, 0n);
    const note = await createNote(DENOMINATIONS[0], secrets);
    expect(hex(note.recipientPk)).toBe(
      "57d5c538e0154b3538ff4cf4d9523a74772da7998031f529723d1feababc4b27",
    );
  });

  it("merkle leaf matches the pinned Rust reference (stsh_field_utils::merkle_leaf)", async () => {
    const secrets = await deriveNoteSecrets(MASTER, 0n);
    const note = await createNote(DENOMINATIONS[0], secrets);
    const leaf = await merkleLeaf(DENOMINATIONS[0], note.commitment);
    expect(hex(leaf)).toBe(
      "138193df950220ff0014a9886cf06fb0e6095ec3340d4deefabcb3ddecbade05",
    );
  });
});
