/**
 * vetKeys wallet crypto tests (BRIEF_VETKEYS_CROSSDEVICE)
 *
 * Covers the pure/offline layers: HD note-secret derivation (with the
 * CROSS-LANGUAGE pinned vector shared with the Rust reference test), note
 * payload serialization, vetKD-input/IBE-identity construction, IBE ciphertext
 * sizing, and the scan paging/filtering logic. The chain-dependent layers
 * (real vetKD derivation, IBE roundtrip, cross-device reconstruction) are
 * proven in canisters/vetkeys/tests/crossdevice_acceptance.rs against PocketIC.
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";
import { IbeCiphertext, MasterPublicKey } from "@dfinity/vetkeys";

import {
  deriveNoteSecrets,
  decomposeAmount,
  noteFromBytes,
  noteToBytes,
  DENOMINATIONS,
  NOTE_PAYLOAD_BYTES,
  type Note,
} from "../src/crypto/notes";
import {
  MAX_ENCRYPTED_PAYLOAD_BYTES,
  VETKEYS_KEY_NAME,
  encryptNotePayload,
  ibeIdentityFor,
  scanPayloads,
  vetkdInput,
} from "../src/crypto/vetkeys";

const hex = (b: Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

describe("HD note-secret derivation", () => {
  const master = new Uint8Array(32).fill(0xab);

  it("matches the CROSS-LANGUAGE pinned vector (Rust: crossdevice_acceptance.rs)", async () => {
    const s0 = await deriveNoteSecrets(master, 0n);
    const concat = hex(s0.spendKey) + hex(s0.rho) + hex(s0.rseed);
    // Pinned 2026-07-13 (Fr-REDUCED secrets — wallet-build Commit 2; secrets are
    // now reduced mod Fr so they are valid field elements). The Rust test
    // (crossdevice_acceptance.rs) pins the identical constant — update BOTH or
    // neither.
    expect(concat).toBe(
      "08231bb6b902c6203c6733f569bc35bf18dc928423f0e6da68abc021b3d8ff08" +
        "d91537a74f69ad54a080cbfd060187aea86ae45f9062f40eaa48355aa1bcc02e" +
        "7a37a79134207c585c511938bff1d81256d1482774065478b4ba9ad105893919",
    );
  });

  it("is deterministic and unique per index", async () => {
    const a0 = await deriveNoteSecrets(master, 0n);
    const a0Again = await deriveNoteSecrets(master, 0n);
    const a1 = await deriveNoteSecrets(master, 1n);
    expect(hex(a0.spendKey)).toBe(hex(a0Again.spendKey));
    expect(hex(a0.rho)).toBe(hex(a0Again.rho));
    expect(hex(a0.spendKey)).not.toBe(hex(a1.spendKey));
    expect(hex(a0.rho)).not.toBe(hex(a1.rho));
    expect(hex(a0.rseed)).not.toBe(hex(a1.rseed));
  });

  it("different masters diverge", async () => {
    const other = new Uint8Array(32).fill(0xcd);
    const a = await deriveNoteSecrets(master, 0n);
    const b = await deriveNoteSecrets(other, 0n);
    expect(hex(a.spendKey)).not.toBe(hex(b.spendKey));
  });
});

describe("note payload serialization", () => {
  it("round-trips through the pinned 104-byte layout", async () => {
    const secrets = await deriveNoteSecrets(new Uint8Array(32).fill(1), 7n);
    const note: Note = {
      value: DENOMINATIONS[1], // 10 STSH
      recipientPk: new Uint8Array(32).fill(9),
      rho: secrets.rho,
      rseed: secrets.rseed,
      commitment: new Uint8Array(32),
      nullifier: new Uint8Array(32),
    };
    const bytes = noteToBytes(note);
    expect(bytes.length).toBe(NOTE_PAYLOAD_BYTES);
    expect(NOTE_PAYLOAD_BYTES).toBe(104);

    const parsed = noteFromBytes(bytes);
    expect(parsed).not.toBeNull();
    expect(parsed!.value).toBe(note.value);
    expect(hex(parsed!.rho)).toBe(hex(note.rho));
    expect(hex(parsed!.rseed)).toBe(hex(note.rseed));
    expect(hex(parsed!.recipientPk)).toBe(hex(note.recipientPk));
  });

  it("rejects wrong-length payloads", () => {
    expect(noteFromBytes(new Uint8Array(50))).toBeNull();
    expect(noteFromBytes(new Uint8Array(105))).toBeNull();
  });
});

describe("vetKD input / IBE identity", () => {
  it("builds len(principal) || principal || key_name (Rust key_id_to_vetkd_input mirror)", () => {
    const principal = Principal.fromUint8Array(new Uint8Array([0xa1, 0, 0, 0, 5]));
    const input = vetkdInput(principal);
    const pBytes = principal.toUint8Array();
    expect(input[0]).toBe(pBytes.length);
    expect(hex(input.slice(1, 1 + pBytes.length))).toBe(hex(pBytes));
    const name = new TextEncoder().encode(VETKEYS_KEY_NAME);
    expect(hex(input.slice(1 + pBytes.length))).toBe(hex(name));
    // Identity construction must not throw.
    ibeIdentityFor(principal);
  });

  it("distinct principals produce distinct identities", () => {
    const a = vetkdInput(Principal.fromUint8Array(new Uint8Array([1, 2, 3])));
    const b = vetkdInput(Principal.fromUint8Array(new Uint8Array([1, 2, 4])));
    expect(hex(a)).not.toBe(hex(b));
  });
});

describe("IBE ciphertext size (merkle-tree 1024-byte cap)", () => {
  it("a 104-byte note payload fits with wide margin", () => {
    // Pure size arithmetic from the library — no chain needed.
    expect(IbeCiphertext.ciphertextSize(NOTE_PAYLOAD_BYTES)).toBeLessThanOrEqual(
      MAX_ENCRYPTED_PAYLOAD_BYTES,
    );
  });

  it("a real offline encryption of a 104-byte payload fits the cap", async () => {
    // MasterPublicKey.productionKey() is a REAL BLS12-381 master key baked into
    // the library — lets us exercise actual IBE encryption fully offline.
    const dpk = MasterPublicKey.productionKey().deriveCanisterKey(
      Principal.fromText("aaaaa-aa").toUint8Array(),
    );
    const recipient = Principal.fromUint8Array(new Uint8Array([0xa1, 1, 2, 3]));
    const secrets = await deriveNoteSecrets(new Uint8Array(32).fill(2), 0n);
    const note: Note = {
      value: DENOMINATIONS[0],
      recipientPk: secrets.spendKey,
      rho: secrets.rho,
      rseed: secrets.rseed,
      commitment: new Uint8Array(32),
      nullifier: new Uint8Array(32),
    };
    const ciphertext = encryptNotePayload(dpk, recipient, noteToBytes(note));
    expect(ciphertext.length).toBeLessThanOrEqual(MAX_ENCRYPTED_PAYLOAD_BYTES);
    // IBE overhead is 136 bytes: 8 header + 32 seed + 96 G2 point.
    expect(ciphertext.length).toBe(NOTE_PAYLOAD_BYTES + 136);
  });
});

describe("cross-device scan paging/filtering", () => {
  it("pages through all payloads and keeps only the decryptable ones", async () => {
    // Synthetic chain: 1200 payloads across 3 pages (500/500/200); "ours" are
    // marked by content. The injected trial-decryptor stands in for
    // tryDecryptNotePayload(vetKey, ·), whose real IBE path is proven on-chain
    // in the Rust acceptance test.
    const ours = new Set([3n, 500n, 1199n]);
    const total = 1200n;
    const progress: bigint[] = [];
    const recovered = await scanPayloads(
      async (from, limit) => {
        const page: Array<[bigint, Uint8Array]> = [];
        for (let i = from; i < from + limit && i < total; i++) {
          page.push([i, new Uint8Array([ours.has(i) ? 1 : 0])]);
        }
        return page;
      },
      (bytes) => (bytes[0] === 1 ? bytes : null),
      (scanned) => progress.push(scanned),
      500n,
    );
    expect(recovered.map((r) => r.leafIndex)).toEqual([3n, 500n, 1199n]);
    expect(progress).toEqual([500n, 1000n, 1200n]);
  });

  it("handles an empty chain and a short final page", async () => {
    const empty = await scanPayloads(async () => [], () => null);
    expect(empty).toEqual([]);

    const short = await scanPayloads(
      async (from) => (from === 0n ? [[0n, new Uint8Array([1])] as [bigint, Uint8Array]] : []),
      (b) => b,
      undefined,
      500n,
    );
    expect(short.length).toBe(1);
  });
});

describe("denomination decomposition (unchanged algorithm, A6.6 ladder)", () => {
  const STSH = 100_000_000n;
  /** The A6.6 floor rung: 1,000 STSH. */
  const RUNG = 1_000n * STSH;

  it("decomposes 123,000 STSH greedily", () => {
    const parts = decomposeAmount(123n * RUNG);
    expect(parts).toEqual([
      100n * RUNG,
      10n * RUNG,
      10n * RUNG,
      RUNG,
      RUNG,
      RUNG,
    ]);
  });

  // ── A6.6 / AC-12 — what the five-tier ladder COSTS the user ───────────────
  //
  // The algorithm is unchanged and deliberately ladder-agnostic, but the ladder
  // moving its floor from 1 STSH to 1,000 STSH changes what it can express. That
  // consequence is asserted here rather than left for a user to discover: with a
  // 1,000-STSH floor, only exact multiples of 1,000 STSH are shieldable at all.

  it("decomposes an amount spanning four rungs, largest first", () => {
    expect(decomposeAmount(1_011_000n * STSH)).toEqual([
      1_000_000n * STSH,
      10_000n * STSH,
      1_000n * STSH,
    ]);
  });

  it("REJECTS any amount below the new 1,000-STSH floor", () => {
    expect(() => decomposeAmount(999n * STSH)).toThrow(/not decomposable/);
    expect(() => decomposeAmount(1n * STSH)).toThrow(/not decomposable/);
  });

  it("REJECTS a non-multiple of the floor between two rungs", () => {
    // 1,500 STSH sits between the 1,000 and 10,000 rungs and is not a multiple
    // of the floor — the greedy pass takes one 1,000 note and strands 500.
    expect(() => decomposeAmount(1_500n * STSH)).toThrow(/not decomposable/);
  });
});
