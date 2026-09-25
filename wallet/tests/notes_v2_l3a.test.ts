/**
 * L3a — note v2 (L0-B) + deployment-config hash (C-DOM-2 wallet companion) tests.
 *
 * Pinned vectors guard the two interop contracts:
 *  - noteToBytesV2 / noteFromBytesV2 round-trip the exact 0x02 121-byte layout,
 *    and a legacy 104-byte payload throws LegacyNoteFormatUnsupportedError;
 *  - deriveNoteSecretsV2 is deterministic in (master, nonce) and canonical;
 *  - computeDeploymentConfigHash is byte-for-byte identical to the pool's
 *    compute_deployment_config_hash (the SAME literal digest the Rust P-DOM test
 *    pins), proving the wallet passes the exact hash the pool gate checks.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { beforeAll, describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";

import { initPoseidon } from "../src/crypto/poseidon";
import {
  DENOMINATIONS,
  LegacyNoteFormatUnsupportedError,
  MAX_SPEND_OUTPUT_VALUE,
  NOTE_PAYLOAD_BYTES_V2,
  NOTE_PAYLOAD_VERSION_V2,
  createShieldNote,
  createSpendOutputNote,
  deriveNoteSecretsV2,
  freshNoteNonce,
  noteFromBytesV2,
  noteToBytesV2,
  type Note,
} from "../src/crypto/notes";
import { computeDeploymentConfigHash } from "../src/session/domainGuard";

function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

// Poseidon is a wasm-pack `--target web` module; node has no fetch for its
// file: URL, so initialize it from the .wasm bytes before the first hash.
const here = dirname(fileURLToPath(import.meta.url));
beforeAll(async () => {
  const wasmBytes = readFileSync(resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm"));
  await initPoseidon(wasmBytes);
});

const MASTER = new Uint8Array(32).fill(0x11);

describe("L0-B note v2 — pinned CROSS-LANGUAGE vector (Rust: crossdevice_acceptance.rs)", () => {
  // canisters/vetkeys/tests/crossdevice_acceptance.rs
  // `test_note_v2_derivation_and_payload_vector` pins the IDENTICAL constants
  // from the SAME inputs — update BOTH or neither. Pinned 2026-07-19.
  it("derivation + exact 121-byte payload match the Rust reference", async () => {
    const master = new Uint8Array(32).fill(0x11);
    const nonce = new Uint8Array(16).fill(0xa5);
    const s = await deriveNoteSecretsV2(master, nonce);
    expect(bytesToHex(s.spendKey)).toBe(
      "621c9edfc0757e794110575baf4d094ae6f773d2082e5b06eb9521863be9900c",
    );
    expect(bytesToHex(s.rho)).toBe(
      "b94fb3a09411db2391f2bbe30aec656dbacf2e9db8b28711a4bed1a1f53d0006",
    );
    expect(bytesToHex(s.rseed)).toBe(
      "1f6f8894356d53b34cd2f0bb803b57990781599cef9c33c52ade8bfab3b02d19",
    );

    const note: Note = {
      value: 100_000_000n,
      rho: s.rho,
      rseed: s.rseed,
      recipientPk: new Uint8Array(32).fill(0x22),
      commitment: new Uint8Array(32),
      nullifier: new Uint8Array(32),
    };
    expect(bytesToHex(noteToBytesV2(note, nonce))).toBe(
      "02a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a50000000005f5e100" +
        "b94fb3a09411db2391f2bbe30aec656dbacf2e9db8b28711a4bed1a1f53d0006" +
        "1f6f8894356d53b34cd2f0bb803b57990781599cef9c33c52ade8bfab3b02d19" +
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
  });
});

describe("L0-B note v2 — derivation", () => {
  it("nonce must be 16 bytes", async () => {
    await expect(deriveNoteSecretsV2(MASTER, new Uint8Array(15))).rejects.toThrow();
  });

  it("is deterministic in (master, nonce) and canonical", async () => {
    const nonce = new Uint8Array(16).fill(7);
    const a = await deriveNoteSecretsV2(MASTER, nonce);
    const b = await deriveNoteSecretsV2(MASTER, nonce);
    expect(bytesToHex(a.spendKey)).toBe(bytesToHex(b.spendKey));
    expect(bytesToHex(a.rho)).toBe(bytesToHex(b.rho));
    expect(bytesToHex(a.rseed)).toBe(bytesToHex(b.rseed));
    // Each secret is a canonical 32-byte field element.
    expect(a.spendKey.length).toBe(32);
    expect(a.rho.length).toBe(32);
    expect(a.rseed.length).toBe(32);
  });

  it("a different nonce yields different secrets (no collision at same value)", async () => {
    const s1 = await deriveNoteSecretsV2(MASTER, new Uint8Array(16).fill(1));
    const s2 = await deriveNoteSecretsV2(MASTER, new Uint8Array(16).fill(2));
    expect(bytesToHex(s1.spendKey)).not.toBe(bytesToHex(s2.spendKey));
  });
});

describe("L0-B note v2 — payload 0x02 / 121 bytes", () => {
  async function sampleNote(value: bigint): Promise<{ note: Note; nonce: Uint8Array }> {
    const nonce = new Uint8Array(16).fill(0xAB);
    const secrets = await deriveNoteSecretsV2(MASTER, nonce);
    const note = await createShieldNote(value, secrets);
    return { note, nonce };
  }

  it("serializes to exactly 121 bytes with the version byte + round-trips", async () => {
    const { note, nonce } = await sampleNote(DENOMINATIONS[0]);
    const bytes = noteToBytesV2(note, nonce);
    expect(bytes.length).toBe(NOTE_PAYLOAD_BYTES_V2);
    expect(bytes.length).toBe(121);
    expect(bytes[0]).toBe(NOTE_PAYLOAD_VERSION_V2);

    const parsed = noteFromBytesV2(bytes);
    expect(parsed).not.toBeNull();
    expect(bytesToHex(parsed!.nonce)).toBe(bytesToHex(nonce));
    expect(parsed!.value).toBe(note.value);
    expect(bytesToHex(parsed!.rho)).toBe(bytesToHex(note.rho));
    expect(bytesToHex(parsed!.rseed)).toBe(bytesToHex(note.rseed));
    expect(bytesToHex(parsed!.recipientPk)).toBe(bytesToHex(note.recipientPk));
  });

  it("the parsed nonce re-derives the identical secrets (recovery)", async () => {
    const { note, nonce } = await sampleNote(DENOMINATIONS[1]);
    const parsed = noteFromBytesV2(noteToBytesV2(note, nonce))!;
    const rederived = await deriveNoteSecretsV2(MASTER, parsed.nonce);
    // rho/rseed in the note came from the same derivation, so they match.
    expect(bytesToHex(rederived.rho)).toBe(bytesToHex(note.rho));
    expect(bytesToHex(rederived.rseed)).toBe(bytesToHex(note.rseed));
  });

  it("a legacy 104-byte payload throws LegacyNoteFormatUnsupportedError", () => {
    expect(() => noteFromBytesV2(new Uint8Array(104))).toThrow(LegacyNoteFormatUnsupportedError);
  });

  it("a wrong-length or wrong-version payload returns null (not our note)", () => {
    expect(noteFromBytesV2(new Uint8Array(50))).toBeNull();
    const wrongVersion = new Uint8Array(NOTE_PAYLOAD_BYTES_V2);
    wrongVersion[0] = 0x01;
    expect(noteFromBytesV2(wrongVersion)).toBeNull();
  });

  it("createShieldNote rejects a non-denomination; createSpendOutputNote allows circuit-valid change", async () => {
    const nonce = freshNoteNonce();
    const secrets = await deriveNoteSecretsV2(MASTER, nonce);
    await expect(createShieldNote(5n, secrets)).rejects.toThrow(/denomination/);
    // change output: 0 (dummy) and the max bound are valid; over-max rejected.
    await expect(createSpendOutputNote(0n, secrets)).resolves.toBeDefined();
    await expect(createSpendOutputNote(MAX_SPEND_OUTPUT_VALUE, secrets)).resolves.toBeDefined();
    await expect(createSpendOutputNote(MAX_SPEND_OUTPUT_VALUE + 1n, secrets)).rejects.toThrow(/range/);
  });
});

describe("C-DOM-2 — wallet deployment-config hash matches the pool byte-for-byte", () => {
  it("equals the pinned Rust P-DOM digest for the known principal set", async () => {
    // The SAME literal digest pinned in the Rust P-DOM test
    // (test_encoding_matches_literal_pinned_digest): pool=[0xAB;10],
    // token=[0xCD;10], merkle=[0xEF;10], nullifier=[0x01;10].
    const PINNED =
      "5a0d4abd89249ea6b09651f710b1d0fe906897a3b8dd59b6cee50dd53e1d8e44";
    const hash = await computeDeploymentConfigHash({
      pool: Principal.fromUint8Array(new Uint8Array(10).fill(0xAB)),
      token: Principal.fromUint8Array(new Uint8Array(10).fill(0xCD)),
      merkle: Principal.fromUint8Array(new Uint8Array(10).fill(0xEF)),
      nullifier: Principal.fromUint8Array(new Uint8Array(10).fill(0x01)),
    });
    expect(bytesToHex(hash)).toBe(PINNED);
  });

  it("binds the pool principal FIRST — a different pool with the same deps differs", async () => {
    const deps = {
      token: Principal.fromUint8Array(new Uint8Array(10).fill(0xCD)),
      merkle: Principal.fromUint8Array(new Uint8Array(10).fill(0xEF)),
      nullifier: Principal.fromUint8Array(new Uint8Array(10).fill(0x01)),
    };
    const a = await computeDeploymentConfigHash({
      pool: Principal.fromUint8Array(new Uint8Array(10).fill(0xAB)),
      ...deps,
    });
    const b = await computeDeploymentConfigHash({
      pool: Principal.fromUint8Array(new Uint8Array(10).fill(0xEE)),
      ...deps,
    });
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });
});
