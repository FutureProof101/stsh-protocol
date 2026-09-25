/**
 * Prover witness-assembly structural tests (wallet-build Commit 3).
 *
 * Commit 3 is structural (brief: "no runtime proof test required here — dev
 * zkey not yet loaded"): these assert buildSpendWitness produces a witness that
 * is self-consistent with the circuit's constraints — every signal name
 * present, the derived public signals (nullifier_hash, output leaves) matching
 * the note crypto, private-spend recipient signals zeroed — and that
 * parsePublicSignals round-trips the 9-signal order. End-to-end fullProve
 * against the dev VK is exercised once a full valid witness (real Merkle path)
 * is available in the spend flow; the dev zkey + circuit wasm are generated
 * (gitignored) and the fullProve dispatch is wired in prover.ts.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { initPoseidon } from "../src/crypto/poseidon";
import { createNote, deriveNoteSecrets, merkleLeaf, leToBigint, DENOMINATIONS } from "../src/crypto/notes";
import { buildSpendWitness, generateSpendProof, parsePublicSignals } from "../src/crypto/prover";
import type { SpendRequest } from "../src/crypto/prover";
import { SessionCancelledError } from "../src/session/taskOwner";

const here = dirname(fileURLToPath(import.meta.url));
const wasmBytes = readFileSync(
  resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm"),
);

beforeAll(async () => {
  await initPoseidon(wasmBytes);
});

async function sampleRequest(): Promise<SpendRequest> {
  const inSecrets = await deriveNoteSecrets(new Uint8Array(32).fill(1), 0n);
  const outSecrets = await deriveNoteSecrets(new Uint8Array(32).fill(2), 0n);
  const inputNote = await createNote(DENOMINATIONS[0], inSecrets);
  const outputNote1 = await createNote(DENOMINATIONS[0], outSecrets);
  const outputNote2 = await createNote(DENOMINATIONS[0], await deriveNoteSecrets(new Uint8Array(32).fill(3), 0n));

  return {
    inputNote,
    spendKey: inSecrets.spendKey,
    merklePath: {
      elements: Array.from({ length: 32 }, () => new Uint8Array(32)), // all-zero siblings (dev)
      indices: Array.from({ length: 32 }, () => 0),
    },
    anchor: new Uint8Array(32).fill(7),
    outputNote1,
    outputNote2,
    publicAmount: 0n,
    fee: 0n,
  };
}

describe("buildSpendWitness", () => {
  it("emits every spend.circom signal name (9 public + private)", async () => {
    const w = await buildSpendWitness(await sampleRequest());
    for (const key of [
      "anchor", "nullifier_hash", "output_merkle_leaf_1", "output_merkle_leaf_2",
      "public_amount", "fee", "recipient_principal", "recipient_subaccount_lo",
      "recipient_subaccount_hi", "spend_key", "in_value", "in_rho", "in_rseed",
      "path_elements", "path_indices", "out_value_1", "out_recipient_pk_1",
      "out_rho_1", "out_rseed_1", "out_value_2", "out_recipient_pk_2",
      "out_rho_2", "out_rseed_2",
    ]) {
      expect(w[key], `missing signal ${key}`).toBeDefined();
    }
    expect((w.path_elements as string[]).length).toBe(32);
    expect((w.path_indices as string[]).length).toBe(32);
  });

  it("derives nullifier_hash + output leaves consistent with the note crypto", async () => {
    const req = await sampleRequest();
    const w = await buildSpendWitness(req);

    // nullifier_hash must equal the input note's nullifier (as a field value).
    expect(w.nullifier_hash).toBe(leToBigint(req.inputNote.nullifier).toString(10));

    // output leaves must equal merkleLeaf(value, commitment) for each output.
    const leaf1 = await merkleLeaf(req.outputNote1.value, req.outputNote1.commitment);
    const leaf2 = await merkleLeaf(req.outputNote2.value, req.outputNote2.commitment);
    expect(w.output_merkle_leaf_1).toBe(leToBigint(leaf1).toString(10));
    expect(w.output_merkle_leaf_2).toBe(leToBigint(leaf2).toString(10));
  });

  it("zeroes the DEF-026 recipient signals for a private spend", async () => {
    const w = await buildSpendWitness(await sampleRequest());
    expect(w.recipient_principal).toBe("0");
    expect(w.recipient_subaccount_lo).toBe("0");
    expect(w.recipient_subaccount_hi).toBe("0");
  });

  it("rejects a wrong-length Merkle path", async () => {
    const req = await sampleRequest();
    req.merklePath.elements = req.merklePath.elements.slice(0, 10);
    await expect(buildSpendWitness(req)).rejects.toThrow(/32 levels/);
  });
});

describe("parsePublicSignals", () => {
  it("maps the 9 signals in PUBLIC_SIGNALS_SCHEMA order", () => {
    const signals = ["10", "11", "12", "13", "14", "15", "16", "17", "18"];
    const p = parsePublicSignals(signals);
    expect(p.anchor).toBe(10n);
    expect(p.nullifierHash).toBe(11n);
    expect(p.outputMerkleLeaf1).toBe(12n);
    expect(p.outputMerkleLeaf2).toBe(13n);
    expect(p.publicAmount).toBe(14n);
    expect(p.fee).toBe(15n);
    expect(p.recipientPrincipal).toBe(16n);
    expect(p.recipientSubaccountLo).toBe(17n);
    expect(p.recipientSubaccountHi).toBe(18n);
  });

  it("rejects a wrong-length signal array", () => {
    expect(() => parsePublicSignals(["1", "2", "3"])).toThrow(/9 public signals/);
  });
});

describe("generateSpendProof cancellation", () => {
  it("aborted before witness construction never creates a worker", async () => {
    const controller = new AbortController();
    controller.abort();
    const spawn = vi.fn();
    await expect(
      generateSpendProof(
        await sampleRequest(),
        { wasmUrl: "blob:wasm", zkeyUrl: "blob:zkey" },
        spawn,
        undefined,
        controller.signal,
      ),
    ).rejects.toBeInstanceOf(SessionCancelledError);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("aborting a hung worker terminates it and settles exactly once", async () => {
    let onmessage: ((event: MessageEvent) => void) | null = null;
    let onerror: ((event: ErrorEvent) => void) | null = null;
    const worker = {
      get onmessage() { return onmessage; },
      set onmessage(value) { onmessage = value; },
      get onerror() { return onerror; },
      set onerror(value) { onerror = value; },
      postMessage: vi.fn(),
      terminate: vi.fn(),
    } as unknown as Worker;
    const controller = new AbortController();
    const pending = generateSpendProof(
      await sampleRequest(),
      { wasmUrl: "blob:wasm", zkeyUrl: "blob:zkey" },
      () => worker,
      undefined,
      controller.signal,
    );
    await vi.waitFor(() => expect(worker.postMessage).toHaveBeenCalledOnce());
    controller.abort();
    await expect(pending).rejects.toBeInstanceOf(SessionCancelledError);
    expect(worker.terminate).toHaveBeenCalledOnce();
    expect(onmessage).toBeNull();
    expect(onerror).toBeNull();
  });
});
