/**
 * Spend-proof witness assembly + prover dispatch (wallet-build Commit 3).
 *
 * Builds the full spend.circom witness (all public + private signals) from a
 * spend request, dispatches it to the prover Web Worker (fullProve), and parses
 * the 9 public signals back per PUBLIC_SIGNALS_SCHEMA.md.
 *
 * Signal order (source-verified against circuits/build/spend.sym):
 *   0 anchor · 1 nullifier_hash · 2 output_merkle_leaf_1 · 3 output_merkle_leaf_2
 *   4 public_amount · 5 fee · 6 recipient_principal · 7 recipient_subaccount_lo
 *   8 recipient_subaccount_hi
 *
 * NOTE (Commit 3 is structural): buildSpendWitness computes the derived public
 * signals (nullifier_hash, output leaves) from the note context so the witness
 * is self-consistent; end-to-end proof verification against the dev VK is
 * exercised once a full valid witness (real Merkle path) is available in the
 * spend flow / a dedicated fixture — the dev zkey + circuit wasm are generated
 * (gitignored) and the fullProve path is wired here.
 */

import type { Note } from "./notes";
import { leToBigint, merkleLeaf } from "./notes";
import type { ProverRequest, ProverResponse } from "../workers/prover.worker";
import { SessionCancelledError, throwIfAborted } from "../session/taskOwner";

const TREE_DEPTH = 32;

/** Where the prover fetches the circuit wasm + proving key from. */
export interface ProverAssets {
  /** spend_js/spend.wasm (witness calculator). */
  wasmUrl: string;
  /** proving key — dev zkey for testing, re-ceremony zkey for production. */
  zkeyUrl: string;
}

/** A public payout target (DEF-026). Omit for a fully-private spend. */
export interface PayoutTarget {
  /** DEF-108 recipient-principal encoding (32-byte LE field element). */
  recipientPrincipal: Uint8Array;
  /** subaccount low 128 bits, LE (32-byte field element). */
  subaccountLo: Uint8Array;
  /** subaccount high 128 bits, LE (32-byte field element). */
  subaccountHi: Uint8Array;
}

/** Everything needed to build a spend witness. */
export interface SpendRequest {
  /** The note being spent, with its Merkle path + anchor. */
  inputNote: Note;
  spendKey: Uint8Array;
  merklePath: { elements: Uint8Array[]; indices: number[] };
  anchor: Uint8Array;
  /** Two output notes (note 2 may be an empty value-0 change note). */
  outputNote1: Note;
  outputNote2: Note;
  publicAmount: bigint;
  fee: bigint;
  /** Public payout target; all-zero signals when omitted (private spend). */
  payout?: PayoutTarget;
}

/** The parsed proof + public signals returned to the caller. */
export interface SpendProof {
  proof: unknown;
  anchor: bigint;
  nullifierHash: bigint;
  outputMerkleLeaf1: bigint;
  outputMerkleLeaf2: bigint;
  publicAmount: bigint;
  fee: bigint;
  recipientPrincipal: bigint;
  recipientSubaccountLo: bigint;
  recipientSubaccountHi: bigint;
  /** Raw 9-element public-signal array (decimal strings), for the pool call. */
  publicSignals: string[];
}

const ZERO32 = new Uint8Array(32);

/**
 * Assemble the spend.circom witness. The derived public signals
 * (nullifier_hash, output leaves) are recomputed here from the note context so
 * the witness is internally consistent with what the circuit will constrain.
 */
export async function buildSpendWitness(
  req: SpendRequest,
  signal?: AbortSignal,
): Promise<Record<string, string | string[]>> {
  throwIfAborted(signal);
  if (req.merklePath.elements.length !== TREE_DEPTH || req.merklePath.indices.length !== TREE_DEPTH) {
    throw new Error(`Merkle path must have exactly ${TREE_DEPTH} levels`);
  }

  const leaf1 = await merkleLeaf(req.outputNote1.value, req.outputNote1.commitment);
  throwIfAborted(signal);
  const leaf2 = await merkleLeaf(req.outputNote2.value, req.outputNote2.commitment);
  throwIfAborted(signal);

  const payout = req.payout ?? {
    recipientPrincipal: ZERO32,
    subaccountLo: ZERO32,
    subaccountHi: ZERO32,
  };

  const dec = (v: bigint) => v.toString(10);
  const le = (b: Uint8Array) => leToBigint(b).toString(10);

  return {
    // ── public (index 0-8, PUBLIC_SIGNALS_SCHEMA order) ──
    anchor: le(req.anchor),
    nullifier_hash: le(req.inputNote.nullifier),
    output_merkle_leaf_1: le(leaf1),
    output_merkle_leaf_2: le(leaf2),
    public_amount: dec(req.publicAmount),
    fee: dec(req.fee),
    recipient_principal: le(payout.recipientPrincipal),
    recipient_subaccount_lo: le(payout.subaccountLo),
    recipient_subaccount_hi: le(payout.subaccountHi),
    // ── private ──
    spend_key: le(req.spendKey),
    in_value: dec(req.inputNote.value),
    in_rho: le(req.inputNote.rho),
    in_rseed: le(req.inputNote.rseed),
    path_elements: req.merklePath.elements.map(le),
    path_indices: req.merklePath.indices.map((i) => dec(BigInt(i))),
    out_value_1: dec(req.outputNote1.value),
    out_recipient_pk_1: le(req.outputNote1.recipientPk),
    out_rho_1: le(req.outputNote1.rho),
    out_rseed_1: le(req.outputNote1.rseed),
    out_value_2: dec(req.outputNote2.value),
    out_recipient_pk_2: le(req.outputNote2.recipientPk),
    out_rho_2: le(req.outputNote2.rho),
    out_rseed_2: le(req.outputNote2.rseed),
  };
}

/** Parse the snarkjs publicSignals array (decimal strings) into named fields. */
export function parsePublicSignals(publicSignals: string[]): Omit<SpendProof, "proof"> {
  if (publicSignals.length !== 9) {
    throw new Error(`expected 9 public signals, got ${publicSignals.length}`);
  }
  return {
    anchor: BigInt(publicSignals[0]),
    nullifierHash: BigInt(publicSignals[1]),
    outputMerkleLeaf1: BigInt(publicSignals[2]),
    outputMerkleLeaf2: BigInt(publicSignals[3]),
    publicAmount: BigInt(publicSignals[4]),
    fee: BigInt(publicSignals[5]),
    recipientPrincipal: BigInt(publicSignals[6]),
    recipientSubaccountLo: BigInt(publicSignals[7]),
    recipientSubaccountHi: BigInt(publicSignals[8]),
    publicSignals,
  };
}

/**
 * Generate a Groth16 spend proof: build the witness, run fullProve in the
 * prover Web Worker, and parse the public signals. `spawnWorker` is injected so
 * the browser (`new Worker(new URL('../workers/prover.worker.ts', import.meta.url))`)
 * and tests (a mock/inline worker) share this logic. Progress is reported as a
 * coarse 0→100.
 */
export async function generateSpendProof(
  req: SpendRequest,
  assets: ProverAssets,
  spawnWorker: () => Worker,
  onProgress?: (pct: number) => void,
  signal?: AbortSignal,
): Promise<SpendProof> {
  throwIfAborted(signal);
  onProgress?.(0);
  const circuitInputs = await buildSpendWitness(req, signal);
  throwIfAborted(signal);
  onProgress?.(10);

  const worker = spawnWorker();
  try {
    const response = await new Promise<ProverResponse>((resolve, reject) => {
      let settled = false;
      const settle = (fn: () => void) => {
        if (settled) return;
        settled = true;
        worker.onmessage = null;
        worker.onerror = null;
        signal?.removeEventListener("abort", onAbort);
        fn();
      };
      const onAbort = () =>
        settle(() => {
          reject(new SessionCancelledError("proof generation was cancelled"));
        });
      worker.onmessage = (e: MessageEvent<ProverResponse>) => settle(() => resolve(e.data));
      worker.onerror = (e) => settle(() => reject(new Error(e.message)));
      signal?.addEventListener("abort", onAbort, { once: true });
      if (signal?.aborted) {
        onAbort();
        return;
      }
      const request: ProverRequest = {
        circuitInputs,
        wasmUrl: assets.wasmUrl,
        zkeyUrl: assets.zkeyUrl,
      };
      worker.postMessage(request);
    });
    throwIfAborted(signal);
    onProgress?.(95);
    if (!response.ok || !response.publicSignals) {
      throw new Error(`proof generation failed: ${response.error ?? "unknown error"}`);
    }
    const parsed = parsePublicSignals(response.publicSignals);
    throwIfAborted(signal);
    onProgress?.(100);
    return { proof: response.proof, ...parsed };
  } finally {
    worker.onmessage = null;
    worker.onerror = null;
    worker.terminate();
  }
}
