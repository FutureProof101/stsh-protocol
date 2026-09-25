/**
 * STSH Groth16 prover Web Worker (wallet-build Commit 3).
 *
 * Runs snarkjs.groth16.fullProve off the main thread — it handles witness
 * generation internally from the circuit's witness-calculator wasm
 * (circuits/build/spend_js/spend.wasm) and the proving key (dev zkey for
 * testing; the re-ceremony zkey for production — 2-8).
 *
 * The proof + 9 public signals are posted back; the caller (crypto/prover.ts)
 * parses them per PUBLIC_SIGNALS_SCHEMA.md. No canister call happens here.
 */

import * as snarkjs from "snarkjs";

export interface ProverRequest {
  /** All spend.circom signals, keyed by name (decimal strings / arrays). */
  circuitInputs: Record<string, string | string[]>;
  /** URL to the circom witness-calculator wasm (spend_js/spend.wasm). */
  wasmUrl: string;
  /** URL to the proving key (dev zkey, or re-ceremony zkey in production). */
  zkeyUrl: string;
}

export interface ProverResponse {
  ok: boolean;
  proof?: unknown;
  publicSignals?: string[];
  error?: string;
}

self.onmessage = async (e: MessageEvent<ProverRequest>) => {
  const { circuitInputs, wasmUrl, zkeyUrl } = e.data;
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInputs,
      wasmUrl,
      zkeyUrl,
    );
    (self as unknown as Worker).postMessage({ ok: true, proof, publicSignals } as ProverResponse);
  } catch (err) {
    (self as unknown as Worker).postMessage({
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    } as ProverResponse);
  }
};
