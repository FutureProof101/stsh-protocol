/**
 * Poseidon WASM loader — thin typed wrapper over circuits/poseidon-wasm
 * (wasm-pack --target web output in ../wasm/poseidon, gitignored build
 * artifact; regenerate with `npm run build:wasm`).
 *
 * Errors thrown by the WASM boundary (non-canonical field elements, wrong
 * lengths) are SURFACED, never swallowed — a non-canonical value reaching
 * Poseidon is a bug to catch loudly (brief Phase 2 hard rule).
 *
 * All inputs/outputs are 32-byte LITTLE-ENDIAN BN254 Fr encodings — the same
 * convention as the canisters (`into_bigint().to_bytes_le()`) and the circuit.
 */

import initWasm, {
  poseidon2 as wasmPoseidon2,
  poseidon3 as wasmPoseidon3,
  poseidon4 as wasmPoseidon4,
  poseidon6 as wasmPoseidon6,
} from "../wasm/poseidon/stsh_poseidon_wasm";

let initialized: Promise<unknown> | null = null;

/**
 * Initialize the WASM module. In the browser the default fetch path is used;
 * tests (node) pass the module bytes explicitly.
 */
export function initPoseidon(moduleOrPath?: BufferSource | string): Promise<unknown> {
  if (!initialized) {
    initialized = moduleOrPath !== undefined
      ? initWasm(moduleOrPath as never)
      : initWasm();
  }
  return initialized;
}

async function ready(): Promise<void> {
  if (!initialized) {
    await initPoseidon();
  } else {
    await initialized;
  }
}

export async function poseidon2(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  await ready();
  return new Uint8Array(wasmPoseidon2(left, right));
}

export async function poseidon3(a: Uint8Array, b: Uint8Array, c: Uint8Array): Promise<Uint8Array> {
  await ready();
  return new Uint8Array(wasmPoseidon3(a, b, c));
}

export async function poseidon4(
  a: Uint8Array,
  b: Uint8Array,
  c: Uint8Array,
  d: Uint8Array,
): Promise<Uint8Array> {
  await ready();
  return new Uint8Array(wasmPoseidon4(a, b, c, d));
}

export async function poseidon6(
  a: Uint8Array,
  b: Uint8Array,
  c: Uint8Array,
  d: Uint8Array,
  e: Uint8Array,
  f: Uint8Array,
): Promise<Uint8Array> {
  await ready();
  return new Uint8Array(wasmPoseidon6(a, b, c, d, e, f));
}
