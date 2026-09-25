/**
 * J-17b — the BUILD-TIME emitter for `src/generated/releasePins.json`.
 *
 * Node-side only: imported by `vite.config.ts` (and by the vitest arm that
 * re-extracts the rows), never by browser code, which imports the emitted JSON.
 *
 * The file is COMMITTED as well as emitted, so `tsc`, vitest and an editor all
 * resolve it. A committed copy that has drifted from the record is exactly the
 * failure this design has to catch rather than tolerate, so
 * `wallet/tests/operator_release_pins.test.ts` re-extracts every `[wasm.*]` row
 * from `deployment/mainnet/release_hashes.toml` at test time and asserts
 * equality with the committed JSON (SSA H-03). The build additionally rewrites
 * it, so a stale copy cannot reach the bundle even if the suite is skipped.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { RELEASE_RECORD_PATH } from "./loadRecord";
import { extractWasmPins, type WasmPins } from "./wasmPins";

/** Where the emitted JSON lives, relative to the wallet package root. */
export const RELEASE_PINS_REL = "src/generated/releasePins.json";

/** Read the located record and extract its `[wasm.*]` pins. */
export function readWasmPins(path: string = RELEASE_RECORD_PATH): WasmPins {
  return extractWasmPins(readFileSync(path, "utf8"));
}

/** Serialise exactly as the committed file is written (trailing newline). */
export function serialiseWasmPins(pins: WasmPins): string {
  return `${JSON.stringify(pins, null, 2)}\n`;
}

/**
 * Write the pins JSON. Returns the text written so a caller can compare it with
 * what is on disk without re-reading.
 */
export function emitReleasePins(walletRoot: string, path?: string): string {
  const text = serialiseWasmPins(readWasmPins(path));
  const target = resolve(walletRoot, RELEASE_PINS_REL);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, text, "utf8");
  return text;
}
