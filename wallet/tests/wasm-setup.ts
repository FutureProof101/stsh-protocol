import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// Vitest globalSetup: fail loudly (with the fix) if the Poseidon WASM artifact
// is missing, instead of a cryptic module-resolution error mid-suite.
export default function setup() {
  const here = dirname(fileURLToPath(import.meta.url));
  const wasm = resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm");
  if (!existsSync(wasm)) {
    throw new Error(
      `Poseidon WASM not built: ${wasm}\n` +
        `Run \`npm run build:wasm\` before \`npm test\` (it's a gitignored artifact).`,
    );
  }
}
