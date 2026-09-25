import { defineConfig } from "vitest/config";

import { releaseDefines } from "./src/release/loadRecord";

export default defineConfig({
  // J-25: the suite runs against the SAME injection the production build uses,
  // read from the same record by the same function. A test that supplied its
  // own value would not bind the shipped wiring.
  define: releaseDefines(),
  test: {
    environment: "jsdom",
    include: ["tests/**/*.test.ts"],
    // The Poseidon WASM (wallet/src/wasm/poseidon) is a gitignored wasm-pack
    // artifact — run `npm run build:wasm` before `npm test`. globalSetup asserts
    // it exists so a missing build fails loudly with the fix, not a cryptic
    // import error.
    globalSetup: ["./tests/wasm-setup.ts"],
  },
});
