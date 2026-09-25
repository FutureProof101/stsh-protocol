import { defineConfig } from "vite";

import { releaseDefines } from "./src/loadReleaseRecord";

// J-25 (I1): the ONLY build-time injection is `[build].source_sha` from
// deployment/mainnet/release_hashes.toml. `releaseDefines` throws — and the
// build therefore fails — if that value is missing or is not a full 40-hex
// commit id. Nothing else from the record is injected.
//
// This config also governs `vitest run` for this package, so the suite asserts
// against the SAME injection the deployed page carries.
export default defineConfig({
  define: releaseDefines(),
});
