/**
 * J-25 RED-3 driver — resolve the PRODUCTION `wallet/vite.config.ts` and print
 * its `define` map as JSON.
 *
 * Why a child process rather than an in-test import: `src/release/loadRecord`
 * locates the release record by walking UP from `process.cwd()`, and that walk
 * happens at module-evaluation time. Vitest runs its suites in worker threads,
 * where `process.chdir` does not exist, so the only way to point the REAL
 * config at a fixture record is to evaluate it in a process whose cwd IS the
 * fixture tree. Nothing about the config is stubbed: `loadConfigFromFile` is
 * Vite's own loader, run against the shipped file at the shipped path.
 *
 * argv[2] — absolute path to the config file to load.
 * stdout  — `{"define": {...}}` on success. Any failure exits non-zero with the
 *           reason on stderr, which is the build-fails case (I1).
 */

import { loadConfigFromFile } from "vite";

const configFile = process.argv[2];
if (typeof configFile !== "string" || configFile === "") {
  console.error("usage: resolveViteDefine.mjs <abs path to vite config>");
  process.exit(2);
}

const loaded = await loadConfigFromFile(
  { command: "build", mode: "production" },
  configFile,
  process.cwd(),
  "silent",
);
if (loaded === null) {
  console.error(`vite could not load ${configFile}`);
  process.exit(3);
}
process.stdout.write(JSON.stringify({ path: loaded.path, define: loaded.config.define ?? null }));
