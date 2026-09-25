// @vitest-environment node
/**
 * L3c isolation gate (Campaign B — per-lane replacement, V3.6.5 correction 5:
 * the gate MOVES with each lane; assertions about landed lanes must fail if
 * they regressed, and only UN-LANDED lane surface stays forbidden).
 *
 * After L3b:
 *
 * - The shield + scan surfaces (pool/vetkeys/merkle actors, note crypto,
 *   note storage, scanner pipeline, scan/balance pages) are REQUIRED to be
 *   reachable — a vacuous pass is a broken gate.
 * - The L3c surfaces (prover, prover worker, the OISY approve bridge —
 *   retired by L0-A — and the spend page) remain FORBIDDEN until L3c lands.
 *
 * Two independent checks, as before: a static import-graph walk from
 * src/main.ts, and a real production bundle scanned for identifiers.
 */

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";

const WALLET_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(WALLET_ROOT, "src");
const ENTRY = path.join(SRC, "main.ts");

/** src-relative prefixes that are still-forbidden surface (post-L3c). */
const FORBIDDEN_PREFIXES = [
  "wallet/oisy",
];

/** src-relative paths the ACTIVE graph must now reach (anti-vacuous + L3a/L3b/L3c). */
const REQUIRED_PATHS = [
  "main.ts",
  "ui/app.ts",
  "session/auth.ts",
  "session/session.ts",
  "ui/tokenFormat.ts",
  "storage/transferJournal.ts",
  // L3a shield surface:
  "ui/pages/shield.ts",
  "ui/shieldFlow.ts",
  "ui/format.ts",
  "actors/pool.ts",
  "actors/vetkeys.ts",
  "crypto/notes.ts",
  "crypto/vetkeys.ts",
  "crypto/fees.ts",
  "session/domainGuard.ts",
  "session/cacheSession.ts",
  "storage/noteCache.ts",
  "storage/journal.ts",
  "storage/indexedDbNoteStore.ts",
  // L3b scan surface:
  "crypto/scanner.ts",
  "actors/merkle.ts",
  "ui/pages/scan.ts",
  "ui/pages/balance.ts",
  // L3c spend surface:
  "ui/spendFlow.ts",
  "ui/pages/spend.ts",
  "crypto/encodeProof.ts",
  "crypto/prover.ts",
  "zk/artifacts.ts",
  "storage/spendJournal.ts",
];

/** Identifiers that exist ONLY in still-forbidden modules. */
const FORBIDDEN_BUNDLE_MARKERS = [
  "approveForShield", // the retired OISY approve bridge (L0-A)
];

/** Identifiers that MUST be in the bundle after L3c (anti-vacuous check). */
const REQUIRED_BUNDLE_MARKERS = [
  "shield_deposit",
  "planShield",
  "runShieldFlow",
  "renderScan",
  "renderBalance",
  "mergeScannedNotes",
  "renderSpend",
  "generateSpendProof",
  "encodeGroth16Proof",
];

function importSpecifiers(source: string): string[] {
  const specs: string[] = [];
  // import ... from "x"; export ... from "x"; import "x"; dynamic import("x")
  const patterns = [
    /(?:import|export)\s+[^"']*?from\s+["']([^"']+)["']/g,
    /import\s+["']([^"']+)["']/g,
    /import\(\s*["']([^"']+)["']\s*\)/g,
  ];
  for (const re of patterns) {
    for (const match of source.matchAll(re)) specs.push(match[1]);
  }
  return specs;
}

function resolveRelative(fromFile: string, spec: string): string | null {
  if (!spec.startsWith(".")) return null; // bare package imports are not lane modules
  const base = path.resolve(path.dirname(fromFile), spec);
  for (const candidate of [base, `${base}.ts`, path.join(base, "index.ts")]) {
    if (candidate.endsWith(".ts") && existsSync(candidate)) return candidate;
  }
  return null; // .css, generated .did.js, wasm assets — not walkable TS
}

/** Walk the transitive TS import graph from `entry`; returns src-relative paths. */
function walkImportGraph(entry: string): Set<string> {
  const visited = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop() as string;
    const rel = path.relative(SRC, file).replace(/\\/g, "/");
    if (visited.has(rel)) continue;
    visited.add(rel);
    for (const spec of importSpecifiers(readFileSync(file, "utf8"))) {
      const resolved = resolveRelative(file, spec);
      if (resolved !== null && !path.relative(SRC, resolved).startsWith("..")) {
        queue.push(resolved);
      }
    }
  }
  return visited;
}

describe("L3c import-graph isolation", () => {
  it("the active app graph reaches the shield surface and no L3c module", () => {
    const visited = walkImportGraph(ENTRY);
    for (const required of REQUIRED_PATHS) {
      expect(visited, `expected the active graph to reach ${required}`).toContain(required);
    }
    const leaks = [...visited].filter((rel) =>
      FORBIDDEN_PREFIXES.some((prefix) => rel.startsWith(prefix)),
    );
    expect(leaks).toEqual([]);
  });
});

describe("L3c built-bundle isolation", () => {
  it("the production bundle carries the shield surface and no L3c identifier", async () => {
    const outDirRel = "node_modules/.cache/stsh-isolation-dist";
    const outDir = path.join(WALLET_ROOT, outDirRel);
    rmSync(outDir, { recursive: true, force: true });
    try {
      await build({
        root: WALLET_ROOT,
        logLevel: "error",
        build: { outDir: outDirRel, emptyOutDir: true, minify: false },
      });
      const assetsDir = path.join(outDir, "assets");
      const jsFiles = readdirSync(assetsDir).filter((f) => f.endsWith(".js"));
      expect(jsFiles.length).toBeGreaterThan(0);
      const bundles = jsFiles.map((f) => readFileSync(path.join(assetsDir, f), "utf8"));
      for (const [i, bundle] of bundles.entries()) {
        for (const marker of FORBIDDEN_BUNDLE_MARKERS) {
          expect(bundle.includes(marker), `${marker} leaked into ${jsFiles[i]}`).toBe(false);
        }
      }
      const all = bundles.join("\n");
      for (const marker of REQUIRED_BUNDLE_MARKERS) {
        expect(all.includes(marker), `${marker} missing from the bundle — vacuous gate`).toBe(true);
      }
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  }, 120_000);
});
