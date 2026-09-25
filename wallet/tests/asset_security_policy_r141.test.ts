/**
 * R14-1 — the SHIPPED asset-canister security policy.
 *
 * Rule 12a: the two load-bearing assertions run against the BUILT artifact
 * (`wallet/dist/.ic-assets.json5`), not against the source under `public/`.
 * The source is what a developer edits; the built file is what the asset
 * canister serves, and only the latter can brick the wallet.
 *
 * A missing `dist` is a FAILURE here, never a skip. The previous revision made
 * the built-file check conditional on `existsSync`, so the whole file reported
 * green with no shipped artifact present at all (SSA-A1-D1) — a vacuous pass in
 * the very test written to enforce "test the artifact, not a proxy".
 *
 * Consequence, stated rather than discovered later: these tests require
 * `npm run build` to have run — and since TESTFOLD/C-14 the canonical gate does
 * that itself. `run_gate.sh` DOES invoke the wallet vitest suite, and its Phase
 * 2c wallet-provisioning step names this very file as the reason it builds
 * `wallet/dist` (`run_gate.sh:319-358`, and the `wallet/dist/.ic-assets.json5`
 * prerequisite at `:589-590`). The earlier claim here — that the gate does not
 * run this suite and "couples nothing in the canonical gate" — was true before
 * C-14 and is false now; it is corrected rather than deleted because a stale
 * reproducibility claim inside the test that enforces "test the artifact, not a
 * proxy" is exactly the failure this file exists to prevent (AR2-S1-03).
 *
 * Two properties, both load-bearing:
 *   1. `script-src` grants `'wasm-unsafe-eval'` — without it the browser refuses
 *      `WebAssembly.compile`, and Poseidon + groth16 proving both die.
 *   2. `'unsafe-eval'` appears NOWHERE — the WASM grant must not widen into a
 *      JavaScript `eval()` grant. Token-exact, because `'wasm-unsafe-eval'`
 *      CONTAINS the substring `unsafe-eval`.
 *
 * The header is extracted from the raw bytes rather than parsed as JSON5 (no
 * JSON5 parser is available and adding a dependency is out of fence). That is
 * also the more honest target: the file's prose comment legitimately MENTIONS
 * `'unsafe-eval'` while forbidding it, so a whole-file substring search would be
 * wrong in both directions.
 */

import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const SOURCE = resolve(here, "../public/.ic-assets.json5");
const BUILT = resolve(here, "../dist/.ic-assets.json5");

/** The SHIPPED policy. Absence of the built artifact is a hard failure. */
function shippedPolicy(): string {
  if (!existsSync(BUILT)) {
    throw new Error(
      `shipped artifact missing: ${BUILT} — run \`npm run build\` first. ` +
        "This assertion is about the file the asset canister serves; a source " +
        "file cannot stand in for it.",
    );
  }
  return policyIn(BUILT);
}

function policyIn(path: string): string {
  const raw = readFileSync(path, "utf8");
  const matches = [...raw.matchAll(/"Content-Security-Policy":\s*"([^"]*)"/g)];
  expect(matches).toHaveLength(1); // exactly one policy, no shadowing duplicate
  return matches[0][1];
}

/** directive name → tokens, e.g. "script-src" → ["'self'", "'wasm-unsafe-eval'"]. */
function directives(csp: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of csp.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    out.set(tokens[0], tokens.slice(1));
  }
  return out;
}

describe("R14-1 — the SHIPPED wallet asset security policy", () => {
  it("the shipped artifact exists at all (absence fails, never skips)", () => {
    expect(existsSync(BUILT)).toBe(true);
  });

  it("SHIPPED: script-src grants 'wasm-unsafe-eval' (Poseidon and groth16 compile WASM)", () => {
    const scriptSrc = directives(shippedPolicy()).get("script-src");
    expect(scriptSrc).toBeDefined();
    // Anchor: the directive really parsed, so the assertion below is not vacuous.
    expect(scriptSrc).toContain("'self'");
    expect(scriptSrc).toContain("'wasm-unsafe-eval'");
  });

  it("SHIPPED: 'unsafe-eval' is granted NOWHERE — token-exact", () => {
    const allTokens = [...directives(shippedPolicy()).values()].flat();
    // Anchor: there are tokens to search AND the substring genuinely occurs, so
    // the exact-token check is doing real work rather than passing by absence.
    expect(allTokens.length).toBeGreaterThan(10);
    expect(allTokens.some((t) => t.includes("unsafe-eval"))).toBe(true);
    expect(allTokens).not.toContain("'unsafe-eval'");
  });

  it("SHIPPED: the rest of dfx 0.28.0's standard policy is unrelaxed", () => {
    const d = directives(shippedPolicy());
    expect(d.get("object-src")).toEqual(["'none'"]);
    expect(d.get("frame-ancestors")).toEqual(["'none'"]);
    expect(d.get("form-action")).toEqual(["'self'"]);
    expect(d.get("base-uri")).toEqual(["'self'"]);
    expect(d.get("default-src")).toEqual(["'self'"]);
  });

  it("SHIPPED: blob: reaches connect-src and worker-src only, never script-src/default-src (WALLET-CSP-BLOB)", () => {
    const d = directives(shippedPolicy());
    expect(d.get("connect-src")).toContain("blob:");
    expect(d.get("worker-src")).toEqual(["'self'", "blob:"]);
    expect(d.get("script-src")).toEqual(["'self'", "'wasm-unsafe-eval'"]);
    expect(d.get("default-src")).toEqual(["'self'"]);
    expect(d.has("child-src")).toBe(false);
  });

  it("the built file is byte-identical to the source it was copied from (E3)", () => {
    expect(readFileSync(BUILT)).toEqual(readFileSync(SOURCE));
  });

  it("the source declares the dfx standard policy alongside the override", () => {
    expect(readFileSync(SOURCE, "utf8")).toMatch(/"security_policy":\s*"standard"/);
  });
});
