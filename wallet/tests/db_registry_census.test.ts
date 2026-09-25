/**
 * L07-04 (R-7 item 6) — the DB registry census.
 *
 * `panicWipe` named two of the three databases this codebase creates because
 * the third declared its name privately inside its own module. This test makes
 * that class of gap impossible to reintroduce quietly.
 *
 * DESIGN: it resolves NO values. It never asks what an identifier evaluates to,
 * which call site a default reaches, or how many hops a name travels. Three
 * purely syntactic conditions:
 *
 *   (a) no `openDB(` / `indexedDB.open(` call passes a STRING LITERAL as its
 *       first argument — no call site may own its own database name;
 *   (b) every file containing such a call imports from `dbRegistry`;
 *   (c) every name constant DECLARED in `dbRegistry.ts` is referenced by at
 *       least one of those files — a declared-but-unwired name is a database
 *       nothing opens and the wipe list may not cover.
 *
 * ...and one condition that is NOT syntactic, added by V1a (CTO ruling
 * `cto-ruling-r7-landed-diff-ambers-2026-09-06`, item 2):
 *
 *   (d) every exported `*_DB_NAME` constant is a MEMBER of `ALL_DB_NAMES`.
 *
 * (d) closes the loop (a)-(c) leave open, demonstrated by the SSA on V1: a
 * fourth database declared in the registry, imported at a real call site and
 * opened there passes (a), (b) and (c) while being absent from `ALL_DB_NAMES`
 * — and `ALL_DB_NAMES` is the ONLY thing `panicWipe`'s fallback path reads
 * (`panicWipe.ts`), so on a browser without `IDBFactory.databases()` that
 * database survives a panic wipe. That is L07-04 reproduced under the test
 * written to prevent it. The `panic_wipe` expectation arms derive their own
 * expectations FROM `ALL_DB_NAMES`, so they cannot notice an omission either
 * (the self-inherited-verification shape); (d) is the only arm that can.
 *
 * (d) reads the module's EXPORTS at test time — a real ESM import, values
 * compared by value — not the source text, so a constant that is exported
 * through any spelling the compiler accepts is still caught.
 *
 * ...plus a floor: finding NOTHING fails, it never passes vacuously.
 *
 * `ALL_DB_NAMES` is deliberately NOT enumerated by (c): the declaration
 * pattern requires a `= "` string initializer, and `ALL_DB_NAMES`'s initializer
 * is `[`. A bare `/_DB_NAMES?\b/` pattern would pick it up, find it referenced
 * only by `panicWipe.ts` — which contains no `openDB(` call and so is not in
 * (a)'s found-file set — and go red at base for a non-defect.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import * as registry from "../src/storage/dbRegistry";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "../src");
const REGISTRY = resolve(SRC, "storage/dbRegistry.ts");

/** Every non-test `.ts` file under `wallet/src`. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return name === "node_modules" ? [] : sourceFiles(full);
    return name.endsWith(".ts") && !name.endsWith(".test.ts") ? [full] : [];
  });
}

interface CallSite {
  file: string;
  line: number;
  firstArg: string;
}

const OPEN_CALL = /(?:\bopenDB|\bindexedDB\.open)\(\s*([^,)]+)[,)]/g;

function callSites(files: string[]): CallSite[] {
  const sites: CallSite[] = [];
  for (const file of files) {
    const lines = readFileSync(file, "utf8").split("\n");
    lines.forEach((text, i) => {
      for (const m of text.matchAll(OPEN_CALL)) {
        sites.push({ file, line: i + 1, firstArg: (m[1] ?? "").trim() });
      }
    });
  }
  return sites;
}

const rel = (f: string): string => relative(SRC, f);

/** Resolves an import specifier against the importing file's own directory. */
function importsRegistry(file: string): boolean {
  const src = readFileSync(file, "utf8");
  for (const m of src.matchAll(/from\s+["']([^"']+)["']/g)) {
    const spec = m[1] ?? "";
    if (!spec.startsWith(".")) continue;
    if (resolve(dirname(file), `${spec}.ts`) === REGISTRY) return true;
  }
  return false;
}

describe("R-7 AC-6a — the DB registry census", () => {
  const files = sourceFiles(SRC);
  const sites = callSites(files);
  const foundFiles = [...new Set(sites.map((s) => s.file))];

  it("finds the call sites at all — a total miss FAILS, it never skips", () => {
    // If `openDB`/`indexedDB.open` is renamed away or a call site's shape
    // changes, every condition below would pass vacuously. This is the floor.
    expect(
      sites.length,
      "no openDB(/indexedDB.open( call sites found under wallet/src at all",
    ).toBeGreaterThanOrEqual(3);
    expect(
      foundFiles.length,
      `expected at least 3 files opening a database, found: ${foundFiles.map(rel).join(", ")}`,
    ).toBeGreaterThanOrEqual(3);
  });

  it("condition (a): no call site inlines its own database name", () => {
    const literals = sites.filter((s) => /^["'`]/.test(s.firstArg));
    expect(
      literals.map((s) => `${rel(s.file)}:${s.line} -> ${s.firstArg}`),
      "a database name must come from dbRegistry.ts, never a literal at the call site",
    ).toEqual([]);
  });

  it("condition (b): every file that opens a database imports from dbRegistry", () => {
    const missing = foundFiles.filter((f) => !importsRegistry(f));
    expect(
      missing.map(rel),
      "these files open a database without importing a name from dbRegistry.ts",
    ).toEqual([]);
  });

  it("condition (c): every declared registry name is wired to a database-opening file", () => {
    const registrySrc = readFileSync(REGISTRY, "utf8");
    // The `= "` anchor is load-bearing: it matches only a scalar string
    // initializer, so `ALL_DB_NAMES` (initializer `[`) is never enumerated.
    const declared = [...registrySrc.matchAll(/^export const ([A-Z0-9_]+_DB_NAME)\s*=\s*"/gm)].map(
      (m) => m[1] as string,
    );
    expect(declared.length, "dbRegistry.ts declares no name constants").toBeGreaterThanOrEqual(3);
    expect(declared).not.toContain("ALL_DB_NAMES");

    const bodies = foundFiles.map((f) => readFileSync(f, "utf8"));
    const unreferenced = declared.filter(
      (name) => !bodies.some((b) => new RegExp(`\\b${name}\\b`).test(b)),
    );
    expect(
      unreferenced,
      "these registry constants are declared but no database-opening file uses them",
    ).toEqual([]);
  });

  it("condition (d): every exported *_DB_NAME is a MEMBER of ALL_DB_NAMES", () => {
    // The module's own exports, at test time — not its source text.
    const exported = Object.entries(registry as Record<string, unknown>).filter(([name]) =>
      /_DB_NAME$/.test(name),
    );
    expect(
      exported.length,
      "dbRegistry.ts exports no *_DB_NAME constants — the census would pass vacuously",
    ).toBeGreaterThanOrEqual(3);

    const all: readonly unknown[] = registry.ALL_DB_NAMES;
    expect(Array.isArray(all), "ALL_DB_NAMES must be an array").toBe(true);

    const omitted = exported
      .filter(([, value]) => !all.includes(value))
      .map(([name, value]) => `${name} (${String(value)})`);
    expect(
      omitted,
      "these exported database names are NOT in ALL_DB_NAMES, so panicWipe's fallback " +
        "path would leave them behind on a browser without IDBFactory.databases()",
    ).toEqual([]);

    // ...and the converse: ALL_DB_NAMES holds nothing that is not a declared
    // constant, so the list cannot drift into carrying an unowned literal.
    const values = new Set(exported.map(([, v]) => v));
    expect(
      all.filter((v) => !values.has(v)).map(String),
      "ALL_DB_NAMES carries names that no exported *_DB_NAME constant declares",
    ).toEqual([]);
  });

  it("no database name string literal is declared outside the registry", () => {
    const offenders = files
      .filter((f) => f !== REGISTRY)
      .flatMap((f) =>
        readFileSync(f, "utf8")
          .split("\n")
          .map((text, i) => ({ f, i, text }))
          .filter(({ text }) => /\bconst\s+[A-Za-z0-9_]*DB_NAME[A-Za-z0-9_]*\s*=\s*["'`]/.test(text))
          .map(({ f: file, i, text }) => `${rel(file)}:${i + 1} -> ${text.trim()}`),
      );
    expect(offenders, "DB name literals belong in dbRegistry.ts and nowhere else").toEqual([]);
  });
});
