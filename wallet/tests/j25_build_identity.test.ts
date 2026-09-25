/**
 * J-25 D-1 / D-2 — the ONE injected release-record value.
 *
 * D-1 build identity: the emitted value is `[build].source_sha`, never HEAD,
 * never a constant, never a similarly named key from another section; a missing
 * or malformed value FAILS the build.
 * D-2 pin independence: perturbing any `[wallet_bundle]` field, with
 * `[build].source_sha` held fixed, leaves the injection byte-identical — which
 * is what makes the record-only child R reproducible (I2).
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { canisterBuildSource } from "../src/release/buildSource";
import { RELEASE_RECORD_PATH, REPO_ROOT, releaseDefines } from "../src/release/loadRecord";
import {
  BUILD_SOURCE_DEFINE,
  buildReleaseDefines,
  ReleaseRecordError,
  selectBuildSourceSha,
} from "../src/release/record";


const RECORD = readFileSync(RELEASE_RECORD_PATH, "utf8");

describe("J-25 D-1 — selection is section-bound and validated", () => {
  it("selects [build].source_sha, not the [wallet_bundle] pin", () => {
    const toml = [
      "[build]",
      'source_sha = "1111111111111111111111111111111111111111"',
      "",
      "[wallet_bundle]",
      'source_sha = "2222222222222222222222222222222222222222"',
    ].join("\n");
    expect(selectBuildSourceSha(toml)).toBe("1111111111111111111111111111111111111111");
  });

  it("ignores decoy source_sha keys in every other section", () => {
    const toml = [
      "[toolchain]",
      'source_sha = "3333333333333333333333333333333333333333"',
      '[wasm."stsh-verifier"]',
      'source_sha = "4444444444444444444444444444444444444444"',
      "[build]",
      'source_sha = "5555555555555555555555555555555555555555"',
      "[wallet_bundle.reproduction]",
      'source_sha = "6666666666666666666666666666666666666666"',
    ].join("\n");
    expect(selectBuildSourceSha(toml)).toBe("5555555555555555555555555555555555555555");
  });

  it("does not select a key that merely contains 'source_sha'", () => {
    expect(() =>
      selectBuildSourceSha('[build]\nbuild_source_sha = "' + "a".repeat(40) + '"'),
    ).toThrow(ReleaseRecordError);
  });

  it("ignores a commented-out declaration", () => {
    const toml = [
      "[build]",
      '# source_sha = "' + "e".repeat(40) + '"',
      'source_sha = "' + "7".repeat(40) + '"',
    ].join("\n");
    expect(selectBuildSourceSha(toml)).toBe("7".repeat(40));
  });

  it("FAILS when [build].source_sha is missing", () => {
    expect(() => selectBuildSourceSha("[build]\nprofile = \"release\"")).toThrow(
      /no \[build\]\.source_sha/,
    );
  });

  it("FAILS on a malformed value rather than emitting it", () => {
    for (const bad of [
      "",
      "deadbeef",
      "A".repeat(40),
      "g".repeat(40),
      "0".repeat(39),
      "0".repeat(41),
    ]) {
      expect(() => selectBuildSourceSha(`[build]\nsource_sha = "${bad}"`), bad).toThrow(
        /not a full 40-hex commit id/,
      );
    }
  });

  it("FAILS rather than guessing on a duplicate declaration", () => {
    expect(() =>
      selectBuildSourceSha(
        ["[build]", 'source_sha = "' + "1".repeat(40) + '"', 'source_sha = "' + "2".repeat(40) + '"'].join(
          "\n",
        ),
      ),
    ).toThrow(/more than once/);
  });

  it("FAILS the build when the record file cannot be read", () => {
    expect(() => releaseDefines("/nonexistent/release_hashes.toml")).toThrow(ReleaseRecordError);
  });

  it("selects a SECOND valid value too — nothing here is hardcoded", () => {
    const other = "b".repeat(40);
    expect(
      selectBuildSourceSha(RECORD.replace(/^source_sha = "[0-9a-f]{40}"/m, `source_sha = "${other}"`)),
    ).toBe(other);
  });
});

describe("J-25 D-1 — the value the BUNDLE carries", () => {
  const recorded = selectBuildSourceSha(RECORD);

  it("the injected define is exactly the record's [build].source_sha", () => {
    expect(canisterBuildSource()).toBe(recorded);
    expect(releaseDefines()).toEqual({ [BUILD_SOURCE_DEFINE]: JSON.stringify(recorded) });
  });

  // THE ANTI-HEAD FIXTURE. This lane's commit is a descendant of the frozen
  // build source, so HEAD and the recorded value DIFFER — an implementation
  // that emitted `git rev-parse HEAD` would emit a different string here. The
  // precondition is asserted, not assumed: if they ever coincided the test
  // above would stop distinguishing the two implementations.
  it("is NOT this checkout's HEAD", () => {
    const head = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
    }).trim();
    expect(head, "fixture precondition: HEAD must differ from [build].source_sha").not.toBe(
      recorded,
    );
    expect(canisterBuildSource()).not.toBe(head);
  });

  // THE ANTI-CONSTANT CHECK. No module on the render path may contain a 40-hex
  // literal: wiring a constant in place of the injected define would have to
  // write one, and this fails on sight.
  it("no module on the panel's path contains a hardcoded commit id", () => {
    for (const rel of [
      "../src/release/buildSource.ts",
      "../src/release/walletPanel.ts",
      "../src/ui/releaseFooter.ts",
    ]) {
      const src = readFileSync(resolve(REPO_ROOT, "wallet/tests", rel), "utf8");
      expect(src, `${rel} carries a 40-hex literal`).not.toMatch(/\b[0-9a-f]{40}\b/);
    }
  });
});

/**
 * Perturb EVERY key inside `[wallet_bundle]` and its subtables, section-aware.
 *
 * Deliberately not a literal search-and-replace: an earlier draft matched the
 * recorded `source_sha` string, which the record-only child then changed —
 * making the test depend on the very row it exists to prove is irrelevant. The
 * rewriter below is bound to the SECTION, so it keeps biting whatever those
 * rows happen to say.
 */
function perturbWalletBundle(toml: string): string {
  let section = "";
  return toml
    .split("\n")
    .map((line) => {
      const sec = /^\[\s*([^\]]+?)\s*\]/.exec(line.trim());
      if (sec !== null) {
        section = sec[1];
        return line;
      }
      if (!(section === "wallet_bundle" || section.startsWith("wallet_bundle."))) return line;
      const kv = /^(\s*)([A-Za-z0-9_-]+)(\s*)=(\s*)(.*)$/.exec(line);
      if (kv === null) return line;
      const [, indent, key, sp1, sp2, value] = kv;
      const perturbedValue = /^"/.test(value)
        ? `"PERTURBED-${key}"`
        : /^(true|false)\b/.test(value)
          ? value.startsWith("true")
            ? "false"
            : "true"
          : "987654321";
      return `${indent}${key}${sp1}=${sp2}${perturbedValue}`;
    })
    .join("\n");
}

describe("J-25 D-2 — pin independence", () => {
  it("perturbing every [wallet_bundle] field leaves the injection identical", () => {
    const perturbed = perturbWalletBundle(RECORD);
    expect(perturbed, "the perturbation must actually change the record").not.toBe(RECORD);
    // It really did rewrite the wallet pin, including its own source_sha.
    expect(perturbed).toContain('"PERTURBED-sha256"');
    expect(perturbed).toContain('"PERTURBED-source_sha"');
    expect(perturbed).toContain('"PERTURBED-method"');
    expect(perturbed).toMatch(/^files\s*=\s*987654321$/m);
    expect(perturbed).toMatch(/^bytes\s*=\s*987654321$/m);
    expect(perturbed).toMatch(/^builds\s*=\s*987654321$/m);
    // ...and left [build] alone, which is what the claim below is about.
    expect(buildReleaseDefines(perturbed)).toEqual(buildReleaseDefines(RECORD));
  });

  it("the define map is the WHOLE record-derived injection surface", () => {
    // If a second record-derived value were ever injected, it would appear
    // here — and the pin-independence claim above would have to cover it too.
    expect(Object.keys(buildReleaseDefines(RECORD))).toEqual([BUILD_SOURCE_DEFINE]);
  });

  it("moving [build].source_sha DOES move the injection (the test is not vacuous)", () => {
    const moved = RECORD.replace(
      /^source_sha = "[0-9a-f]{40}"/m,
      'source_sha = "' + "d".repeat(40) + '"',
    );
    expect(buildReleaseDefines(moved)).not.toEqual(buildReleaseDefines(RECORD));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RED-3 (SSA landed-diff 2026-09-09) — the PRODUCTION Vite config.
//
// Everything above binds helpers. The acceptance suite ran under
// `vitest.config.ts`, which calls `releaseDefines()` independently, so nothing
// bound `wallet/vite.config.ts` itself: the SSA replaced its
// `define: releaseDefines()` with a literal commit id, all 51 J-25 tests stayed
// green, and a real build then shipped the WRONG source label. These tests load
// the shipped config file with Vite's own loader against fixture records and
// assert the resolved define. A literal cannot equal two different fixtures, so
// that mutation fails here.
// ─────────────────────────────────────────────────────────────────────────────

const PRODUCTION_VITE_CONFIG = resolve(REPO_ROOT, "wallet/vite.config.ts");
const DEFINE_DRIVER = resolve(REPO_ROOT, "wallet/tests/helpers/resolveViteDefine.mjs");

/** A minimal record: a `[build]` block plus a decoy `[wallet_bundle]` pin. */
function fixtureRecord(buildSha: string, walletSha = "e".repeat(40)): string {
  return [
    "# fixture release record (J-25 RED-3)",
    "[build]",
    `source_sha = "${buildSha}"`,
    "",
    "[wallet_bundle]",
    `source_sha = "${walletSha}"`,
    'sha256 = "' + "f".repeat(64) + '"',
    "",
  ].join("\n");
}

/**
 * Evaluate the production config in a process whose cwd is a throwaway tree
 * holding `record` (or holding no record at all when `record` is null).
 */
function resolveProductionDefine(record: string | null): Record<string, string> {
  const root = mkdtempSync(join(tmpdir(), "j25-vite-"));
  try {
    const wallet = join(root, "wallet");
    mkdirSync(wallet, { recursive: true });
    if (record !== null) {
      const dir = join(root, "deployment", "mainnet");
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "release_hashes.toml"), record, "utf8");
    }
    const out = execFileSync(process.execPath, [DEFINE_DRIVER, PRODUCTION_VITE_CONFIG], {
      cwd: wallet,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const parsed = JSON.parse(out) as { path: string; define: Record<string, string> | null };
    // The loader really did read the shipped file, not something generated.
    expect(parsed.path).toBe(PRODUCTION_VITE_CONFIG);
    expect(parsed.define, "the production config emits no define at all").not.toBeNull();
    return parsed.define as Record<string, string>;
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe("J-25 RED-3 — the PRODUCTION vite.config.ts injects the record value", () => {
  const A = "1a".repeat(20);
  const B = "9b7c".repeat(10);

  it("emits the record's [build].source_sha, not HEAD and not a constant", () => {
    const head = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
    }).trim();
    expect(head).toMatch(/^[0-9a-f]{40}$/);
    expect(A, "the fixture must differ from HEAD for this test to bite").not.toBe(head);

    const define = resolveProductionDefine(fixtureRecord(A));
    expect(Object.keys(define)).toEqual([BUILD_SOURCE_DEFINE]);
    expect(define[BUILD_SOURCE_DEFINE]).toBe(JSON.stringify(A));
    expect(define[BUILD_SOURCE_DEFINE]).not.toContain(head);
    // Vite and Vitest share ONE define source, and this is it.
    expect(define).toEqual(buildReleaseDefines(fixtureRecord(A)));
  });

  it("a SECOND record value moves the injection — the config reads, it does not hardcode", () => {
    expect(B).not.toBe(A);
    const define = resolveProductionDefine(fixtureRecord(B));
    expect(define[BUILD_SOURCE_DEFINE]).toBe(JSON.stringify(B));
  });

  it("it selects the [build] occurrence, never the [wallet_bundle] pin", () => {
    const walletPin = "7c".repeat(20);
    const define = resolveProductionDefine(fixtureRecord(A, walletPin));
    expect(define[BUILD_SOURCE_DEFINE]).toBe(JSON.stringify(A));
    expect(define[BUILD_SOURCE_DEFINE]).not.toContain(walletPin);
  });

  it("a MISSING record FAILS the production config load — there is no fallback", () => {
    let stderr = "";
    try {
      resolveProductionDefine(null);
      expect.unreachable("the production config loaded with no release record");
    } catch (e) {
      stderr = String((e as { stderr?: string }).stderr ?? (e as Error).message);
    }
    expect(stderr).toMatch(/cannot locate deployment\/mainnet\/release_hashes\.toml/);
  });

  it("a MALFORMED [build].source_sha FAILS the production config load", () => {
    let stderr = "";
    try {
      resolveProductionDefine(fixtureRecord("not-a-commit-id"));
      expect.unreachable("the production config loaded a malformed source_sha");
    } catch (e) {
      stderr = String((e as { stderr?: string }).stderr ?? (e as Error).message);
    }
    expect(stderr).toMatch(/not a full 40-hex commit id/);
  });

  it("an ABSENT [build] section FAILS the production config load", () => {
    let stderr = "";
    try {
      resolveProductionDefine('[wallet_bundle]\nsource_sha = "' + "e".repeat(40) + '"\n');
      expect.unreachable("the production config loaded a record with no [build]");
    } catch (e) {
      stderr = String((e as { stderr?: string }).stderr ?? (e as Error).message);
    }
    expect(stderr).toMatch(/no \[build\]\.source_sha/);
  });

  it("the shipped config's define comes from releaseDefines and nothing else", () => {
    const src = readFileSync(PRODUCTION_VITE_CONFIG, "utf8");
    // A defence in depth for the behavioural tests above, not a substitute:
    // the define must be the shared loader's call, with no literal beside it.
    expect(src).toMatch(/define:\s*releaseDefines\(\)/);
    expect(src).not.toMatch(/[0-9a-f]{40}/);
    const vitest = readFileSync(resolve(REPO_ROOT, "wallet/vitest.config.ts"), "utf8");
    expect(vitest).toMatch(/define:\s*releaseDefines\(\)/);
  });
});
