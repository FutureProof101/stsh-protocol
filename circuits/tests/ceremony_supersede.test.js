/**
 * ceremony_supersede.test.js — A-4 LANDING (2026-09-12)
 * ─────────────────────────────────────────────────────
 * Asserts the `superseded` contract that A-4 added to verify_ceremony.mjs.
 *
 * WHY THIS EXISTS. A-4 overwrote the artifacts that `ceremony_material.m5`
 * pins (circuits/build/spend_1.zkey, circuits/verification_key.json) with the
 * production ceremony outputs. m5 can therefore never be measured again, and
 * the manifest says so with a `superseded` key instead of leaving the m5 run
 * permanently RED for the wrong reason (A-3 SSA F1).
 *
 * A skip mechanism is dangerous in exactly one way: if it ever attached to the
 * LIVE generation, the gate would report a green ceremony while checking
 * nothing. Both halves of the contract are asserted here:
 *
 *   T1  `ceremony_material.next` does NOT carry `superseded`.
 *   T2  `--generation m5` emits zero PASS lines and zero FAIL lines, at least
 *       one SKIP line, and names the superseding generation.
 *   T3  it exits 0.
 *   T4  it reads no artifact file.
 *
 * T4 is proved BEHAVIOURALLY, not by reading the implementation. The test first
 * measures, first-hand, that the bytes now at m5's own vk path hash to something
 * DIFFERENT from m5.vk.sha256. Any implementation that actually opened that file
 * would have had to emit a C5 FAIL. Zero FAIL lines, given a genuine and
 * independently measured mismatch, is therefore evidence the file was not read —
 * rather than evidence that the pins happen to agree.
 *
 * Usage:  cd circuits && node tests/ceremony_supersede.test.js
 */

"use strict";

const { execFileSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { readFileSync, existsSync } = require("node:fs");
const { resolve } = require("node:path");

const CIRCUITS = resolve(__dirname, "..");
const ROOT = resolve(CIRCUITS, "..");
const MANIFEST = resolve(CIRCUITS, "ceremony/domain_manifest.json");
const CHECKER = resolve(CIRCUITS, "scripts/verify_ceremony.mjs");

let failures = 0;
const ok = (name, cond, detail) => {
  console.log(`  ${cond ? "ok  " : "FAIL"}  ${name}`);
  if (!cond) {
    failures += 1;
    if (detail) console.log(`        ${detail}`);
  }
};

console.log("── ceremony supersede contract (A-4) ──");

const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
const m5 = manifest.ceremony_material.m5;
const next = manifest.ceremony_material.next;

// ── T1 — the live generation must never be skippable ─────────────────────────
ok(
  "T1  ceremony_material.next does NOT carry `superseded`",
  !Object.prototype.hasOwnProperty.call(next, "superseded"),
  "the LIVE generation carries a supersede marker — the gate would skip every check and still exit 0",
);

ok(
  "T1b ceremony_material.m5 DOES carry `superseded` naming its successor",
  !!(m5.superseded && m5.superseded.by === "next" && String(m5.superseded.reason || "").length > 40),
  "m5 must declare by/reason so the skip is recorded, not implicit",
);

// ── T4 setup — an INDEPENDENT measurement that m5's pins are genuinely stale ──
// This is what makes T2's "zero FAIL lines" meaningful rather than circular.
const m5VkPath = resolve(ROOT, m5.vk.path);
ok("T4a m5's declared vk path still exists on disk", existsSync(m5VkPath), m5VkPath);
const liveVkHash = createHash("sha256").update(readFileSync(m5VkPath)).digest("hex");
ok(
  "T4b bytes at m5's vk path DIFFER from m5.vk.sha256 (measured first-hand)",
  liveVkHash !== m5.vk.sha256,
  `live ${liveVkHash} vs pin ${m5.vk.sha256} — if these were equal, T2 would prove nothing`,
);

// ── T2/T3 — run the checker over the superseded generation ───────────────────
let out;
let exitCode = 0;
try {
  out = execFileSync("node", [CHECKER, "--generation", "m5"], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 32 * 1024 * 1024,
  });
} catch (e) {
  out = `${e.stdout || ""}${e.stderr || ""}`;
  exitCode = typeof e.status === "number" ? e.status : 1;
}

const lines = out.split("\n");
const statusLines = lines.filter((l) => /^\[(PASS|FAIL|SKIP)/.test(l.trim()));
const passLines = statusLines.filter((l) => /^\[PASS/.test(l.trim()));
const failLines = statusLines.filter((l) => /^\[FAIL/.test(l.trim()));
const skipLines = statusLines.filter((l) => /^\[SKIP/.test(l.trim()));

ok("T3  exit status is 0", exitCode === 0, `exit ${exitCode}`);
ok("T2a zero PASS lines", passLines.length === 0, `${passLines.length} PASS line(s)`);
ok(
  "T2b zero FAIL lines (with T4b proving a file read WOULD have failed)",
  failLines.length === 0,
  `${failLines.length} FAIL line(s)`,
);
ok("T2c at least one SKIP line", skipLines.length > 0, `${skipLines.length} SKIP line(s)`);
ok(
  "T2d every check C0-C6 is reported",
  ["C0", "C1", "C2", "C3", "C4", "C5", "C6"].every((id) =>
    skipLines.some((l) => l.includes(` ${id} `)),
  ),
  `skipped: ${skipLines.length}`,
);
ok(
  "T2e the summary NAMES the superseding generation",
  /── summary ──/.test(out) && /superseded by 'next'/.test(out),
  "summary must tell the reader what to verify instead",
);
ok(
  "T2f no 'evidence incomplete' verdict is printed for a superseded generation",
  !/CEREMONY EVIDENCE INCOMPLETE/.test(out),
  "a superseded generation is not an incomplete one",
);

console.log("");
if (failures) {
  console.log(`ceremony supersede contract: ${failures} assertion(s) FAILED`);
  process.exit(1);
}
console.log("ceremony supersede contract: all assertions passed");
