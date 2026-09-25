#!/usr/bin/env node
/**
 * verify_spend_artifacts.mjs — L3c prebuild gate (Option A artifact ruling).
 *
 * Verifies the two TRACKED production proving artifacts byte-exactly (length
 * + SHA-256) BEFORE anything bundles, then copies them into a CLEAN,
 * regenerated Vite staging directory (wallet/public/zk/ — gitignored, never
 * committed; the rule is "no second duplicate copy under wallet/" — this dir
 * is a build product, wiped and recreated every time).
 *
 * Fails the build on any mismatch. Hashes are pinned here AND in
 * wallet/src/zk/spendManifest.json — distinct fields, never substituted:
 *   zkey artifact file hash  : 4898655e… (spend_1.zkey)
 *   witness-wasm file hash   : 3e910987… (spend_js/spend.wasm)
 *   exported VK / pool pin   : 84dba305… (checked by the runtime handler
 *                                          against the pool attestation,
 *                                          NOT against these files)
 */
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const STAGING = resolve(ROOT, "wallet/public/zk");

const ARTIFACTS = [
  {
    src: "circuits/build/spend_1.zkey",
    out: "spend_1.zkey",
    sha256: "4898655e8b3c3de9517f649f7caf8366ff4f9c95190ac274d5859de58f21e80c",
    bytes: 7527594,
  },
  {
    src: "circuits/build/spend_js/spend.wasm",
    out: "spend.wasm",
    sha256: "3e910987203d8e3b42e1b656d21aa4dffce23cad0f1dd84f6f093fce6fbf4585",
    bytes: 3818474,
  },
];

let failed = false;
for (const a of ARTIFACTS) {
  const path = resolve(ROOT, a.src);
  let buf;
  try {
    buf = readFileSync(path);
  } catch {
    console.error(`FATAL: missing proving artifact ${a.src}`);
    failed = true;
    continue;
  }
  const len = statSync(path).size;
  const hash = createHash("sha256").update(buf).digest("hex");
  if (len !== a.bytes || hash !== a.sha256) {
    console.error(
      `FATAL: ${a.src} failed verification\n  expected ${a.bytes} bytes / sha256 ${a.sha256}\n  got      ${len} bytes / sha256 ${hash}`,
    );
    failed = true;
  }
}
if (failed) process.exit(1);

// Clean, regenerated staging (never a committed duplicate).
rmSync(STAGING, { recursive: true, force: true });
mkdirSync(STAGING, { recursive: true });
for (const a of ARTIFACTS) {
  copyFileSync(resolve(ROOT, a.src), resolve(STAGING, a.out));
}
console.log(`spend artifacts verified + staged to ${STAGING}`);
