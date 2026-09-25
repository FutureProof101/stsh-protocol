// @vitest-environment node
/**
 * J-17b / SSA H-03 — the committed `src/generated/releasePins.json` must equal a
 * FRESH extraction of every `[wasm.*]` row from
 * `deployment/mainnet/release_hashes.toml`.
 *
 * Why an equality arm and not just the build step: the JSON is committed so that
 * `tsc`, vitest and an editor resolve it, and a committed generated file is
 * exactly the kind of artifact that goes stale silently when the record is
 * re-pinned in another lane. The build rewrites it, but a suite that never
 * checks would let a stale copy sit in the tree looking authoritative.
 *
 * This arm re-derives from the RECORD, not from the JSON, so it is not
 * self-inherited: nothing here takes its expected value from the artifact under
 * test. The count is regenerated here too — ten is asserted against the record's
 * own sections, never carried forward as a remembered number.
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

import committed from "../src/generated/releasePins.json";
import { RELEASE_RECORD_PATH, REPO_ROOT } from "../src/release/loadRecord";
import { serialiseWasmPins } from "../src/release/emitPins";
import { extractWasmPins, ROLE_PACKAGE_ALIAS, UNPINNED_ROLES } from "../src/release/wasmPins";
import { ReleaseRecordError } from "../src/release/record";

const RECORD = readFileSync(RELEASE_RECORD_PATH, "utf8");

describe("release pins", () => {
  it("the committed JSON equals a fresh extraction from the record", () => {
    expect(committed).toEqual(extractWasmPins(RECORD));
  });

  it("the committed FILE is byte-identical to what the build step writes", () => {
    const onDisk = readFileSync(
      resolve(REPO_ROOT, "wallet/src/generated/releasePins.json"),
      "utf8",
    );
    expect(onDisk).toBe(serialiseWasmPins(extractWasmPins(RECORD)));
  });

  it("extracts EVERY [wasm.*] section the record declares — count derived, not remembered", () => {
    const sections = RECORD.split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => /^\[\s*wasm\.[^\]]*\]\s*(#.*)?$/.test(l));
    expect(Object.keys(extractWasmPins(RECORD))).toHaveLength(sections.length);
  });

  it("keeps the QUOTED section's package name intact (the stsh-verifier trap)", () => {
    expect(RECORD).toContain('[wasm."stsh-verifier"]');
    const pins = extractWasmPins(RECORD);
    expect(pins["stsh-verifier"]).toMatch(/^[0-9a-f]{64}$/);
    // The naive `split('.')` failure mode would leave a key starting with a quote.
    expect(Object.keys(pins).some((k) => k.includes('"'))).toBe(false);
  });

  it("carries a pin for every BORN_UNDER_VAULT role except the unpinned one", () => {
    const pins = extractWasmPins(RECORD);
    for (const [role, pkg] of Object.entries(ROLE_PACKAGE_ALIAS)) {
      if (UNPINNED_ROLES.includes(role)) {
        expect(pins[pkg]).toBeUndefined();
      } else {
        expect(pins[pkg]).toMatch(/^[0-9a-f]{64}$/);
      }
    }
  });

  it("NEVER reads [wallet_bundle] — the circularity G-01 forbids", () => {
    // The bundle section carries its own sha256 and source_sha. If the extractor
    // ever wandered into it, the emitted map would depend on the digest of the
    // bundle it is compiled into, and the record-only rebind would not reproduce.
    const bundleSha = /\[wallet_bundle\][\s\S]*?sha256\s*=\s*"([0-9a-f]{64})"/.exec(RECORD);
    expect(bundleSha).not.toBeNull();
    expect(Object.values(extractWasmPins(RECORD))).not.toContain(bundleSha![1]);
    expect(Object.keys(extractWasmPins(RECORD))).not.toContain("wallet_bundle");
  });

  it("fails the build rather than degrading on a malformed record", () => {
    expect(() => extractWasmPins("[wasm.a]\nsha256 = \"nope\"\n")).toThrow(ReleaseRecordError);
    expect(() => extractWasmPins("[wasm.a]\npath = \"x\"\n")).toThrow(ReleaseRecordError);
    expect(() =>
      extractWasmPins(`[wasm.a]\nsha256 = "${"0".repeat(64)}"\n[wasm.a]\nsha256 = "${"1".repeat(64)}"\n`),
    ).toThrow(ReleaseRecordError);
    expect(() => extractWasmPins("[build]\nsource_sha = \"x\"\n")).toThrow(ReleaseRecordError);
  });
});

/**
 * WALLET-V12 AC-1 — the HARDEN-04 re-pins, as LITERALS written here from the
 * HARDEN-04 packet / `deployment/mainnet/release_hashes.toml` (not read back
 * from the JSON under test), so a bundle built on a stale record can never pass
 * the gate again: Vault Upgrade forms #29 (pool) and #30 (vesting) are only
 * buildable on a wallet that compiles these two values in.
 */
const HARDEN04_POOL = "dca03f68fbf3ddf4c1bb1c4c36689d9a3dcf124fb5aab2bff50d88cca51afd69";
const HARDEN04_VESTING = "8b9c58600198ed83d426430b55cdac38f61a612773628a82f778c95622225a2e";
/** final-v11's compiled (pre-HARDEN-04) values — must be GONE. */
const PRE_HARDEN04_POOL = "5fa7176e15548db1740fa184842db279b10f5621e1d9400a641caccc82910dc5";
const PRE_HARDEN04_VESTING = "760488eb60d9b23bd3b612b122fb183ea5f9c1525208709e580956cf1ee59b27";

describe("WALLET-V12 AC-1 — the compiled pins are the HARDEN-04 pins", () => {
  it("releasePins.json (the module the bundle compiles in): pool and vesting equal the HARDEN-04 values", () => {
    expect((committed as Record<string, string>).shielded_pool).toBe(HARDEN04_POOL);
    expect((committed as Record<string, string>).vesting).toBe(HARDEN04_VESTING);
    // …and the record agrees (a re-pin in another lane must update both).
    expect(extractWasmPins(RECORD).shielded_pool).toBe(HARDEN04_POOL);
    expect(extractWasmPins(RECORD).vesting).toBe(HARDEN04_VESTING);
  });

  it("the BUILT bundle carries both HARDEN-04 pins and neither final-v11 value (absence fails, never skips)", () => {
    const assets = resolve(REPO_ROOT, "wallet/dist/assets");
    expect(existsSync(assets), "run `npm run build` first — the gate does").toBe(true);
    const js = readdirSync(assets)
      .filter((f) => f.endsWith(".js"))
      .map((f) => readFileSync(join(assets, f), "utf8"))
      .join("\n");
    expect(js).toContain(HARDEN04_POOL);
    expect(js).toContain(HARDEN04_VESTING);
    expect(js).not.toContain(PRE_HARDEN04_POOL);
    expect(js).not.toContain(PRE_HARDEN04_VESTING);
  });
});

/**
 * WALLET-V13 AC-1 — the CURRENT ledger re-pin, as a LITERAL written here from
 * `deployment/mainnet/release_hashes.toml` (not read back from the JSON under
 * test). final-v12 compiled the OLD token pin, so its operator page refused the
 * ledger Vault Upgrade (record §3y); a bundle that compiles anything but this
 * value must never pass again. Moved by TOKEN-APPROVE-TTL (final-v14):
 * 994a77ff… (TOKEN-METADATA, 5e8d54a) → 70786d0d… — a re-pin lane updates this
 * literal, which is exactly what this guard exists to force.
 */
const V13_TOKEN = "70786d0db75b8409b00f7c7b94454c5e9e5c01457302009d2e39f7a7a46aa952";
/** final-v12's compiled (pre-TOKEN-METADATA) token value — must be GONE. */
const PRE_V13_TOKEN = "ac9336f2111b76e25f8afd0957dd5c0c619166c96192e7de5bc8fcf944c354b6";
/** final-v13's compiled (pre-TOKEN-APPROVE-TTL) token value — must be GONE. */
const PRE_APPROVE_TTL_TOKEN = "994a77ff3c34c8b941b18ce6e63c74e42c4963aa0ffcc31404501de31639800b";

/** Every .js under `<dist>/assets`, concatenated; absence FAILS, never skips. */
function bundleJs(dist: string): string {
  const assets = join(dist, "assets");
  expect(existsSync(assets), `${assets} is missing — build/stage it first`).toBe(true);
  return readdirSync(assets)
    .filter((f) => f.endsWith(".js"))
    .map((f) => readFileSync(join(assets, f), "utf8"))
    .join("\n");
}

function expectV13Pins(js: string): void {
  expect(js).toContain(V13_TOKEN);
  expect(js).toContain(HARDEN04_POOL);
  expect(js).toContain(HARDEN04_VESTING);
  expect(js).not.toContain(PRE_V13_TOKEN);
  expect(js).not.toContain(PRE_APPROVE_TTL_TOKEN);
  expect(js).not.toContain(PRE_HARDEN04_POOL);
  expect(js).not.toContain(PRE_HARDEN04_VESTING);
}

/**
 * The STAGED artifact (A1-lite D-4): the `wallet/dist` arm only ever sees the
 * gate's own rebuild, which always agrees with the head — it could not have
 * caught the installed/staged bundle going stale. This arm checks the bundle
 * the lane actually STAGES for install. It runs when the lane names that
 * directory (`STSH_STAGED_WALLET_DIST=~/stsh-walletdeploy/final-v13/dist`);
 * once named, absence FAILS. The gate-side, always-on staleness guard is
 * `verify_custody_manifest` check (9) (ARCHITECTURE.md law 7(g)).
 */
const STAGED = process.env.STSH_STAGED_WALLET_DIST;

describe("WALLET-V13 AC-1 — the compiled pins include the current ledger pin", () => {
  it("releasePins.json: stsh_token equals the current ledger pin, and so does the record", () => {
    expect((committed as Record<string, string>).stsh_token).toBe(V13_TOKEN);
    expect(extractWasmPins(RECORD).stsh_token).toBe(V13_TOKEN);
    expect((committed as Record<string, string>).shielded_pool).toBe(HARDEN04_POOL);
    expect((committed as Record<string, string>).vesting).toBe(HARDEN04_VESTING);
  });

  it("the BUILT bundle (wallet/dist) carries token, pool and vesting pins and no pre-V13 value", () => {
    expectV13Pins(bundleJs(resolve(REPO_ROOT, "wallet/dist")));
  });

  it.runIf(STAGED !== undefined && STAGED !== "")(
    "the STAGED bundle ($STSH_STAGED_WALLET_DIST) carries token, pool and vesting pins and no pre-V13 value",
    () => {
      expectV13Pins(bundleJs(STAGED as string));
    },
  );
});
