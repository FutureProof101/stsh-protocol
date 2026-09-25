// @vitest-environment node
/**
 * WT-1b — the TRANSITIONAL (Phase B.1) launch-config variant.
 *
 * WHY THIS FILE EXISTS. SSA rehearsal risk R-3
 * (`reviews/SSA_REHEARSAL_MAINNET_SEQUENCE_R1_2026-09-14.md`, CRITICAL) found
 * that the WT-1 lane shipped ONE bundle for TWO scheduled installs. Brief V3
 * Phase B.1 requires a bundle that forwards NO `derivationOrigin`, so that a
 * login at `https://app.stsh.fi` still yields the OLD II principals — the ones
 * the old Vault and Upgrader signers must hold to propose and approve the
 * step-7 rotation. Phase D.8 requires the opposite. The landed bundle carries
 * `derivationOrigin`, and installing it as "transitional" re-roots the alias
 * SILENTLY: no error, the old principals become unproducible, the Vault is
 * reachable only as the machine signer (1 of a threshold of 2), and the
 * rotation deadlocks.
 *
 * So the transitional deployment is now a BUILT, COMMITTED, MEASURABLE artifact
 * (`npm run build:transitional`), not a hand edit of `dist`, and these arms are
 * what stop the two variants from drifting into differing by anything other
 * than the one key they are supposed to differ by.
 *
 * INDEPENDENT EXPECTED SIDE, as in `wt1_canister_rooted_identity.test.ts` and
 * `origin_policy_s102.test.ts`: every expected value here is a literal written
 * in THIS file. The origins are not imported from `config.ts`, and the variant
 * file is not compared against itself.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluateSessionPolicy, permittedServingOrigins, resolveConfig } from "../src/session/config";
import { normaliseLaunchOrigin } from "../src/session/launchConfig";

const here = dirname(fileURLToPath(import.meta.url));
const walletRoot = resolve(here, "..");

/** The DNS alias — the origin BOTH variants are served from. Literal. */
const ALIAS_ORIGIN = "https://app.stsh.fi";
/** The pinned wallet-canister origin. Literal. */
const NATIVE_ORIGIN = "https://s3tyu-aaaaa-aaaab-qhdjq-cai.icp0.io";

const FINAL_PATH = resolve(walletRoot, "public/wallet-config.json");
const TRANSITIONAL_PATH = resolve(walletRoot, "public/wallet-config.transitional.json");

const readConfig = (path: string): Record<string, unknown> =>
  JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;

/**
 * Build a `WalletConfig` the way `app.ts` does at runtime: the defaults, plus
 * the two fields the same-origin config asset contributes, passed through the
 * SAME shape validator the loader uses. `loadDerivationOrigin` returns
 * `undefined` when the key is absent, so an absent key must reach the policy as
 * `undefined` and not as a missing property with some other meaning.
 */
const configFromAsset = (asset: Record<string, unknown>) => ({
  ...resolveConfig({}),
  launchOrigin: normaliseLaunchOrigin(asset.launchOrigin),
  derivationOrigin:
    asset.derivationOrigin === undefined ? undefined : normaliseLaunchOrigin(asset.derivationOrigin),
});

describe("WT-1b — the transitional config asset is exactly the final one minus derivationOrigin", () => {
  it("the transitional asset omits the KEY, rather than setting it to null or empty", () => {
    const transitional = readConfig(TRANSITIONAL_PATH);
    // `in`, not a truthiness check: `{"derivationOrigin": null}` and
    // `{"derivationOrigin": ""}` both reach the policy as a value it must
    // refuse, which would block login instead of producing the old principals.
    expect("derivationOrigin" in transitional).toBe(false);
    expect(transitional.launchOrigin).toBe(ALIAS_ORIGIN);
  });

  it("the final asset carries the pinned native origin (the Phase D.8 shape)", () => {
    const final = readConfig(FINAL_PATH);
    expect(final.launchOrigin).toBe(ALIAS_ORIGIN);
    expect(final.derivationOrigin).toBe(NATIVE_ORIGIN);
  });

  it("the two assets differ by the derivationOrigin key and by NOTHING else", () => {
    // The whole risk this lane closes is a transitional bundle that differs from
    // the final one in some second, unnoticed way — a stale launchOrigin, a
    // dropped field a later lane adds. Asserted as a SET comparison over keys
    // plus a value comparison over the shared keys, so a new field added to one
    // file and not the other fails here rather than at the ceremony.
    const final = readConfig(FINAL_PATH);
    const transitional = readConfig(TRANSITIONAL_PATH);

    const finalKeys = Object.keys(final).sort();
    const transitionalKeys = Object.keys(transitional).sort();
    expect(finalKeys.filter((k) => k !== "derivationOrigin")).toEqual(transitionalKeys);
    expect(finalKeys).toContain("derivationOrigin");

    for (const key of transitionalKeys) {
      expect([key, transitional[key]]).toEqual([key, final[key]]);
    }
  });
});

describe("WT-1b — the session policy reads the absent key as 'transitional', not as a refusal", () => {
  it("both serving origins are accepted under the transitional asset", () => {
    const config = configFromAsset(readConfig(TRANSITIONAL_PATH));
    for (const origin of [ALIAS_ORIGIN, NATIVE_ORIGIN]) {
      const policy = evaluateSessionPolicy(config, origin);
      expect(policy.kind).toBe("production");
    }
    expect([...permittedServingOrigins(config)].sort()).toEqual([ALIAS_ORIGIN, NATIVE_ORIGIN].sort());
  });

  it("NO derivationOrigin is carried under the transitional asset, at either origin", () => {
    // This is the property the rotation depends on. If anything is carried here,
    // `auth.ts` forwards it to `AuthClient.login`, `app.stsh.fi` derives from the
    // native origin, and the OLD signer principals cease to be producible.
    const config = configFromAsset(readConfig(TRANSITIONAL_PATH));
    for (const origin of [ALIAS_ORIGIN, NATIVE_ORIGIN]) {
      const policy = evaluateSessionPolicy(config, origin);
      expect(policy.kind).toBe("production");
      if (policy.kind === "production") expect(policy.derivationOrigin).toBeUndefined();
    }
  });

  it("the final asset DOES carry it — the contrast, so the arm above cannot pass vacuously", () => {
    // Without this pair, an `evaluateSessionPolicy` that dropped derivationOrigin
    // entirely would make the transitional arm green while the D.8 bundle was
    // just as inert. Same helper, same call, opposite expectation.
    const config = configFromAsset(readConfig(FINAL_PATH));
    for (const origin of [ALIAS_ORIGIN, NATIVE_ORIGIN]) {
      const policy = evaluateSessionPolicy(config, origin);
      expect(policy.kind).toBe("production");
      if (policy.kind === "production") expect(policy.derivationOrigin).toBe(NATIVE_ORIGIN);
    }
  });

  it("the transitional asset still fails closed if its launchOrigin is lost", () => {
    // Absent `derivationOrigin` is permitted; absent `launchOrigin` is not, and
    // the transitional variant must not have weakened that (S1-02).
    const config = { ...configFromAsset(readConfig(TRANSITIONAL_PATH)), launchOrigin: undefined };
    const policy = evaluateSessionPolicy(config, ALIAS_ORIGIN);
    expect(policy.kind).toBe("blocked");
    if (policy.kind === "blocked") expect(policy.reason).toMatch(/wallet-config\.json/i);
  });

  it("a third origin is still refused under the transitional asset", () => {
    const config = configFromAsset(readConfig(TRANSITIONAL_PATH));
    for (const rogue of ["https://staging.stsh.fi", "https://app.stsh.fi.evil.example", "https://stsh.fi"]) {
      expect(evaluateSessionPolicy(config, rogue).kind).toBe("blocked");
    }
  });
});

describe("WT-1b — the variant SOURCE is a build input, never a served asset", () => {
  it("the build config wires the variant plugin and removes the variant source from dist", () => {
    // Asserted over the build config's source rather than over `dist`, because
    // the gate's wallet leg runs against whichever variant was built last and
    // this property must hold for BOTH. The dist-side evidence is the file count
    // recorded in `deployment/mainnet/release_hashes.toml` (11 for both bundles).
    const config = readFileSync(resolve(walletRoot, "vite.config.ts"), "utf8");
    expect(config).toContain("walletConfigVariantPlugin()");
    expect(config).toContain('const TRANSITIONAL_CONFIG = "wallet-config.transitional.json";');
    expect(config).toContain("rmSync(join(dist, TRANSITIONAL_CONFIG), { force: true })");
  });

  it("package.json exposes the transitional build and leaves the default build final", () => {
    const pkg = JSON.parse(readFileSync(resolve(walletRoot, "package.json"), "utf8")) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts["build:transitional"]).toBe("WALLET_CONFIG_VARIANT=transitional npm run build");
    // The DEFAULT build must not mention the variant at all: the final bundle is
    // what every ordinary build and every gate run produces.
    expect(pkg.scripts.build).not.toContain("WALLET_CONFIG_VARIANT");
  });
});
