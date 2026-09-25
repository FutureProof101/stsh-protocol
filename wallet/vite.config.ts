import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { copyFileSync, rmSync } from "node:fs";

import { defineConfig, type Plugin } from "vite";

import { emitReleasePins } from "./src/release/emitPins";
import { releaseDefines } from "./src/release/loadRecord";

const WALLET_ROOT = dirname(fileURLToPath(import.meta.url));

/**
 * J-17b: re-emit `src/generated/releasePins.json` from the record's `[wasm.*]`
 * rows before the graph is read, so the operator page's install-artifact check
 * can never be compiled against a stale committed copy. `[wallet_bundle]` is
 * not read (SSA G-01) — the emitted map is the ten Wasm pins and nothing else,
 * so this step cannot make the bundle depend on its own digest.
 */
function releasePinsPlugin(): Plugin {
  return {
    name: "stsh-release-pins",
    buildStart() {
      emitReleasePins(WALLET_ROOT);
    },
  };
}

/**
 * WT-1b — the TRANSITIONAL vs FINAL launch-config variant.
 *
 * WT-1 schedules TWO installs on the wallet asset canister `s3tyu` from ONE
 * source tree (brief V3 Phase B.1 and Phase D.8):
 *
 *   B.1 TRANSITIONAL — `wallet-config.json` carries NO `derivationOrigin`, so a
 *       login at `app.stsh.fi` still derives from the alias and yields the OLD
 *       II principals. That is the point: the OLD Vault/Upgrader signers must be
 *       able to sign the step-7 rotation, and they can only do so as the
 *       principals the alias produces. Logins at the native `s3tyu` origin
 *       already yield the NEW principals, which is how Phase B.2 collects them.
 *   D.8 FINAL — `wallet-config.json` carries `derivationOrigin`, so BOTH origins
 *       derive from the native origin and every user has one principal.
 *
 * SSA rehearsal R-3 (CRITICAL) recorded what happens if the final bundle is
 * installed as the transitional one: `app.stsh.fi` logins silently re-root, the
 * old principals become unproducible, the Vault is reachable only as the machine
 * signer (1 of a threshold of 2), and the rotation cannot be proposed or
 * approved. Nothing errors. So the transitional deployment is built here, as a
 * committed, measurable artifact — NOT as a hand edit of `dist` after the build,
 * which was the only procedure that existed before this lane.
 *
 * The CODE is identical across the two variants. Only the emitted
 * `wallet-config.json` asset differs, and it differs only by the presence of the
 * `derivationOrigin` key (asserted in `tests/wt1b_transitional_bundle.test.ts`).
 *
 * `wallet-config.transitional.json` lives in `public/` so it is committed and
 * reviewable next to the config it varies, but it is REMOVED from `dist` in both
 * variants: it is a build INPUT, never a served asset. Shipping it would add a
 * twelfth file to the measured bundle and would serve a second, contradictory
 * config at a guessable path.
 *
 * FAILS CLOSED on an unrecognised `WALLET_CONFIG_VARIANT`. A typo must not
 * silently produce the final bundle under a transitional label — that is R-3's
 * failure mode with a different cause.
 */
const CONFIG_VARIANT_ENV = "WALLET_CONFIG_VARIANT";
const FINAL_CONFIG = "wallet-config.json";
const TRANSITIONAL_CONFIG = "wallet-config.transitional.json";

function walletConfigVariantPlugin(): Plugin {
  const raw = process.env[CONFIG_VARIANT_ENV];
  const variant = raw === undefined || raw === "" ? "final" : raw;
  if (variant !== "final" && variant !== "transitional") {
    throw new Error(
      `${CONFIG_VARIANT_ENV}="${raw}" is not a recognised wallet config variant. ` +
        `Use "final" (the default, Phase D.8) or "transitional" (Phase B.1).`,
    );
  }
  return {
    name: "stsh-wallet-config-variant",
    apply: "build",
    closeBundle() {
      const dist = join(WALLET_ROOT, "dist");
      if (variant === "transitional") {
        // Overwrite AFTER vite has copied `public/`, so the emitted asset is the
        // transitional one at the one path the wallet ever fetches
        // (`launchConfig.ts` LAUNCH_CONFIG_PATH is relative and same-origin).
        copyFileSync(join(dist, TRANSITIONAL_CONFIG), join(dist, FINAL_CONFIG));
      }
      // Both variants: the variant SOURCE is never served.
      rmSync(join(dist, TRANSITIONAL_CONFIG), { force: true });
      this.info(`wallet config variant: ${variant}`);
    },
  };
}

// Vanilla TS wallet build. ES workers (scanner/prover) and the poseidon wasm
// asset are emitted as-is; no framework plugin. `base: ""` keeps asset URLs
// relative so the bundle serves correctly from an IC asset canister.
//
// J-25 (I1): the ONLY build-time injection is `[build].source_sha` from
// deployment/mainnet/release_hashes.toml. `releaseDefines` throws — and so the
// build fails — if that value is missing or is not a full 40-hex commit id.
// Nothing else from the record is injected, which is what makes the
// record-only child R reproducible (I2).
export default defineConfig({
  base: "",
  plugins: [releasePinsPlugin(), walletConfigVariantPlugin()],
  define: releaseDefines(),
  build: {
    target: "es2022",
    outDir: "dist",
    emptyOutDir: true,
  },
  worker: {
    format: "es",
  },
});
