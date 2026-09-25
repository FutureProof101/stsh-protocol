/**
 * WALLET-SHIELD-LAYER1 item 4 — the SIL OFL 1.1 licence texts SHIP with the
 * fonts they license (OFL §2: the licence must accompany every copy of the
 * font software, including embedded/bundled copies).
 *
 * The texts are committed beside the fonts (`src/assets/fonts/*-OFL.txt`) and
 * copied into `public/fonts/`, which Vite copies verbatim into `dist/fonts/`.
 * Two copies can drift, so the served copy must be byte-identical to the one
 * beside the font. The dist arm runs against the BUILT artifact and FAILS when
 * `dist` is absent (the gate builds it first), never skips — the same rule as
 * `asset_security_policy_r141`.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const WALLET = join(dirname(fileURLToPath(import.meta.url)), "..");
const TEXTS = ["DMSans-OFL.txt", "JetBrainsMono-OFL.txt"] as const;

describe("OFL licence texts ship with the bundled fonts", () => {
  for (const name of TEXTS) {
    it(`public/fonts/${name} is byte-identical to src/assets/fonts/${name}`, () => {
      const source = readFileSync(join(WALLET, "src/assets/fonts", name));
      const served = readFileSync(join(WALLET, "public/fonts", name));
      expect(served.equals(source)).toBe(true);
      expect(source.toString("utf8")).toMatch(/SIL OPEN FONT LICENSE Version 1\.1/);
    });

    it(`dist/fonts/${name} is in the built bundle (absence fails, never skips)`, () => {
      const built = join(WALLET, "dist/fonts", name);
      expect(existsSync(built), "run `npm run build` first — the gate does").toBe(true);
      expect(readFileSync(built).equals(readFileSync(join(WALLET, "src/assets/fonts", name)))).toBe(
        true,
      );
    });
  }
});
