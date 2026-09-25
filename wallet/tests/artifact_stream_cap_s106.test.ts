// @vitest-environment node
/**
 * AR2-S1-06 — the artifact stream cap must actually bind.
 *
 * `loadVerifiedArtifact` passed `Math.max(pin.bytes, MAX_ARTIFACT_STREAM_BYTES)`,
 * so the bound was always the 16 MiB ceiling (every pin is smaller), and a pin
 * ABOVE the ceiling would have raised it. The exact length is known at the call
 * site, so the cap is now `Math.min(...)`.
 *
 * SCOPE, stated once: this is a RESOURCE bound. What makes a wrong artifact fail
 * closed is the SHA-256 check, which already did that. Nothing here adds integrity.
 *
 * INDEPENDENT EXPECTED SIDE (HARNESS_DELTA §1, and SSA-B's RED on brief V1).
 * The expected digests below are a HARDCODED TABLE. They are not produced by
 * hashing the bytes this test serves — that would derive the expected side from
 * the artefact under test. They were computed once, out of band, from the
 * fixture's definition, and T-3b proves the table can fail by flipping a byte of
 * the SERVED artifact and requiring RED.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ManifestError, fetchCapped, loadVerifiedArtifact } from "../src/zk/artifacts";

/** The ceiling the shipped module names. Written as a literal, not imported. */
const CEILING = 16 * 1024 * 1024;

/** Fixture: 1024 bytes of 0xA5. Defined by this constant, not by a file. */
const FIXTURE_LEN = 1024;
const fixture = (fill = 0xa5, len = FIXTURE_LEN) => new Uint8Array(len).fill(fill);

/** HARDCODED DIGEST TABLE — computed out of band from the definition above. */
const DIGESTS: Record<string, string> = {
  "0xa5 x1024": "e75809e0d15667ce44e6aa5c64689a4917b245eb0920094ff0b017dc0612a17a",
  "0xa4 x1024": "db0b65b28bf17ae5f5937c2124493d06dc5a1a0bf0975ea7499ccfb62c629b27",
};

const serve = (bytes: Uint8Array) =>
  vi.spyOn(globalThis, "fetch").mockImplementation(
    async () => new Response(bytes as unknown as BodyInit, { status: 200 }),
  );

afterEach(() => {
  vi.restoreAllMocks();
});

describe("T-1 — an over-long stream trips at the PINNED length, not at the ceiling", () => {
  it("throws naming the pinned length when the server sends more than the pin", async () => {
    serve(fixture(0xa5, FIXTURE_LEN * 4));
    const pin = { id: "fx", path: "/zk/fx", bytes: FIXTURE_LEN, sha256: DIGESTS["0xa5 x1024"] };
    // The thrown message must name 1024 — the pinned length. Before the fix the
    // stream ran to completion and failed later on length/hash, having already
    // buffered four times what was pinned.
    await expect(loadVerifiedArtifact(pin)).rejects.toThrow(
      new RegExp(`exceeds the ${FIXTURE_LEN}-byte cap`),
    );
    await expect(loadVerifiedArtifact(pin)).rejects.toBeInstanceOf(ManifestError);
  });

  it("stops at the pinned length even when the overshoot is a single byte", async () => {
    serve(fixture(0xa5, FIXTURE_LEN + 1));
    const pin = { id: "fx", path: "/zk/fx", bytes: FIXTURE_LEN, sha256: DIGESTS["0xa5 x1024"] };
    await expect(loadVerifiedArtifact(pin)).rejects.toThrow(/exceeds the 1024-byte cap/);
  });
});

describe("T-2 — a pin above the ceiling does NOT raise the cap", () => {
  it("caps at the ceiling, not at the oversized pin", async () => {
    // The defect in one arm: with `Math.max` this pin would have set a 32 MiB
    // bound. The stream must stop at the 16 MiB ceiling instead.
    const oversizedPin = { id: "fx", path: "/zk/fx", bytes: 32 * 1024 * 1024, sha256: DIGESTS["0xa5 x1024"] };
    serve(fixture(0xa5, CEILING + 4096));
    await expect(loadVerifiedArtifact(oversizedPin)).rejects.toThrow(
      new RegExp(`exceeds the ${CEILING}-byte cap`),
    );
  });

  it("fetchCapped's own ceiling default is the 16 MiB value the module names", async () => {
    serve(fixture(0xa5, CEILING + 1));
    await expect(fetchCapped("/zk/fx")).rejects.toThrow(new RegExp(`${CEILING}-byte cap`));
  });
});

describe("T-3 — a correct artifact still loads, verified against the hardcoded table", () => {
  it("loads when the served bytes match the pinned length and the TABLE digest", async () => {
    serve(fixture());
    const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const url = await loadVerifiedArtifact({
      id: "fx",
      path: "/zk/fx",
      bytes: FIXTURE_LEN,
      sha256: DIGESTS["0xa5 x1024"],
    });
    expect(url.startsWith("blob:")).toBe(true);
    URL.revokeObjectURL(url);
    expect(revoke).toHaveBeenCalled();
  });
});

describe("T-3b — the SHIPPED artifact, and a one-byte mutation of it", () => {
  // SSA-B landed-diff RED, 2026-08-24T18:27:49Z, and the correction is real: the
  // synthetic buffers below prove the digest comparison works, but they are not
  // a SHIPPED value. This block sources its bytes from the pinned artifact that
  // actually ships — `circuits/build/spend_js/spend.wasm` — and flips one byte
  // of it while holding the pin fixed.
  //
  // INDEPENDENT EXPECTED SIDE: both digests are literals below. I computed them
  // with `sha256sum` / a standalone hasher over the file, NOT by reading
  // `spendManifest` (the artefact-under-test anti-pattern) and NOT by hashing
  // the bytes the stub serves. That SHIPPED_SHA256 also equals the manifest's
  // own pin is the point: two independent paths agree.
  const here = dirname(fileURLToPath(import.meta.url));
  const SHIPPED = new Uint8Array(readFileSync(resolve(here, "../../circuits/build/spend_js/spend.wasm")));

  const SHIPPED_LEN = 3_818_474;
  const SHIPPED_SHA256 = "3e910987203d8e3b42e1b656d21aa4dffce23cad0f1dd84f6f093fce6fbf4585";
  /** The same artifact with byte 1000 XOR 0x01 — digest pinned independently. */
  const MUTATED_SHA256 = "ea51dc25cebee416ee260f620f25a16677a1832967704b7440ea13feaf145bd4";

  const shippedPin = { id: "spend.wasm", path: "/zk/spend.wasm", bytes: SHIPPED_LEN, sha256: SHIPPED_SHA256 };

  it("the shipped artifact on disk still matches the independently pinned length", () => {
    // If this fails, the fixture moved and the two digests below are stale —
    // said out loud so a future reader does not debug the wrong thing.
    expect(SHIPPED.length).toBe(SHIPPED_LEN);
  });

  it("loads the SHIPPED artifact against the independently pinned digest", async () => {
    serve(SHIPPED);
    const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const url = await loadVerifiedArtifact(shippedPin);
    expect(url.startsWith("blob:")).toBe(true);
    URL.revokeObjectURL(url);
    expect(revoke).toHaveBeenCalled();
  });

  it("goes RED when ONE byte of the SHIPPED artifact is flipped, pin held fixed", async () => {
    const mutated = new Uint8Array(SHIPPED);
    mutated[1000] ^= 0x01;
    serve(mutated);
    await expect(loadVerifiedArtifact(shippedPin)).rejects.toThrow(/SHA-256 mismatch/);
    // And the reported digest is the mutation's own independently pinned value,
    // so this is a real comparison against a known other value, not a generic throw.
    serve(mutated);
    await expect(loadVerifiedArtifact(shippedPin)).rejects.toThrow(new RegExp(MUTATED_SHA256));
  });

  it("still goes RED on the synthetic fixture — the digest table itself works", async () => {
    // Retained from the synthetic arms: cheap, and it isolates the comparison
    // from anything about the shipped file's size or provenance.
    serve(fixture(0xa4));
    await expect(
      loadVerifiedArtifact({ id: "fx", path: "/zk/fx", bytes: FIXTURE_LEN, sha256: DIGESTS["0xa5 x1024"] }),
    ).rejects.toThrow(new RegExp(DIGESTS["0xa4 x1024"]));
  });
});
