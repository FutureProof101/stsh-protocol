// @vitest-environment node
/**
 * W-CEREMONY-BIND — spendManifest.json is a freeze-matrix artifact (AR2-S1-04).
 *
 * `wallet/src/zk/spendManifest.json` duplicates values the A-3 domain freeze
 * pins, is build-bundled with no env override, and gates spend via
 * `assertDeploymentTuple`. Until this lane it was covered by NO freeze
 * mechanism: absent from the artifact matrix, from the FINALIZE checklist and
 * from the derive tool's hand-carry list.
 *
 * WHY THIS FILE EXISTS RATHER THAN AN EXTENSION OF artifacts_l3c.test.ts:
 * that suite builds BOTH sides of every comparison from `spendManifest` itself
 * (`TUPLE.pool = spendManifest.frozenPoolPrincipal`, `ATTESTATION_OK.vkHash =
 * spendManifest.vkHash`, …). It proves the comparison logic is fail-closed,
 * which is a real and different property — but it cannot notice a changed pin,
 * because the pin moves on both sides at once. Editing any frozen value leaves
 * that suite green. This suite therefore takes its expected side ONLY from:
 *
 *   (a) a hardcoded table below, transcribed from the M5 freeze and never read
 *       back from the file under test; and
 *   (b) circuits/ceremony/domain_manifest.json — a SECOND PRODUCER of the same
 *       values, maintained by the ceremony rather than by the wallet build.
 *
 * Nothing here reads a pinned value through `wallet/src/zk/artifacts.ts`, which
 * imports the manifest and would reintroduce the same circularity one level up.
 *
 * BOUND IS NOT CORRECT. These assertions make a change to a pinned value
 * detectable. They do not make the current values right: `vkHash` is the DEV VK
 * and `frozenPoolPrincipal` is the orphaned/hostile M5 principal. Both stay
 * wrong until the A6.7 re-encode. See CEREMONY_FREEZE_RULES.md §2a.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { ManifestError, assertDeploymentTuple } from "../src/zk/artifacts";

const here = dirname(fileURLToPath(import.meta.url));

/** The file under test — read as raw JSON, never through src/zk/artifacts.ts. */
const manifest = JSON.parse(
  readFileSync(resolve(here, "../src/zk/spendManifest.json"), "utf8"),
);

/** Independent producer (b): the ceremony's own manifest. */
const ceremony = JSON.parse(
  readFileSync(resolve(here, "../../circuits/ceremony/domain_manifest.json"), "utf8"),
);

/**
 * Independent expected side (a). Hardcoded on purpose: a value read from the
 * artifact under test is not an expectation, it is a tautology.
 *
 * A-3 FINALIZE / A6.7 updates this table in the SAME commit as the manifest —
 * that is the point. A pin that can move without a test author noticing is
 * exactly the gap AR2-S1-04 named.
 */
const M5_PINS = {
  vkHash: "84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914",
  frozenPoolPrincipal: "cxrfg-qaaaa-aaaar-qchfa-cai",
  circuitVersion: 3,
  poolVersion: 1,
  networkId: 1,
  assetId: 0,
  proofSystemId: "groth16-bn254",
} as const;

/** Hardcoded artifact-matrix membership (M-5). Set equality, both directions. */
const EXPECTED_MATRIX_PATHS = [
  "circuits/spend.circom",
  "circuits/build/spend.r1cs",
  "circuits/build/spend_js/spend.wasm",
  "wallet/src/crypto/notes.ts",
  "wallet/tests/poseidon.test.ts",
  "POSEIDON_PARAMS.md",
  "circuits/ceremony/domain_manifest.json",
  "wallet/src/zk/spendManifest.json",
] as const;

/**
 * Hardcoded A6.7 re-encode targets ADDED BY THIS LANE (M-6, AR2-S3-03). The
 * governing ruling names circuits/ceremony/domain_manifest.json only; these
 * four are the additive surfaces. Read from the hardcoded table, never from the
 * list under test — otherwise deleting a row would delete its own expectation.
 */
const EXPECTED_ADDITIVE_REENCODE_TARGETS = [
  { path: "wallet/src/zk/spendManifest.json", field: "frozenPoolPrincipal" },
  { path: "wallet/src/session/config.ts", field: "DEFAULT_POOL_CANISTER_ID" },
  { path: "canister_ids.json", field: "shielded_pool.ic" },
  { path: "MAINNET_DEPLOYMENT.md", field: "the real mainnet pool principal" },
  { path: "docs/ceremony/DOMAIN_CONSTANTS_MATRIX.md", field: "row 0" },
] as const;

/**
 * DO-NOT-MOVE sites (AR-2 consistency leg). Hardcoded, because the whole point
 * is that these cannot be found — or protected — by grepping for the value.
 * `recipient.test.ts` is the one that matters most: sweeping its input AND its
 * hardcoded expected bytes together leaves a test that only proves the encoder
 * agrees with itself.
 */
const EXPECTED_NON_TARGETS = [
  "wallet/tests/oisy_approve.test.ts",
  "wallet/tests/transfer_a2.test.ts",
  "wallet/tests/journal_cas_ac1.test.ts",
  "wallet/tests/recipient.test.ts",
  "canisters/vault/src/lib.rs",
  "canisters/custody-types/src/lib.rs",
  "wallet/scripts/derive_domain_constants.mjs",
] as const;

describe("W-CEREMONY-BIND — pinned manifest values, expected side built independently", () => {
  it.each([
    ["vkHash", M5_PINS.vkHash],
    ["frozenPoolPrincipal", M5_PINS.frozenPoolPrincipal],
    ["circuitVersion", M5_PINS.circuitVersion],
    ["poolVersion", M5_PINS.poolVersion],
    ["networkId", M5_PINS.networkId],
    ["assetId", M5_PINS.assetId],
    ["proofSystemId", M5_PINS.proofSystemId],
  ])("%s equals the hardcoded M5 pin", (field, expected) => {
    expect(manifest[field as string]).toBe(expected);
  });

  it("frozenPoolPrincipal equals the ceremony manifest's source principal (second producer)", () => {
    // A-3 FINALIZE: the LIVE generation is `next`. The m5_* fields are retained
    // as the frozen historical record and are deliberately NOT what the shipped
    // manifest is checked against any more.
    const source = ceremony.domain_constants.DOMAIN_POOL_CANISTER_ID.next_source_principal;
    expect(source, "ceremony manifest must name the mainnet-v2 source principal").toBeTruthy();
    expect(manifest.frozenPoolPrincipal).toBe(source);
  });

  it("vkHash equals the ceremony manifest's PRODUCTION verification-key sha256 (second producer)", () => {
    // A-4 LANDING: the ceremony slot is filled, so the wallet is bound to
    // ceremony_material.next.vk — the mainnet-v2 production key.
    //
    // Deliberately NOT dev_chain: that block is RETAINED as superseded history
    // (it records what shipped before A-4) and must never track the production
    // artifacts, or the record of what was superseded is erased. Asserting
    // against it here would also mean this test passed while the wallet shipped
    // the dev key.
    const prodVk = ceremony.ceremony_material.next.vk.sha256;
    expect(prodVk, "ceremony_material.next.vk.sha256 must be filled at A-4").toBeTruthy();
    expect(manifest.vkHash).toBe(prodVk);
    expect(manifest.vkHash).not.toBe(ceremony.ceremony_material.next.dev_chain.vk.sha256);
  });

  it.each([
    ["circuitVersion", "DOMAIN_CIRCUIT_VERSION"],
    ["networkId", "DOMAIN_NETWORK_ID"],
    ["assetId", "DOMAIN_ASSET_ID"],
  ])("%s equals the ceremony manifest's %s next_value (second producer)", (field, constant) => {
    expect(String(manifest[field as string])).toBe(
      String(ceremony.domain_constants[constant as string].next_value),
    );
  });

  it("the artifact sha256 pins equal the ceremony manifest's (second producer)", () => {
    const wasm = manifest.artifacts.find((a: { id: string }) => a.id === "spend.wasm");
    const zkey = manifest.artifacts.find((a: { id: string }) => a.id === "spend_1.zkey");
    const matrixWasm = ceremony.artifact_matrix.atomic_set.find((a: { path: string }) =>
      a.path.endsWith("spend_js/spend.wasm"),
    );
    expect(wasm.sha256).toBe(matrixWasm.next_sha256);
    // A-4 LANDING: the shipped zkey is the ceremony output, not the dev chain.
    const prodZkey = ceremony.ceremony_material.next.zkey.sha256;
    expect(prodZkey, "ceremony_material.next.zkey.sha256 must be filled at A-4").toBeTruthy();
    expect(zkey.sha256).toBe(prodZkey);
    expect(zkey.sha256).not.toBe(ceremony.ceremony_material.next.dev_chain.zkey.sha256);
  });

  it("a wallet holding the pinned pool accepts its own deployment tuple, and only that pool", () => {
    // Second leg of the frozenPoolPrincipal arm: the value is not merely
    // recorded, it gates spend. tuple.pool comes from the HARDCODED table, so a
    // mutated manifest makes this throw rather than silently agreeing.
    const tuple = {
      pool: M5_PINS.frozenPoolPrincipal,
      token: "aaaaa-aa",
      merkle: "aaaaa-aa",
      nullifier: "aaaaa-aa",
      verifier: "aaaaa-aa",
    };
    expect(() => assertDeploymentTuple(tuple)).not.toThrow();
    expect(() => assertDeploymentTuple({ ...tuple, pool: "aaaaa-aa" })).toThrow(ManifestError);
  });
});

describe("W-CEREMONY-BIND — the freeze matrix covers this manifest (AR2-S1-04)", () => {
  const paths = ceremony.artifact_matrix.atomic_set.map((a: { path: string }) => a.path);

  it("spendManifest.json is an artifact-matrix member", () => {
    expect(paths).toContain("wallet/src/zk/spendManifest.json");
  });

  it("the matrix row set is exactly the expected set (no additions, no silent drops)", () => {
    expect([...paths].sort()).toEqual([...EXPECTED_MATRIX_PATHS].sort());
  });

  it("its row records what it encodes and that it is tracked", () => {
    const row = ceremony.artifact_matrix.atomic_set.find(
      (a: { path: string }) => a.path === "wallet/src/zk/spendManifest.json",
    );
    expect(row.tracked).toBe(true);
    for (const field of ["frozenPoolPrincipal", "vkHash", "circuitVersion", "poolVersion"]) {
      expect(row.encodes).toContain(field);
    }
  });
});

describe("W-CEREMONY-BIND — the A6.7 re-encode target list is recorded, not recited (AR2-S3-03)", () => {
  const targets = ceremony.reencode_targets;

  it("the ruling's own surface is present and attributed to the ruling", () => {
    const ruled = targets.surfaces.find(
      (s: { path: string }) => s.path === "circuits/ceremony/domain_manifest.json",
    );
    expect(ruled.source).toBe("ruling");
    expect(targets.ruling).toContain("CTO_RULING_A65_M5_REENCODE_OWNER");
  });

  it.each(EXPECTED_ADDITIVE_REENCODE_TARGETS.map((t) => [t.path, t.field]))(
    "%s is a re-encode target for %s",
    (path, field) => {
      const row = targets.surfaces.find((s: { path: string }) => s.path === path);
      expect(row, `${path} is missing from reencode_targets`).toBeTruthy();
      expect(row.field, `${path} records the wrong field`).toContain(field);
      expect(row.source).toBe("W-CEREMONY-BIND");
    },
  );

  it("the surface set is exactly the ruling's one plus this lane's five", () => {
    expect([...targets.surfaces.map((s: { path: string }) => s.path)].sort()).toEqual(
      [
        "circuits/ceremony/domain_manifest.json",
        ...EXPECTED_ADDITIVE_REENCODE_TARGETS.map((t) => t.path),
      ].sort(),
    );
  });

  it("the target value is RECORDED now that it is known — never a guessed principal", () => {
    // Was: UNKNOWN_UNTIL_RESERVED. A-3 FINALIZE discharged it — the pool exists
    // (born under the Vault at J-18), so the target is the real principal and
    // the record says which lane put it there.
    expect(targets.next_value).toBe(M5_PINS.frozenPoolPrincipal);
    expect(targets.next_value_status).toContain("RE_ENCODED_2026-09-12");
    // Reservation is not installation: the ruling's distinction, asserted so a
    // later edit cannot quietly collapse the two.
    expect(targets.lifecycle).toContain("RESERVATION and NOT an install");
    expect(targets.lifecycle).toContain("HELD");
  });

  it("the worksheet's exclusion from the artifact matrix is RECORDED, not silent", () => {
    // AR-2 found this file in neither list. It is principal-bearing (so it is a
    // re-encode target) but is a worksheet (so it is not an atomic-freeze row).
    // Both halves must be written down: a silent omission is the defect.
    const row = targets.surfaces.find(
      (s: { path: string }) => s.path === "docs/ceremony/DOMAIN_CONSTANTS_MATRIX.md",
    );
    expect(row.artifact_matrix_disposition).toContain("DELIBERATELY EXCLUDED");
    expect(row.discovery_hazard).toContain("U+00AD");
    // ...and it must NOT have crept into the atomic set on the strength of that.
    expect(
      ceremony.artifact_matrix.atomic_set.map((a: { path: string }) => a.path),
    ).not.toContain("docs/ceremony/DOMAIN_CONSTANTS_MATRIX.md");
  });

  it("the soft-hyphen hazard is real: a value grep does not find the worksheet", () => {
    // Executed, not asserted from the note. The Fr integer in row 0 carries a
    // U+00AD, so the plain value never matches — which is why the completeness
    // rule is "enumerate from the list, never from a grep".
    const fr = ceremony.domain_constants.DOMAIN_POOL_CANISTER_ID.next_value;
    const worksheet = readFileSync(
      resolve(here, "../../docs/ceremony/DOMAIN_CONSTANTS_MATRIX.md"),
      "utf8",
    );
    expect(worksheet).not.toContain(fr); // the grep blind spot itself
    expect(worksheet).toContain("\u00ad"); // and the reason for it
  });
});

describe("W-CEREMONY-BIND — the DO-NOT-MOVE list (AR-2 consistency leg)", () => {
  const nonTargets = ceremony.reencode_non_targets;

  it.each(EXPECTED_NON_TARGETS)("%s is recorded as a non-target with a reason", (path) => {
    const row = nonTargets.sites.find((s: { path: string }) => s.path === path);
    expect(row, `${path} is missing from reencode_non_targets`).toBeTruthy();
    expect(row.means, `${path} records no meaning`).toBeTruthy();
    expect(row.if_swept, `${path} records no consequence`).toBeTruthy();
  });

  it("the non-target set is exactly the expected set", () => {
    expect([...nonTargets.sites.map((s: { path: string }) => s.path)].sort()).toEqual(
      [...EXPECTED_NON_TARGETS].sort(),
    );
  });

  it("no site appears on both lists — a surface cannot be a target and a non-target", () => {
    const t = new Set(
      ceremony.reencode_targets.surfaces.map((s: { path: string }) => s.path),
    );
    for (const s of nonTargets.sites) expect(t.has(s.path)).toBe(false);
  });

  it("the enumeration rule forbids the grep that would sweep them", () => {
    expect(nonTargets.rule).toContain("NEVER from a value or principal grep");
  });

  it("M5_PRINCIPAL's question is ANSWERED, not left open", () => {
    const row = nonTargets.sites.find((s: { path: string }) =>
      s.path.endsWith("derive_domain_constants.mjs"),
    );
    expect(row.if_swept).toContain("does NOT move");
  });
});

describe("W-CEREMONY-BIND — re-encode target list, remaining assertions", () => {
  const targets2 = ceremony.reencode_targets;
  it("the current value is recorded as the hostile/uncontrolled orphan, and bound != correct", () => {
    // The ORPHAN, transcribed independently — not M5_PINS, which after A-3
    // FINALIZE holds the live pool. `current_value` is the record of what the
    // surfaces held BEFORE the re-encode and stays on the orphan.
    expect(targets2.current_value).toBe("ohspu-zqaaa-aaaad-qmasq-cai");
    expect(targets2.current_value_disposition).toContain("HOSTILE-UNCONTROLLED");
    expect(targets2.bound_is_not_correct).toBeTruthy();
  });
});
