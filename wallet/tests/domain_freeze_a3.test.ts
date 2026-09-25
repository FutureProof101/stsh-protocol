/**
 * A-3 domain-constant freeze guard.
 *
 * The four DOMAIN_* constants feed the FIRST Poseidon input of every note
 * commitment and every nullifier. The pool pins exactly one circuit/VK at a time
 * and has no note-migration mechanism, so once real unspent notes exist a change
 * to any of these four values makes those notes permanently unspendable — with
 * no error raised anywhere. That failure mode is silent, which is precisely why
 * it needs a test rather than a comment.
 *
 * This suite guards three separate things:
 *
 *  1. DERIVABILITY — DOMAIN_POOL_CANISTER_ID is not a magic number. It must be
 *     reproducible from a principal via the single normative DEF-108 rule. A
 *     mistyped digit at FINALIZE is otherwise undetectable.
 *  2. MANIFEST AGREEMENT — the wallet's constants agree with
 *     circuits/ceremony/domain_manifest.json, the artifact the ceremony and A6.7
 *     consume. Drift between them means the atomic Step-2 change was staggered.
 *  3. DOMAIN VECTOR — Poseidon(4) over the four constants reproduces the pinned
 *     domainHash. This is the wallet half of wallet/circuit equality; the circuit
 *     half is the recompiled R1CS, compared at FINALIZE AFTER all A6.6
 *     constraint changes (not before).
 *
 * NOT covered here, deliberately: ptau / zkey / VK. Those are proving material,
 * NOT part of the commitment domain, and may change under a compatible circuit
 * upgrade. See docs/ceremony/CEREMONY_FREEZE_RULES.md — conflating the two layers
 * would either over-freeze the VK forever or imply the domain constants are as
 * swappable as the VK. They are not.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { Principal } from "@dfinity/principal";
import { beforeAll, describe, expect, it } from "vitest";

import { initPoseidon, poseidon4 } from "../src/crypto/poseidon";
import {
  DOMAIN_ASSET_ID,
  DOMAIN_CIRCUIT_VERSION,
  DOMAIN_NETWORK_ID,
  DOMAIN_POOL_CANISTER_ID,
  bigintToFieldLe,
  encodeRecipientSignals,
} from "../src/crypto/notes";

const here = dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(
  readFileSync(resolve(here, "../../circuits/ceremony/domain_manifest.json"), "utf8"),
);

const wasmBytes = readFileSync(resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm"));
const hex = (b: Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

/** DEF-108 encoding read back as a little-endian BN254 Fr integer. */
function principalToFr(text: string): bigint {
  const buf = encodeRecipientSignals(Principal.fromText(text));
  let v = 0n;
  for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(buf[i]);
  return v;
}

beforeAll(async () => {
  await initPoseidon(wasmBytes);
});

// The generation the wallet is currently pinned to. A-3 FINALIZE (2026-09-12)
// flipped this to "next" in the SAME commit that re-pinned notes.ts and
// recompiled the circuit.
// NOTE the `as` rather than a plain annotation: with a literal annotation TS
// narrows the const to its initialiser and then reports the three ternaries
// below as impossible comparisons (TS2367), failing `tsc` in the wallet build.
// The widened union is the point — this switch is meant to be flipped.
const PINNED_GENERATION = "next" as "m5" | "next";
const valueKey = PINNED_GENERATION === "m5" ? "m5_value" : "next_value";
const principalKey = PINNED_GENERATION === "m5" ? "m5_source_principal" : "next_source_principal";
const hashKey = PINNED_GENERATION === "m5" ? "m5_le32_hex" : "next_le32_hex";

const dc = manifest.domain_constants;

describe("A-3 freeze — DOMAIN_POOL_CANISTER_ID is derived, not transcribed", () => {
  it("reproduces the pinned value from its source principal via the DEF-108 rule", () => {
    const source = dc.DOMAIN_POOL_CANISTER_ID[principalKey];
    expect(source, "manifest must name the source principal").toBeTruthy();
    expect(principalToFr(source).toString()).toBe(DOMAIN_POOL_CANISTER_ID.toString());
  });

  it("the DEF-108 rule is length-committing (trailing-zero-distinct principals differ)", () => {
    // byte[31] = len is what prevents [0x04] and [0x04,0x00] collapsing to the
    // same field element. If that byte were ever dropped, these would collide.
    const a = encodeRecipientSignals(Principal.fromUint8Array(new Uint8Array([4])));
    const b = encodeRecipientSignals(Principal.fromUint8Array(new Uint8Array([4, 0])));
    expect(hex(a)).not.toBe(hex(b));
    expect(a[31]).toBe(1);
    expect(b[31]).toBe(2);
  });
});

describe("A-3 freeze — wallet constants agree with the ceremony manifest", () => {
  it.each([
    ["DOMAIN_POOL_CANISTER_ID", DOMAIN_POOL_CANISTER_ID],
    ["DOMAIN_ASSET_ID", DOMAIN_ASSET_ID],
    ["DOMAIN_CIRCUIT_VERSION", DOMAIN_CIRCUIT_VERSION],
    ["DOMAIN_NETWORK_ID", DOMAIN_NETWORK_ID],
  ] as const)("%s matches the manifest", (name, walletValue) => {
    const expected = dc[name][valueKey];
    expect(expected, `manifest is missing ${name}.${valueKey}`).toBeTruthy();
    expect(walletValue.toString()).toBe(String(expected));
  });

  it("the manifest fixes the Poseidon(4) input ORDER, not just the values", () => {
    // Order is part of the contract: Poseidon is not symmetric, so a permuted
    // input list silently yields a different domain and unspendable notes.
    expect([
      dc.DOMAIN_POOL_CANISTER_ID.index,
      dc.DOMAIN_ASSET_ID.index,
      dc.DOMAIN_CIRCUIT_VERSION.index,
      dc.DOMAIN_NETWORK_ID.index,
    ]).toEqual([0, 1, 2, 3]);
  });

  it("every constant carries an action and a justification", () => {
    for (const name of Object.keys(dc)) {
      if (name.startsWith("$")) continue;
      expect(dc[name].action, `${name} has no action`).toBeTruthy();
      expect(dc[name].justification, `${name} has no justification`).toBeTruthy();
    }
  });
});

describe("A-3 freeze — domain vector", () => {
  it("Poseidon(4) over the four constants reproduces the pinned domainHash", async () => {
    const domainHash = await poseidon4(
      bigintToFieldLe(DOMAIN_POOL_CANISTER_ID, "DOMAIN_POOL_CANISTER_ID"),
      bigintToFieldLe(DOMAIN_ASSET_ID, "DOMAIN_ASSET_ID"),
      bigintToFieldLe(DOMAIN_CIRCUIT_VERSION, "DOMAIN_CIRCUIT_VERSION"),
      bigintToFieldLe(DOMAIN_NETWORK_ID, "DOMAIN_NETWORK_ID"),
    );
    expect(hex(domainHash)).toBe(manifest.domain_hash[hashKey]);
  });

  it("a one-value change produces a completely different domain (no silent tolerance)", async () => {
    const base = await poseidon4(
      bigintToFieldLe(DOMAIN_POOL_CANISTER_ID, "pool"),
      bigintToFieldLe(DOMAIN_ASSET_ID, "asset"),
      bigintToFieldLe(DOMAIN_CIRCUIT_VERSION, "cv"),
      bigintToFieldLe(DOMAIN_NETWORK_ID, "net"),
    );
    const bumped = await poseidon4(
      bigintToFieldLe(DOMAIN_POOL_CANISTER_ID, "pool"),
      bigintToFieldLe(DOMAIN_ASSET_ID, "asset"),
      bigintToFieldLe(DOMAIN_CIRCUIT_VERSION + 1n, "cv"), // the A6.6 bump
      bigintToFieldLe(DOMAIN_NETWORK_ID, "net"),
    );
    expect(hex(bumped)).not.toBe(hex(base));
  });
});

describe("A-3 freeze — FINALIZE is claimed, and the manifest says so", () => {
  it("the manifest is marked FINALIZED for the next generation", () => {
    // The mirror image of the PREP assertion this replaced: before A-3 FINALIZE
    // these three fields proved the lane had NOT landed; now they prove it has,
    // and a revert of the manifest alone (without reverting notes.ts and the
    // circuit) is caught here rather than silently shipping a split domain.
    expect(manifest.phase).toBe("A-3-FINALIZE");
    expect(manifest.status).toBe("FINALIZED");
    expect(manifest.generation.next_finalized).toBe(true);
  });

  it("records that the pool pin was re-encoded and nothing still blocks it", () => {
    expect(dc.DOMAIN_POOL_CANISTER_ID.action).toBe("RE_ENCODED");
    expect(dc.DOMAIN_POOL_CANISTER_ID.blocked_on).toBeNull();
    expect(dc.DOMAIN_POOL_CANISTER_ID.next_source_principal).toBe(
      "cxrfg-qaaaa-aaaar-qchfa-cai",
    );
  });

  it("the m5 generation record is retained, not overwritten", () => {
    // Retain-and-add is the manifest's own convention: the frozen generation
    // record must survive the finalize, or the historical domain becomes
    // unreconstructable from the artifact that claims to record it.
    expect(dc.DOMAIN_POOL_CANISTER_ID.m5_source_principal).toBe(
      "ohspu-zqaaa-aaaad-qmasq-cai",
    );
    expect(manifest.domain_hash.m5_le32_hex).toBe(
      "f86a7fd6a66d358ddbe7d8fa7b303f5da7e63d41b7ee207c6a31359c6220c125",
    );
  });
});
