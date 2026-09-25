/**
 * H-2 vetKeys hardening (BRIEF_VETKEY_HARDENING.md, SSA A3/A4)
 *
 * A3: assertCanisterConfig now REQUIRES an explicit expected vetKD key name and asserts
 *     BOTH the domain separator and the key name — a mainnet canister accidentally left on
 *     "test_key_1" must be rejected (it would otherwise derive against the wrong key).
 * A4: the vetKD derivation input + context bytes are frozen as an exact fixed vector,
 *     byte-identical to the Rust reference
 *     (canisters/vetkeys/tests/crossdevice_acceptance.rs
 *     test_h2_a4_vetkd_input_and_context_fixed_vector — update BOTH or neither).
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";

import {
  assertCanisterConfig,
  vetkdInput,
  VETKEYS_CONTEXT,
  type VetkeysCanister,
} from "../src/crypto/vetkeys";

/** A VetkeysCanister stub whose get_config() returns a fixed (domain, keyName) tuple. */
function mockCanister(config: [string, string]): VetkeysCanister {
  return {
    getVetkeyVerificationKey: async () => new Uint8Array(),
    getEncryptedVetkey: async () => ({ encryptedKey: new Uint8Array(), remaining: 4 }),
    // W-VETKEYS Layer 1 — not exercised by this suite.
    registerDevice: async () => {
      throw new Error("registerDevice not scripted by this test");
    },
    revokeDevice: async () => {
      throw new Error("revokeDevice not scripted by this test");
    },
    getWrappedSecret: async () => {
      throw new Error("getWrappedSecret not scripted by this test");
    },
    listDevices: async () => {
      throw new Error("listDevices not scripted by this test");
    },
    replaceEnvelope: async () => {
      throw new Error("replaceEnvelope not scripted by this test");
    },
    getConfig: async () => config,
  };
}

describe("H-2 A3 — assertCanisterConfig requires an explicit expected key name", () => {
  it("accepts a matching domain + expected production key (key_1)", async () => {
    await expect(
      assertCanisterConfig(mockCanister([VETKEYS_CONTEXT, "key_1"]), "key_1"),
    ).resolves.toBeUndefined();
  });

  it("accepts a local test key when that is exactly what the caller expects", async () => {
    await expect(
      assertCanisterConfig(mockCanister([VETKEYS_CONTEXT, "test_key_1"]), "test_key_1"),
    ).resolves.toBeUndefined();
  });

  it("rejects a domain-separator mismatch", async () => {
    await expect(
      assertCanisterConfig(mockCanister(["stsh.wallet.notes.v2", "key_1"]), "key_1"),
    ).rejects.toThrow(/domain separator mismatch/);
  });

  it("rejects production expecting key_1 when the canister is on test_key_1", async () => {
    await expect(
      assertCanisterConfig(mockCanister([VETKEYS_CONTEXT, "test_key_1"]), "key_1"),
    ).rejects.toThrow(/key-name mismatch/);
  });

  it("rejects a local expectation when the canister is on a different key", async () => {
    await expect(
      assertCanisterConfig(mockCanister([VETKEYS_CONTEXT, "key_1"]), "test_key_1"),
    ).rejects.toThrow(/key-name mismatch/);
  });
});

describe("H-2 A4 — vetKD derivation input + context are frozen fixed vectors", () => {
  it("vetkdInput(pinned principal) equals the exact byte vector (== Rust reference)", () => {
    const principal = Principal.fromUint8Array(
      new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x02]),
    );
    const expected = new Uint8Array([
      0x0a, // len = 10
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x02, // principal
      0x6e, 0x6f, 0x74, 0x65, 0x73, // "notes"
    ]);
    expect(Array.from(vetkdInput(principal))).toEqual(Array.from(expected));
  });

  it("the context (domain separator) bytes are frozen", () => {
    const expectedContext = new Uint8Array([
      0x73, 0x74, 0x73, 0x68, 0x2e, 0x77, 0x61, 0x6c, 0x6c, 0x65, // "stsh.walle"
      0x74, 0x2e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x2e, 0x76, 0x31, // "t.notes.v1"
    ]);
    expect(Array.from(new TextEncoder().encode(VETKEYS_CONTEXT))).toEqual(
      Array.from(expectedContext),
    );
  });
});
