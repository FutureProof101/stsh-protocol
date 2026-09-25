/**
 * DEF-108 recipient-encoding equality checkpoint (wallet-build Commit 2).
 *
 * The wallet's encodeRecipientSignals must byte-match the canister's
 * encode_recipient_signals (shielded-pool/src/lib.rs): principal bytes at
 * [0..len], byte[31] = principal byte length. Vector: the pool principal
 * ohspu-zqaaa-aaaad-qmasq-cai (10 bytes) — expected bytes computed directly
 * from the source algorithm.
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";

import { encodeRecipientSignals } from "../src/crypto/notes";

const hex = (b: Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

describe("DEF-108 recipient encoding", () => {
  it("matches the canister encode_recipient_signals for the pool principal", () => {
    const principal = Principal.fromText("ohspu-zqaaa-aaaad-qmasq-cai");
    const encoded = encodeRecipientSignals(principal);

    // byte[31] is the principal byte length (10 for this principal).
    expect(encoded[31]).toBe(principal.toUint8Array().length);
    expect(encoded[31]).toBe(10);

    // Full 32-byte encoding, source-verified against shielded-pool/src/lib.rs.
    expect(hex(encoded)).toBe(
      "000000000070602501010000000000000000000000000000000000000000000a",
    );
  });

  it("places the principal bytes at the front and zeros the middle", () => {
    const principal = Principal.fromText("ohspu-zqaaa-aaaad-qmasq-cai");
    const pbytes = principal.toUint8Array();
    const encoded = encodeRecipientSignals(principal);
    expect(hex(encoded.slice(0, pbytes.length))).toBe(hex(pbytes));
    for (let i = pbytes.length; i < 31; i++) expect(encoded[i]).toBe(0);
  });
});
