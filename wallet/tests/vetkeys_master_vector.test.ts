/**
 * D-1a carried obligation (CTO_RULING_D1A_RECOVERY_DIRECT_REDERIVE_2026-08-27,
 * §3): a FIXED-VECTOR regression test on the master-note-secret derivation.
 *
 * WHY THIS EXISTS. Layer-2 recovery works by RE-DERIVING the same master note
 * secret from the same vetKey — there is no stored recovery grant to fall back
 * on (that was Option A, ruled). So `masterNoteSecret` is not just a helper:
 * it IS the recovery mechanism. If a `@dfinity/vetkeys` upgrade changed
 * `deriveSymmetricKey` by one byte, every existing user's notes would become
 * undecryptable and nothing else in the suite would notice — the wallet would
 * happily derive a NEW, self-consistent secret and find zero notes.
 *
 * The dependency is pinned EXACT (not caret) in wallet/package.json for the
 * same reason. A bump that moves this vector is a RED gate, not a chore.
 */

import { describe, expect, it } from "vitest";
import { VetKey } from "@dfinity/vetkeys";

import { MASTER_NOTE_SECRET_DOMAIN_SEP, masterNoteSecret } from "../src/crypto/vetkeys";

const hex = (b: Uint8Array): string =>
  [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

const fromHex = (s: string): Uint8Array =>
  new Uint8Array((s.match(/../g) ?? []).map((byte) => parseInt(byte, 16)));

/**
 * A fixed, publicly-known vetKey fixture: the compressed encoding of the
 * BLS12-381 G1 generator. Chosen deliberately over a random one — it is a
 * standard constant anyone can re-derive from the curve specification, so this
 * vector is reproducible outside this repository.
 */
const FIXTURE_VETKEY_HEX =
  "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

/** FROZEN. Moving this line requires a ruling, not an edit. */
const EXPECTED_MASTER_SECRET_HEX = "ce3ca7537d25a104aab50f8c1eef9d4ff0044693d3288d663ac8009b09f777fc";

describe("masterNoteSecret — byte-stability (D-1a §3)", () => {
  it("derives the frozen vector from the fixed vetKey", () => {
    const vetKey = VetKey.deserialize(fromHex(FIXTURE_VETKEY_HEX));
    expect(hex(masterNoteSecret(vetKey))).toBe(EXPECTED_MASTER_SECRET_HEX);
  });

  it("is deterministic — the same vetKey always yields the same master secret", () => {
    const a = masterNoteSecret(VetKey.deserialize(fromHex(FIXTURE_VETKEY_HEX)));
    const b = masterNoteSecret(VetKey.deserialize(fromHex(FIXTURE_VETKEY_HEX)));
    expect(hex(a)).toBe(hex(b));
    expect(a.length).toBe(32);
  });

  it("is domain-separated — a different domain gives a different secret", () => {
    const vetKey = VetKey.deserialize(fromHex(FIXTURE_VETKEY_HEX));
    expect(hex(vetKey.deriveSymmetricKey("stsh-notes-master-v1-NOT", 32))).not.toBe(
      EXPECTED_MASTER_SECRET_HEX,
    );
    // And the domain separator itself is pinned: it is part of the namespace.
    expect(MASTER_NOTE_SECRET_DOMAIN_SEP).toBe("stsh-notes-master-v1");
  });
});
