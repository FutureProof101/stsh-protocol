/**
 * W-VETKEYS D-1b v3 §2/§3 — the device envelope and the two cache keys.
 *
 * The envelope is what makes Layer 1 possible, and it is also the only
 * canister-side secret derivative in the design. These arms cover both modes,
 * every fail-closed branch of the parser, and the key-separation rules.
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";
import { VetKey } from "@dfinity/vetkeys";

import {
  buildEnvelope,
  decodeEnvelope,
  EnvelopeFormatError,
  EnvelopeMode,
  ENVELOPE_PROTOCOL,
  ENVELOPE_VERSION,
  encodeHeader,
  openEnvelope,
  VETKEY_SERIALIZED_BYTES,
} from "../src/crypto/envelope";
import { exportDevicePublicKeys, generateDeviceKeys } from "../src/crypto/devices";
import {
  CACHE_PASSCODE_INFO,
  CACHE_UNLOCK_DOMAIN,
  cacheUnlockKeyFromPasscode,
  cacheUnlockKeyIiOnly,
  deserializeVetKeyChecked,
  envelopeIsPasscodeProtected,
  openVetKeyEnvelope,
  serializeVetKeyChecked,
  wrapVetKeyForDevice,
} from "../src/crypto/layer1";
import {
  ARGON2ID_ITERATIONS,
  ARGON2ID_MEMORY_KIB,
  ARGON2ID_PARALLELISM,
  ARGON2ID_SALT_BYTES,
  KDF_VERSION_ARGON2ID,
} from "../src/storage/noteCache";

const hex = (b: Uint8Array): string =>
  [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (s: string): Uint8Array =>
  new Uint8Array((s.match(/../g) ?? []).map((b) => parseInt(b, 16)));

/** The BLS12-381 G1 generator — a reproducible public vetKey fixture. */
const FIXTURE_VETKEY = () =>
  VetKey.deserialize(
    fromHex(
      "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    ),
  );

const CANISTER = Principal.fromUint8Array(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 1, 1]));
const OWNER = Principal.fromUint8Array(new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0x02, 0x01]));
const OTHER = Principal.fromUint8Array(new Uint8Array([0x99, 0x88, 0x77, 0x66, 0x02, 0x01]));

async function device() {
  const keys = await generateDeviceKeys();
  const pub = await exportDevicePublicKeys(keys);
  return { keys, encSpki: pub.encSpki };
}

describe("D-1b §2 — the device envelope", () => {
  it("round-trips the RAW vetKey in II-only mode, with zero derives involved", async () => {
    const d = await device();
    const binding = { canisterId: CANISTER, owner: OWNER, deviceId: "dev-1", encSpki: d.encSpki };
    const vetKey = FIXTURE_VETKEY();

    const envelope = await wrapVetKeyForDevice(binding, vetKey);
    expect(envelopeIsPasscodeProtected(envelope)).toBe(false);

    const opened = await openVetKeyEnvelope(envelope, binding, d.keys.encryption.privateKey);
    expect(hex(opened.serialize())).toBe(hex(vetKey.serialize()));
  }, 60_000);

  it("round-trips in passcode mode, and the wrong passcode fails closed", async () => {
    const d = await device();
    const binding = { canisterId: CANISTER, owner: OWNER, deviceId: "dev-1", encSpki: d.encSpki };
    const vetKey = FIXTURE_VETKEY();

    const envelope = await wrapVetKeyForDevice(binding, vetKey, "correct horse");
    expect(envelopeIsPasscodeProtected(envelope)).toBe(true);

    const opened = await openVetKeyEnvelope(
      envelope,
      binding,
      d.keys.encryption.privateKey,
      "correct horse",
    );
    expect(hex(opened.serialize())).toBe(hex(vetKey.serialize()));

    await expect(
      openVetKeyEnvelope(envelope, binding, d.keys.encryption.privateKey, "wrong horse"),
    ).rejects.toThrow(EnvelopeFormatError);
  }, 120_000);

  it("the passcode wraps the OUTSIDE: the RSA ciphertext is not visible in passcode mode", async () => {
    const d = await device();
    const binding = { canisterId: CANISTER, owner: OWNER, deviceId: "dev-1", encSpki: d.encSpki };
    const vetKey = FIXTURE_VETKEY();

    const iiOnly = await buildEnvelope(binding, new Uint8Array(384).fill(7));
    const passcoded = await buildEnvelope(binding, new Uint8Array(384).fill(7), "pw");
    // The II-only body IS the RSA ciphertext; the passcode body is not.
    expect(hex(iiOnly)).toContain(hex(new Uint8Array(384).fill(7)));
    expect(hex(passcoded)).not.toContain(hex(new Uint8Array(384).fill(7)));
    expect(vetKey).toBeDefined();
  }, 120_000);

  it("refuses a passcode on an II-only envelope and a missing one on a passcode envelope", async () => {
    const d = await device();
    const binding = { canisterId: CANISTER, owner: OWNER, deviceId: "dev-1", encSpki: d.encSpki };
    const iiOnly = await wrapVetKeyForDevice(binding, FIXTURE_VETKEY());
    const passcoded = await wrapVetKeyForDevice(binding, FIXTURE_VETKEY(), "pw");

    await expect(
      openVetKeyEnvelope(iiOnly, binding, d.keys.encryption.privateKey, "pw"),
    ).rejects.toThrow(/II-only/);
    await expect(
      openVetKeyEnvelope(passcoded, binding, d.keys.encryption.privateKey),
    ).rejects.toThrow(/passcode is required/);
  }, 120_000);

  it("binds the envelope to canister, owner and device — a foreign envelope is refused", async () => {
    const d = await device();
    const binding = { canisterId: CANISTER, owner: OWNER, deviceId: "dev-1", encSpki: d.encSpki };
    const envelope = await wrapVetKeyForDevice(binding, FIXTURE_VETKEY());

    for (const [label, wrong] of [
      ["canister", { ...binding, canisterId: OTHER }],
      ["owner", { ...binding, owner: OTHER }],
      ["device id", { ...binding, deviceId: "dev-2" }],
    ] as const) {
      await expect(
        openVetKeyEnvelope(envelope, wrong, d.keys.encryption.privateKey),
        `a mismatched ${label} must be refused`,
      ).rejects.toThrow(/does not match/);
    }
  }, 60_000);

  it("another device's private key cannot open the envelope", async () => {
    const mine = await device();
    const theirs = await device();
    const binding = {
      canisterId: CANISTER,
      owner: OWNER,
      deviceId: "dev-1",
      encSpki: mine.encSpki,
    };
    const envelope = await wrapVetKeyForDevice(binding, FIXTURE_VETKEY());
    await expect(
      openVetKeyEnvelope(envelope, binding, theirs.keys.encryption.privateKey),
    ).rejects.toBeTruthy();
  }, 60_000);

  it("any tampered header byte fails the AAD check", async () => {
    const d = await device();
    const binding = { canisterId: CANISTER, owner: OWNER, deviceId: "dev-1", encSpki: d.encSpki };
    const envelope = await wrapVetKeyForDevice(binding, FIXTURE_VETKEY(), "pw");
    const { headerBytes } = decodeEnvelope(envelope);

    // Flip a byte inside the SALT — a header field that the parser accepts at
    // any value, so only the AAD can catch it.
    const tampered = new Uint8Array(envelope);
    const saltOffset = headerBytes.length - ARGON2ID_SALT_BYTES;
    tampered[saltOffset] ^= 0xff;
    await expect(
      openVetKeyEnvelope(tampered, binding, d.keys.encryption.privateKey, "pw"),
    ).rejects.toThrow(EnvelopeFormatError);
  }, 120_000);

  it("refuses an unknown version, an unknown mode and a weakened KDF", async () => {
    const d = await device();
    const binding = { canisterId: CANISTER, owner: OWNER, deviceId: "dev-1", encSpki: d.encSpki };
    const envelope = await wrapVetKeyForDevice(binding, FIXTURE_VETKEY(), "pw");
    const protocolPrefixLen = 4 + ENVELOPE_PROTOCOL.length;

    const badVersion = new Uint8Array(envelope);
    badVersion[protocolPrefixLen] = ENVELOPE_VERSION + 1;
    expect(() => decodeEnvelope(badVersion)).toThrow(/unknown envelope version/);

    const badMode = new Uint8Array(envelope);
    badMode[protocolPrefixLen + 2] = 9;
    expect(() => decodeEnvelope(badMode)).toThrow(/unknown envelope mode/);

    // A DOWNGRADED KDF parameter set must be refused on READ, not merely never
    // written: authentication alone would faithfully carry an attacker's
    // weakening if the wallet were ever tricked into writing one.
    const weakHeader = await encodeHeader({
      ...binding,
      mode: EnvelopeMode.Passcode,
      version: ENVELOPE_VERSION,
      kdfId: KDF_VERSION_ARGON2ID,
      memoryKib: 8,
      iterations: 1,
      parallelism: 1,
      salt: new Uint8Array(ARGON2ID_SALT_BYTES),
    });
    const weak = new Uint8Array([...weakHeader, ...new Uint8Array(64)]);
    expect(() => decodeEnvelope(weak)).toThrow(/not the pinned ones/);
  }, 120_000);

  it("refuses an II-only envelope that carries KDF material", async () => {
    const d = await device();
    const header = await encodeHeader({
      canisterId: CANISTER,
      owner: OWNER,
      deviceId: "dev-1",
      encSpki: d.encSpki,
      mode: EnvelopeMode.IiOnly,
      version: ENVELOPE_VERSION,
      kdfId: KDF_VERSION_ARGON2ID,
      memoryKib: ARGON2ID_MEMORY_KIB,
      iterations: ARGON2ID_ITERATIONS,
      parallelism: ARGON2ID_PARALLELISM,
      salt: new Uint8Array(ARGON2ID_SALT_BYTES),
    });
    expect(() => decodeEnvelope(new Uint8Array([...header, 1, 2, 3]))).toThrow(
      /no KDF parameters or salt/,
    );
  }, 30_000);

  it("refuses an envelope with no body and a truncated one", async () => {
    const d = await device();
    const binding = { canisterId: CANISTER, owner: OWNER, deviceId: "dev-1", encSpki: d.encSpki };
    const envelope = await wrapVetKeyForDevice(binding, FIXTURE_VETKEY());
    const { headerBytes } = decodeEnvelope(envelope);
    expect(() => decodeEnvelope(headerBytes)).toThrow(/no body/);
    expect(() => decodeEnvelope(envelope.subarray(0, 8))).toThrow(EnvelopeFormatError);
  }, 60_000);
});

describe("D-1b §2(6) — the vetKey serialization pin", () => {
  it("is 48 bytes and round-trips", () => {
    const bytes = serializeVetKeyChecked(FIXTURE_VETKEY());
    expect(bytes.length).toBe(VETKEY_SERIALIZED_BYTES);
    expect(hex(deserializeVetKeyChecked(bytes).serialize())).toBe(hex(bytes));
  });

  it("refuses to parse a wrong-width vetKey rather than guessing", () => {
    expect(() => deserializeVetKeyChecked(new Uint8Array(47))).toThrow(/expected 48/);
    expect(() => deserializeVetKeyChecked(new Uint8Array(49))).toThrow(/expected 48/);
  });
});

describe("D-1b §3 — cache-unlock keys", () => {
  /**
   * FROZEN. The II-only cache key is derived from the vetKey under its own
   * domain; if this vector moves, every existing cache becomes unreadable.
   */
  const CACHE_UNLOCK_VECTOR = "2c12d135c66b6b02e7c1a0d039a46f216305f9832279e7a7122596fe5f0dc587";

  it("derives the frozen II-only cache key from the fixed vetKey", () => {
    expect(hex(cacheUnlockKeyIiOnly(FIXTURE_VETKEY()))).toBe(CACHE_UNLOCK_VECTOR);
  });

  it("is a DIFFERENT key from the note master secret — separate domains", () => {
    const vetKey = FIXTURE_VETKEY();
    const cacheKey = cacheUnlockKeyIiOnly(vetKey);
    const master = vetKey.deriveSymmetricKey("stsh-notes-master-v1", 32);
    expect(hex(cacheKey)).not.toBe(hex(master));
    expect(CACHE_UNLOCK_DOMAIN).toBe("stsh-note-cache-unlock-v1");
  });

  it("passcode mode: the cache subkey is NOT the envelope key, and the info string is what separates them", async () => {
    const salt = new Uint8Array(ARGON2ID_SALT_BYTES).fill(0x5a);
    const { envelopePasscodeKeyBytes } = await import("../src/crypto/envelope");
    const envelopeKey = await envelopePasscodeKeyBytes("pw", salt);
    const cacheKey = await cacheUnlockKeyFromPasscode("pw", salt);
    expect(hex(cacheKey)).not.toBe(hex(envelopeKey));
    expect(cacheKey.length).toBe(32);
    expect(CACHE_PASSCODE_INFO).toBe("stsh-note-cache-passcode-v1");

    // A different passcode gives a different cache key — the subkey really does
    // depend on the secret, not just on the domain string.
    const other = await cacheUnlockKeyFromPasscode("pw2", salt);
    expect(hex(other)).not.toBe(hex(cacheKey));
  }, 120_000);
});
