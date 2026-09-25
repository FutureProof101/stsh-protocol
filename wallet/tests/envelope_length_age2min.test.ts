/**
 * VETKEYS-AGE-2MIN — AC-7 / AD-12: the device envelope the wallet actually
 * builds must fit the canister's stored-size bound.
 *
 * The mainnet failure this lane fixes: `register_device` refused EVERY first
 * device with "the wrapped envelope exceeds the maximum stored size", because
 * the canister bounded the stored value at 512 bytes while the wallet's
 * envelope is header + body (551–627 bytes). No test caught it: the canister
 * suite used a bare 384-byte blob and every wallet test mocked
 * `registerDevice`. These arms build the REAL encoding — real RSA-OAEP-3072
 * device keys, real header, real Argon2id + AES-GCM in passcode mode — and
 * measure it.
 *
 * RECIPROCAL LITERALS (CTO addendum: "both literals cite each other"):
 *   - 1024 = `WRAPPED_SECRET_MAX_BYTES` (`canisters/vetkeys/src/state.rs`),
 *     and `ENVELOPE_NEW_BOUND_BYTES` in `canisters/vetkeys/tests/crossdevice_acceptance.rs`.
 *   - 627 = `ENVELOPE_CEILING_BYTES` in the same canister test: passcode mode,
 *     64-byte device id (`MAX_DEVICE_ID_BYTES`, `pins.rs`), 29-byte owner
 *     (`PRINCIPAL_MAX_BYTES`, `state.rs`), 10-byte canister id.
 *   - 583 = the II-only worst case; 551 / 595 = what `randomDeviceId()` (32
 *     hex chars) produces today, II-only / passcode.
 * Exact sizes are asserted as well as the ceiling, so an empty or truncated
 * encoder cannot pass on "≤ 1024" alone (SSA §4).
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";
import { VetKey } from "@dfinity/vetkeys";

import { exportDevicePublicKeys, generateDeviceKeys, randomDeviceId } from "../src/crypto/devices";
import { wrapVetKeyForDevice } from "../src/crypto/layer1";
import { decodeEnvelope, EnvelopeMode } from "../src/crypto/envelope";

/** The canister's stored-size bound — see the header comment for its twin. */
const CANISTER_STORED_BOUND = 1024;

const fromHex = (s: string): Uint8Array =>
  new Uint8Array((s.match(/../g) ?? []).map((b) => parseInt(b, 16)));
const FIXTURE_VETKEY = () =>
  VetKey.deserialize(
    fromHex(
      "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    ),
  );

/** The live vetkeys canister (a7l2d) — a 10-byte principal, like every mainnet id here. */
const CANISTER = Principal.fromText("a7l2d-caaaa-aaaar-qchja-cai");
/** A self-authenticating II principal is the IC maximum: 29 bytes. */
const OWNER = Principal.fromUint8Array(new Uint8Array(29).fill(0x5a));
/** `MAX_DEVICE_ID_BYTES` = 64: the longest device id the canister admits. */
const LONGEST_DEVICE_ID = "a".repeat(64);

async function envelopeFor(deviceId: string, passcode?: string): Promise<Uint8Array> {
  const keys = await generateDeviceKeys();
  const pub = await exportDevicePublicKeys(keys);
  return wrapVetKeyForDevice(
    { canisterId: CANISTER, owner: OWNER, deviceId, encSpki: pub.encSpki },
    FIXTURE_VETKEY(),
    passcode,
  );
}

describe("AC-7 — the real device envelope fits the canister's 1024-byte stored bound", () => {
  it("fixture shape: the principals and ids are the sizes the arithmetic assumes", () => {
    expect(CANISTER.toUint8Array().length).toBe(10);
    expect(OWNER.toUint8Array().length).toBe(29);
    expect(new TextEncoder().encode(LONGEST_DEVICE_ID).length).toBe(64);
    expect(new TextEncoder().encode(randomDeviceId()).length).toBe(32);
  });

  it("II-only, longest device id: exactly 583 bytes, ≤ 1024", async () => {
    const env = await envelopeFor(LONGEST_DEVICE_ID);
    expect(decodeEnvelope(env).header.mode).toBe(EnvelopeMode.IiOnly);
    expect(env.length).toBe(583);
    expect(env.length).toBeLessThanOrEqual(CANISTER_STORED_BOUND);
  }, 60_000);

  it("passcode, longest device id: exactly 627 bytes (the protocol ceiling), ≤ 1024", async () => {
    const env = await envelopeFor(LONGEST_DEVICE_ID, "correct horse battery staple");
    expect(decodeEnvelope(env).header.mode).toBe(EnvelopeMode.Passcode);
    expect(env.length).toBe(627);
    expect(env.length).toBeLessThanOrEqual(CANISTER_STORED_BOUND);
  }, 120_000);

  it("what the wallet generates today (randomDeviceId): 551 II-only / 595 passcode — both over the OLD 512 cap", async () => {
    const ii = await envelopeFor(randomDeviceId());
    const pass = await envelopeFor(randomDeviceId(), "correct horse battery staple");
    expect(ii.length).toBe(551);
    expect(pass.length).toBe(595);
    // The defect, stated: the pre-lane cap refused both of these.
    expect(ii.length).toBeGreaterThan(512);
    expect(pass.length).toBeGreaterThan(512);
    expect(Math.max(ii.length, pass.length)).toBeLessThanOrEqual(CANISTER_STORED_BOUND);
  }, 120_000);
});
