/**
 * W-VETKEYS Layer 1 (wallet side) — device keys, envelopes, transcripts.
 *
 * The load-bearing arm in this file is the FROZEN-VECTOR one: the wallet's
 * transcript encoder is asserted against the byte-exact vectors frozen in
 * canisters/vetkeys/src/transcript.rs. Two independent implementations, one
 * pinned answer — if either side drifts, approvals stop verifying in
 * production, and this test is what says so first.
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";
import {
  encodeApprovalV1,
  encodeRevokeV1,
  encodeSetDeviceApprovalPolicyV1,
  exportDevicePublicKeys,
  generateDeviceKeys,
  normalizeLowS,
  randomDeviceId,
  randomNonce,
  sha256,
  signTranscript,
  unwrapMasterSecret,
  wrapMasterSecret,
  MASTER_SECRET_BYTES,
  WRAPPED_ENVELOPE_BYTES,
} from "../src/crypto/devices";
import {
  DEVICE_APPROVAL_CLOCK_MARGIN_NS,
  classifyDeviceApprovalPolicy,
} from "../src/ui/deviceApprovalCopy";

const hex = (b: Uint8Array): string =>
  [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

/** The exact fixture frozen in canisters/vetkeys/src/transcript.rs. */
const CANISTER = Principal.fromUint8Array(
  new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x01]),
);
const OWNER = Principal.fromUint8Array(
  new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x02, 0x01]),
);
const fill = (byte: number, n: number) => new Uint8Array(n).fill(byte);

const APPROVAL_V1_VECTOR_HEX =
  "1c000000737473682e7665746b6579732e6465766963652d617070726f76616c01000a000000010203040506070801010f00000072656769737465725f6465766963650a000000aabbccddeeff001102010d0000006465766963652d6973737565720a0000006465766963652d6e65771111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444400002a36fe9c9717";

const REVOKE_V1_VECTOR_HEX =
  "1c000000737473682e7665746b6579732e6465766963652d617070726f76616c01000a000000010203040506070801010d0000007265766f6b655f6465766963650a000000aabbccddeeff001102010d0000006465766963652d6973737565720d0000006465766963652d7461726765745555555555555555555555555555555500002a36fe9c9717";

/**
 * LAUNCH-HARDEN-04 O-8 — `SET_DEVICE_APPROVAL_POLICY_V1_VECTOR_HEX`, copied
 * byte-for-byte from canisters/vetkeys/src/transcript.rs (its literal is
 * computed outside the Rust encoder). WALLET-V12 O-4's cross-language drift lock.
 */
const SET_DEVICE_APPROVAL_POLICY_V1_VECTOR_HEX =
  "1c000000737473682e7665746b6579732e6465766963652d617070726f76616c01000a000000010203040506070801011a0000007365745f6465766963655f617070726f76616c5f706f6c6963790a000000aabbccddeeff001102010d0000006465766963652d697373756572019999999999999999999999999999999900002a36fe9c9717";

describe("WALLET-V12 — SetDeviceApprovalPolicyV1 is byte-identical to the canister", () => {
  const fields = {
    canisterId: CANISTER,
    owner: OWNER,
    issuerDeviceId: "device-issuer",
    requireDeviceApproval: true,
    nonce: fill(0x99, 16),
    expiryNs: 1_700_000_000_000_000_000n,
  };

  it("matches the frozen Rust vector, byte for byte (and its frozen SHA-256)", async () => {
    const bytes = encodeSetDeviceApprovalPolicyV1(fields);
    expect(hex(bytes)).toBe(SET_DEVICE_APPROVAL_POLICY_V1_VECTOR_HEX);
    expect(hex(await sha256(bytes))).toBe(
      "df2c890eb526e1c1c50e8f3d960e73e9e8d2941a752851aace59ad07da2b99b2",
    );
  });

  it("the 1-byte flag sits directly after the issuer id: set and clear differ in exactly that byte", () => {
    const on = encodeSetDeviceApprovalPolicyV1(fields);
    const off = encodeSetDeviceApprovalPolicyV1({ ...fields, requireDeviceApproval: false });
    expect(on.length).toBe(off.length);
    const diffs = [...on].map((b, i) => (b !== off[i] ? i : -1)).filter((i) => i >= 0);
    const flagAt = on.length - 8 - 16 - 1; // … ‖ flag ‖ nonce(16) ‖ expiry(8)
    expect(diffs).toEqual([flagAt]);
    expect(on[flagAt]).toBe(1);
    expect(off[flagAt]).toBe(0);
  });

  it("never aliases the other device-approval actions", () => {
    const setBytes = hex(encodeSetDeviceApprovalPolicyV1(fields));
    const revoke = hex(
      encodeRevokeV1({
        canisterId: CANISTER,
        owner: OWNER,
        issuerDeviceId: "device-issuer",
        targetDeviceId: "device-target",
        nonce: fill(0x99, 16),
        expiryNs: fields.expiryNs,
      }),
    );
    expect(setBytes).not.toBe(revoke);
    expect(setBytes.startsWith(revoke)).toBe(false);
  });
});

describe("W-VETKEYS transcripts — byte-identical to the canister", () => {
  it("ApprovalV1 matches the frozen Rust vector, byte for byte", () => {
    const bytes = encodeApprovalV1({
      canisterId: CANISTER,
      owner: OWNER,
      issuerDeviceId: "device-issuer",
      newDeviceId: "device-new",
      encPubkeyHash: fill(0x11, 32),
      signPubkeyHash: fill(0x22, 32),
      wrappedSecretHash: fill(0x33, 32),
      nonce: fill(0x44, 16),
      expiryNs: 1_700_000_000_000_000_000n,
    });
    expect(hex(bytes)).toBe(APPROVAL_V1_VECTOR_HEX);
  });

  it("RevokeV1 matches the frozen Rust vector, byte for byte", () => {
    const bytes = encodeRevokeV1({
      canisterId: CANISTER,
      owner: OWNER,
      issuerDeviceId: "device-issuer",
      targetDeviceId: "device-target",
      nonce: fill(0x55, 16),
      expiryNs: 1_700_000_000_000_000_000n,
    });
    expect(hex(bytes)).toBe(REVOKE_V1_VECTOR_HEX);
  });

  it("the two actions never alias, and neither prefixes the other", () => {
    const shared = {
      canisterId: CANISTER,
      owner: OWNER,
      issuerDeviceId: "device-issuer",
      nonce: fill(0x44, 16),
      expiryNs: 1_700_000_000_000_000_000n,
    };
    const approval = hex(
      encodeApprovalV1({
        ...shared,
        newDeviceId: "device-x",
        encPubkeyHash: fill(0x11, 32),
        signPubkeyHash: fill(0x22, 32),
        wrappedSecretHash: fill(0x33, 32),
      }),
    );
    const revoke = hex(encodeRevokeV1({ ...shared, targetDeviceId: "device-x" }));
    expect(approval).not.toBe(revoke);
    expect(approval.startsWith(revoke)).toBe(false);
    expect(revoke.startsWith(approval)).toBe(false);
  });

  it("length-prefixes keep adjacent device ids unambiguous", () => {
    const base = {
      canisterId: CANISTER,
      owner: OWNER,
      encPubkeyHash: fill(0x11, 32),
      signPubkeyHash: fill(0x22, 32),
      wrappedSecretHash: fill(0x33, 32),
      nonce: fill(0x44, 16),
      expiryNs: 1n,
    };
    const left = encodeApprovalV1({ ...base, issuerDeviceId: "ab", newDeviceId: "c" });
    const right = encodeApprovalV1({ ...base, issuerDeviceId: "a", newDeviceId: "bc" });
    expect(hex(left)).not.toBe(hex(right));
  });

  it("refuses a hash or nonce of the wrong width rather than padding it", () => {
    const bad = {
      canisterId: CANISTER,
      owner: OWNER,
      issuerDeviceId: "i",
      newDeviceId: "n",
      encPubkeyHash: fill(0x11, 31),
      signPubkeyHash: fill(0x22, 32),
      wrappedSecretHash: fill(0x33, 32),
      nonce: fill(0x44, 16),
      expiryNs: 1n,
    };
    expect(() => encodeApprovalV1(bad)).toThrow(/exactly 32 bytes/);
  });
});

describe("W-VETKEYS device keys and envelopes", () => {
  it("generates NON-EXTRACTABLE private halves and exports only public SPKI", async () => {
    const keys = await generateDeviceKeys();
    expect(keys.encryption.privateKey.extractable).toBe(false);
    expect(keys.signing.privateKey.extractable).toBe(false);
    // The capability is simply not granted: exporting must FAIL, not merely
    // be avoided by convention.
    await expect(
      globalThis.crypto.subtle.exportKey("pkcs8", keys.encryption.privateKey),
    ).rejects.toBeTruthy();

    const pub = await exportDevicePublicKeys(keys);
    expect(pub.encSpki.length).toBeGreaterThan(0);
    expect(pub.signSpki.length).toBeGreaterThan(0);
  }, 30_000);

  it("wraps and unwraps the master secret; only the holding device can read it", async () => {
    const alice = await generateDeviceKeys();
    const mallory = await generateDeviceKeys();
    const pub = await exportDevicePublicKeys(alice);
    const master = globalThis.crypto.getRandomValues(new Uint8Array(MASTER_SECRET_BYTES));

    const envelope = await wrapMasterSecret(pub.encSpki, master);
    expect(envelope.length).toBe(WRAPPED_ENVELOPE_BYTES);
    // SPLIT KNOWLEDGE: the envelope alone is not the secret.
    expect(hex(envelope)).not.toContain(hex(master));

    expect(hex(await unwrapMasterSecret(alice.encryption.privateKey, envelope))).toBe(hex(master));
    await expect(
      unwrapMasterSecret(mallory.encryption.privateKey, envelope),
    ).rejects.toBeTruthy();
  }, 30_000);

  it("refuses to wrap anything that is not a 32-byte master secret", async () => {
    const keys = await generateDeviceKeys();
    const pub = await exportDevicePublicKeys(keys);
    await expect(wrapMasterSecret(pub.encSpki, new Uint8Array(31))).rejects.toThrow(/32 bytes/);
  }, 30_000);
});

describe("W-VETKEYS approval signatures", () => {
  /**
   * The canister REFUSES high-S signatures (it never normalizes-then-accepts).
   * WebCrypto does not produce low-S by convention, so without this
   * normalization roughly half of all honest approvals would be rejected.
   * Repeated so the arm actually crosses the high-S case rather than passing
   * on a lucky draw.
   */
  it("always emits LOW-S signatures", async () => {
    const keys = await generateDeviceKeys();
    const order =
      0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    for (let i = 0; i < 12; i++) {
      const sig = await signTranscript(
        keys.signing.privateKey,
        new TextEncoder().encode(`transcript ${i}`),
      );
      expect(sig.length).toBe(64);
      const s = [...sig.subarray(32)].reduce((n, b) => (n << 8n) | BigInt(b), 0n);
      expect(s <= order / 2n).toBe(true);
    }
  }, 60_000);

  it("a normalized signature still verifies — normalization is honest, not a forgery", async () => {
    const keys = await generateDeviceKeys();
    const msg = new TextEncoder().encode("canonical transcript");
    const sig = await signTranscript(keys.signing.privateKey, msg);
    const ok = await globalThis.crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      keys.signing.publicKey,
      sig.slice(),
      msg.slice(),
    );
    expect(ok).toBe(true);
  }, 30_000);

  /**
   * THE PAIRED ARM. An HONEST high-S signature — one WebCrypto really produced
   * — is a valid signature that the canister nonetheless REFUSES. Normalizing
   * it must yield a DIFFERENT byte string that is still valid. Both halves are
   * asserted here, and the canister side of the pair
   * (`c10_a_high_s_signature_is_refused_at_the_boundary`) refuses the raw form
   * and accepts this one. If either side stops, one of the two arms fails.
   */
  it("an honest high-S signature is valid, and normalizing it keeps it valid", async () => {
    const keys = await generateDeviceKeys();
    const order =
      0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const sBigInt = (sig: Uint8Array) =>
      [...sig.subarray(32)].reduce((n, b) => (n << 8n) | BigInt(b), 0n);
    const verify = (sig: Uint8Array, msg: Uint8Array) =>
      globalThis.crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        keys.signing.publicKey,
        sig.slice(),
        msg.slice(),
      );

    // Sign until WebCrypto hands us a genuinely high-S signature. It does about
    // half the time — which is exactly why the normalization is load-bearing.
    let raw: Uint8Array | null = null;
    let msg = new Uint8Array();
    for (let i = 0; i < 40 && raw === null; i++) {
      msg = new TextEncoder().encode(`high-s hunt ${i}`);
      const candidate = new Uint8Array(
        await globalThis.crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          keys.signing.privateKey,
          msg.slice(),
        ),
      );
      if (sBigInt(candidate) > order / 2n) raw = candidate;
    }
    expect(raw, "WebCrypto produced no high-S signature in 40 tries").not.toBeNull();

    // It IS honest: WebCrypto verifies it. The canister refuses it anyway.
    expect(await verify(raw as Uint8Array, msg)).toBe(true);

    const normalized = normalizeLowS(raw as Uint8Array);
    expect(hex(normalized)).not.toBe(hex(raw as Uint8Array));
    expect(sBigInt(normalized) <= order / 2n).toBe(true);
    expect(await verify(normalized, msg)).toBe(true);
  }, 60_000);

  it("normalizeLowS flips a high-S scalar and leaves a low-S one alone", () => {
    const order =
      0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const toBytes = (n: bigint) => {
      const out = new Uint8Array(32);
      for (let i = 31; i >= 0; i--) {
        out[i] = Number(n & 0xffn);
        n >>= 8n;
      }
      return out;
    };
    const high = new Uint8Array(64);
    high.set(toBytes(order - 3n), 32);
    const flipped = normalizeLowS(high);
    expect(hex(flipped.subarray(32))).toBe(hex(toBytes(3n)));

    const low = new Uint8Array(64);
    low.set(toBytes(7n), 32);
    expect(hex(normalizeLowS(low))).toBe(hex(low));
  });

  it("refuses a signature that is not 64 bytes", () => {
    expect(() => normalizeLowS(new Uint8Array(70))).toThrow(/64-byte/);
  });
});

describe("W-VETKEYS helpers", () => {
  it("sha256 matches a known vector", async () => {
    // SHA-256("abc"), the FIPS 180-4 example.
    expect(hex(await sha256(new TextEncoder().encode("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("nonces and device ids are fresh each time", () => {
    expect(randomNonce().length).toBe(16);
    expect(hex(randomNonce())).not.toBe(hex(randomNonce()));
    expect(randomDeviceId()).toHaveLength(32);
    expect(randomDeviceId()).not.toBe(randomDeviceId());
  });
});

describe("WALLET-V12 — the device-approval read-back, classified against the local clock", () => {
  const NOW = 1_800_000_000_000_000_000n;
  const row = (pending: bigint | null) => ({
    require_device_approval: true,
    set_at_ns: 1n,
    pending_clear_effective_at_ns: pending === null ? ([] as []) : ([pending] as [bigint]),
  });

  it("no row → off; a row → on; a pending clear → pending-clear with its instant", () => {
    expect(classifyDeviceApprovalPolicy(null, NOW)).toEqual({ kind: "off" });
    expect(classifyDeviceApprovalPolicy(row(null), NOW)).toEqual({ kind: "on" });
    const t = NOW + 3_600_000_000_000n;
    expect(classifyDeviceApprovalPolicy(row(t), NOW)).toEqual({ kind: "pending-clear", effectiveAtNs: t });
  });

  it("a matured clear (the canister keeps the row) → off, but only past the skew margin; inside it stays pending", () => {
    const t = NOW - 1n; // just matured by the local clock
    expect(classifyDeviceApprovalPolicy(row(t), NOW).kind, "unsure → pending").toBe("pending-clear");
    expect(classifyDeviceApprovalPolicy(row(NOW - DEVICE_APPROVAL_CLOCK_MARGIN_NS), NOW)).toEqual({ kind: "off" });
  });
});
