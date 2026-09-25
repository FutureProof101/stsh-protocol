/**
 * STSH W-VETKEYS Layer 1 — per-device keys, envelopes, and signed approvals
 * (design brief V4 2ab2d6d8…, CTO ruling D-1 2f173cad… as amended by D-1a)
 *
 * THE POINT OF THIS MODULE: after a principal's first device exists, ordinary
 * logins, sessions and new-device approvals perform ZERO vetKD derives. The
 * master note secret is wrapped to each authorized device's non-extractable
 * public key and stored canister-side; a device unwraps its own envelope in
 * memory and the scanner proceeds. Layer 2 (a real derive) is reserved for
 * first-ever bootstrap and genuine all-devices-lost recovery.
 *
 * SPLIT KNOWLEDGE. The canister holds the envelope and never the plaintext;
 * the device holds the unwrap key and never exports it. A passive canister
 * compromise reads nothing; a stolen offline device alone reads nothing.
 *
 * NON-EXTRACTABLE, ALWAYS. Every private key here is generated with
 * `extractable: false`. Nothing in this design needs a private half exported,
 * so the capability is simply never granted — that is a stronger statement
 * than a policy not to call `exportKey`.
 *
 * The unwrapped master secret is MEMORY-ONLY and is never written anywhere:
 * see the amended HARD RULE in ../storage/noteCache.ts.
 */

import { Principal } from "@dfinity/principal";

/**
 * Device ENCRYPTION keypair — RSA-OAEP-3072 / SHA-256.
 *
 * WHY RSA-OAEP AND NOT ECDH+HKDF+AES: WebCrypto offers no native ECIES, so an
 * EC choice means hand-composing a hybrid scheme (ephemeral ECDH → KDF → AEAD)
 * in application code. RSA-OAEP is one named primitive doing one job, natively
 * supported, and the payload is a single 32-byte secret — far inside the
 * ~318-byte OAEP limit for a 3072-bit modulus. Fewer moving parts is the
 * security argument here.
 */
export const DEVICE_ENC_ALGORITHM: RsaHashedKeyGenParams = {
  name: "RSA-OAEP",
  modulusLength: 3072,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: "SHA-256",
};

/** Device SIGNING keypair — P-256 ECDSA, used only for approval transcripts. */
export const DEVICE_SIGN_ALGORITHM: EcKeyGenParams = {
  name: "ECDSA",
  namedCurve: "P-256",
};

/** The master note secret is 32 bytes; the wrapped envelope is 384 (3072/8). */
export const MASTER_SECRET_BYTES = 32;
export const WRAPPED_ENVELOPE_BYTES = 384;

/** Transcript constants — MUST byte-match canisters/vetkeys/src/transcript.rs. */
export const TRANSCRIPT_PROTOCOL = "stsh.vetkeys.device-approval";
export const TRANSCRIPT_VERSION = 1;
export const ACTION_REGISTER_DEVICE = "register_device";
export const ACTION_REVOKE_DEVICE = "revoke_device";
/** Action tag for `replace_envelope` (D-1b v3 §2). */
export const ACTION_REPLACE_ENVELOPE = "replace_envelope";
/** Action tag for `set_device_approval_policy` (LAUNCH-HARDEN-04 O-8). */
export const ACTION_SET_DEVICE_APPROVAL_POLICY = "set_device_approval_policy";

/** Approval nonces are 16 bytes, single-use, scoped to (principal, issuer). */
export const NONCE_BYTES = 16;

/** The P-256 group order `n`, for the low-S normalization below. */
const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export interface DeviceKeyPair {
  encryption: CryptoKeyPair;
  signing: CryptoKeyPair;
}

export interface DevicePublicKeys {
  /** SPKI DER — exactly what the canister stores and hashes. */
  encSpki: Uint8Array;
  signSpki: Uint8Array;
}

/**
 * Generate a device's two keypairs. Both private halves are NON-EXTRACTABLE
 * and stay inside WebCrypto; only the public halves are ever exported.
 */
export async function generateDeviceKeys(
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<DeviceKeyPair> {
  const encryption = (await subtle.generateKey(DEVICE_ENC_ALGORITHM, false, [
    "encrypt",
    "decrypt",
  ])) as CryptoKeyPair;
  const signing = (await subtle.generateKey(DEVICE_SIGN_ALGORITHM, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return { encryption, signing };
}

/** Export the PUBLIC halves as SPKI DER. Private halves cannot be exported. */
export async function exportDevicePublicKeys(
  keys: DeviceKeyPair,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<DevicePublicKeys> {
  return {
    encSpki: new Uint8Array(await subtle.exportKey("spki", keys.encryption.publicKey)),
    signSpki: new Uint8Array(await subtle.exportKey("spki", keys.signing.publicKey)),
  };
}

/**
 * Wrap the 32-byte master note secret to a device's encryption public key.
 *
 * Done CLIENT-SIDE, always: the canister must never see the plaintext, which
 * is the whole of split knowledge. `encSpki` is the target device's exported
 * public key — for a new device being approved, that is the key inside the
 * approval transcript, so the envelope and the transcript commit to the same
 * device.
 */
export async function wrapMasterSecret(
  encSpki: Uint8Array,
  masterSecret: Uint8Array,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<Uint8Array> {
  if (masterSecret.length !== MASTER_SECRET_BYTES) {
    throw new Error(
      `master note secret must be ${MASTER_SECRET_BYTES} bytes, got ${masterSecret.length}`,
    );
  }
  const key = await subtle.importKey(
    "spki",
    bufferSource(encSpki),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
  const wrapped = await subtle.encrypt({ name: "RSA-OAEP" }, key, bufferSource(masterSecret));
  return new Uint8Array(wrapped);
}

/**
 * Unwrap this device's envelope. The result is MEMORY-ONLY — callers must drop
 * it on lock() and must never persist it (../storage/noteCache.ts HARD RULE).
 */
export async function unwrapMasterSecret(
  privateKey: CryptoKey,
  envelope: Uint8Array,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<Uint8Array> {
  const plain = new Uint8Array(
    await subtle.decrypt({ name: "RSA-OAEP" }, privateKey, bufferSource(envelope)),
  );
  if (plain.length !== MASTER_SECRET_BYTES) {
    // A wrong-length plaintext means the envelope was not one of ours; refuse
    // rather than hand a caller something it will use as a root secret.
    throw new Error(
      `unwrapped envelope is ${plain.length} bytes, expected ${MASTER_SECRET_BYTES}`,
    );
  }
  return plain;
}

// ── Canonical transcripts (byte-identical to the canister's) ─────────────────
//
// Encoding rule, frozen: every VARIABLE-length field is `u32-LE length ||
// bytes`; fixed-width fields are raw at their pinned widths (version u16-LE,
// hashes 32 B, nonce 16 B, expiry u64-LE); field order is fixed; nothing else
// is appended. These bytes are what the device signs and what the canister
// REBUILDS and verifies — a divergence of one byte fails every approval, which
// is why the frozen Rust vectors are re-asserted from this side in the tests.

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

function u16le(n: number): Uint8Array {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, true);
  return b;
}

function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
}

function varField(bytes: Uint8Array): Uint8Array {
  return concatBytes([u32le(bytes.length), bytes]);
}

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export interface ApprovalFields {
  canisterId: Principal;
  owner: Principal;
  issuerDeviceId: string;
  newDeviceId: string;
  encPubkeyHash: Uint8Array;
  signPubkeyHash: Uint8Array;
  wrappedSecretHash: Uint8Array;
  nonce: Uint8Array;
  expiryNs: bigint;
}

export function encodeApprovalV1(f: ApprovalFields): Uint8Array {
  assertFixed(f.encPubkeyHash, 32, "encPubkeyHash");
  assertFixed(f.signPubkeyHash, 32, "signPubkeyHash");
  assertFixed(f.wrappedSecretHash, 32, "wrappedSecretHash");
  assertFixed(f.nonce, NONCE_BYTES, "nonce");
  return concatBytes([
    varField(utf8(TRANSCRIPT_PROTOCOL)),
    u16le(TRANSCRIPT_VERSION),
    varField(f.canisterId.toUint8Array()),
    varField(utf8(ACTION_REGISTER_DEVICE)),
    varField(f.owner.toUint8Array()),
    varField(utf8(f.issuerDeviceId)),
    varField(utf8(f.newDeviceId)),
    f.encPubkeyHash,
    f.signPubkeyHash,
    f.wrappedSecretHash,
    f.nonce,
    u64le(f.expiryNs),
  ]);
}

export interface RevokeFields {
  canisterId: Principal;
  owner: Principal;
  issuerDeviceId: string;
  targetDeviceId: string;
  nonce: Uint8Array;
  expiryNs: bigint;
}

export function encodeRevokeV1(f: RevokeFields): Uint8Array {
  assertFixed(f.nonce, NONCE_BYTES, "nonce");
  return concatBytes([
    varField(utf8(TRANSCRIPT_PROTOCOL)),
    u16le(TRANSCRIPT_VERSION),
    varField(f.canisterId.toUint8Array()),
    varField(utf8(ACTION_REVOKE_DEVICE)),
    varField(f.owner.toUint8Array()),
    varField(utf8(f.issuerDeviceId)),
    varField(utf8(f.targetDeviceId)),
    f.nonce,
    u64le(f.expiryNs),
  ]);
}

export interface ReplaceFields {
  canisterId: Principal;
  owner: Principal;
  deviceId: string;
  oldEnvelopeHash: Uint8Array;
  newEnvelopeHash: Uint8Array;
  nonce: Uint8Array;
  expiryNs: bigint;
}

/**
 * `ReplaceV1` — the self-signed envelope replacement (D-1b v3 §2).
 *
 * `oldEnvelopeHash` is the anti-rollback field: the canister rebuilds this
 * transcript from what it has stored RIGHT NOW, so a signature naming a
 * superseded envelope simply does not verify. The wallet must therefore hash
 * the envelope it just fetched, not one it remembers.
 */
export function encodeReplaceV1(f: ReplaceFields): Uint8Array {
  assertFixed(f.oldEnvelopeHash, 32, "oldEnvelopeHash");
  assertFixed(f.newEnvelopeHash, 32, "newEnvelopeHash");
  assertFixed(f.nonce, NONCE_BYTES, "nonce");
  return concatBytes([
    varField(utf8(TRANSCRIPT_PROTOCOL)),
    u16le(TRANSCRIPT_VERSION),
    varField(f.canisterId.toUint8Array()),
    varField(utf8(ACTION_REPLACE_ENVELOPE)),
    varField(f.owner.toUint8Array()),
    varField(utf8(f.deviceId)),
    f.oldEnvelopeHash,
    f.newEnvelopeHash,
    f.nonce,
    u64le(f.expiryNs),
  ]);
}

export interface SetDeviceApprovalPolicyFields {
  canisterId: Principal;
  owner: Principal;
  issuerDeviceId: string;
  requireDeviceApproval: boolean;
  nonce: Uint8Array;
  expiryNs: bigint;
}

/**
 * `SetDeviceApprovalPolicyV1` — an ACTIVE device sets (`true`) or clears
 * (`false`) its principal's "require device approval" flag (LAUNCH-HARDEN-04
 * O-8; WALLET-V12 O-4). Same encoding rule as the others; the flag is a FIXED
 * 1-byte field (0 | 1) directly after the issuer id
 * (`canisters/vetkeys/src/transcript.rs`), so a signature over "set" can never
 * be replayed as "clear". Signed by the EXISTING device signing key — no new
 * key, no new derive (I-2).
 */
export function encodeSetDeviceApprovalPolicyV1(f: SetDeviceApprovalPolicyFields): Uint8Array {
  assertFixed(f.nonce, NONCE_BYTES, "nonce");
  return concatBytes([
    varField(utf8(TRANSCRIPT_PROTOCOL)),
    u16le(TRANSCRIPT_VERSION),
    varField(f.canisterId.toUint8Array()),
    varField(utf8(ACTION_SET_DEVICE_APPROVAL_POLICY)),
    varField(f.owner.toUint8Array()),
    varField(utf8(f.issuerDeviceId)),
    new Uint8Array([f.requireDeviceApproval ? 1 : 0]),
    f.nonce,
    u64le(f.expiryNs),
  ]);
}

/**
 * Sign a transcript with this device's signing key, NORMALIZED TO LOW-S.
 *
 * THIS NORMALIZATION IS LOAD-BEARING, not hygiene. The canister REFUSES a
 * high-S signature outright (it never normalizes-then-accepts, because that
 * would make two distinct byte strings verify against one transcript). P-256
 * signers do NOT produce low-S by convention — neither WebCrypto nor
 * RustCrypto — so roughly HALF of all honest signatures come out high-S. Ship
 * this without the normalization and about half of all device approvals fail
 * with an opaque rejection.
 */
export async function signTranscript(
  signingKey: CryptoKey,
  transcript: Uint8Array,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<Uint8Array> {
  const raw = new Uint8Array(
    await subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      signingKey,
      bufferSource(transcript),
    ),
  );
  return normalizeLowS(raw);
}

/**
 * `(r, s)` → `(r, n - s)` when `s > n/2`. The pair is still a valid signature
 * for the same message and key — that is precisely the ECDSA malleability the
 * canister's low-S rule closes, used here in the honest direction.
 */
export function normalizeLowS(signature: Uint8Array): Uint8Array {
  if (signature.length !== 64) {
    throw new Error(`expected a 64-byte P-256 (r || s) signature, got ${signature.length}`);
  }
  const s = bytesToBigInt(signature.subarray(32));
  if (s <= P256_ORDER / 2n) return signature;
  const out = new Uint8Array(signature);
  out.set(bigIntToBytes(P256_ORDER - s, 32), 32);
  return out;
}

/** SHA-256, for the three hashes the approval transcript binds. */
export async function sha256(
  bytes: Uint8Array,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest("SHA-256", bufferSource(bytes)));
}

/** A fresh single-use approval nonce. */
export function randomNonce(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
}

/** A fresh device id — opaque, 16 random bytes as lowercase hex (32 chars). */
export function randomDeviceId(): string {
  return [...globalThis.crypto.getRandomValues(new Uint8Array(16))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function assertFixed(bytes: Uint8Array, width: number, name: string): void {
  if (bytes.length !== width) {
    throw new Error(`${name} must be exactly ${width} bytes, got ${bytes.length}`);
  }
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function bigIntToBytes(n: bigint, width: number): Uint8Array {
  const out = new Uint8Array(width);
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

/**
 * Realm/interop guard: hand WebCrypto a TIGHT `Uint8Array` copy, never a raw
 * `ArrayBuffer`.
 *
 * Two environment-dependent failure modes are closed at once: a view whose
 * underlying buffer is larger than the view (some implementations reject it),
 * and a cross-realm `ArrayBuffer`, which jsdom refuses outright with
 * `ERR_INVALID_ARG_TYPE` even though the bytes are fine. A typed-array copy is
 * accepted everywhere and costs nothing at these sizes.
 */
function bufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  // Built on a fresh, exactly-sized `ArrayBuffer` so the type is
  // `Uint8Array<ArrayBuffer>` — `slice()` keeps the `ArrayBufferLike` parameter,
  // which WebCrypto's TypeScript signatures reject.
  const copy = new Uint8Array(new ArrayBuffer(bytes.length));
  copy.set(bytes);
  return copy;
}
