/**
 * STSH W-VETKEYS Layer 1 — the ZERO-DERIVE path (D-1b v3/v4 + brief V4)
 *
 * Composes ./devices (device keys) and ./envelope (the stored blob) into the
 * two operations the wallet actually performs:
 *
 *   wrapVetKeyForDevice  — after a Layer-2 ceremony, seal the raw vetKey to
 *                          this device (optionally under a passcode);
 *   openVetKeyEnvelope   — on every later login, open it, with NO derive.
 *
 * Plus the two cache-unlock keys (v3 §3), which are deliberately derived from
 * DIFFERENT inputs in the two modes and never reuse a key, nonce or AAD with
 * the envelope.
 *
 * MEMORY-ONLY, ALWAYS. Everything returned here is plaintext key material. It
 * lives in memory, and callers drop it on lock/logout. See the HARD RULE in
 * ../storage/noteCache.ts.
 */

import { VetKey } from "@dfinity/vetkeys";

import {
  buildEnvelope,
  decodeEnvelope,
  EnvelopeBinding,
  EnvelopeFormatError,
  EnvelopeMode,
  envelopePasscodeKeyBytes,
  openEnvelope,
  VETKEY_SERIALIZED_BYTES,
} from "./envelope";
import { unwrapMasterSecret, wrapMasterSecret } from "./devices";

/**
 * Note-cache unlock domain, II-only mode (v3 §3) — its OWN domain separator.
 *
 * Never the raw vetKey bytes and never the note-master domain: the cache key
 * and the note-secret root must be independent, so that learning one does not
 * yield the other.
 */
export const CACHE_UNLOCK_DOMAIN = "stsh-note-cache-unlock-v1";

/** Note-cache subkey domain, passcode mode (v3 §3) — HKDF info string. */
export const CACHE_PASSCODE_INFO = "stsh-note-cache-passcode-v1";

/** Both cache keys are 32 bytes. */
export const CACHE_KEY_BYTES = 32;

/**
 * Serialize a vetKey for wrapping, with the ROUND TRIP VERIFIED (v3 §2(6)).
 *
 * This is the pin that makes a `@dfinity/vetkeys` upgrade a loud failure rather
 * than a silent one: if the encoding ever changes width or format, an envelope
 * written today could not be opened tomorrow, and the user's notes would be
 * unrecoverable with no error to point at. So the bytes are re-parsed and
 * re-serialized here, BEFORE anything is stored.
 */
export function serializeVetKeyChecked(vetKey: VetKey): Uint8Array {
  const bytes = vetKey.serialize();
  if (bytes.length !== VETKEY_SERIALIZED_BYTES) {
    throw new EnvelopeFormatError(
      `vetKey serialization is ${bytes.length} bytes, expected the pinned ` +
        `${VETKEY_SERIALIZED_BYTES} — refusing to wrap an unrecognised encoding`,
    );
  }
  const roundTripped = VetKey.deserialize(bytes).serialize();
  if (
    roundTripped.length !== bytes.length ||
    !bytes.every((b, i) => b === roundTripped[i])
  ) {
    throw new EnvelopeFormatError(
      "vetKey serialization does not round-trip — refusing to wrap it",
    );
  }
  return bytes;
}

/** Parse wrapped bytes back into a vetKey, refusing anything unexpected. */
export function deserializeVetKeyChecked(bytes: Uint8Array): VetKey {
  if (bytes.length !== VETKEY_SERIALIZED_BYTES) {
    throw new EnvelopeFormatError(
      `unwrapped vetKey is ${bytes.length} bytes, expected ${VETKEY_SERIALIZED_BYTES}`,
    );
  }
  // Trailing or malformed encodings throw out of `deserialize`; we do not
  // rescue them into a "best effort" key.
  return VetKey.deserialize(bytes);
}

/**
 * Seal the raw vetKey to this device. `passcode === undefined` is the II-only
 * default; supplying one produces the passcode-mode envelope.
 */
export async function wrapVetKeyForDevice(
  binding: EnvelopeBinding,
  vetKey: VetKey,
  passcode?: string,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<Uint8Array> {
  const bytes = serializeVetKeyChecked(vetKey);
  const deviceCiphertext = await wrapMasterSecretSized(binding.encSpki, bytes, subtle);
  return buildEnvelope(binding, deviceCiphertext, passcode, subtle);
}

/**
 * Open a stored envelope and recover the vetKey. ZERO vetKD derives — this is
 * the whole point of Layer 1.
 */
export async function openVetKeyEnvelope(
  envelope: Uint8Array,
  binding: EnvelopeBinding,
  devicePrivateKey: CryptoKey,
  passcode?: string,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<VetKey> {
  const deviceCiphertext = await openEnvelope(envelope, binding, passcode, subtle);
  const bytes = await unwrapMasterSecretSized(devicePrivateKey, deviceCiphertext, subtle);
  return deserializeVetKeyChecked(bytes);
}

/** Is this stored envelope passcode-protected? For UX and for the toggle. */
export function envelopeIsPasscodeProtected(envelope: Uint8Array): boolean {
  return decodeEnvelope(envelope).header.mode === EnvelopeMode.Passcode;
}

/**
 * The note-cache unlock key in II-ONLY mode: derived from the vetKey under its
 * own domain separator (v3 §3). Pinned by a fixed vector in the tests.
 */
export function cacheUnlockKeyIiOnly(vetKey: VetKey): Uint8Array {
  return vetKey.deriveSymmetricKey(CACHE_UNLOCK_DOMAIN, CACHE_KEY_BYTES);
}

/**
 * The note-cache unlock key in PASSCODE mode: HKDF-SHA-256 over the envelope's
 * Argon2id output (v3 §3).
 *
 * The Argon2id result is NOT reused raw. One expensive derivation feeds two
 * independent keys through different `info` strings, so compromising the cache
 * key does not hand over the envelope key, and neither shares a nonce or AAD
 * domain with the other.
 */
export async function cacheUnlockKeyFromPasscode(
  passcode: string,
  envelopeSalt: Uint8Array,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<Uint8Array> {
  const passcodeKey = await envelopePasscodeKeyBytes(passcode, envelopeSalt);
  try {
    return await hkdfSha256(passcodeKey, CACHE_PASSCODE_INFO, CACHE_KEY_BYTES, subtle);
  } finally {
    passcodeKey.fill(0);
  }
}

async function hkdfSha256(
  ikm: Uint8Array,
  info: string,
  length: number,
  subtle: SubtleCrypto,
): Promise<Uint8Array> {
  const key = await subtle.importKey("raw", tight(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      // Salt is empty BY DESIGN: the IKM is already a high-entropy Argon2id
      // output over a random per-envelope salt, so a second salt would add
      // nothing while creating another value to store and keep in sync.
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(info),
    },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

function tight(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(new ArrayBuffer(bytes.length));
  copy.set(bytes);
  return copy;
}

/**
 * The device wrap/unwrap pair, widened from the 32-byte master secret to the
 * 48-byte vetKey.
 *
 * `devices.ts` still exposes the 32-byte helpers because the master note secret
 * is still derived and used — what changed in D-1b is WHAT gets sealed to the
 * device, not that the master secret stopped existing.
 */
async function wrapMasterSecretSized(
  encSpki: Uint8Array,
  plaintext: Uint8Array,
  subtle: SubtleCrypto,
): Promise<Uint8Array> {
  const key = await subtle.importKey(
    "spki",
    tight(encSpki),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
  return new Uint8Array(await subtle.encrypt({ name: "RSA-OAEP" }, key, tight(plaintext)));
}

async function unwrapMasterSecretSized(
  privateKey: CryptoKey,
  ciphertext: Uint8Array,
  subtle: SubtleCrypto,
): Promise<Uint8Array> {
  return new Uint8Array(
    await subtle.decrypt({ name: "RSA-OAEP" }, privateKey, tight(ciphertext)),
  );
}

// Re-exported so callers have one import for the Layer-1 surface.
export { wrapMasterSecret, unwrapMasterSecret };
