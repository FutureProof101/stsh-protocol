/**
 * STSH W-VETKEYS — the DEVICE ENVELOPE (D-1b v3 §2, as carried by v4)
 *
 * The envelope is the one canister-side secret derivative in this design: the
 * user's RAW vetKey, wrapped to a registered device's non-extractable RSA key,
 * and — if the user opts in — wrapped again as a whole under a passcode-derived
 * AES-256-GCM key. It is what makes ordinary logins cost ZERO vetKD derives:
 * a registered device fetches its envelope, opens it in memory, and proceeds.
 *
 * WHY THE RAW vetKey AND NOT THE MASTER NOTE SECRET (D-1b, Owner Option 1):
 * note payloads are IBE-encrypted to the owner's principal, so DISCOVERING a
 * note requires the vetKey itself; the master note secret only derives note
 * secrets from notes already found. Wrapping the master secret alone would have
 * meant every scan, shield and spend still paid for a derive.
 *
 * WHY THE PASSCODE WRAPS THE OUTSIDE (SSA's construction, adopted in v3 §2):
 * `AES-GCM(passcode_key, RSA-OAEP(device_key, vetkey))`, never the reverse and
 * never a second inner layer. The RSA ciphertext is a fixed-size opaque blob;
 * encrypting it whole means the passcode layer has exactly one job, its AAD
 * covers the entire header, and turning the passcode off is a pure unwrapping
 * with nothing left behind. An inside-out construction would let the two layers
 * disagree about what they authenticate.
 *
 * HONESTY (v3 §1 as corrected by v4 §1) — this file implements a wrapping, not
 * a revocation mechanism. An attacker who copied a device's envelope AND can
 * use that device's private key recovers the RAW vetKey, which trial-decrypts
 * every payload addressed to that principal, INCLUDING FUTURE ones. Replacing
 * or deleting the stored envelope does not undo that. The only remedy is
 * migration to a fresh Internet Identity principal (see ../ui/recoveryCopy.ts).
 */

import { Principal } from "@dfinity/principal";
import { argon2id } from "hash-wasm";

import {
  ARGON2ID_ITERATIONS,
  ARGON2ID_KEY_BYTES,
  ARGON2ID_MEMORY_KIB,
  ARGON2ID_PARALLELISM,
  ARGON2ID_SALT_BYTES,
  KDF_VERSION_ARGON2ID,
} from "../storage/noteCache";
import { sha256 } from "./devices";

/** Envelope protocol tag — PINNED. Distinct from the transcript protocol. */
export const ENVELOPE_PROTOCOL = "stsh.vetkeys.device-envelope";
/** Envelope format version — PINNED. Unknown versions fail closed. */
export const ENVELOPE_VERSION = 1;

/** How the envelope is protected. */
export enum EnvelopeMode {
  /** Internet Identity only — the default. Device RSA wrap, nothing else. */
  IiOnly = 0,
  /** Opt-in wallet passcode — the whole RSA ciphertext under AES-256-GCM. */
  Passcode = 1,
}

/** AES-GCM nonce width for the passcode layer. */
export const ENVELOPE_GCM_NONCE_BYTES = 12;

/**
 * The RAW vetKey's serialized width — PINNED to the exact `@dfinity/vetkeys`
 * version in package.json (D-1b v3 §2(6)).
 *
 * A vetKey is a BLS12-381 G1 point in compressed form. Pinning the length here
 * and ROUND-TRIP VERIFYING before the bytes are ever wrapped means a dependency
 * bump that changes the encoding is caught at wrap time — not months later when
 * a user cannot recover.
 */
export const VETKEY_SERIALIZED_BYTES = 48;

export interface EnvelopeBinding {
  /** The vetkeys canister — binds an envelope to one deployment. */
  canisterId: Principal;
  owner: Principal;
  deviceId: string;
  /** SPKI DER of the device's RSA-OAEP encryption public key. */
  encSpki: Uint8Array;
}

export class EnvelopeFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvelopeFormatError";
  }
}

// ── Canonical header ─────────────────────────────────────────────────────────
//
// Same encoding rule as the §C transcripts: every variable-length field is
// u32-LE length-prefixed, fixed-width fields are raw at their pinned widths,
// field order is fixed, nothing else is appended. The header is BOTH a prefix
// of the stored envelope and, in passcode mode, the AES-GCM AAD — so the mode,
// the version, the KDF parameters and the identity the envelope belongs to are
// all authenticated, and none of them can be edited in transit.

const te = new TextEncoder();

function u16le(n: number): Uint8Array {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, true);
  return b;
}

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function varField(bytes: Uint8Array): Uint8Array {
  return concat([u32le(bytes.length), bytes]);
}

export interface EnvelopeHeader extends EnvelopeBinding {
  mode: EnvelopeMode;
  version: number;
  kdfId: number;
  memoryKib: number;
  iterations: number;
  parallelism: number;
  /** Empty in II-only mode; 16 bytes in passcode mode. */
  salt: Uint8Array;
}

/**
 * Serialize the canonical header.
 *
 * The KDF parameters are present in BOTH modes (zeroed in II-only) so the
 * header's shape never depends on the mode — a parser that had to branch on
 * mode before it could find the mode would be a hole.
 */
export async function encodeHeader(header: EnvelopeHeader): Promise<Uint8Array> {
  return concat([
    varField(te.encode(ENVELOPE_PROTOCOL)),
    u16le(header.version),
    new Uint8Array([header.mode]),
    varField(header.canisterId.toUint8Array()),
    varField(header.owner.toUint8Array()),
    varField(te.encode(header.deviceId)),
    await sha256(header.encSpki),
    new Uint8Array([header.kdfId]),
    u32le(header.memoryKib),
    u32le(header.iterations),
    u32le(header.parallelism),
    varField(header.salt),
  ]);
}

function readVar(bytes: Uint8Array, cursor: { at: number }): Uint8Array {
  if (cursor.at + 4 > bytes.length) throw new EnvelopeFormatError("truncated length prefix");
  const len = new DataView(bytes.buffer, bytes.byteOffset).getUint32(cursor.at, true);
  const from = cursor.at + 4;
  if (from + len > bytes.length) throw new EnvelopeFormatError("length prefix overruns envelope");
  cursor.at = from + len;
  return bytes.subarray(from, from + len);
}

function readByte(bytes: Uint8Array, cursor: { at: number }): number {
  if (cursor.at >= bytes.length) throw new EnvelopeFormatError("truncated byte");
  return bytes[cursor.at++];
}

function readU32(bytes: Uint8Array, cursor: { at: number }): number {
  if (cursor.at + 4 > bytes.length) throw new EnvelopeFormatError("truncated u32");
  const v = new DataView(bytes.buffer, bytes.byteOffset).getUint32(cursor.at, true);
  cursor.at += 4;
  return v;
}

/**
 * The header as READ BACK. It carries the device key's HASH, not the key: the
 * hash is what the header commits to, and reconstructing a public key from a
 * digest is not a thing — so the type says so rather than carrying an empty
 * field that looks like data.
 */
export interface ParsedHeader extends Omit<EnvelopeHeader, "encSpki"> {
  encSpkiHash: Uint8Array;
}

/** Parse a stored envelope into its header and body. Fails closed. */
export function decodeEnvelope(envelope: Uint8Array): {
  header: ParsedHeader;
  headerBytes: Uint8Array;
  body: Uint8Array;
} {
  const cursor = { at: 0 };
  const protocol = new TextDecoder().decode(readVar(envelope, cursor));
  if (protocol !== ENVELOPE_PROTOCOL) {
    throw new EnvelopeFormatError(`unknown envelope protocol ${JSON.stringify(protocol)}`);
  }
  if (cursor.at + 2 > envelope.length) throw new EnvelopeFormatError("truncated version");
  const version = new DataView(envelope.buffer, envelope.byteOffset).getUint16(cursor.at, true);
  cursor.at += 2;
  if (version !== ENVELOPE_VERSION) {
    // Fail closed BEFORE any cryptographic work: a future version may mean a
    // different construction entirely, and guessing is how downgrades happen.
    throw new EnvelopeFormatError(`unknown envelope version ${version}`);
  }
  const modeByte = readByte(envelope, cursor);
  if (modeByte !== EnvelopeMode.IiOnly && modeByte !== EnvelopeMode.Passcode) {
    throw new EnvelopeFormatError(`unknown envelope mode ${modeByte}`);
  }
  const canisterId = Principal.fromUint8Array(new Uint8Array(readVar(envelope, cursor)));
  const owner = Principal.fromUint8Array(new Uint8Array(readVar(envelope, cursor)));
  const deviceId = new TextDecoder().decode(readVar(envelope, cursor));
  if (cursor.at + 32 > envelope.length) throw new EnvelopeFormatError("truncated key hash");
  const encSpkiHash = envelope.subarray(cursor.at, cursor.at + 32);
  cursor.at += 32;
  const kdfId = readByte(envelope, cursor);
  const memoryKib = readU32(envelope, cursor);
  const iterations = readU32(envelope, cursor);
  const parallelism = readU32(envelope, cursor);
  const salt = new Uint8Array(readVar(envelope, cursor));

  const headerBytes = envelope.subarray(0, cursor.at);
  const body = envelope.subarray(cursor.at);
  if (body.length === 0) throw new EnvelopeFormatError("envelope has no body");

  const mode = modeByte as EnvelopeMode;
  if (mode === EnvelopeMode.Passcode) {
    if (kdfId !== KDF_VERSION_ARGON2ID) {
      throw new EnvelopeFormatError(`unknown envelope KDF id ${kdfId}`);
    }
    // The parameters are AUTHENTICATED by the AAD, but they are also CHECKED:
    // authentication alone would faithfully carry an attacker-chosen weakening
    // if the wallet ever wrote one, and a downgrade must be refused on read as
    // well as never written.
    if (
      memoryKib !== ARGON2ID_MEMORY_KIB ||
      iterations !== ARGON2ID_ITERATIONS ||
      parallelism !== ARGON2ID_PARALLELISM
    ) {
      throw new EnvelopeFormatError(
        `envelope KDF parameters (m=${memoryKib}, t=${iterations}, p=${parallelism}) are not ` +
          `the pinned ones — refusing a weakened KDF`,
      );
    }
    if (salt.length !== ARGON2ID_SALT_BYTES) {
      throw new EnvelopeFormatError(`passcode envelope salt must be ${ARGON2ID_SALT_BYTES} bytes`);
    }
    if (body.length <= ENVELOPE_GCM_NONCE_BYTES) {
      throw new EnvelopeFormatError("passcode envelope body is too short to hold a nonce");
    }
  } else if (salt.length !== 0 || kdfId !== 0 || memoryKib !== 0 || iterations !== 0 || parallelism !== 0) {
    // An II-only envelope carrying KDF material is malformed, not "II-only with
    // extras" — refusing it keeps the two modes genuinely disjoint.
    throw new EnvelopeFormatError("an II-only envelope must carry no KDF parameters or salt");
  }

  return {
    header: {
      canisterId,
      owner,
      deviceId,
      encSpkiHash: new Uint8Array(encSpkiHash),
      mode,
      version,
      kdfId,
      memoryKib,
      iterations,
      parallelism,
      salt,
    },
    headerBytes: new Uint8Array(headerBytes),
    body: new Uint8Array(body),
  };
}

/** Derive the passcode key. Same Argon2id parameters as the note cache. */
async function derivePasscodeKeyBytes(passcode: string, salt: Uint8Array): Promise<Uint8Array> {
  const raw = await argon2id({
    password: passcode,
    salt,
    memorySize: ARGON2ID_MEMORY_KIB,
    iterations: ARGON2ID_ITERATIONS,
    parallelism: ARGON2ID_PARALLELISM,
    hashLength: ARGON2ID_KEY_BYTES,
    outputType: "binary",
  });
  return raw as Uint8Array;
}

/**
 * The passcode key as raw bytes — also the input to the note-cache subkey
 * (v3 §3), which HKDFs it under a different info string so no key is ever
 * reused across the envelope and the cache.
 */
export async function envelopePasscodeKeyBytes(
  passcode: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  if (salt.length !== ARGON2ID_SALT_BYTES) {
    throw new EnvelopeFormatError(`envelope salt must be ${ARGON2ID_SALT_BYTES} bytes`);
  }
  return derivePasscodeKeyBytes(passcode, salt);
}

function tight(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(new ArrayBuffer(bytes.length));
  copy.set(bytes);
  return copy;
}

/**
 * Build a stored envelope around an already-RSA-wrapped vetKey.
 *
 * `deviceCiphertext` is the RSA-OAEP wrap; in II-only mode it is stored as the
 * body verbatim, and in passcode mode it is the AES-GCM PLAINTEXT.
 */
export async function buildEnvelope(
  binding: EnvelopeBinding,
  deviceCiphertext: Uint8Array,
  passcode?: string,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<Uint8Array> {
  if (passcode === undefined) {
    const header = await encodeHeader({
      ...binding,
      mode: EnvelopeMode.IiOnly,
      version: ENVELOPE_VERSION,
      kdfId: 0,
      memoryKib: 0,
      iterations: 0,
      parallelism: 0,
      salt: new Uint8Array(0),
    });
    return concat([header, deviceCiphertext]);
  }

  // Salt is per owner/device envelope and is NEVER shared with a note-cache
  // salt (v3 §2(4)) — two independent secrets must not share a KDF input.
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(ARGON2ID_SALT_BYTES));
  const header = await encodeHeader({
    ...binding,
    mode: EnvelopeMode.Passcode,
    version: ENVELOPE_VERSION,
    kdfId: KDF_VERSION_ARGON2ID,
    memoryKib: ARGON2ID_MEMORY_KIB,
    iterations: ARGON2ID_ITERATIONS,
    parallelism: ARGON2ID_PARALLELISM,
    salt,
  });
  const keyBytes = await derivePasscodeKeyBytes(passcode, salt);
  const key = await subtle.importKey("raw", tight(keyBytes), { name: "AES-GCM" }, false, [
    "encrypt",
  ]);
  keyBytes.fill(0);
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(ENVELOPE_GCM_NONCE_BYTES));
  const ciphertext = new Uint8Array(
    await subtle.encrypt(
      { name: "AES-GCM", iv: tight(nonce), additionalData: tight(header) },
      key,
      tight(deviceCiphertext),
    ),
  );
  return concat([header, nonce, ciphertext]);
}

/**
 * Recover the RSA ciphertext from a stored envelope, checking that the envelope
 * belongs to the identity that is asking.
 *
 * The binding check is not decoration: an envelope names its canister, owner
 * and device, so an envelope handed over from another deployment, principal or
 * device is refused before any key is used.
 */
export async function openEnvelope(
  envelope: Uint8Array,
  binding: EnvelopeBinding,
  passcode?: string,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<Uint8Array> {
  const parsed = decodeEnvelope(envelope);
  const expectedHeader = await encodeHeader({
    ...binding,
    mode: parsed.header.mode,
    version: parsed.header.version,
    kdfId: parsed.header.kdfId,
    memoryKib: parsed.header.memoryKib,
    iterations: parsed.header.iterations,
    parallelism: parsed.header.parallelism,
    salt: parsed.header.salt,
  });
  // Comparing the whole header rather than field-by-field means a field added
  // later cannot be forgotten here.
  if (
    expectedHeader.length !== parsed.headerBytes.length ||
    !expectedHeader.every((b, i) => b === parsed.headerBytes[i])
  ) {
    throw new EnvelopeFormatError(
      "envelope header does not match this canister/owner/device — refusing to open it",
    );
  }

  if (parsed.header.mode === EnvelopeMode.IiOnly) {
    if (passcode !== undefined) {
      throw new EnvelopeFormatError("this envelope is II-only; no passcode applies");
    }
    return parsed.body;
  }

  if (passcode === undefined) {
    throw new EnvelopeFormatError("this envelope is passcode-protected; a passcode is required");
  }
  const keyBytes = await derivePasscodeKeyBytes(passcode, parsed.header.salt);
  const key = await subtle.importKey("raw", tight(keyBytes), { name: "AES-GCM" }, false, [
    "decrypt",
  ]);
  keyBytes.fill(0);
  const nonce = parsed.body.subarray(0, ENVELOPE_GCM_NONCE_BYTES);
  const ciphertext = parsed.body.subarray(ENVELOPE_GCM_NONCE_BYTES);
  try {
    return new Uint8Array(
      await subtle.decrypt(
        { name: "AES-GCM", iv: tight(nonce), additionalData: tight(parsed.headerBytes) },
        key,
        tight(ciphertext),
      ),
    );
  } catch {
    // GCM does not distinguish "wrong passcode" from "tampered envelope", and
    // neither should this: both mean the bytes are not openable as claimed.
    throw new EnvelopeFormatError("wrong passcode, or the envelope has been tampered with");
  }
}

/** The mode of a stored envelope, for UX ("passcode is on"). */
export function envelopeMode(envelope: Uint8Array): EnvelopeMode {
  return decodeEnvelope(envelope).header.mode;
}
