/**
 * STSH Note Cryptography
 * Build plan: M3 — Wallet Frontend
 *
 * Handles client-side note creation, scanning, and proof generation.
 * ALL cryptographic operations happen here in the browser.
 * Keys are NEVER transmitted to any canister or server.
 */

import { Principal } from "@dfinity/principal";
import { poseidon2, poseidon3, poseidon4, poseidon6 } from "./poseidon";

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * Fixed denominations in base STSH units (8 decimals) — the five-tier launch
 * ladder (OWNER_RULING_LAUNCH_LADDER 2026-09-08, lane A6.6). Mirrors the pool's
 * own `DENOMINATIONS`; the top rung is the circuit's value bound.
 */
export const DENOMINATIONS = [
  BigInt(1_000) * BigInt(100_000_000),       //       1,000 STSH
  BigInt(10_000) * BigInt(100_000_000),      //      10,000 STSH
  BigInt(100_000) * BigInt(100_000_000),     //     100,000 STSH
  BigInt(1_000_000) * BigInt(100_000_000),   //   1,000,000 STSH
  BigInt(10_000_000) * BigInt(100_000_000),  //  10,000,000 STSH
] as const;

export type Denomination = typeof DENOMINATIONS[number];

// ── Domain constants (DEF-082 — D2 ceremony values, finalized at A1) ────────────
//
// These MUST match circuits/spend.circom Constraint 0 byte-for-byte. The wallet
// computes domain_sep = Poseidon(4)([POOL_ID, ASSET_ID, CIRCUIT_VERSION,
// NETWORK_ID]) from exactly these values and feeds it as the first input to
// every commitment/nullifier hash.
//
// DOMAIN_POOL_CANISTER_ID is the deployed shielded-pool principal
// (cxrfg-qaaaa-aaaar-qchfa-cai, born under the Vault at J-18) encoded to a BN254
// field element
// byte-identically to the canister's DEF-108 encode_recipient_signals (the
// single normative principal→Fr rule). First injected at the A1 ceremony over the
// now-orphaned ohspu-zqaaa-aaaad-qmasq-cai; RE-ENCODED to the Vault-born pool at
// A-3 FINALIZE (2026-09-12, generation mainnet-v2) — the A-3 domain-severance
// control. (Lane label per MAINNET_DEPLOYMENT.md:318,328, which is authoritative
// for lane naming; W-DOCFIX-3/AR2-S1-05. This is a RELABEL, not a re-scheduling —
// when the re-pin happens is unchanged. The full principal-surface sweep is
// circuits/ceremony/domain_manifest.json -> reencode_targets.)
export const DOMAIN_POOL_CANISTER_ID = BigInt(
  "4523128485832663883733241601901871400518358776001584537546685574107874983936",
); // cxrfg-qaaaa-aaaar-qchfa-cai → Fr (A-3 FINALIZE, mainnet-v2)
export const DOMAIN_ASSET_ID         = BigInt(0);  // STSH native token (final)
export const DOMAIN_CIRCUIT_VERSION  = BigInt(3);  // circuit-finalization revision (bumped 2->3 at A6.6)
export const DOMAIN_NETWORK_ID       = BigInt(1);  // ICP mainnet (final)
//
// Canonical domainHash.out for the mainnet-v2 vector [cxrfg→Fr, 0, 3, 1]
// (circomlib Poseidon(4)) — recomputed at A-3 FINALIZE (2026-09-12) and asserted
// by wallet/tests/poseidon.test.ts + wallet/tests/domain_freeze_a3.test.ts:
//   decimal : 9578431337377839681221818034592677386495104691038362380902047525493741438900
//   LE 32B  : b4c713664074d78bed0527155ed4c508f8e9308fb325eec76a0e2e4e34332d15
// The historical D2/A1 vector [ohspu→Fr, 0, 2, 1] is retained in POSEIDON_PARAMS.md.

/**
 * D2 ceremony VK hash — for development testing only. Updated to the re-ceremony
 * value at the A6.7 / 2-8 re-ceremony (label per MAINNET_DEPLOYMENT.md:16,328;
 * relabelled from "gate 2-5" by W-DOCFIX-3/AR2-S1-05 — same act, one label).
 */
export const PINNED_VK_HASH_D2 =
  "84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914";

// ── Circuit domain-separation constants (source-verified spend.circom, F2) ──────
//
// PK_DOMAIN=1 / NULLIFIER_DOMAIN=2 / COMMITMENT_DOMAIN=3 / MERKLE_LEAF_DOMAIN=4
// (MERKLE_LEAF_DOMAIN is declared below with the DEF-111 leaf block.)
export const PK_DOMAIN         = BigInt(1); // recipient_pk = Poseidon(2)(spend_key, PK_DOMAIN)      [spend.circom:379]
export const NULLIFIER_DOMAIN  = BigInt(2); // nullifier = Poseidon(4)(domain_sep, spend_key, in_commitment, NULLIFIER_DOMAIN)
export const COMMITMENT_DOMAIN = BigInt(3); // commitment = Poseidon(6)(domain_sep, value, recipient_pk, rho, rseed, COMMITMENT_DOMAIN)

// ── BN254 Fr canonicality (wallet-side guard, mirrors stsh-field-utils) ─────────
//
// Every bigint→32-byte-field conversion must be in-range BEFORE crossing the
// Poseidon WASM boundary (which rejects — never silently reduces). Sources that
// are in-range by construction (HKDF-derived 32-byte secrets are NOT — they can
// exceed the modulus and must be checked; note values and small domain
// constants ARE) still go through the boundary's own guard as defence-in-depth.
export const BN254_FR_MODULUS = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

/** Throws if `value` is not a canonical BN254 Fr element. */
export function assertFrInRange(value: bigint, label: string): void {
  if (value < 0n || value >= BN254_FR_MODULUS) {
    throw new Error(
      `${label} is not a canonical BN254 Fr element (must be 0 <= v < Fr modulus)`,
    );
  }
}

/** Interpret 32 little-endian bytes as a bigint (the circuit's field-element value). */
export function leToBigint(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

/**
 * Reduce 32 little-endian bytes modulo the BN254 Fr modulus, returning a
 * CANONICAL 32-byte LE field element. This is the one legitimate reduction in
 * the wallet: HKDF-SHA256 output is a uniform 256-bit value, and ~78% of such
 * values exceed the (~254-bit) Fr modulus, so a raw chunk is usually NOT a
 * valid field element. Reduction here mirrors exactly what the circuit's
 * witness calculator (ffjavascript reduces input signals mod p) and the Rust
 * reference (`Fr::from_le_bytes_mod_order`) do — so wallet == circuit == Rust.
 * After this, every note secret is canonical and the guarded Poseidon boundary
 * accepts it (the guard REJECTS non-canonical; it never reduces).
 */
export function reduceLeToField(bytes: Uint8Array): Uint8Array {
  return bigintToFieldLe(leToBigint(bytes) % BN254_FR_MODULUS, "reduced field element");
}

// ── DEF-111 / B-prime: value-bound outer Merkle leaf (pinned reference) ─────────
//
// The tree leaf is NOT the inner note commitment; it is a value-bound outer hash:
//   merkle_leaf = Poseidon(value, inner_note_commitment, MERKLE_LEAF_DOMAIN)  (Poseidon(3), t=4)
// with the purpose tag LAST and domain_sep OMITTED (the inner commitment already
// binds it). MUST byte-match circuits/spend.circom `MerkleLeaf` and the canister
// stsh_field_utils::merkle_leaf. `value` is the note's spendable value. On deposit
// the fee is charged ON TOP, so the credited private balance is the FULL GROSS:
// private_balance_credit = gross_shield_amount, NOT reduced by the shielding fee
// (canisters/shielded-pool/src/lib.rs:4031; the depositor transfers
// gross + protocol_shielding_fee). Corrects a superseded fee-deducted statement
// (AR1-10): binding `gross - fee` in a leaf the pool binds at `gross` yields a note
// that can never be spent, with no error at any point.
// M3 prover obligation: the wallet-computed leaf for a shared fixed note must
// byte-equal the circuit/canister output (leaf-agreement equality checkpoint).
export const MERKLE_LEAF_DOMAIN = BigInt(4);  // PK=1 / NULLIFIER=2 / COMMITMENT=3 / MERKLE_LEAF=4

/** A private note — contains all secrets needed to spend */
export interface Note {
  value:        bigint;      // base STSH units
  recipientPk:  Uint8Array;  // 32-byte recipient public key
  rho:          Uint8Array;  // 32-byte randomness (nullifier seed)
  rseed:        Uint8Array;  // 32-byte randomness (commitment blinding)
  commitment:   Uint8Array;  // 32-byte Poseidon commitment (public)
  nullifier:    Uint8Array;  // 32-byte nullifier (derived, kept private until spend)
}

/** Encrypted note payload stored on-chain alongside commitment */
export interface EncryptedPayload {
  ciphertext: Uint8Array;
  nonce:      Uint8Array;
  ephemeral:  Uint8Array;   // ephemeral public key for ECDH
}

// The spend-proof bundle (`SpendProof`) + `generateSpendProof` live in
// ./prover.ts (Commit 3) — it owns the snarkjs fullProve Web-Worker dispatch,
// the witness assembly, and the 9-public-signal parse. The stale placeholder
// SpendProof/generateSpendProof that used to sit here were removed when the
// real prover wiring landed.

// ── Key derivation (vetKeys — II-anchored, cross-device) ─────────────────────
//
// BRIEF_VETKEYS_CROSSDEVICE §3: note secrets are derived from the user's
// vetKey (obtained via canisters/vetkeys — see ./vetkeys.ts), NOT from a
// device-local mnemonic/seed. Determinism is the whole point: any device that
// authenticates the same Internet Identity principal re-derives the identical
// note secrets and rebuilds the wallet's note set from on-chain data alone.
// The old BIP-39 `deriveKeys(mnemonic)` scaffold is superseded and removed —
// there is no device-local seed, no export/import.
//
// DERIVATION SPEC — must byte-match the Rust reference implementation in
// canisters/vetkeys/tests/crossdevice_acceptance.rs (a shared pinned test
// vector in wallet/tests/notes.test.ts + that Rust test enforces this):
//   master_note_secret = vetKey.deriveSymmetricKey("stsh-notes-master-v1", 32)
//     (computed in ./vetkeys.ts — the vetKey never leaves that module raw)
//   per-note secrets (index i, u64 little-endian):
//     HKDF-SHA256(ikm = master, salt = "stsh-note-v1",
//                 info = "stsh.note." || LE64(i), out = 96 bytes)
//       -> spendKey = reduce(out[0..32]), rho = reduce(out[32..64]),
//          rseed = reduce(out[64..96])
//     where reduce(·) = the 32-byte value mod BN254 Fr (see reduceLeToField).
//     The reduction is MANDATORY: raw HKDF chunks are uniform 256-bit values,
//     ~78% of which exceed the Fr modulus and are not valid field elements —
//     the circuit reduces its input signals mod p, so the wallet must match.

/** HKDF salt for per-note derivation — PINNED (matches the Rust reference). */
export const NOTE_HKDF_SALT = "stsh-note-v1";
/** HKDF info prefix for per-note derivation — PINNED. */
export const NOTE_HKDF_INFO_PREFIX = "stsh.note.";

/** Per-note secret triple, derived deterministically from the master secret. */
export interface NoteSecrets {
  spendKey: Uint8Array; // 32 bytes
  rho:      Uint8Array; // 32 bytes
  rseed:    Uint8Array; // 32 bytes
}

/**
 * Derive the per-note secrets for `index` from the master note secret
 * (HD-wallet style: deterministic and unique per index).
 *
 * The master secret comes from the user's vetKey (see ./vetkeys.ts
 * `masterNoteSecret`). Same II principal -> same master -> same per-note
 * secrets on every device.
 */
export async function deriveNoteSecrets(
  masterNoteSecret: Uint8Array,
  index: bigint,
): Promise<NoteSecrets> {
  const encoder = new TextEncoder();
  const ikm = await crypto.subtle.importKey(
    "raw",
    masterNoteSecret as BufferSource,
    { name: "HKDF" },
    false,
    ["deriveBits"],
  );

  // info = "stsh.note." || LE64(index)
  const prefix = encoder.encode(NOTE_HKDF_INFO_PREFIX);
  const info = new Uint8Array(prefix.length + 8);
  info.set(prefix, 0);
  const view = new DataView(info.buffer);
  view.setBigUint64(prefix.length, index, true); // little-endian

  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode(NOTE_HKDF_SALT),
      info,
    },
    ikm,
    96 * 8,
  );

  const okm = new Uint8Array(bits);
  // Reduce each chunk mod Fr so the secrets are canonical field elements (see
  // reduceLeToField). The circuit does the same on its input signals.
  return {
    spendKey: reduceLeToField(okm.slice(0, 32)),
    rho:      reduceLeToField(okm.slice(32, 64)),
    rseed:    reduceLeToField(okm.slice(64, 96)),
  };
}

// ── Circuit-anchored note derivation (real Poseidon) ────────────────────────

/**
 * domainHash / domain_sep = Poseidon(4)(DOMAIN_POOL_CANISTER_ID, DOMAIN_ASSET_ID,
 * DOMAIN_CIRCUIT_VERSION, DOMAIN_NETWORK_ID). The DEF-035 cross-deployment
 * prefix fed as the FIRST input to every commitment and nullifier hash.
 * Computed once and cached (the constants never change within a deployment).
 */
let domainSepCache: Uint8Array | null = null;
export async function domainSep(): Promise<Uint8Array> {
  if (!domainSepCache) {
    domainSepCache = await poseidon4(
      bigintToFieldLe(DOMAIN_POOL_CANISTER_ID, "DOMAIN_POOL_CANISTER_ID"),
      bigintToFieldLe(DOMAIN_ASSET_ID, "DOMAIN_ASSET_ID"),
      bigintToFieldLe(DOMAIN_CIRCUIT_VERSION, "DOMAIN_CIRCUIT_VERSION"),
      bigintToFieldLe(DOMAIN_NETWORK_ID, "DOMAIN_NETWORK_ID"),
    );
  }
  return domainSepCache;
}

/**
 * recipient_pk = Poseidon(2)(spend_key, PK_DOMAIN) — spend.circom:379.
 * The commitment binds the DERIVED pk, not the raw HKDF spend key; at spend
 * time the circuit re-derives it from the spender's spend_key witness, proving
 * ownership. `spendKey` must already be a canonical field element (it is —
 * deriveNoteSecrets reduced it).
 */
export async function derivePk(spendKey: Uint8Array): Promise<Uint8Array> {
  return poseidon2(spendKey, bigintToFieldLe(PK_DOMAIN, "PK_DOMAIN"));
}

/**
 * merkle_leaf = Poseidon(3)(value, inner_commitment, MERKLE_LEAF_DOMAIN) —
 * DEF-111 value-bound outer leaf (spend.circom MerkleLeaf; byte-identical to
 * stsh_field_utils::merkle_leaf, proven in the poseidon-wasm crate test). This
 * is the value submitted to the pool/merkle canister at shield time, NOT the
 * inner commitment.
 */
export async function merkleLeaf(value: bigint, commitment: Uint8Array): Promise<Uint8Array> {
  return poseidon3(
    bigintToFieldLe(value, "note value"),
    commitment,
    bigintToFieldLe(MERKLE_LEAF_DOMAIN, "MERKLE_LEAF_DOMAIN"),
  );
}

/**
 * DEF-108 recipient-principal encoding for the `private_spend` public signal —
 * byte-for-byte identical to the canister's `encode_recipient_signals`
 * (shielded-pool/src/lib.rs): the principal's bytes at [0..len], zeros in the
 * middle, and byte[31] = principal byte length (so trailing-zero-distinct
 * principals don't collide). NOT the note's `recipient_pk` — this is the
 * withdrawal recipient, a separate path (do not cross-wire).
 */
export function encodeRecipientSignals(principal: Principal): Uint8Array {
  const pbytes = principal.toUint8Array(); // 1..=29 bytes
  if (pbytes.length > 29) {
    throw new Error(`principal is ${pbytes.length} bytes; canister expects <= 29`);
  }
  const encoded = new Uint8Array(32);
  encoded.set(pbytes, 0);
  encoded[31] = pbytes.length; // DEF-108 length byte (also keeps it < Fr modulus)
  return encoded;
}

// ── Note creation ─────────────────────────────────────────────────────────────

/**
 * Create a note the wallet owns, using DETERMINISTIC per-note secrets derived
 * from the user's vetKey (see `deriveNoteSecrets`). Same II principal + index
 * reproduces the identical note on any device (cross-device / recovery).
 *
 * Real circuit-anchored derivation (F1, source-verified spend.circom):
 *   recipient_pk = Poseidon(2)(spend_key, PK_DOMAIN=1)                                  [:379]
 *   commitment   = Poseidon(6)(domain_sep, value, recipient_pk, rho, rseed, COMMITMENT_DOMAIN=3)  [:164]
 *   nullifier    = Poseidon(4)(domain_sep, spend_key, commitment, NULLIFIER_DOMAIN=2)   [DEF-109-A]
 * The nullifier's third input is the INNER commitment (not the Merkle leaf).
 *
 * Payload encryption is NOT done here — the caller IBE-encrypts
 * `noteToBytes(note)` to the recipient's II principal via ./vetkeys.ts
 * `encryptNotePayload`, then submits the ciphertext through the existing
 * (unchanged) shield/spend paths. The Merkle leaf submitted to the tree is
 * `merkleLeaf(value, commitment)` (DEF-111) — computed separately at shield time.
 */
export async function createNote(value: bigint, secrets: NoteSecrets): Promise<Note> {
  if (!DENOMINATIONS.includes(value as Denomination)) {
    throw new Error(`Invalid denomination: ${value}. Must be one of ${DENOMINATIONS}`);
  }

  const { spendKey, rho, rseed } = secrets;
  const ds = await domainSep();

  // recipient_pk = Poseidon(2)(spend_key, PK_DOMAIN) — the commitment binds the
  // DERIVED pk, not the raw spend key (spend.circom Constraint 1).
  const recipientPk = await derivePk(spendKey);

  // inner_commitment = Poseidon(6)(domain_sep, value, recipient_pk, rho, rseed, COMMITMENT_DOMAIN)
  const commitment = await poseidon6(
    ds,
    bigintToFieldLe(value, "note value"),
    recipientPk,
    rho,
    rseed,
    bigintToFieldLe(COMMITMENT_DOMAIN, "COMMITMENT_DOMAIN"),
  );

  // DEF-109-A: nullifier = Poseidon(4)(domain_sep, spend_key, inner_commitment, NULLIFIER_DOMAIN).
  // Full-note binding — the third input is the inner Poseidon(6) commitment,
  // NOT the Merkle leaf (source-verified spend.circom:406). Computed now for
  // storage; only revealed at spend.
  const nullifier = await poseidon4(
    ds,
    spendKey,
    commitment,
    bigintToFieldLe(NULLIFIER_DOMAIN, "NULLIFIER_DOMAIN"),
  );

  return { value, recipientPk, rho, rseed, commitment, nullifier };
}

/**
 * The most notes ONE shield operation may produce (WL-23 / WL-2b §4a).
 *
 * RULED by `reviews/CTO_RULING_WL-23_note_cap_2026-08-22.md` and ratified at
 * 16 (Owner's veto window closed at that value). A change is this one constant
 * and nothing else — no call site depends on the number.
 *
 * It is a WALLET-SIDE PRODUCT RULE. No canister enforces it and nothing about
 * consensus changes; it exists for two reasons that point the same way:
 *
 *  1. An operation's authorization lease needs a BOUNDED call count. With the
 *     cap, one shield is at most `1 approve + 16 deposits = 17` wire calls, so
 *     the lease deadline can be derived from a fixed multiplier rather than
 *     from an open-ended `prepared.length`.
 *  2. An unbounded operation is itself a privacy artefact. Thirty-two
 *     sequential public calls from one principal is a maximally linkable
 *     pattern; many small operations beat one giant linkable one — the same
 *     reasoning as the randomised submission delay.
 *
 * NOTE this is a cap on note COUNT, not on amount: under the five-tier ladder
 * `[1_000, 10_000, 100_000, 1_000_000, 10_000_000]` an amount `A` STSH is first
 * required to be a whole multiple of 1,000 (it is otherwise not decomposable at
 * all and throws before this cap is consulted); writing `M = A / 1_000`, the
 * greedy decomposition costs `floor(M / 10_000) + digit_sum(M mod 10_000)`
 * notes. So 16,000 STSH is M=16 -> 10_000 + 6x1_000 = **7** notes and is
 * accepted, while 9,999,000 STSH is M=9999 -> 9+9+9+9 = **36** notes and is
 * refused. (9,999 STSH is not decomposable at all — not a multiple of 1,000.)
 */
export const MAX_NOTES_PER_OPERATION = 16;

/**
 * Decompose an arbitrary amount into denomination notes.
 * E.g. 123,000 STSH → [100_000, 10_000, 10_000, 1_000, 1_000, 1_000]
 * Wallet calls createNote() for each denomination.
 *
 * The `MAX_NOTES_PER_OPERATION` cap is enforced HERE, at the definition, and
 * not at any call site: both callers (`runShieldFlow`'s step 0 and the shield
 * page's `planShield` preview) inherit it, and a future third caller cannot
 * forget it. In the flow this runs before the deployment binding, before the
 * fee snapshot and before a single token is drawn from the lease — so an
 * over-cap amount reaches no network at all.
 */
export function decomposeAmount(amountBaseUnits: bigint): bigint[] {
  const result: bigint[] = [];
  let remaining = amountBaseUnits;

  // Greedily assign largest denominations first
  for (const denom of [...DENOMINATIONS].reverse()) {
    while (remaining >= denom) {
      result.push(denom);
      remaining -= denom;
    }
  }

  if (remaining !== 0n) {
    throw new Error(`Amount ${amountBaseUnits} is not decomposable into fixed denominations`);
  }

  // The message states the count, the cap and the remedy, and deliberately does
  // NOT say "amounts above X" — the cap is on note count, so such a sentence
  // would be false (16,000 STSH is 7 notes and fits; 9,999,000 STSH is 36 and
  // does not).
  if (result.length > MAX_NOTES_PER_OPERATION) {
    throw new Error(
      `This amount needs ${result.length} fixed-denomination notes, which is more than the ` +
        `${MAX_NOTES_PER_OPERATION} one shield may create. Split it into separate shields. ` +
        `(The limit is on the NUMBER of notes, not the amount — a larger round amount can need ` +
        `fewer notes than a smaller uneven one.)`,
    );
  }

  return result;
}

// ── Note scanning ─────────────────────────────────────────────────────────────
//
// Cross-device scan orchestration (paging merkle-tree `get_payloads` +
// IBE trial-decryption with the user's vetKey) lives in ./vetkeys.ts
// (`scanNotes`). This module stays pure: it provides the serialize/parse pair
// the scanner uses to turn decrypted payload bytes back into `Note`s.

// ── Proof generation ──────────────────────────────────────────────────────────
//
// Moved to ./prover.ts (Commit 3): `generateSpendProof` builds the spend.circom
// witness (buildSpendWitness), dispatches snarkjs fullProve to the prover Web
// Worker, and parses the 9 public signals. The old stub that threw here is gone.

// ── Note payload serialization ────────────────────────────────────────────────
//
// The plaintext layout that gets IBE-encrypted into the on-chain payload.
// PINNED: value (8B big-endian) || rho (32) || rseed (32) || recipientPk (32)
// = 104 bytes. Must match the Rust reference `note_to_bytes` in
// canisters/vetkeys/tests/crossdevice_acceptance.rs.
// (The old placeholder `encryptNote` that returned UNENCRYPTED bytes is gone —
// encryption is real IBE in ./vetkeys.ts `encryptNotePayload`.)

export const NOTE_PAYLOAD_BYTES = 8 + 32 + 32 + 32; // 104

export function noteToBytes(note: Note): Uint8Array {
  const buf = new Uint8Array(NOTE_PAYLOAD_BYTES);
  const view = new DataView(buf.buffer);
  // Pack value as 8 bytes big-endian
  view.setBigUint64(0, note.value, false);
  buf.set(note.rho,   8);
  buf.set(note.rseed, 40);
  buf.set(note.recipientPk, 72);
  return buf;
}

/**
 * Parse decrypted payload bytes back into note fields (the inverse of
 * `noteToBytes`). commitment/nullifier are re-derived by the caller (they are
 * not part of the payload). Returns null on a wrong-length payload — a payload
 * that IBE-decrypted for us but isn't a note.
 */
export function noteFromBytes(bytes: Uint8Array): Pick<Note, "value" | "rho" | "rseed" | "recipientPk"> | null {
  if (bytes.length !== NOTE_PAYLOAD_BYTES) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    value:       view.getBigUint64(0, false),
    rho:         bytes.slice(8, 40),
    rseed:       bytes.slice(40, 72),
    recipientPk: bytes.slice(72, 104),
  };
}

// ── L0-B: note v2 (payload 0x02, per-note nonce, new HKDF domain) ───────────────
//
// v2 supersedes the index-based v1 derivation. The KEY CHANGE is the per-note
// randomness source: v1 keyed the HKDF `info` on a sequential index (LE64(i)),
// which is deterministic across devices but requires an agreed index space; v2
// keys it on a fresh 16-byte CSPRNG NONCE stored IN the encrypted payload, so no
// index coordination is needed and two notes never collide even at the same
// value. The commitment/nullifier derivation (Poseidon) is UNCHANGED — only the
// secret-derivation salt/info and the payload serialization differ.
//
// DERIVATION (must byte-match the pinned TS/Rust interop vector):
//   per-note secrets from (master, nonce[16]):
//     HKDF-SHA256(ikm = master, salt = "stsh-note-v2",
//                 info = "stsh.note.v2" || nonce, out = 96 bytes)
//       -> spendKey = reduce(out[0..32]), rho = reduce(out[32..64]),
//          rseed = reduce(out[64..96])
//
// PAYLOAD v2 — exact 121 bytes (L0-B):
//   version:u8(0x02) || nonce:[u8;16] || value:u64be || rho:[u8;32]
//     || rseed:[u8;32] || recipient_pk:[u8;32]

/** HKDF salt for v2 per-note derivation — PINNED. */
export const NOTE_HKDF_SALT_V2 = "stsh-note-v2";
/** HKDF info prefix for v2 per-note derivation — PINNED. */
export const NOTE_HKDF_INFO_PREFIX_V2 = "stsh.note.v2";
/** Note payload version byte (L0-B). */
export const NOTE_PAYLOAD_VERSION_V2 = 0x02;
/** v2 per-note nonce length (CSPRNG). */
export const NOTE_NONCE_BYTES = 16;
/** v2 payload: 1 (version) + 16 (nonce) + 8 (value) + 32 (rho) + 32 (rseed) + 32 (pk). */
export const NOTE_PAYLOAD_BYTES_V2 = 1 + NOTE_NONCE_BYTES + 8 + 32 + 32 + 32; // 121
/**
 * Max value a private-spend CHANGE output may carry (L0-C rider): the circuit's
 * value bound. Shield notes are fixed-denomination only; change may be any
 * circuit-valid amount in `0..=MAX_SPEND_OUTPUT_VALUE` (0 = dummy).
 */
export const MAX_SPEND_OUTPUT_VALUE = 1_000_000_000_000_000n;

/** A legacy (v1, 104-byte) payload was found where a v2 note was required. */
export class LegacyNoteFormatUnsupportedError extends Error {
  constructor() {
    super(
      "A legacy (v1, 104-byte) note payload was encountered where the v2 (0x02, 121-byte) " +
        "format is required. It is not migrated in place — handle per the caller's policy " +
        "(typed reject for the local cache; quarantine-and-continue for an on-chain candidate).",
    );
    this.name = "LegacyNoteFormatUnsupportedError";
  }
}

/** Mint a fresh 16-byte CSPRNG note nonce (one per created note). */
export function freshNoteNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(NOTE_NONCE_BYTES));
}

/**
 * v2 per-note secret derivation from (master, nonce). Deterministic in the nonce
 * — the SAME (master, nonce) always reproduces the SAME secrets, so a device that
 * recovers the nonce (from the encrypted payload) re-derives the note.
 */
export async function deriveNoteSecretsV2(
  masterNoteSecret: Uint8Array,
  nonce: Uint8Array,
): Promise<NoteSecrets> {
  if (nonce.length !== NOTE_NONCE_BYTES) {
    throw new Error(`v2 note nonce must be ${NOTE_NONCE_BYTES} bytes, got ${nonce.length}`);
  }
  const encoder = new TextEncoder();
  const ikm = await crypto.subtle.importKey(
    "raw",
    masterNoteSecret as BufferSource,
    { name: "HKDF" },
    false,
    ["deriveBits"],
  );
  // info = "stsh.note.v2" || nonce
  const prefix = encoder.encode(NOTE_HKDF_INFO_PREFIX_V2);
  const info = new Uint8Array(prefix.length + nonce.length);
  info.set(prefix, 0);
  info.set(nonce, prefix.length);

  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: encoder.encode(NOTE_HKDF_SALT_V2), info },
    ikm,
    96 * 8,
  );
  const okm = new Uint8Array(bits);
  return {
    spendKey: reduceLeToField(okm.slice(0, 32)),
    rho: reduceLeToField(okm.slice(32, 64)),
    rseed: reduceLeToField(okm.slice(64, 96)),
  };
}

/**
 * The Poseidon note derivation shared by shield + spend outputs (unchanged from
 * v1 `createNote`): recipient_pk, inner commitment, nullifier. Callers pass
 * secrets from `deriveNoteSecretsV2`.
 */
async function assembleNote(value: bigint, secrets: NoteSecrets): Promise<Note> {
  const { spendKey, rho, rseed } = secrets;
  const ds = await domainSep();
  const recipientPk = await derivePk(spendKey);
  const commitment = await poseidon6(
    ds,
    bigintToFieldLe(value, "note value"),
    recipientPk,
    rho,
    rseed,
    bigintToFieldLe(COMMITMENT_DOMAIN, "COMMITMENT_DOMAIN"),
  );
  const nullifier = await poseidon4(
    ds,
    spendKey,
    commitment,
    bigintToFieldLe(NULLIFIER_DOMAIN, "NULLIFIER_DOMAIN"),
  );
  return { value, recipientPk, rho, rseed, commitment, nullifier };
}

/**
 * Create a SHIELD note (v2). Fixed-denomination only (anti-drift law #1): the
 * deposit path never mints a variable-amount note.
 */
export async function createShieldNote(value: bigint, secrets: NoteSecrets): Promise<Note> {
  if (!DENOMINATIONS.includes(value as Denomination)) {
    throw new Error(`Invalid shield denomination: ${value}. Must be one of ${DENOMINATIONS}`);
  }
  return assembleNote(value, secrets);
}

/**
 * Create a private-spend CHANGE output note (v2). Arbitrary circuit-valid value
 * in `0..=MAX_SPEND_OUTPUT_VALUE` (0 = a zero dummy, never contributes to
 * balance). Spend-side surface (L3c) — kept here with the v2 derivation.
 */
export async function createSpendOutputNote(value: bigint, secrets: NoteSecrets): Promise<Note> {
  if (value < 0n || value > MAX_SPEND_OUTPUT_VALUE) {
    throw new Error(`spend output value ${value} out of range 0..=${MAX_SPEND_OUTPUT_VALUE}`);
  }
  return assembleNote(value, secrets);
}

/**
 * Serialize a note + its nonce into the v2 (0x02) 121-byte plaintext that gets
 * IBE-encrypted into the on-chain payload. `nonce` is the SAME nonce used to
 * derive the note's secrets — it must be stored so a recovering device can
 * re-derive them.
 */
export function noteToBytesV2(note: Note, nonce: Uint8Array): Uint8Array {
  if (nonce.length !== NOTE_NONCE_BYTES) {
    throw new Error(`v2 note nonce must be ${NOTE_NONCE_BYTES} bytes, got ${nonce.length}`);
  }
  const buf = new Uint8Array(NOTE_PAYLOAD_BYTES_V2);
  buf[0] = NOTE_PAYLOAD_VERSION_V2;
  buf.set(nonce, 1);
  const view = new DataView(buf.buffer);
  view.setBigUint64(1 + NOTE_NONCE_BYTES, note.value, false); // u64 big-endian
  buf.set(note.rho, 1 + NOTE_NONCE_BYTES + 8);
  buf.set(note.rseed, 1 + NOTE_NONCE_BYTES + 40);
  buf.set(note.recipientPk, 1 + NOTE_NONCE_BYTES + 72);
  return buf;
}

/** Parsed v2 payload fields (commitment/nullifier are re-derived by the caller). */
export interface NoteV2Fields {
  nonce: Uint8Array;
  value: bigint;
  rho: Uint8Array;
  rseed: Uint8Array;
  recipientPk: Uint8Array;
}

/**
 * STRICT v2 parse (L0-B). A well-formed 0x02/121-byte payload returns its fields;
 * a legacy 104-byte payload throws `LegacyNoteFormatUnsupportedError` (the caller
 * decides: typed reject for the local cache, quarantine-and-continue for an
 * on-chain candidate); any other shape (wrong length, wrong version byte) returns
 * null — a payload that decrypted for us but is not a note.
 */
export function noteFromBytesV2(bytes: Uint8Array): NoteV2Fields | null {
  if (bytes.length === NOTE_PAYLOAD_BYTES) {
    // A legacy v1 (104-byte) payload where v2 is required.
    throw new LegacyNoteFormatUnsupportedError();
  }
  if (bytes.length !== NOTE_PAYLOAD_BYTES_V2 || bytes[0] !== NOTE_PAYLOAD_VERSION_V2) {
    return null;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    nonce: bytes.slice(1, 1 + NOTE_NONCE_BYTES),
    value: view.getBigUint64(1 + NOTE_NONCE_BYTES, false),
    rho: bytes.slice(1 + NOTE_NONCE_BYTES + 8, 1 + NOTE_NONCE_BYTES + 40),
    rseed: bytes.slice(1 + NOTE_NONCE_BYTES + 40, 1 + NOTE_NONCE_BYTES + 72),
    recipientPk: bytes.slice(1 + NOTE_NONCE_BYTES + 72, 1 + NOTE_NONCE_BYTES + 104),
  };
}

/**
 * bigint → 32-byte LITTLE-ENDIAN field element (the encoding the Poseidon WASM
 * boundary and the canisters use: ark `into_bigint().to_bytes_le()`).
 * Asserts canonicality per the wallet-side guard rule — the WASM boundary
 * would reject anyway, but failing here names the call site.
 */
export function bigintToFieldLe(n: bigint, label = "field element"): Uint8Array {
  assertFrInRange(n, label);
  const bytes = new Uint8Array(32);
  let value = n;
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}
