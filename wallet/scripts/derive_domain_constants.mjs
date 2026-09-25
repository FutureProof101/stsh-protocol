#!/usr/bin/env node
/**
 * derive_domain_constants.mjs — A-3 PREP ceremony tool.
 *
 * Turns a pool canister principal into DOMAIN_POOL_CANISTER_ID, using the
 * SINGLE normative principal->Fr rule (DEF-108 `encode_recipient_signals`,
 * canisters/shielded-pool/src/lib.rs, mirrored by wallet notes.ts
 * `encodeRecipientSignals`):
 *
 *     bytes[0..len] = principal bytes   (1..=29)
 *     bytes[31]     = len               (also keeps the value < BN254 Fr modulus)
 *     value         = LE interpretation of those 32 bytes
 *
 * Why this exists: at FINALIZE the pool principal must be hand-carried into
 * circuits/spend.circom, wallet/src/crypto/notes.ts, POSEIDON_PARAMS.md,
 * wallet/src/zk/spendManifest.json and the ceremony record. A mistyped digit
 * there produces a circuit that verifies proofs nobody can generate and notes
 * nobody can spend — with no error at any point. This makes the value derived
 * and self-checked, not transcribed.
 *
 * spendManifest.json was added to this list by W-CEREMONY-BIND (AR2-S1-04): it
 * carries the principal in TEXT form (frozenPoolPrincipal, not the derived Fr),
 * is build-bundled with no env override, and gates assertDeploymentTuple — so a
 * wrong value there disables spend outright. The full principal-surface sweep is
 * circuits/ceremony/domain_manifest.json -> reencode_targets.
 *
 * The tool ALWAYS re-derives the known M5 vector first and aborts if it does not
 * reproduce, so a broken/upgraded principal library cannot silently emit a wrong
 * constant.
 *
 * Usage:
 *   node wallet/scripts/derive_domain_constants.mjs <pool-principal-text>
 *   node wallet/scripts/derive_domain_constants.mjs --selftest
 *
 * It does NOT compute domainHash — that is deliberately left to the Poseidon
 * layer, where wallet/circuit equality is the actual acceptance test
 * (wallet/tests/domain_freeze_a3.test.ts + the recompiled circuit).
 */
import { Principal } from "@dfinity/principal";

/** DEF-108 encoding, as a BN254 Fr integer (little-endian over the 32 bytes). */
export function principalToFr(text) {
  const bytes = Principal.fromText(text).toUint8Array();
  if (bytes.length < 1 || bytes.length > 29) {
    throw new Error(`principal is ${bytes.length} bytes; the rule expects 1..=29`);
  }
  const buf = new Uint8Array(32);
  buf.set(bytes, 0);
  buf[31] = bytes.length;
  let v = 0n;
  for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(buf[i]); // little-endian
  return { value: v, bytes: buf, principalBytes: bytes };
}

const hex = (b) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");

// ── Known-answer self-check (M5 pin, POSEIDON_PARAMS.md) ─────────────────────
const M5_PRINCIPAL = "ohspu-zqaaa-aaaad-qmasq-cai";
const M5_FR =
  "4523128485832663883733241601901871400518358776001584537534818377974931259392";

function selftest() {
  const got = principalToFr(M5_PRINCIPAL).value.toString();
  if (got !== M5_FR) {
    console.error(
      `FATAL: principal->Fr self-check FAILED.\n  principal: ${M5_PRINCIPAL}\n  expected : ${M5_FR}\n  got      : ${got}\n` +
        `The encoding rule or the principal library has drifted. Do NOT use any value this tool emits.`,
    );
    process.exit(1);
  }
}

const arg = process.argv[2];
selftest();

if (arg === "--selftest" || arg === undefined) {
  console.log(`principal->Fr self-check OK (${M5_PRINCIPAL})`);
  if (arg === undefined) {
    console.log("\nusage: node wallet/scripts/derive_domain_constants.mjs <pool-principal-text>");
    process.exit(2);
  }
  process.exit(0);
}

const { value, bytes, principalBytes } = principalToFr(arg);

if (arg === M5_PRINCIPAL) {
  console.error(
    `\n  WARNING: that is the ABANDONED M5 pool principal (Module hash: None).\n` +
      `  A-3 FINALIZE requires the NEW pool principal emitted by A6.5.\n`,
  );
}

console.log(`
principal                 : ${arg}
principal bytes (${String(principalBytes.length).padStart(2)})       : ${hex(principalBytes)}
DOMAIN_POOL_CANISTER_ID   : ${value}
  as LE 32-byte hex       : ${hex(bytes)}

Paste into, atomically (see circuits/ceremony/domain_manifest.json artifact_matrix):
  circuits/spend.circom          — the DOMAIN_POOL_CANISTER_ID literal, then recompile
  wallet/src/crypto/notes.ts     — export const DOMAIN_POOL_CANISTER_ID
  POSEIDON_PARAMS.md             — constants table + canonical domainHash vector
  circuits/ceremony/domain_manifest.json — domain_constants.DOMAIN_POOL_CANISTER_ID.next_value

The principal TEXT (not this Fr) also re-encodes into every surface listed under
domain_manifest.json -> reencode_targets, including:
  wallet/src/zk/spendManifest.json — frozenPoolPrincipal (build-bundled, gates spend)

Then run the wallet/circuit domain-vector equality test AFTER all A6.6 constraint
changes are in — not before.
`);
