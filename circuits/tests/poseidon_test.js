/**
 * Poseidon Cross-Verification Test
 * ─────────────────────────────────
 * Computes ZERO_VALUES and protocol test vectors using circomlib's Poseidon
 * (BN254, circomlib standard parameters) and prints them for cross-checking
 * against the Rust merkle_tree canister.
 *
 * Circuit version: 0.3.0-a0
 * Domain constants: PK_DOMAIN=1, NULLIFIER_DOMAIN=2, COMMITMENT_DOMAIN=3
 *
 * All Poseidon instances in the STSH circuit use circomlib parameters:
 *   Poseidon(2) → t=3, RF=8, RP=57  (Merkle tree nodes, PK derivation)
 *   Poseidon(3) → t=4               (Nullifier derivation)
 *   Poseidon(5) → t=6               (Note commitment)
 *
 * circomlibjs buildPoseidon() selects round parameters by input count automatically.
 * The t=3 configuration matches POSEIDON_PARAMS.md (the Merkle tree config).
 *
 * Cross-check with Rust:
 *   cargo test -p merkle_tree test_print_zero_values -- --nocapture
 *
 * Any mismatch is a HARD STOP — do not proceed to trusted setup.
 *
 * Usage:
 *   cd circuits && npm install && node tests/poseidon_test.js
 */

"use strict";

const { buildPoseidon } = require("circomlibjs");

// Domain constants — MUST match circuit
const PK_DOMAIN         = 1n;
const NULLIFIER_DOMAIN  = 2n;
const COMMITMENT_DOMAIN = 3n;
// DEF-035 deployment-binding domain separation (must match spend.circom STSHSpend).
const DOMAIN_POOL_CANISTER_ID = 1n;   // DEV PLACEHOLDER — replace at M5
const DOMAIN_ASSET_ID         = 0n;
const DOMAIN_CIRCUIT_VERSION  = 1n;
const DOMAIN_NETWORK_ID       = 1n;

// BN254 Fr modulus
const FR_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function frToBigInt(F, val) {
  return BigInt(F.toObject(val).toString());
}

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  function hash(...inputs) {
    return frToBigInt(F, poseidon(inputs.map(x => F.e(x))));
  }

  console.log("=== STSH Poseidon Cross-Verification (v0.3.0-a0) ===");
  console.log("Parameters: circomlib standard, BN254 Fr, t auto-selected by input count");
  console.log(`Fr modulus p = ${FR_P}`);
  console.log("");

  // ── ZERO_VALUES — Merkle empty-node hash chain (t=3, 2-input Poseidon) ────
  console.log("── ZERO_VALUES[0..3] (Merkle tree, Poseidon(2) / t=3) ──");
  console.log("MUST match Rust: cargo test -p merkle_tree test_print_zero_values -- --nocapture");
  console.log("");

  const zero_values = [];
  let prev = 0n;
  for (let i = 0; i <= 3; i++) {
    const h = hash(prev, prev);
    zero_values.push(h);
    // little-endian hex
    let n = h;
    const le_bytes = [];
    for (let b = 0; b < 32; b++) { le_bytes.push(Number(n & 0xFFn).toString(16).padStart(2, "0")); n >>= 8n; }
    console.log(`ZERO_VALUES[${i}] decimal: ${h}`);
    console.log(`ZERO_VALUES[${i}] hex LE:  ${le_bytes.join("")}`);
    console.log("");
    prev = h;
  }

  // ── Protocol test vectors (circuit v0.3.0-a0) ───────────────────────────
  console.log("── Protocol test vectors ──");
  console.log("These encode the full commitment chain for spend_key=42, rho=99, rseed=77, value=1e8");
  console.log("");

  // PK derivation: Poseidon(spend_key=42, PK_DOMAIN=1) — Poseidon(2), t=3
  const spend_key = 42n, rho = 99n, rseed = 77n, value = 100_000_000n;
  // DEF-035 deployment-binding domain separator (Poseidon(4)).
  const domain_sep = hash(DOMAIN_POOL_CANISTER_ID, DOMAIN_ASSET_ID, DOMAIN_CIRCUIT_VERSION, DOMAIN_NETWORK_ID);
  const pk_42 = hash(spend_key, PK_DOMAIN);
  console.log(`derived_pk = Poseidon([42, PK_DOMAIN=1]):`);
  console.log(`  decimal: ${pk_42}`);
  console.log("");

  // Nullifier: Poseidon(spend_key=42, rho=99, NULLIFIER_DOMAIN=2) — Poseidon(3), t=4
  const nf_42_99 = hash(domain_sep, spend_key, rho, NULLIFIER_DOMAIN);
  console.log(`nullifier = Poseidon([domain_sep, 42, 99, NULLIFIER_DOMAIN=2]):`);
  console.log(`  decimal: ${nf_42_99}`);
  console.log("");

  // Commitment: Poseidon(value=1e8, pk_42, rho=99, rseed=77, COMMITMENT_DOMAIN=3) — Poseidon(5), t=6
  const cmt_42 = hash(domain_sep, value, pk_42, rho, rseed, COMMITMENT_DOMAIN);
  console.log(`commitment = Poseidon([domain_sep, 1e8, pk_42, 99, 77, COMMITMENT_DOMAIN=3]):`);
  console.log(`  decimal: ${cmt_42}`);
  console.log("");

  // Poseidon([1, 2]) — standard cross-check vector (from POSEIDON_PARAMS.md)
  const p12 = hash(1n, 2n);
  console.log(`Poseidon([1, 2]) (standard test vector):`);
  console.log(`  decimal: ${p12}`);
  console.log("");

  // ── Domain distinctness (security property) ──────────────────────────────
  console.log("── Domain distinctness (all 3 domains must produce distinct outputs) ──");
  const d1 = hash(spend_key, PK_DOMAIN);
  const d2 = hash(spend_key, NULLIFIER_DOMAIN);
  const d3 = hash(spend_key, COMMITMENT_DOMAIN);
  const distinct = d1 !== d2 && d1 !== d3 && d2 !== d3;
  console.log(`  Poseidon([42, PK_DOMAIN=1]):         ${d1}`);
  console.log(`  Poseidon([42, NULLIFIER_DOMAIN=2]):  ${d2}`);
  console.log(`  Poseidon([42, COMMITMENT_DOMAIN=3]): ${d3}`);
  console.log(`  All distinct: ${distinct ? "✓ YES" : "✗ NO — CRITICAL FAILURE"}`);
  console.log("");

  // ── Sanity checks ─────────────────────────────────────────────────────────
  let all_ok = true;
  function check(name, cond, detail) {
    if (cond) { console.log(`  ✓ ${name}`); }
    else       { console.error(`  ✗ FAIL: ${name}${detail ? ` — ${detail}` : ""}`); all_ok = false; }
  }

  console.log("── Sanity checks ──");
  check("ZERO_VALUES[0] is non-zero (Poseidon(0,0) ≠ 0)", zero_values[0] !== 0n, zero_values[0]);
  check("ZERO_VALUES[0] < Fr modulus", zero_values[0] < FR_P);
  check("derived_pk is non-zero", pk_42 !== 0n);
  check("derived_pk < Fr modulus", pk_42 < FR_P);
  check("nullifier is non-zero", nf_42_99 !== 0n);
  check("commitment is non-zero", cmt_42 !== 0n);
  check("domain constants produce distinct outputs", distinct);
  console.log("");

  // ── Instructions ─────────────────────────────────────────────────────────
  console.log("── Cross-check instructions ──");
  console.log("1. Run Rust: cargo test -p merkle_tree test_print_zero_values -- --nocapture");
  console.log("2. Compare ZERO_VALUES[0..3] decimal values with output above.");
  console.log("3. If ANY value differs: HARD STOP. Do not proceed to trusted setup.");
  console.log("4. If all match: check the boxes in POSEIDON_PARAMS.md audit checklist.");
  console.log("");
  console.log("Note: The Poseidon(3) and Poseidon(5) test vectors above (nullifier,");
  console.log("commitment) use t=4 and t=6 respectively — these do not have a Rust");
  console.log("counterpart yet. The ZK engineer must verify these by running the");
  console.log("compiled circuit on known inputs and checking publicSignals matches.");

  if (!all_ok) process.exit(1);
}

main().catch(err => { console.error("Fatal:", err); process.exit(1); });
