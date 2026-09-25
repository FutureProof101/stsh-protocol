/**
 * STSH Spend Circuit — Adversarial Test Suite
 * ─────────────────────────────────────────────
 * Tests ownership, nullifier, commitment, and value safety properties.
 *
 * NO-CEREMONY WITNESS GATE (ZK Review Run 1):
 *   This suite runs at the WITNESS level and needs only the compiled circuit —
 *   NOT a trusted-setup zkey. For each adversarial input it (a) generates a
 *   witness from spend.wasm via `snarkjs wtns calculate`, then (b) runs the
 *   explicit `snarkjs wtns check <r1cs> <wtns>` R1CS-satisfaction gate. An input
 *   is ACCEPTED only if the witness computes AND satisfies the R1CS; it is
 *   REJECTED if either step fails. We do NOT rely on the witness calculator
 *   throwing as the sole gate (SSA-PATCH #1).
 *
 * Prerequisites:
 *   circuits/build/spend.r1cs
 *   circuits/build/spend_js/spend.wasm
 *   (produced by: cd circuits && npm install && circom spend.circom --r1cs --wasm --sym --output ./build)
 *
 * Usage:
 *   cd circuits && node tests/adversarial.test.js
 *   # Point at a different compiled circuit (before/mutation variants):
 *   STSH_BUILD_DIR=/path/to/build node tests/adversarial.test.js
 *
 * Circuit version: 0.3.0-a0  (+ ZK Review Run 1: DEF-106 / DEF-094 / DEF-109-A)
 * Domain constants: PK_DOMAIN=1, NULLIFIER_DOMAIN=2, COMMITMENT_DOMAIN=3
 * MAX_NOTE_VALUE: 1_000_000_000_000_000 (10^15 base STSH units = 10,000,000 STSH,
 *                 the top rung of the five-tier launch ladder — A6.6)
 */

"use strict";

const path        = require("path");
const fs          = require("fs");
const os          = require("os");
const { buildPoseidon } = require("circomlibjs");
const snarkjs           = require("snarkjs");

// =============================================================================
// Constants — MUST match circuit
// =============================================================================
const PK_DOMAIN          = 1n;
const NULLIFIER_DOMAIN   = 2n;
const COMMITMENT_DOMAIN  = 3n;
const MERKLE_LEAF_DOMAIN = 4n;  // DEF-111 / B-prime value-bound outer leaf purpose tag
const MAX_NOTE_VALUE     = 1_000_000_000_000_000n;  // 10^15 base STSH units

// BN254 Fr modulus
const FR_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// DEF-106 band arithmetic (see remediation plan §1.2):
//   2^50 = 1,125,899,906,842,624 ; MAX_NOTE_VALUE+1 = 1,000,000,000,000,001
//   negative-band width k_max = 2^50 - (MAX+1), DERIVED from 2^50 rather than
//   restated, so the band tracks the bit width instead of a stale literal.
const TWO_POW_50    = 1_125_899_906_842_624n;
const BAND_K_MAX    = TWO_POW_50 - (MAX_NOTE_VALUE + 1n);   // 125,899,906,842,623

// Paths to compiled circuit artifacts (STSH_BUILD_DIR lets us target before/mutation builds)
const BUILD_DIR = process.env.STSH_BUILD_DIR
  ? path.resolve(process.env.STSH_BUILD_DIR)
  : path.join(__dirname, "..", "build");
const WASM_PATH = path.join(BUILD_DIR, "spend_js", "spend.wasm");
const R1CS_PATH = path.join(BUILD_DIR, "spend.r1cs");

const TREE_DEPTH = 32;
const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "stsh-wtns-"));

// =============================================================================
// Test harness
// =============================================================================
let passed = 0, failed = 0, skipped = 0;
function pass(name)          { console.log(`  ✓ PASS  ${name}`); passed++; }
function fail(name, reason)  { console.error(`  ✗ FAIL  ${name}`); if (reason) console.error(`         ${reason}`); failed++; }
function skip(name, reason)  { console.log(`  – SKIP  ${name}  (${reason})`); skipped++; }
function tag(name)           { return name.replace(/[^a-z0-9]+/gi, "_").slice(0, 60); }
function firstLine(s)        { return String(s).split("\n").find(l => l.trim()) || String(s).trim(); }

// Generate a witness from the compiled wasm (snarkjs API — needs only the wasm, no zkey). {ok, wtnsPath, err}.
async function gen_witness(input, name) {
  const wtnsPath = path.join(TMP_DIR, `${tag(name)}.wtns`);
  try {
    await snarkjs.wtns.calculate(input, WASM_PATH, wtnsPath);
    return { ok: true, wtnsPath };
  } catch (e) {
    return { ok: false, err: (e && e.message ? e.message : e || "").toString() };
  }
}

// Explicit R1CS-satisfaction gate (authoritative — needs only the r1cs, no zkey; SSA-PATCH #1). {ok, err}.
async function check_witness(wtnsPath) {
  try {
    const ok = await snarkjs.wtns.check(R1CS_PATH, wtnsPath);
    return { ok: !!ok };
  } catch (e) {
    return { ok: false, err: (e && e.message ? e.message : e || "").toString() };
  }
}

// ACCEPT: witness computes AND satisfies the R1CS.
async function expect_accept(name, input) {
  const g = await gen_witness(input, name);
  if (!g.ok) { fail(name, `witness generation failed (expected ACCEPT): ${firstLine(g.err)}`); return; }
  const c = await check_witness(g.wtnsPath);
  if (c.ok) pass(name); else fail(name, `wtns check failed (expected ACCEPT): ${firstLine(c.err)}`);
}

// REJECT: witness generation throws OR the R1CS check fails (either is a valid rejection).
async function expect_reject(name, input) {
  const g = await gen_witness(input, name);
  if (!g.ok) { pass(name); return; }                    // rejected at witness calculation
  const c = await check_witness(g.wtnsPath);
  if (!c.ok) pass(name);
  else fail(name, "witness satisfies R1CS but should have been REJECTED (defect OPEN)");
}

// =============================================================================
// Field / Poseidon helpers (must match circuit)
// =============================================================================
function mod_p(x)          { return ((x % FR_P) + FR_P) % FR_P; }
function modpow(b, e, m)   { b = mod_p(b); let r = 1n; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
function modinv(a)         { return modpow(a, FR_P - 2n, FR_P); }  // Fermat (p prime)

function poseidon_hash(poseidon, inputs) {
  const F = poseidon.F;
  return BigInt(F.toObject(poseidon(inputs.map(x => F.e(mod_p(BigInt(x)))))).toString());
}
function derive_pk(poseidon, spend_key) {
  return poseidon_hash(poseidon, [spend_key, PK_DOMAIN]);
}

// DEF-035 deployment-binding domain separator (must match spend.circom STSHSpend
// Constraint 0). PR #27 circuit finalization (DEF-082) set POOL_CANISTER_ID and
// CIRCUIT_VERSION to the staging value 2; keep these in lock-step with the circuit.
const DOMAIN_POOL_CANISTER_ID = 4523128485832663883733241601901871400518358776001584537546685574107874983936n;  // cxrfg-qaaaa-aaaar-qchfa-cai
const DOMAIN_ASSET_ID         = 0n;
const DOMAIN_CIRCUIT_VERSION  = 3n;   // circuit-finalization revision (2->3 at A6.6)
const DOMAIN_NETWORK_ID       = 1n;
function derive_domain_sep(poseidon) {
  return poseidon_hash(poseidon, [DOMAIN_POOL_CANISTER_ID, DOMAIN_ASSET_ID, DOMAIN_CIRCUIT_VERSION, DOMAIN_NETWORK_ID]);
}

function derive_commitment(poseidon, value, recipient_pk, rho, rseed) {
  // DEF-035: domain_sep prepended as the first input (matches NoteCommitment).
  return poseidon_hash(poseidon, [derive_domain_sep(poseidon), value, recipient_pk, rho, rseed, COMMITMENT_DOMAIN]);
}

// DEF-111 / B-prime: the value-bound OUTER Merkle leaf. Membership now proves the
// note's spendable value, not just its inner commitment:
//   leaf = Poseidon(value, inner_commitment, MERKLE_LEAF_DOMAIN)   [Poseidon(3), t=4]
// domain_sep is intentionally OMITTED (the inner commitment already binds it).
// MUST match circuits/spend.circom `MerkleLeaf` and gen_test_input.js.
function derive_merkle_leaf(poseidon, value, inner_commitment) {
  return poseidon_hash(poseidon, [value, inner_commitment, MERKLE_LEAF_DOMAIN]);
}

// DEF-109-A: full-note nullifier binding. The nullifier commits to the input note's
// COMMITMENT (which binds value, derived_pk, rho, rseed) rather than the bare rho.
// MUST match circuits/spend.circom NullifierDerivation.
function derive_nullifier(poseidon, spend_key, in_commitment) {
  return poseidon_hash(poseidon, [derive_domain_sep(poseidon), spend_key, in_commitment, NULLIFIER_DOMAIN]);
}
// Pre-DEF-109 form, kept ONLY to demonstrate the closed collision in the D1 test.
function derive_nullifier_legacy(poseidon, spend_key, rho) {
  return poseidon_hash(poseidon, [derive_domain_sep(poseidon), spend_key, rho, NULLIFIER_DOMAIN]);
}

// Depth-32 Merkle proof for a single leaf (sibling at level 0, zero siblings above).
function build_depth1_proof(poseidon, leaf, sibling, is_right_child) {
  const first = is_right_child
    ? poseidon_hash(poseidon, [sibling, leaf])
    : poseidon_hash(poseidon, [leaf, sibling]);
  const path_elements = new Array(TREE_DEPTH).fill(0n);
  const path_indices  = new Array(TREE_DEPTH).fill(0n);
  path_elements[0] = sibling;
  path_indices[0]  = is_right_child ? 1n : 0n;
  let current = first;
  for (let i = 1; i < TREE_DEPTH; i++) current = poseidon_hash(poseidon, [current, 0n]);
  return { root: current, path_elements, path_indices };
}

// Build a FULLY CONSISTENT witness: input-note commitment, its Merkle proof/anchor,
// the DEF-109-A full-note nullifier, and BOTH output commitments are all recomputed
// from the supplied values. So the only way such a witness fails is a genuine circuit
// constraint (value range or balance) — never an accidental commitment/anchor mismatch.
// This is what makes the DEF-106 range tests attributable to the RANGE check alone
// (SSA-PATCH #2). `p.merkle` overrides the proof (used by the DEF-094 forgery test).
function build_consistent_input(poseidon, p = {}) {
  const spend_key      = p.spend_key      ?? 42n;
  const in_rho         = p.in_rho         ?? 99n;
  const in_rseed       = p.in_rseed       ?? 77n;
  const in_value       = p.in_value       ?? 100_000_000n;
  const fee            = p.fee            ?? 0n;
  const public_amount  = p.public_amount  ?? 0n;
  const out_rho_1      = p.out_rho_1      ?? 111n;
  const out_rseed_1    = p.out_rseed_1    ?? 222n;
  const out_rho_2      = p.out_rho_2      ?? 333n;
  const out_rseed_2    = p.out_rseed_2    ?? 444n;
  const out_value_1    = p.out_value_1    ?? in_value;
  const out_value_2    = p.out_value_2    ?? 0n;
  const is_right_child = p.is_right_child ?? false;

  const recipient_pk       = derive_pk(poseidon, spend_key);
  const out_recipient_pk_1 = p.out_recipient_pk_1 ?? recipient_pk;
  const out_recipient_pk_2 = p.out_recipient_pk_2 ?? recipient_pk;

  const in_commitment = derive_commitment(poseidon, in_value, recipient_pk, in_rho, in_rseed);
  // Nullifier mode lets the DEF-106/094 before/attribution runs target the pre-DEF-109
  // circuit (legacy = bind rho) so those tests stay attributable to range/merkle, not to
  // a nullifier-formula mismatch. Default is the fixed DEF-109-A full-note binding.
  const nullifier = (process.env.STSH_NULLIFIER === "legacy")
    ? derive_nullifier_legacy(poseidon, spend_key, in_rho)
    : derive_nullifier(poseidon, spend_key, in_commitment);

  // DEF-111: the tree leaf is the VALUE-BOUND outer hash, not the raw inner
  // commitment. The circuit feeds MerkleLeaf(in_value, in_commitment) into MerkleProof,
  // so the anchor must be built over that leaf for `anchor === merkle.root` to hold.
  const in_leaf = derive_merkle_leaf(poseidon, in_value, in_commitment);

  let anchor, path_elements, path_indices;
  if (p.merkle) {
    ({ anchor, path_elements, path_indices } = p.merkle);
  } else {
    const proof = build_depth1_proof(poseidon, in_leaf, p.sibling ?? 1234567890n, is_right_child);
    anchor = proof.root; path_elements = proof.path_elements; path_indices = proof.path_indices;
  }

  const out_commit_1 = derive_commitment(poseidon, out_value_1, out_recipient_pk_1, out_rho_1, out_rseed_1);
  const out_commit_2 = derive_commitment(poseidon, out_value_2, out_recipient_pk_2, out_rho_2, out_rseed_2);
  // DEF-111: public signals 2/3 are the value-bound OUTER leaves (output_merkle_leaf_1/2),
  // not the inner commitments. output_commitment_i stays a private circuit intermediate.
  const out_leaf_1 = derive_merkle_leaf(poseidon, out_value_1, out_commit_1);
  const out_leaf_2 = derive_merkle_leaf(poseidon, out_value_2, out_commit_2);

  return {
    anchor:                 mod_p(anchor).toString(),
    nullifier_hash:         mod_p(nullifier).toString(),
    output_merkle_leaf_1:   mod_p(out_leaf_1).toString(),
    output_merkle_leaf_2:   mod_p(out_leaf_2).toString(),
    public_amount:        mod_p(public_amount).toString(),
    fee:                  mod_p(fee).toString(),
    // DEF-026 recipient binding (public, unconstrained in-circuit). No-payout
    // encoding is all-zero (private spend); still required as circuit inputs.
    recipient_principal:      mod_p(p.recipient_principal     ?? 0n).toString(),
    recipient_subaccount_lo:  mod_p(p.recipient_subaccount_lo ?? 0n).toString(),
    recipient_subaccount_hi:  mod_p(p.recipient_subaccount_hi ?? 0n).toString(),
    spend_key:            mod_p(spend_key).toString(),
    in_value:             mod_p(in_value).toString(),
    in_rho:               mod_p(in_rho).toString(),
    in_rseed:             mod_p(in_rseed).toString(),
    path_elements:        path_elements.map(x => mod_p(BigInt(x)).toString()),
    path_indices:         path_indices.map(x => mod_p(BigInt(x)).toString()),
    out_value_1:          mod_p(out_value_1).toString(),
    out_recipient_pk_1:   mod_p(out_recipient_pk_1).toString(),
    out_rho_1:            mod_p(out_rho_1).toString(),
    out_rseed_1:          mod_p(out_rseed_1).toString(),
    out_value_2:          mod_p(out_value_2).toString(),
    out_recipient_pk_2:   mod_p(out_recipient_pk_2).toString(),
    out_rho_2:            mod_p(out_rho_2).toString(),
    out_rseed_2:          mod_p(out_rseed_2).toString(),
  };
}
// Convenience wrapper: consistent base note (spend_key=42) with field overrides.
// Overriding a PRIVATE field (spend_key/in_rho/in_rseed/in_value) intentionally
// desyncs it from the recomputed commitment/anchor/nullifier — used by the A-tests
// to prove tampering is rejected.
function valid_input(poseidon, overrides = {}) {
  return { ...build_consistent_input(poseidon), ...overrides };
}

// =============================================================================
// Test suite (witness level — no ceremony)
// =============================================================================
async function run_tests(poseidon) {

  // ── Section A: Ownership and spend authority ───────────────────────────
  console.log("\n── A: Ownership and spend authority ──");

  await expect_accept("A1: correct spend_key spends note", valid_input(poseidon));
  await expect_reject("A2: wrong spend_key fails",                       valid_input(poseidon, { spend_key: "999" }));
  await expect_reject("A3: tampered nullifier_hash fails",               valid_input(poseidon, { nullifier_hash: "12345" }));
  await expect_reject("A4: wrong rho fails (commitment+nullifier mismatch)", valid_input(poseidon, { in_rho: "555" }));
  await expect_reject("A5: wrong rseed fails (commitment mismatch)",      valid_input(poseidon, { in_rseed: "666" }));
  await expect_reject("A6: wrong in_value fails (commitment mismatch)",   valid_input(poseidon, { in_value: "200000000" }));

  // A7: nullifier changes when rho changes (DEF-109-A: via the commitment).
  {
    const pk = derive_pk(poseidon, 42n);
    const c1 = derive_commitment(poseidon, 100_000_000n, pk, 1n, 77n);
    const c2 = derive_commitment(poseidon, 100_000_000n, pk, 2n, 77n);
    const nf1 = derive_nullifier(poseidon, 42n, c1);
    const nf2 = derive_nullifier(poseidon, 42n, c2);
    nf1 !== nf2 ? pass("A7: nullifier changes when rho changes") : fail("A7: nullifier changes when rho changes", `nf1===nf2=${nf1}`);
  }
  // A8: nullifier changes when spend_key changes.
  {
    const c1 = derive_commitment(poseidon, 100_000_000n, derive_pk(poseidon, 10n), 99n, 77n);
    const c2 = derive_commitment(poseidon, 100_000_000n, derive_pk(poseidon, 11n), 99n, 77n);
    const nf1 = derive_nullifier(poseidon, 10n, c1);
    const nf2 = derive_nullifier(poseidon, 11n, c2);
    nf1 !== nf2 ? pass("A8: nullifier changes when spend_key changes") : fail("A8: nullifier changes when spend_key changes", `nf1===nf2=${nf1}`);
  }
  // A9: commitment changes when recipient_pk changes.
  {
    const c1 = derive_commitment(poseidon, 1_000_000_000n, derive_pk(poseidon, 42n), 99n, 77n);
    const c2 = derive_commitment(poseidon, 1_000_000_000n, derive_pk(poseidon, 43n), 99n, 77n);
    c1 !== c2 ? pass("A9: commitment changes when recipient_pk changes") : fail("A9: commitment changes when recipient_pk changes", `c1===c2=${c1}`);
  }
  // A10: domain constants produce distinct outputs (no cross-domain collision).
  {
    const x = 42n;
    const pk_out  = poseidon_hash(poseidon, [x, PK_DOMAIN]);
    const nf_out  = poseidon_hash(poseidon, [x, NULLIFIER_DOMAIN]);
    const cmt_out = poseidon_hash(poseidon, [x, COMMITMENT_DOMAIN]);
    (pk_out !== nf_out && pk_out !== cmt_out && nf_out !== cmt_out)
      ? pass("A10: domain constants produce distinct outputs")
      : fail("A10: domain constants produce distinct outputs", `pk=${pk_out}, nf=${nf_out}, cmt=${cmt_out}`);
  }

  // ── Section B: Amount and value safety (DEF-106) ───────────────────────
  console.log("\n── B: Amount and value safety (DEF-106) ──");

  // B2/B3/B4: positive values ABOVE MAX_NOTE_VALUE — rejected by the retained
  // LessThan(50) upper bound (reject before AND after; DEF-106 does not affect this).
  await expect_reject("B2: in_value above MAX_NOTE_VALUE fails",
    build_consistent_input(poseidon, { in_value: MAX_NOTE_VALUE + 1n, out_value_1: MAX_NOTE_VALUE + 1n, out_value_2: 0n }));
  await expect_reject("B3: out_value_1 above MAX_NOTE_VALUE fails",
    build_consistent_input(poseidon, { in_value: MAX_NOTE_VALUE + 1n, out_value_1: MAX_NOTE_VALUE + 1n, out_value_2: 0n }));
  await expect_reject("B4: fee above MAX_NOTE_VALUE fails",
    build_consistent_input(poseidon, { in_value: MAX_NOTE_VALUE + 1n, fee: MAX_NOTE_VALUE + 1n, out_value_1: 0n, out_value_2: 0n }));

  // B1: near-Fr-modulus output value (negative band, k=1). BEFORE fix: ACCEPTED
  // (difference-only LessThan admits it). AFTER fix: rejected by raw Num2Bits(50).
  // Balance held: in=1e8, out1=p-1, out2=1e8+1  ->  (p-1)+(1e8+1) = p+1e8 = 1e8.
  await expect_reject("B1: out_value near Fr modulus fails (DEF-106 negative band, k=1)",
    build_consistent_input(poseidon, { in_value: 100_000_000n, out_value_1: FR_P - 1n, out_value_2: 100_000_001n }));

  // B5: sum wraparound. in=1e8, out1=2e8, out2=p-1e8. Balance held in-field.
  // BEFORE fix: out2=p-1e8 sits in the negative band -> LessThan admits it -> ACCEPT
  // (a mint). AFTER fix: raw Num2Bits(50) on out2 rejects. Failure is attributable
  // to the range check alone — commitments and balance are both satisfied.
  await expect_reject("B5: value sum wraparound via near-modulus out_value fails",
    build_consistent_input(poseidon, { in_value: 100_000_000n, out_value_1: 200_000_000n, out_value_2: FR_P - 100_000_000n }));

  // B5a: MAXIMUM-EXTRACTION PoC / band ceiling. out2 = p - BAND_K_MAX, out1 chosen
  // so in-field balance holds; out1 = in + BAND_K_MAX <= MAX. BEFORE fix this is the
  // real ~1,258,999.07 STSH mint (ACCEPT). AFTER fix: rejected on out2 raw range.
  await expect_reject("B5a: max-extraction PoC (band ceiling) fails",
    build_consistent_input(poseidon, { in_value: 100_000_000n, out_value_1: 100_000_000n + BAND_K_MAX, out_value_2: FR_P - BAND_K_MAX }));

  // B5b: exact rejection edge — out2 = p - (BAND_K_MAX+1), one below the band floor.
  // Rejected BOTH before (LessThan internal Num2Bits(51) overflow) AND after (raw
  // Num2Bits(50)). Pins the boundary so a future widening is caught.
  await expect_reject("B5b: exact rejection edge (one below band floor) fails",
    build_consistent_input(poseidon, { in_value: 100_000_000n, out_value_1: 100_000_000n + (BAND_K_MAX + 1n), out_value_2: FR_P - (BAND_K_MAX + 1n) }));

  // B5c: isolates a SECOND signal (in_value) in the band with balance satisfied.
  // in_value = p-k, out_value_2 = p-k, out_value_1 = 0, k=1e8. Field balance:
  // (p-k) = 0 + (p-k) + 0 + 0. BEFORE fix: both in_value and out_value_2 pass the
  // difference-only range -> ACCEPT. AFTER fix: raw Num2Bits(50) on in_value (and
  // out_value_2) rejects. Balance holds either way, so the before-fix success is
  // attributable to raw-range closure on in_value, not to the balance equation.
  await expect_reject("B5c: in-band in_value with balance satisfied fails (isolates in_value)",
    build_consistent_input(poseidon, { in_value: FR_P - 100_000_000n, out_value_1: 0n, out_value_2: FR_P - 100_000_000n }));

  // B6: zero output value is allowed (empty change note).
  await expect_accept("B6: zero output value is allowed (empty note)", build_consistent_input(poseidon, { out_value_2: 0n }));

  // B7: dust (1 base unit) is circuit-valid (canister enforces the minimum, not the circuit).
  await expect_accept("B7: dust value is circuit-valid (canister enforces minimum)",
    build_consistent_input(poseidon, { in_value: 1n, out_value_1: 1n, out_value_2: 0n }));

  // B7a/B7b (A6.6): the NEW bound is exactly where it says it is. The top ladder
  // rung (10,000,000 STSH = MAX_NOTE_VALUE) must be provable, and one base unit
  // above it must not. This is AC-4's own vacuity check: it fails against the OLD
  // 10^11 bound in BOTH directions, so it cannot pass on a stale circuit.
  await expect_accept("B7a: public_amount at MAX_NOTE_VALUE (top ladder rung) is accepted",
    build_consistent_input(poseidon, { in_value: MAX_NOTE_VALUE, out_value_1: 0n, out_value_2: 0n, public_amount: MAX_NOTE_VALUE }));
  await expect_reject("B7b: public_amount above MAX_NOTE_VALUE (bound + 1) fails",
    build_consistent_input(poseidon, { in_value: MAX_NOTE_VALUE + 1n, out_value_1: 0n, out_value_2: 0n, public_amount: MAX_NOTE_VALUE + 1n }));

  // B8: value balance violated (out > in) fails.
  await expect_reject("B8: value balance violation (out > in) fails",
    build_consistent_input(poseidon, { in_value: 100_000_000n, out_value_1: 200_000_000n, out_value_2: 0n }));

  // ── Section C: Merkle membership soundness (DEF-094) ───────────────────
  console.log("\n── C: Merkle membership soundness (DEF-094) ──");

  // C1: NON-BOOLEAN path selector forges membership onto a real root while the leaf
  // is an unrelated (attacker-invented) note. Route (a): full STSHSpend witness.
  // Switcher: outL = L + (R-L)*sel, outR = R - (R-L)*sel. Pick target children (A,B),
  // set R = A+B-L and sel = (A-L)/(A+B-2L) so (outL,outR) = (A,B) regardless of L,
  // making level-1 = Poseidon(A,B) independent of the real leaf. Hash that up 31 zero
  // levels to the anchor. BEFORE fix: sel unconstrained -> forged root == anchor ->
  // ACCEPT (mint up to MAX per proof). AFTER fix: path_indices[0]*(1-path_indices[0])
  // === 0 rejects the non-boolean sel.
  {
    const sk_x = 7n, v_x = 100_000_000n, rho_x = 5n, rseed_x = 6n;
    // DEF-111: the circuit's level-0 leaf (L) is the VALUE-BOUND outer leaf, not the
    // inner commitment — the forgery math must target it so the ONLY broken constraint
    // is the DEF-094 selector booleanity (attribution preserved).
    const in_commit_x = derive_commitment(poseidon, v_x, derive_pk(poseidon, sk_x), rho_x, rseed_x);
    const X = derive_merkle_leaf(poseidon, v_x, in_commit_x); // circuit level-0 leaf L
    const A = 111111n, B = 222222n;                        // "real" top-level children
    const forged_level1 = poseidon_hash(poseidon, [A, B]);
    let anchor = forged_level1;
    for (let i = 1; i < TREE_DEPTH; i++) anchor = poseidon_hash(poseidon, [anchor, 0n]);
    const R0  = mod_p(A + B - X);
    const sel = mod_p((A - X) * modinv(mod_p(A + B - 2n * X)));  // NON-boolean
    const path_elements = new Array(TREE_DEPTH).fill(0n); path_elements[0] = R0;
    const path_indices  = new Array(TREE_DEPTH).fill(0n); path_indices[0]  = sel;
    const forged = build_consistent_input(poseidon, {
      spend_key: sk_x, in_value: v_x, in_rho: rho_x, in_rseed: rseed_x,
      out_value_1: v_x, out_value_2: 0n,
      merkle: { anchor, path_elements, path_indices },
    });
    await expect_reject("C1: non-boolean path selector forges membership (must be rejected)", forged);
  }

  // C2: legitimate membership with a BOOLEAN selector (right child, sel=1) still
  // succeeds — guards against an over-tight fix.
  await expect_accept("C2: boolean selector (right-child membership) still succeeds",
    build_consistent_input(poseidon, { is_right_child: true }));

  // ── Section D: Nullifier note-binding (DEF-109-A) ──────────────────────
  console.log("\n── D: Nullifier full-note binding (DEF-109-A) ──");

  // D1: two valid notes with the SAME spend_key and SAME rho but different
  // value/rseed. They have distinct commitments (already true). The LEGACY nullifier
  // Poseidon(ds, sk, rho, ND) COLLIDES (the bug: one note bricks the other). The
  // DEF-109-A nullifier Poseidon(ds, sk, in_commitment, ND) is DISTINCT (fixed).
  {
    const sk = 42n, rho = 99n, pk = derive_pk(poseidon, sk);
    const c1 = derive_commitment(poseidon, 100_000_000n, pk, rho, 77n);
    const c2 = derive_commitment(poseidon, 200_000_000n, pk, rho, 88n);
    const legacy1 = derive_nullifier_legacy(poseidon, sk, rho);
    const legacy2 = derive_nullifier_legacy(poseidon, sk, rho);
    const fixed1  = derive_nullifier(poseidon, sk, c1);
    const fixed2  = derive_nullifier(poseidon, sk, c2);
    (c1 !== c2 && legacy1 === legacy2 && fixed1 !== fixed2)
      ? pass("D1: same (spend_key,rho) + different value/rseed -> legacy collides, DEF-109-A distinct")
      : fail("D1: DEF-109-A nullifier distinctness", `c1==c2:${c1===c2} legacyEq:${legacy1===legacy2} fixedDistinct:${fixed1!==fixed2}`);
  }

  // ── Summary ─────────────────────────────────────────────────────────────
  console.log(`\n── Results: ${passed} passed, ${failed} failed, ${skipped} skipped ──`);
  // snarkjs keeps a BN254 worker thread pool alive, which would otherwise hang the
  // event loop after a clean run — force an explicit exit with the pass/fail code.
  process.exit(failed > 0 ? 1 : 0);
}

// =============================================================================
// Entry point
// =============================================================================
async function main() {
  console.log("=== STSH Spend Circuit — Adversarial Test Suite (witness gate) ===");
  console.log(`Build dir: ${BUILD_DIR}`);
  console.log(`PK_DOMAIN=${PK_DOMAIN}, NULLIFIER_DOMAIN=${NULLIFIER_DOMAIN}, COMMITMENT_DOMAIN=${COMMITMENT_DOMAIN}, MAX_NOTE_VALUE=${MAX_NOTE_VALUE}`);

  for (const p of [WASM_PATH, R1CS_PATH]) {
    if (!fs.existsSync(p)) {
      console.error(`\n✗ Missing compiled artifact: ${p}`);
      console.error("  Compile first: cd circuits && npm install && circom spend.circom --r1cs --wasm --sym --output ./build");
      process.exit(2);
    }
  }
  const poseidon = await buildPoseidon();
  await run_tests(poseidon);
}

main().catch(err => { console.error("Fatal error:", err); process.exit(1); });
