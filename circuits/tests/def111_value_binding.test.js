/**
 * def111_value_binding.test.js — DEF-111 / B-prime §5.2 value-binding membership.
 *
 * Proves the exploit DEF-111 closes: a note whose in_value differs from the value
 * bound in the tree leaf CANNOT prove Merkle membership. Because the leaf is
 * MerkleLeaf(in_value, in_commitment), changing the value changes the leaf, changes
 * the root — so a note cannot sit at another value's anchor.
 *
 * Construction (isolates value-binding, not balance):
 *   - Build a fully self-consistent witness input for in_value = V2 (2 STSH), with
 *     its own anchor A2 (balance holds, all === constraints for V2 satisfied).
 *   - Tamper: swap in the anchor A1 of a DIFFERENT-value note (V1 = 1 STSH). Now the
 *     ONLY broken constraint is Merkle membership (anchor A1 === root-over-V2-leaf),
 *     and it breaks *because the leaf binds the value*. wtns check MUST fail.
 *   - Control: the untampered V2 input MUST pass wtns check.
 *
 * Witness-level, no ceremony. Run: node tests/def111_value_binding.test.js
 * Requires build/spend.r1cs + build/spend_js/spend.wasm (compile first).
 */
const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");
const { execFileSync } = require("child_process");

const TREE_DEPTH = 32;
const PK_DOMAIN = "1", NULLIFIER_DOMAIN = "2", COMMITMENT_DOMAIN = "3", MERKLE_LEAF_DOMAIN = "4";
const DOMAIN = ["2", "0", "2", "1"]; // DEF-082 staging [pool, asset, version, network]

function snarkjs(args) {
  return execFileSync("node", ["node_modules/.bin/snarkjs", ...args], { encoding: "utf8" });
}

function buildInput(P, inValue) {
  const domain_sep = P(...DOMAIN);
  const derived_pk = P("42", PK_DOMAIN);
  const in_commitment = P(domain_sep, inValue, derived_pk, "99", "77", COMMITMENT_DOMAIN);
  const nullifier_hash = P(domain_sep, "42", in_commitment, NULLIFIER_DOMAIN);
  const in_leaf = P(inValue, in_commitment, MERKLE_LEAF_DOMAIN);

  const zero = ["14744269619966411208579211824598458697587494354926760081771325075741142829156"];
  for (let i = 1; i < TREE_DEPTH; i++) zero.push(P(zero[i - 1], zero[i - 1]));
  let current = in_leaf;
  for (let i = 0; i < TREE_DEPTH; i++) current = P(current, zero[i]);
  const anchor = current;

  // self-transfer: out_value_1 = inValue, out_value_2 = 0, fee = 0, public_amount = 0.
  const inner1 = P(domain_sep, inValue, derived_pk, "111", "222", COMMITMENT_DOMAIN);
  const inner2 = P(domain_sep, "0", derived_pk, "333", "444", COMMITMENT_DOMAIN);
  const leaf1 = P(inValue, inner1, MERKLE_LEAF_DOMAIN);
  const leaf2 = P("0", inner2, MERKLE_LEAF_DOMAIN);

  return {
    anchor, nullifier_hash,
    output_merkle_leaf_1: leaf1, output_merkle_leaf_2: leaf2,
    public_amount: "0", fee: "0",
    recipient_principal: "0", recipient_subaccount_lo: "0", recipient_subaccount_hi: "0",
    spend_key: "42", in_value: inValue, in_rho: "99", in_rseed: "77",
    path_elements: zero.slice(0, TREE_DEPTH), path_indices: Array(TREE_DEPTH).fill("0"),
    out_value_1: inValue, out_recipient_pk_1: derived_pk, out_rho_1: "111", out_rseed_1: "222",
    out_value_2: "0", out_recipient_pk_2: derived_pk, out_rho_2: "333", out_rseed_2: "444",
  };
}

function witnessCheckPasses(inputPath) {
  execFileSync("node", ["build/spend_js/generate_witness.js", "build/spend_js/spend.wasm", inputPath, "build/vb.wtns"], { stdio: "pipe" });
  const out = snarkjs(["wtns", "check", "build/spend.r1cs", "build/vb.wtns"]);
  return /WITNESS IS CORRECT/.test(out);
}

(async () => {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const P = (...xs) => F.toObject(poseidon(xs.map(x => F.e(BigInt(x))))).toString();

  const V1 = "100000000";   // 1 STSH
  const V2 = "200000000";   // 2 STSH

  const in1 = buildInput(P, V1);
  const in2 = buildInput(P, V2);

  // Control: valid V2 witness must be satisfiable.
  fs.writeFileSync("build/vb_valid.json", JSON.stringify(in2));
  const controlOk = witnessCheckPasses("build/vb_valid.json");

  // Tamper: V2 note, but V1's anchor. Only membership should break.
  const tampered = { ...in2, anchor: in1.anchor };
  fs.writeFileSync("build/vb_tampered.json", JSON.stringify(tampered));
  let tamperedRejected = false;
  try {
    // generate_witness may itself throw on the unsatisfied === (depending on path);
    // either a throw OR a failing wtns check counts as rejection.
    tamperedRejected = !witnessCheckPasses("build/vb_tampered.json");
  } catch (e) {
    tamperedRejected = true;
  }

  console.log("control (valid V2 note)      wtns check:", controlOk ? "PASS (satisfiable)" : "FAIL");
  console.log("tampered (V2 note @ V1 anchor) rejected:", tamperedRejected ? "PASS (membership fails)" : "FAIL — value NOT bound!");

  if (controlOk && tamperedRejected) {
    console.log("DEF-111 §5.2 value-binding: PASS — a mismatched-value note cannot prove membership.");
    process.exit(0);
  } else {
    console.error("DEF-111 §5.2 value-binding: FAIL");
    process.exit(1);
  }
})().catch(e => { console.error(e); process.exit(1); });
