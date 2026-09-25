/**
 * gen_test_input.js — A1 Task 3: generate spend circuit test inputs
 *
 * Computes all Poseidon hashes from pinned test values, builds a single-leaf
 * Merkle path (depth 32, leaf at index 0), and writes tests/test_input.json.
 *
 * Run:  node tests/gen_test_input.js
 * Then: node build/spend_js/generate_witness.js build/spend_js/spend.wasm tests/test_input.json witness.wtns
 *
 * Test vectors verified against POSEIDON_PARAMS.md (circomlibjs@0.1.7, BN254).
 */

const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Helper: Poseidon over BigInt-coercible inputs, returns decimal string.
    function P(...inputs) {
        const result = poseidon(inputs.map(x => F.e(BigInt(x))));
        return F.toObject(result).toString();
    }

    // ── Known test values ─────────────────────────────────────────────────────
    const SPEND_KEY     = "42";
    const IN_RHO        = "99";
    const IN_RSEED      = "77";
    const IN_VALUE      = "100000000000";   // 1e11 base STSH units (1,000 STSH —
                                            // DENOMINATIONS[0], the A6.6 ladder floor;
                                            // the fixture note must be depositable)

    // Domain constants (must match spend.circom)
    const PK_DOMAIN          = "1";
    const NULLIFIER_DOMAIN   = "2";
    const COMMITMENT_DOMAIN  = "3";
    const MERKLE_LEAF_DOMAIN = "4";   // DEF-111 value-bound outer leaf

    // DEF-035 deployment-binding domain separation (must match spend.circom STSHSpend
    // DOMAIN_* constants). Prepended as the FIRST input to the nullifier and every
    // commitment hash. PK derivation is NOT domain-separated (matches the circuit).
    // DEF-082 circuit-finalization: staging pool-id = 2, circuit version = 2; A6.6 moved it to 3.
    const DOMAIN_POOL_CANISTER_ID = "4523128485832663883733241601901871400518358776001584537546685574107874983936";  // cxrfg-qaaaa-aaaar-qchfa-cai
    const DOMAIN_ASSET_ID         = "0";
    const DOMAIN_CIRCUIT_VERSION  = "3";   // circuit-finalization revision (2->3 at A6.6)
    const DOMAIN_NETWORK_ID       = "1";
    const domain_sep = P(DOMAIN_POOL_CANISTER_ID, DOMAIN_ASSET_ID, DOMAIN_CIRCUIT_VERSION, DOMAIN_NETWORK_ID);
    console.log("domain_sep        :", domain_sep);

    // ── Step 1: derive pk ─────────────────────────────────────────────────────
    const derived_pk = P(SPEND_KEY, PK_DOMAIN);
    console.log("derived_pk        :", derived_pk);
    // Expected: 16556036937753546091282698062266362651008751416415631538814028886573393469713

    // ── Step 2: input commitment (computed BEFORE the nullifier — DEF-109-A) ──
    const in_commitment = P(domain_sep, IN_VALUE, derived_pk, IN_RHO, IN_RSEED, COMMITMENT_DOMAIN);
    console.log("in_commitment     :", in_commitment);

    // ── Step 3: nullifier (DEF-109-A full-note binding) ───────────────────────
    // nullifier = Poseidon(domain_sep, spend_key, in_commitment, NULLIFIER_DOMAIN)
    // (binds the whole note via in_commitment, NOT the bare rho — matches the circuit).
    const nullifier_hash = P(domain_sep, SPEND_KEY, in_commitment, NULLIFIER_DOMAIN);
    console.log("nullifier_hash    :", nullifier_hash);

    // T55_IN_COMMITMENT for security_tests.rs — 32-byte little-endian of in_commitment.
    function toLeBytes(decStr) {
        let n = BigInt(decStr);
        const out = [];
        for (let i = 0; i < 32; i++) { out.push("0x" + Number(n & 0xffn).toString(16).padStart(2, "0")); n >>= 8n; }
        return out;
    }
    const _leb = toLeBytes(in_commitment);
    console.log("T55_IN_COMMITMENT (LE bytes, paste into security_tests.rs):");
    console.log("    " + _leb.slice(0, 16).join(", ") + ",");
    console.log("    " + _leb.slice(16, 32).join(", ") + ",");

    const _t68 = toLeBytes((BigInt(nullifier_hash) + 1n).toString());
    console.log("T68_TAMPERED_NF (nullifier_hash+1, LE bytes for security_tests.rs):");
    console.log("    " + _t68.slice(0, 16).join(", ") + ",");
    console.log("    " + _t68.slice(16, 32).join(", ") + ",");

    // ── Step 4: Merkle path (depth 32, leaf at position 0) ───────────────────
    //
    // zeroValues[0] = Poseidon(0,0)  — Rust ZERO_VALUES[0] (canonical empty leaf, M4 Poseidon convention)
    // zeroValues[i] = Poseidon(zeroValues[i-1], zeroValues[i-1])  — matches Rust ZERO_VALUES[i]
    //
    // path_elements[i] = zeroValues[i]   (sibling is a fully-empty subtree)
    // path_indices[i]  = "0"             (leaf is always left child)
    //
    // zeroValues[0] matches POSEIDON_PARAMS.md ZERO_VALUES[0] = Poseidon(0,0)
    // zeroValues[i] matches ZERO_VALUES[i] for all i

    const TREE_DEPTH = 32;
    // Seed with Poseidon(0,0) — the Rust canonical empty leaf (ZERO_VALUES[0]).
    // Previously seeded with "0", which mismatched the Rust Merkle canister's M4 zero convention.
    const zeroValues = ["14744269619966411208579211824598458697587494354926760081771325075741142829156"];
    for (let i = 1; i < TREE_DEPTH; i++) {
        zeroValues.push(P(zeroValues[i - 1], zeroValues[i - 1]));
    }

    // Sanity-check first four against POSEIDON_PARAMS.md / Rust ZERO_VALUES[0..3]
    const EXPECTED_ZERO = [
        "14744269619966411208579211824598458697587494354926760081771325075741142829156",
        "7423237065226347324353380772367382631490014989348495481811164164159255474657",
        "11286972368698509976183087595462810875513684078608517520839298933882497716792",
        "3607627140608796879659380071776844901612302623152076817094415224584923813162",
    ];
    let zeroCrossCheckOk = true;
    for (let i = 0; i < 4; i++) {
        if (zeroValues[i] !== EXPECTED_ZERO[i]) {
            console.error(`CROSS-CHECK FAIL: zeroValues[${i}] = ${zeroValues[i]}`);
            console.error(`  expected                             ${EXPECTED_ZERO[i]}`);
            zeroCrossCheckOk = false;
        }
    }
    if (zeroCrossCheckOk) {
        console.log("zero_values xcheck: PASS (levels 0-3 match POSEIDON_PARAMS.md / Rust ZERO_VALUES)");
    }

    const path_elements = zeroValues.slice(0, TREE_DEPTH);  // [zeroValues[0]..zeroValues[31]] = ZERO_VALUES[0..31]
    const path_indices  = Array(TREE_DEPTH).fill("0");

    // ── Step 5: compute anchor by walking the path ────────────────────────────
    // DEF-111: the tree leaf is the VALUE-BOUND outer hash, not the raw inner
    // commitment. Seed the walk from MerkleLeaf(in_value, in_commitment) so the
    // fixture anchor matches what the pool builds when it deposits a note of
    // in_value with this commitment (merkle_leaf(private_balance, commitment)).
    const in_leaf = P(IN_VALUE, in_commitment, MERKLE_LEAF_DOMAIN);
    console.log("in_leaf (DEF-111) :", in_leaf);
    let current = in_leaf;
    for (let i = 0; i < TREE_DEPTH; i++) {
        // path_indices[i] = 0  →  current is left child
        current = P(current, path_elements[i]);
    }
    const anchor = current;
    console.log("anchor            :", anchor);

    // ── Step 6: output notes + DEF-026 recipient binding (two fixtures) ───────
    //
    // The input note (in_commitment, nullifier, anchor) is IDENTICAL across both
    // fixtures — only the output-note value, public_amount, and recipient signals
    // differ.  So T55_IN_COMMITMENT and the deposit/anchor are shared.
    //
    //   Fixture 2 (canonical, tests/test_input.json -> proof.json/public.json):
    //     none-payout — public_amount = 0, recipient signals [6][7][8] = 0.
    //     Consumed by the bulk of the integration suite (test_55, 64-70, 90,
    //     94-96, 99, full-path benchmark, verifier_tests v04/v05), all of which
    //     submit private_spend with public_payout = None.
    //
    //   Fixture 1 (DEF-026, tests/test_input_payout_a.json ->
    //              proof_payout_a.json/public_payout_a.json):
    //     payout-to-A — public_amount = 60_000, recipient = encode(A).
    //     Drives the recipient-binding tests A (valid), B/C/D (substituted
    //     principal / subaccount-lo / subaccount-hi all rejected).
    //
    // Recipient signals are encoded EXACTLY as the pool's encode_recipient_signals
    // (canisters/shielded-pool src/lib.rs): principal -> raw bytes right-padded to
    // 32, little-endian field element; subaccount -> bytes[0..16] => lo (128-bit
    // LE), bytes[16..32] => hi.  A None payout encodes all three signals as zero.

    const OUT_VALUE_2 = "0";   // dummy empty change note (shared)
    const OUT_RHO_1   = "111";
    const OUT_RSEED_1 = "222";
    const OUT_RHO_2   = "333";
    const OUT_RSEED_2 = "444";
    const FEE         = "0";
    const out_pk_1 = derived_pk;   // send to self
    const out_pk_2 = derived_pk;   // dummy note (value = 0)

    const leBytesToDecimal = (bytes) => {
        let n = 0n;
        for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
        return n.toString(10);
    };

    // recipient === null  =>  public_payout = None  =>  all three signals zero.
    // Otherwise { principalBytes: number[], subaccount: number[32] }.
    function encodeRecipient(recipient) {
        if (recipient === null) {
            return { principal: "0", subLo: "0", subHi: "0" };
        }
        const principal32 = [...recipient.principalBytes];
        while (principal32.length < 32) principal32.push(0);
        // DEF-108: commit the principal length in byte[31] so trailing-zero-distinct
        // principals no longer collide — MUST match the canister encode_recipient_signals
        // (principal_sig[31] = pbytes.len()). len <= 29 keeps the field element canonical.
        principal32[31] = recipient.principalBytes.length;
        const sub = recipient.subaccount;            // exactly 32 bytes
        return {
            principal: leBytesToDecimal(principal32),
            subLo:     leBytesToDecimal(sub.slice(0, 16)),
            subHi:     leBytesToDecimal(sub.slice(16, 32)),
        };
    }

    function buildScenario(name, { OUT_VALUE_1, PUBLIC_AMOUNT, recipient, outPath }) {
        const rsig = encodeRecipient(recipient);
        // DEF-111: public signals 2/3 are the VALUE-BOUND outer leaves, not the inner
        // commitments. inner_commitment_i stays a private circuit intermediate.
        const inner_commitment_1 = P(domain_sep, OUT_VALUE_1, out_pk_1, OUT_RHO_1, OUT_RSEED_1, COMMITMENT_DOMAIN);
        const inner_commitment_2 = P(domain_sep, OUT_VALUE_2, out_pk_2, OUT_RHO_2, OUT_RSEED_2, COMMITMENT_DOMAIN);
        const output_merkle_leaf_1 = P(OUT_VALUE_1, inner_commitment_1, MERKLE_LEAF_DOMAIN);
        const output_merkle_leaf_2 = P(OUT_VALUE_2, inner_commitment_2, MERKLE_LEAF_DOMAIN);

        const balanceOk =
            BigInt(IN_VALUE) === BigInt(OUT_VALUE_1) + BigInt(OUT_VALUE_2) + BigInt(FEE) + BigInt(PUBLIC_AMOUNT);

        console.log(`\n[${name}]`);
        console.log("  out_value_1            :", OUT_VALUE_1);
        console.log("  public_amount  (sig 4) :", PUBLIC_AMOUNT);
        console.log("  recipient_principal(6) :", rsig.principal);
        console.log("  recipient_sub_lo   (7) :", rsig.subLo);
        console.log("  recipient_sub_hi   (8) :", rsig.subHi);
        console.log("  output_merkle_leaf_1   :", output_merkle_leaf_1);
        console.log("  output_merkle_leaf_2   :", output_merkle_leaf_2);
        console.log("  balance check          :", balanceOk ? "PASS" : "FAIL — input will not satisfy circuit");
        if (!balanceOk) throw new Error(`${name}: balance check failed — refusing to write ${outPath}`);

        const input = {
            // Public signals [0..8] in circuit order.
            anchor,
            nullifier_hash,
            output_merkle_leaf_1,
            output_merkle_leaf_2,
            public_amount:           PUBLIC_AMOUNT,
            fee:                     FEE,
            recipient_principal:     rsig.principal,      // signal[6]
            recipient_subaccount_lo: rsig.subLo,          // signal[7]
            recipient_subaccount_hi: rsig.subHi,          // signal[8]

            // Private signals
            spend_key:          SPEND_KEY,
            in_value:           IN_VALUE,
            in_rho:             IN_RHO,
            in_rseed:           IN_RSEED,
            path_elements,
            path_indices,
            out_value_1:        OUT_VALUE_1,
            out_recipient_pk_1: out_pk_1,
            out_rho_1:          OUT_RHO_1,
            out_rseed_1:        OUT_RSEED_1,
            out_value_2:        OUT_VALUE_2,
            out_recipient_pk_2: out_pk_2,
            out_rho_2:          OUT_RHO_2,
            out_rseed_2:        OUT_RSEED_2,
        };
        fs.writeFileSync(outPath, JSON.stringify(input, null, 2));
        console.log(`  Written: ${outPath}`);
    }

    // ── Fixture 2 — canonical none-payout (recipient zero, public_amount 0) ───
    buildScenario("none-payout (canonical)", {
        OUT_VALUE_1:   "100000000000",   // self-transfer: all value to output 1
        PUBLIC_AMOUNT: "0",
        recipient:     null,
        outPath:       "tests/test_input.json",
    });

    // ── Fixture 1 — DEF-026 payout-to-A (public_amount > 0, recipient = A) ─────
    // Recipient A: principal bytes [0xA1..0xA5]; subaccount[0]=0x0B (lo=11),
    // subaccount[16]=0x0C (hi=12). The integration test constructs the SAME
    // Principal::from_slice([0xA1..0xA5]) and 32-byte subaccount, so the pool's
    // encode_recipient_signals reproduces
    // (2261564242916331941866620800950935700259179388000792266395655938365985104545, 11, 12)
    // bit-for-bit (DEF-108 length-byte encoding: buf[31] = principal len).
    // public_amount = 60_000 = DEFAULT_FEE(10_000) + 50_000 (mirrors test_100
    // accounting); out_value_1 reduced so the balance equation still holds.
    const RECIPIENT_A_SUBACCOUNT = new Array(32).fill(0);
    RECIPIENT_A_SUBACCOUNT[0]  = 0x0B;   // low 128-bit half  -> 11
    RECIPIENT_A_SUBACCOUNT[16] = 0x0C;   // high 128-bit half -> 12
    buildScenario("payout-to-A (DEF-026)", {
        OUT_VALUE_1:   "99999940000",    // 1e11 - 60_000
        PUBLIC_AMOUNT: "60000",
        recipient:     { principalBytes: [0xA1, 0xA2, 0xA3, 0xA4, 0xA5], subaccount: RECIPIENT_A_SUBACCOUNT },
        outPath:       "tests/test_input_payout_a.json",
    });
}

main().catch(err => { console.error(err); process.exit(1); });
