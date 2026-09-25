pragma circom 2.1.9;

// =============================================================================
// STSH Spend Circuit
// Version: 0.3.0-a0  (M4-ZK-A0: soundness + domain separation)
// =============================================================================
//
// Covers both private_spend and withdraw operations:
//   - private_spend: public_amount = 0, fee paid from note value
//   - withdraw:      public_amount > 0, recipient in ProofEnvelope (canister-layer)
//
// Single-input → two-output (1-in-2-out). Multi-input is a M5 extension.
//
// Proof system:  Groth16 on BN254
// Hash function: circomlib Poseidon (BN254 Fr, see POSEIDON_PARAMS.md)
// Tree depth:    32  (supports 2^32 ≈ 4 billion notes)
//
// =============================================================================
// SOUNDNESS STATUS (M4-ZK-A0)
// =============================================================================
//
//   ✓ Merkle membership enforced
//   ✓ Spend key ownership proven: derived_pk = Poseidon(spend_key, PK_DOMAIN)
//   ✓ Commitment chain: derived_pk wired directly into input note commitment
//   ✓ Nullifier correctly formed: Poseidon(domain_sep, spend_key, in_commitment, NULLIFIER_DOMAIN)  [DEF-109-A full-note binding]
//   ✓ Output commitments correctly formed (same COMMITMENT_DOMAIN)
//   ✓ Domain separation: PK_DOMAIN / NULLIFIER_DOMAIN / COMMITMENT_DOMAIN
//   ✓ Range checks: all value signals ∈ [0, MAX_NOTE_VALUE]
//   ✓ Value balance: in_value == sum(outputs) + fee + public_amount
//
//   ✗ No asset_id / canister_id / circuit_version in circuit signals
//     → Enforced by ProofEnvelope at canister layer (see PUBLIC_SIGNALS_SCHEMA.md)
//   ✗ No BabyJubjub EdDSA spend keys (M5 upgrade path)
//   ✗ Single-input only (M5 multi-input extension)
//
// =============================================================================
// TRUSTED SETUP STATUS
// =============================================================================
//
//   DEV CHAIN ONLY — the dev chain was regenerated 2026-09-12 (A-3 FINALIZE) over
//   THIS circuit (DOMAIN_POOL_CANISTER_ID re-encoded to the Vault-born pool
//   cxrfg-qaaaa-aaaar-qchfa-cai); the zkey carries a
//   single contribution named `dev contribution`. The mainnet-v2 ceremony has NOT
//   run. The dev verification key is committed at circuits/verification_key.json
//   (sha256 = PINNED_VK_HASH = 84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914)
//   and compiled into the verifier canister. THE CIRCUIT IS CEREMONY-FROZEN once
//   the launch ceremony runs: any change to this file after that invalidates the
//   VK and requires a new ceremony. The launch VK comes from the A6.7/2-8
//   re-ceremony, which pool launch is gated on.
//
//   Proof verification in production is the real Groth16 verifier canister
//   (async inter-canister call from shielded_pool); the historical
//   verify_proof_stub() is gone from production paths. Invalid proofs are
//   rejected (ProofRejected).
//
// =============================================================================
// CONSTRAINT CHAIN (per input note)
// =============================================================================
//
//   (private)  spend_key
//       │
//       ▼  Poseidon(spend_key, PK_DOMAIN)  [Poseidon(2), t=3]
//   derived_pk
//       │   (private)  value, rho, rseed
//       ▼  Poseidon(domain_sep, value, derived_pk, rho, rseed, COMMITMENT_DOMAIN)  [Poseidon(6), t=7]
//   note_commitment ───────────────────────────────────────┐
//       │                                                   │
//       ▼  Merkle path proof                                ▼  Poseidon(domain_sep, spend_key, note_commitment, NULLIFIER_DOMAIN)  [Poseidon(4), t=5]
//   anchor (public)                              derived_nullifier ── public nullifier_hash   [DEF-109-A: binds whole note]
//
// =============================================================================

include "./node_modules/circomlib/circuits/poseidon.circom";
include "./node_modules/circomlib/circuits/bitify.circom";
include "./node_modules/circomlib/circuits/comparators.circom";
include "./node_modules/circomlib/circuits/switcher.circom";

// =============================================================================
// Domain separation constants  (protocol version v1)
// =============================================================================
//
// These fixed values are embedded in the R1CS. Any change requires a new
// circuit compilation and trusted setup ceremony.
//
// Rationale for distinct values: prevents cross-domain Poseidon collisions
// (e.g., a nullifier hash cannot accidentally equal a note commitment).
//
// M5 note: If asset_id, pool_canister_id, or circuit_version are promoted
// to in-circuit signals, update these constants accordingly and increment the
// protocol version string.
//
// IMPORTANT: The wallet software MUST use the same domain constants when
// computing note commitments and deriving recipient_pk for deposit.
//   PK_DOMAIN:         inputs[1] of Poseidon(2) for spend_key → pk derivation
//   NULLIFIER_DOMAIN:  last input of Poseidon(4) for nullifier derivation (DEF-035 + DEF-109-A)
//   COMMITMENT_DOMAIN: last input of Poseidon(6) for note commitment (DEF-035)

// =============================================================================
// Note value bounds
// =============================================================================
//
// MAX_NOTE_VALUE = 10^15 base STSH units = 10,000,000 STSH (maximum fixed denomination)
// All value signals must be in [0, MAX_NOTE_VALUE].
//
// Zero is permitted for change/dummy output notes (explicitly allowed).
// Non-zero values below the minimum denomination (10^8 = 1 STSH) are NOT
// rejected at circuit level — dust enforcement is a wallet / canister concern.
// Zero note policy: an output note with value=0 is a valid empty note.

// =============================================================================
// MerkleProof
// Verifies a leaf exists in an incremental Merkle tree using Poseidon(2) [t=3].
// Input ordering: left child (inputs[0]) before right child (inputs[1]).
// This matches the Rust merkle-tree canister (poseidon_hash_pair(left, right)).
// =============================================================================
template MerkleProof(depth) {
    signal input leaf;
    signal input path_elements[depth];  // sibling hashes at each level
    signal input path_indices[depth];   // 0 = current node is left, 1 = right

    signal output root;

    component hashers[depth];
    component switchers[depth];

    signal levels[depth + 1];
    levels[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        hashers[i]   = Poseidon(2);
        switchers[i] = Switcher();

        // DEF-094: force the path selector boolean. Without this, Switcher's linear
        // combination + a free sibling lets a non-boolean sel forge any (outL,outR),
        // making Merkle membership vacuous (mint up to MAX_NOTE_VALUE per forged proof).
        path_indices[i] * (1 - path_indices[i]) === 0;

        switchers[i].sel <== path_indices[i];
        switchers[i].L   <== levels[i];
        switchers[i].R   <== path_elements[i];

        hashers[i].inputs[0] <== switchers[i].outL;   // left child
        hashers[i].inputs[1] <== switchers[i].outR;   // right child

        levels[i + 1] <== hashers[i].out;
    }

    root <== levels[depth];
}

// =============================================================================
// NoteCommitment
// commitment = Poseidon(domain_sep, value, recipient_pk, rho, rseed, COMMITMENT_DOMAIN)
//
// Poseidon(6) [t=7]. domain_sep (the DEF-035 cross-deployment domain hash,
// domainHash.out) is the FIRST input; COMMITMENT_DOMAIN = 3 (within-deployment
// purpose tag) is the LAST. Together they prevent cross-deployment replay and
// cross-scheme (pk/nullifier/commitment) collisions.
//
// WALLET REQUIREMENT: the canonical wallet reference for this hash (arity,
// input order, domain constants, Poseidon parameters) is POSEIDON_PARAMS.md —
// do not implement from this comment alone. A wallet omitting domain_sep or
// using a pre-DEF-035 arity (Poseidon(4)/Poseidon(5)) produces incompatible,
// unspendable commitments.
//
// Used for BOTH input notes (proving membership) and output notes (creating).
// =============================================================================
template NoteCommitment() {
    // DEF-035: deployment-binding domain separator (domainHash.out), prepended as
    // the FIRST Poseidon input. Within-deployment separation is still provided by
    // COMMITMENT_DOMAIN; this adds cross-deployment separation.
    signal input domain_sep;
    signal input value;
    signal input recipient_pk;
    signal input rho;
    signal input rseed;

    signal output commitment;

    var COMMITMENT_DOMAIN = 3;

    component hasher = Poseidon(6);
    hasher.inputs[0] <== domain_sep;        // DEF-035 cross-deployment prefix
    hasher.inputs[1] <== value;
    hasher.inputs[2] <== recipient_pk;
    hasher.inputs[3] <== rho;
    hasher.inputs[4] <== rseed;
    hasher.inputs[5] <== COMMITMENT_DOMAIN;

    commitment <== hasher.out;
}

// =============================================================================
// MerkleLeaf  (DEF-111 / B-prime: value-bound outer Merkle leaf)
// leaf = Poseidon(value, inner_note_commitment, MERKLE_LEAF_DOMAIN)  [Poseidon(3), t=4]
//
// The tree leaf binds the note's SPENDABLE value alongside its inner commitment,
// so Merkle membership proves the value too — closing the DEF-111 gap where a note
// could commit a value larger than the escrowed/credited amount. The inner
// commitment already binds domain_sep (DEF-035) + value + pk + rho + rseed, so the
// outer leaf OMITS domain_sep (0b ruling: transitively bound) → Poseidon(3).
// MERKLE_LEAF_DOMAIN = 4 continues the within-deployment purpose-tag sequence
// (PK_DOMAIN=1 / NULLIFIER_DOMAIN=2 / COMMITMENT_DOMAIN=3 / MERKLE_LEAF_DOMAIN=4);
// the purpose tag is the LAST input, matching commitment/nullifier convention.
// LEAF-AGREEMENT CONTRACT: the pool + wallet must compute this identical hash
// (same params, arity, field order, domain tag) — see POSEIDON_PARAMS.md.
// =============================================================================
template MerkleLeaf() {
    signal input value;
    signal input inner_note_commitment;

    signal output leaf;

    var MERKLE_LEAF_DOMAIN = 4;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== value;
    hasher.inputs[1] <== inner_note_commitment;
    hasher.inputs[2] <== MERKLE_LEAF_DOMAIN;

    leaf <== hasher.out;
}

// =============================================================================
// NullifierDerivation  (DEF-109-A: full-note binding)
// nullifier = Poseidon(domain_sep, spend_key, in_commitment, NULLIFIER_DOMAIN)
//
// Poseidon(4) [t=5]. DEF-035 prepends domain_sep as the first input for cross-
// deployment separation; NULLIFIER_DOMAIN is the last input for within-deployment
// purpose separation. DEF-109-A binds the THIRD input to the input note's
// commitment (not the bare rho): in_commitment already binds value, derived_pk,
// rho and rseed, so the nullifier commits to the whole note. Two valid notes
// sharing (spend_key, rho) but differing in value/rseed then produce DISTINCT
// nullifiers, closing the same-(spend_key, rho) collision (DEF-109).
//
// The NULLIFIER_DOMAIN = 2 constant is embedded in the R1CS.
// The on-chain nullifier_registry stores these values.
// =============================================================================
template NullifierDerivation() {
    // DEF-035: deployment-binding domain separator (domainHash.out), prepended as
    // the FIRST Poseidon input. NULLIFIER_DOMAIN still provides within-deployment
    // purpose separation; this adds cross-deployment separation.
    signal input domain_sep;
    signal input spend_key;
    // DEF-109-A: the input note's commitment (binds value, derived_pk, rho, rseed),
    // replacing the bare rho so the nullifier commits to the whole note.
    signal input in_commitment;

    signal output nullifier;

    var NULLIFIER_DOMAIN = 2;

    component hasher = Poseidon(4);
    hasher.inputs[0] <== domain_sep;        // DEF-035 cross-deployment prefix
    hasher.inputs[1] <== spend_key;
    hasher.inputs[2] <== in_commitment;     // DEF-109-A full-note binding
    hasher.inputs[3] <== NULLIFIER_DOMAIN;

    nullifier <== hasher.out;
}

// =============================================================================
// STSHSpend — main template
//
// Constraint chain summary:
//   1. Derive pk from spend_key:        derived_pk = Poseidon(spend_key, PK_DOMAIN)
//   2. Derive input commitment:         in_commit  = Poseidon(domain_sep, value, derived_pk, rho, rseed, COMMITMENT_DOMAIN)
//   3. Derive nullifier (full-note):    nullifier  = Poseidon(domain_sep, spend_key, in_commit, NULLIFIER_DOMAIN)  [DEF-109-A]
//   4. Merkle membership:               in_commit is a leaf in the tree at anchor
//   5. Public signal bindings:          anchor, nullifier_hash, output_commitment_{1,2}, public_amount, fee
//   6. Output commitments:              each output note correctly formed
//   7. Range checks:                    all value signals ∈ [0, MAX_NOTE_VALUE]
//   8. Value balance:                   in_value == out_value_1 + out_value_2 + fee + public_amount
//
// Public signal ordering (0-indexed, matches snarkjs publicSignals array):
//   0: anchor
//   1: nullifier_hash
//   2: output_merkle_leaf_1   (DEF-111 value-bound outer leaf)
//   3: output_merkle_leaf_2   (DEF-111 value-bound outer leaf)
//   4: public_amount
//   5: fee
//
// WARNING: Always confirm signal indices from the .sym file after compilation.
// The ordering below is set by the `component main { public [...] }` declaration.
// =============================================================================
template STSHSpend(tree_depth) {

    // ── Public inputs (revealed to verifier) ──────────────────────────────
    signal input anchor;                // Merkle root the proof anchors to
    signal input nullifier_hash;        // Poseidon(domain_sep, spend_key, in_commitment, NULLIFIER_DOMAIN) [DEF-109-A]
    signal input output_merkle_leaf_1;   // Output note 1 value-bound Merkle leaf (DEF-111)
    signal input output_merkle_leaf_2;   // Output note 2 value-bound Merkle leaf (DEF-111)
    signal input public_amount;         // Net public value leaving shielded pool (0 = private)
    signal input fee;                   // Protocol fee in base STSH units

    // ── DEF-026: recipient/subaccount proof binding ───────────────────────
    // Public inputs that bind the proof to a specific public-payout recipient.
    // Bound by BOTH (a) Groth16 public-input membership — substituting any of these
    // in the public-signal vector changes vk_x and fails the pairing — AND (b) an
    // explicit in-circuit constraint added by DEF-112 (see "Constraint 5c" below),
    // so the binding no longer rests only on the implicit membership property
    // (defense-in-depth). No-payout encoding: all three are Fr::zero(). See PUBLIC_SIGNALS_*.md.
    signal input recipient_principal;        // principal bytes, LE zero-padded to 32 -> Fr
    signal input recipient_subaccount_lo;    // subaccount[0..16]  (low 128 bits)  LE -> Fr
    signal input recipient_subaccount_hi;    // subaccount[16..32] (high 128 bits) LE -> Fr

    // ── Private inputs (known only to prover) ─────────────────────────────

    // Spend key — the sole secret that proves note ownership.
    // All ownership-related values (recipient_pk, nullifier) are DERIVED
    // from spend_key inside the circuit. The prover does NOT supply
    // recipient_pk directly — it is computed and wired internally.
    signal input spend_key;

    // Input note blinding and derivation randomness
    signal input in_value;              // Denomination of the input note
    signal input in_rho;                // PRF input: nullifier derivation + commitment blinding
    signal input in_rseed;              // Additional blinding: commitment hiding

    // Merkle proof path for the input note
    signal input path_elements[tree_depth];
    signal input path_indices[tree_depth];

    // Output note 1 (change note or payment to self)
    signal input out_value_1;
    signal input out_recipient_pk_1;    // Any valid recipient (their Poseidon(spend_key, PK_DOMAIN))
    signal input out_rho_1;
    signal input out_rseed_1;

    // Output note 2 (empty note, change, or payment — out_value_2 may be 0)
    signal input out_value_2;
    signal input out_recipient_pk_2;
    signal input out_rho_2;
    signal input out_rseed_2;

    // ── Internal value bounds ──────────────────────────────────────────────
    // 10,000,000 STSH = 10^15 base units (maximum fixed denomination — the top
    // rung of the five-tier launch ladder 1k / 10k / 100k / 1M / 10M STSH,
    // OWNER_RULING_LAUNCH_LADDER 2026-09-08, lane A6.6).
    // All value signals must be in [0, MAX_NOTE_VALUE].
    var MAX_NOTE_VALUE = 1000000000000000;   // 10^15

    // ── Constraint 0 (DEF-035): deployment-binding domain separator ───────
    // Binds every nullifier and output commitment to THIS deployment so a proof
    // generated for one STSH deployment cannot be replayed on another sharing the
    // same VK (cross-deployment double-spend, QA-DEF-035). These are circuit-
    // compile-time constants (NOT public signals) baked into the R1CS.
    //   DOMAIN_POOL_CANISTER_ID : deployed shielded-pool principal as a BN254 field
    //                             element, encoded byte-identically to DEF-108
    //                             `encode_recipient_signals` (the single normative
    //                             principal→Fr rule — no second encoding). Value below
    //                             is the Vault-born mainnet pool principal
    //                             (cxrfg-qaaaa-aaaar-qchfa-cai), re-encoded at A-3
    //                             FINALIZE (2026-09-12) for generation mainnet-v2.
    //                             The A1 value (ohspu-zqaaa-aaaad-qmasq-cai) is
    //                             HISTORICAL: that principal is orphaned/HOSTILE per
    //                             deployment/mainnet/custody_manifest.toml and the
    //                             re-encode is the A-3 domain-severance control. The
    //                             staging sentinel `2` is older still (pre-A1 dev
    //                             circuit only).
    //   DOMAIN_ASSET_ID         : 0 = STSH native token (final).
    //   DOMAIN_CIRCUIT_VERSION  : monotonic per circuit/ceremony change; bumped once to
    //                             2 for the whole circuit-finalization revision
    //                             (DEF-082 + DEF-112 + DEF-111/B-prime).
    //   DOMAIN_NETWORK_ID       : 1 = ICP mainnet (final).
    // Within-deployment purpose separation already exists (PK_DOMAIN/NULLIFIER_DOMAIN/
    // COMMITMENT_DOMAIN); this adds the cross-deployment layer.
    var DOMAIN_POOL_CANISTER_ID = 4523128485832663883733241601901871400518358776001584537546685574107874983936;  // cxrfg-qaaaa-aaaar-qchfa-cai (Vault-born mainnet shielded_pool, J-18 2026-09-12)
    var DOMAIN_ASSET_ID         = 0;   // STSH native token (final)
    var DOMAIN_CIRCUIT_VERSION  = 3;   // circuit-finalization revision (single bump for all 3 stages; 2->3 at A6.6, MAX_NOTE_VALUE 10^11 -> 10^15)
    var DOMAIN_NETWORK_ID       = 1;   // ICP mainnet (final)

    component domainHash = Poseidon(4);
    domainHash.inputs[0] <== DOMAIN_POOL_CANISTER_ID;
    domainHash.inputs[1] <== DOMAIN_ASSET_ID;
    domainHash.inputs[2] <== DOMAIN_CIRCUIT_VERSION;
    domainHash.inputs[3] <== DOMAIN_NETWORK_ID;
    // domainHash.out is the first input to every nullifier and commitment hash below.

    // ── Constraint 1: Spend key → recipient_pk derivation ─────────────────
    // derived_pk = Poseidon(spend_key, PK_DOMAIN)
    //
    // PK_DOMAIN = 1 ensures this Poseidon(2) output cannot collide with
    // nullifier outputs (NULLIFIER_DOMAIN=2) or commitments (COMMITMENT_DOMAIN=3).
    //
    // derived_pk is wired directly into the input note commitment (constraint 3).
    // The prover does NOT supply recipient_pk as a separate private input —
    // any such signal would create a gap in the ownership chain.
    var PK_DOMAIN = 1;
    component pk_deriver = Poseidon(2);
    pk_deriver.inputs[0] <== spend_key;
    pk_deriver.inputs[1] <== PK_DOMAIN;

    // ── Constraint 2: Input note commitment ───────────────────────────────
    // derived_commitment = Poseidon(domain_sep, in_value, derived_pk, in_rho, in_rseed, COMMITMENT_DOMAIN)
    //
    // pk_deriver.out is wired directly here — no intermediate equality.
    // This closes the ownership gap: the Merkle leaf is definitionally
    // Poseidon(domain_sep, value, Poseidon(spend_key, PK_DOMAIN), rho, rseed, COMMITMENT_DOMAIN).
    // Declared BEFORE the nullifier (DEF-109-A) so its commitment can bind the nullifier.
    component in_commit = NoteCommitment();
    in_commit.domain_sep   <== domainHash.out;   // DEF-035
    in_commit.value        <== in_value;
    in_commit.recipient_pk <== pk_deriver.out;   // DIRECT WIRE — no gap
    in_commit.rho          <== in_rho;
    in_commit.rseed        <== in_rseed;

    // ── Constraint 3: Nullifier derivation (DEF-109-A full-note binding) ───
    // derived_nullifier = Poseidon(domain_sep, spend_key, in_commit.commitment, NULLIFIER_DOMAIN)
    // in_commit.commitment already binds in_value, derived_pk, in_rho and in_rseed,
    // so the nullifier commits to the WHOLE note: two valid notes sharing
    // (spend_key, rho) but differing in value/rseed yield DISTINCT nullifiers.
    // Must match public nullifier_hash signal.
    component nf = NullifierDerivation();
    nf.domain_sep    <== domainHash.out;         // DEF-035
    nf.spend_key     <== spend_key;
    nf.in_commitment <== in_commit.commitment;   // DEF-109-A full-note binding
    nullifier_hash === nf.nullifier;

    // ── Constraint 4: Merkle membership (DEF-111 value-bound leaf) ─────────
    // The tree leaf is MerkleLeaf(in_value, in_commit.commitment) — membership now
    // proves the note's spendable value too, not just the inner commitment. The
    // nullifier (Constraint 3) still binds the inner commitment, unchanged.
    component in_leaf = MerkleLeaf();
    in_leaf.value                 <== in_value;
    in_leaf.inner_note_commitment <== in_commit.commitment;
    component merkle = MerkleProof(tree_depth);
    merkle.leaf <== in_leaf.leaf;
    for (var i = 0; i < tree_depth; i++) {
        merkle.path_elements[i] <== path_elements[i];
        merkle.path_indices[i]  <== path_indices[i];
    }
    anchor === merkle.root;

    // ── Constraint 5: Output note commitments ─────────────────────────────
    // Output recipient_pks are provided by the prover (the sender chooses
    // who receives each output note). They must be valid Poseidon(spend_key, PK_DOMAIN)
    // values for the intended recipients, but the circuit does NOT verify this —
    // the recipient's spend_key is their secret, unknown to the circuit.
    // A note sent to an incorrect recipient_pk is unspendable by anyone.
    component out_commit_1 = NoteCommitment();
    out_commit_1.domain_sep   <== domainHash.out;   // DEF-035
    out_commit_1.value        <== out_value_1;
    out_commit_1.recipient_pk <== out_recipient_pk_1;
    out_commit_1.rho          <== out_rho_1;
    out_commit_1.rseed        <== out_rseed_1;
    // DEF-111: public signal 2 is the value-bound outer leaf, not the inner
    // commitment. out_commit_1.commitment stays a private intermediate.
    component out_leaf_1 = MerkleLeaf();
    out_leaf_1.value                 <== out_value_1;
    out_leaf_1.inner_note_commitment <== out_commit_1.commitment;
    output_merkle_leaf_1 === out_leaf_1.leaf;

    component out_commit_2 = NoteCommitment();
    out_commit_2.domain_sep   <== domainHash.out;   // DEF-035
    out_commit_2.value        <== out_value_2;
    out_commit_2.recipient_pk <== out_recipient_pk_2;
    out_commit_2.rho          <== out_rho_2;
    out_commit_2.rseed        <== out_rseed_2;
    // DEF-111: public signal 3 is the value-bound outer leaf, not the inner
    // commitment. out_commit_2.commitment stays a private intermediate.
    component out_leaf_2 = MerkleLeaf();
    out_leaf_2.value                 <== out_value_2;
    out_leaf_2.inner_note_commitment <== out_commit_2.commitment;
    output_merkle_leaf_2 === out_leaf_2.leaf;

    // ── Constraint 5c (DEF-112): explicit recipient public-signal binding ──
    // The recipient signals are ALSO bound by Groth16 public-input membership;
    // this adds an explicit, non-vacuous in-circuit constraint so the binding no
    // longer rests only on that implicit toolchain property (defense-in-depth,
    // ZK-1/ZK-6). Each squaring forces its signal into the R1CS (verified: +3
    // non-linear constraints at --O2, not pruned). The signals stay FREE public
    // inputs — the all-zero no-payout encoding is preserved; they are NOT
    // constrained to any value, and rp/rsl/rsh_bind feed nothing else.
    signal rp_bind;  rp_bind  <== recipient_principal      * recipient_principal;
    signal rsl_bind; rsl_bind <== recipient_subaccount_lo  * recipient_subaccount_lo;
    signal rsh_bind; rsh_bind <== recipient_subaccount_hi  * recipient_subaccount_hi;

    // ── Constraint 6: Value range checks ──────────────────────────────────
    // All value signals must be in [0, MAX_NOTE_VALUE].
    //
    // DEF-106: two-sided range. LessThan(50) internally applies Num2Bits(51) to the
    // DIFFERENCE (v + 2^50 - (MAX+1)) only — it never decomposes v itself, so it
    // admits a negative-band alias: any v = p - k (1 <= k <= 2^50-(MAX+1)) also
    // passes, letting an output note encode a field-negative value and mint. The
    // Num2Bits(50) block below decomposes each RAW value, proving v ∈ [0, 2^50);
    // LessThan(50) then trims that to [0, MAX_NOTE_VALUE]. Together:
    //   a) Num2Bits(50) rejects the negative band (any p - k is >> 2^50)
    //   b) LessThan(50) enforces the business-logic upper bound (MAX_NOTE_VALUE)
    //   c) Zero is allowed (0 ∈ [0, 2^50) and 0 < MAX_NOTE_VALUE + 1)
    //
    // LessThan(50): supports values < 2^50 = 1,125,899,906,842,624 > MAX_NOTE_VALUE+1.
    // The comparison target (MAX_NOTE_VALUE + 1) must be < 2^50 ✓.
    //
    // Zero note policy:
    //   out_value = 0 is ALLOWED (empty change/dummy note). Zero notes are
    //   spendable but contribute no value. They should not be disclosed as
    //   "real" outputs to the recipient. Dust policy is wallet-enforced.
    //
    // Note: public_amount and fee are public signals (verifier-supplied).
    // Their range is also checked here to ensure the value balance constraint
    // is meaningful (no Fr arithmetic surprises from adversarial public inputs).

    // DEF-106: prove each RAW value is a 50-bit non-negative integer BEFORE the
    // difference-only LessThan check, closing the negative-band aliasing. 2^50 >
    // MAX_NOTE_VALUE, so Num2Bits(50) alone is not a tight upper bound — the
    // LessThan(50) checks below still trim [0, 2^50) down to [0, MAX_NOTE_VALUE].
    component in_value_bits    = Num2Bits(50);  in_value_bits.in    <== in_value;
    component out_value_1_bits = Num2Bits(50);  out_value_1_bits.in <== out_value_1;
    component out_value_2_bits = Num2Bits(50);  out_value_2_bits.in <== out_value_2;
    component fee_bits         = Num2Bits(50);  fee_bits.in         <== fee;
    component pub_amount_bits  = Num2Bits(50);  pub_amount_bits.in  <== public_amount;

    component in_value_range    = LessThan(50);
    component out_value_1_range = LessThan(50);
    component out_value_2_range = LessThan(50);
    component fee_range         = LessThan(50);
    component pub_amount_range  = LessThan(50);

    in_value_range.in[0]    <== in_value;       in_value_range.in[1]    <== MAX_NOTE_VALUE + 1;
    out_value_1_range.in[0] <== out_value_1;    out_value_1_range.in[1] <== MAX_NOTE_VALUE + 1;
    out_value_2_range.in[0] <== out_value_2;    out_value_2_range.in[1] <== MAX_NOTE_VALUE + 1;
    fee_range.in[0]         <== fee;             fee_range.in[1]         <== MAX_NOTE_VALUE + 1;
    pub_amount_range.in[0]  <== public_amount;   pub_amount_range.in[1]  <== MAX_NOTE_VALUE + 1;

    in_value_range.out    === 1;
    out_value_1_range.out === 1;
    out_value_2_range.out === 1;
    fee_range.out         === 1;
    pub_amount_range.out  === 1;

    // ── Constraint 7: Value balance ───────────────────────────────────────
    // Enforced AFTER range checks (range checks prevent Fr modular tricks).
    // in_value == out_value_1 + out_value_2 + fee + public_amount
    //
    // This is a linear constraint in Fr. After range-checking all signals to
    // [0, MAX_NOTE_VALUE], the sum fits comfortably within Fr (no overflow:
    // 4 × MAX_NOTE_VALUE = 4 × 10^15 << 2^52 << Fr modulus).
    in_value === out_value_1 + out_value_2 + fee + public_amount;
}

// =============================================================================
// Instantiate at depth 32 (supports 2^32 ≈ 4 billion notes)
//
// Public signal indices (0-based, snarkjs publicSignals array order):
//   0: anchor
//   1: nullifier_hash
//   2: output_merkle_leaf_1      (DEF-111 value-bound outer leaf)
//   3: output_merkle_leaf_2      (DEF-111 value-bound outer leaf)
//   4: public_amount
//   5: fee
//   6: recipient_principal       (DEF-026)
//   7: recipient_subaccount_lo   (DEF-026)
//   8: recipient_subaccount_hi   (DEF-026)
//
// WARNING: Verify indices against the compiled .sym file.
// Do NOT hardcode indices in canister or wallet code without .sym confirmation.
// =============================================================================
component main {
    public [
        anchor,
        nullifier_hash,
        output_merkle_leaf_1,
        output_merkle_leaf_2,
        public_amount,
        fee,
        recipient_principal,
        recipient_subaccount_lo,
        recipient_subaccount_hi
    ]
} = STSHSpend(32);
