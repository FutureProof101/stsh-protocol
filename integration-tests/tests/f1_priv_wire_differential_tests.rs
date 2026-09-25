// =============================================================================
// STSH — lane F1-PRIV (R1-F1 CRITICAL) exit evidence: the hidden values are not
// on the private_spend wire, in either direction
// =============================================================================
//
// R1 measured the REQUEST side of `private_spend` and found the hidden note
// values in cleartext (`input_amounts` / `output_amounts`). This lane deletes
// them. The property is only closed if it is EXECUTED, in both legs:
//
//   §1 REQUEST leg   — two spends differing ONLY in hidden value encode to
//                      byte-identical candid, outside the ciphertext and
//                      commitment fields (which are hashed/encrypted and were
//                      verified uniform by R1.6).
//   §1b ANTI-VACUITY — the same differential run against the PRE-CHANGE argument
//                      shape (the mirror below, which still carries the two
//                      fields) must FAIL. Without this, §1 is a tautology.
//   §2 RESPONSE leg  — the R1-owed leg R1 could not execute: a live PocketIC
//                      `private_spend` reply must not reintroduce a
//                      value-dependent shape.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   ./run_gate.sh   (builds the seven test Wasms and sets POCKET_IC_BIN)
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

fn pool_test_wasm() -> Vec<u8> {
    let path = env!("POOL_TEST_WASM");
    std::fs::read(path)
        .unwrap_or_else(|e| panic!("Cannot read shielded_pool_test Wasm at {}: {}", path, e))
}

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

#[derive(CandidType, Deserialize)]
struct PoolInitArgs {
    token_canister: Principal,
    nullifier_canister: Principal,
    merkle_canister: Principal,
    treasury_canister: Principal,
    staking_canister: Principal,
    controller: Principal,
    initial_vk_hash: [u8; 32],
    initial_proof_system: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ProofEnvelope {
    circuit_version: u32,
    proof_system_id: String,
    verifying_key_hash: [u8; 32],
    root_reference: [u8; 32],
    pool_version: u32,
    proof_bytes: Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PublicPayout {
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
    public_amount: u128,
}

/// The SHIPPED argument shape after this lane — no cleartext value anywhere.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct SpendArgs {
    spend_id: u64,
    envelope: ProofEnvelope,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs: Vec<Vec<u8>>,
    fee: u128,
    public_payout: Option<PublicPayout>,
}

/// The PRE-CHANGE argument shape, kept ONLY as the anti-vacuity control for
/// §1b. It is not sent to any canister.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct LegacySpendArgs {
    spend_id: u64,
    envelope: ProofEnvelope,
    input_amounts: Vec<u128>,
    output_amounts: Vec<u128>,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs: Vec<Vec<u8>>,
    fee: u128,
    public_payout: Option<PublicPayout>,
}

const FEE: u128 = 0;

fn envelope() -> ProofEnvelope {
    ProofEnvelope {
        circuit_version: 0,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: [0u8; 32],
        root_reference: [0u8; 32],
        pool_version: 1,
        proof_bytes: vec![],
    }
}

/// A spend of `hidden_value`, in the shipped shape. The hidden value reaches
/// only the ciphertext and the commitments — never a scalar field — which is
/// exactly the property under test. Commitments and ciphertexts are stand-ins of
/// FIXED LENGTH here, as the wallet's are (R1.6: fixed 121-byte v2 plaintext →
/// constant-length IBE ciphertext), so a length difference cannot leak either.
fn shipped(hidden_value: u128) -> SpendArgs {
    let mut leaf = [0u8; 32];
    leaf[31] = 0x00;
    leaf[8..24].copy_from_slice(&hidden_value.to_le_bytes());
    let mut ct = vec![0u8; 121];
    ct[..16].copy_from_slice(&hidden_value.to_le_bytes());
    SpendArgs {
        spend_id: 900_001,
        envelope: envelope(),
        // Canonical BN254 Fr: leading byte 0x00 keeps the value below the modulus so
        // the reply is a real validation outcome, not a canonicality rejection.
        nullifiers: vec![{
            let mut nf = [0xAAu8; 32];
            nf[31] = 0x00;
            nf
        }],
        output_commitments: vec![leaf, {
            let mut oc = [0xBBu8; 32];
            oc[31] = 0x00;
            oc
        }],
        encrypted_outputs: vec![ct, vec![0u8; 121]],
        fee: FEE,
        public_payout: None,
    }
}

fn legacy(hidden_value: u128) -> LegacySpendArgs {
    let s = shipped(hidden_value);
    LegacySpendArgs {
        spend_id: s.spend_id,
        envelope: s.envelope,
        input_amounts: vec![hidden_value],
        output_amounts: vec![hidden_value, 0],
        nullifiers: s.nullifiers,
        output_commitments: s.output_commitments,
        encrypted_outputs: s.encrypted_outputs,
        fee: s.fee,
        public_payout: s.public_payout,
    }
}

/// Blank the hashed/encrypted fields — the channels R1.6 verified uniform — so
/// what remains is every OTHER byte of the encoded argument.
fn outside_ciphertext_and_commitments(args: &SpendArgs) -> Vec<u8> {
    let mut a = args.clone();
    a.output_commitments = vec![[0u8; 32], [0u8; 32]];
    a.encrypted_outputs = vec![vec![0u8; 121], vec![0u8; 121]];
    candid::encode_one(&a).expect("encode")
}

fn legacy_outside_ciphertext_and_commitments(args: &LegacySpendArgs) -> Vec<u8> {
    let mut a = args.clone();
    a.output_commitments = vec![[0u8; 32], [0u8; 32]];
    a.encrypted_outputs = vec![vec![0u8; 121], vec![0u8; 121]];
    candid::encode_one(&a).expect("encode")
}

// ── §1 + §1b — the request-leg differential and its anti-vacuity control ──────

#[test]
fn f1_priv_wire_differential_two_spends_differ_only_in_ciphertext() {
    // 1 STSH vs 1000 STSH — three orders of magnitude apart.
    let a = shipped(100_000_000);
    let b = shipped(100_000_000_000);

    let ea = outside_ciphertext_and_commitments(&a);
    let eb = outside_ciphertext_and_commitments(&b);
    assert_eq!(
        ea, eb,
        "SHIPPED shape: two spends differing only in hidden value must be \
         byte-identical outside the ciphertext/commitment fields"
    );

    // The full encodings differ ONLY inside those fields (they must differ —
    // otherwise the fixture is not actually carrying a different value).
    let fa = candid::encode_one(&a).expect("encode");
    let fb = candid::encode_one(&b).expect("encode");
    assert_ne!(
        fa, fb,
        "anti-vacuity: the two fixtures must differ somewhere, or this proves nothing"
    );
    assert_eq!(fa.len(), fb.len(), "and they must not differ in LENGTH");

    // §1b ANTI-VACUITY — the SAME differential against the PRE-CHANGE shape
    // FAILS. This is the executed proof that the assertion above has teeth: it
    // is the identical comparison, on the identical values, and the only
    // difference is the two deleted fields.
    let la = legacy_outside_ciphertext_and_commitments(&legacy(100_000_000));
    let lb = legacy_outside_ciphertext_and_commitments(&legacy(100_000_000_000));
    assert_ne!(
        la, lb,
        "PRE-CHANGE shape must FAIL this differential — if it passes, the \
         differential is not measuring what it claims (R1-F1 was a real finding)"
    );
}

// ── §6 F1b — the residual candid message-length channel, MEASURED ────────────

#[test]
fn f1b_residual_message_length_channel_measured() {
    // Same spend shape, values three orders of magnitude apart.
    let small = candid::encode_one(&shipped(100_000_000)).expect("encode").len();
    let large = candid::encode_one(&shipped(100_000_000_000)).expect("encode").len();
    assert_eq!(
        small, large,
        "message length must not vary with the hidden value (F1b: the residue is \
         SHAPE, not value)"
    );

    // What DOES still vary: the number of outputs — i.e. spend shape. Measured,
    // not asserted away: this is the B-1 disclosure row this lane owes.
    let mut three_out = shipped(100_000_000);
    three_out.output_commitments.push([0xCCu8; 32]);
    three_out.encrypted_outputs.push(vec![0u8; 121]);
    let bigger = candid::encode_one(&three_out).expect("encode").len();
    assert!(
        bigger > small,
        "the residual channel is vector length = spend shape: {} vs {}",
        bigger,
        small
    );
    println!(
        "F1B_MEASURED shipped_1_in_2_out_bytes={} shipped_1_in_2_out_large_value_bytes={} \
         one_extra_output_bytes={} delta_per_output_bytes={}",
        small,
        large,
        bigger,
        bigger - small
    );
    // For the record, and for the B-1 row: the pre-change shape at the same
    // spend, whose length ALSO moved with the value's LEB128 encoding.
    let l_small = candid::encode_one(&legacy(100_000_000)).expect("encode").len();
    let l_large = candid::encode_one(&legacy(100_000_000_000)).expect("encode").len();
    println!(
        "F1B_MEASURED legacy_small_value_bytes={} legacy_large_value_bytes={} \
         legacy_value_dependent_delta_bytes={}",
        l_small,
        l_large,
        l_large as i64 - l_small as i64
    );
}

// ── §2 — the RESPONSE leg (the leg R1 could not execute) ─────────────────────

#[test]
fn f1_priv_response_leg_is_value_independent() {
    let pic = PocketIc::new();
    let pool = create_canister(&pic);
    pic.install_canister(
        pool,
        pool_test_wasm(),
        candid::encode_one(&PoolInitArgs {
            token_canister: p(0x10),
            nullifier_canister: p(0x11),
            merkle_canister: p(0x12),
            treasury_canister: p(0x01),
            staking_canister: p(0x02),
            controller: p(0xC0),
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        })
        .expect("encode init"),
        None,
    );

    // Two spends that, before this lane, would have DECLARED different hidden
    // values. The pool now receives no declared value at all, so the request
    // bytes are identical — and the replies must be too.
    let caller = p(0x77);
    let reply_a = pic
        .update_call(
            pool,
            caller,
            "private_spend",
            candid::encode_one(&shipped(100_000_000)).expect("encode"),
        )
        .expect("call not rejected");
    let reply_b = pic
        .update_call(
            pool,
            caller,
            "private_spend",
            candid::encode_one(&shipped(100_000_000_000)).expect("encode"),
        )
        .expect("call not rejected");

    assert_eq!(
        reply_a.len(),
        reply_b.len(),
        "RESPONSE leg: reply length must not depend on the hidden value"
    );
    assert_eq!(
        reply_a, reply_b,
        "RESPONSE leg: the reply must not reintroduce a value-dependent shape"
    );

    // Anti-vacuity: the reply is a real, decodable pool reply — not an empty
    // buffer, which would make the equality above meaningless. Decoded as an
    // untyped IDL value so this test cannot drift with the PoolError variant
    // set (a typed mirror would fail closed on any unrelated variant addition).
    assert!(!reply_a.is_empty(), "reply must not be empty");
    let decoded: candid::types::value::IDLValue =
        candid::decode_one(&reply_a).expect("reply decodes as a candid value");
    let rendered = format!("{decoded:?}");
    assert!(
        !rendered.contains("SumMismatch"),
        "SumMismatch is RETIRED by this lane and must never be returned; got {rendered}"
    );
    // And the reply must not carry either deleted field name back to the caller.
    assert!(
        !rendered.contains("input_amounts") && !rendered.contains("output_amounts"),
        "the response must not name the deleted cleartext fields; got {rendered}"
    );
    println!("F1_RESPONSE_LEG reply_bytes={} decoded={rendered}", reply_a.len());
}
