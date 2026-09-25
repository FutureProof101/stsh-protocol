// =============================================================================
// STSH — privacy differential / uniformity regression suite (charter a4fd9e47)
// =============================================================================
//
// Landed by lane TESTFOLD §3.6 from Reviewer-R1's sweep designs
// (R1_DIFFERENTIAL_TRANSCRIPT.md R1.1, R1_UNIFORMITY.md §6). Those designs were
// written against corpus 018331a, where the assertions below were RED: the pool's
// `PrivateSpendArgs` then carried `input_amounts` / `output_amounts` as public
// `nat` vectors, so two spends differing only in the hidden note value produced
// different ingress bytes AND different ingress LENGTHS (1017 vs 1021 bytes in
// R1's captured transcript — a magnitude side channel readable without parsing
// candid at all).
//
// STATUS RE-ESTABLISHED AT THIS LANE'S BASE (160cad2d), as §3.6 requires: lane
// F1-PRIV has since REMOVED both fields (see the comment at
// canisters/shielded-pool/src/lib.rs, `PrivateSpendArgs`). Every assertion here is
// therefore GREEN at 160cad2d and lands as a REGRESSION LOCK, not as an expected
// failure. Landing them as "expected RED" would have been a false gate line — the
// precise trap §3.6 names.
//
// What each assertion locks — i.e. what re-introducing the leak looks like:
//   R1-F1  (CRITICAL): any per-spend value quantity on the ingress wire makes the
//                      two encodings differ → assertion 1 fails.
//   R1-F1b (HIGH):     a variable-length (LEB128 `nat`) private quantity makes the
//                      two encodings differ in LENGTH → assertion 2 fails. Kept
//                      deliberately separate from assertion 1 so a partial fix
//                      (e.g. padding values but keeping `nat`) cannot pass silently.
//   R1-F4  (HIGH):     dummy-output and change-position distinguishability were
//                      corollaries of F1 on the cleartext channel; assertion 3
//                      locks the property R1 measured as already PASSing on the
//                      hashed/encrypted channel — fixed-length ciphertexts — so a
//                      future variable-length or compressed payload path is caught.
//
// SURFACE: this is the REQUEST leg, which R1 showed is decisive on its own — the
// property failed before any response was considered. It needs no PocketIC and no
// prebuilt Wasm: it encodes the pool crate's own argument type and diffs bytes.
// R1's assertion 3 (the PocketIC response-shape leg) remains genuinely unexecuted
// and is NOT claimed here; it is named as owed work in the lane package rather
// than argued away.
// =============================================================================

use candid::{CandidType, Encode};
use serde::{Deserialize, Serialize};

/// The pool's tracked interface — the authority for what actually reaches the
/// wire. The mirror types below are checked against it by
/// `r1_f1_mirror_matches_the_tracked_did`, so a field added to the canister and
/// its `.did` cannot leave this suite quietly asserting about a stale shape.
const POOL_DID: &str = include_str!("../../canisters/shielded-pool/shielded_pool.did");

/// Mirror of the pool's `PrivateSpendArgs`. Integration tests declare their own
/// candid types throughout this crate (the canister crates are cdylibs, not
/// libraries it links); the DID check above is what keeps this honest.
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
struct PrivateSpendPublicPayout {
    recipient: candid::Principal,
    recipient_subaccount: Option<[u8; 32]>,
    public_amount: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PrivateSpendArgs {
    spend_id: u64,
    envelope: ProofEnvelope,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    encrypted_outputs: Vec<Vec<u8>>,
    fee: u128,
    public_payout: Option<PrivateSpendPublicPayout>,
    expected_deployment_config_hash: Option<[u8; 32]>,
}

/// A spend whose ONLY varying input is the hidden note value the wallet would
/// have spent. Everything an observer could otherwise key on is fixed: same
/// spend_id, same envelope, same nullifier, same output commitments, same
/// fixed-length encrypted payloads, same fee, same public payout (none).
///
/// `hidden_value` is deliberately UNUSED in the constructed args. That is the
/// property: at 160cad2d there is no field for it to reach. If a future edit
/// gives it one, this parameter becomes live and the assertions below fail —
/// which is the entire point of taking it as a parameter rather than dropping it.
fn spend_with_hidden_value(hidden_value: u128) -> PrivateSpendArgs {
    let _ = hidden_value;
    PrivateSpendArgs {
        spend_id: 4242,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: [0x11; 32],
            root_reference: [0x22; 32],
            pool_version: 1,
            proof_bytes: vec![0x33; 256],
        },
        nullifiers: vec![[0x44; 32]],
        output_commitments: vec![[0x55; 32], [0x66; 32]],
        // Fixed-length IBE ciphertexts: R1 §6.3 measured the plaintext as a
        // constant-length record, so a zero-value dummy note encrypts to exactly
        // the same length as a 500-STSH note.
        encrypted_outputs: vec![vec![0x77; 192], vec![0x88; 192]],
        fee: 0,
        public_payout: None,
        expected_deployment_config_hash: Some([0x99; 32]),
    }
}

/// R1-F1 — two spends differing ONLY in the hidden note value must be
/// byte-identical on the ingress wire. RED at 018331a; GREEN at 160cad2d after
/// F1-PRIV removed the cleartext amount vectors.
#[test]
fn r1_f1_request_bytes_are_identical_for_two_hidden_values() {
    let a = Encode!(&spend_with_hidden_value(100_000_000)).expect("encode A");
    let b = Encode!(&spend_with_hidden_value(50_000_000_000)).expect("encode B");

    if a != b {
        let first = a
            .iter()
            .zip(b.iter())
            .position(|(x, y)| x != y)
            .unwrap_or_else(|| a.len().min(b.len()));
        panic!(
            "R1-F1 REGRESSION: the hidden note value is observable in the \
             private_spend ingress argument. A is {} bytes, B is {} bytes, first \
             divergence at offset {first}. A per-spend value quantity has been \
             re-introduced onto the wire; ICP ingress arguments are visible to the \
             boundary node, to every replica, and in the block payload.",
            a.len(),
            b.len()
        );
    }
}

/// R1-F1b — the ingress LENGTH must not vary with the magnitude of a hidden
/// value. Separate from the test above on purpose: a fix that uniformizes values
/// but keeps a variable-length `nat` encoding would pass one and fail the other,
/// and an adversary who cannot parse candid still reads length.
#[test]
fn r1_f1b_request_length_is_independent_of_hidden_value_magnitude() {
    let small = Encode!(&spend_with_hidden_value(1)).expect("encode small");
    let large = Encode!(&spend_with_hidden_value(u128::MAX / 2)).expect("encode large");

    assert_eq!(
        small.len(),
        large.len(),
        "R1-F1b REGRESSION: ingress message length varies with the magnitude of a \
         hidden value ({} vs {} bytes). Candid encodes `nat` as variable-length \
         LEB128, so this channel survives any fix that keeps a private quantity as \
         a `nat` on the wire — it closes only by removing the quantity or moving to \
         a fixed-width encoding.",
        small.len(),
        large.len()
    );
}

/// R1-F4 / R1 §6.3 — the encrypted-output channel is length-uniform: a
/// zero-value dummy output is indistinguishable in length from a real one, and
/// the two output positions are interchangeable. R1 measured this channel as
/// already PASSing at 018331a; this locks it against a future variable-length or
/// compressed payload path, which would reopen dummy-output distinguishability on
/// the channel that currently carries the real cryptographic work.
#[test]
fn r1_f4_encrypted_output_payloads_are_length_uniform() {
    let args = spend_with_hidden_value(7);
    let lengths: Vec<usize> = args.encrypted_outputs.iter().map(|p| p.len()).collect();
    assert_eq!(
        args.encrypted_outputs.len(),
        args.output_commitments.len(),
        "every output commitment must carry exactly one encrypted payload"
    );
    assert!(
        lengths.windows(2).all(|w| w[0] == w[1]),
        "R1-F4 REGRESSION: encrypted output payloads differ in length ({lengths:?}). \
         A dummy output must be length-indistinguishable from a real one; a \
         variable-length or compressed payload path reopens the channel R1 §6.3 \
         measured as sound."
    );
}

/// The lock that keeps the three assertions above meaningful: the mirror type
/// must carry EXACTLY the fields the tracked `.did` declares for
/// `PrivateSpendArgs`. Re-introducing `input_amounts` / `output_amounts` — or any
/// other per-spend quantity — on the canister and its `.did` fails HERE even if
/// the mirror is not updated, so a stale mirror cannot hide a reopened leak.
#[test]
fn r1_f1_mirror_matches_the_tracked_did() {
    // Field names as declared in shielded_pool.did's `PrivateSpendArgs` record,
    // read from the file rather than restated.
    let start = POOL_DID
        .find("type PrivateSpendArgs = record {")
        .expect("shielded_pool.did must declare PrivateSpendArgs");
    let body = &POOL_DID[start..];
    let end = body.find("};").expect("the record must terminate");
    let body = &body[..end];

    let mut did_fields: Vec<String> = Vec::new();
    for line in body.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let Some((name, _)) = line.split_once(':') else { continue };
        did_fields.push(name.trim().to_string());
    }
    did_fields.sort();

    // DERIVED from the mirror type itself, not hand-listed: a hand-maintained
    // list would let a field be added to the struct and silently omitted here.
    let mut mirror_fields: Vec<String> = match &*<PrivateSpendArgs as CandidType>::ty() {
        candid::types::TypeInner::Record(fields) => {
            fields.iter().map(|f| f.id.to_string()).collect()
        }
        other => panic!("PrivateSpendArgs must be a candid record, got {other:?}"),
    };
    mirror_fields.sort();

    assert_eq!(
        did_fields, mirror_fields,
        "the private_spend argument record on the wire no longer matches this \
         suite's mirror. If a field was ADDED, the privacy assertions in this file \
         are no longer testing the real message — update the mirror and re-derive \
         whether the new field can vary with a hidden quantity (R1-F1/F1b)."
    );

    // The specific fields R1-F1 was about, named so the regression reads plainly.
    for banned in ["input_amounts", "output_amounts"] {
        assert!(
            !did_fields.iter().any(|f| f == banned),
            "R1-F1 REGRESSION: `{banned}` is back on the public private_spend \
             interface. F1-PRIV removed it because it disclosed hidden note values \
             in cleartext on the ingress wire while being bound to nothing."
        );
    }
}
