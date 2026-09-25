// =============================================================================
// STSH — L3c / H6-2: the wallet's 256-byte compact proof encoding, proven
// three ways against the REAL production verifier Wasm.
//
//   1. The TS encoder's output (pinned in wallet/tests/encodeProof.test.ts and
//      here) is BYTE-EQUAL to the Rust reference `proof_json_to_bytes` on the
//      ceremony proof fixture (circuits/proof.json — REGENERATED at lane A-4
//      against the mainnet-v2 launch proving key, so it is valid against the
//      pinned VK 84dba305…, not the retired dev key).
//   2. The SAME bytes verify OK through the REAL production verifier canister
//      (stsh_verifier, compiled-in pinned VK) with the 9 fixture public
//      signals — i.e. what the wallet encodes, the verifier accepts.
//   3. A tampered public signal is rejected (the verifier is not rubber-stamping).
//
// The ceremony fixtures (circuits/proof.json + public.json) are tracked; the
// proving key is circuits/build/spend_1.zkey (tracked since L3c, Option A).
//
// A-4 (2026-09-12): swapping the VK invalidated every committed proof fixture —
// a Groth16 proof is only valid under the key that produced it — so proof.json
// and proof_payout_a.json were re-proved over the ceremony zkey. Groth16 proving
// is randomised, so the 256-byte pin below MOVED even though the circuit, the
// inputs and all 9 public signals are unchanged (public.json is byte-identical
// before and after, which is the check that only the proof moved).
// =============================================================================

use candid::{Decode, Encode, Principal};
use pocket_ic::PocketIc;
use std::path::PathBuf;

/// Pinned output of the wallet's `encodeGroth16Proof` on circuits/proof.json
/// (captured from the TS encoder; asserted byte-equal to the Rust reference
/// below — three-way agreement: TS == Rust == verifier-accepted).
const TS_ENCODED_PROOF_HEX: &str = "00cd4223a51f7bca91facc4500ebc78840799425edbc18095fbdf19b595c042529e68e97efa3750f4d6f1d3114e633b27020227838c8e510d83a66a1dba8582db74cfad1f42646e8d260c475890453752f4e999733cbfce390feea22ed093d2ae51755c4302681eb4c22bbdf1bb7ea5fe9494ea340bddfcadcd3b00946536612c83f8fbf7a743f6a36a4c571115368d45bdb2d2ce4773c2d9f3400c11a9eb5067b8b80123dc46388e628e979996af797a80b08b84d64253f96fa7a27bcca431e3dea9bc890925b5eafe5794ce861392a1f99dfac262a0083a515ab329d7db811988a4b0473e84735ca625d61c764d7cd772d5ecb7102e865a7fd2d2bf9da672a";

fn hex_decode(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex string must be even-length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex decode"))
        .collect()
}

fn circuits_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration-tests must be inside the workspace")
        .join("circuits")
}

fn verifier_wasm() -> Vec<u8> {
    let path = env!("VERIFIER_WASM");
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read verifier Wasm at {}: {}\nBuild first: \
             cargo build --target wasm32-unknown-unknown --release -p stsh-verifier",
            path, e
        )
    })
}

/// DEF-083: the verifier only answers its authorized pool principal.
fn test_pool_principal() -> Principal {
    Principal::from_slice(&[0x99; 29])
}

fn call_verify(
    pic: &PocketIc,
    verifier: Principal,
    proof_bytes: Vec<u8>,
    signals: Vec<Vec<u8>>,
) -> Result<(), String> {
    let encoded = Encode!(&proof_bytes, &signals).expect("encode args");
    let bytes = pic
        .update_call(verifier, test_pool_principal(), "verify_spend_canister", encoded)
        .expect("verify_spend_canister call was rejected (canister trap/install fail)");
    Decode!(&bytes, Result<(), String>).expect("decode Result<(),String>")
}

fn load_signals() -> [[u8; 32]; 9] {
    let public_json = std::fs::read_to_string(circuits_dir().join("public.json"))
        .expect("circuits/public.json must exist (tracked ceremony fixture)");
    stsh_verifier::public_json_to_signals(&public_json).expect("public_json_to_signals failed")
}

#[test]
fn l3c_ts_encoded_bytes_equal_rust_reference() {
    let proof_json = std::fs::read_to_string(circuits_dir().join("proof.json"))
        .expect("circuits/proof.json must exist (tracked ceremony fixture)");
    let rust_bytes = stsh_verifier::proof_json_to_bytes(&proof_json)
        .expect("proof_json_to_bytes failed");
    let ts_bytes = hex_decode(TS_ENCODED_PROOF_HEX);
    assert_eq!(ts_bytes.len(), 256, "the compact proof encoding is exactly 256 bytes");
    assert_eq!(
        rust_bytes, ts_bytes,
        "the wallet TS encoder must be byte-equal to the Rust proof_json_to_bytes \
         (256-byte compact, G2 c0-first, 32-byte LE Fq)"
    );
}

#[test]
fn l3c_encoded_proof_verifies_in_real_production_verifier_wasm() {
    let pic = PocketIc::new();
    let verifier = pic.create_canister();
    pic.add_cycles(verifier, 100_000_000_000_000);
    pic.install_canister(
        verifier,
        verifier_wasm(),
        Encode!(&test_pool_principal()).expect("encode verifier init args"),
        None,
    );

    let proof_bytes = hex_decode(TS_ENCODED_PROOF_HEX);
    let signals = load_signals();

    // (2) The TS-encoded bytes + the request-derived 9 signals VERIFY through
    // the real production verifier Wasm (compiled-in pinned VK).
    let signals_vec: Vec<Vec<u8>> = signals.iter().map(|s| s.to_vec()).collect();
    let result = call_verify(&pic, verifier, proof_bytes.clone(), signals_vec);
    assert!(
        result.is_ok(),
        "the wallet-encoded proof must verify through the production verifier Wasm; got {:?}",
        result
    );

    // All 9 public signals are the fixture's request-derived values (the flow
    // compares them canonically before submit — assert the shape here).
    assert_eq!(signals.len(), 9, "the spend circuit has exactly 9 public signals");

    // (3) A tampered signal is rejected — the verifier is not rubber-stamping.
    let mut tampered = signals;
    tampered[8][0] ^= 0x01;
    let tampered_vec: Vec<Vec<u8>> = tampered.iter().map(|s| s.to_vec()).collect();
    let rejected = call_verify(&pic, verifier, proof_bytes, tampered_vec);
    assert!(
        rejected.is_err(),
        "a tampered public signal must be rejected by the production verifier"
    );
}
