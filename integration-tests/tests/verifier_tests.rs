// =============================================================================
// STSH — A2-0 Verifier Canister Installability Gate (PocketIC)
// =============================================================================
//
// Primary question: Can the dedicated verifier canister (containing ark-groth16
// BN254 pairing code) install on ICP/PocketIC, or does it hit the same
// CanisterInvalidWasm function-complexity limit as the embedded approach?
//
// A2-0 acceptance gate:
//   test_v00 — verifier canister installs (no CanisterInvalidWasm)
//   test_v01 — empty proof bytes rejected by verifier canister
//   test_v02 — truncated proof bytes (100 bytes) rejected
//   test_v03 — wrong VK hash query returns compiled-in hash correctly
//   test_v04 — valid proof accepted (requires circuits/proof.json + public.json)
//   test_v05 — tampered proof rejected (requires artifacts)
//
// If test_v00 fails with CanisterInvalidWasm, the ark-groth16 approach is
// fundamentally incompatible with IC regardless of canister boundary.
// Stop and evaluate alternatives (wasm-opt splitting, different library, etc.).
//
// PREREQUISITES:
//   1. Build verifier canister Wasm:
//        cargo build --target wasm32-unknown-unknown --release -p stsh-verifier
//   2. export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   3. cargo test -p integration-tests --test verifier_tests
//
// SKIP behaviour:
//   test_v04, test_v05 require circuits/proof.json + public.json.
//   If missing they print SKIP and return — not a failure.
//
// A2-1 BENCHMARK:
//   test_v08_benchmark — measures avg/p50/p95/worst wall time + IC instruction
//   count over N=20 calls, plus verifier Wasm size, and checks p95 instruction
//   count against the provisional 20B ceiling. SKIP if artifacts missing.
//   Run with --nocapture to see the printed report:
//     cargo test -p integration-tests --test verifier_tests test_v08 -- --nocapture
// =============================================================================

use candid::{Encode, Decode, Principal};
use pocket_ic::PocketIc;
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// Wasm loading
// ─────────────────────────────────────────────────────────────────────────────

/// DEF-083: the verifier requires the authorized pool principal at init and
/// rejects any other caller of the proof-verification endpoints. These
/// standalone verifier tests install with this fixed test principal and issue
/// verification calls as it. vk_hash stays public (called as anonymous below).
fn test_pool_principal() -> Principal {
    Principal::from_slice(&[0x99; 29])
}

fn verifier_init_args() -> Vec<u8> {
    Encode!(&test_pool_principal()).expect("encode verifier init args")
}

fn verifier_wasm() -> Vec<u8> {
    let path = env!("VERIFIER_WASM");
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read verifier Wasm at {}:\n  {}\n\
             Build first:\n  \
             cargo build --target wasm32-unknown-unknown --release -p stsh-verifier",
            path, e
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Circuit artifact helpers
// ─────────────────────────────────────────────────────────────────────────────

fn circuits_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration-tests must be inside the workspace")
        .join("circuits")
}

struct Artifacts {
    proof_bytes: Vec<u8>,          // 256 bytes compact proof
    signals:     [[u8; 32]; 9],
}

// G-d (remediation lane R-L): was `-> Option<Artifacts>` returning `None` when the
// fixture was absent, with every caller silently returning. A missing fixture now
// panics naming the file and the producing command.
fn load_artifacts() -> Artifacts {
    let proof_path  = circuits_dir().join("proof.json");
    let public_path = circuits_dir().join("public.json");
    for path in [&proof_path, &public_path] {
        assert!(
            path.exists(),
            "REQUIRED FIXTURE MISSING: {}\n  \
             Produce it with the A0 trusted setup followed by A1 proof generation \
             (see run_gate.sh's circuit-artifact prerequisites). This test does NOT \
             skip when the fixture is absent.",
            path.display()
        );
    }
    let proof_json  = std::fs::read_to_string(&proof_path).expect("read proof.json");
    let public_json = std::fs::read_to_string(&public_path).expect("read public.json");
    // proof_json_to_bytes returns Vec<u8> (256 bytes)
    let proof_bytes = stsh_verifier::proof_json_to_bytes(&proof_json)
        .expect("proof_json_to_bytes failed");
    let signals = stsh_verifier::public_json_to_signals(&public_json)
        .expect("public_json_to_signals failed");
    Artifacts { proof_bytes, signals }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: call verify_spend_canister on the verifier canister
// ─────────────────────────────────────────────────────────────────────────────

// pocket-ic v9: update_call / query_call return Result<Vec<u8>, E> directly.
// Success = Ok(candid_bytes), rejection = Err(_).

fn call_verify(
    pic: &PocketIc,
    verifier: Principal,
    proof_bytes: Vec<u8>,
    signals: Vec<Vec<u8>>,
) -> Result<(), String> {
    let caller  = test_pool_principal(); // DEF-083: must match the init-time authorized pool
    let encoded = Encode!(&proof_bytes, &signals).expect("encode args");
    let bytes   = pic
        .update_call(verifier, caller, "verify_spend_canister", encoded)
        .expect("verify_spend_canister call was rejected (canister trap/install fail)");
    Decode!(&bytes, Result<(), String>).expect("decode Result<(),String>")
}

fn call_vk_hash(pic: &PocketIc, verifier: Principal) -> Vec<u8> {
    let caller  = Principal::anonymous();
    let encoded = Encode!().expect("encode empty args");
    let bytes   = pic
        .query_call(verifier, caller, "vk_hash", encoded)
        .expect("vk_hash query was rejected");
    Decode!(&bytes, Vec<u8>).expect("decode Vec<u8>")
}

/// A2-1 benchmark helper: calls verify_spend_canister_benchmark, which returns
/// (Result<(), String>, instruction_count).
fn call_verify_benchmark(
    pic: &PocketIc,
    verifier: Principal,
    proof_bytes: Vec<u8>,
    signals: Vec<Vec<u8>>,
) -> (Result<(), String>, u64) {
    let caller  = test_pool_principal(); // DEF-083: benchmark endpoint is pool-gated too
    let encoded = Encode!(&proof_bytes, &signals).expect("encode args");
    let bytes   = pic
        .update_call(verifier, caller, "verify_spend_canister_benchmark", encoded)
        .expect("verify_spend_canister_benchmark call was rejected (canister trap/install fail)");
    Decode!(&bytes, Result<(), String>, u64).expect("decode (Result<(),String>, u64)")
}

// ─────────────────────────────────────────────────────────────────────────────
// A2-0 GATE TESTS
// ─────────────────────────────────────────────────────────────────────────────

/// A2-0 GATE: Can the verifier canister install at all?
///
/// This is the critical question. If ark-groth16 BN254 pairing code produces
/// a Wasm function with complexity > 1,000,000, install will panic with
/// CanisterInvalidWasm. That means the library is incompatible with IC
/// regardless of which canister hosts it.
///
/// PASS = ark-groth16 can live in a dedicated canister on IC.
/// FAIL = must evaluate alternatives (wasm-opt, different library, etc.).
#[test]
fn test_v00_verifier_canister_installs() {
    let pic = PocketIc::new();
    let wasm = verifier_wasm();
    // install_canister panics on CanisterInvalidWasm — test fails with clear message
    let verifier = pic.create_canister();
    pic.add_cycles(verifier, 100_000_000_000_000);
    pic.install_canister(verifier, wasm, verifier_init_args(), None);
    println!("PASS: verifier canister installed. Principal: {}", verifier);
    println!("      ark-groth16 BN254 is compatible with IC Wasm complexity limit.");
}

/// Empty proof bytes (0 bytes) — verifier returns Err.
#[test]
fn test_v01_empty_proof_rejected() {
    let pic = PocketIc::new();
    let verifier = pic.create_canister();
    pic.add_cycles(verifier, 100_000_000_000_000);
    pic.install_canister(verifier, verifier_wasm(), verifier_init_args(), None);

    let dummy_signals: Vec<Vec<u8>> = (0..6).map(|_| vec![0u8; 32]).collect();
    let result = call_verify(&pic, verifier, vec![], dummy_signals);
    assert!(
        result.is_err(),
        "Expected Err for empty proof, got Ok"
    );
    println!("PASS: empty proof rejected — {}", result.unwrap_err());
}

/// Truncated proof bytes (100 bytes instead of 256) — verifier returns Err.
#[test]
fn test_v02_truncated_proof_rejected() {
    let pic = PocketIc::new();
    let verifier = pic.create_canister();
    pic.add_cycles(verifier, 100_000_000_000_000);
    pic.install_canister(verifier, verifier_wasm(), verifier_init_args(), None);

    let dummy_signals: Vec<Vec<u8>> = (0..6).map(|_| vec![0u8; 32]).collect();
    let result = call_verify(&pic, verifier, vec![0u8; 100], dummy_signals);
    assert!(
        result.is_err(),
        "Expected Err for truncated proof, got Ok"
    );
    println!("PASS: truncated proof rejected — {}", result.unwrap_err());
}

/// Wrong signal count (5 instead of 6) — verifier returns Err.
#[test]
fn test_v03_wrong_signal_count_rejected() {
    let pic = PocketIc::new();
    let verifier = pic.create_canister();
    pic.add_cycles(verifier, 100_000_000_000_000);
    pic.install_canister(verifier, verifier_wasm(), verifier_init_args(), None);

    // Only 5 signals — should be rejected before hitting the pairing
    let bad_signals: Vec<Vec<u8>> = (0..5).map(|_| vec![0u8; 32]).collect();
    let result = call_verify(&pic, verifier, vec![0u8; 256], bad_signals);
    assert!(
        result.is_err(),
        "Expected Err for 5 signals, got Ok"
    );
    println!("PASS: wrong signal count rejected — {}", result.unwrap_err());
}

/// vk_hash query returns the SHA-256 of the compiled-in VK.
/// Must match stsh_verifier::compiled_vk_sha256() (native host call).
#[test]
fn test_v04_vk_hash_query_matches_compiled_hash() {
    let pic = PocketIc::new();
    let verifier = pic.create_canister();
    pic.add_cycles(verifier, 100_000_000_000_000);
    pic.install_canister(verifier, verifier_wasm(), verifier_init_args(), None);

    let canister_hash = call_vk_hash(&pic, verifier);
    let native_hash   = stsh_verifier::compiled_vk_sha256().to_vec();
    assert_eq!(
        canister_hash, native_hash,
        "vk_hash() from canister does not match compiled_vk_sha256() from native"
    );
    println!("PASS: vk_hash consistent — {}", hex_bytes(&canister_hash));
}

/// Valid proof accepted (requires circuits/proof.json + public.json).
/// SKIP if artifacts are missing.
#[test]
fn test_v05_valid_proof_accepted() {
    let art = load_artifacts();

    let pic = PocketIc::new();
    let verifier = pic.create_canister();
    pic.add_cycles(verifier, 100_000_000_000_000);
    pic.install_canister(verifier, verifier_wasm(), verifier_init_args(), None);

    let signals: Vec<Vec<u8>> = art.signals.iter().map(|s| s.to_vec()).collect();
    let start  = std::time::Instant::now();
    let result = call_verify(&pic, verifier, art.proof_bytes.to_vec(), signals);
    let elapsed = start.elapsed();

    assert!(
        result.is_ok(),
        "Expected Ok for valid proof, got Err: {:?}",
        result.unwrap_err()
    );
    println!("PASS: valid proof accepted in {:?}", elapsed);
}

/// Tampered proof (first 32 bytes zeroed) rejected.
/// SKIP if artifacts are missing.
#[test]
fn test_v06_tampered_proof_rejected() {
    let art = load_artifacts();

    let pic = PocketIc::new();
    let verifier = pic.create_canister();
    pic.add_cycles(verifier, 100_000_000_000_000);
    pic.install_canister(verifier, verifier_wasm(), verifier_init_args(), None);

    let mut tampered = art.proof_bytes.to_vec();
    tampered[0..32].fill(0); // zero the pi_a.x coordinate

    let signals: Vec<Vec<u8>> = art.signals.iter().map(|s| s.to_vec()).collect();
    let result  = call_verify(&pic, verifier, tampered, signals);
    assert!(
        result.is_err(),
        "Expected Err for tampered proof, got Ok"
    );
    println!("PASS: tampered proof rejected — {}", result.unwrap_err());
}

/// Tampered public signal (signal[1] = nullifier_hash zeroed) rejected.
/// SKIP if artifacts are missing.
#[test]
fn test_v07_tampered_signal_rejected() {
    let art = load_artifacts();

    let pic = PocketIc::new();
    let verifier = pic.create_canister();
    pic.add_cycles(verifier, 100_000_000_000_000);
    pic.install_canister(verifier, verifier_wasm(), verifier_init_args(), None);

    let mut signals: Vec<Vec<u8>> = art.signals.iter().map(|s| s.to_vec()).collect();
    // XOR every byte of signal[1] — guaranteed different regardless of original value.
    // (Zeroing is not safe: if the original nullifier_hash is already 0 in dev proofs,
    // the tamper is a no-op and the proof still verifies.)
    signals[1] = art.signals[1].iter().map(|b| b ^ 0xFF).collect();

    let result = call_verify(&pic, verifier, art.proof_bytes.to_vec(), signals);
    assert!(
        result.is_err(),
        "Expected Err for tampered signal, got Ok"
    );
    println!("PASS: tampered signal rejected — {}", result.unwrap_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// A2-1 — VERIFIER CANISTER BENCHMARK
// ─────────────────────────────────────────────────────────────────────────────
//
// Goal: measure whether Groth16 verification on the dedicated verifier
// canister is economically viable, per docs (A2-1 scope):
//   - avg / p50 / p95 / worst wall-clock latency (PocketIC proxy)
//   - avg / p50 / p95 / worst IC instruction count (-> cycle estimate)
//   - verifier Wasm binary size
//   - p95 instruction-derived cycle estimate vs provisional 20B ceiling
//
// On application subnets, 1 instruction == 1 cycle for compute charges
// (see IC pricing docs), so the instruction count from
// ic_cdk::api::instruction_counter() is used directly as a cycle estimate
// for the verification call itself. This does NOT include fixed per-call
// overhead (message routing, cycles for argument/response payload), which
// PocketIC does not expose — the wall-clock numbers are the closest proxy
// for end-to-end latency.
//
// SKIP if circuits/proof.json + public.json are missing.
// PASS criterion: p95 instruction estimate <= 20_000_000_000 (20B), the
// provisional PM-approved ceiling from A0. If exceeded, this test prints a
// clear FAIL marker but does not panic — A2-1 requires human review of the
// printed numbers before deciding whether to proceed to A2-2.
#[test]
fn test_v08_benchmark() {
    let art = load_artifacts();

    const N: usize = 20;
    const CEILING_INSTRUCTIONS: u64 = 20_000_000_000; // 20B provisional ceiling

    let pic = PocketIc::new();
    let verifier = pic.create_canister();
    pic.add_cycles(verifier, 100_000_000_000_000);
    pic.install_canister(verifier, verifier_wasm(), verifier_init_args(), None);

    let signals: Vec<Vec<u8>> = art.signals.iter().map(|s| s.to_vec()).collect();

    // Warmup call (not measured) — let PocketIC settle / cache anything it can.
    let (warmup_result, _) =
        call_verify_benchmark(&pic, verifier, art.proof_bytes.to_vec(), signals.clone());
    assert!(
        warmup_result.is_ok(),
        "warmup call failed, cannot benchmark: {:?}",
        warmup_result.unwrap_err()
    );

    let mut wall_times_us: Vec<u128> = Vec::with_capacity(N);
    let mut instructions: Vec<u64> = Vec::with_capacity(N);

    for i in 0..N {
        let start = std::time::Instant::now();
        let (result, instr) =
            call_verify_benchmark(&pic, verifier, art.proof_bytes.to_vec(), signals.clone());
        let elapsed = start.elapsed();

        assert!(
            result.is_ok(),
            "benchmark iteration {} failed: {:?}",
            i,
            result.unwrap_err()
        );

        wall_times_us.push(elapsed.as_micros());
        instructions.push(instr);
    }

    wall_times_us.sort_unstable();
    instructions.sort_unstable();

    let avg_us  = wall_times_us.iter().sum::<u128>() / wall_times_us.len() as u128;
    let p50_us  = percentile(&wall_times_us, 50);
    let p95_us  = percentile(&wall_times_us, 95);
    let worst_us = *wall_times_us.last().unwrap();

    let avg_instr  = instructions.iter().sum::<u64>() / instructions.len() as u64;
    let p50_instr  = percentile(&instructions, 50);
    let p95_instr  = percentile(&instructions, 95);
    let worst_instr = *instructions.last().unwrap();

    let wasm_size = std::fs::metadata(env!("VERIFIER_WASM"))
        .map(|m| m.len())
        .unwrap_or(0);

    println!("=============================================================");
    println!("A2-1 VERIFIER CANISTER BENCHMARK (N={})", N);
    println!("-------------------------------------------------------------");
    println!("Wall-clock latency (PocketIC proxy, microseconds):");
    println!("  avg : {:>10}", avg_us);
    println!("  p50 : {:>10}", p50_us);
    println!("  p95 : {:>10}", p95_us);
    println!("  max : {:>10}", worst_us);
    println!("-------------------------------------------------------------");
    println!("IC instruction count (== cycle estimate for compute, app subnet):");
    println!("  avg : {:>15}", avg_instr);
    println!("  p50 : {:>15}", p50_instr);
    println!("  p95 : {:>15}", p95_instr);
    println!("  max : {:>15}", worst_instr);
    println!("-------------------------------------------------------------");
    println!("Verifier Wasm size: {} bytes ({:.1} KiB)", wasm_size, wasm_size as f64 / 1024.0);
    println!("-------------------------------------------------------------");
    println!(
        "20B ceiling check: p95={} vs ceiling={} -> {}",
        p95_instr,
        CEILING_INSTRUCTIONS,
        if p95_instr <= CEILING_INSTRUCTIONS { "PASS" } else { "FAIL — revisit verifier strategy" }
    );
    println!("=============================================================");
}

/// Nearest-rank percentile over an already-sorted slice.
fn percentile<T: Copy>(sorted: &[T], pct: usize) -> T {
    let idx = (sorted.len() * pct).div_ceil(100).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// UMC-31 / BR-15 (lane R-11) — the DEF-083 caller gate, exercised negatively
// ─────────────────────────────────────────────────────────────────────────────

/// The verifier's own doc claims the proof endpoints "cannot be used as a public
/// verification/cycle-burn oracle". Every pre-existing test called them AS the
/// authorized pool, so nothing in the tree exercised the refusal — the claim
/// rested on reading `assert_pool_caller()`, not on running it.
///
/// This calls both guarded endpoints from `Principal::anonymous()` and from an
/// unrelated non-anonymous principal, and asserts each call is REJECTED at the
/// canister boundary (the guard traps, so PocketIC surfaces `Err`, not a decoded
/// `Result::Err` payload — an important distinction: a decodable reply would
/// mean the body ran and the cycles were burned).
///
/// `vk_hash` is deliberately NOT gated and is asserted to still answer anonymous
/// callers, so a regression that gated everything indiscriminately is also
/// visible here.
#[test]
fn umc31_proof_endpoints_refuse_every_non_pool_caller() {
    let pic = PocketIc::new();
    let verifier = pic.create_canister();
    pic.add_cycles(verifier, 100_000_000_000_000);
    pic.install_canister(verifier, verifier_wasm(), verifier_init_args(), None);

    let proof_bytes = vec![0u8; 256];
    let signals: Vec<Vec<u8>> = (0..9).map(|_| vec![0u8; 32]).collect();
    let encoded = Encode!(&proof_bytes, &signals).expect("encode args");

    // An unrelated, non-anonymous principal — the anonymous case alone would
    // leave "any authenticated principal" untested.
    let stranger = Principal::from_slice(&[0x42; 29]);
    assert_ne!(stranger, test_pool_principal());

    for caller in [Principal::anonymous(), stranger] {
        for method in ["verify_spend_canister", "verify_spend_canister_benchmark"] {
            let out = pic.update_call(verifier, caller, method, encoded.clone());
            assert!(
                out.is_err(),
                "DEF-083: `{method}` accepted a call from {caller} — the endpoint is a public \
                 verification/cycle-burn oracle"
            );
        }
    }

    // The ungated query still answers anonymously: the guard is targeted, not a
    // blanket lockout that would pass this test for the wrong reason.
    let h = call_vk_hash(&pic, verifier);
    assert_eq!(h.len(), 32, "vk_hash must stay publicly callable");

    // And the authorized pool still gets THROUGH the gate (it fails later, on
    // the all-zero proof, which is a decoded Err — proof that the refusals above
    // are the caller gate and not a universally broken endpoint).
    let allowed = call_verify(&pic, verifier, proof_bytes, signals);
    assert!(
        allowed.is_err(),
        "an all-zero proof must be rejected on its merits"
    );
}
