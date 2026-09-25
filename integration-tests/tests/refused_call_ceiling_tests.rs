// =============================================================================
// STSH — REFUSED-CALL CYCLE CEILINGS  (remediation lane R-L, campaign §5 G-b)
// =============================================================================
//
// THE DEFECT CLASS. A rate-limited or floor-guarded endpoint has TWO cost
// paths, and only one of them is ever thought about. The accepted path does the
// work and is obviously expensive. The REFUSED path is supposed to be cheap —
// that is the entire point of putting a limiter in front of an expensive
// operation — but nothing in this repo has ever asserted it. A refusal that
// costs nearly as much as the work it refuses is not a defence; it is a cheaper
// attack, because the attacker no longer has to satisfy the precondition.
//
// These tests measure the cycles a REFUSED call actually costs and assert it
// stays under a ceiling.
//
// THE CEILING IS NOT DERIVED FROM THE CODE (brief §4 invariant 2).
// THE PIN IS NOT A MULTIPLIER (CTO_RULING_RL_REFUSED_CEILING_PIN_2026-09-05).
// It is `ceil_100k(max(samples) + 3 x (max - min))`, per endpoint, and it lives
// as a LITERAL in scripts/gate_lints/refused_call_ceilings.toml, which this test
// reads. The first cut pinned at x1.5 of the max and the lane's own M5 mutation
// could not cross it: these refusals are ~6.3-6.8M cycles of almost entirely
// FIXED per-message overhead, so x1.5 granted ~3.2M cycles of headroom against a
// real run-to-run spread of 2,818-93,623. The margin only has to absorb the
// measurement's noise, so it is derived from the SPREAD, not from the baseline.
//
// The test never reads a `pub const` in the canister crate -- a ceiling taken
// from the artifact it checks proves nothing, and AC-6/M6b exists to catch
// exactly that substitution.
//
// The assertion is ONE-SIDED on purpose: a refusal getting CHEAPER is never a
// regression. Each registry row also carries the `m5_*` fields that size the
// mutation proving the pin bites (2 x headroom RED / 0.5 x headroom GREEN).
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   cargo build --target wasm32-unknown-unknown --release \
//       -p stsh_token -p smoke_alarm_monitor -p upgrader -p shielded_pool
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// The registry — read as DATA, never as a canister constant
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CeilingRegistry {
    row: Vec<CeilingRow>,
}

#[derive(Debug, Deserialize, Clone)]
struct CeilingRow {
    id: String,
    ceiling_cycles: u64,
    measured_cycles: u64,
}

fn registry_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("scripts/gate_lints/refused_call_ceilings.toml")
}

/// The ceiling for one registry id, read from the committed TOML.
///
/// A missing file or a missing row is a hard failure naming both — the test
/// must never quietly fall back to a default, because a default IS a ceiling
/// derived from nothing.
fn ceiling(id: &str) -> CeilingRow {
    let path = registry_path();
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "REQUIRED REGISTRY MISSING: {} ({e}).\n  \
             The refused-call ceilings are DATA, reviewed as data; this test \
             deliberately has no fallback value.",
            path.display()
        )
    });
    let reg: CeilingRegistry = toml::from_str(&text)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    reg.row
        .into_iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no [[row]] with id = \"{id}\" in {}", path.display()))
}

/// Measure a refused call's cycle cost, `SAMPLES` times, and assert the MAXIMUM
/// sample is under the registry ceiling. Returns the samples for the packet.
const SAMPLES: usize = 5;

fn assert_under_ceiling(id: &str, samples: &[u64]) {
    let row = ceiling(id);
    let max = *samples.iter().max().expect("at least one sample");
    let min = *samples.iter().min().expect("at least one sample");
    assert!(
        max <= row.ceiling_cycles,
        "REFUSED-CALL CEILING EXCEEDED for `{id}`.\n  \
         samples (cycles): {samples:?}\n  \
         min {min}, max {max}\n  \
         ceiling {} = ceil_100k(max + 3 x spread), pinned from a max sample of {} in \
         scripts/gate_lints/refused_call_ceilings.toml\n  \
         A refusal that costs this much is not a defence — it is a cheaper \
         attack than the work it refuses. Either the refusal path gained work \
         it should not do, or the ceiling must be re-measured and re-pinned in \
         the SAME change, with the measurement in the review packet.",
        row.ceiling_cycles, row.measured_cycles
    );
    println!("[ceiling] {id}: samples {samples:?} max {max} <= ceiling {}", row.ceiling_cycles);
}

fn p(b: u8) -> Principal {
    Principal::from_slice(&[b; 29])
}
fn anon() -> Principal {
    Principal::anonymous()
}

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {pkg} Wasm at {path}: {e}.\n\
             Build first (two-phase sequence in this file's header)."
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// C-1 — smoke-alarm-monitor `request_refresh`, rate-limited refusal (UMC-28)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct MonitorInit {
    token_canister: Principal,
    pool_principal: Principal,
    treasury_principal: Principal,
    pool_attestation_source: Principal,
    refresh_interval_ns: u64,
    max_staleness_ns: u64,
    history_capacity: u32,
}

fn deploy_monitor(pic: &PocketIc) -> Principal {
    let id = pic.create_canister();
    pic.add_cycles(id, 20_000_000_000_000);
    let init = MonitorInit {
        // Nonexistent sources: the refusal path under test is the RATE LIMIT,
        // which is checked before any source is read, so the sources'
        // reachability is irrelevant to what is being measured — and a rig with
        // no dependencies is a rig that cannot drift.
        token_canister: p(0x77),
        pool_principal: p(0x50),
        treasury_principal: p(0x51),
        pool_attestation_source: p(0x78),
        refresh_interval_ns: 60 * 1_000_000_000,
        max_staleness_ns: 300 * 1_000_000_000,
        history_capacity: 3,
    };
    pic.install_canister(
        id,
        load_wasm(env!("MONITOR_WASM"), "smoke_alarm_monitor"),
        candid::encode_one(init).unwrap(),
        None,
    );
    id
}

#[test]
fn ceiling_c1_smoke_alarm_request_refresh_refusal() {
    let pic = PocketIc::new();
    let monitor = deploy_monitor(&pic);
    // Let the install-time refresh happen so LAST_REFRESH_ATTEMPT_NS is set and
    // every subsequent call inside the window is refused.
    pic.advance_time(Duration::from_secs(1));
    pic.tick();
    pic.tick();

    // Prime once: the FIRST call may be accepted depending on timer ordering.
    let _ = pic.update_call(monitor, anon(), "request_refresh", candid::encode_args(()).unwrap());
    pic.tick();

    let mut samples = Vec::new();
    for _ in 0..SAMPLES {
        let before = pic.cycle_balance(monitor);
        let raw = pic
            .update_call(monitor, anon(), "request_refresh", candid::encode_args(()).unwrap())
            .expect("the endpoint replies; it refuses in the Err arm, it does not trap");
        let after = pic.cycle_balance(monitor);
        let decoded: Result<(), String> = candid::decode_one(&raw).expect("decode");
        assert!(
            decoded.is_err(),
            "this test measures the REFUSED path; the call was accepted, so the \
             rate limit did not engage and the measurement is of the wrong path"
        );
        samples.push(before.saturating_sub(after) as u64);
    }
    assert_under_ceiling("C-1-smoke-alarm-request-refresh", &samples);
}

// ─────────────────────────────────────────────────────────────────────────────
// C-2 — upgrader `refresh_controller_invariant_now`, rate-limited refusal
//       (UMC-03). The R6 constants are RULED, so the endpoint refuses with
//       `TooSoon`/`AlreadyInFlight` inside the 6 h window rather than `NotRuled`.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct UpgraderInitArgs {
    recovery_members: Vec<Principal>,
    threshold: u32,
    vault: Principal,
}

fn deploy_upgrader(pic: &PocketIc) -> Principal {
    let id = pic.create_canister();
    pic.add_cycles(id, 20_000_000_000_000);
    let init = UpgraderInitArgs {
        recovery_members: vec![p(0x11), p(0x12), p(0x13)],
        threshold: 2,
        vault: p(0x20),
    };
    pic.install_canister(
        id,
        load_wasm(env!("UPGRADER_WASM"), "upgrader"),
        candid::encode_one(init).unwrap(),
        None,
    );
    id
}

#[test]
fn ceiling_c2_upgrader_refresh_controller_invariant_refusal() {
    let pic = PocketIc::new();
    let up = deploy_upgrader(&pic);

    // Drive the endpoint once so the refresh ledger records an accepted (or
    // at least attempted) charge; every call inside the ruled interval after
    // that is refused. The first call's outcome is deliberately not asserted —
    // what matters is that the SUBSEQUENT ones refuse, which is asserted below.
    let _ = pic.update_call(
        up,
        anon(),
        "refresh_controller_invariant_now",
        candid::encode_args(()).unwrap(),
    );
    pic.tick();

    let mut samples = Vec::new();
    for _ in 0..SAMPLES {
        let before = pic.cycle_balance(up);
        let raw = pic
            .update_call(
                up,
                anon(),
                "refresh_controller_invariant_now",
                candid::encode_args(()).unwrap(),
            )
            .expect("the endpoint replies; it refuses in the Err arm");
        let after = pic.cycle_balance(up);
        // Only the variant TAG matters here, not the Ok payload's shape:
        // decoding the full ControllerInvariant would couple this test to the
        // invariant view's type, which is the canister-crate coupling
        // invariant 2 forbids.
        let refused = match candid::decode_one::<candid::types::value::IDLValue>(&raw) {
            Ok(candid::types::value::IDLValue::Variant(v)) => v.0.id.get_id() == candid::idl_hash("Err"),
            _ => false,
        };
        assert!(
            refused,
            "this test measures the REFUSED path; the call was accepted, so the \
             rate limit did not engage and the measurement is of the wrong path. \
             reply = {:?}",
            candid::decode_one::<candid::types::value::IDLValue>(&raw)
        );
        samples.push(before.saturating_sub(after) as u64);
    }
    assert_under_ceiling("C-2-upgrader-refresh-controller-invariant", &samples);
}
