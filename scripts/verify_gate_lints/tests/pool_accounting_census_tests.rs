//! FU1-2 pool accounting-statics reference-count census — the GATE-VISIBLE
//! surface (lane R-11, brief §3.1 / AC-1).
//!
//! `cargo test --workspace` runs this over the REAL tree. The
//! `pool-accounting-census` subcommand runs the identical walk for a packet.

use std::path::PathBuf;

use verify_gate_lints::pool_accounting_census as pac;
use verify_gate_lints::target_cfg::TargetAtoms;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root is two levels above scripts/verify_gate_lints")
        .to_path_buf()
}

/// Every reference (read or write) to the six pool accounting statics, in every
/// function reachable in the non-test build, matches the literal expectation
/// table — and the two RETIRED (post-R-13) bypass functions match their exact
/// baselined reference counts.
#[test]
fn fu1_2_known_bypass_census() {
    let root = root();
    let target = TargetAtoms::capture(&root).expect("rustc --print cfg --target wasm32");
    let violations = pac::run(&root, &target).expect("census walk");
    assert!(
        violations.is_empty(),
        "pool accounting reference-count census findings:\n  {}",
        violations.join("\n  ")
    );
}

/// The census is not vacuous: the walk really does find the 32 enumerated
/// references, 6 of which are writes, spread over 10 functions. (Pre-R-13 this
/// read 37 / 11 / 12: the five funnel-bypassing writes inside
/// `apply_private_spend_accounting` and `apply_withdrawal_accounting` are gone,
/// and with them those two functions.) A degenerate
/// walk that found nothing would pass `fu1_2_known_bypass_census`'s emptiness
/// check only by also failing every MISSING-reference rule, so this test states
/// the shape directly rather than inferring it.
#[test]
fn fu1_2_census_walk_observes_the_enumerated_population() {
    let root = root();
    let target = TargetAtoms::capture(&root).expect("rustc --print cfg --target wasm32");
    let observed = pac::observe(&root, &target).expect("census walk");
    let refs: usize = observed.iter().map(|o| o.reads + o.writes).sum();
    let writes: usize = observed.iter().map(|o| o.writes).sum();
    let fns: std::collections::BTreeSet<&str> =
        observed.iter().map(|o| o.func.as_str()).collect();
    assert_eq!(refs, 32, "total accounting-static references: {observed:#?}");
    assert_eq!(writes, 6, "total accounting-static writes: {observed:#?}");
    assert_eq!(fns.len(), 10, "functions referencing the six statics: {fns:?}");
}
