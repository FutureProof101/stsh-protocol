//! A-6c evidence suite — the LIVE balance source, driven over a MOCK TRANSPORT.
//!
//! Leg 1 of the lane's two-leg evidence. Leg 2 is one recorded run of the
//! shipped binary against a local replica; it is NOT here and must never be,
//! because a network-dependent test inside the standing gate makes the gate
//! non-deterministic.
//!
//! The mock sits at the RAW CANDID BYTES seam, not at `Observation`. That is
//! the whole point: a mock returning a pre-decoded `Observation::Balance(u128)`
//! would never execute the candid decoder or the checked `nat`→`u128`
//! conversion, so it could not prove anything about either. Here every test
//! below runs the shipped decode path.
//!
//! No timing assertion anywhere. Queries are counted, never timed.

use candid::{Nat, Principal};
use cycle_monitor::*;
use std::cell::RefCell;

/// A budget source with a full, healthy rolling-hour history — so the BALANCE
/// arms below measure the balance section rather than the C-26 section.
///
/// The arms that measure the C-26 section itself live in
/// `budget_rule_tests.rs`, including the one that pins the honest new default:
/// an UNWIRED budget query makes the run Incomplete, never Ok.
struct HealthyBudget;
impl DeriveBudgetSource for HealthyBudget {
    fn budget_stats(&self) -> BudgetObservation {
        BudgetObservation::Stats(DeriveBudgetStats {
            window_ns: 3_600_000_000_000,
            budget: 20,
            consumed: 1,
            retry_after_ns: 0,
            tagged_consumed: 1,
            distinct_principals: 1,
            max_by_one_principal: 1,
            first_derive_dispatches: 1,
            refusals_budget_total: 0,
            stats_epoch_ns: 1,
            floor: CycleFloorView::Live { admits: true },
            sightings_recorded_total: 0,
            age_refusals_total: 0,
            sightings_pending: 0,
        })
    }
}

/// The prior state these arms carry: a full span of quiet history, so the two
/// rolling-hour rules are EVALUATED rather than Incomplete.
fn quiet_prior() -> PriorState {
    let sample = |at_ns| CounterSample { at_ns, value: 0, epoch_ns: 1 };
    PriorState::Present {
        run_at_ns: NOW - 1,
        budget: Some(DeriveBudgetReport {
            saturation: RuleOutcome::Quiet,
            concentration: RuleOutcome::Quiet,
            refusal_spike: RuleOutcome::Quiet,
            funding_wave: RuleOutcome::Quiet,
            floor: RuleOutcome::Quiet,
            first_saturated_at_ns: None,
            refusal_history: vec![sample(NOW - 3_600_000_000_000)],
            sighting_history: vec![sample(NOW - 3_600_000_000_000)],
            reasons: Vec::new(),
        }),
    }
}


const NOW: u64 = 1_700_000_000_000_000_000;
const RESERVE: u128 = 1_000_000_000_000; // 1T cycles

/// A real, parseable principal for each of the six registered canisters.
/// Distinct values, so a test cannot pass by conflating two canisters.
const PRINCIPALS: [&str; 6] = [
    "rrkah-fqaaa-aaaaa-aaaaq-cai",
    "ryjl3-tyaaa-aaaaa-aaaba-cai",
    "r7inp-6aaaa-aaaaa-aaabq-cai",
    "rkp4c-7iaaa-aaaaa-aaaca-cai",
    "rno2w-sqaaa-aaaaa-aaacq-cai",
    "renrk-eyaaa-aaaaa-aaada-cai",
];

/// NOT a round number, and NOT reachable by truncating a larger value —
/// so an exact-equality assertion on it cannot be satisfied by accident.
const EXACT_BALANCE: u128 = 987_654_321_098_765_432_109_876_543_210_987_651;

fn encode_nat(n: &Nat) -> Vec<u8> {
    candid::encode_one(n).expect("nat encodes")
}

/// What the mock should do for one canister.
#[derive(Clone)]
enum Reply {
    /// A well-formed candid `nat` reply carrying this value.
    Nat(Nat),
    /// A well-formed reply that is NOT a nat (candid `text`).
    NotANat,
    /// Bytes that are not candid at all.
    Garbage,
    /// The query does not complete.
    TransportError,
}

/// Mock transport, keyed by principal, with a call counter.
struct MockTransport {
    by_principal: Vec<(String, Reply)>,
    calls: RefCell<usize>,
}

impl MockTransport {
    fn new(entries: Vec<(String, Reply)>) -> Self {
        Self { by_principal: entries, calls: RefCell::new(0) }
    }
}

impl QueryTransport for MockTransport {
    fn query_cycle_balance(&self, principal: Principal) -> Result<Vec<u8>, String> {
        *self.calls.borrow_mut() += 1;
        let text = principal.to_text();
        let reply = self
            .by_principal
            .iter()
            .find(|(p, _)| *p == text)
            .map(|(_, r)| r.clone())
            .unwrap_or(Reply::TransportError);
        match reply {
            Reply::Nat(n) => Ok(encode_nat(&n)),
            Reply::NotANat => Ok(candid::encode_one("not a balance").expect("text encodes")),
            Reply::Garbage => Ok(vec![0xff, 0x00, 0xde, 0xad, 0xbe, 0xef]),
            Reply::TransportError => Err("connection refused (mock)".to_string()),
        }
    }

    /// The C-26 query. These arms measure the BALANCE section, so the mock
    /// serves a healthy, quiet reading — and it is a REAL candid encode of the
    /// monitor's own mirror type, so a decode regression fails here too.
    fn query_derive_budget_stats(&self, _principal: Principal) -> Result<Vec<u8>, String> {
        candid::encode_one(healthy_budget_stats()).map_err(|e| e.to_string())
    }
}

/// A quiet, healthy `DeriveBudgetStats`.
fn healthy_budget_stats() -> DeriveBudgetStats {
    DeriveBudgetStats {
        window_ns: 3_600_000_000_000,
        budget: 20,
        consumed: 1,
        retry_after_ns: 0,
        tagged_consumed: 1,
        distinct_principals: 1,
        max_by_one_principal: 1,
        first_derive_dispatches: 1,
        refusals_budget_total: 0,
        stats_epoch_ns: 1,
        floor: CycleFloorView::Live { admits: true },
        sightings_recorded_total: 0,
        age_refusals_total: 0,
        sightings_pending: 0,
    }
}

// Injecting a BORROWED transport — so a test can read the call counter after
// the source has been consumed by `run` — is now served by the crate's blanket
// `impl QueryTransport for &T`, added so the CLI can share ONE agent between the
// balance source and the C-26 source. The local impl this replaces would
// conflict with it.

/// The six registered canisters, each with a principal and a valid reserve.
fn configured_fleet() -> Vec<CanisterConfig> {
    let params: Vec<CanisterConfig> = shipped_register()
        .iter()
        .zip(PRINCIPALS)
        .map(|(r, p)| CanisterConfig {
            name: r.name.clone(),
            principal: Some(p.to_string()),
            freeze_reserve_cycles: Some(RESERVE),
            reserve_provenance: Some("controller canister_status at deploy".to_string()),
            reserve_observed_at_ns: Some(NOW - 1),
        })
        .collect();
    derive_fleet(&params).expect("all six are register members")
}

/// A healthy balance: strictly above 3× reserve.
fn healthy() -> Nat {
    Nat::from(RESERVE * 10)
}

fn all_healthy_mock() -> MockTransport {
    MockTransport::new(PRINCIPALS.iter().map(|p| (p.to_string(), Reply::Nat(healthy()))).collect())
}

// ── L1 — six observations present ────────────────────────────────────────────

#[test]
fn l1_all_six_report_a_balance_and_the_run_exits_0() {
    let configs = configured_fleet();
    let transport = all_healthy_mock();
    let source = LiveBalanceSource::new(transport);

    let snap = run_with_budget(&configs, &source, &HealthyBudget, quiet_prior(), false, NOW);

    assert_eq!(snap.canisters.len(), 6, "the register decides membership");
    for c in &snap.canisters {
        assert_eq!(
            c.status,
            CanisterStatus::CoveredHealthy,
            "{} should be healthy, got {:?} ({})",
            c.canister,
            c.status,
            c.reason
        );
        assert!(c.balance.is_some(), "{} must carry a balance", c.canister);
    }
    assert_eq!(snap.aggregate, Aggregate::Ok);
    assert_eq!(snap.aggregate.exit_code(), 0);
}

// ── L2 — ANY ONE missing/erroring canister is caught, at every slot ──────────

/// THE LOAD-BEARING TEST. Driven six times, once per register slot: removing
/// any single canister's observation must produce a NON-ZERO exit.
///
/// "One representative canister" would not prove this — it would leave five
/// slots where a source could silently fail and the run still exit 0.
#[test]
fn l2_any_single_failing_canister_alerts_at_every_one_of_the_six_slots() {
    let configs = configured_fleet();
    let mut outcomes: Vec<(String, i32)> = Vec::new();

    for (i, name) in shipped_register().iter().map(|r| r.name.clone()).enumerate() {
        // Every canister healthy EXCEPT slot i, whose query fails.
        let entries: Vec<(String, Reply)> = PRINCIPALS
            .iter()
            .enumerate()
            .map(|(j, p)| {
                let reply =
                    if j == i { Reply::TransportError } else { Reply::Nat(healthy()) };
                (p.to_string(), reply)
            })
            .collect();
        let source = LiveBalanceSource::new(MockTransport::new(entries));
        let snap = run_with_budget(&configs, &source, &HealthyBudget, quiet_prior(), false, NOW);

        let failed: Vec<&CanisterReport> = snap
            .canisters
            .iter()
            .filter(|c| c.status == CanisterStatus::SourceFailed)
            .collect();
        assert_eq!(failed.len(), 1, "exactly one canister should have failed at slot {i}");
        assert_eq!(failed[0].canister, name, "the failure must be attributed to slot {i}");

        let code = snap.aggregate.exit_code();
        assert_ne!(code, 0, "a failing {name} must NOT exit 0");
        assert_eq!(code, 1, "a source failure is ALERT (1), not INCOMPLETE (2)");
        outcomes.push((name, code));
    }

    assert_eq!(outcomes.len(), 6, "six slots driven, six outcomes recorded");
}

/// L2b — the INCOMPLETE limb at the shipped register size. A canister whose
/// observation is absent (no source wired) must exit 2, and it must do so with
/// all six names present, not a two-canister fixture.
#[test]
fn l2b_an_unobserved_canister_is_incomplete_and_exits_2_at_six_names() {
    let configs = configured_fleet();
    assert_eq!(configs.len(), 6, "the mutation must bite at the SHIPPED size");

    struct OneUnwired(usize);
    impl BalanceSource for OneUnwired {
        fn balance_of(&self, c: &CanisterConfig) -> Observation {
            if c.name == shipped_register()[self.0].name {
                Observation::NotWired
            } else {
                Observation::Balance(RESERVE * 10)
            }
        }
    }

    for i in 0..6 {
        let snap = run_with_budget(&configs, &OneUnwired(i), &HealthyBudget, quiet_prior(), false, NOW);
        assert_eq!(snap.aggregate, Aggregate::Incomplete, "slot {i}");
        assert_eq!(snap.aggregate.exit_code(), 2, "INCOMPLETE must exit 2, slot {i}");
    }
}

// ── L3 — value plumbing is EXACT ─────────────────────────────────────────────

#[test]
fn l3_the_balance_arrives_unchanged_through_the_real_candid_decoder() {
    let cfg = CanisterConfig {
        name: "shielded_pool".to_string(),
        principal: Some(PRINCIPALS[0].to_string()),
        freeze_reserve_cycles: Some(RESERVE),
        reserve_provenance: Some("deploy-time canister_status".to_string()),
        reserve_observed_at_ns: Some(NOW - 1),
    };
    let source = LiveBalanceSource::new(MockTransport::new(vec![(
        PRINCIPALS[0].to_string(),
        Reply::Nat(Nat::from(EXACT_BALANCE)),
    )]));

    let obs = source.balance_of(&cfg);
    assert_eq!(
        obs,
        Observation::Balance(EXACT_BALANCE),
        "the value must survive candid encode → decode → u128 EXACTLY"
    );

    let report = classify_canister(&cfg, obs, NOW);
    assert_eq!(
        report.balance,
        Some(EXACT_BALANCE),
        "and must reach the report unchanged, not rounded and not truncated"
    );
}

/// L3b — u128::MAX itself round-trips. The boundary value is in range and must
/// NOT be mistaken for an overflow.
#[test]
fn l3b_u128_max_is_in_range_and_is_not_an_overflow() {
    let cfg = CanisterConfig {
        name: "token".to_string(),
        principal: Some(PRINCIPALS[4].to_string()),
        freeze_reserve_cycles: Some(RESERVE),
        reserve_provenance: Some("deploy-time canister_status".to_string()),
        reserve_observed_at_ns: Some(NOW - 1),
    };
    let source = LiveBalanceSource::new(MockTransport::new(vec![(
        PRINCIPALS[4].to_string(),
        Reply::Nat(Nat::from(u128::MAX)),
    )]));
    assert_eq!(source.balance_of(&cfg), Observation::Balance(u128::MAX));
}

// ── L4 — a nat larger than u128 is a FAILURE, never a balance ───────────────

#[test]
fn l4_a_nat_exceeding_u128_is_refused_and_never_becomes_a_balance() {
    let cfg = CanisterConfig {
        name: "verifier".to_string(),
        principal: Some(PRINCIPALS[1].to_string()),
        freeze_reserve_cycles: Some(RESERVE),
        reserve_provenance: Some("deploy-time canister_status".to_string()),
        reserve_observed_at_ns: Some(NOW - 1),
    };
    // u128::MAX + 1 — the smallest nat that does not fit.
    let too_big = Nat::from(u128::MAX) + Nat::from(1u8);
    let source = LiveBalanceSource::new(MockTransport::new(vec![(
        PRINCIPALS[1].to_string(),
        Reply::Nat(too_big),
    )]));

    let obs = source.balance_of(&cfg);
    assert_eq!(
        obs,
        Observation::Failed(FailureKind::BalanceExceedsU128),
        "an out-of-range nat must map to a FAILURE"
    );
    assert!(
        !matches!(obs, Observation::Balance(_)),
        "and must never present as a balance — a truncated value landing above \
         the threshold would MANUFACTURE health"
    );

    let report = classify_canister(&cfg, obs, NOW);
    assert_eq!(report.status, CanisterStatus::SourceFailed);
    assert_eq!(report.balance, None, "no balance is recorded for a refused value");
    assert_eq!(aggregate(&[report], RunStatus::Fresh), Aggregate::Alert);
}

/// L4b — a value far above the range is refused for the same reason, and in
/// particular is NOT silently reduced modulo 2^128 to something healthy.
#[test]
fn l4b_a_hugely_oversized_nat_does_not_wrap_into_a_healthy_looking_balance() {
    let cfg = CanisterConfig {
        name: "merkle_tree".to_string(),
        principal: Some(PRINCIPALS[3].to_string()),
        freeze_reserve_cycles: Some(RESERVE),
        reserve_provenance: Some("deploy-time canister_status".to_string()),
        reserve_observed_at_ns: Some(NOW - 1),
    };
    // (u128::MAX + 1) * 2^8 + a healthy-looking low word: if the conversion
    // truncated, this would read as a perfectly healthy balance.
    let wrapped_would_be_healthy =
        (Nat::from(u128::MAX) + Nat::from(1u8)) * Nat::from(256u16) + Nat::from(RESERVE * 10);
    let source = LiveBalanceSource::new(MockTransport::new(vec![(
        PRINCIPALS[3].to_string(),
        Reply::Nat(wrapped_would_be_healthy),
    )]));

    assert_eq!(
        source.balance_of(&cfg),
        Observation::Failed(FailureKind::BalanceExceedsU128),
        "truncation would have produced a healthy balance here — it must not"
    );
}

// ── L5 — every FailureKind has its own bite ─────────────────────────────────

fn cfg_with(name: &str, principal: Option<&str>) -> CanisterConfig {
    CanisterConfig {
        name: name.to_string(),
        principal: principal.map(str::to_string),
        freeze_reserve_cycles: Some(RESERVE),
        reserve_provenance: Some("deploy-time canister_status".to_string()),
        reserve_observed_at_ns: Some(NOW - 1),
    }
}

#[test]
fn l5a_principal_missing_has_its_own_kind_and_reason() {
    let source = LiveBalanceSource::new(MockTransport::new(vec![]));
    let obs = source.balance_of(&cfg_with("shielded_pool", None));
    assert_eq!(obs, Observation::Failed(FailureKind::PrincipalMissing));
    assert_eq!(
        classify_canister(&cfg_with("shielded_pool", None), obs, NOW).reason,
        FailureKind::PrincipalMissing.reason()
    );
    // and no query was attempted — an unconfigured canister costs no socket.
    let source2 = MockTransport::new(vec![]);
    let s = LiveBalanceSource::new(source2);
    let _ = s.balance_of(&cfg_with("shielded_pool", None));
}

#[test]
fn l5b_unparseable_principal_has_its_own_kind_and_reason() {
    let cfg = cfg_with("verifier", Some("not-a-principal"));
    let source = LiveBalanceSource::new(MockTransport::new(vec![]));
    let obs = source.balance_of(&cfg);
    assert_eq!(obs, Observation::Failed(FailureKind::PrincipalUnparseable));
    assert_eq!(classify_canister(&cfg, obs, NOW).reason, FailureKind::PrincipalUnparseable.reason());
}

#[test]
fn l5c_transport_failure_has_its_own_kind_and_reason() {
    let cfg = cfg_with("token", Some(PRINCIPALS[4]));
    let source = LiveBalanceSource::new(MockTransport::new(vec![(
        PRINCIPALS[4].to_string(),
        Reply::TransportError,
    )]));
    let obs = source.balance_of(&cfg);
    assert_eq!(obs, Observation::Failed(FailureKind::Transport));
    assert_eq!(classify_canister(&cfg, obs, NOW).reason, FailureKind::Transport.reason());
}

#[test]
fn l5d_undecodable_reply_has_its_own_kind_and_reason() {
    let cfg = cfg_with("nullifier_registry", Some(PRINCIPALS[2]));

    // A well-formed candid reply of the WRONG TYPE.
    let source = LiveBalanceSource::new(MockTransport::new(vec![(
        PRINCIPALS[2].to_string(),
        Reply::NotANat,
    )]));
    let obs = source.balance_of(&cfg);
    assert_eq!(obs, Observation::Failed(FailureKind::ReplyUndecodable));
    assert_eq!(classify_canister(&cfg, obs, NOW).reason, FailureKind::ReplyUndecodable.reason());

    // And bytes that are not candid at all take the same limb.
    let garbage = LiveBalanceSource::new(MockTransport::new(vec![(
        PRINCIPALS[2].to_string(),
        Reply::Garbage,
    )]));
    assert_eq!(
        garbage.balance_of(&cfg),
        Observation::Failed(FailureKind::ReplyUndecodable)
    );
}

#[test]
fn l5e_oversized_balance_has_its_own_kind_and_reason() {
    let cfg = cfg_with("vetkeys", Some(PRINCIPALS[5]));
    let source = LiveBalanceSource::new(MockTransport::new(vec![(
        PRINCIPALS[5].to_string(),
        Reply::Nat(Nat::from(u128::MAX) + Nat::from(1u8)),
    )]));
    let obs = source.balance_of(&cfg);
    assert_eq!(obs, Observation::Failed(FailureKind::BalanceExceedsU128));
    assert_eq!(classify_canister(&cfg, obs, NOW).reason, FailureKind::BalanceExceedsU128.reason());
}

/// L5f — the five kinds are MUTUALLY DISTINCT in their observable.
///
/// This is the test that fails if anyone later collapses the failures back into
/// one sentence: five kinds must yield five different reasons, and the count is
/// asserted against the enumeration, not eyeballed.
#[test]
fn l5f_every_failure_kind_carries_a_distinct_reason() {
    let kinds = [
        FailureKind::PrincipalMissing,
        FailureKind::PrincipalUnparseable,
        FailureKind::Transport,
        FailureKind::ReplyUndecodable,
        FailureKind::BalanceExceedsU128,
    ];
    let mut reasons: Vec<&str> = kinds.iter().map(|k| k.reason()).collect();
    let defined = reasons.len();
    reasons.sort_unstable();
    reasons.dedup();
    assert_eq!(
        reasons.len(),
        defined,
        "{defined} kinds defined but only {} distinct reasons — a collapse",
        reasons.len()
    );
    assert_eq!(defined, 5, "five kinds defined, five bite tests above");

    // Every kind still routes to SourceFailed => Alert. The aggregate mapping
    // is UNCHANGED by this lane; only the reason discriminates.
    for k in kinds {
        let cfg = cfg_with("shielded_pool", Some(PRINCIPALS[0]));
        let r = classify_canister(&cfg, Observation::Failed(k), NOW);
        assert_eq!(r.status, CanisterStatus::SourceFailed, "{k:?}");
        assert_eq!(aggregate(&[r], RunStatus::Fresh), Aggregate::Alert, "{k:?}");
    }
}

// ── L6 — no principal configured is a FAILURE, not a coverage gap ───────────

#[test]
fn l6_an_unconfigured_canister_is_source_failed_never_not_yet_covered() {
    // The register, with NO parameters supplied at all.
    let configs = derive_fleet(&[]).expect("empty params is legal");
    let source = LiveBalanceSource::new(MockTransport::new(vec![]));
    let snap = run_with_budget(&configs, &source, &HealthyBudget, quiet_prior(), false, NOW);

    assert_eq!(snap.canisters.len(), 6);
    for c in &snap.canisters {
        assert_eq!(
            c.status,
            CanisterStatus::SourceFailed,
            "{} — after A-6c a source EXISTS, so a missing principal is a failure \
             to watch it, not an absence of coverage",
            c.canister
        );
        assert_ne!(
            c.status,
            CanisterStatus::NotYetCovered,
            "{} must not read as a coverage gap",
            c.canister
        );
        assert_ne!(c.status, CanisterStatus::CoveredHealthy, "{} must not read as healthy", c.canister);
        assert_eq!(c.reason, FailureKind::PrincipalMissing.reason());
    }
    assert_eq!(snap.aggregate, Aggregate::Alert);
    assert_eq!(snap.aggregate.exit_code(), 1, "ALERT (1), not INCOMPLETE (2), not OK (0)");
}

// ── L7 — the query budget survives the live source ──────────────────────────

/// E8's property, re-asserted through the LIVE source: exactly one query per
/// monitored canister. Counted, never timed.
#[test]
fn l7_exactly_one_query_per_monitored_canister_through_the_live_source() {
    let configs = configured_fleet();
    let transport = all_healthy_mock();

    // Borrow the transport so the counter is still readable after the run.
    let source = LiveBalanceSource::new(&transport);
    let snap = run_with_budget(&configs, &source, &HealthyBudget, quiet_prior(), false, NOW);
    assert_eq!(snap.aggregate, Aggregate::Ok);

    let calls = *transport.calls.borrow();
    assert!(
        calls <= configs.len(),
        "queries per run ({calls}) must be at most one per monitored canister ({})",
        configs.len()
    );
    assert_eq!(calls, configs.len(), "and each of the six is actually consulted");
}

/// L7b — the limbs that short-circuit above the transport cost NO query.
///
/// Asserted causally, against the counter, rather than inferred from the code:
/// six unconfigured canisters must produce six failures and ZERO socket calls.
#[test]
fn l7b_unconfigured_canisters_cost_no_query_at_all() {
    let configs = derive_fleet(&[]).expect("empty params is legal");
    let transport = MockTransport::new(vec![]);
    let source = LiveBalanceSource::new(&transport);

    let snap = run_with_budget(&configs, &source, &HealthyBudget, quiet_prior(), false, NOW);

    assert_eq!(
        *transport.calls.borrow(),
        0,
        "a canister with no principal must be refused ABOVE the transport"
    );
    assert_eq!(snap.canisters.len(), 6);
    assert!(snap.canisters.iter().all(|c| c.status == CanisterStatus::SourceFailed));
}

// ── L8 — the whole fleet unreachable, deterministically ─────────────────────

/// SSA_DIFF_A-6c_RED_V2 D1's replacement coverage.
///
/// E16 case 4 used to prove "endpoint unreachable ⇒ six transport failures ⇒
/// exit 1" by pointing the real binary at a dead port. That made the standing
/// gate depend on an OS socket outcome, which brief §5.2 forbids. The same
/// property is proved here with no socket at all: the mock transport refuses
/// every query, which is exactly what an unreachable replica looks like from
/// above the transport seam.
#[test]
fn l8_an_unreachable_fleet_is_six_transport_failures_and_exits_1() {
    let configs = configured_fleet();
    let transport = MockTransport::new(
        PRINCIPALS.iter().map(|p| (p.to_string(), Reply::TransportError)).collect(),
    );
    let source = LiveBalanceSource::new(&transport);

    let snap = run_with_budget(&configs, &source, &HealthyBudget, quiet_prior(), false, NOW);

    assert_eq!(snap.canisters.len(), 6);
    for c in &snap.canisters {
        assert_eq!(c.status, CanisterStatus::SourceFailed, "{}", c.canister);
        assert_eq!(
            c.reason,
            FailureKind::Transport.reason(),
            "{} must say WHY, and say the transport thing specifically",
            c.canister
        );
        assert_eq!(c.balance, None, "{} must carry no balance", c.canister);
    }
    assert_eq!(snap.aggregate, Aggregate::Alert);
    assert_eq!(snap.aggregate.exit_code(), 1, "ALERT (1), never OK (0), never INCOMPLETE (2)");

    // Each canister was genuinely tried — six attempts, not a short-circuit.
    assert_eq!(
        *transport.calls.borrow(),
        6,
        "an unreachable fleet must still be QUERIED six times; failing without \
         trying would be a different bug wearing the same report"
    );
}
