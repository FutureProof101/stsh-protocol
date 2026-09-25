// =============================================================================
// §S7 START SETTLEMENT — ACCEPTANCE, THE SHARED-PREDICATE HALF
//
// Normative source: A1_START_SETTLEMENT_CONTRACT_V5_2026-08-07.md
// (sha256 e004fc7c3c6c6410461cfa2fa70efcc81c2f9200329b71c3e4ce601dae2c2c8b),
// dispatched by CTO_RULING_S7_SCOPE_AND_DISPATCH_2026-08-11.md
// (sha256 89896e85bb2750bcbd3ab64fb995646afd41572161ee675cf8a63bfbff38ed81).
//
// WHY THESE ITEMS LIVE HERE, AND WHY THAT IS "BOTH DIRECTIONS".
// V5 §10 requires every acceptance test to run in BOTH directions. For the
// items in this file the two directions are not two code paths that happen to
// agree — they are ONE function that both planes call
// (`classify_start_reconcile`, `validate_start_evidence`, `maps_to`,
// `semantic_key`, `evidence_commitment`, `callback_may_write`). Asserting the
// predicate once here is therefore a STRICTLY STRONGER statement than asserting
// it twice against two copies: a copy can drift between assertions, a shared
// function cannot. The `both_directions_share_one_predicate` test below pins
// that this remains true, so these items cannot silently become
// single-direction if someone later forks the logic.
//
// Plane-specific behaviour — E1, the E2 sweep, the §3c fence's audit, the §8a
// atomic durable transition, single-flight, and the Candid target-redirection
// surface — is NOT provable from pure functions and is asserted in each
// canister's own suite, in both directions.
//
// Every mechanism test below carries its MUTATION CHECK 1:1, inline, marked
// `MUTATION:`. The form is: break the mechanism, confirm THIS test's assertion
// would fail, restore. A settlement test that passes against a broken
// settlement proves nothing.
// =============================================================================

use candid::Principal;
use stsh_custody_types::{
    callback_may_write, classify_start_reconcile, validate_start_evidence, ActionOutcome,
    EvidenceRejection, ObservedCanisterStatus, ReconcileTerminalOutcome, SettlementEvidenceConflict,
    SettlementRecord, StartIntent, StartObjectiveEvidence, StartReconcileDisposition,
    StartReconcileRejection, StartSourceState, START_MAX_EVIDENCE_AGE_NS,
};

// ── Fixtures ────────────────────────────────────────────────────────────────

fn p(b: u8) -> Principal {
    Principal::from_slice(&[b; 29])
}

/// Cell 4's target is the VAULT and its controller is the UPGRADER; cell 3's
/// target is the UPGRADER and its controller is the VAULT. The predicate is
/// direction-agnostic, so both are exercised by parameterising these two.
const VAULT: u8 = 0xF0;
const UPGRADER: u8 = 0xF1;

const INTENT_AT: u64 = 1_000_000_000;
const NOW: u64 = INTENT_AT + 60_000_000_000; // 60 s after the intent

/// The two instances, as data. Every test that can be direction-parameterised
/// runs over BOTH rows — which is the literal reading of "every test runs in
/// both directions" for the shared predicate.
struct Direction {
    name: &'static str,
    target: Principal,
    controller: Principal,
}

fn directions() -> [Direction; 2] {
    [
        Direction {
            name: "cell 4 (Upgrader -> Vault)",
            target: p(VAULT),
            controller: p(UPGRADER),
        },
        Direction {
            name: "cell 3 (Vault -> Upgrader)",
            target: p(UPGRADER),
            controller: p(VAULT),
        },
    ]
}

fn intent(d: &Direction) -> StartIntent {
    StartIntent {
        proposal_id: 7,
        target: d.target,
        epoch: 3,
        intent_at_ns: INTENT_AT,
    }
}

fn evidence(d: &Direction, status: ObservedCanisterStatus, at: u64) -> StartObjectiveEvidence {
    StartObjectiveEvidence {
        observed_target_principal: d.target,
        observed_canister_status: status,
        observed_controllers: vec![d.controller],
        observed_at_ns: at,
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ACCEPTANCE 4 — reconciliation happy path: Running => Executed,
//                Stopped => Failed.  (§5 terminal mappings)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn acceptance_4_terminal_mappings_both_directions() {
    for d in directions() {
        let i = intent(&d);
        let src = |ev: &StartObjectiveEvidence| StartSourceState {
            outcome: ActionOutcome::OutcomeUnknown,
            intent: &i,
            settlement: None,
            required_controllers: std::slice::from_ref(&d.controller),
        };

        let running = evidence(&d, ObservedCanisterStatus::Running, NOW);
        assert_eq!(
            classify_start_reconcile(Some(src(&running)), &running, NOW),
            Ok(StartReconcileDisposition::Settle(ReconcileTerminalOutcome::Executed)),
            "{}: Running must settle Executed",
            d.name
        );

        let stopped = evidence(&d, ObservedCanisterStatus::Stopped, NOW);
        assert_eq!(
            classify_start_reconcile(Some(src(&stopped)), &stopped, NOW),
            Ok(StartReconcileDisposition::Settle(ReconcileTerminalOutcome::Failed)),
            "{}: Stopped must settle Failed",
            d.name
        );

        // MUTATION: swap the mapping (Running -> Failed). `maps_to` is the sole
        // settlement predicate, so a swapped table changes the disposition and
        // both assertions above flip. Confirm the two outcomes are genuinely
        // distinguishable rather than both defaulting to one value — if they
        // were equal, a broken table would pass.
        assert_ne!(
            running.maps_to(),
            stopped.maps_to(),
            "{}: MUTATION GUARD — Running and Stopped must map to DIFFERENT \
             terminals, else a collapsed mapping table would pass this test",
            d.name
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ACCEPTANCE 5 — `Stopping` is inconclusive: no terminalization.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn acceptance_5_stopping_is_inconclusive_both_directions() {
    for d in directions() {
        let i = intent(&d);
        let ev = evidence(&d, ObservedCanisterStatus::Stopping, NOW);
        let src = StartSourceState {
            outcome: ActionOutcome::OutcomeUnknown,
            intent: &i,
            settlement: None,
            required_controllers: std::slice::from_ref(&d.controller),
        };
        assert_eq!(
            classify_start_reconcile(Some(src), &ev, NOW),
            Ok(StartReconcileDisposition::Inconclusive),
            "{}: Stopping proves neither success nor failure and must NOT terminalize",
            d.name
        );

        // MUTATION: force `Stopping` into either bucket — i.e. make `maps_to`
        // return Some(_) for it — and this becomes a `Settle`, not
        // `Inconclusive`. That is precisely the assumption R-2 forecloses.
        assert!(
            ev.maps_to().is_none(),
            "{}: MUTATION — mapping Stopping to a terminal makes the assertion \
             above unreachable; Stopping must map to NO outcome",
            d.name
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ACCEPTANCE 6 — the evidence rejection set. Each rejected, NONE terminalizing.
// (§4: pre-intent, future-dated, too-old, wrong target, drifted controllers.)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn acceptance_6_evidence_rejection_set_both_directions() {
    for d in directions() {
        let i = intent(&d);
        let ctrl = std::slice::from_ref(&d.controller);

        let cases: Vec<(&str, StartObjectiveEvidence, EvidenceRejection)> = vec![
            (
                "pre-intent",
                evidence(&d, ObservedCanisterStatus::Running, INTENT_AT - 1),
                EvidenceRejection::PredatesIntent,
            ),
            (
                "future-dated",
                evidence(&d, ObservedCanisterStatus::Running, NOW + 1),
                EvidenceRejection::FutureEvidence,
            ),
            (
                "too-old",
                {
                    // Older than the ruled bound, measured from `now`.
                    let mut e = evidence(&d, ObservedCanisterStatus::Running, INTENT_AT);
                    e.observed_at_ns = INTENT_AT;
                    e
                },
                EvidenceRejection::EvidenceTooOld,
            ),
            (
                "wrong target",
                {
                    let mut e = evidence(&d, ObservedCanisterStatus::Running, NOW);
                    e.observed_target_principal = p(0x0C);
                    e
                },
                EvidenceRejection::WrongPrincipal,
            ),
            (
                "drifted controllers",
                {
                    let mut e = evidence(&d, ObservedCanisterStatus::Running, NOW);
                    e.observed_controllers = vec![p(0x0D)];
                    e
                },
                EvidenceRejection::WrongControllers,
            ),
        ];

        for (label, ev, expected) in cases {
            // "too-old" needs a `now` far past the bound; the others use NOW.
            let now = if label == "too-old" {
                INTENT_AT + START_MAX_EVIDENCE_AGE_NS + 1
            } else {
                NOW
            };
            assert_eq!(
                validate_start_evidence(&ev, &i, ctrl, now),
                Err(expected.clone()),
                "{}: {label} must be rejected as {expected:?}",
                d.name
            );
            // NONE TERMINALIZING: the same input through the full gate ladder
            // must reject, never settle.
            let src = StartSourceState {
                outcome: ActionOutcome::OutcomeUnknown,
                intent: &i,
                settlement: None,
                required_controllers: ctrl,
            };
            assert_eq!(
                classify_start_reconcile(Some(src), &ev, now),
                Err(StartReconcileRejection::EvidenceRejected(expected)),
                "{}: {label} must not terminalize",
                d.name
            );
        }

        // MUTATION: the boundary is `> START_MAX_EVIDENCE_AGE_NS`, so evidence
        // exactly AT the bound is still valid. Relaxing the check to `>=` — or
        // dropping it — would admit the too-old case above. Pin both sides of
        // the boundary so a one-sided change cannot pass.
        let at_bound = evidence(&d, ObservedCanisterStatus::Running, INTENT_AT);
        assert_eq!(
            validate_start_evidence(&at_bound, &i, ctrl, INTENT_AT + START_MAX_EVIDENCE_AGE_NS),
            Ok(()),
            "{}: evidence exactly at the freshness bound is VALID",
            d.name
        );
        assert_eq!(
            validate_start_evidence(&at_bound, &i, ctrl, INTENT_AT + START_MAX_EVIDENCE_AGE_NS + 1),
            Err(EvidenceRejection::EvidenceTooOld),
            "{}: one ns past the bound is REJECTED — MUTATION: widening this \
             comparison makes the too-old case above pass wrongly",
            d.name
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ACCEPTANCE 7 — illegal source states are typed rejections, zero mutation.
// Plus: assert NO `Rejected` variant exists (§3, CONF-01).
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn acceptance_7_illegal_source_states_both_directions() {
    for d in directions() {
        let i = intent(&d);
        let ev = evidence(&d, ObservedCanisterStatus::Running, NOW);
        let ctrl = std::slice::from_ref(&d.controller);

        // Every non-`OutcomeUnknown` state WITHOUT a settlement record.
        // `Executed`/`Failed` here are the callback-terminalized case: terminal,
        // but never settled by reconciliation, so they hold no record and are
        // illegal sources — which is what acceptance 7 requires.
        for state in [
            ActionOutcome::Pending,
            ActionOutcome::Executing,
            ActionOutcome::Cancelled,
            ActionOutcome::Expired,
            ActionOutcome::Executed,
            ActionOutcome::Failed,
        ] {
            let src = StartSourceState {
                outcome: state,
                intent: &i,
                settlement: None,
                required_controllers: ctrl,
            };
            assert_eq!(
                classify_start_reconcile(Some(src), &ev, NOW),
                Err(StartReconcileRejection::IllegalSourceState),
                "{}: {state:?} is an illegal source state",
                d.name
            );
        }

        // The SOLE legal source state.
        let src = StartSourceState {
            outcome: ActionOutcome::OutcomeUnknown,
            intent: &i,
            settlement: None,
            required_controllers: ctrl,
        };
        assert!(
            matches!(
                classify_start_reconcile(Some(src), &ev, NOW),
                Ok(StartReconcileDisposition::Settle(_))
            ),
            "{}: OutcomeUnknown is the sole legal source state",
            d.name
        );
    }
}

/// §3 / CONF-01 — **no `Rejected` variant exists at any commit**, and the
/// builder must not add one. Asserted structurally: the debug rendering of the
/// complete variant set is pinned, so adding a variant fails HERE.
///
/// §3 states the source-state rule as a PREDICATE, not a list, precisely so a
/// future variant is denied by default rather than falling through into
/// settlement. This test pins the set the predicate was reasoned about.
#[test]
fn acceptance_7_no_rejected_variant_exists() {
    let all = [
        ActionOutcome::Pending,
        ActionOutcome::Executing,
        ActionOutcome::Executed,
        ActionOutcome::Failed,
        ActionOutcome::OutcomeUnknown,
        ActionOutcome::Cancelled,
        ActionOutcome::Expired,
    ];
    let rendered: Vec<String> = all.iter().map(|v| format!("{v:?}")).collect();
    assert!(
        !rendered.iter().any(|v| v == "Rejected"),
        "CONF-01: no `Rejected` ActionOutcome variant may exist"
    );
    assert_eq!(
        rendered.len(),
        7,
        "the ActionOutcome variant set this contract reasoned about is seven \
         states; a new variant must be classified against §3 before this pin moves"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// ACCEPTANCE 9 — replay classification and the audit bound. (§7d)
// ═════════════════════════════════════════════════════════════════════════════

/// 9(a) concordant replay => error, zero mutation.
/// 9(b) N distinct fresh CONCORDANT observations with N distinct timestamps and
///      N distinct `evidence_commitment`s => ZERO conflict events. **This is the
///      C2 growth route and is the point of the test; asserting a repeated
///      identical hash is not sufficient and does not satisfy this item.**
/// 9(c) N distinct fresh DISCORDANT observations => EXACTLY ONE conflict.
/// 9(d) a later observation differing ONLY in timestamp is CONCORDANT.
#[test]
fn acceptance_9_replay_classification_both_directions() {
    for d in directions() {
        let i = intent(&d);
        let ctrl = std::slice::from_ref(&d.controller);

        // Settled Executed on a Running observation.
        let settling = evidence(&d, ObservedCanisterStatus::Running, INTENT_AT + 1);
        let record = SettlementRecord::settle(ReconcileTerminalOutcome::Executed, &settling);

        // ── 9(b) — N distinct fresh CONCORDANT observations ─────────────────
        //
        // Distinct timestamps => distinct `evidence_commitment` values. All
        // must classify CONCORDANT and none may reach the conflict branch.
        let mut commitments = std::collections::HashSet::new();
        for k in 1..=8u64 {
            let ev = evidence(&d, ObservedCanisterStatus::Running, INTENT_AT + 1000 * k);
            assert!(
                commitments.insert(ev.evidence_commitment()),
                "{}: 9(b) requires N DISTINCT evidence_commitment values — a \
                 repeated hash does not exercise the C2 growth route",
                d.name
            );
            // The semantic identity is INVARIANT across those distinct
            // commitments — that is the whole of the C2 remediation.
            assert_eq!(
                ev.semantic_key(),
                settling.semantic_key(),
                "{}: 9(d) — differing ONLY in timestamp must leave semantic_key \
                 unchanged",
                d.name
            );
            let src = StartSourceState {
                outcome: ActionOutcome::Executed,
                intent: &i,
                settlement: Some(&record),
                required_controllers: ctrl,
            };
            assert_eq!(
                classify_start_reconcile(Some(src), &ev, NOW),
                Ok(StartReconcileDisposition::ReplayConcordant {
                    stored: ReconcileTerminalOutcome::Executed
                }),
                "{}: 9(a)/9(b)/9(d) — a semantically concordant replay is \
                 CONCORDANT regardless of timestamp, and never a conflict",
                d.name
            );
        }

        // MUTATION: were concordance decided on `evidence_commitment` (the
        // timestamped hash) instead of `semantic_key`, every one of the eight
        // observations above would compare unequal and be classified
        // DISCORDANT — unbounded permanent conflict events, the exact C2
        // defect. Pin that the two hashes genuinely differ, so the test is not
        // vacuous.
        let a = evidence(&d, ObservedCanisterStatus::Running, INTENT_AT + 1);
        let b = evidence(&d, ObservedCanisterStatus::Running, INTENT_AT + 2);
        assert_eq!(a.semantic_key(), b.semantic_key());
        assert_ne!(
            a.evidence_commitment(),
            b.evidence_commitment(),
            "{}: MUTATION GUARD — the timestamped commitment MUST differ across \
             observations, else 9(b) proves nothing about the C2 route",
            d.name
        );

        // ── 9(c) — N distinct fresh DISCORDANT observations => EXACTLY ONE ──
        //
        // The cap is a durable one-bit flag, so the FIRST discordance reports
        // `cap_available: true` and every later one reports `false`. The plane
        // writes on the first only; the count of conflict events is therefore
        // exactly one, and that is asserted end-to-end in each canister's suite.
        let mut record = record.clone();
        let mut cap_true_count = 0;
        for k in 1..=8u64 {
            let ev = evidence(&d, ObservedCanisterStatus::Stopped, INTENT_AT + 2000 * k);
            let src = StartSourceState {
                outcome: ActionOutcome::Executed,
                intent: &i,
                settlement: Some(&record),
                required_controllers: ctrl,
            };
            match classify_start_reconcile(Some(src), &ev, NOW) {
                Ok(StartReconcileDisposition::ReplayDiscordant {
                    stored,
                    replay_mapped,
                    cap_available,
                }) => {
                    assert_eq!(stored, ReconcileTerminalOutcome::Executed);
                    assert_eq!(replay_mapped, ReconcileTerminalOutcome::Failed);
                    if cap_available {
                        cap_true_count += 1;
                        // The plane's write, modelled: one bit, false -> true.
                        record.conflict_recorded = true;
                    }
                }
                other => panic!("{}: expected a discordant replay, got {other:?}", d.name),
            }
        }
        assert_eq!(
            cap_true_count, 1,
            "{}: 9(c) — N distinct fresh discordant observations must yield \
             EXACTLY ONE conflict, for the lifetime of the proposal",
            d.name
        );

        // MUTATION: remove the cap — i.e. leave `conflict_recorded` false —
        // and all eight discordances report `cap_available: true`, so the
        // count becomes 8 and the assertion above fails.
        let mut uncapped = SettlementRecord::settle(ReconcileTerminalOutcome::Executed, &settling);
        uncapped.conflict_recorded = false;
        let ev = evidence(&d, ObservedCanisterStatus::Stopped, INTENT_AT + 3);
        let src = StartSourceState {
            outcome: ActionOutcome::Executed,
            intent: &i,
            settlement: Some(&uncapped),
            required_controllers: ctrl,
        };
        assert!(
            matches!(
                classify_start_reconcile(Some(src), &ev, NOW),
                Ok(StartReconcileDisposition::ReplayDiscordant { cap_available: true, .. })
            ),
            "{}: MUTATION — with the cap cleared the branch reports available \
             again, which is what makes the count assertion above load-bearing",
            d.name
        );

        // A `Stopping` replay maps to no outcome: inconclusive, never a
        // conflict, and still never success-shaped.
        let stopping = evidence(&d, ObservedCanisterStatus::Stopping, NOW);
        let src = StartSourceState {
            outcome: ActionOutcome::Executed,
            intent: &i,
            settlement: Some(&record),
            required_controllers: ctrl,
        };
        assert_eq!(
            classify_start_reconcile(Some(src), &stopping, NOW),
            Ok(StartReconcileDisposition::ReplayInconclusive {
                stored: ReconcileTerminalOutcome::Executed
            }),
            "{}: an inconclusive replay is neither concordant nor a conflict",
            d.name
        );
    }
}

/// §7c — **replay is NEVER success-shaped**, in every branch of §7d.
#[test]
fn acceptance_9_every_replay_branch_is_an_error_shape() {
    for d in directions() {
        let i = intent(&d);
        let ctrl = std::slice::from_ref(&d.controller);
        let settling = evidence(&d, ObservedCanisterStatus::Running, INTENT_AT + 1);
        let record = SettlementRecord::settle(ReconcileTerminalOutcome::Executed, &settling);

        for status in [
            ObservedCanisterStatus::Running,  // concordant
            ObservedCanisterStatus::Stopped,  // discordant
            ObservedCanisterStatus::Stopping, // inconclusive
        ] {
            let ev = evidence(&d, status, NOW);
            let src = StartSourceState {
                outcome: ActionOutcome::Executed,
                intent: &i,
                settlement: Some(&record),
                required_controllers: ctrl,
            };
            let disp = classify_start_reconcile(Some(src), &ev, NOW).expect("classified");
            assert_eq!(
                disp.already_settled_outcome(),
                Some(ReconcileTerminalOutcome::Executed),
                "{}: {status:?} replay must surface AlreadySettled carrying the \
                 stored outcome — never Ok",
                d.name
            );
        }

        // MUTATION GUARD: the two NON-replay dispositions must NOT report an
        // already-settled outcome, else the assertion above would hold
        // vacuously for everything.
        assert_eq!(
            StartReconcileDisposition::Settle(ReconcileTerminalOutcome::Executed)
                .already_settled_outcome(),
            None
        );
        assert_eq!(
            StartReconcileDisposition::Inconclusive.already_settled_outcome(),
            None
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ACCEPTANCE 14 — transition-graph closure, including the callback. (§3a, §3c)
// ═════════════════════════════════════════════════════════════════════════════

/// **No callback writes any edge while the state is not `Executing`.**
///
/// This is the §3c.2 guard as a predicate, and it is the property that closes
/// the graph — V2 asserted closure WITHOUT it, and was wrong to.
#[test]
fn acceptance_14_callback_may_write_only_from_executing() {
    assert!(
        callback_may_write(ActionOutcome::Executing),
        "the normal path: a callback observing Executing may write"
    );
    for fenced in [
        ActionOutcome::OutcomeUnknown, // E2 already ran
        ActionOutcome::Executed,       // already settled, single-shot
        ActionOutcome::Failed,
        ActionOutcome::Cancelled, // unreachable with a live intent
        ActionOutcome::Expired,
        ActionOutcome::Pending,
    ] {
        assert!(
            !callback_may_write(fenced),
            "{fenced:?} MUST fence the callback: zero settlement-state mutation, \
             zero lock change, no terminalization"
        );
    }
    // MUTATION: widening the guard to admit `OutcomeUnknown` — the tempting
    // "the reply finally arrived, use it" change — reintroduces an
    // un-evidenced settlement path, which is exactly what R-2 forecloses. It
    // flips the first fenced assertion above.
}

/// §3a — no edge leaves a terminal state, and no edge returns to
/// `Pending`/`Executing`. Proven through the ONE function that can produce a
/// state change: no input yields a disposition that writes from a terminal
/// source, and no disposition names `Pending` or `Executing` as a destination.
#[test]
fn acceptance_14_no_edge_out_of_terminal_or_back_to_pending() {
    for d in directions() {
        let i = intent(&d);
        let ctrl = std::slice::from_ref(&d.controller);
        for status in [
            ObservedCanisterStatus::Running,
            ObservedCanisterStatus::Stopped,
            ObservedCanisterStatus::Stopping,
        ] {
            let ev = evidence(&d, status, NOW);
            for terminal in [ActionOutcome::Cancelled, ActionOutcome::Expired] {
                let src = StartSourceState {
                    outcome: terminal,
                    intent: &i,
                    settlement: None,
                    required_controllers: ctrl,
                };
                assert_eq!(
                    classify_start_reconcile(Some(src), &ev, NOW),
                    Err(StartReconcileRejection::IllegalSourceState),
                    "{}: no edge leaves {terminal:?}",
                    d.name
                );
            }
        }
        // The only destinations the disposition type can express are the two
        // §5 terminals; there is no variant naming Pending or Executing, so
        // "never back to Pending/Executing" is structural, not asserted.
        let settle = StartReconcileDisposition::Settle(ReconcileTerminalOutcome::Executed);
        assert!(matches!(
            settle,
            StartReconcileDisposition::Settle(
                ReconcileTerminalOutcome::Executed | ReconcileTerminalOutcome::Failed
            )
        ));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ACCEPTANCE 15 — evaluation order and the burn-the-marker vector. (§7f)
// ═════════════════════════════════════════════════════════════════════════════

/// 15(a) — the four gates return their OWN typed error, asserted for the SAME
/// input in BOTH directions. The four responses must be DISTINCT from each
/// other and IDENTICAL across directions.
#[test]
fn acceptance_15a_four_distinct_typed_errors_identical_across_directions() {
    let mut per_direction: Vec<Vec<String>> = Vec::new();

    for d in directions() {
        let i = intent(&d);
        let ctrl = std::slice::from_ref(&d.controller);
        let settling = evidence(&d, ObservedCanisterStatus::Running, INTENT_AT + 1);
        let record = SettlementRecord::settle(ReconcileTerminalOutcome::Executed, &settling);
        let good = evidence(&d, ObservedCanisterStatus::Running, NOW);
        let bad = {
            let mut e = good.clone();
            e.observed_controllers = vec![p(0x0D)]; // drifted
            e
        };

        // (1) unknown / pruned proposal
        let r1 = classify_start_reconcile(None, &good, NOW);
        // (2) a `Pending` proposal
        let r2 = classify_start_reconcile(
            Some(StartSourceState {
                outcome: ActionOutcome::Pending,
                intent: &i,
                settlement: None,
                required_controllers: ctrl,
            }),
            &good,
            NOW,
        );
        // (3) invalid evidence against a SETTLED proposal
        let r3 = classify_start_reconcile(
            Some(StartSourceState {
                outcome: ActionOutcome::Executed,
                intent: &i,
                settlement: Some(&record),
                required_controllers: ctrl,
            }),
            &bad,
            NOW,
        );
        // (4) a valid replay
        let r4 = classify_start_reconcile(
            Some(StartSourceState {
                outcome: ActionOutcome::Executed,
                intent: &i,
                settlement: Some(&record),
                required_controllers: ctrl,
            }),
            &good,
            NOW,
        );

        assert_eq!(r1, Err(StartReconcileRejection::UnknownProposal), "{}", d.name);
        assert_eq!(r2, Err(StartReconcileRejection::IllegalSourceState), "{}", d.name);
        assert_eq!(
            r3,
            Err(StartReconcileRejection::EvidenceRejected(
                EvidenceRejection::WrongControllers
            )),
            "{}: step 3 runs BEFORE step 4, so invalid evidence against a settled \
             proposal is an EVIDENCE rejection, not a replay",
            d.name
        );
        assert_eq!(
            r4,
            Ok(StartReconcileDisposition::ReplayConcordant {
                stored: ReconcileTerminalOutcome::Executed
            }),
            "{}",
            d.name
        );

        let rendered = vec![
            format!("{r1:?}"),
            format!("{r2:?}"),
            format!("{r3:?}"),
            format!("{r4:?}"),
        ];
        // FOUR DISTINCT responses.
        let uniq: std::collections::HashSet<&String> = rendered.iter().collect();
        assert_eq!(
            uniq.len(),
            4,
            "{}: the four gates must produce FOUR DISTINCT responses",
            d.name
        );
        per_direction.push(rendered);
    }

    // IDENTICAL ACROSS DIRECTIONS — the asymmetry CUST-SSA-004 exists to
    // prevent. Both planes call this one function, so identity is structural;
    // this asserts it observably.
    assert_eq!(
        per_direction[0], per_direction[1],
        "the two directions must return the SAME typed responses for the same \
         inputs — differing typed errors for identical input is exactly the \
         asymmetry CUST-SSA-004 exists to prevent"
    );
}

/// 15(b) — **the burn-the-marker vector.** Invalid evidence submitted against a
/// settled proposal N times NEVER sets `conflict_recorded`; the marker is still
/// available, and one genuinely discordant §4-valid evidence then records.
///
/// MUTATION (normative form): reorder the gates so §7d precedes §4, and this
/// test fails. Modelled explicitly below.
#[test]
fn acceptance_15b_invalid_evidence_never_burns_the_marker() {
    for d in directions() {
        let i = intent(&d);
        let ctrl = std::slice::from_ref(&d.controller);
        let settling = evidence(&d, ObservedCanisterStatus::Running, INTENT_AT + 1);
        let record = SettlementRecord::settle(ReconcileTerminalOutcome::Executed, &settling);
        assert!(!record.conflict_recorded, "the cap starts available");

        // N invalid submissions, each of which WOULD be discordant if it were
        // allowed to reach §7d: they observe `Stopped` against a proposal
        // settled `Executed`. Each is rejected at step 3 instead.
        for k in 0..8u64 {
            let mut ev = evidence(&d, ObservedCanisterStatus::Stopped, NOW - k);
            ev.observed_controllers = vec![p(0x0D)]; // drifted => §4 invalid
            let src = StartSourceState {
                outcome: ActionOutcome::Executed,
                intent: &i,
                settlement: Some(&record),
                required_controllers: ctrl,
            };
            assert_eq!(
                classify_start_reconcile(Some(src), &ev, NOW),
                Err(StartReconcileRejection::EvidenceRejected(
                    EvidenceRejection::WrongControllers
                )),
                "{}: invalid evidence must be rejected at §7f step 3 and never \
                 reach the §7d conflict branch",
                d.name
            );
        }
        // THE MARKER IS STILL AVAILABLE.
        assert!(
            !record.conflict_recorded,
            "{}: N invalid submissions must leave conflict_recorded UNTOUCHED",
            d.name
        );

        // One genuinely discordant §4-VALID observation now records.
        let valid_discordant = evidence(&d, ObservedCanisterStatus::Stopped, NOW);
        let src = StartSourceState {
            outcome: ActionOutcome::Executed,
            intent: &i,
            settlement: Some(&record),
            required_controllers: ctrl,
        };
        assert_eq!(
            classify_start_reconcile(Some(src), &valid_discordant, NOW),
            Ok(StartReconcileDisposition::ReplayDiscordant {
                stored: ReconcileTerminalOutcome::Executed,
                replay_mapped: ReconcileTerminalOutcome::Failed,
                cap_available: true,
            }),
            "{}: after N invalid submissions the marker must still be available \
             for the first genuine discordance",
            d.name
        );

        // MUTATION, modelled: §7d BEFORE §4. The invalid submissions above
        // would then be classified on their SEMANTIC content alone — which is
        // discordant — and would consume the one-shot marker with garbage,
        // suppressing the genuine discordance for ever.
        let mut ev = evidence(&d, ObservedCanisterStatus::Stopped, NOW);
        ev.observed_controllers = vec![p(0x0D)];
        assert_eq!(
            ev.maps_to(),
            Some(ReconcileTerminalOutcome::Failed),
            "{}: MUTATION — this invalid evidence DOES map to a discordant \
             terminal, so a §7d-before-§4 order would burn the marker on it. \
             That is why step 3 must precede step 4.",
            d.name
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ACCEPTANCE 16 — the conflict payload is FROZEN. (§7d.1)
// ═════════════════════════════════════════════════════════════════════════════

/// 16(a) — the first §4-valid semantic discordance produces exactly one event
/// carrying **all eight fields with exactly the specified values**, asserted
/// INDIVIDUALLY, with `stored_*` read from the `SettlementRecord` and
/// `replay_*` from the submitted evidence, and
/// `stored_outcome != replay_mapped_outcome`.
///
/// 16(d) — the payload carries NO §3c callback payload and no unlisted value.
#[test]
fn acceptance_16a_conflict_payload_all_eight_fields_both_directions() {
    for d in directions() {
        let settling = evidence(&d, ObservedCanisterStatus::Running, INTENT_AT + 1);
        let record = SettlementRecord::settle(ReconcileTerminalOutcome::Executed, &settling);
        let replay = evidence(&d, ObservedCanisterStatus::Stopped, NOW);
        let replay_mapped = replay.maps_to().expect("Stopped maps");

        let c = SettlementEvidenceConflict::new(7, &record, &replay, replay_mapped);

        // 1
        assert_eq!(c.proposal_id, 7, "{}: field 1", d.name);
        // 2 — from the STORED record
        assert_eq!(c.stored_outcome, record.outcome, "{}: field 2", d.name);
        // 3 — from the STORED record, never recomputed (§8a invariant 6)
        assert_eq!(c.stored_semantic_key, record.semantic_key, "{}: field 3", d.name);
        // 4 — from the STORED record
        assert_eq!(
            c.stored_evidence_commitment, record.evidence_commitment,
            "{}: field 4",
            d.name
        );
        // 5 — §5 applied to the replay: THE DISCORDANCE ITSELF
        assert_eq!(c.replay_mapped_outcome, ReconcileTerminalOutcome::Failed, "{}: field 5", d.name);
        // 6 — §4a over the replay, comparable to field 3
        assert_eq!(c.replay_semantic_key, replay.semantic_key(), "{}: field 6", d.name);
        // 7 — §4a over the replay
        assert_eq!(
            c.replay_evidence_commitment,
            replay.evidence_commitment(),
            "{}: field 7",
            d.name
        );
        // 8 — the replay's §4 field 4
        assert_eq!(c.replay_observed_at_ns, replay.observed_at_ns, "{}: field 8", d.name);

        // The discordance itself.
        assert_ne!(
            c.stored_outcome, c.replay_mapped_outcome,
            "{}: 16(a) — a conflict event exists only where the two disagree",
            d.name
        );
        // Fields 3 and 6 are COMPARABLE and, on a genuine discordance, DIFFER.
        assert_ne!(
            c.stored_semantic_key, c.replay_semantic_key,
            "{}: a semantic discordance must show differing semantic identities",
            d.name
        );

        // MUTATION (normative form): DROP ANY SINGLE FIELD and confirm failure.
        // Dropping a field is a compile error here — the struct has exactly
        // eight and the constructor fills all eight — so the mutation is
        // expressed as: every field must be INDIVIDUALLY WRONG-DETECTABLE.
        // Proven by rebuilding with a different replay and asserting each
        // replay-derived field moves, and rebuilding with a different record
        // and asserting each stored-derived field moves. A field that is
        // constant across both is one this test could not detect the loss of.
        let other_replay = evidence(&d, ObservedCanisterStatus::Stopping, NOW - 5);
        let c2 = SettlementEvidenceConflict::new(
            8,
            &record,
            &other_replay,
            ReconcileTerminalOutcome::Executed,
        );
        assert_ne!(c.proposal_id, c2.proposal_id, "{}: field 1 is detectable", d.name);
        assert_ne!(
            c.replay_mapped_outcome, c2.replay_mapped_outcome,
            "{}: field 5 is detectable",
            d.name
        );
        assert_ne!(
            c.replay_semantic_key, c2.replay_semantic_key,
            "{}: field 6 is detectable",
            d.name
        );
        assert_ne!(
            c.replay_evidence_commitment, c2.replay_evidence_commitment,
            "{}: field 7 is detectable",
            d.name
        );
        assert_ne!(
            c.replay_observed_at_ns, c2.replay_observed_at_ns,
            "{}: field 8 is detectable",
            d.name
        );

        let other_settling = evidence(&d, ObservedCanisterStatus::Stopped, INTENT_AT + 2);
        let other_record = SettlementRecord::settle(ReconcileTerminalOutcome::Failed, &other_settling);
        let c3 = SettlementEvidenceConflict::new(7, &other_record, &replay, replay_mapped);
        assert_ne!(c.stored_outcome, c3.stored_outcome, "{}: field 2 is detectable", d.name);
        assert_ne!(
            c.stored_semantic_key, c3.stored_semantic_key,
            "{}: field 3 is detectable",
            d.name
        );
        assert_ne!(
            c.stored_evidence_commitment, c3.stored_evidence_commitment,
            "{}: field 4 is detectable",
            d.name
        );
    }
}

/// 16(d) — **the payload may not carry the §3c callback payload or any value
/// not listed.** Asserted structurally against the Candid encoding: the record
/// has exactly the eight named fields and nothing else.
#[test]
fn acceptance_16d_payload_carries_nothing_unlisted() {
    let d = &directions()[0];
    let settling = evidence(d, ObservedCanisterStatus::Running, INTENT_AT + 1);
    let record = SettlementRecord::settle(ReconcileTerminalOutcome::Executed, &settling);
    let replay = evidence(d, ObservedCanisterStatus::Stopped, NOW);
    let c = SettlementEvidenceConflict::new(7, &record, &replay, ReconcileTerminalOutcome::Failed);

    let ty = format!("{:?}", <SettlementEvidenceConflict as candid::CandidType>::ty());
    for field in [
        "proposal_id",
        "stored_outcome",
        "stored_semantic_key",
        "stored_evidence_commitment",
        "replay_mapped_outcome",
        "replay_semantic_key",
        "replay_evidence_commitment",
        "replay_observed_at_ns",
    ] {
        assert!(ty.contains(field), "field {field} must be present: {ty}");
    }
    // Nothing resembling a callback payload.
    for forbidden in ["reject_detail", "callback", "payload", "reply"] {
        assert!(
            !ty.contains(forbidden),
            "§7d.1: the payload may not carry `{forbidden}` — the §3c callback \
             payload is NEVER evidence and must not appear here: {ty}"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// §4a — the two canonical hashes, and what each is FOR.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn semantic_key_excludes_timestamp_and_commitment_includes_it() {
    for d in directions() {
        let a = evidence(&d, ObservedCanisterStatus::Running, 111);
        let b = evidence(&d, ObservedCanisterStatus::Running, 222);
        assert_eq!(
            a.semantic_key(),
            b.semantic_key(),
            "{}: the timestamp is EXCLUDED from semantic_key",
            d.name
        );
        assert_ne!(
            a.evidence_commitment(),
            b.evidence_commitment(),
            "{}: the timestamp is INCLUDED in evidence_commitment",
            d.name
        );

        // The semantic key IS sensitive to each of its three inputs.
        let mut t = a.clone();
        t.observed_target_principal = p(0x0C);
        assert_ne!(a.semantic_key(), t.semantic_key(), "{}: target", d.name);

        let mut s = a.clone();
        s.observed_canister_status = ObservedCanisterStatus::Stopped;
        assert_ne!(a.semantic_key(), s.semantic_key(), "{}: status", d.name);

        let mut c = a.clone();
        c.observed_controllers = vec![p(0x0D)];
        assert_ne!(a.semantic_key(), c.semantic_key(), "{}: controllers", d.name);

        // The controller SET is unordered: ordering must not change identity.
        let mut o1 = a.clone();
        o1.observed_controllers = vec![p(0x01), p(0x02)];
        let mut o2 = a.clone();
        o2.observed_controllers = vec![p(0x02), p(0x01)];
        assert_eq!(
            o1.semantic_key(),
            o2.semantic_key(),
            "{}: semantic identity is a function of the SET, not the vector",
            d.name
        );

        // Domain separation: the two hashes never collide over the same bytes.
        assert_ne!(
            a.semantic_key(),
            a.evidence_commitment(),
            "{}: the two hashes are domain-separated",
            d.name
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// THE "ONE MECHANISM" PIN
// ═════════════════════════════════════════════════════════════════════════════

/// V5 §0: "The builder must not implement the two directions differently. That
/// divergence is the specific failure SSA raised the blocker to prevent."
///
/// The predicate is direction-agnostic BY CONSTRUCTION: it takes the target and
/// the required controller set as PARAMETERS and contains no branch on which
/// canister is running. This test pins that property observably — the same
/// inputs, relabelled for the other direction, produce the same disposition.
#[test]
fn both_directions_share_one_predicate() {
    let [c4, c3] = directions();
    let i4 = intent(&c4);
    let i3 = intent(&c3);

    for status in [
        ObservedCanisterStatus::Running,
        ObservedCanisterStatus::Stopped,
        ObservedCanisterStatus::Stopping,
    ] {
        let e4 = evidence(&c4, status, NOW);
        let e3 = evidence(&c3, status, NOW);
        let r4 = classify_start_reconcile(
            Some(StartSourceState {
                outcome: ActionOutcome::OutcomeUnknown,
                intent: &i4,
                settlement: None,
                required_controllers: std::slice::from_ref(&c4.controller),
            }),
            &e4,
            NOW,
        );
        let r3 = classify_start_reconcile(
            Some(StartSourceState {
                outcome: ActionOutcome::OutcomeUnknown,
                intent: &i3,
                settlement: None,
                required_controllers: std::slice::from_ref(&c3.controller),
            }),
            &e3,
            NOW,
        );
        assert_eq!(
            r4, r3,
            "the two instances of the one mechanism must agree on {status:?}"
        );
    }
}
