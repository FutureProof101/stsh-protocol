use super::*;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Frozen {
    ledger: Principal,
    from_subaccount: Option<Vec<u8>>,
    destination: Principal,
    destination_subaccount: Option<Vec<u8>>,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
enum Phase {
    PreDispatch,
    MayHaveDispatched,
}
#[derive(CandidType, Deserialize, Clone, Debug)]
struct Retry {
    memo_sequence: u128,
    generation: u64,
    boot: u64,
    phase: Phase,
    prior_ambiguity: bool,
    dispatched: bool,
    frozen: Option<Frozen>,
}
#[derive(CandidType, Deserialize, Clone, Debug)]
struct Payout {
    retry: Option<Retry>,
    block_index: Option<Nat>,
}
#[derive(CandidType, Deserialize, Clone, Debug)]
struct Record {
    public_payout: Option<Payout>,
    status: SpendStatus,
}
fn record(pic: &PocketIc, s: &Stack, id: u64) -> Record {
    decode::<Option<Record>, _>(
        "record",
        pic.query_call(
            s.pool,
            s.controller,
            "get_spend_status",
            candid::encode_one(id).unwrap(),
        ),
    )
    .unwrap()
}
fn retry(pic: &PocketIc, s: &Stack, caller: Principal, id: u64) -> Result<Nat, PoolError> {
    decode(
        "retry",
        pic.update_call(
            s.pool,
            caller,
            "retry_private_spend_payout",
            candid::encode_one(id).unwrap(),
        ),
    )
}
fn fault(pic: &PocketIc, s: &Stack, id: u64, mode: u8) {
    let _: () = decode(
        "fault",
        pic.update_call(
            s.pool,
            s.controller,
            "r15_fault_for_test",
            candid::encode_args((id, mode)).unwrap(),
        ),
    );
    if mode == 0 {
        for request in pic
            .get_canister_http()
            .into_iter()
            .filter(|r| r.url == format!("https://r15.invalid/{}", id))
        {
            release_http(pic, request);
        }
    }
}
fn fee(pic: &PocketIc, s: &Stack, amount: u128) {
    let _: () = decode(
        "fee",
        pic.update_call(
            s.token,
            s.controller,
            "r15_set_transfer_fee_for_test",
            candid::encode_one(amount).unwrap(),
        ),
    );
}
fn live(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "live",
        pic.query_call(
            s.pool,
            s.controller,
            "r15_live_for_test",
            candid::encode_args(()).unwrap(),
        ),
    )
}
fn setup() -> (PocketIc, Stack) {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);
    fund_pool_1000(&pic, &s);
    (pic, s)
}
#[test]
fn executed_unknown_fee_drift_never_reprices_and_duplicate_settles() {
    let (pic, s) = setup();
    let dest = p(0x71);
    let amount = 100 * STSH;
    inject_payout_pending(&pic, &s, 15001, dest, amount);
    fault(&pic, &s, 15001, 1);
    assert!(retry(&pic, &s, s.controller, 15001).is_err());
    assert_eq!(token_balance(&pic, &s, dest), amount);
    let frozen = record(&pic, &s, 15001)
        .public_payout
        .unwrap()
        .retry
        .unwrap()
        .frozen
        .unwrap();
    assert_eq!(frozen.memo.as_ref().unwrap().len(), 32);
    fee(&pic, &s, 10);
    let r: Result<ReconcilePayoutResult, PoolError> = decode(
        "reopen",
        reconcile_payout(&pic, &s, s.controller, 15001, PayoutOutcome::NotExecuted),
    );
    assert_eq!(r, Ok(ReconcilePayoutResult::RevertedToPending));
    fault(&pic, &s, 15001, 0);
    assert!(retry(&pic, &s, s.controller, 15001).is_err());
    assert_eq!(token_balance(&pic, &s, dest), amount);
    assert_eq!(
        record(&pic, &s, 15001)
            .public_payout
            .unwrap()
            .retry
            .unwrap()
            .frozen
            .unwrap(),
        frozen
    );
    assert!(matches!(
        spend_status(&pic, &s, 15001),
        Some(SpendStatus::PayoutUnknown { .. })
    ));
    fee(&pic, &s, 0);
    let _: Result<ReconcilePayoutResult, PoolError> = decode(
        "reopen",
        reconcile_payout(&pic, &s, s.controller, 15001, PayoutOutcome::NotExecuted),
    );
    assert!(retry(&pic, &s, s.controller, 15001).is_ok());
    assert_eq!(token_balance(&pic, &s, dest), amount);
    assert_eq!(
        record(&pic, &s, 15001)
            .public_payout
            .unwrap()
            .retry
            .unwrap()
            .frozen
            .unwrap(),
        frozen
    );
}
#[test]
fn rejected_balance_query_releases_claim_and_later_retry_completes() {
    let (pic, s) = setup();
    let dest = p(0x72);
    inject_payout_pending(&pic, &s, 15002, dest, 100 * STSH);
    pic.stop_canister(s.token, None).unwrap();
    assert!(retry(&pic, &s, s.controller, 15002).is_err());
    assert!(matches!(
        spend_status(&pic, &s, 15002),
        Some(SpendStatus::PayoutPending { .. })
    ));
    assert_eq!(live(&pic, &s), 0);
    pic.start_canister(s.token, None).unwrap();
    assert_eq!(token_balance(&pic, &s, dest), 0);
    assert!(retry(&pic, &s, s.controller, 15002).is_ok());
    assert_eq!(token_balance(&pic, &s, dest), 100 * STSH);
}
#[test]
fn actual_post_dispatch_callback_trap_releases_executor_but_preserves_unknown() {
    let (pic, s) = setup();
    let dest = p(0x73);
    inject_payout_pending(&pic, &s, 15003, dest, 100 * STSH);
    fault(&pic, &s, 15003, 2);
    assert!(pic
        .update_call(
            s.pool,
            s.controller,
            "retry_private_spend_payout",
            candid::encode_one(15003u64).unwrap()
        )
        .is_err());
    assert_eq!(token_balance(&pic, &s, dest), 100 * STSH);
    assert_eq!(live(&pic, &s), 0, "actual CDK cleanup must drop guard");
    assert!(retry(&pic, &s, s.controller, 15003).is_err());
    assert!(matches!(
        spend_status(&pic, &s, 15003),
        Some(SpendStatus::PayoutUnknown { .. })
    ));
    assert!(
        record(&pic, &s, 15003)
            .public_payout
            .unwrap()
            .retry
            .unwrap()
            .prior_ambiguity
    );
    assert_eq!(token_balance(&pic, &s, dest), 100 * STSH);
}
#[test]
fn actual_pre_dispatch_callback_trap_is_permissionlessly_recoverable() {
    let (pic, s) = setup();
    let dest = p(0x74);
    inject_payout_pending(&pic, &s, 15004, dest, 100 * STSH);
    fault(&pic, &s, 15004, 3);
    assert!(pic
        .update_call(
            s.pool,
            s.controller,
            "retry_private_spend_payout",
            candid::encode_one(15004u64).unwrap()
        )
        .is_err());
    assert_eq!(token_balance(&pic, &s, dest), 0);
    assert_eq!(live(&pic, &s), 0);
    fault(&pic, &s, 15004, 0);
    assert_eq!(
        retry(&pic, &s, anon(), 15004),
        Err(PoolError::PayoutOutcomePrivate)
    );
    assert_eq!(token_balance(&pic, &s, dest), 100 * STSH);
    assert!(retry(&pic, &s, s.controller, 15004).is_ok());
}
#[test]
fn foreign_candid_bytes_identical_for_absent_underfunded_unknown_and_success() {
    let (pic, s) = setup();
    let dest = p(0x75);
    let call = |id| {
        pic.update_call(
            s.pool,
            anon(),
            "retry_private_spend_payout",
            candid::encode_one(id).unwrap(),
        )
        .unwrap()
    };
    let absent = call(15999u64);
    assert_eq!(
        candid::decode_one::<Result<Nat, PoolError>>(&absent).unwrap(),
        Err(PoolError::PayoutOutcomePrivate)
    );
    inject_payout_pending(&pic, &s, 15005, dest, TOTAL_SUPPLY);
    assert_eq!(call(15005), absent);
    inject_payout_pending(&pic, &s, 15006, dest, 100 * STSH);
    fault(&pic, &s, 15006, 1);
    assert_eq!(call(15006), absent);
    assert_eq!(call(15006), absent);
    inject_payout_pending(&pic, &s, 15007, dest, 100 * STSH);
    assert_eq!(call(15007), absent);
    assert_eq!(call(15007), absent);
    assert_eq!(token_balance(&pic, &s, dest), 200 * STSH);
}
#[test]
fn low_balance_duplicate_and_window_exhaustion_keep_frozen_identity() {
    let (pic, s) = setup();
    let dest = p(0x76);
    let balance = token_balance(&pic, &s, s.pool);
    inject_payout_pending(&pic, &s, 15008, dest, balance);
    fault(&pic, &s, 15008, 1);
    assert!(retry(&pic, &s, s.controller, 15008).is_err());
    assert_eq!(token_balance(&pic, &s, s.pool), 0);
    let f = record(&pic, &s, 15008)
        .public_payout
        .unwrap()
        .retry
        .unwrap()
        .frozen
        .unwrap();
    let _: Result<ReconcilePayoutResult, PoolError> = decode(
        "reopen",
        reconcile_payout(&pic, &s, s.controller, 15008, PayoutOutcome::NotExecuted),
    );
    fault(&pic, &s, 15008, 0);
    assert!(retry(&pic, &s, s.controller, 15008).is_ok());
    assert_eq!(token_balance(&pic, &s, dest), balance);
    assert_eq!(
        record(&pic, &s, 15008)
            .public_payout
            .unwrap()
            .retry
            .unwrap()
            .frozen
            .unwrap(),
        f
    );

    let (pic, s) = setup();
    inject_payout_pending(&pic, &s, 15009, dest, 100 * STSH);
    fault(&pic, &s, 15009, 1);
    assert!(retry(&pic, &s, s.controller, 15009).is_err());
    let f = record(&pic, &s, 15009)
        .public_payout
        .unwrap()
        .retry
        .unwrap()
        .frozen
        .unwrap();
    pic.advance_time(std::time::Duration::from_secs(25 * 3600));
    let _: Result<ReconcilePayoutResult, PoolError> = decode(
        "reopen",
        reconcile_payout(&pic, &s, s.controller, 15009, PayoutOutcome::NotExecuted),
    );
    fault(&pic, &s, 15009, 0);
    assert!(retry(&pic, &s, s.controller, 15009).is_err());
    assert_eq!(token_balance(&pic, &s, dest), 100 * STSH);
    assert_eq!(
        record(&pic, &s, 15009)
            .public_payout
            .unwrap()
            .retry
            .unwrap()
            .frozen
            .unwrap(),
        f
    );
}
#[test]
fn capacity_64_real_suspended_executors_refuses_65_then_releases_exact_slot() {
    let (pic, s) = setup();
    pic.add_cycles(s.pool, 100_000_000_000_000);
    let dest = p(0x77);
    for id in 16000..16065 {
        inject_payout_pending(&pic, &s, id, dest, STSH);
        if id < 16064 {
            fault(&pic, &s, id, 4);
        }
    }
    let calls: Vec<_> = (16000..16064)
        .map(|id| {
            pic.submit_call(
                s.pool,
                s.controller,
                "retry_private_spend_payout",
                candid::encode_one(id as u64).unwrap(),
            )
            .unwrap()
        })
        .collect();
    for _ in 0..256 {
        if live(&pic, &s) == 64 {
            break;
        }
        pic.tick();
    }
    assert_eq!(live(&pic, &s), 64);
    assert_eq!(token_balance(&pic, &s, dest), 0);
    // Inline promotion reaches irreversible accounting/nullifier finality but
    // saturation must leave an owed Pending payout and release the append lease.
    let args = PrivateSpendArgs {
        spend_id: 17000,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".into(),
            verifying_key_hash: [0; 32],
            root_reference: merkle_root(&pic, &s),
            pool_version: 1,
            proof_bytes: vec![0; 8],
        },
        nullifiers: vec![[0x2f; 32]],
        output_commitments: vec![[0x20; 32], [0x21; 32]],
        encrypted_outputs: vec![vec![], vec![]],
        fee: 0,
        public_payout: Some(PrivateSpendPublicPayout {
            destination: dest,
            destination_subaccount: None,
            public_amount: SPEND_PUBLIC_AMOUNT,
        }),
    };
    let inline: Result<(), PoolError> = decode(
        "inline saturation",
        pic.update_call(
            s.pool,
            s.user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );
    assert_eq!(inline, Ok(())); // Accepted spend; the durable Pending obligation remains.
    assert!(matches!(
        spend_status(&pic, &s, 17000),
        Some(SpendStatus::PayoutPending { .. })
    ));
    assert_eq!(token_balance(&pic, &s, dest), 0);
    assert_eq!(
        retry(&pic, &s, s.controller, 16064),
        Err(PoolError::PayoutExecutorBusy)
    );
    assert!(matches!(
        spend_status(&pic, &s, 16064),
        Some(SpendStatus::PayoutPending { .. })
    ));
    let refused: Result<ReconcilePayoutResult, PoolError> = decode(
        "live reconciliation",
        reconcile_payout(&pic, &s, s.controller, 16000, PayoutOutcome::NotExecuted),
    );
    assert_eq!(refused, Err(PoolError::PayoutNotPending));
    fault(&pic, &s, 16000, 0);
    let done: Result<Nat, PoolError> = decode("first release", pic.await_call(calls[0].clone()));
    assert!(done.is_ok());
    assert_eq!(live(&pic, &s), 63);
    assert!(retry(&pic, &s, s.controller, 16064).is_ok());
    assert_eq!(live(&pic, &s), 63);
    for request in pic.get_canister_http().into_iter().rev() {
        release_http(&pic, request);
    }
    for call in calls.into_iter().skip(1) {
        let done: Result<Nat, PoolError> = decode("release", pic.await_call(call));
        assert!(done.is_ok());
    }
    assert_eq!(live(&pic, &s), 0);
    assert_eq!(token_balance(&pic, &s, dest), 65 * STSH);
}
#[test]
fn live_post_ledger_executor_cannot_be_reconciled_or_retried() {
    let (pic, s) = setup();
    let dest = p(0x78);
    inject_payout_pending(&pic, &s, 15010, dest, STSH);
    fault(&pic, &s, 15010, 5);
    let call = pic
        .submit_call(
            s.pool,
            s.controller,
            "retry_private_spend_payout",
            candid::encode_one(15010u64).unwrap(),
        )
        .unwrap();
    for _ in 0..15 {
        pic.tick();
    }
    assert_eq!(token_balance(&pic, &s, dest), STSH);
    assert_eq!(live(&pic, &s), 1);
    let r: Result<ReconcilePayoutResult, PoolError> = decode(
        "reconcile",
        reconcile_payout(
            &pic,
            &s,
            s.controller,
            15010,
            PayoutOutcome::Executed { block_index: 0 },
        ),
    );
    assert_eq!(r, Err(PoolError::PayoutNotPending));
    assert_eq!(
        retry(&pic, &s, s.controller, 15010),
        Err(PoolError::PayoutNotPending)
    );
    fault(&pic, &s, 15010, 0);
    let r: Result<Nat, PoolError> = decode("release", pic.await_call(call));
    assert!(r.is_ok());
    assert_eq!(token_balance(&pic, &s, dest), STSH);
}
fn upgrade(pic: &PocketIc, s: &Stack) {
    pic.upgrade_canister(
        s.pool,
        pool_test_wasm(),
        candid::encode_args(()).unwrap(),
        None,
    )
    .unwrap();
}
fn ready(pic: &PocketIc, s: &Stack) -> Option<bool> {
    decode(
        "key readiness",
        pic.query_call(
            s.pool,
            s.controller,
            "payout_memo_key_ready",
            candid::encode_args(()).unwrap(),
        ),
    )
}
#[test]
fn true_predecessor_legacy_pending_unknown_submitting_and_terminal_upgrade() {
    let pic = PocketIc::new();
    let s = deploy_stack_with_pool(
        &pic,
        load_wasm(env!("POOL_PRE_R15_TEST_WASM"), "R15 predecessor"),
        false,
    );
    for id in 18000..18004 {
        inject_payout_pending(&pic, &s, id, p(0x79), STSH);
    }
    set_spend_status(
        &pic,
        &s,
        18001,
        SpendStatus::PayoutUnknown {
            reason: "legacy unknown".into(),
        },
    );
    set_spend_status(&pic, &s, 18002, SpendStatus::PayoutSubmitting);
    set_spend_status(
        &pic,
        &s,
        18003,
        SpendStatus::PayoutUnknown {
            reason: "legacy terminal setup".into(),
        },
    );
    let r: Result<ReconcilePayoutResult, PoolError> = decode(
        "legacy executed",
        reconcile_payout(
            &pic,
            &s,
            s.controller,
            18003,
            PayoutOutcome::Executed { block_index: 53 },
        ),
    );
    assert!(r.is_ok());
    upgrade(&pic, &s);
    assert_eq!(ready(&pic, &s), Some(false));
    for id in 18000..18003 {
        assert!(record(&pic, &s, id).public_payout.unwrap().retry.is_none());
        assert!(retry(&pic, &s, s.controller, id).is_err());
        let r: Result<ReconcilePayoutResult, PoolError> = decode(
            "legacy refuses invention",
            reconcile_payout(&pic, &s, s.controller, id, PayoutOutcome::NotExecuted),
        );
        assert_eq!(r, Err(PoolError::PayoutLegacyHold));
        let r: Result<ReconcilePayoutResult, PoolError> = decode(
            "legacy trusted executed",
            reconcile_payout(
                &pic,
                &s,
                s.controller,
                id,
                PayoutOutcome::Executed { block_index: id },
            ),
        );
        assert!(r.is_ok());
        assert_eq!(
            record(&pic, &s, id).public_payout.unwrap().block_index,
            Some(Nat::from(id))
        );
    }
    assert_eq!(retry(&pic, &s, s.controller, 18003), Ok(Nat::from(53u8)));
    assert_eq!(ready(&pic, &s), Some(false));
}
#[test]
fn frozen_unknown_upgrade_preserves_key_sequence_payload_and_duplicate() {
    let (pic, s) = setup();
    let dest = p(0x7a);
    inject_payout_pending(&pic, &s, 18010, dest, STSH);
    fault(&pic, &s, 18010, 1);
    assert!(retry(&pic, &s, s.controller, 18010).is_err());
    let before = record(&pic, &s, 18010)
        .public_payout
        .unwrap()
        .retry
        .unwrap();
    upgrade(&pic, &s);
    assert_eq!(ready(&pic, &s), Some(true));
    let after = record(&pic, &s, 18010)
        .public_payout
        .unwrap()
        .retry
        .unwrap();
    assert_eq!(after.memo_sequence, before.memo_sequence);
    assert_eq!(after.frozen, before.frozen);
    let _: Result<ReconcilePayoutResult, PoolError> = decode(
        "reopen",
        reconcile_payout(&pic, &s, s.controller, 18010, PayoutOutcome::NotExecuted),
    );
    assert!(retry(&pic, &s, s.controller, 18010).is_ok());
    let settled = record(&pic, &s, 18010)
        .public_payout
        .unwrap()
        .retry
        .unwrap();
    assert!(settled.boot > before.boot);
    assert_eq!(settled.frozen, before.frozen);
    assert_eq!(token_balance(&pic, &s, dest), STSH);
}
#[test]
fn malformed_frozen_payloads_refuse_before_dispatch() {
    let (pic, s) = setup();
    let dest = p(0x7b);
    for mode in 0..7u8 {
        let id = 18100 + u64::from(mode);
        inject_payout_pending(&pic, &s, id, dest, STSH);
        fault(&pic, &s, id, 1);
        assert!(retry(&pic, &s, s.controller, id).is_err());
        let _: () = decode(
            "corrupt",
            pic.update_call(
                s.pool,
                s.controller,
                "r15_corrupt_frozen_for_test",
                candid::encode_args((id, mode)).unwrap(),
            ),
        );
        assert_eq!(
            retry(&pic, &s, s.controller, id),
            Err(PoolError::PayoutStateInvalid)
        );
        assert_eq!(live(&pic, &s), 0);
    }
    assert_eq!(token_balance(&pic, &s, dest), 7 * STSH);
}
#[test]
fn missing_or_corrupt_current_control_cell_rejects_upgrade_without_regeneration() {
    for mode in [0u8, 3] {
        let (pic, s) = setup();
        let _: () = decode(
            "corrupt control",
            pic.update_call(
                s.pool,
                s.controller,
                "r15_control_fault_for_test",
                candid::encode_one(mode).unwrap(),
            ),
        );
        assert!(pic
            .upgrade_canister(
                s.pool,
                pool_test_wasm(),
                candid::encode_args(()).unwrap(),
                None
            )
            .is_err());
    }
}
fn accrual(pic: &PocketIc, s: &Stack) -> Vec<u128> {
    decode(
        "accrual",
        pic.query_call(
            s.pool,
            s.controller,
            "r15_accrual_for_test",
            candid::encode_args(()).unwrap(),
        ),
    )
}
#[test]
fn terminal_accrual_uses_original_split_once_for_retry_duplicate_and_reconcile() {
    let (pic, s) = setup();
    let dest = p(0x7c);
    let before = accrual(&pic, &s);
    for (offset, mode) in [0u8, 1, 1].into_iter().enumerate() {
        let id = 18200 + offset as u64;
        inject_payout_pending(&pic, &s, id, dest, STSH);
        let _: () = decode(
            "split",
            pic.update_call(
                s.pool,
                s.controller,
                "r15_fixture_split_for_test",
                candid::encode_args((id, 11u128, 13u128, 17u128)).unwrap(),
            ),
        );
        fault(&pic, &s, id, mode);
        let initial = retry(&pic, &s, s.controller, id);
        if mode == 0 {
            assert!(initial.is_ok());
        } else if offset == 1 {
            let _: Result<ReconcilePayoutResult, PoolError> = decode(
                "reopen",
                reconcile_payout(&pic, &s, s.controller, id, PayoutOutcome::NotExecuted),
            );
            fault(&pic, &s, id, 0);
            assert!(retry(&pic, &s, s.controller, id).is_ok());
        } else {
            let r: Result<ReconcilePayoutResult, PoolError> = decode(
                "executed",
                reconcile_payout(
                    &pic,
                    &s,
                    s.controller,
                    id,
                    PayoutOutcome::Executed { block_index: 7 },
                ),
            );
            assert!(r.is_ok());
        }
        assert!(retry(&pic, &s, s.controller, id).is_ok());
        let _: Result<ReconcilePayoutResult, PoolError> = decode(
            "repeat",
            reconcile_payout(
                &pic,
                &s,
                s.controller,
                id,
                PayoutOutcome::Executed { block_index: 99 },
            ),
        );
    }
    let after = accrual(&pic, &s);
    assert_eq!(after, vec![before[0] + 33, before[1] + 39, before[2] + 51]);
}

fn release_http(pic: &PocketIc, request: pocket_ic::common::rest::CanisterHttpRequest) {
    use pocket_ic::common::rest::{
        CanisterHttpReply, CanisterHttpResponse, MockCanisterHttpResponse,
    };
    pic.mock_canister_http_response(MockCanisterHttpResponse {
        subnet_id: request.subnet_id,
        request_id: request.request_id,
        response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 200,
            headers: vec![],
            body: vec![],
        }),
        additional_responses: vec![],
    });
}
fn public_control(pic: &PocketIc, s: &Stack) -> (u64, u128, bool) {
    candid::decode_args(
        &pic.query_call(
            s.pool,
            s.controller,
            "r15_control_public_for_test",
            candid::encode_args(()).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}
fn provision(pic: &PocketIc, s: &Stack) -> Result<bool, PoolError> {
    decode(
        "provision",
        pic.update_call(
            s.pool,
            s.controller,
            "initialize_payout_memo_key",
            candid::encode_args(()).unwrap(),
        ),
    )
}
#[test]
fn random_failure_malformed_reply_and_concurrent_late_provision_preserve_counters() {
    for mode in [1u8, 2] {
        let pic = PocketIc::new();
        let s = deploy_stack_with_pool(&pic, pool_test_wasm(), false);
        let _: () = decode(
            "provision mode",
            pic.update_call(
                s.pool,
                s.controller,
                "r15_provision_fault_for_test",
                candid::encode_one(mode).unwrap(),
            ),
        );
        assert_eq!(provision(&pic, &s), Err(PoolError::PayoutMemoKeyNotReady));
        assert_eq!(ready(&pic, &s), Some(false));
        let _: () = decode(
            "clear mode",
            pic.update_call(
                s.pool,
                s.controller,
                "r15_provision_fault_for_test",
                candid::encode_one(0u8).unwrap(),
            ),
        );
        assert_eq!(provision(&pic, &s), Ok(true));
    }
    let pic = PocketIc::new();
    let s = deploy_stack_with_pool(&pic, pool_test_wasm(), false);
    let _: () = decode(
        "race mode",
        pic.update_call(
            s.pool,
            s.controller,
            "r15_provision_fault_for_test",
            candid::encode_one(3u8).unwrap(),
        ),
    );
    fault(&pic, &s, 0, 4);
    let a = pic
        .submit_call(
            s.pool,
            s.controller,
            "initialize_payout_memo_key",
            candid::encode_args(()).unwrap(),
        )
        .unwrap();
    let b = pic
        .submit_call(
            s.pool,
            s.controller,
            "initialize_payout_memo_key",
            candid::encode_args(()).unwrap(),
        )
        .unwrap();
    for _ in 0..16 {
        pic.tick();
    }
    assert_eq!(ready(&pic, &s), Some(true)); // whichever ingress won committed the first result
    assert!(
        !pic.get_canister_http().is_empty(),
        "second raw_rand result really held"
    );
    inject_payout_pending(&pic, &s, 18300, p(0x7d), STSH);
    let before = public_control(&pic, &s);
    assert_eq!(before.1, 1);
    fault(&pic, &s, 0, 0);
    for message in [a, b] {
        let result: Result<bool, PoolError> =
            decode("provision completion", pic.await_call(message));
        assert_eq!(result, Ok(true));
    }
    assert_eq!(public_control(&pic, &s), before);
}
#[test]
fn oversized_nat_balance_is_safe_preflight_error() {
    let (pic, s) = setup();
    let dest = p(0x7e);
    inject_payout_pending(&pic, &s, 18301, dest, STSH);
    let _: () = decode(
        "oversize",
        pic.update_call(
            s.token,
            s.controller,
            "r15_balance_oversize_for_test",
            candid::encode_one(true).unwrap(),
        ),
    );
    assert!(retry(&pic, &s, s.controller, 18301).is_err());
    assert_eq!(live(&pic, &s), 0);
    assert!(matches!(
        spend_status(&pic, &s, 18301),
        Some(SpendStatus::PayoutPending { .. })
    ));
    let _: () = decode(
        "restore",
        pic.update_call(
            s.token,
            s.controller,
            "r15_balance_oversize_for_test",
            candid::encode_one(false).unwrap(),
        ),
    );
    assert_eq!(token_balance(&pic, &s, dest), 0);
    assert!(retry(&pic, &s, s.controller, 18301).is_ok());
}
#[derive(CandidType, Serialize)]
struct Prune {
    older_than_ns: u64,
    max_records: u64,
    prune_spends: bool,
    prune_deposits: bool,
    scan_legacy_spends: bool,
    scan_legacy_deposits: bool,
    max_scan_records: u64,
    legacy_spend_cursor: Option<u64>,
    legacy_deposit_cursor: Option<Vec<u8>>,
}
#[derive(CandidType, Deserialize)]
struct Pruned {
    spends_pruned: u64,
}
#[test]
fn real_terminal_pruning_and_reused_id_never_repeat_memo_or_sequence() {
    let (pic, s) = setup();
    let dest = p(0x7f);
    inject_payout_pending(&pic, &s, 18302, dest, STSH);
    assert!(retry(&pic, &s, s.controller, 18302).is_ok());
    let old = record(&pic, &s, 18302)
        .public_payout
        .unwrap()
        .retry
        .unwrap();
    let result: Pruned = decode(
        "prune",
        pic.update_call(
            s.pool,
            s.controller,
            "prune_terminal_records",
            candid::encode_one(Prune {
                older_than_ns: u64::MAX,
                max_records: 10,
                prune_spends: true,
                prune_deposits: false,
                scan_legacy_spends: false,
                scan_legacy_deposits: false,
                max_scan_records: 0,
                legacy_spend_cursor: None,
                legacy_deposit_cursor: None,
            })
            .unwrap(),
        ),
    );
    assert_eq!(result.spends_pruned, 1);
    inject_payout_pending(&pic, &s, 18302, dest, STSH);
    assert!(retry(&pic, &s, s.controller, 18302).is_ok());
    let new = record(&pic, &s, 18302)
        .public_payout
        .unwrap()
        .retry
        .unwrap();
    assert!(new.memo_sequence > old.memo_sequence);
    assert_ne!(new.frozen.unwrap().memo, old.frozen.unwrap().memo);
    assert_eq!(token_balance(&pic, &s, dest), 2 * STSH);
}
#[test]
fn frozen_memo_survives_test_key_change() {
    let (pic, s) = setup();
    let dest = p(0x80);
    inject_payout_pending(&pic, &s, 18303, dest, STSH);
    fault(&pic, &s, 18303, 1);
    assert!(retry(&pic, &s, s.controller, 18303).is_err());
    let old = record(&pic, &s, 18303)
        .public_payout
        .unwrap()
        .retry
        .unwrap()
        .frozen;
    let _: () = decode(
        "test key change",
        pic.update_call(
            s.pool,
            s.controller,
            "r15_control_fault_for_test",
            candid::encode_one(2u8).unwrap(),
        ),
    );
    let _: Result<ReconcilePayoutResult, PoolError> = decode(
        "reopen",
        reconcile_payout(&pic, &s, s.controller, 18303, PayoutOutcome::NotExecuted),
    );
    fault(&pic, &s, 18303, 0);
    assert!(retry(&pic, &s, s.controller, 18303).is_ok());
    assert_eq!(
        record(&pic, &s, 18303)
            .public_payout
            .unwrap()
            .retry
            .unwrap()
            .frozen,
        old
    );
    assert_eq!(token_balance(&pic, &s, dest), STSH);
}
mod baseline;
#[test]
fn actual_upgrade_discards_held_futures_and_keyed_recovery_preserves_phase() {
    for mode in [4u8, 5] {
        let (pic, s) = setup();
        let dest = p(0x81);
        let id = 18400 + u64::from(mode);
        inject_payout_pending(&pic, &s, id, dest, STSH);
        fault(&pic, &s, id, mode);
        let old_call = pic
            .submit_call(
                s.pool,
                s.controller,
                "retry_private_spend_payout",
                candid::encode_one(id).unwrap(),
            )
            .unwrap();
        for _ in 0..32 {
            if !pic.get_canister_http().is_empty() {
                break;
            }
            pic.tick();
        }
        assert_eq!(live(&pic, &s), 1);
        assert!(!pic.get_canister_http().is_empty());
        let before = record(&pic, &s, id).public_payout.unwrap().retry.unwrap();
        upgrade(&pic, &s);
        assert_eq!(live(&pic, &s), 0);
        let reads: u64 = decode(
            "R15 boot reads",
            pic.query_call(
                s.pool,
                s.controller,
                "r15_record_reads_for_test",
                candid::encode_args(()).unwrap(),
            ),
        );
        assert_eq!(reads, 0);
        // The IC discards prior module futures, not merely the heap-map entries.
        for request in pic.get_canister_http() {
            release_http(&pic, request);
        }
        for _ in 0..4 {
            pic.tick();
        }
        let _ = pic.await_call_no_ticks(old_call);
        if mode == 4 {
            assert_eq!(token_balance(&pic, &s, dest), 0);
            assert!(retry(&pic, &s, s.controller, id).is_ok());
        } else {
            assert_eq!(
                retry(&pic, &s, s.controller, id),
                Err(PoolError::PayoutOutcomeUnknown)
            );
            let _: Result<ReconcilePayoutResult, PoolError> = decode(
                "reopen",
                reconcile_payout(&pic, &s, s.controller, id, PayoutOutcome::NotExecuted),
            );
            assert!(retry(&pic, &s, s.controller, id).is_ok());
        }
        assert_eq!(token_balance(&pic, &s, dest), STSH);
        let after = record(&pic, &s, id).public_payout.unwrap().retry.unwrap();
        assert!(after.boot > before.boot);
        assert_eq!(after.memo_sequence, before.memo_sequence);
        if mode == 5 {
            assert_eq!(after.frozen, before.frozen);
        }
    }
}
#[test]
fn large_history_adds_zero_r15_boot_reads_and_keyed_recovery_is_bounded() {
    let (pic, s) = setup();
    let id = 18410;
    inject_payout_pending(&pic, &s, id, p(0x82), STSH);
    fault(&pic, &s, id, 3);
    assert!(pic
        .update_call(
            s.pool,
            s.controller,
            "retry_private_spend_payout",
            candid::encode_one(id).unwrap()
        )
        .is_err());
    let _: () = decode(
        "history",
        pic.update_call(
            s.pool,
            s.controller,
            "r15_seed_history_for_test",
            candid::encode_args((id, 20000u64, 3000u32)).unwrap(),
        ),
    );
    upgrade(&pic, &s);
    let reads = || {
        decode::<u64, _>(
            "R15 reads",
            pic.query_call(
                s.pool,
                s.controller,
                "r15_record_reads_for_test",
                candid::encode_args(()).unwrap(),
            ),
        )
    };
    assert_eq!(
        reads(),
        0,
        "R15 boot performs no payout record access even with large history"
    );
    // Existing unrelated recovery is measured/drained separately, never claimed absent.
    for _ in 0..128 {
        let remaining: u64 = decode(
            "remaining",
            pic.query_call(
                s.pool,
                s.controller,
                "recovery_remaining_for_test",
                candid::encode_args(()).unwrap(),
            ),
        );
        if remaining == 0 {
            break;
        }
        let _: (u64, u64, u64) = candid::decode_args(
            &pic.update_call(
                s.pool,
                s.controller,
                "measure_recovery_chunk_instructions_for_test",
                candid::encode_args(()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    }
    assert_eq!(reads(), 0);
    assert!(retry(&pic, &s, s.controller, id).is_ok());
    assert!(
        reads() <= 8,
        "one supplied ID uses a bounded number of BTreeMap keyed reads"
    );
}
#[derive(CandidType, Deserialize)]
struct Lease {
    held: bool,
}
#[test]
fn sequence_exhaustion_rejects_before_nullifier_burn_and_record_creation() {
    let (pic, s) = setup();
    let id = 18411;
    let nullifier = vec![0x2eu8; 32];
    let _: () = decode(
        "exhaust",
        pic.update_call(
            s.pool,
            s.controller,
            "r15_control_fault_for_test",
            candid::encode_one(1u8).unwrap(),
        ),
    );
    let args = PrivateSpendArgs {
        spend_id: id,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".into(),
            verifying_key_hash: [0; 32],
            root_reference: merkle_root(&pic, &s),
            pool_version: 1,
            proof_bytes: vec![0; 8],
        },
        nullifiers: vec![[0x2e; 32]],
        output_commitments: vec![[0x20; 32], [0x21; 32]],
        encrypted_outputs: vec![vec![], vec![]],
        fee: 0,
        public_payout: Some(PrivateSpendPublicPayout {
            destination: p(0x83),
            destination_subaccount: None,
            public_amount: SPEND_PUBLIC_AMOUNT,
        }),
    };
    let r: Result<(), PoolError> = decode(
        "exhausted spend",
        pic.update_call(
            s.pool,
            s.user,
            "private_spend",
            candid::encode_one(args).unwrap(),
        ),
    );
    assert_eq!(r, Err(PoolError::PayoutStateInvalid));
    let burned: bool = decode(
        "nullifier",
        pic.query_call(
            s.null,
            anon(),
            "contains_nullifier",
            candid::encode_one(nullifier).unwrap(),
        ),
    );
    assert!(!burned);
    let r: Option<Record> = decode(
        "no record",
        pic.query_call(
            s.pool,
            s.controller,
            "get_spend_status",
            candid::encode_one(id).unwrap(),
        ),
    );
    assert!(r.is_none());
    let lease: Lease = decode(
        "lease",
        pic.query_call(
            s.pool,
            s.controller,
            "get_append_lease_status",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert!(!lease.held);
}
#[test]
fn foreign_bytes_cover_pause_recovery_key_unready_and_all_status_screens() {
    let (pic, s) = setup();
    let dest = p(0x84);
    let call = |id: u64| {
        pic.update_call(
            s.pool,
            anon(),
            "retry_private_spend_payout",
            candid::encode_one(id).unwrap(),
        )
        .unwrap()
    };
    let expected = call(19999);
    for (i, status) in [
        SpendStatus::Requested,
        SpendStatus::PayoutSubmitting,
        SpendStatus::PayoutUnknown {
            reason: "secret reason".into(),
        },
        SpendStatus::Finalized,
    ]
    .into_iter()
    .enumerate()
    {
        let id = 18500 + i as u64;
        inject_payout_pending(&pic, &s, id, dest, STSH);
        set_spend_status(&pic, &s, id, status);
        assert_eq!(call(id), expected);
    }
    inject_payout_pending(&pic, &s, 18510, dest, STSH);
    let _: () = decode(
        "no payout",
        pic.update_call(
            s.pool,
            s.controller,
            "r15_no_payout_for_test",
            candid::encode_one(18510u64).unwrap(),
        ),
    );
    assert_eq!(call(18510), expected);
    inject_payout_pending(&pic, &s, 18511, dest, STSH);
    let _: () = decode(
        "key absent",
        pic.update_call(
            s.pool,
            s.controller,
            "r15_control_fault_for_test",
            candid::encode_one(4u8).unwrap(),
        ),
    );
    assert_eq!(call(18511), expected);
    let _: Result<(), String> = decode(
        "pause",
        pic.update_call(
            s.pool,
            s.controller,
            "emergency_pause_spends",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_eq!(call(18511), expected);
    assert_eq!(call(19999), expected);
    let _: () = decode(
        "unpause",
        pic.update_call(
            s.pool,
            s.controller,
            "unpause_spends",
            candid::encode_args(()).unwrap(),
        ),
    );
    let _: () = decode(
        "recovery",
        pic.update_call(
            s.pool,
            s.controller,
            "set_recovery_cursor_phase_for_test",
            candid::encode_one(0u8).unwrap(),
        ),
    );
    assert_eq!(call(18511), expected);
    assert_eq!(call(19999), expected);
    assert_eq!(token_balance(&pic, &s, dest), 0);
}

mod accrual;
#[test]
fn actual_control_counter_and_key_persist_and_next_allocation_is_monotonic() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let (pic, s) = setup();
    let _: () = decode(
        "known test key",
        pic.update_call(
            s.pool,
            s.controller,
            "r15_control_fault_for_test",
            candid::encode_one(2u8).unwrap(),
        ),
    );
    inject_payout_pending(&pic, &s, 18700, p(0x86), STSH);
    assert!(retry(&pic, &s, s.controller, 18700).is_ok());
    let before = public_control(&pic, &s);
    assert_eq!(before.1, 1);
    assert!(before.2);
    upgrade(&pic, &s);
    let after = public_control(&pic, &s);
    assert_eq!(after.1, before.1);
    assert_eq!(after.0, before.0 + 1);
    assert!(after.2);
    inject_payout_pending(&pic, &s, 18701, p(0x86), STSH);
    assert_eq!(public_control(&pic, &s).1, 2);
    assert!(retry(&pic, &s, s.controller, 18701).is_ok());
    let r = record(&pic, &s, 18701)
        .public_payout
        .unwrap()
        .retry
        .unwrap();
    assert_eq!(r.memo_sequence, 1);
    // Fixed NONSECRET test key; the API returns only the stored payout digest.
    // A silently regenerated upgrade key would fail this standard HMAC check.
    let mut reference = Hmac::<Sha256>::new_from_slice(&[91u8; 32]).unwrap();
    reference.update(b"stsh.private-payout.memo.v1");
    for principal in [s.pool, s.token] {
        reference.update(&[principal.as_slice().len() as u8]);
        reference.update(principal.as_slice());
    }
    reference.update(&18701u64.to_le_bytes());
    reference.update(&1u128.to_le_bytes());
    assert_eq!(
        r.frozen.unwrap().memo,
        Some(reference.finalize().into_bytes().to_vec())
    );
}
