//! Before-side witnesses on the exact, unmodified 9f7c81e pool Wasm.
//! These intentionally assert the OLD defect, not the fixed contract.
//! B4 pays through the real ledger, then the predecessor's existing test-only
//! status setter models lost observation AFTER payment. It does not inject a
//! fake payment. Actual callback-loss/cleanup is separately exercised on R-15.
use super::*;

fn predecessor() -> (PocketIc, Stack) {
    let pic = PocketIc::new();
    let s = deploy_stack_with_pool(
        &pic,
        load_wasm(env!("POOL_PRE_R15_TEST_WASM"), "exact R15 predecessor"),
        false,
    );
    fund_pool_1000(&pic, &s);
    (pic, s)
}

#[test]
fn before_b4_real_payment_then_modeled_unknown_and_fee_drift_double_pays() {
    let (pic, s) = predecessor();
    let dest = p(0x81);
    let id = 19001;
    inject_payout_pending(&pic, &s, id, dest, 100 * STSH);
    assert!(retry(&pic, &s, s.controller, id).is_ok());
    assert_eq!(token_balance(&pic, &s, dest), 100 * STSH);
    // Existing predecessor test seam models the pool's lost observation only.
    set_spend_status(
        &pic,
        &s,
        id,
        SpendStatus::PayoutUnknown {
            reason: "modeled callback loss after real payment".into(),
        },
    );
    fee(&pic, &s, 7);
    let reopened: Result<ReconcilePayoutResult, PoolError> = decode(
        "old reopen",
        reconcile_payout(&pic, &s, s.controller, id, PayoutOutcome::NotExecuted),
    );
    assert!(matches!(
        reopened,
        Ok(ReconcilePayoutResult::RevertedToPending)
    ));
    assert!(retry(&pic, &s, s.controller, id).is_ok());
    assert_eq!(
        token_balance(&pic, &s, dest),
        200 * STSH - 7,
        "before B4: repriced request created a second real recipient credit"
    );
    assert_eq!(token_balance(&pic, &s, s.pool), 800 * STSH);
}

#[test]
fn before_b2_rejected_balance_query_strands_submitting_without_payment() {
    let (pic, s) = predecessor();
    let dest = p(0x82);
    let id = 19002;
    inject_payout_pending(&pic, &s, id, dest, STSH);
    pic.stop_canister(s.token, None).unwrap();
    assert!(retry(&pic, &s, s.controller, id).is_err());
    assert_eq!(
        spend_status(&pic, &s, id),
        Some(SpendStatus::PayoutSubmitting)
    );
    pic.start_canister(s.token, None).unwrap();
    assert_eq!(
        retry(&pic, &s, s.controller, id),
        Err(PoolError::PayoutNotPending)
    );
    assert_eq!(token_balance(&pic, &s, dest), 0);
}

#[test]
fn before_b3_foreign_retry_distinguishes_missing_and_exposes_terminal_block() {
    let (pic, s) = predecessor();
    let id = 19003;
    let absent = pic
        .update_call(
            s.pool,
            anon(),
            "retry_private_spend_payout",
            candid::encode_one(id).unwrap(),
        )
        .unwrap();
    let missing: Result<Nat, PoolError> = candid::decode_one(&absent).unwrap();
    assert!(matches!(missing, Err(PoolError::TransferFailed(_))));
    inject_payout_pending(&pic, &s, id, p(0x83), STSH);
    let terminal = pic
        .update_call(
            s.pool,
            anon(),
            "retry_private_spend_payout",
            candid::encode_one(id).unwrap(),
        )
        .unwrap();
    let revealed: Result<Nat, PoolError> = candid::decode_one(&terminal).unwrap();
    assert!(
        revealed.is_ok(),
        "before B3: a foreign caller receives the ledger block"
    );
    assert_ne!(terminal, absent);
    assert_eq!(token_balance(&pic, &s, p(0x83)), STSH);
}

#[derive(CandidType)]
struct SnapshotSpend {
    spend_id: u64,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    public_payout: Option<PendingPublicPayout>,
    outputs_committed: u32,
    status: SpendStatus,
    created_at_ns: u64,
    submitter: Option<Principal>,
    fee: Option<u128>,
    fee_split_ops: Option<u128>,
    fee_split_insurance: Option<u128>,
    fee_split_staking: Option<u128>,
}

#[test]
fn before_b7_retry_and_executed_finalization_omit_stored_mirror_split() {
    let (pic, s) = predecessor();
    for (id, status) in [
        (
            19004,
            SpendStatus::PayoutPending {
                reason: "owed".into(),
            },
        ),
        (
            19005,
            SpendStatus::PayoutUnknown {
                reason: "operator evidence".into(),
            },
        ),
    ] {
        let rec = SnapshotSpend {
            spend_id: id,
            nullifiers: vec![],
            output_commitments: vec![],
            public_payout: Some(PendingPublicPayout {
                destination: p(0x84),
                destination_subaccount: None,
                public_amount: STSH,
                protocol_fee: 41,
                block_index: None,
            }),
            outputs_committed: 0,
            status,
            created_at_ns: 1,
            submitter: Some(s.controller),
            fee: Some(41),
            fee_split_ops: Some(11),
            fee_split_insurance: Some(13),
            fee_split_staking: Some(17),
        };
        let _: u64 = decode(
            "old snapshot injection",
            pic.update_call(
                s.pool,
                s.controller,
                "inject_pending_spend_for_test",
                candid::encode_one(rec).unwrap(),
            ),
        );
    }
    assert!(retry(&pic, &s, s.controller, 19004).is_ok());
    let reconciled: Result<ReconcilePayoutResult, PoolError> = decode(
        "old Executed",
        reconcile_payout(
            &pic,
            &s,
            s.controller,
            19005,
            PayoutOutcome::Executed { block_index: 7 },
        ),
    );
    assert!(reconciled.is_ok());
    assert_eq!(spend_status(&pic, &s, 19004), Some(SpendStatus::Finalized));
    assert_eq!(spend_status(&pic, &s, 19005), Some(SpendStatus::Finalized));
    // R-15 adds a test-only reader of the existing MemoryId23, preserved at
    // upgrade. It does not backfill terminal history or accrue during upgrade.
    upgrade(&pic, &s);
    assert_eq!(
        accrual(&pic, &s),
        vec![0, 0, 0],
        "before B7: two known stored splits were skipped (expected 22/26/34)"
    );
}
