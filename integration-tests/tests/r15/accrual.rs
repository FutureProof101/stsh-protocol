use super::*;
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum SpendFeeMode {
    FixedStsh,
    XdrPegged,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct GovernanceFeeParams {
    protocol_shielding_fee_stsh: u128,
    protocol_unshielding_fee_stsh: u128,
    protocol_private_spend_fee_stsh: u128,
    minimum_withdrawal_gross: u128,
    minimum_recipient_amount: u128,
    minimum_private_credit: u128,
    fee_reference_price_stsh_per_icp_e8s: u128,
    fee_safety_margin_bps: u32,
    max_fee_change_bps_per_update: u32,
    fee_update_cooldown_ns: u64,
    operations_split_bps: u32,
    insurance_split_bps: u32,
    staking_rewards_split_bps: u32,
    staking_rewards_enabled: bool,
    minimum_treasury_runway_months: u32,
    target_treasury_runway_months: u32,
    shield_fee_bps: Option<u16>,
    unshield_fee_bps: Option<u16>,
    shield_flat_minimum_fee_e8s: Option<u128>,
    unshield_flat_minimum_fee_e8s: Option<u128>,
    spend_fee_mode: Option<SpendFeeMode>,
    fee_model_version: Option<u32>,
    params_epoch: Option<u64>,
}

fn set_split(pic: &PocketIc, s: &Stack, ops: u32) {
    let mut params: GovernanceFeeParams = decode(
        "params",
        pic.query_call(
            s.pool,
            s.controller,
            "get_governance_fee_params",
            candid::encode_args(()).unwrap(),
        ),
    );
    params.operations_split_bps = ops;
    params.insurance_split_bps = 10000 - ops;
    params.staking_rewards_split_bps = 0;
    params.unshield_fee_bps = Some(0);
    params.unshield_flat_minimum_fee_e8s = Some(100);
    let result: Result<(), String> = decode(
        "change split",
        pic.update_call(
            s.pool,
            s.controller,
            "set_governance_fee_params_unchecked_for_test",
            candid::encode_one(params).unwrap(),
        ),
    );
    assert_eq!(result, Ok(()));
}
fn args(pic: &PocketIc, s: &Stack, id: u64) -> PrivateSpendArgs {
    PrivateSpendArgs {
        spend_id: id,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".into(),
            verifying_key_hash: [0; 32],
            root_reference: merkle_root(pic, s),
            pool_version: 1,
            proof_bytes: vec![0; 8],
        },
        nullifiers: vec![[0x2d; 32]],
        output_commitments: vec![[0x20; 32], [0x21; 32]],
        encrypted_outputs: vec![vec![], vec![]],
        fee: 100,
        public_payout: Some(PrivateSpendPublicPayout {
            destination: p(0x85),
            destination_subaccount: None,
            public_amount: SPEND_PUBLIC_AMOUNT,
        }),
    }
}
#[test]
fn actual_inline_and_all_delayed_finalizers_accrue_identical_original_snapshot_once() {
    for mode in 0..6u8 {
        let (pic, s) = setup();
        set_split(&pic, &s, 7000);
        let id = 18600 + u64::from(mode);
        assert_eq!(accrual(&pic, &s), vec![0, 0, 0]);
        if mode == 4 {
            inject_payout_pending(&pic, &s, id, p(0x85), SPEND_PUBLIC_AMOUNT);
            let _: () = decode(
                "original split",
                pic.update_call(
                    s.pool,
                    s.controller,
                    "r15_fixture_split_for_test",
                    candid::encode_args((id, 70u128, 30u128, 0u128)).unwrap(),
                ),
            );
            assert!(retry(&pic, &s, s.controller, id).is_ok());
        } else {
            let injection = match mode {
                1 | 3 => 1,
                2 => 2,
                5 => 4,
                _ => 0,
            };
            fault(&pic, &s, id, injection);
            let message = pic
                .submit_call(
                    s.pool,
                    s.user,
                    "private_spend",
                    candid::encode_one(args(&pic, &s, id)).unwrap(),
                )
                .unwrap();
            if mode == 5 {
                for _ in 0..64 {
                    if !pic.get_canister_http().is_empty() {
                        break;
                    }
                    pic.tick();
                }
                assert!(!pic.get_canister_http().is_empty());
                assert_eq!(accrual(&pic, &s), vec![0, 0, 0]);
                set_split(&pic, &s, 2000); // actual governance mutation while executor is suspended
                fault(&pic, &s, id, 0);
            }
            let result = pic.await_call(message);
            if mode == 2 {
                assert!(result.is_err());
                assert_eq!(accrual(&pic, &s), vec![0, 0, 0]);
                let snapshot = candid::encode_one(accounting(&pic, &s)).unwrap();
                upgrade(&pic, &s);
                assert_eq!(accrual(&pic, &s), vec![0, 0, 0]);
                assert_eq!(candid::encode_one(accounting(&pic, &s)).unwrap(), snapshot);
            } else {
                let decoded: Result<(), PoolError> = decode("inline", result);
                if mode == 0 || mode == 5 {
                    assert!(decoded.is_ok());
                } else {
                    assert!(decoded.is_err());
                }
            }
            if matches!(mode, 1 | 2 | 3) {
                let snapshot = candid::encode_one(accounting(&pic, &s)).unwrap();
                assert_eq!(accrual(&pic, &s), vec![0, 0, 0]);
                set_split(&pic, &s, 2000);
                let decision = if mode == 3 {
                    PayoutOutcome::Executed { block_index: 9 }
                } else {
                    PayoutOutcome::NotExecuted
                };
                let result: Result<ReconcilePayoutResult, PoolError> = decode(
                    "settle",
                    reconcile_payout(&pic, &s, s.controller, id, decision),
                );
                assert!(result.is_ok());
                if mode != 3 {
                    fault(&pic, &s, id, 0);
                    assert!(retry(&pic, &s, s.controller, id).is_ok());
                }
                assert_eq!(
                    candid::encode_one(accounting(&pic, &s)).unwrap(),
                    snapshot,
                    "settlement must not repeat pool accounting"
                );
            }
        }
        assert_eq!(
            accrual(&pic, &s),
            vec![70, 30, 0],
            "mode {} must use original70/30 snapshot",
            mode
        );
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
        assert_eq!(accrual(&pic, &s), vec![70, 30, 0]);
        assert_eq!(token_balance(&pic, &s, p(0x85)), SPEND_PUBLIC_AMOUNT);
    }
}
