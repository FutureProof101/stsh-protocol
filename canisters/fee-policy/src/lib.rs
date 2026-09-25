// =============================================================================
// stsh-fee-policy
// =============================================================================
//
// Pure types + calculation functions for the formal STSH Protocol Fee,
// Reserve, and Staking Policy (docs/STSH_FEE_POLICY.md, 2026-06-11).
//
// This crate is deliberately:
//   - Free of ic-cdk / ic-stable-structures — no canister runtime dependency.
//   - Free of side effects — every function here is pure (no state, no I/O).
//   - Shared by shielded_pool (deposit/withdrawal/private-spend previews and
//     prechecks) and treasury (reserve splitting, runway, staking gating).
//
// All amounts are e8s (1 STSH = 100_000_000 e8s, matching canisters/token's
// DECIMALS = 8) represented as u128.
//
// Section references (## N) below correspond to docs/STSH_FEE_POLICY.md.
// =============================================================================

#![forbid(unsafe_code)]

use candid::CandidType;
use serde::{Deserialize, Serialize};

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors returned by the pure fee-policy calculation/precheck functions.
///
/// These map directly onto the precheck lists in docs/STSH_FEE_POLICY.md
/// sections 11 (deposit) and 12 (withdrawal). Callers (shielded_pool,
/// treasury) should translate these into their own PoolError /
/// TreasuryError variants rather than propagating this type across the
/// candid boundary, but it is CandidType so it CAN be returned directly if
/// convenient.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum FeePolicyError {
    // R2-4 (sweep fold): `GrossShieldAmountTooSmall` was REMOVED here.
    //
    // Under fee-on-top the note is credited the FULL gross and the shielding fee
    // is charged on top, so `compute_deposit_preview` has no path that can build
    // it — the too-small case surfaces as `PrivateCreditBelowMinimum` instead.
    // It had exactly two references in the whole tree: this definition and one
    // unreachable translation arm in the pool. It is on no `.did`, so removing it
    // moves no candid interface. Removal also deletes that arm's unchecked
    // `protocol_shielding_fee + 1`, which is the better outcome than auditing an
    // addition that can never execute (the file's E9/A-5 checked-arithmetic
    // convention would otherwise apply to it).

    /// `private_balance_credit` would fall below `minimum_private_credit`.
    /// Section 11: `private_balance_credit >= minimum_private_credit`.
    PrivateCreditBelowMinimum { private_balance_credit: u128, minimum_private_credit: u128 },

    /// Public account balance does not cover gross amount + native ledger fee.
    /// Section 11: `public_balance >= gross_shield_amount + stsh_icrc_transfer_from_fee`.
    InsufficientPublicBalance { required: u128, available: u128 },

    /// ICRC-2 allowance does not cover gross amount + native ledger fee.
    /// Section 11: `allowance >= gross_shield_amount + stsh_icrc_transfer_from_fee`.
    InsufficientAllowance { required: u128, available: u128 },

    /// `withdraw_gross_amount` is below the governance minimum withdrawal.
    /// Section 12: `withdraw_gross_amount >= minimum_withdrawal_gross`.
    WithdrawalBelowMinimum { withdraw_gross_amount: u128, minimum_withdrawal_gross: u128 },

    /// `withdraw_gross_amount` does not exceed the sum of fees — there would
    /// be nothing left for the recipient.
    /// Section 12: `withdraw_gross_amount > stsh_icrc_transfer_fee + protocol_unshielding_fee`.
    GrossAmountBelowFees { withdraw_gross_amount: u128, total_fee: u128 },

    /// `recipient_net_amount` would fall below `minimum_recipient_amount`
    /// (dust-exit protection).
    /// Section 12: `recipient_net_amount >= minimum_recipient_amount`.
    RecipientBelowMinimum { recipient_net_amount: u128, minimum_recipient_amount: u128 },

    /// Private balance is insufficient to cover the gross withdrawal amount.
    /// Section 12: `private_balance >= withdraw_gross_amount`.
    InsufficientPrivateBalance { withdraw_gross_amount: u128, private_balance: u128 },

    /// Pool escrow is insufficient to cover the ledger transfer out.
    /// Section 12: `pool_escrow_balance >= recipient_net_amount + stsh_icrc_transfer_fee`.
    InsufficientEscrow { required: u128, available: u128 },

    /// A private spend with public ledger movement was previewed without a
    /// native STSH ledger fee being supplied. Section 8: "If the private
    /// spend causes public ledger movement, the native STSH ledger fee must
    /// also be included."
    MissingLedgerFeeForPublicTransfer,

    /// A u128 arithmetic operation would have overflowed. Should never
    /// happen for realistic STSH amounts (max supply 1B * 1e8 = 1e17, far
    /// below u128::MAX), but checked explicitly rather than relying on
    /// wrapping/panicking arithmetic in financial code.
    ArithmeticOverflow,

    /// Governance fee-bucket split basis points (operations + insurance +
    /// staking_rewards) do not sum to 10_000 (100%).
    InvalidFeeSplitBps { operations_split_bps: u32, insurance_split_bps: u32, staking_rewards_split_bps: u32 },

    /// The spend fee is configured in an XDR-pegged mode but the price oracle
    /// inputs are unavailable/unconfigured. Fail-closed: the quote AND the
    /// execution reject rather than silently falling back to stale or zero
    /// pricing (fee-build lane §2). Only `SpendFeeMode::FixedStsh` is active
    /// until the oracle lane wires price inputs.
    SpendFeeOracleUnavailable,

    // ── A-1 setter guardrails (RB-SWARM-A1, ruled 2026-07-31) ──────────────
    /// A `u16` fee rate above 10 000 bps (100%). Rejected outright, and checked
    /// ahead of the routine-tuning range so the failure names the real problem.
    BpsAboveOneHundredPercent { field: String, bps: u16 },

    /// A fee RATE outside the ruled routine-tuning range
    /// `[FEE_BPS_FLOOR, FEE_BPS_CEILING]`. The nonzero floor blocks accidental
    /// zeroing; the ceiling blocks a confiscatory rate.
    FeeRateOutOfRange { field: String, bps: u16, floor: u16, ceiling: u16 },

    /// An STSH-denominated fee outside its ruled ABSOLUTE `[floor, ceiling]`.
    /// The per-call ratio bound alone is NOT sufficient — repeated `2x` calls
    /// would otherwise walk the fee up without limit (L8-F1).
    FeeAmountOutOfRange { field: String, amount: u128, floor: u128, ceiling: u128 },

    /// A single call moving a fee rate by more than
    /// [`MAX_BPS_CHANGE_PER_UPDATE`] ABSOLUTE basis points. Deliberately
    /// distinct from `max_fee_change_bps_per_update`, which is percent-of-current.
    FeeRateChangeTooLarge { field: String, current_bps: u16, requested_bps: u16, max_abs_change_bps: u16 },

    /// A single call moving an STSH-denominated fee outside the ruled
    /// `[0.5x, 2x]` per-call ratio (bidirectional).
    FeeAmountChangeOutOfRatio { field: String, current: u128, requested: u128 },

    /// A routine tuning call inside the canister-owned cooldown window. The
    /// clock is `last_fee_update_ns`, held by the canister — never caller input.
    FeeUpdateCooldownActive { last_update_ns: u64, now_ns: u64, cooldown_ns: u64 },

    /// The submitted `fee_update_cooldown_ns` disagrees with the enforced
    /// canister-owned constant. Rejected so the ADVERTISED cooldown can never
    /// drift from the one actually enforced.
    FeeUpdateCooldownFieldMismatch { configured_ns: u64, required_ns: u64 },

    /// The caller supplied a `params_epoch` that is not the canister-computed
    /// next epoch. The caller cannot choose the stored epoch.
    InvalidParamsEpoch { supplied: u64, expected: u64 },

    // ── W4 4-3 (fee-split launch posture, ruled 2026-08-18) ────────────────
    /// A nonzero `staking_rewards_split_bps` while `staking_rewards_enabled`
    /// is false. Section 17 ("No fee income routes to staking rewards at
    /// launch") was previously a comment on the field only; this makes it a
    /// binding rejected at the setter boundary.
    ///
    /// Deliberately NOT folded into `InvalidFeeSplitBps`: that error means
    /// "the three shares do not sum to 100%", which is a different defect and
    /// stays true of a different set of inputs. A posture violation names
    /// itself so the operator sees the real problem.
    StakingSplitNonzeroWhileDisabled { staking_rewards_split_bps: u32 },

    /// W4 4-2 / G-FEESPLIT: an attempt to set `staking_rewards_enabled = true`
    /// while the section-18 runway gate is not wired.
    ///
    /// The runway RULE exists and is fail-closed
    /// ([`staking_distribution_allowed`]), but its input
    /// (`monthly_runway_cost`) has no on-chain storage and the predicate has no
    /// production call site — so "distributions pause below 6 months runway"
    /// cannot currently be enforced at all. Enabling staking would therefore
    /// start routing fee income with its stated precondition unenforceable.
    /// Staking is excluded at launch by ruling D1 (2026-08-14); this makes that
    /// exclusion enforced rather than commented.
    StakingEnableBlockedRunwayUnwired,
}

// ── Fee-model versioning + value-fee launch constants (fee-build lane) ──────────

/// Fee-model version stamped into [`GovernanceFeeParams::launch_defaults`] and
/// bound by the wallet [`FeeQuote`]. Bump when the fee formula/shape changes so
/// a stale wallet quote cannot silently under/over-pay (B3 §0.4).
pub const FEE_MODEL_VERSION: u32 = 1;

/// Launch value-fee defaults. The fee-build mechanism commit keeps the
/// mechanism inert (all zero → every effective fee is 0); the nonzero-defaults
/// commit raises the shield/unshield rate to 25 bps and the spend fee to
/// 0.1 STSH. Resolver accessors below fall back to these SAME constants, so a
/// pre-fee-build persisted params record (whose new fields Candid-decode as
/// `None`) resolves to exactly the current launch defaults.
pub const LAUNCH_SHIELD_FEE_BPS: u16 = 0;
pub const LAUNCH_UNSHIELD_FEE_BPS: u16 = 0;
pub const LAUNCH_SHIELD_FLAT_MINIMUM_FEE_E8S: u128 = 0;
pub const LAUNCH_UNSHIELD_FLAT_MINIMUM_FEE_E8S: u128 = 0;

/// Documented **mainnet launch fee configuration** (fee-build lane §2). These
/// are the values governance applies via `set_governance_fee_params` as a
/// scripted deploy step — they are deliberately NOT baked into
/// [`GovernanceFeeParams::launch_defaults`], which stays fail-safe fee-free so a
/// fresh/mis-configured install never silently charges. `MAINNET_DEPLOYMENT.md`
/// documents these same values plus the post-deploy hard-gate that confirms the
/// LIVE params match them before the pool opens to the public. This is the
/// single source of truth for the deploy doc + [`GovernanceFeeParams::mainnet_launch_config`]
/// + the launch-config drift-guard test.
pub const MAINNET_LAUNCH_SHIELD_FEE_BPS: u16 = 25;
pub const MAINNET_LAUNCH_UNSHIELD_FEE_BPS: u16 = 25;
/// Spend fee (shielded->shielded, `FixedStsh`): **2.5 STSH** — RULED by
/// `OWNER_RULING_FEE_FLOOR_2_5_STSH` 2026-09-08 (lane A6.6/R-14), superseding the
/// 0.1 STSH placeholder of `OWNER_RULING_FEE_MODEL_CONSOLIDATED_2026-08-21`.
///
/// Cost basis, not a round number: at STSH = $0.00033 and 1 T cycles ~= $1.33, a
/// measured `private_spend` of 601.4 M cycles
/// (`integration-tests/tests/full_path_private_spend_benchmark.rs`) costs the
/// protocol ~= $0.0008. The 0.1 STSH fee lost ~= $0.00077 per operation; break-even
/// is ~= 2.4 STSH.
pub const MAINNET_LAUNCH_SPEND_FEE_E8S: u128 = 250_000_000;
/// Shield/unshield flat minimum at launch: **2.5 STSH** — RULED by
/// `OWNER_RULING_FEE_FLOOR_2_5_STSH` 2026-09-08 (lane A6.6/R-14), which supersedes
/// the 0.1 STSH value of `OWNER_RULING_FEE_MODEL_CONSOLIDATED_2026-08-21`, which
/// in turn superseded the 1,000-STSH value ruled 2026-07-31 (V4, RB-SWARM-A1).
/// The model is `max(2.5 STSH, 0.25%)` in BOTH directions with no cap at launch.
///
/// Same cost basis as [`MAINNET_LAUNCH_SPEND_FEE_E8S`]: 2.5 STSH is just above the
/// ~=2.4 STSH break-even at the measured cycle cost. It also lands exactly on the
/// value fee at the ladder's FLOOR rung (0.25% x 1,000 STSH = 2.5 STSH), so the
/// flat minimum binds only below the floor rung and the model is continuous at it.
///
/// This is the governance fee param and is deliberately NOT the in-circuit fee
/// wall (A6.6 territory); the two values are separate and must not be conflated.
/// It is NO LONGER equal to [`FLAT_MINIMUM_FEE_FLOOR_E8S`] (0.1 STSH) — the floor
/// is the guardrail's lower bound and is unchanged; the launch value now sits
/// above it, inside the band `[0.1 STSH, 5 STSH]`.
pub const MAINNET_LAUNCH_FLAT_MINIMUM_FEE_E8S: u128 = 250_000_000;

// ── A-1 setter guardrails: the RULED numeric policy ───────────────────────────
//
// RULED by CTO + Owner 2026-07-31 (`RB_SWARM_A1_FEE_FLOOR_TREE_GRIEF.md`, "A1
// numeric policy (fold)"). These are policy law, not builder-chosen defaults —
// changing one is a governance decision, not a refactor.
//
// The guardrails split into three independent layers, and all three are needed:
//
//   1. ABSOLUTE bounds  — where a value may ever sit.
//   2. PER-CALL bounds  — how far one call may move it (absolute points for
//                         rates, a bidirectional ratio for STSH amounts).
//   3. COOLDOWN         — how often a call may land at all, on a clock the
//                         canister owns.
//
// Layer 2 alone is insufficient (L8-F1): a per-call `2x` still permits
// unbounded doubling day after day, which is why layer 1 exists.

/// e8s per whole STSH (DECIMALS = 8 in `canisters/token`).
pub const E8S_PER_STSH: u128 = 100_000_000;

/// Basis-point denominator: 10 000 bps == 100%.
pub const BPS_DENOMINATOR: u16 = 10_000;

/// Routine-tuning FLOOR for `shield_fee_bps` / `unshield_fee_bps` — RULED.
/// Nonzero so an accidental (or malicious) zeroing is not a routine `set`.
pub const FEE_BPS_FLOOR: u16 = 1;
/// Routine-tuning CEILING for `shield_fee_bps` / `unshield_fee_bps` — RULED.
/// 500 bps = 5%; above this is confiscatory.
pub const FEE_BPS_CEILING: u16 = 500;

/// Maximum ABSOLUTE basis-point move of a fee RATE in one call — RULED.
///
/// This is a distinct concept from the pre-existing
/// `GovernanceFeeParams::max_fee_change_bps_per_update`, which is
/// *percent-of-current*. That field is deliberately NOT overloaded here (SSA
/// fold v2 gate 2): 100 absolute points means `shield_fee_bps` may move
/// 25 -> 125 but not 25 -> 126, regardless of what percentage that represents.
pub const MAX_BPS_CHANGE_PER_UPDATE: u16 = 100;

/// Absolute FLOOR for `shield_flat_minimum_fee_e8s` /
/// `unshield_flat_minimum_fee_e8s` — RULED: **0.1 STSH** by
/// `OWNER_RULING_FEE_MODEL_CONSOLIDATED_2026-08-21`, superseding the 1,000-STSH
/// figure ruled 2026-07-31 (RB-SWARM-A1). This is the guardrail FLOOR, not the
/// launch value: the launch flat minimum is 2.5 STSH (A6.6). Nonzero so
/// governance can operate `max(flat, bps)` without enabling dust.
pub const FLAT_MINIMUM_FEE_FLOOR_E8S: u128 = E8S_PER_STSH / 10;
/// Absolute CEILING for the shield/unshield flat minimums — RULED: **5 STSH** by
/// `CTO_RULING_A-7_flatmin_ceiling_2026-08-21`, superseding 5,000 STSH.
///
/// The old ceiling was five times the in-circuit value bound, so a value the
/// setter would ACCEPT could make every public-payout exit unprovable — the same
/// defect class as the floor, surviving in the band. 5 STSH mirrors
/// [`PRIVATE_SPEND_FEE_CEILING_E8S`], leaves 50x governance headroom above the
/// 0.1-STSH floor, and sits orders of magnitude below the circuit bound.
/// Enforced against that bound by
/// `shielded_pool::tests::governance_accepted_flat_minimum_cannot_make_an_exit_unprovable`.
pub const FLAT_MINIMUM_FEE_CEILING_E8S: u128 = 5 * E8S_PER_STSH;

/// Absolute FLOOR for `protocol_private_spend_fee_stsh` — RULED: 0.1 STSH
/// (the launch value).
pub const PRIVATE_SPEND_FEE_FLOOR_E8S: u128 = E8S_PER_STSH / 10;
/// Absolute CEILING for `protocol_private_spend_fee_stsh` — RULED: 5 STSH.
pub const PRIVATE_SPEND_FEE_CEILING_E8S: u128 = 5 * E8S_PER_STSH;

/// Cooldown between ROUTINE fee-tuning calls — RULED: 24h, in nanoseconds.
///
/// Enforced against a canister-owned `last_fee_update_ns`, never against
/// caller-supplied state (SSA gate 5: the same class of finding as P-STK's
/// cooldown clock — a security-relevant clock must not be caller-chosen).
pub const FEE_UPDATE_COOLDOWN_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

/// The STSH-denominated per-call ratio bound is `[1/2 x, 2 x]` — RULED,
/// bidirectional (SSA fold v2 gate 3: the downward bound was undefined).
/// Expressed as a numerator/denominator pair so the check stays integer-only.
pub const FEE_AMOUNT_MAX_RATIO_NUM: u128 = 2;
pub const FEE_AMOUNT_MAX_RATIO_DEN: u128 = 1;

/// Spend-fee pricing mode (fee-build lane §2). Structured so the XDR peg can be
/// switched on later without a further struct change.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendFeeMode {
    /// Fixed STSH amount taken directly from `protocol_private_spend_fee_stsh`.
    /// The only mode active in the fee-build lane.
    FixedStsh,
    /// XDR-pegged (0.5 XDR target). Requires the price oracle (a later lane);
    /// until then it FAILS CLOSED — [`compute_private_spend_fee_preview`]
    /// returns [`FeePolicyError::SpendFeeOracleUnavailable`] rather than
    /// pricing off stale/zero inputs.
    XdrPegged,
}

// ── Governance parameters (section 20) ────────────────────────────────────────

/// Governance-controlled fee/reserve/staking parameters.
///
/// Native STSH ICRC ledger fees (`icrc1_fee`) are deliberately NOT part of
/// this struct — section 20: "Native STSH ledger fees are NOT manually
/// configured protocol action-fee parameters. They must be queried from the
/// STSH ledger using `icrc1_fee`." Callers fetch that value live and pass it
/// into the preview/precheck functions below as `stsh_icrc_transfer_fee` /
/// `stsh_icrc_transfer_from_fee`.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GovernanceFeeParams {
    // ── Protocol action fees (section 5, 9) ────────────────────────────────
    /// Protocol fee charged on shield_deposit (section 6). e8s.
    pub protocol_shielding_fee_stsh: u128,
    /// Protocol fee charged on withdraw (section 7). e8s.
    pub protocol_unshielding_fee_stsh: u128,
    /// Protocol fee charged on private_spend (section 8). e8s.
    pub protocol_private_spend_fee_stsh: u128,

    // ── Minimums / dust protection (section 10) ────────────────────────────
    /// Minimum gross withdrawal amount. e8s.
    pub minimum_withdrawal_gross: u128,
    /// Minimum amount the recipient must net after fees. e8s.
    pub minimum_recipient_amount: u128,
    /// Minimum private balance credit on deposit. e8s.
    pub minimum_private_credit: u128,

    // ── Fee sizing inputs (section 9) ───────────────────────────────────────
    /// STSH per ICP reference price, scaled by 1e8 (i.e. an e8s-fixed-point
    /// ratio). Used only by off-chain / governance tooling to derive the
    /// `protocol_*_fee_stsh` values from `measured_p95_protocol_cost_in_icp`
    /// — NOT consumed by the preview/precheck functions in this crate.
    pub fee_reference_price_stsh_per_icp_e8s: u128,
    /// Safety margin in basis points applied on top of measured protocol
    /// cost (section 9). E.g. 12500 = 1.25x (launch), 10500-11500 = mature.
    pub fee_safety_margin_bps: u32,
    /// Maximum allowed change to any `protocol_*_fee_stsh` per governance
    /// update, in basis points of the current value.
    pub max_fee_change_bps_per_update: u32,
    /// Minimum time between fee parameter updates, in nanoseconds.
    pub fee_update_cooldown_ns: u64,

    // ── Reserve split (sections 15, 16, 19) ─────────────────────────────────
    /// Share of protocol action fees credited to the operations reserve.
    pub operations_split_bps: u32,
    /// Share of protocol action fees credited to the insurance/security reserve.
    pub insurance_split_bps: u32,
    /// Share of protocol action fees credited to the staking-rewards reserve.
    /// MUST be 0 while `staking_rewards_enabled == false` (section 17: "No
    /// fee income routes to staking rewards at launch").
    ///
    /// **ENFORCED, not advisory** (W4 4-3, 2026-08-18): every setter rejects a
    /// nonzero value here while the master switch is false — see
    /// [`GovernanceFeeParams::validate_staking_posture`]. Before W4 this was a
    /// comment only, so governance could store the very configuration that
    /// would start routing fee income to staking the moment the switch flipped.
    ///
    /// Second line of defence, unchanged: if such a configuration was ever
    /// stored, [`split_protocol_fee_to_reserves`] still redistributes this
    /// share to operations/insurance rather than honouring it.
    pub staking_rewards_split_bps: u32,

    // ── Staking / runway (sections 17, 18) ──────────────────────────────────
    /// Master switch. MUST be `false` at launch (section 17/23).
    pub staking_rewards_enabled: bool,
    /// Minimum treasury runway, in months, required before any staking
    /// distribution may occur (section 18). Suggested: 6.
    pub minimum_treasury_runway_months: u32,
    /// Target treasury runway, in months (section 18/19). Suggested: 12.
    pub target_treasury_runway_months: u32,

    // ── Value fees (fee-build lane, 2026-07-11) ─────────────────────────────
    //
    // Shield/unshield are charged as a percentage of value (bps) with a flat
    // minimum floor — NOT the flat `protocol_shielding_fee_stsh` /
    // `protocol_unshielding_fee_stsh` above, which are superseded for
    // shield/unshield sizing and retained only for upgrade compatibility.
    //
    //   effective_fee = max(flat_minimum, amount * bps / 10_000)   (floor div)
    //
    // Every field below is `Option<_>` so a params record persisted BEFORE the
    // fee-build lane decodes cleanly (Candid fills a missing field only when it
    // is `opt`); the resolver accessors map `None` to the launch-default
    // constants, so an old record resolves to exactly the current launch
    // defaults. Governance sets concrete `Some(_)` values via
    // `set_governance_fee_params`.
    /// Shield fee rate, basis points of the shielded amount. `None` → launch default.
    pub shield_fee_bps: Option<u16>,
    /// Unshield fee rate, basis points of the withdrawn amount. `None` → launch default.
    pub unshield_fee_bps: Option<u16>,
    /// Flat minimum shield protocol fee (dust floor). e8s. `None` → launch default.
    pub shield_flat_minimum_fee_e8s: Option<u128>,
    /// Flat minimum unshield protocol fee (dust floor). e8s. `None` → launch default.
    pub unshield_flat_minimum_fee_e8s: Option<u128>,
    /// Spend-fee pricing mode. `None` → [`SpendFeeMode::FixedStsh`].
    pub spend_fee_mode: Option<SpendFeeMode>,
    /// Fee-model version the wallet `FeeQuote` binds to. `None` → [`FEE_MODEL_VERSION`].
    pub fee_model_version: Option<u32>,
    /// Params epoch, bumped on each governance fee change so a stale wallet
    /// quote is rejected at execution. `None` → 0.
    pub params_epoch: Option<u64>,
}

impl GovernanceFeeParams {
    /// Launch-phase defaults consistent with docs/STSH_FEE_POLICY.md sections
    /// 17 ("No fee income routes to staking rewards at launch") and 19
    /// ("Launch Phase: 0% staking rewards / 80-90% operations / 10-20%
    /// insurance"). `protocol_*_fee_stsh` are left at 0 here — callers must
    /// size them per section 9 from the A2-1/A2-2 measured costs before use.
    pub fn launch_defaults() -> Self {
        Self {
            protocol_shielding_fee_stsh: 0,
            protocol_unshielding_fee_stsh: 0,
            protocol_private_spend_fee_stsh: 0,
            minimum_withdrawal_gross: 0,
            minimum_recipient_amount: 0,
            minimum_private_credit: 0,
            fee_reference_price_stsh_per_icp_e8s: 0,
            fee_safety_margin_bps: 12_500, // 1.25x, section 9 launch suggestion
            max_fee_change_bps_per_update: 1_000, // 10% per update, conservative default
            fee_update_cooldown_ns: 24 * 60 * 60 * 1_000_000_000, // 24h
            operations_split_bps: 8_500, // within 80-90% launch range
            insurance_split_bps: 1_500,  // within 10-20% launch range
            staking_rewards_split_bps: 0,
            staking_rewards_enabled: false,
            minimum_treasury_runway_months: 6,
            target_treasury_runway_months: 12,
            // Value fees seeded from the launch constants. The mechanism is
            // inert at these values (all effective fees 0); the nonzero-defaults
            // commit raises the shield/unshield rate + spend fee.
            shield_fee_bps: Some(LAUNCH_SHIELD_FEE_BPS),
            unshield_fee_bps: Some(LAUNCH_UNSHIELD_FEE_BPS),
            shield_flat_minimum_fee_e8s: Some(LAUNCH_SHIELD_FLAT_MINIMUM_FEE_E8S),
            unshield_flat_minimum_fee_e8s: Some(LAUNCH_UNSHIELD_FLAT_MINIMUM_FEE_E8S),
            spend_fee_mode: Some(SpendFeeMode::FixedStsh),
            fee_model_version: Some(FEE_MODEL_VERSION),
            params_epoch: Some(0),
        }
    }

    /// The documented **mainnet launch fee configuration** — 25 bps
    /// shield/unshield + 2.5 STSH fixed spend fee — governance applies this via
    /// `set_governance_fee_params` as a scripted deploy step (see
    /// `MAINNET_DEPLOYMENT.md`). NOT the code default: [`Self::launch_defaults`]
    /// stays fee-free. `params_epoch` is stamped to 1 (the first governance-set
    /// config) so the wallet `FeeQuote` binds to a distinct epoch. Single source
    /// of truth for the deploy doc + the launch-config tests.
    pub fn mainnet_launch_config() -> Self {
        Self {
            protocol_private_spend_fee_stsh: MAINNET_LAUNCH_SPEND_FEE_E8S,
            shield_fee_bps: Some(MAINNET_LAUNCH_SHIELD_FEE_BPS),
            unshield_fee_bps: Some(MAINNET_LAUNCH_UNSHIELD_FEE_BPS),
            // Shield/unshield flat minimum = 2.5 STSH, RULED 2026-09-08
            // (OWNER_RULING_FEE_FLOOR_2_5_STSH, lane A6.6/R-14), superseding the
            // 0.1 STSH value of 2026-08-21; inside the unchanged guardrail band
            // [0.1 STSH, 5 STSH], so the setter accepts it.
            // `launch_defaults()` stays fee-free and is deliberately untouched.
            shield_flat_minimum_fee_e8s: Some(MAINNET_LAUNCH_FLAT_MINIMUM_FEE_E8S),
            unshield_flat_minimum_fee_e8s: Some(MAINNET_LAUNCH_FLAT_MINIMUM_FEE_E8S),
            spend_fee_mode: Some(SpendFeeMode::FixedStsh),
            params_epoch: Some(1),
            ..Self::launch_defaults()
        }
    }

    // ── Value-fee resolver accessors ────────────────────────────────────────
    //
    // Each maps `None` (a pre-fee-build persisted record) to the launch-default
    // constant, so old state resolves to exactly the current launch defaults.
    /// Effective shield fee rate (bps). `None` → [`LAUNCH_SHIELD_FEE_BPS`].
    pub fn shield_fee_bps(&self) -> u16 {
        self.shield_fee_bps.unwrap_or(LAUNCH_SHIELD_FEE_BPS)
    }
    /// Effective unshield fee rate (bps). `None` → [`LAUNCH_UNSHIELD_FEE_BPS`].
    pub fn unshield_fee_bps(&self) -> u16 {
        self.unshield_fee_bps.unwrap_or(LAUNCH_UNSHIELD_FEE_BPS)
    }
    /// Effective shield flat-minimum fee (e8s). `None` → [`LAUNCH_SHIELD_FLAT_MINIMUM_FEE_E8S`].
    pub fn shield_flat_minimum_fee_e8s(&self) -> u128 {
        self.shield_flat_minimum_fee_e8s
            .unwrap_or(LAUNCH_SHIELD_FLAT_MINIMUM_FEE_E8S)
    }
    /// Effective unshield flat-minimum fee (e8s). `None` → [`LAUNCH_UNSHIELD_FLAT_MINIMUM_FEE_E8S`].
    pub fn unshield_flat_minimum_fee_e8s(&self) -> u128 {
        self.unshield_flat_minimum_fee_e8s
            .unwrap_or(LAUNCH_UNSHIELD_FLAT_MINIMUM_FEE_E8S)
    }
    /// Effective spend-fee mode. `None` → [`SpendFeeMode::FixedStsh`].
    pub fn spend_fee_mode(&self) -> SpendFeeMode {
        self.spend_fee_mode.unwrap_or(SpendFeeMode::FixedStsh)
    }
    /// Effective fee-model version. `None` → [`FEE_MODEL_VERSION`].
    pub fn fee_model_version(&self) -> u32 {
        self.fee_model_version.unwrap_or(FEE_MODEL_VERSION)
    }
    /// Effective params epoch. `None` → 0.
    pub fn params_epoch(&self) -> u64 {
        self.params_epoch.unwrap_or(0)
    }

    /// Effective shield protocol fee for `amount`:
    /// `max(shield_flat_minimum_fee_e8s, amount * shield_fee_bps / 10_000)`,
    /// checked multiply (never wraps), floor division (rounds in the user's
    /// favour). Fee-build lane §1.
    pub fn shield_protocol_fee(&self, amount: u128) -> Result<u128, FeePolicyError> {
        value_fee(amount, self.shield_fee_bps(), self.shield_flat_minimum_fee_e8s())
    }
    /// Effective unshield protocol fee for `amount`:
    /// `max(unshield_flat_minimum_fee_e8s, amount * unshield_fee_bps / 10_000)`.
    pub fn unshield_protocol_fee(&self, amount: u128) -> Result<u128, FeePolicyError> {
        value_fee(
            amount,
            self.unshield_fee_bps(),
            self.unshield_flat_minimum_fee_e8s(),
        )
    }

    /// Validates that the three reserve-split shares sum to 10_000 bps
    /// (100%) and that staking is not double-counted while disabled.
    pub fn validate_split_bps(&self) -> Result<(), FeePolicyError> {
        let total = u32::from(self.operations_split_bps)
            .checked_add(self.insurance_split_bps)
            .and_then(|v| v.checked_add(self.staking_rewards_split_bps))
            .ok_or(FeePolicyError::ArithmeticOverflow)?;
        if total != 10_000 {
            return Err(FeePolicyError::InvalidFeeSplitBps {
                operations_split_bps: self.operations_split_bps,
                insurance_split_bps: self.insurance_split_bps,
                staking_rewards_split_bps: self.staking_rewards_split_bps,
            });
        }
        Ok(())
    }

    // ── W4 4-3: staking launch posture ───────────────────────────────────────
    //
    // Why this is NOT inside `validate_split_bps`, deliberately:
    //
    // `validate_split_bps` is called by `split_protocol_fee_to_reserves` on
    // EVERY fee split, against whatever params are already stored — including
    // params written before this binding existed. Folding the posture rule in
    // there would turn a governance-hygiene violation into a fee-path failure
    // and would strand any historical configuration, which is exactly the
    // failure mode `split_protocol_fee_to_reserves`'s redistribution branch was
    // written to survive.
    //
    // So: the SETTER refuses to accept a bad posture (this function), and the
    // SPLIT still behaves safely if one was ever stored (the redistribution
    // branch). Those are two independent defences and both are load-bearing.

    /// W4 4-3: `staking_rewards_split_bps` must be 0 while
    /// `staking_rewards_enabled == false` (section 17, and the D1 ruling that
    /// staking is excluded at launch).
    ///
    /// A property of the SUBMITTED value alone — same classification as
    /// [`Self::validate_fee_bounds`], so it applies to the one-shot bootstrap
    /// set as well as to routine tuning. There is no legitimate reason to
    /// bootstrap into a posture governance may not subsequently set.
    pub fn validate_staking_posture(&self) -> Result<(), FeePolicyError> {
        if !self.staking_rewards_enabled && self.staking_rewards_split_bps != 0 {
            return Err(FeePolicyError::StakingSplitNonzeroWhileDisabled {
                staking_rewards_split_bps: self.staking_rewards_split_bps,
            });
        }

        // ── G-FEESPLIT gate (W4 4-2) ─────────────────────────────────────────
        //
        // The switch itself cannot be flipped while the runway gate it depends
        // on is unwired. This is the EXECUTABLE form of the "distributions
        // pause below 6 months runway" requirement: rather than build the
        // runway engine (explicitly out of scope — post-launch by D1), the
        // precondition is enforced by refusing the state that would need it.
        //
        // TO WHOEVER ENABLES STAKING: this is a single deliberate barrier, and
        // removing it is the LAST step, not the first. It may only come out
        // once (1) `monthly_runway_cost` is stored on-chain and governable,
        // (2) `staking_distribution_allowed` is wired to a real call site on
        // the distribution path, and (3) the 6-month minimum is enforced there.
        // Removing it earlier silently converts a fail-closed gate into a
        // no-op. Change is CTO/SSA-adjudicated; see the G-FEESPLIT suite.
        if self.staking_rewards_enabled {
            return Err(FeePolicyError::StakingEnableBlockedRunwayUnwired);
        }

        Ok(())
    }

    // ── A-1 setter guardrails ────────────────────────────────────────────────
    //
    // Split into two functions on purpose. `validate_fee_bounds` is a property
    // of the SUBMITTED value alone and applies to EVERY accepted set, including
    // the one-shot bootstrap. `validate_fee_change_from` is a property of the
    // TRANSITION and is what bootstrap is exempt from — the first zero->launch
    // move necessarily violates any ordinary per-call cap.
    //
    // Neither reads a clock or any canister state: the cooldown is enforced by
    // the owning canister against ITS OWN `last_fee_update_ns`, because this
    // crate has no runtime and must never be handed a caller-supplied clock.

    /// Absolute bounds every accepted parameter set must satisfy, bootstrap
    /// included. The ruled ranges are **the constants in this file, not a
    /// transcription of them** — rates within [`FEE_BPS_FLOOR`,
    /// `FEE_BPS_CEILING`], shield/unshield flat minimum within
    /// [`FLAT_MINIMUM_FEE_FLOOR_E8S`, `FLAT_MINIMUM_FEE_CEILING_E8S`], and
    /// private-spend fee within [`PRIVATE_SPEND_FEE_FLOOR_E8S`,
    /// `PRIVATE_SPEND_FEE_CEILING_E8S`]. Naming the symbols is deliberate: a
    /// docstring that hardcodes a band a few hundred lines from the constants
    /// defining it drifts, and this one had — it carried a flat-minimum band
    /// four orders of magnitude above the shipped floor until 2026-08-23.
    ///
    /// Note what is NOT here: there is no path to a below-floor or zero value.
    /// That is the ruling ("Below-floor / zeroing: NOT a routine `set`") — any
    /// future below-floor governance action needs its own explicitly-logged,
    /// harder path, ruled in its own right. A-1 does not build one.
    pub fn validate_fee_bounds(&self) -> Result<(), FeePolicyError> {
        for (field, bps) in [
            ("shield_fee_bps", self.shield_fee_bps()),
            ("unshield_fee_bps", self.unshield_fee_bps()),
        ] {
            // Checked FIRST and separately: `u16` permits values above 100%,
            // and "your 90 000 bps rate is outside [1, 500]" would bury the
            // actual defect under a range message.
            if bps > BPS_DENOMINATOR {
                return Err(FeePolicyError::BpsAboveOneHundredPercent {
                    field: field.to_string(),
                    bps,
                });
            }
            if bps < FEE_BPS_FLOOR || bps > FEE_BPS_CEILING {
                return Err(FeePolicyError::FeeRateOutOfRange {
                    field: field.to_string(),
                    bps,
                    floor: FEE_BPS_FLOOR,
                    ceiling: FEE_BPS_CEILING,
                });
            }
        }

        for (field, amount, floor, ceiling) in [
            (
                "shield_flat_minimum_fee_e8s",
                self.shield_flat_minimum_fee_e8s(),
                FLAT_MINIMUM_FEE_FLOOR_E8S,
                FLAT_MINIMUM_FEE_CEILING_E8S,
            ),
            (
                "unshield_flat_minimum_fee_e8s",
                self.unshield_flat_minimum_fee_e8s(),
                FLAT_MINIMUM_FEE_FLOOR_E8S,
                FLAT_MINIMUM_FEE_CEILING_E8S,
            ),
            (
                "protocol_private_spend_fee_stsh",
                self.protocol_private_spend_fee_stsh,
                PRIVATE_SPEND_FEE_FLOOR_E8S,
                PRIVATE_SPEND_FEE_CEILING_E8S,
            ),
        ] {
            if amount < floor || amount > ceiling {
                return Err(FeePolicyError::FeeAmountOutOfRange {
                    field: field.to_string(),
                    amount,
                    floor,
                    ceiling,
                });
            }
        }

        // The cooldown the record ADVERTISES must be the one the canister
        // ENFORCES. Without this the struct could carry a 1-second cooldown
        // while the canister silently held callers to 24h — a governance
        // surface that lies about itself.
        if self.fee_update_cooldown_ns != FEE_UPDATE_COOLDOWN_NS {
            return Err(FeePolicyError::FeeUpdateCooldownFieldMismatch {
                configured_ns: self.fee_update_cooldown_ns,
                required_ns: FEE_UPDATE_COOLDOWN_NS,
            });
        }

        Ok(())
    }

    /// Per-call movement caps, relative to the CURRENTLY LIVE parameters.
    /// Bootstrap (the one-shot zero->launch activation) is exempt from this and
    /// from the cooldown; nothing else ever is.
    ///
    /// Rates: `|new - old| <= 100` ABSOLUTE basis points.
    /// STSH amounts: `new` within `[old/2, old*2]`, bidirectional.
    pub fn validate_fee_change_from(&self, current: &Self) -> Result<(), FeePolicyError> {
        for (field, current_bps, requested_bps) in [
            ("shield_fee_bps", current.shield_fee_bps(), self.shield_fee_bps()),
            ("unshield_fee_bps", current.unshield_fee_bps(), self.unshield_fee_bps()),
        ] {
            let delta = requested_bps.abs_diff(current_bps);
            if delta > MAX_BPS_CHANGE_PER_UPDATE {
                return Err(FeePolicyError::FeeRateChangeTooLarge {
                    field: field.to_string(),
                    current_bps,
                    requested_bps,
                    max_abs_change_bps: MAX_BPS_CHANGE_PER_UPDATE,
                });
            }
        }

        for (field, current_amount, requested) in [
            (
                "shield_flat_minimum_fee_e8s",
                current.shield_flat_minimum_fee_e8s(),
                self.shield_flat_minimum_fee_e8s(),
            ),
            (
                "unshield_flat_minimum_fee_e8s",
                current.unshield_flat_minimum_fee_e8s(),
                self.unshield_flat_minimum_fee_e8s(),
            ),
            (
                "protocol_private_spend_fee_stsh",
                current.protocol_private_spend_fee_stsh,
                self.protocol_private_spend_fee_stsh,
            ),
        ] {
            // `requested <= 2*current` AND `2*requested >= current`, i.e.
            // `requested >= current/2` without a lossy division. Checked
            // multiplies: the absolute ceilings above keep these far from
            // overflow, but financial code does not rely on that.
            let up = current_amount
                .checked_mul(FEE_AMOUNT_MAX_RATIO_NUM)
                .ok_or(FeePolicyError::ArithmeticOverflow)?;
            let down = requested
                .checked_mul(FEE_AMOUNT_MAX_RATIO_NUM)
                .ok_or(FeePolicyError::ArithmeticOverflow)?;
            if requested > up || down < current_amount {
                return Err(FeePolicyError::FeeAmountChangeOutOfRatio {
                    field: field.to_string(),
                    current: current_amount,
                    requested,
                });
            }
        }

        Ok(())
    }

    /// True when this parameter set is EXACTLY the documented mainnet launch
    /// configuration — the programmatic form of the `MAINNET_DEPLOYMENT.md`
    /// P15-002 hard-gate, so deploy tooling can assert on a boolean instead of
    /// a human eyeballing raw Candid.
    ///
    /// **This is an INITIAL-LAUNCH predicate, not a permanent health check**
    /// (SSA gate 7). It is expected to go `false` after the first legitimate
    /// governance tuning call; a `false` after launch is not by itself a fault.
    ///
    /// Compares RESOLVED values, not raw `Option`s, so a record persisted
    /// before the fee-build lane (whose new fields decode as `None`) is judged
    /// on what it actually means rather than on how it happens to be encoded.
    pub fn matches_mainnet_launch_config(&self) -> bool {
        let target = Self::mainnet_launch_config();
        self.protocol_shielding_fee_stsh == target.protocol_shielding_fee_stsh
            && self.protocol_unshielding_fee_stsh == target.protocol_unshielding_fee_stsh
            && self.protocol_private_spend_fee_stsh == target.protocol_private_spend_fee_stsh
            && self.minimum_withdrawal_gross == target.minimum_withdrawal_gross
            && self.minimum_recipient_amount == target.minimum_recipient_amount
            && self.minimum_private_credit == target.minimum_private_credit
            && self.fee_reference_price_stsh_per_icp_e8s
                == target.fee_reference_price_stsh_per_icp_e8s
            && self.fee_safety_margin_bps == target.fee_safety_margin_bps
            && self.max_fee_change_bps_per_update == target.max_fee_change_bps_per_update
            && self.fee_update_cooldown_ns == target.fee_update_cooldown_ns
            && self.operations_split_bps == target.operations_split_bps
            && self.insurance_split_bps == target.insurance_split_bps
            && self.staking_rewards_split_bps == target.staking_rewards_split_bps
            && self.staking_rewards_enabled == target.staking_rewards_enabled
            && self.minimum_treasury_runway_months == target.minimum_treasury_runway_months
            && self.target_treasury_runway_months == target.target_treasury_runway_months
            && self.shield_fee_bps() == target.shield_fee_bps()
            && self.unshield_fee_bps() == target.unshield_fee_bps()
            && self.shield_flat_minimum_fee_e8s() == target.shield_flat_minimum_fee_e8s()
            && self.unshield_flat_minimum_fee_e8s() == target.unshield_flat_minimum_fee_e8s()
            && self.spend_fee_mode() == target.spend_fee_mode()
            && self.fee_model_version() == target.fee_model_version()
            && self.params_epoch() == target.params_epoch()
    }
}

/// `max(flat_minimum, amount * bps / 10_000)` with **checked** multiply
/// (overflow → [`FeePolicyError::ArithmeticOverflow`], never wraps) and **floor**
/// division (rounds in the user's favour). Base-units integer math only — no
/// floats. Shared by the shield/unshield value-fee accessors. Fee-build lane §1.
fn value_fee(amount: u128, bps: u16, flat_minimum: u128) -> Result<u128, FeePolicyError> {
    let by_bps = amount
        .checked_mul(bps as u128)
        .ok_or(FeePolicyError::ArithmeticOverflow)?
        / 10_000;
    Ok(flat_minimum.max(by_bps))
}

// ── Fee buckets (section 15) ───────────────────────────────────────────────────

/// Identifies which protocol reserve/income bucket a fee amount belongs to.
/// Section 15.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeBucket {
    /// Section 15.1 — protocol_shielding_fee income.
    Shielding,
    /// Section 15.2 — protocol_unshielding_fee income.
    Unshielding,
    /// Section 15.3 — protocol_private_spend_fee income.
    PrivateSpend,
    /// Section 15.4 — operations reserve (cycles, monitoring, maintenance).
    OperationsReserve,
    /// Section 15.5 — insurance / security reserve.
    InsuranceReserve,
    /// Section 15.6 — governance/staking rewards reserve. Disabled at
    /// launch (section 17) — only ever funded from surplus, never directly
    /// from action fees, while `staking_rewards_enabled == false`.
    StakingRewardsReserve,
}

// ── Deposit / shielding (section 6) ────────────────────────────────────────────

/// Preview of a `shield_deposit` per docs/STSH_FEE_POLICY.md section 6.
///
/// **Fee-ON-TOP (fee-build lane §2, LOCKED).** The shielding fee is charged on
/// top of the deposit, NOT deducted from the note — so the note is credited the
/// FULL requested amount and the fixed-denomination invariant (Law #1) holds at
/// any nonzero fee.
///
/// Worked example (100 STSH shield, 25 bps fee, 0.01 STSH ledger fee):
/// ```text
/// Amount to shield (credited):    100 STSH      (private_balance_credit)
/// Protocol shielding fee:         0.25 STSH     (protocol_shielding_fee)
/// Amount pulled into pool:        100.25 STSH   (pool_transfer_in)
/// STSH ledger transfer fee:       0.01 STSH     (stsh_icrc_transfer_from_fee)
/// Total public STSH debit:        100.26 STSH   (total_public_debit)
/// ```
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DepositPreview {
    /// Amount the user requests to shield (gross, before fees). e8s. With
    /// fee-on-top this is also the amount credited to the private balance.
    pub gross_shield_amount: u128,
    /// Native STSH ICRC ledger fee for the `transfer_from` into the pool,
    /// queried live via `icrc1_fee`. e8s.
    pub stsh_icrc_transfer_from_fee: u128,
    /// Protocol shielding fee (value fee: `max(flat_min, gross*bps/10_000)`). e8s.
    pub protocol_shielding_fee: u128,
    /// `gross_shield_amount` (FULL — fee is on top, not deducted). Credited to
    /// the user's private balance and backs escrow 1:1. e8s.
    pub private_balance_credit: u128,
    /// `gross_shield_amount + protocol_shielding_fee`. The ICRC-2
    /// `transfer_from` amount pulled into the pool (escrow gets the gross, the
    /// reserves get the protocol fee). e8s.
    pub pool_transfer_in: u128,
    /// `pool_transfer_in + stsh_icrc_transfer_from_fee`. Total debited from the
    /// user's public account (what the user must have approved). e8s.
    pub total_public_debit: u128,
}

/// Computes a [`DepositPreview`] and validates the section 11 invariants
/// that depend only on the requested amount and governance parameters
/// (i.e. NOT the live balance/allowance checks — see [`precheck_deposit`]
/// for the full precheck including those).
pub fn compute_deposit_preview(
    gross_shield_amount: u128,
    stsh_icrc_transfer_from_fee: u128,
    params: &GovernanceFeeParams,
) -> Result<DepositPreview, FeePolicyError> {
    // Fee-ON-TOP value fee: max(shield_flat_minimum, gross * shield_bps / 10_000).
    let protocol_shielding_fee = params.shield_protocol_fee(gross_shield_amount)?;

    // Fee-on-top: the note is credited the FULL requested amount (fixed
    // denomination preserved, Law #1). Section 11: private_balance_credit >=
    // minimum_private_credit — with fee-on-top private_balance_credit ==
    // gross_shield_amount.
    let private_balance_credit = gross_shield_amount;
    if private_balance_credit < params.minimum_private_credit {
        return Err(FeePolicyError::PrivateCreditBelowMinimum {
            private_balance_credit,
            minimum_private_credit: params.minimum_private_credit,
        });
    }

    // The pool pulls gross + protocol fee (escrow gets the gross, reserves get
    // the protocol fee); the ledger fee is charged on top of that by the ledger.
    let pool_transfer_in = gross_shield_amount
        .checked_add(protocol_shielding_fee)
        .ok_or(FeePolicyError::ArithmeticOverflow)?;
    let total_public_debit = pool_transfer_in
        .checked_add(stsh_icrc_transfer_from_fee)
        .ok_or(FeePolicyError::ArithmeticOverflow)?;

    Ok(DepositPreview {
        gross_shield_amount,
        stsh_icrc_transfer_from_fee,
        protocol_shielding_fee,
        private_balance_credit,
        pool_transfer_in,
        total_public_debit,
    })
}

/// Full section 11 deposit precheck: [`compute_deposit_preview`] plus the
/// live public-balance and allowance checks.
///
/// `public_balance` / `allowance` are the caller's current STSH ledger
/// balance and ICRC-2 allowance for the pool, fetched live by the caller
/// (this crate performs no I/O).
pub fn precheck_deposit(
    gross_shield_amount: u128,
    stsh_icrc_transfer_from_fee: u128,
    public_balance: u128,
    allowance: u128,
    params: &GovernanceFeeParams,
) -> Result<DepositPreview, FeePolicyError> {
    let preview = compute_deposit_preview(gross_shield_amount, stsh_icrc_transfer_from_fee, params)?;

    // Section 11: public_balance >= gross_shield_amount + stsh_icrc_transfer_from_fee
    if public_balance < preview.total_public_debit {
        return Err(FeePolicyError::InsufficientPublicBalance {
            required: preview.total_public_debit,
            available: public_balance,
        });
    }

    // Section 11: allowance >= gross_shield_amount + stsh_icrc_transfer_from_fee
    if allowance < preview.total_public_debit {
        return Err(FeePolicyError::InsufficientAllowance {
            required: preview.total_public_debit,
            available: allowance,
        });
    }

    Ok(preview)
}

// ── Withdrawal / unshielding (sections 7, 10, 12, 14) ──────────────────────────

/// Preview of a `withdraw` per docs/STSH_FEE_POLICY.md section 7.
///
/// Worked example (section 7):
/// ```text
/// Private balance withdrawn:      100 STSH
/// STSH ledger transfer fee:       0.01 STSH
/// Protocol unshielding fee:       0.03 STSH
/// Recipient receives:             99.96 STSH
/// ```
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WithdrawalPreview {
    /// Amount debited from the user's private balance (gross). e8s.
    pub withdraw_gross_amount: u128,
    /// Native STSH ICRC ledger fee for the transfer from pool to recipient,
    /// queried live via `icrc1_fee`. e8s.
    pub stsh_icrc_transfer_fee: u128,
    /// Protocol unshielding fee (governance parameter). e8s.
    pub protocol_unshielding_fee: u128,
    /// `withdraw_gross_amount - stsh_icrc_transfer_fee - protocol_unshielding_fee`.
    /// Amount the recipient actually receives. e8s.
    pub recipient_net_amount: u128,
    /// `recipient_net_amount + stsh_icrc_transfer_fee`. Amount debited from
    /// pool escrow via the STSH ledger transfer. e8s.
    pub ledger_debit_from_pool: u128,
}

/// Computes a [`WithdrawalPreview`] and validates the section 12 invariants
/// that depend only on the requested amount and governance parameters (i.e.
/// NOT the live private-balance/escrow checks — see [`precheck_withdrawal`]
/// for the full precheck including those).
pub fn compute_withdrawal_preview(
    withdraw_gross_amount: u128,
    stsh_icrc_transfer_fee: u128,
    params: &GovernanceFeeParams,
) -> Result<WithdrawalPreview, FeePolicyError> {
    // Unshield value fee: max(unshield_flat_minimum, gross * unshield_bps /
    // 10_000). Fee-INCLUSIVE (deducted from the withdrawn amount, unlike the
    // fee-on-top shield) — the recipient nets gross minus ledger fee minus this.
    let protocol_unshielding_fee = params.unshield_protocol_fee(withdraw_gross_amount)?;

    // Section 12: withdraw_gross_amount >= minimum_withdrawal_gross
    if withdraw_gross_amount < params.minimum_withdrawal_gross {
        return Err(FeePolicyError::WithdrawalBelowMinimum {
            withdraw_gross_amount,
            minimum_withdrawal_gross: params.minimum_withdrawal_gross,
        });
    }

    let total_fee = stsh_icrc_transfer_fee
        .checked_add(protocol_unshielding_fee)
        .ok_or(FeePolicyError::ArithmeticOverflow)?;

    // Section 12: withdraw_gross_amount > stsh_icrc_transfer_fee + protocol_unshielding_fee
    if withdraw_gross_amount <= total_fee {
        return Err(FeePolicyError::GrossAmountBelowFees {
            withdraw_gross_amount,
            total_fee,
        });
    }

    let recipient_net_amount = withdraw_gross_amount - total_fee;

    // Section 12: recipient_net_amount >= minimum_recipient_amount
    if recipient_net_amount < params.minimum_recipient_amount {
        return Err(FeePolicyError::RecipientBelowMinimum {
            recipient_net_amount,
            minimum_recipient_amount: params.minimum_recipient_amount,
        });
    }

    let ledger_debit_from_pool = recipient_net_amount
        .checked_add(stsh_icrc_transfer_fee)
        .ok_or(FeePolicyError::ArithmeticOverflow)?;

    Ok(WithdrawalPreview {
        withdraw_gross_amount,
        stsh_icrc_transfer_fee,
        protocol_unshielding_fee,
        recipient_net_amount,
        ledger_debit_from_pool,
    })
}

/// Full section 12 withdrawal precheck: [`compute_withdrawal_preview`] plus
/// the live private-balance and pool-escrow checks.
///
/// `private_balance` is the caller's current private balance (section 12:
/// `private_balance >= withdraw_gross_amount` — this is what makes "full
/// private balance withdrawal" work: pass `private_balance` itself as
/// `withdraw_gross_amount` and this check becomes `>=` with equality).
/// `pool_escrow_balance` is the pool's current on-ledger escrow balance.
pub fn precheck_withdrawal(
    withdraw_gross_amount: u128,
    stsh_icrc_transfer_fee: u128,
    private_balance: u128,
    pool_escrow_balance: u128,
    params: &GovernanceFeeParams,
) -> Result<WithdrawalPreview, FeePolicyError> {
    let preview = compute_withdrawal_preview(withdraw_gross_amount, stsh_icrc_transfer_fee, params)?;

    // Section 12: private_balance >= withdraw_gross_amount
    if private_balance < preview.withdraw_gross_amount {
        return Err(FeePolicyError::InsufficientPrivateBalance {
            withdraw_gross_amount: preview.withdraw_gross_amount,
            private_balance,
        });
    }

    // Section 12: pool_escrow_balance >= recipient_net_amount + stsh_icrc_transfer_fee
    if pool_escrow_balance < preview.ledger_debit_from_pool {
        return Err(FeePolicyError::InsufficientEscrow {
            required: preview.ledger_debit_from_pool,
            available: pool_escrow_balance,
        });
    }

    Ok(preview)
}

/// Section 10: `minimum_withdrawal_gross = max(fixed_floor, total_fee * safety_multiple)`.
///
/// This is a sizing helper for governance/tooling to derive a value for
/// [`GovernanceFeeParams::minimum_withdrawal_gross`] — it is NOT called by
/// [`compute_withdrawal_preview`], which uses the governance-set value
/// directly.
pub fn suggested_minimum_withdrawal_gross(
    stsh_icrc_transfer_fee: u128,
    protocol_unshielding_fee: u128,
    fixed_floor: u128,
    safety_multiple: u128,
) -> Result<u128, FeePolicyError> {
    let total_fee = stsh_icrc_transfer_fee
        .checked_add(protocol_unshielding_fee)
        .ok_or(FeePolicyError::ArithmeticOverflow)?;
    let scaled = total_fee
        .checked_mul(safety_multiple)
        .ok_or(FeePolicyError::ArithmeticOverflow)?;
    Ok(fixed_floor.max(scaled))
}

/// Section 14 accounting deltas applied on a successful withdrawal.
///
/// ```text
/// private_liability   -= withdraw_gross_amount
/// escrow_backing       -= withdraw_gross_amount
/// operations_reserve   += protocol_unshielding_fee
/// ledger_transfer_out  =  recipient_net_amount + stsh_icrc_transfer_fee
/// ```
///
/// Returned as plain deltas; callers apply them to their own stable-state
/// accounting fields (this crate holds no state).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WithdrawalAccountingDelta {
    pub private_liability_decrease: u128,
    pub escrow_backing_decrease: u128,
    pub operations_reserve_increase: u128,
    pub ledger_transfer_out: u128,
}

/// Derives the section 14 accounting deltas from a [`WithdrawalPreview`].
pub fn withdrawal_accounting_delta(preview: &WithdrawalPreview) -> WithdrawalAccountingDelta {
    WithdrawalAccountingDelta {
        private_liability_decrease: preview.withdraw_gross_amount,
        escrow_backing_decrease: preview.withdraw_gross_amount,
        operations_reserve_increase: preview.protocol_unshielding_fee,
        ledger_transfer_out: preview.ledger_debit_from_pool,
    }
}

// ── Private spend (section 8) ──────────────────────────────────────────────────

/// Preview of the fee charged for `private_spend` per section 8.
///
/// ```text
/// private_spend_total_fee = protocol_private_spend_fee
///   [+ stsh_icrc_transfer_fee, only if the spend causes public ledger movement]
/// ```
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PrivateSpendFeePreview {
    /// Protocol private-spend fee (governance parameter). e8s.
    pub protocol_private_spend_fee: u128,
    /// Native STSH ICRC ledger fee, only non-zero if this private spend
    /// causes a public STSH ledger transfer. e8s.
    pub stsh_icrc_transfer_fee: u128,
    /// `protocol_private_spend_fee + stsh_icrc_transfer_fee`. e8s.
    pub total_fee: u128,
    /// Whether this spend involves a public ledger movement (informational —
    /// mirrors the input, kept for callers that pass the preview around).
    pub includes_public_ledger_movement: bool,
}

/// Computes a [`PrivateSpendFeePreview`] per section 8.
///
/// `stsh_icrc_transfer_fee` MUST be `Some(fee)` (live `icrc1_fee` value) when
/// `includes_public_ledger_movement` is `true`, and is ignored (treated as 0)
/// otherwise.
pub fn compute_private_spend_fee_preview(
    includes_public_ledger_movement: bool,
    stsh_icrc_transfer_fee: Option<u128>,
    params: &GovernanceFeeParams,
) -> Result<PrivateSpendFeePreview, FeePolicyError> {
    // Fee-build lane §2: the spend fee is fixed-STSH at launch. An XDR-pegged
    // mode FAILS CLOSED here (quote AND execution reject) until the oracle lane
    // wires price inputs — never a silent fallback to stale/zero pricing.
    let protocol_private_spend_fee = match params.spend_fee_mode() {
        SpendFeeMode::FixedStsh => params.protocol_private_spend_fee_stsh,
        SpendFeeMode::XdrPegged => return Err(FeePolicyError::SpendFeeOracleUnavailable),
    };

    let ledger_fee = if includes_public_ledger_movement {
        stsh_icrc_transfer_fee.ok_or(FeePolicyError::MissingLedgerFeeForPublicTransfer)?
    } else {
        0
    };

    let total_fee = protocol_private_spend_fee
        .checked_add(ledger_fee)
        .ok_or(FeePolicyError::ArithmeticOverflow)?;

    Ok(PrivateSpendFeePreview {
        protocol_private_spend_fee,
        stsh_icrc_transfer_fee: ledger_fee,
        total_fee,
        includes_public_ledger_movement,
    })
}

// ── Wallet fee quote (B3 §0.4 contract) ─────────────────────────────────────────

/// Reference asset a [`FeeQuote`] is denominated in. STSH is the only asset in
/// the fee-build lane; ICP/XDR are reserved for future cash-like assets / the
/// XDR peg.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeAsset {
    Stsh,
    Icp,
    Xdr,
}

/// Wallet-facing fee quote (B3 §0.4). **Preview only** — the pool is the
/// execution authority and rejects any transaction whose
/// `(fee_model_version, params_epoch)` or amounts do not match its live config
/// at execution time. Built from the crate previews so the quote math is
/// byte-identical client- and canister-side.
///
/// `protocol_fee` / `ledger_fee` / `reserve` / gross-net stay SEPARATE fields
/// (never collapsed into one "fee") per B3 §0.1/§0.4. In the value-fee model
/// the protocol fee is itself split to the reserves internally, so
/// `reserve_e8s` is 0 (no reserve is withheld from the user beyond the protocol
/// fee) — the field is retained for contract shape + future cash-like assets.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FeeQuote {
    pub asset: FeeAsset,
    /// STSH protocol fee (income). e8s.
    pub protocol_fee_e8s: u128,
    /// Underlying ICRC ledger fee, if any (separate line). e8s.
    pub ledger_fee_e8s: u128,
    /// Reserve withheld from the user beyond the protocol fee — 0 in the
    /// value-fee model (the protocol fee funds the reserves internally). e8s.
    pub reserve_e8s: u128,
    pub gross_amount_e8s: u128,
    pub net_amount_e8s: u128,
    /// Pool-exposed model version the quote binds to.
    pub fee_model_version: u32,
    /// Pool-exposed params epoch the quote binds to.
    pub params_epoch: u64,
}

/// Builds the wallet [`FeeQuote`] for a shield from a [`DepositPreview`].
pub fn shield_fee_quote(preview: &DepositPreview, params: &GovernanceFeeParams) -> FeeQuote {
    FeeQuote {
        asset: FeeAsset::Stsh,
        protocol_fee_e8s: preview.protocol_shielding_fee,
        ledger_fee_e8s: preview.stsh_icrc_transfer_from_fee,
        reserve_e8s: 0,
        gross_amount_e8s: preview.gross_shield_amount,
        net_amount_e8s: preview.private_balance_credit,
        fee_model_version: params.fee_model_version(),
        params_epoch: params.params_epoch(),
    }
}

/// Builds the wallet [`FeeQuote`] for an unshield from a [`WithdrawalPreview`].
pub fn unshield_fee_quote(preview: &WithdrawalPreview, params: &GovernanceFeeParams) -> FeeQuote {
    FeeQuote {
        asset: FeeAsset::Stsh,
        protocol_fee_e8s: preview.protocol_unshielding_fee,
        ledger_fee_e8s: preview.stsh_icrc_transfer_fee,
        reserve_e8s: 0,
        gross_amount_e8s: preview.withdraw_gross_amount,
        net_amount_e8s: preview.recipient_net_amount,
        fee_model_version: params.fee_model_version(),
        params_epoch: params.params_epoch(),
    }
}

/// Builds the wallet [`FeeQuote`] for a `private_spend` from a
/// [`PrivateSpendFeePreview`]. The spend amounts are hidden, so gross/net are 0
/// — only the (public) protocol + ledger fees are quoted.
pub fn spend_fee_quote(preview: &PrivateSpendFeePreview, params: &GovernanceFeeParams) -> FeeQuote {
    FeeQuote {
        asset: FeeAsset::Stsh,
        protocol_fee_e8s: preview.protocol_private_spend_fee,
        ledger_fee_e8s: preview.stsh_icrc_transfer_fee,
        reserve_e8s: 0,
        gross_amount_e8s: 0,
        net_amount_e8s: 0,
        fee_model_version: params.fee_model_version(),
        params_epoch: params.params_epoch(),
    }
}

// ── Reserve splitting (sections 15, 16, 17, 19) ─────────────────────────────────

/// Result of splitting a protocol action fee across the three reserve
/// buckets (sections 15.4-15.6).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReserveSplit {
    pub operations_reserve: u128,
    pub insurance_reserve: u128,
    /// Always 0 while `staking_rewards_enabled == false` (section 17),
    /// regardless of `staking_rewards_split_bps` — see
    /// [`split_protocol_fee_to_reserves`].
    pub staking_rewards_reserve: u128,
}

/// Splits `fee_amount` (a `protocol_shielding_fee` / `protocol_unshielding_fee`
/// / `protocol_private_spend_fee` charge) across operations / insurance /
/// staking-rewards reserves per `params`'s split bps (section 15/16).
///
/// Per section 17 ("No fee income routes to staking rewards at launch"), if
/// `params.staking_rewards_enabled == false`, the staking share is
/// redistributed to operations and insurance proportionally to their
/// relative bps weights (so the full fee is always accounted for and no
/// value is silently dropped).
///
/// Integer-division remainder (if any) is credited to `operations_reserve`
/// so `operations_reserve + insurance_reserve + staking_rewards_reserve ==
/// fee_amount` exactly.
pub fn split_protocol_fee_to_reserves(
    fee_amount: u128,
    params: &GovernanceFeeParams,
) -> Result<ReserveSplit, FeePolicyError> {
    params.validate_split_bps()?;

    let (ops_bps, ins_bps, staking_bps): (u128, u128, u128) = if params.staking_rewards_enabled {
        (
            params.operations_split_bps as u128,
            params.insurance_split_bps as u128,
            params.staking_rewards_split_bps as u128,
        )
    } else {
        // Redistribute the staking share proportionally to ops/insurance.
        // ops_bps + ins_bps + staking_bps == 10_000 (validated above), and
        // ops_bps + ins_bps > 0 in any sane configuration (staking alone
        // cannot be 100%); guard against the degenerate 0/0 case anyway.
        let ops = params.operations_split_bps as u128;
        let ins = params.insurance_split_bps as u128;
        let staking = params.staking_rewards_split_bps as u128;
        let ops_ins_total = ops + ins;
        if ops_ins_total == 0 {
            // Degenerate config: dump everything into operations.
            (10_000, 0, 0)
        } else {
            let extra_ops = staking * ops / ops_ins_total;
            let extra_ins = staking - extra_ops;
            (ops + extra_ops, ins + extra_ins, 0)
        }
    };

    let operations_reserve = fee_amount
        .checked_mul(ops_bps)
        .ok_or(FeePolicyError::ArithmeticOverflow)?
        / 10_000;
    let insurance_reserve = fee_amount
        .checked_mul(ins_bps)
        .ok_or(FeePolicyError::ArithmeticOverflow)?
        / 10_000;
    let staking_rewards_reserve = if staking_bps == 0 {
        0
    } else {
        fee_amount
            .checked_mul(staking_bps)
            .ok_or(FeePolicyError::ArithmeticOverflow)?
            / 10_000
    };

    // Credit any integer-division remainder to operations so the split sums
    // exactly to fee_amount.
    let allocated = operations_reserve + insurance_reserve + staking_rewards_reserve;
    let remainder = fee_amount - allocated; // fee_amount >= allocated always (floor division)
    let operations_reserve = operations_reserve + remainder;

    debug_assert_eq!(operations_reserve + insurance_reserve + staking_rewards_reserve, fee_amount);

    Ok(ReserveSplit {
        operations_reserve,
        insurance_reserve,
        staking_rewards_reserve,
    })
}

// ── Treasury runway / staking gate (section 18, 19) ─────────────────────────────

/// Section 18: `treasury_runway = available_operating_reserve / monthly_runway_cost`,
/// expressed in whole months (floor division).
///
/// Returns `None` if `monthly_runway_cost == 0` (undefined / infinite
/// runway — callers should treat this as "runway requirement trivially
/// satisfied" or "cost model not configured", per their own policy; this
/// crate does not make that judgement call).
pub fn compute_treasury_runway_months(
    available_operating_reserve: u128,
    monthly_runway_cost: u128,
) -> Option<u128> {
    if monthly_runway_cost == 0 {
        return None;
    }
    Some(available_operating_reserve / monthly_runway_cost)
}

/// Section 18: "No staking-fee distribution may occur unless
/// `treasury_runway >= 6 months`" AND `staking_rewards_enabled == true`
/// (section 17/23 — staking is disabled entirely at launch regardless of
/// runway).
///
/// `runway_months = None` (i.e. `monthly_runway_cost == 0`, see
/// [`compute_treasury_runway_months`]) is treated as runway requirement NOT
/// satisfied — distributions stay paused until the cost model is
/// configured and a concrete runway can be computed.
pub fn staking_distribution_allowed(
    params: &GovernanceFeeParams,
    runway_months: Option<u128>,
) -> bool {
    if !params.staking_rewards_enabled {
        return false;
    }
    match runway_months {
        Some(months) => months >= params.minimum_treasury_runway_months as u128,
        None => false,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 1 STSH = 1e8 e8s (DECIMALS = 8, matches canisters/token).
    const STSH: u128 = 100_000_000;

    fn launch_params() -> GovernanceFeeParams {
        let mut p = GovernanceFeeParams::launch_defaults();
        // Shield/unshield expressed as flat-minimum value fees (bps = 0) to
        // mirror the fixed worked-example fees; the spend fee is the flat
        // protocol spend fee (FixedStsh mode).
        p.shield_flat_minimum_fee_e8s = Some(20_000_000); // 0.20 STSH
        p.unshield_flat_minimum_fee_e8s = Some(3_000_000); // 0.03 STSH
        p.protocol_private_spend_fee_stsh = 5_000_000; // 0.05 STSH (illustrative)
        p
    }

    // ── Section 6 worked example: deposit (fee-ON-TOP) ─────────────────────

    #[test]
    fn deposit_preview_fee_on_top() {
        let params = launch_params();
        let gross = 100 * STSH; // 100 STSH
        let ledger_fee = STSH / 100; // 0.01 STSH

        let preview = compute_deposit_preview(gross, ledger_fee, &params).expect("valid deposit");

        assert_eq!(preview.gross_shield_amount, 100 * STSH);
        assert_eq!(preview.stsh_icrc_transfer_from_fee, STSH / 100); // 0.01
        assert_eq!(preview.protocol_shielding_fee, 20_000_000); // 0.20 (flat-min)
        // Fee ON TOP: the note is credited the FULL 100 STSH.
        assert_eq!(preview.private_balance_credit, 100 * STSH);
        // Pool pulls gross + protocol fee = 100.20 STSH.
        assert_eq!(preview.pool_transfer_in, 100 * STSH + 20_000_000);
        // Total public debit = pool_transfer_in + ledger fee = 100.21 STSH.
        assert_eq!(preview.total_public_debit, 100 * STSH + 20_000_000 + STSH / 100);
    }

    #[test]
    fn deposit_shield_fee_bps_on_top() {
        // 25 bps of 100 STSH = 0.25 STSH, on top of a full 100 STSH credit.
        let mut params = GovernanceFeeParams::launch_defaults();
        params.shield_fee_bps = Some(25);
        params.shield_flat_minimum_fee_e8s = Some(0);
        let gross = 100 * STSH;
        let preview = compute_deposit_preview(gross, 0, &params).unwrap();
        assert_eq!(preview.protocol_shielding_fee, 25 * STSH / 100); // 0.25 STSH
        assert_eq!(preview.private_balance_credit, gross); // full credit
        assert_eq!(preview.pool_transfer_in, gross + 25 * STSH / 100);
    }

    #[test]
    fn deposit_rejects_private_credit_below_minimum() {
        let mut params = launch_params();
        params.minimum_private_credit = 10 * STSH;

        // With fee-on-top, private_balance_credit == gross. 5 STSH < 10 STSH min.
        let err = compute_deposit_preview(5 * STSH, 0, &params).unwrap_err();
        assert!(matches!(err, FeePolicyError::PrivateCreditBelowMinimum { .. }));
    }

    #[test]
    fn precheck_deposit_enforces_balance_and_allowance() {
        let params = launch_params();
        let gross = 100 * STSH;
        let ledger_fee = STSH / 100;
        // total_public_debit = gross + protocol fee (0.20) + ledger fee (0.01).
        let total_debit = compute_deposit_preview(gross, ledger_fee, &params)
            .unwrap()
            .total_public_debit;

        // Exactly enough balance and allowance -> ok
        let preview = precheck_deposit(gross, ledger_fee, total_debit, total_debit, &params)
            .expect("exactly sufficient balance/allowance should pass");
        assert_eq!(preview.total_public_debit, total_debit);

        // Insufficient balance
        let err = precheck_deposit(gross, ledger_fee, total_debit - 1, total_debit, &params).unwrap_err();
        assert!(matches!(err, FeePolicyError::InsufficientPublicBalance { .. }));

        // Insufficient allowance
        let err = precheck_deposit(gross, ledger_fee, total_debit, total_debit - 1, &params).unwrap_err();
        assert!(matches!(err, FeePolicyError::InsufficientAllowance { .. }));
    }

    // ── Section 7 worked example: withdrawal ───────────────────────────────

    #[test]
    fn withdrawal_preview_matches_worked_example() {
        let params = launch_params();
        let gross = 100 * STSH; // 100 STSH
        let ledger_fee = STSH / 100; // 0.01 STSH

        let preview = compute_withdrawal_preview(gross, ledger_fee, &params).expect("valid withdrawal");

        assert_eq!(preview.withdraw_gross_amount, 100 * STSH);
        assert_eq!(preview.stsh_icrc_transfer_fee, STSH / 100); // 0.01
        assert_eq!(preview.protocol_unshielding_fee, 3_000_000); // 0.03
        assert_eq!(preview.recipient_net_amount, 9_996_000_000); // 99.96
        assert_eq!(preview.ledger_debit_from_pool, 9_997_000_000); // 99.97
    }

    #[test]
    fn withdrawal_rejects_below_minimum_gross() {
        let mut params = launch_params();
        params.minimum_withdrawal_gross = 10 * STSH;

        let err = compute_withdrawal_preview(10 * STSH - 1, STSH / 100, &params).unwrap_err();
        assert!(matches!(err, FeePolicyError::WithdrawalBelowMinimum { .. }));

        // exactly at minimum -> passes the minimum check (may still fail
        // other checks depending on fee sizes, but not this one)
        let result = compute_withdrawal_preview(10 * STSH, STSH / 100, &params);
        assert!(!matches!(result, Err(FeePolicyError::WithdrawalBelowMinimum { .. })));
    }

    #[test]
    fn withdrawal_rejects_gross_not_exceeding_total_fee() {
        let params = launch_params();
        // Unshield flat-min fee (0.03) + ledger fee (0.01); flat-min is constant
        // in gross so this stays exact.
        let total_fee = params.unshield_flat_minimum_fee_e8s() + (STSH / 100);

        let err = compute_withdrawal_preview(total_fee, STSH / 100, &params).unwrap_err();
        assert!(matches!(err, FeePolicyError::GrossAmountBelowFees { .. }));
    }

    #[test]
    fn withdrawal_rejects_recipient_dust() {
        let mut params = launch_params();
        params.minimum_recipient_amount = 50 * STSH;

        let total_fee = params.unshield_flat_minimum_fee_e8s() + (STSH / 100);
        // recipient_net = gross - total_fee = 1 STSH < 50 STSH minimum
        let gross = total_fee + 1 * STSH;
        let err = compute_withdrawal_preview(gross, STSH / 100, &params).unwrap_err();
        assert!(matches!(err, FeePolicyError::RecipientBelowMinimum { .. }));
    }

    #[test]
    fn full_private_balance_withdrawal_works() {
        let params = launch_params();
        let private_balance = 1_234 * STSH + 56_789; // arbitrary non-round balance
        let ledger_fee = STSH / 100;

        // Withdrawing the FULL private balance gross == private_balance.
        let preview = precheck_withdrawal(
            private_balance,
            ledger_fee,
            private_balance,        // private_balance == withdraw_gross_amount
            preview_escrow(private_balance, ledger_fee, &params),
            &params,
        )
        .expect("full balance withdrawal should be accepted");

        assert_eq!(preview.withdraw_gross_amount, private_balance);
        // Nothing left "stuck" in the private balance.
        let delta = withdrawal_accounting_delta(&preview);
        assert_eq!(delta.private_liability_decrease, private_balance);
        assert_eq!(delta.escrow_backing_decrease, private_balance);
    }

    /// Helper: minimum escrow needed for a withdrawal to pass precheck.
    fn preview_escrow(gross: u128, ledger_fee: u128, params: &GovernanceFeeParams) -> u128 {
        let preview = compute_withdrawal_preview(gross, ledger_fee, params).unwrap();
        preview.ledger_debit_from_pool
    }

    #[test]
    fn precheck_withdrawal_enforces_private_balance_and_escrow() {
        let params = launch_params();
        let gross = 100 * STSH;
        let ledger_fee = STSH / 100;
        let preview = compute_withdrawal_preview(gross, ledger_fee, &params).unwrap();
        let required_escrow = preview.ledger_debit_from_pool;

        // Insufficient private balance
        let err = precheck_withdrawal(gross, ledger_fee, gross - 1, required_escrow, &params).unwrap_err();
        assert!(matches!(err, FeePolicyError::InsufficientPrivateBalance { .. }));

        // Insufficient escrow
        let err = precheck_withdrawal(gross, ledger_fee, gross, required_escrow - 1, &params).unwrap_err();
        assert!(matches!(err, FeePolicyError::InsufficientEscrow { .. }));

        // Exactly sufficient -> ok
        precheck_withdrawal(gross, ledger_fee, gross, required_escrow, &params).expect("exact sufficiency should pass");
    }

    #[test]
    fn withdrawal_accounting_delta_invariant() {
        let params = launch_params();
        let gross = 100 * STSH;
        let ledger_fee = STSH / 100;
        let preview = compute_withdrawal_preview(gross, ledger_fee, &params).unwrap();
        let delta = withdrawal_accounting_delta(&preview);

        // Section 14 invariant: ledger_transfer_out = recipient_net + ledger_fee
        assert_eq!(delta.ledger_transfer_out, preview.recipient_net_amount + ledger_fee);
        assert_eq!(delta.private_liability_decrease, gross);
        assert_eq!(delta.escrow_backing_decrease, gross);
        assert_eq!(delta.operations_reserve_increase, params.unshield_protocol_fee(gross).unwrap());
    }

    // ── Section 8: private spend fee ───────────────────────────────────────

    #[test]
    fn private_spend_fee_without_public_movement_excludes_ledger_fee() {
        let params = launch_params();
        let preview = compute_private_spend_fee_preview(false, None, &params).unwrap();

        assert_eq!(preview.protocol_private_spend_fee, params.protocol_private_spend_fee_stsh);
        assert_eq!(preview.stsh_icrc_transfer_fee, 0);
        assert_eq!(preview.total_fee, params.protocol_private_spend_fee_stsh);
        assert!(!preview.includes_public_ledger_movement);
    }

    #[test]
    fn private_spend_fee_with_public_movement_includes_ledger_fee() {
        let params = launch_params();
        let ledger_fee = STSH / 100;
        let preview = compute_private_spend_fee_preview(true, Some(ledger_fee), &params).unwrap();

        assert_eq!(preview.stsh_icrc_transfer_fee, ledger_fee);
        assert_eq!(preview.total_fee, params.protocol_private_spend_fee_stsh + ledger_fee);
    }

    #[test]
    fn private_spend_fee_with_public_movement_requires_ledger_fee() {
        let params = launch_params();
        let err = compute_private_spend_fee_preview(true, None, &params).unwrap_err();
        assert_eq!(err, FeePolicyError::MissingLedgerFeeForPublicTransfer);
    }

    // ── Section 10: suggested minimum withdrawal ───────────────────────────

    #[test]
    fn suggested_minimum_withdrawal_uses_max_of_floor_and_scaled_fee() {
        let total_fee = 4_000_000u128; // 0.01 + 0.03 STSH
        let safety_multiple = 20u128;

        // Scaled fee dominates: 4_000_000 * 20 = 80_000_000 (0.80 STSH) > floor
        let v = suggested_minimum_withdrawal_gross(STSH / 100, 3_000_000, 1_000_000, safety_multiple).unwrap();
        assert_eq!(v, total_fee * safety_multiple);

        // Floor dominates
        let v = suggested_minimum_withdrawal_gross(0, 0, 1_000_000, safety_multiple).unwrap();
        assert_eq!(v, 1_000_000);
    }

    // ── Sections 15-17: reserve splitting ──────────────────────────────────

    #[test]
    fn reserve_split_sums_to_fee_amount_when_staking_disabled() {
        let mut params = launch_params();
        params.operations_split_bps = 8_500;
        params.insurance_split_bps = 1_500;
        params.staking_rewards_split_bps = 0;
        params.staking_rewards_enabled = false;

        let fee = 1_000_000_007u128; // deliberately not a round number
        let split = split_protocol_fee_to_reserves(fee, &params).unwrap();

        assert_eq!(split.staking_rewards_reserve, 0);
        assert_eq!(
            split.operations_reserve + split.insurance_reserve + split.staking_rewards_reserve,
            fee
        );
    }

    /// NOTE (W4 4-3, 2026-08-18): this test deliberately exercises a
    /// configuration the SETTER now refuses
    /// ([`GovernanceFeeParams::validate_staking_posture`]). That is not a
    /// contradiction and the test is deliberately left unweakened — it is the
    /// second line of defence. The setter stops such a posture being STORED;
    /// this proves that if one ever was stored (or predates the binding), the
    /// fee path still routes nothing to staking and still accounts for the
    /// whole fee. Do not delete this because "the setter prevents it".
    #[test]
    fn reserve_split_redistributes_staking_share_when_disabled() {
        let mut params = launch_params();
        // Configure as if staking WERE enabled with a 10% share...
        params.operations_split_bps = 8_000;
        params.insurance_split_bps = 1_000;
        params.staking_rewards_split_bps = 1_000;
        // ...but staking is disabled at launch (section 17).
        params.staking_rewards_enabled = false;

        let fee = 100 * STSH;
        let split = split_protocol_fee_to_reserves(fee, &params).unwrap();

        assert_eq!(split.staking_rewards_reserve, 0);
        assert_eq!(split.operations_reserve + split.insurance_reserve, fee);
        // Operations (8000) and insurance (1000) split the extra 1000 in
        // proportion 8:1, i.e. ops gets 8/9 of the extra share.
        assert!(split.operations_reserve > 8_000 * fee / 10_000);
        assert!(split.insurance_reserve > 1_000 * fee / 10_000);
    }

    #[test]
    fn reserve_split_enabled_staking_uses_configured_bps() {
        let mut params = launch_params();
        params.operations_split_bps = 7_000;
        params.insurance_split_bps = 1_500;
        params.staking_rewards_split_bps = 1_500;
        params.staking_rewards_enabled = true;

        let fee = 100 * STSH;
        let split = split_protocol_fee_to_reserves(fee, &params).unwrap();

        assert_eq!(split.operations_reserve + split.insurance_reserve + split.staking_rewards_reserve, fee);
        assert!(split.staking_rewards_reserve > 0);
    }

    #[test]
    fn reserve_split_rejects_invalid_bps_total() {
        let mut params = launch_params();
        params.operations_split_bps = 5_000;
        params.insurance_split_bps = 1_000;
        params.staking_rewards_split_bps = 0; // sums to 6_000, not 10_000

        let err = split_protocol_fee_to_reserves(1_000, &params).unwrap_err();
        assert!(matches!(err, FeePolicyError::InvalidFeeSplitBps { .. }));
    }

    // ── Section 18: runway / staking gate ──────────────────────────────────

    #[test]
    fn runway_months_floor_division() {
        assert_eq!(compute_treasury_runway_months(1_000, 100), Some(10));
        assert_eq!(compute_treasury_runway_months(1_050, 100), Some(10)); // floor
        assert_eq!(compute_treasury_runway_months(0, 100), Some(0));
        assert_eq!(compute_treasury_runway_months(1_000, 0), None);
    }

    #[test]
    fn staking_distribution_disabled_at_launch_regardless_of_runway() {
        let mut params = launch_params();
        params.staking_rewards_enabled = false;
        params.minimum_treasury_runway_months = 6;

        // Even with a huge runway, staking stays off while the flag is false.
        assert!(!staking_distribution_allowed(&params, Some(1_000)));
        assert!(!staking_distribution_allowed(&params, None));
    }

    #[test]
    fn staking_distribution_gated_on_runway_when_enabled() {
        let mut params = launch_params();
        params.staking_rewards_enabled = true;
        params.minimum_treasury_runway_months = 6;

        assert!(!staking_distribution_allowed(&params, Some(5)));
        assert!(staking_distribution_allowed(&params, Some(6)));
        assert!(staking_distribution_allowed(&params, Some(12)));
        assert!(!staking_distribution_allowed(&params, None));
    }

    // ── W4 4-3: staking launch posture binding ─────────────────────────────

    #[test]
    fn staking_split_nonzero_while_disabled_is_rejected() {
        let mut params = launch_params();
        params.operations_split_bps = 8_000;
        params.insurance_split_bps = 1_000;
        params.staking_rewards_split_bps = 1_000;
        params.staking_rewards_enabled = false;

        // The split total is perfectly valid — this is NOT a sum defect, and
        // the posture error must name itself rather than borrow InvalidFeeSplitBps.
        params.validate_split_bps().expect("split total is valid");

        let err = params.validate_staking_posture().unwrap_err();
        assert!(matches!(
            err,
            FeePolicyError::StakingSplitNonzeroWhileDisabled { staking_rewards_split_bps: 1_000 }
        ));
    }

    /// The G-FEESPLIT gate: the master switch cannot be turned on at all while
    /// the section-18 runway gate is unwired, independently of the split value.
    /// Both shapes are refused, and each names its own reason.
    #[test]
    fn enabling_staking_is_blocked_while_the_runway_is_unwired() {
        let mut params = launch_params();
        params.operations_split_bps = 7_000;
        params.insurance_split_bps = 1_500;
        params.staking_rewards_split_bps = 1_500;
        params.staking_rewards_enabled = true;

        assert!(matches!(
            params.validate_staking_posture().unwrap_err(),
            FeePolicyError::StakingEnableBlockedRunwayUnwired
        ));

        // Even with a zero split — enabling the switch is itself the blocked act.
        params.operations_split_bps = 8_500;
        params.insurance_split_bps = 1_500;
        params.staking_rewards_split_bps = 0;
        assert!(matches!(
            params.validate_staking_posture().unwrap_err(),
            FeePolicyError::StakingEnableBlockedRunwayUnwired
        ));
    }

    #[test]
    fn the_launch_posture_itself_passes() {
        let mut params = launch_params();
        params.operations_split_bps = 8_500;
        params.insurance_split_bps = 1_500;
        params.staking_rewards_split_bps = 0;
        params.staking_rewards_enabled = false;

        params
            .validate_staking_posture()
            .expect("staking off + zero split is the launch posture and must pass");
    }

    /// The posture binding is a SETTER rule and must not leak into the fee
    /// path. `split_protocol_fee_to_reserves` runs against already-stored
    /// params — including any written before the binding existed — and must
    /// still redistribute rather than fail. Defence in depth, both layers live.
    #[test]
    fn posture_binding_does_not_break_the_split_path_for_stored_params() {
        let mut params = launch_params();
        params.operations_split_bps = 8_000;
        params.insurance_split_bps = 1_000;
        params.staking_rewards_split_bps = 1_000;
        params.staking_rewards_enabled = false;

        // The setter would now refuse this configuration...
        assert!(params.validate_staking_posture().is_err());
        // ...but if it is already stored, the split still accounts for the
        // full fee and still routes nothing to staking.
        let fee = 100 * STSH;
        let split = split_protocol_fee_to_reserves(fee, &params).unwrap();
        assert_eq!(split.staking_rewards_reserve, 0);
        assert_eq!(split.operations_reserve + split.insurance_reserve, fee);
    }

    /// W4 4-2 (document-and-gate): the launch posture is that staking is OFF.
    /// The runway engine is deliberately NOT built — `monthly_runway_cost` has
    /// no on-chain storage and `staking_distribution_allowed` has no production
    /// call site. Both are G-FEESPLIT gate items that must close BEFORE
    /// `staking_rewards_enabled` may be set true (post-launch by the D1 ruling).
    /// Until then this assertion is the enforcement.
    #[test]
    fn w4_4_2_launch_config_keeps_staking_off_and_split_zero() {
        for (name, params) in [
            ("launch_defaults", GovernanceFeeParams::launch_defaults()),
            ("mainnet_launch_config", GovernanceFeeParams::mainnet_launch_config()),
        ] {
            assert!(!params.staking_rewards_enabled, "{name}: staking must be off at launch");
            assert_eq!(params.staking_rewards_split_bps, 0, "{name}: staking split must be 0");
            params
                .validate_staking_posture()
                .unwrap_or_else(|e| panic!("{name}: launch posture must satisfy 4-3: {e:?}"));
        }
    }

    #[test]
    fn launch_defaults_pass_split_bps_validation() {
        let params = GovernanceFeeParams::launch_defaults();
        params.validate_split_bps().expect("launch defaults must sum to 10_000 bps");
        assert!(!params.staking_rewards_enabled);
        assert_eq!(params.staking_rewards_split_bps, 0);
    }

    /// Drift guard: the documented mainnet launch config must equal the values
    /// in MAINNET_DEPLOYMENT.md (25 bps shield/unshield + 2.5 STSH spend,
    /// FixedStsh), and `launch_defaults()` must stay fail-safe fee-free. If any
    /// of these change, this test fails so the doc + deploy gate are updated in
    /// lockstep.
    #[test]
    fn mainnet_launch_config_matches_documented_values() {
        let c = GovernanceFeeParams::mainnet_launch_config();
        assert_eq!(c.shield_fee_bps(), 25, "documented launch shield fee = 25 bps");
        assert_eq!(c.unshield_fee_bps(), 25, "documented launch unshield fee = 25 bps");
        assert_eq!(
            c.protocol_private_spend_fee_stsh, 250_000_000,
            "documented launch spend fee = 2.5 STSH"
        );
        assert_eq!(c.spend_fee_mode(), SpendFeeMode::FixedStsh, "fixed-STSH mode at launch");
        // RULED by OWNER_RULING_FEE_FLOOR_2_5_STSH 2026-09-08 (lane A6.6/R-14):
        // the launch flat minimum is 2.5 STSH in BOTH directions, superseding the
        // 0.1 STSH of 2026-08-21, which superseded the 1,000 STSH of 2026-07-31
        // (RB-SWARM-A1). Retargeted with the ruling cited here rather than
        // weakened — the literal value is asserted, never read back from the
        // constant it is meant to guard.
        assert_eq!(
            c.shield_flat_minimum_fee_e8s(),
            250_000_000,
            "documented launch shield flat minimum = 2.5 STSH"
        );
        assert_eq!(
            c.unshield_flat_minimum_fee_e8s(),
            250_000_000,
            "documented launch unshield flat minimum = 2.5 STSH"
        );
        // The 2.5-STSH flat minimum is NOT the in-circuit fee wall (A6.6 widened
        // that to 10^15 e8s along with the top ladder rung). Separate values,
        // separate lanes.
        assert_ne!(
            c.shield_flat_minimum_fee_e8s(),
            10_000_000 * E8S_PER_STSH,
            "flat minimum must not be conflated with the in-circuit fee wall"
        );
        c.validate_split_bps().expect("launch config split bps must be valid");
        // The launch config must be settable through the guarded setter — if it
        // were not, the deploy step could never run.
        c.validate_fee_bounds()
            .expect("the mainnet launch config must satisfy the ruled absolute bounds");
        assert!(c.matches_mainnet_launch_config(), "the launch config matches itself");

        // launch_defaults() (the CODE default) stays fee-free.
        let d = GovernanceFeeParams::launch_defaults();
        assert_eq!(d.shield_fee_bps(), 0, "code default must remain fee-free");
        assert_eq!(d.unshield_fee_bps(), 0, "code default must remain fee-free");
        assert_eq!(d.protocol_private_spend_fee_stsh, 0, "code default must remain fee-free");
        assert_eq!(d.shield_flat_minimum_fee_e8s(), 0, "code default must remain fee-free");
        assert_eq!(d.unshield_flat_minimum_fee_e8s(), 0, "code default must remain fee-free");
    }

    /// A6.6 / A66-FEE-FLOOR — the live exit-fee helper, exercised as a function
    /// of its argument rather than as a restated constant.
    ///
    /// `unshield_protocol_fee` is invoked at the ladder's FLOOR rung and at the
    /// rung above it under the shipped launch config (25 bps, 2.5 STSH flat
    /// minimum). The two results must differ: at 1,000 STSH the value fee is
    /// exactly 2.5 STSH (0.25% x 1,000), and at 10,000 STSH it is 25 STSH. A fee
    /// helper that returned the same number for both would be a flat fee wearing
    /// a percentage's name — precisely what the 2.5 STSH floor could have masked
    /// if it had been set above the value fee at the floor rung.
    ///
    /// It also pins the continuity the ruling relies on: 2.5 STSH is where the
    /// flat minimum and the value fee MEET at the floor rung, so the minimum
    /// binds only below the ladder and never inside it.
    // BINDING: A66-FEE-FLOOR
    #[test]
    fn test_unshield_protocol_fee_differs_across_the_launch_ladder() {
        let params = GovernanceFeeParams::mainnet_launch_config();

        let floor_rung = 1_000 * E8S_PER_STSH;
        let next_rung = 10_000 * E8S_PER_STSH;

        let at_floor = params
            .unshield_protocol_fee(floor_rung)
            .expect("the exit fee must be computable at the floor rung");
        let at_next = params
            .unshield_protocol_fee(next_rung)
            .expect("the exit fee must be computable at the rung above");

        assert_ne!(
            at_floor, at_next,
            "the exit fee must scale with the amount, not sit flat across the ladder"
        );
        assert_eq!(at_floor, 250_000_000, "0.25% x 1,000 STSH = 2.5 STSH");
        assert_eq!(at_next, 2_500_000_000, "0.25% x 10,000 STSH = 25 STSH");

        // Continuity at the floor rung: the flat minimum equals the value fee
        // there, so it is never the binding term anywhere on the ladder.
        assert_eq!(at_floor, MAINNET_LAUNCH_FLAT_MINIMUM_FEE_E8S);
    }

    // ── A-1 setter guardrails (RB-SWARM-A1, RULED 2026-07-31) ───────────────
    //
    // These cover the PURE half: what a submitted parameter set must satisfy,
    // and how far one call may move it. The stateful half — cooldown clock,
    // canister-owned epoch, bootstrap one-shot, atomic rejection — needs a real
    // canister and lives in `integration-tests/tests/fee_setter_guardrail_tests.rs`.

    /// The ruled bounds are law; a typo in one of them is a policy change made
    /// by accident. Pin every number the ruling names.
    #[test]
    fn ruled_guardrail_constants_are_the_ruled_values() {
        assert_eq!(FEE_BPS_FLOOR, 1);
        assert_eq!(FEE_BPS_CEILING, 500);
        assert_eq!(MAX_BPS_CHANGE_PER_UPDATE, 100);
        // A-7: OWNER_RULING_FEE_MODEL_CONSOLIDATED_2026-08-21 moves the floor to
        // 0.1 STSH; CTO_RULING_A-7_flatmin_ceiling_2026-08-21 moves the ceiling to
        // 5 STSH. Literal values, not derived from the constants under test.
        assert_eq!(FLAT_MINIMUM_FEE_FLOOR_E8S, 10_000_000);
        assert_eq!(FLAT_MINIMUM_FEE_CEILING_E8S, 500_000_000);
        assert_eq!(PRIVATE_SPEND_FEE_FLOOR_E8S, E8S_PER_STSH / 10);
        assert_eq!(PRIVATE_SPEND_FEE_CEILING_E8S, 5 * E8S_PER_STSH);
        assert_eq!(FEE_UPDATE_COOLDOWN_NS, 24 * 60 * 60 * 1_000_000_000);
        // A6.6 (OWNER_RULING_FEE_FLOOR_2_5_STSH): the launch flat minimum is no
        // longer the guardrail floor — the FLOOR is unchanged at 0.1 STSH and the
        // launch value now sits above it, strictly inside the band. Asserted as a
        // relation, so a future ruling that collapses them again REDs here.
        assert_eq!(MAINNET_LAUNCH_FLAT_MINIMUM_FEE_E8S, 250_000_000);
        assert!(MAINNET_LAUNCH_FLAT_MINIMUM_FEE_E8S > FLAT_MINIMUM_FEE_FLOOR_E8S);
        assert!(MAINNET_LAUNCH_FLAT_MINIMUM_FEE_E8S < FLAT_MINIMUM_FEE_CEILING_E8S);
    }

    /// A rate above 100% is rejected as such, ahead of the range check, so the
    /// error names the real defect rather than burying it.
    #[test]
    fn bps_above_one_hundred_percent_rejected_outright() {
        let mut p = GovernanceFeeParams::mainnet_launch_config();
        p.shield_fee_bps = Some(10_001);
        match p.validate_fee_bounds() {
            Err(FeePolicyError::BpsAboveOneHundredPercent { field, bps }) => {
                assert_eq!(field, "shield_fee_bps");
                assert_eq!(bps, 10_001);
            }
            other => panic!("expected BpsAboveOneHundredPercent, got {other:?}"),
        }
        // Exactly 10 000 is not "above 100%" — it falls through to the range
        // check, which is what rejects it.
        let mut p = GovernanceFeeParams::mainnet_launch_config();
        p.unshield_fee_bps = Some(BPS_DENOMINATOR);
        assert!(matches!(
            p.validate_fee_bounds(),
            Err(FeePolicyError::FeeRateOutOfRange { .. })
        ));
    }

    /// Rate bounds are inclusive at both ends: 1 and 500 pass, 0 and 501 fail.
    #[test]
    fn fee_rate_bounds_are_inclusive() {
        for bps in [FEE_BPS_FLOOR, 25, FEE_BPS_CEILING] {
            let mut p = GovernanceFeeParams::mainnet_launch_config();
            p.shield_fee_bps = Some(bps);
            p.unshield_fee_bps = Some(bps);
            p.validate_fee_bounds().unwrap_or_else(|e| panic!("{bps} bps must pass: {e:?}"));
        }
        for bps in [0u16, FEE_BPS_CEILING + 1] {
            let mut p = GovernanceFeeParams::mainnet_launch_config();
            p.shield_fee_bps = Some(bps);
            assert!(
                matches!(p.validate_fee_bounds(), Err(FeePolicyError::FeeRateOutOfRange { .. })),
                "{bps} bps must be rejected"
            );
        }
    }

    /// Zeroing is not a routine `set` — the ruling's central point. A "reset to
    /// launch_defaults" call must be refused by the ordinary setter path.
    #[test]
    fn launch_defaults_cannot_be_set_through_the_guarded_path() {
        assert!(
            GovernanceFeeParams::launch_defaults().validate_fee_bounds().is_err(),
            "the fee-free code default must not be reachable as a routine governance set"
        );
    }

    /// STSH-denominated absolute bounds, inclusive at both ends (L8-F1: the
    /// per-call ratio alone would permit unbounded daily doubling).
    #[test]
    fn stsh_denominated_absolute_bounds_are_inclusive() {
        let ok = [
            (FLAT_MINIMUM_FEE_FLOOR_E8S, PRIVATE_SPEND_FEE_FLOOR_E8S),
            (FLAT_MINIMUM_FEE_CEILING_E8S, PRIVATE_SPEND_FEE_CEILING_E8S),
        ];
        for (flat, spend) in ok {
            let mut p = GovernanceFeeParams::mainnet_launch_config();
            p.shield_flat_minimum_fee_e8s = Some(flat);
            p.unshield_flat_minimum_fee_e8s = Some(flat);
            p.protocol_private_spend_fee_stsh = spend;
            p.validate_fee_bounds().expect("boundary values must be accepted");
        }

        let bad = [
            FLAT_MINIMUM_FEE_FLOOR_E8S - 1,
            FLAT_MINIMUM_FEE_CEILING_E8S + 1,
            0,
        ];
        for flat in bad {
            let mut p = GovernanceFeeParams::mainnet_launch_config();
            p.shield_flat_minimum_fee_e8s = Some(flat);
            assert!(
                matches!(p.validate_fee_bounds(), Err(FeePolicyError::FeeAmountOutOfRange { .. })),
                "flat minimum {flat} must be rejected"
            );
        }
        for spend in [PRIVATE_SPEND_FEE_FLOOR_E8S - 1, PRIVATE_SPEND_FEE_CEILING_E8S + 1, 0] {
            let mut p = GovernanceFeeParams::mainnet_launch_config();
            p.protocol_private_spend_fee_stsh = spend;
            assert!(
                matches!(p.validate_fee_bounds(), Err(FeePolicyError::FeeAmountOutOfRange { .. })),
                "spend fee {spend} must be rejected"
            );
        }
    }

    /// The advertised cooldown cannot drift from the enforced one.
    #[test]
    fn cooldown_field_must_equal_the_enforced_constant() {
        let mut p = GovernanceFeeParams::mainnet_launch_config();
        p.fee_update_cooldown_ns = 1;
        assert!(matches!(
            p.validate_fee_bounds(),
            Err(FeePolicyError::FeeUpdateCooldownFieldMismatch { configured_ns: 1, .. })
        ));
    }

    /// The rate cap is ABSOLUTE basis points, NOT percent-of-current — the
    /// distinction SSA fold v2 gate 2 required. 25 -> 125 passes (100 points);
    /// 25 -> 126 fails, even though `max_fee_change_bps_per_update` (1 000 =
    /// 10% of current) would be a far tighter percent-of-current limit and is
    /// deliberately not consulted here.
    #[test]
    fn rate_change_cap_is_absolute_points_not_percent_of_current() {
        let current = GovernanceFeeParams::mainnet_launch_config(); // 25 bps
        assert_eq!(current.shield_fee_bps(), 25);

        let mut ok = current.clone();
        ok.shield_fee_bps = Some(125);
        ok.validate_fee_change_from(&current).expect("+100 absolute points is permitted");

        let mut too_far = current.clone();
        too_far.shield_fee_bps = Some(126);
        match too_far.validate_fee_change_from(&current) {
            Err(FeePolicyError::FeeRateChangeTooLarge { current_bps, requested_bps, max_abs_change_bps, .. }) => {
                assert_eq!((current_bps, requested_bps, max_abs_change_bps), (25, 126, 100));
            }
            other => panic!("expected FeeRateChangeTooLarge, got {other:?}"),
        }

        // Downward moves are capped identically — 500 -> 399 is 101 points.
        let mut high = current.clone();
        high.shield_fee_bps = Some(500);
        let mut down = current.clone();
        down.shield_fee_bps = Some(399);
        assert!(down.validate_fee_change_from(&high).is_err());
        down.shield_fee_bps = Some(400);
        assert!(down.validate_fee_change_from(&high).is_ok());
    }

    /// The STSH ratio bound is bidirectional: `[0.5x, 2x]`.
    #[test]
    fn stsh_amount_ratio_is_bidirectional() {
        let mut current = GovernanceFeeParams::mainnet_launch_config();
        current.protocol_private_spend_fee_stsh = E8S_PER_STSH; // 1 STSH

        for requested in [E8S_PER_STSH / 2, E8S_PER_STSH, 2 * E8S_PER_STSH] {
            let mut p = current.clone();
            p.protocol_private_spend_fee_stsh = requested;
            p.validate_fee_change_from(&current)
                .unwrap_or_else(|e| panic!("{requested} must be within [0.5x, 2x]: {e:?}"));
        }
        for requested in [E8S_PER_STSH / 2 - 1, 2 * E8S_PER_STSH + 1] {
            let mut p = current.clone();
            p.protocol_private_spend_fee_stsh = requested;
            assert!(
                matches!(
                    p.validate_fee_change_from(&current),
                    Err(FeePolicyError::FeeAmountChangeOutOfRatio { .. })
                ),
                "{requested} must be outside [0.5x, 2x]"
            );
        }
    }

    /// Ratio and absolute bounds are INDEPENDENT layers: a `2x` move that lands
    /// above the absolute ceiling is still refused. This is the L8-F1 fix — the
    /// ratio alone permits unbounded doubling day after day.
    #[test]
    fn ratio_does_not_license_escaping_the_absolute_ceiling() {
        let mut current = GovernanceFeeParams::mainnet_launch_config();
        current.shield_flat_minimum_fee_e8s = Some(3_000 * E8S_PER_STSH);

        let mut doubled = current.clone();
        doubled.shield_flat_minimum_fee_e8s = Some(6_000 * E8S_PER_STSH);
        // The transition check alone is happy — exactly 2x.
        doubled.validate_fee_change_from(&current).expect("2x satisfies the ratio layer");
        // The absolute layer is what stops it.
        assert!(
            matches!(
                doubled.validate_fee_bounds(),
                Err(FeePolicyError::FeeAmountOutOfRange { .. })
            ),
            "6,000 STSH exceeds the 5,000 STSH absolute ceiling"
        );
    }

    /// Bootstrap is exactly the transition an ordinary per-call cap forbids —
    /// which is WHY the ruling exempts it, and why the exemption has to be
    /// one-shot canister state rather than an inference.
    #[test]
    fn bootstrap_transition_would_fail_the_ordinary_change_cap() {
        let defaults = GovernanceFeeParams::launch_defaults();
        let launch = GovernanceFeeParams::mainnet_launch_config();
        assert!(
            launch.validate_fee_change_from(&defaults).is_err(),
            "0 -> launch must be inexpressible as a routine tuning step"
        );
    }

    /// The equality predicate is exact, and is an INITIAL-LAUNCH check: it goes
    /// false after any legitimate tuning, which is expected, not a fault.
    #[test]
    fn launch_config_equality_predicate() {
        assert!(GovernanceFeeParams::mainnet_launch_config().matches_mainnet_launch_config());
        assert!(
            !GovernanceFeeParams::launch_defaults().matches_mainnet_launch_config(),
            "the fee-free code default is NOT the launch config"
        );

        // One legitimate post-launch tuning step, and the predicate is false.
        let mut tuned = GovernanceFeeParams::mainnet_launch_config();
        tuned.shield_fee_bps = Some(50);
        assert!(!tuned.matches_mainnet_launch_config());

        // The epoch is part of the identity: the launch config is epoch 1.
        let mut wrong_epoch = GovernanceFeeParams::mainnet_launch_config();
        wrong_epoch.params_epoch = Some(2);
        assert!(!wrong_epoch.matches_mainnet_launch_config());
    }

    // ── Value-fee mechanism (fee-build lane) ───────────────────────────────

    #[test]
    fn value_fee_bps_floor_and_flat_minimum() {
        // 25 bps of 100 STSH = 0.25 STSH.
        assert_eq!(value_fee(100 * STSH, 25, 0).unwrap(), 25 * STSH / 100);
        // Flat minimum wins when it exceeds the bps amount.
        assert_eq!(value_fee(100 * STSH, 25, 1 * STSH).unwrap(), 1 * STSH);
        // Floor division rounds in the user's favour: 25 bps of 3 e8s = 0.
        assert_eq!(value_fee(3, 25, 0).unwrap(), 0);
        // bps = 0 with no floor → 0.
        assert_eq!(value_fee(u128::MAX, 0, 0).unwrap(), 0);
    }

    #[test]
    fn value_fee_multiply_is_checked_not_wrapping() {
        // amount * bps overflows u128 → explicit error, never a wrapped value.
        let err = value_fee(u128::MAX, 25, 0).unwrap_err();
        assert!(matches!(err, FeePolicyError::ArithmeticOverflow));
    }

    #[test]
    fn spend_fee_fixed_mode_uses_flat_value() {
        let mut params = GovernanceFeeParams::launch_defaults();
        params.protocol_private_spend_fee_stsh = 10_000_000; // 0.1 STSH
        let preview = compute_private_spend_fee_preview(false, None, &params).unwrap();
        assert_eq!(preview.total_fee, 10_000_000);
    }

    #[test]
    fn spend_fee_xdr_pegged_fails_closed() {
        let mut params = GovernanceFeeParams::launch_defaults();
        params.spend_fee_mode = Some(SpendFeeMode::XdrPegged);
        params.protocol_private_spend_fee_stsh = 10_000_000;
        // No oracle wired this lane → quote rejects rather than pricing off
        // stale/zero inputs.
        let err = compute_private_spend_fee_preview(false, None, &params).unwrap_err();
        assert!(matches!(err, FeePolicyError::SpendFeeOracleUnavailable));
    }

    #[test]
    fn shield_fee_quote_keeps_fields_separate() {
        let params = launch_params();
        let preview = compute_deposit_preview(100 * STSH, STSH / 100, &params).unwrap();
        let quote = shield_fee_quote(&preview, &params);
        assert_eq!(quote.protocol_fee_e8s, 20_000_000); // 0.20
        assert_eq!(quote.ledger_fee_e8s, STSH / 100); // 0.01 — separate line
        assert_eq!(quote.reserve_e8s, 0);
        assert_eq!(quote.gross_amount_e8s, 100 * STSH);
        assert_eq!(quote.net_amount_e8s, 100 * STSH); // full credit (fee on top)
        assert_eq!(quote.fee_model_version, FEE_MODEL_VERSION);
        assert_eq!(quote.params_epoch, 0);
    }

    /// Upgrade safety (fee-build lane §1.6): a GovernanceFeeParams persisted
    /// BEFORE the value-fee fields existed must still Candid-decode, with the
    /// new fields resolving to the current launch defaults. Modelled with a
    /// legacy struct holding exactly the pre-fee-build field set.
    #[test]
    fn legacy_params_decode_to_launch_defaults() {
        #[derive(CandidType)]
        struct GovernanceFeeParamsLegacy {
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
        }

        let legacy = GovernanceFeeParamsLegacy {
            protocol_shielding_fee_stsh: 0,
            protocol_unshielding_fee_stsh: 0,
            protocol_private_spend_fee_stsh: 0,
            minimum_withdrawal_gross: 0,
            minimum_recipient_amount: 0,
            minimum_private_credit: 0,
            fee_reference_price_stsh_per_icp_e8s: 0,
            fee_safety_margin_bps: 12_500,
            max_fee_change_bps_per_update: 1_000,
            fee_update_cooldown_ns: 24 * 60 * 60 * 1_000_000_000,
            operations_split_bps: 8_500,
            insurance_split_bps: 1_500,
            staking_rewards_split_bps: 0,
            staking_rewards_enabled: false,
            minimum_treasury_runway_months: 6,
            target_treasury_runway_months: 12,
        };

        let bytes = candid::encode_one(&legacy).expect("encode legacy");
        let decoded: GovernanceFeeParams = candid::decode_one(&bytes).expect("decode into new type");

        // The six new fields are absent on the wire → Candid None → resolvers
        // map them to the current launch defaults.
        assert_eq!(decoded.shield_fee_bps, None);
        assert_eq!(decoded.shield_fee_bps(), LAUNCH_SHIELD_FEE_BPS);
        assert_eq!(decoded.unshield_fee_bps(), LAUNCH_UNSHIELD_FEE_BPS);
        assert_eq!(decoded.shield_flat_minimum_fee_e8s(), LAUNCH_SHIELD_FLAT_MINIMUM_FEE_E8S);
        assert_eq!(decoded.unshield_flat_minimum_fee_e8s(), LAUNCH_UNSHIELD_FLAT_MINIMUM_FEE_E8S);
        assert_eq!(decoded.spend_fee_mode(), SpendFeeMode::FixedStsh);
        assert_eq!(decoded.fee_model_version(), FEE_MODEL_VERSION);
        assert_eq!(decoded.params_epoch(), 0);

        // And they equal what launch_defaults() resolves to.
        let launch = GovernanceFeeParams::launch_defaults();
        assert_eq!(decoded.shield_fee_bps(), launch.shield_fee_bps());
        assert_eq!(decoded.spend_fee_mode(), launch.spend_fee_mode());
    }
}
