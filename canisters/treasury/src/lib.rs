// =============================================================================
// STSH Treasury Canister
// Security classification: SUPPLY BOUNDARY — protocol revenue only.
//                          NEVER mix escrow user funds with treasury revenue.
// =============================================================================
//
// HARD RULE: The shielded pool escrow account is NOT a treasury account.
// Escrow funds belong to pool depositors. Treasury funds are protocol revenue.
// These must NEVER be mixed. This canister has zero access to escrow funds.
//
// Named subaccounts (all immutable assignments at init):
//   operations       — cycles, relayers, monitoring, grants
//   audit            — ring-fenced for audit payments only
//   insurance        — emergency reserve; higher withdrawal threshold
//   bug_bounty       — funded by treasury + protocol fees
//   staking_rewards  — fixed allocation for public staker rewards
//   liquidity        — market-making / DEX liquidity
//   community        — grants, ecosystem, wallet adoption
//
// Fee routing: the pool owns the split calculation (via GovernanceFeeParams).
// Treasury receives pre-split bucket amounts via receive_fee_split and only
// credits the named buckets — no bps math here.
// =============================================================================

// Rider 1 (CTO ruling, upgrade-persistence hardening Phase 2): production
// builds of this crate must contain no `unsafe`. `cfg_attr(not(test), ...)`
// keeps the guard off the test cfg only so a future test harness that needs
// `unsafe` is not blocked by it; every shipped Wasm is compiled without `test`
// and therefore under `forbid`. Treasury is unsafe-free today, so this is a
// no-op guard that turns a silent future regression into a build failure.
#![cfg_attr(not(test), forbid(unsafe_code))]

use candid::{CandidType, Nat, Principal};
use ic_cdk::api::{call::call, time};
use ic_cdk_macros::{init, post_upgrade, query, update};
use stsh_eager_cell::{PrincipalRefs, Scalars};
use ic_stable_structures::{
    cell::Cell,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    DefaultMemoryImpl, StableBTreeMap, Storable,
};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;

const MEM_SUBACCOUNTS:  MemoryId = MemoryId::new(0);
const MEM_PROPOSALS:    MemoryId = MemoryId::new(1);
const MEM_FEE_LOG:      MemoryId = MemoryId::new(2);
// ── RETIRED, FROZEN FOREVER ──────────────────────────────────────────────────
//
// MemoryId 3 held the pre-hardening `STABLE_STATE` checkpoint cell (Candid
// `TreasuryStableState`, written by `pre_upgrade`). Retired by
// upgrade-persistence hardening Phase 2 (2026-07-31) and NEVER recycled:
// `ic-stable-structures` would silently hand a new structure the decommissioned
// region's bytes, reinterpreting a dead checkpoint as live state of a different
// type — a durable corruption with no runtime error to catch. Registered as
// `retired` + frozen in docs/MEMORY_ID_REGISTRY.md; the gate lint enforces it.
//
// const MEM_STABLE_STATE: MemoryId = MemoryId::new(3);   // RETIRED — do not reuse

/// EAGER cell — token/pool/controller refs, GROUPED (set together in `init`).
const MEM_CANISTER_REFS: MemoryId = MemoryId::new(4);
/// EAGER cell — `next_proposal_id`. Separate from the fee-log index: the two
/// counters are mutated by DIFFERENT operations and `Cell::set` rewrites the
/// whole cell, so grouping them would drag each into the other's writes.
const MEM_NEXT_PROPOSAL_ID: MemoryId = MemoryId::new(5);
/// EAGER cell — `fee_log_index`.
const MEM_FEE_LOG_INDEX: MemoryId = MemoryId::new(6);

// ── L0 custody-vault allocation, landed by lane L3a (F-1) ────────────────────
// MemoryId 7: durable inflight-withdrawal reservation
// (CUSTODY_VAULT_INTERFACE_FREEZE_V6 §7). Allocated by L0 in the single
// campaign-wide MemoryId change so the registry lint and
// docs/MEMORY_ID_REGISTRY.md agree. Lane L3a lands the StableBTreeMap keyed by
// proposal_id (`{proposal_id, args_fingerprint, reserved_at_ns, status}`,
// inserted before the `icrc1_fee` await, never deletable) that replaces the
// heap-only INFLIGHT_PROPOSALS gate.
const MEM_INFLIGHT_WITHDRAWAL_RESERVATION: MemoryId = MemoryId::new(7);

// ── W2 2-6 (SSA-S1S4-001) ────────────────────────────────────────────────────
// MemoryId 8: per-bucket cumulative debit-shortfall accounting. A SEPARATE map
// from 0 (`SUBACCOUNTS`) deliberately: `SubaccountBalance` is returned by
// `get_subaccount_balances` and is the live balance record, while this is an
// append-only incident counter whose whole purpose is to survive independently
// of any balance mutation. Packet V1 §2(1)/(4), V2 §2(7).
const MEM_BUCKET_SHORTFALL: MemoryId = MemoryId::new(8);

/// Grouped canister-reference cell: token, pool, controller.
type CanisterRefsCell = PrincipalRefs<3>;
/// A single eager u64 counter, widened to the shared `Scalars` word.
type CounterCell = Scalars<1>;

type Mem = VirtualMemory<DefaultMemoryImpl>;

/// 7 days in nanoseconds — minimum timelock for treasury withdrawals
const WITHDRAWAL_TIMELOCK_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

/// DEF-068: insurance-subaccount withdrawals require a HIGHER timelock than
/// the standard WITHDRAWAL_TIMELOCK_NS. Named so the policy is auditable from
/// this constants block; value unchanged from the pre-DEF-068 inline literal
/// (14 days).
const INSURANCE_WITHDRAWAL_TIMELOCK_NS: u64 = 14 * 24 * 60 * 60 * 1_000_000_000;

/// Hard cap: total fee bps cannot exceed this value (10000 = 100%)
const MAX_FEE_BPS: u32 = 500; // 5% max total fee

// ── Pool treasury_disburse interface (mirror of shielded-pool, Lane A) ────────
//
// Local mirrors of the shielded-pool `treasury_disburse` Candid interface.
// Inter-canister calls are by method name + Candid encoding, so Lane B defines
// its own mirror types rather than depending on the pool crate — these MUST match
// canisters/shielded-pool/src/lib.rs as of Lane A v2 (commit 5e62f75). Lane B
// does not edit or link the pool crate.
//
// Under Option 2 the treasury no longer holds real STSH and no longer mirrors the
// ICRC-1 transfer interface — the pool performs the on-ledger transfer.

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum TreasuryReserveBucket {
    Operations,
    Insurance,
    StakingRewards,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TreasuryDisburseArgs {
    proposal_id:          u64,
    bucket:               TreasuryReserveBucket,
    recipient:            Principal,
    recipient_subaccount: Option<[u8; 32]>,
    amount:               u128,
    expected_ledger_fee:  u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum TreasuryDisburseResult {
    Executed        { block_index: Nat },
    AlreadyExecuted { block_index: Nat },
}

// Full mirror of the shielded-pool PoolError variant set so the `treasury_disburse`
// Candid reply always decodes, whatever error the pool returns.
//
// B4: this mirror is GUARDED by test_treasury_poolerror_mirror_is_pool_superset (below),
// which references the pool's authoritative `shielded_pool::PoolError` directly (rlib
// dev-dep) and FAILS on any missing/mismatched variant. Do NOT edit this enum by hand
// against a copied list — add whatever variant the conformance test names, with a
// byte-identical payload. Numeric record fields use u128/u32 to match the pool's Rust
// types; a field-type mismatch (e.g. u64 vs u128) also fails decode and the guard.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum PoolError {
    InvalidDenomination,
    InvalidProof,
    NullifierAlreadySpent,
    NullifierReserved,
    AnchorNotFound,
    EscrowUnderfunded { required: u128, available: u128 },
    InsufficientEscrowCoverage { requested: u128, available: u128 },
    CircuitVersionMismatch { expected: u32, got: u32 },
    VerifyingKeyMismatch,
    PoolVersionMismatch,
    ProofSystemMismatch,
    TransferFailed(String),
    AmountBelowLedgerFee { amount: u128, fee: u128 },
    BelowMinimumDeposit { public_amount: u128, minimum: u128 },
    InsufficientOperationsReserve { needed: u128, available: u128 },
    InvariantViolationDuplicateNullifier,
    Paused,
    // FU1-1 (lane A-5): mirrors shielded_pool PoolError. The pool is closed
    // because its post-upgrade recovery scan has not finished, NOT because an
    // operator paused it; the text carries the remaining-work count. A
    // treasury_disburse reply could not carry it today (the recovery gate is on
    // shield/spend/withdraw and their reconcilers, not disburse), but the mirror
    // must stay a superset of the pool's PoolError for Candid decode.
    RecoveryInProgress(String),
    SolvencyCheckFailed,
    DuplicateWithdrawalId,
    NotInitialised,
    CommitmentAppendFailed(String),
    DepositCommitmentPending,
    SumMismatch { inputs: u128, outputs: u128 },
    SumOverflow,
    MalformedSpendArgs,
    DuplicateOutputCommitment,
    InvalidOutputCommitment,
    DuplicateSpendId,
    // P-DOM (C-DOM-2): mirrors shielded_pool PoolError; a treasury_disburse reply
    // could not carry it (deployment-config gate is on shield/spend, not disburse),
    // but the mirror must stay a superset of the pool's PoolError for Candid decode.
    DeploymentConfigMismatch,
    SpendFeeNotSupported,
    VerifierUnavailable(String),
    ProofRejected(String),
    InvalidVerifierKeyHashLength { len: u64 },
    VerifierKeyHashMismatch,
    VerifierKeyHashChangedDuringAttestation,
    VerifierConfigInProgress,
    PrivateSpendFeeMismatch { expected: u128, got: u128 },
    InsufficientPrivateLiability { required: u128, available: u128 },
    WithdrawalBelowMinimum { withdraw_gross_amount: u128, minimum_withdrawal_gross: u128 },
    GrossAmountBelowFees { withdraw_gross_amount: u128, total_fee: u128 },
    RecipientBelowMinimum { recipient_net_amount: u128, minimum_recipient_amount: u128 },
    IdempotencyKeyConflict,
    EncryptedPayloadTooLarge { len: u64, max: u64 },
    EncryptedOutputTooLarge { index: u32, len: u64, max: u64 },
    InvalidProofLength { len: u64, expected: u64 },
    DepositTransferNotConfirmed,
    DepositAppendInProgress,
    DepositAppendUnknown,
    DepositAlreadyCompleted,
    PayoutNotPending,
    PayoutOutcomeUnknown,
    PayoutOutcomePrivate,
    PayoutExecutorBusy,
    PayoutMemoKeyNotReady,
    PayoutLegacyHold,
    PayoutStateInvalid,
    SpendNotFound,
    WrongSpendStatus,
    DisbursementNotFound,
    DisbursementNotReconcilable,
    /// RB-SWARM-A2: the pool refuses a proposal_id that carries a reconciliation
    /// tombstone. `execute_withdrawal` CAN receive this (a retry of a proposal
    /// whose ambiguous disbursement was reconciled), so the mirror must carry it
    /// or the reply fails Candid decode.
    DisbursementProposalIdRetired,
    PartialNullifierInsert { present: u32, absent: u32, total: u32 },
    OutputAppendUnknown,
    OutputAppendRejected(String),
    AmbiguousMerkleState,
    StagedOutputsMissing,
    InvalidCommitment,
    DepositNotFound,
    DepositNotReconcilable,
    AnonymousCaller,
    WithdrawalNotFound,
    WrongWithdrawalStatus,
    Unauthorized,
    WithdrawalPayoutObligation,
    // P-VK (POOL-04): mirrors shielded_pool PoolError; a treasury_disburse reply
    // could not carry it (the epoch gate is on private_spend, not disburse), but
    // the mirror must stay a superset of the pool's PoolError for Candid decode.
    SecurityEpochChanged,
}

// ── Fee source types ──────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum FeeSource {
    ShieldFee,
    PrivateTransferFee,
    UnshieldFee,
    DexRevenue,
}

// ── Subaccount balances ───────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SubaccountBalance {
    pub name: String,
    pub balance: u128,
}

impl Storable for SubaccountBalance {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

// ── Withdrawal proposals ──────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ProposalStatus { Pending, Executed, Rejected, Expired }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct WithdrawalProposal {
    pub id:              u64,
    pub proposer:        Principal,
    pub subaccount_name: String,
    pub recipient:       Principal,
    pub amount:          u128,
    pub description:     String,
    pub created_at_ns:   u64,
    pub execute_after_ns: u64,
    pub status:          ProposalStatus,
}

impl Storable for WithdrawalProposal {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

// ── Durable inflight-withdrawal reservation (F-1, custody-vault freeze §7) ───
//
// Lane L3a replaces the heap-only `INFLIGHT_PROPOSALS: HashSet<u64>` (cleared
// on upgrade — see MIGRATION LOG) with a StableBTreeMap over MemoryId 7. The
// record is inserted BEFORE the first `await` in `execute_withdrawal` (the
// `icrc1_fee` call), so the pre-await segment commits the reservation before
// any yield: a trap in a later continuation or an upgrade mid-execution leaves
// a durable witness instead of silently clearing the gate.
//
// Records are NEVER deleted — there is deliberately no removal API. A record
// is a permanent witness that an execution attempt reserved the proposal_id;
// only its `status` moves, and only forward:
//
//   Reserved        — a turn holds the reservation (pre-await segment committed)
//   Executed        — the pool confirmed disbursement; terminal
//   Failed          — a DEFINITE local/pool rejection (fee call result,
//                     overflow, insufficient balance, typed pool error);
//                     nothing disbursed, so a retry may re-reserve
//   OutcomeUnknown  — transport failure after the pool call, or a Reserved
//                     record swept by `post_upgrade` (its turn died with the
//                     upgrade); a retry re-reserves and the pool's
//                     fingerprint-bound idempotency returns the prior result
//
// `Reserved` is the exclusive gate: a second call for the same proposal_id
// while a record is Reserved is rejected ("already executing"), exactly as
// the heap gate behaved — but now the gate survives traps and upgrades.

//   RetryingUnknown    — W2 2-6 §2(9b): an UNKNOWN-RETRY is in flight (re-entry
//                        while the record was `OutcomeUnknown`). ACTIVE
//                        everywhere `Reserved` is, and swept exactly like
//                        `Reserved` by `post_upgrade`. It exists so the retry's
//                        error handling can be conservative (retain) without
//                        being conservative for fresh attempts too.
//   RetiredNotExecuted — W2 2-6 §2(9g): the pool has TERMINALLY decided
//                        non-execution for this proposal id (typed
//                        `DisbursementProposalIdRetired`). Terminal and
//                        INACTIVE everywhere: zero encumbrance, never legacy-
//                        active, never re-reservable, never swept, not counted
//                        toward the upgrade scan cap, does not block rejection.
//                        The proposal id is dead — paying the recipient needs a
//                        NEW proposal with a NEW id.

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationStatus {
    Reserved,
    Executed,
    Failed,
    OutcomeUnknown,
    RetryingUnknown,
    RetiredNotExecuted,
}

impl ReservationStatus {
    /// ACTIVE = the reservation may still be resolved by a further attempt, so
    /// it encumbers its bucket, blocks rejection, and counts as legacy-active
    /// when its encumbrance is unrecorded. This is the single definition every
    /// admission, rejection, and legacy-blocker decision reads — W2 2-6
    /// §2(2)/(5a)/(9b)/(9g)(ii).
    ///
    /// `RetiredNotExecuted` is deliberately NOT active: the pool has decided,
    /// there is nothing left to resolve, and treating it as active would
    /// encumber a bucket forever.
    fn is_active(self) -> bool {
        matches!(
            self,
            ReservationStatus::Reserved
                | ReservationStatus::OutcomeUnknown
                | ReservationStatus::RetryingUnknown
        )
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct InflightWithdrawalReservation {
    pub proposal_id:       u64,
    /// FNV-1a-64 over the candid encoding of the disbursement-relevant
    /// proposal fields. Detects same-id/different-args reuse; the pool's own
    /// fingerprint binding remains the authoritative idempotency check.
    pub args_fingerprint:  u64,
    pub reserved_at_ns:    u64,
    pub status:            ReservationStatus,
    /// W2 2-6 §2(2): the bucket this reservation encumbers. `None` on a
    /// pre-W2-2-6 record (#90 record-width widening: old bytes decode `None`).
    pub subaccount_name:        Option<String>,
    /// W2 2-6 §2(2): the `total_debit` this reservation encumbers, written in
    /// the SAME await-free segment that read the balance and made the
    /// admission decision, so the encumbrance is durable before the pool await.
    /// `None` on a pre-W2-2-6 record → a LEGACY ACTIVE record while its status
    /// is active, which fail-closed BLOCKS its bucket (§2(5a)) rather than
    /// being read as zero encumbrance.
    ///
    /// Release is by STATUS, not by clearing this field: every encumbrance sum
    /// is scoped to `status.is_active()`, so settling `Failed` /
    /// `RetiredNotExecuted` or claiming `Executed` releases it. The recorded
    /// amount is retained afterwards as a forensic witness of what was held.
    /// (Implementation reading of "released on Failed and at claim_execution";
    /// behaviourally identical, disclosed in the evidence packet.)
    pub encumbered_total_debit: Option<u128>,
}

/// W2 2-6 §2(1)/(7): per-bucket cumulative debit-shortfall accounting.
///
/// `shortfall_total` / `shortfall_events` SATURATE, and a saturating write sets
/// `shortfall_overflowed` durably. Documented contract: with the flag set the
/// value means "AT LEAST this much; the exact total is no longer
/// representable". Without the flag, values are exact. The never-under-report
/// property is carried by value-plus-flag, not by the value alone.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BucketShortfall {
    pub shortfall_total:      u128,
    pub shortfall_events:     u64,
    pub shortfall_overflowed: bool,
}

impl Storable for BucketShortfall {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

/// W2 2-6 §2(4): one row of the ungated integrity query.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BucketIntegrity {
    pub subaccount_name:      String,
    pub shortfall_total:      u128,
    pub shortfall_events:     u64,
    pub shortfall_overflowed: bool,
    /// Sum of `encumbered_total_debit` over ACTIVE reservations on this bucket.
    pub encumbered_total:     u128,
    /// Active reservations on this bucket with NO recorded encumbrance — each
    /// one fail-closed blocks the bucket (§2(5a)).
    pub legacy_active_count:  u64,
    /// Terminal `RetiredNotExecuted` reservations on this bucket — dead
    /// reservations awaiting operator rejection of their proposal (§2(9g)(ii)).
    pub retired_count:        u64,
}

// ── W2 2-6: stable operator-facing refusal codes ─────────────────────────────
//
// CTO ruling (2026-08-16, relayed): `execute_withdrawal` keeps its
// `Result<(), String>` surface — the packet's "typed" constraint is load-bearing
// on the INBOUND side (pool errors are matched as Candid VARIANTS, never as
// text; see the `treasury_disburse` match arms) and that is unchanged. Outbound
// refusals carry a stable machine-checkable code prefix instead, so a DID break
// and a rewrite of passing tests' error assertions buy no safety.
//
// The codes are the contract. They are distinct, stable, and asserted on by the
// W2 2-6 suites. Never reuse or re-word a code without a superseding ruling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefusalCode {
    /// §2(5a): an active reservation with unrecorded encumbrance blocks the
    /// bucket (or, if its bucket is underivable, blocks globally).
    LegacyBlocked,
    /// §2(7): a checked admission sum overflowed. Fail closed; never wrap.
    AdmissionOverflow,
    /// §2(2): `balance < total_debit + E[b]`.
    BucketEncumbered,
    /// §2(9g): the pool terminally retired this proposal id.
    Retired,
    /// §2(9g)(ii): `reserve_withdrawal` refuses to re-reserve a retired record.
    RetiredNotReReservable,
}

impl RefusalCode {
    fn as_str(self) -> &'static str {
        match self {
            RefusalCode::LegacyBlocked          => "W226-LEGACY-BLOCKED",
            RefusalCode::AdmissionOverflow      => "W226-ADMISSION-OVERFLOW",
            RefusalCode::BucketEncumbered       => "W226-BUCKET-ENCUMBERED",
            RefusalCode::Retired                => "W226-RETIRED",
            RefusalCode::RetiredNotReReservable => "W226-RETIRED-NO-RERESERVE",
        }
    }

    fn msg(self, detail: impl AsRef<str>) -> String {
        format!("{}: {}", self.as_str(), detail.as_ref())
    }
}

impl Storable for InflightWithdrawalReservation {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

// ── Fee routing log entry ─────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct FeeLogEntry {
    pub timestamp_ns:  u64,
    pub source:        FeeSource,
    pub total_amount:  u128,
    pub operations:    u128,
    pub insurance:     u128,
    pub audit:         u128,
    pub staking:       u128,
}

impl Storable for FeeLogEntry {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

// ── State ─────────────────────────────────────────────────────────────────────

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// subaccount_name → SubaccountBalance
    static SUBACCOUNTS: RefCell<StableBTreeMap<String, SubaccountBalance, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_SUBACCOUNTS)))
    );

    static PROPOSALS: RefCell<StableBTreeMap<u64, WithdrawalProposal, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_PROPOSALS)))
    );

    static FEE_LOG: RefCell<StableBTreeMap<u64, FeeLogEntry, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_FEE_LOG)))
    );

    /// EAGER durable source of truth for TOKEN_CANISTER + POOL_CANISTER +
    /// CONTROLLER. Sentinel default on a fresh region so an absent cell fails
    /// closed in `post_upgrade`.
    static CANISTER_REFS: RefCell<Cell<CanisterRefsCell, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_CANISTER_REFS)),
            CanisterRefsCell::sentinel(),
        ).expect("CANISTER_REFS: Cell::init failed — stable memory corrupt")
    );

    /// EAGER durable source of truth for NEXT_PROPOSAL_ID.
    static NEXT_PROPOSAL_ID_CELL: RefCell<Cell<CounterCell, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_NEXT_PROPOSAL_ID)),
            CounterCell::sentinel(),
        ).expect("NEXT_PROPOSAL_ID_CELL: Cell::init failed — stable memory corrupt")
    );

    /// EAGER durable source of truth for FEE_LOG_INDEX.
    static FEE_LOG_INDEX_CELL: RefCell<Cell<CounterCell, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_FEE_LOG_INDEX)),
            CounterCell::sentinel(),
        ).expect("FEE_LOG_INDEX_CELL: Cell::init failed — stable memory corrupt")
    );

    static TOKEN_CANISTER:   RefCell<Option<Principal>> = RefCell::new(None);
    static POOL_CANISTER:    RefCell<Option<Principal>> = RefCell::new(None);
    static CONTROLLER:       RefCell<Option<Principal>> = RefCell::new(None);
    static NEXT_PROPOSAL_ID: RefCell<u64> = RefCell::new(1);
    static FEE_LOG_INDEX:    RefCell<u64> = RefCell::new(0);

    /// proposal_id → durable inflight-withdrawal reservation (F-1). Stable, so
    /// the reservation survives upgrades; insert-once semantics — records are
    /// never removed, only their `status` moves forward (see the type block).
    static INFLIGHT_RESERVATIONS: RefCell<StableBTreeMap<u64, InflightWithdrawalReservation, Mem>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_INFLIGHT_WITHDRAWAL_RESERVATION))
        ));

    /// W2 2-6 §2(1): subaccount_name → cumulative debit-shortfall record.
    /// Rows are created lazily on the first shortfall; an absent row means
    /// "no shortfall has ever been recorded for this bucket".
    static BUCKET_SHORTFALLS: RefCell<StableBTreeMap<String, BucketShortfall, Mem>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_BUCKET_SHORTFALL))
        ));
}

// ── Counter narrowing — FAIL CLOSED (SSA P1, 2026-07-31) ────────────────────
//
// `Scalars` stores u128 words; every counter here is a u64. A bare `as u64`
// narrowing is FAIL-OPEN: a structurally valid cell holding a word above
// `u64::MAX` would silently truncate to a plausible-looking value, and the
// canister would resume issuing proposal ids that collide with stored records,
// or fee-log indices that overwrite existing entries. Truncation is exactly the
// class of silent, durable corruption the sentinel exists to prevent, so the
// narrowing must trap instead.
//
// Kept as PURE functions returning `Option` so the rejection rule is unit-
// testable natively: neither case is reachable through the public interface
// (one needs a corrupted region, the other 2^64 operations), so a native test
// is the only place the rule can actually be exercised.

/// An id counter: must narrow to u64 AND be non-zero. Zero is not a legal
/// value for `next_proposal_id` — it is seeded at 1 and only ever increments,
/// so a durable zero means a wrapped or corrupt region, and resuming on it
/// would re-issue id 1 over a stored proposal.
fn decode_id_counter(word: u128) -> Option<u64> {
    match u64::try_from(word) {
        Ok(0) => None,
        Ok(v) => Some(v),
        Err(_) => None,
    }
}

/// An index counter: must narrow to u64. Zero IS legal here — `fee_log_index`
/// is seeded at 0 and a canister that has never received a fee split sits there
/// legitimately.
fn decode_index_counter(word: u128) -> Option<u64> {
    u64::try_from(word).ok()
}

/// One step of a monotonic counter. `checked_add` because wrapping at
/// exhaustion would restart the sequence at zero and enable id/index REUSE —
/// the same failure mode as recycling a MemoryId, and just as silent.
fn bump_counter(cur: u64) -> Option<u64> {
    cur.checked_add(1)
}

// ── Eager write-through helpers ───────────────────────────────────────────────
//
// Every former-checkpoint field is written through one of these, and NOTHING
// else writes the heap mirrors outside `post_upgrade`. That is what replaces
// `pre_upgrade`: the durable value is always current, so there is no window in
// which an upgrade (or a trap) can lose a mutation that the caller already
// observed.
//
// ORDER, everywhere below: stable write FIRST, heap mirror only on success. A
// failed stable write traps with the heap untouched, so heap and stable state
// can never disagree. None of these helpers `await` — each is a single atomic
// message segment, so a rejected operation rolls the whole segment back and no
// partial scalar can be persisted.

/// GROUPED, per the eager-cell grouping rule: all three refs are set together
/// (only in `init`) and are meaningless individually, so ONE `Cell::set` makes
/// a half-applied authority record unrepresentable. Phase 0 measured a grouped
/// two-field raw write at 2 370 instructions against 4 119 for separate cells —
/// grouping co-mutated fields is cheaper as well as atomic.
fn set_canister_refs(token_canister: Principal, pool_canister: Principal, controller: Principal) {
    CANISTER_REFS.with(|c| {
        c.borrow_mut()
            .set(CanisterRefsCell::new([token_canister, pool_canister, controller]))
            .expect("set_canister_refs: stable cell write failed");
    });
    TOKEN_CANISTER.with(|t| *t.borrow_mut() = Some(token_canister));
    POOL_CANISTER.with(|p| *p.borrow_mut() = Some(pool_canister));
    CONTROLLER.with(|c| *c.borrow_mut() = Some(controller));
}

/// Allocate the next proposal id and persist the incremented counter.
///
/// SEMANTIC ORDERING: this is the exact point the protocol already allocated
/// the id — `propose_withdrawal` validates the subaccount and the balance
/// BEFORE calling here, and there is no `await` between here and the
/// `PROPOSALS.insert`. Nothing is moved ahead of an external-success await.
fn alloc_proposal_id() -> u64 {
    let id = NEXT_PROPOSAL_ID.with(|n| *n.borrow());
    let next = bump_counter(id)
        .unwrap_or_else(|| ic_cdk::trap("alloc_proposal_id: proposal id space exhausted"));
    NEXT_PROPOSAL_ID_CELL.with(|c| {
        c.borrow_mut()
            .set(CounterCell::new([next as u128]))
            .expect("alloc_proposal_id: stable cell write failed");
    });
    NEXT_PROPOSAL_ID.with(|n| *n.borrow_mut() = next);
    id
}

/// Allocate the next fee-log index and persist the incremented counter.
/// Same no-`await` segment as the `FEE_LOG` insert that consumes it, so the
/// index and its entry are durable together or not at all.
fn alloc_fee_log_index() -> u64 {
    let idx = FEE_LOG_INDEX.with(|i| *i.borrow());
    let next = bump_counter(idx)
        .unwrap_or_else(|| ic_cdk::trap("alloc_fee_log_index: fee log index space exhausted"));
    FEE_LOG_INDEX_CELL.with(|c| {
        c.borrow_mut()
            .set(CounterCell::new([next as u128]))
            .expect("alloc_fee_log_index: stable cell write failed");
    });
    FEE_LOG_INDEX.with(|i| *i.borrow_mut() = next);
    idx
}

/// Seed both counter cells at their initial values. Called ONLY from `init`:
/// the sentinel must be replaced with real state at install time, or the very
/// first upgrade of a never-mutated canister would trap on a surviving
/// sentinel even though the install was perfectly legitimate.
fn seed_counters() {
    NEXT_PROPOSAL_ID_CELL.with(|c| {
        c.borrow_mut()
            .set(CounterCell::new([1]))
            .expect("seed_counters: NEXT_PROPOSAL_ID_CELL write failed");
    });
    FEE_LOG_INDEX_CELL.with(|c| {
        c.borrow_mut()
            .set(CounterCell::new([0]))
            .expect("seed_counters: FEE_LOG_INDEX_CELL write failed");
    });
}

// ── Init ──────────────────────────────────────────────────────────────────────

#[init]
fn init(token_canister: Principal, pool_canister: Principal, controller: Principal) {
    set_canister_refs(token_canister, pool_canister, controller);
    seed_counters();

    // Initialise named subaccounts with zero balances
    let names = ["operations", "audit", "insurance", "bug_bounty",
                 "staking_rewards", "liquidity", "community"];
    SUBACCOUNTS.with(|s| {
        let mut map = s.borrow_mut();
        for name in names {
            map.insert(name.to_string(), SubaccountBalance {
                name: name.to_string(),
                balance: 0,
            });
        }
    });
}

// ── Fee receipt (called by shielded pool) ─────────────────────────────────────

/// Receive pre-split protocol fee revenue from the pool.
/// The pool owns the split calculation (GovernanceFeeParams); this function
/// only credits the named buckets. Only callable by the shielded pool canister.
///
/// HARD RULE: This canister never has access to pool escrow funds.
/// Pool escrow is held in the token canister under the pool's account.
/// This function receives ONLY protocol fee revenue.
#[update]
fn receive_fee_split(
    source:                 FeeSource,
    operations_amount:      u128,
    insurance_amount:       u128,
    staking_rewards_amount: u128,
    timestamp_ns:           u64,
) -> Result<(), String> {
    let pool = POOL_CANISTER.with(|p| p.borrow().ok_or("Pool canister not set".to_string()))?;
    if ic_cdk::caller() != pool {
        return Err("Only shielded pool canister may call receive_fee_split".to_string());
    }

    // Atomic, overflow-checked credit (Task 4 integrity). Pre-validates all three
    // buckets so a (theoretical) overflow on one leaves every bucket unchanged and
    // the pool sees an error — preventing partial credit + double-credit on retry.
    // Amounts are bounded by protocol fee revenue, so overflow is unreachable.
    credit_many(&[
        ("operations", operations_amount),
        ("insurance", insurance_amount),
        ("staking_rewards", staking_rewards_amount),
    ])?;

    let total_amount = operations_amount
        .saturating_add(insurance_amount)
        .saturating_add(staking_rewards_amount);

    // R-2 (C-30): the timestamp is SUPPLIED BY THE POOL, not read here.
    //
    // For the immediate sources (ShieldFee, UnshieldFee) the pool passes `time()`
    // at the call, which is the previous behaviour exactly. For the batched
    // PrivateTransferFee it passes the WINDOW BOUNDARY the flush timer was armed
    // for. Reading `time()` here instead would stamp the row with the moment the
    // inter-canister call happened to land, and that scheduler lateness carries
    // sub-window information about the flush — which is the signal the batching
    // exists to remove. The caller check above is what makes a caller-supplied
    // timestamp safe: only the pool can reach this function.
    //
    // An all-zero batched call is ACCEPTED and writes its row (crediting
    // nothing): an empty window must publish, or the SILENCE becomes the signal.
    let entry = FeeLogEntry {
        timestamp_ns,
        source,
        total_amount,
        operations: operations_amount,
        insurance:  insurance_amount,
        audit:      0,
        staking:    staking_rewards_amount,
    };
    let idx = alloc_fee_log_index();
    FEE_LOG.with(|log| log.borrow_mut().insert(idx, entry));

    Ok(())
}

// ── Queries ───────────────────────────────────────────────────────────────────

/// Returns all named subaccount balances. Publicly readable.
/// Watcher calls this to verify treasury accounting.
#[query]
fn get_subaccount_balances() -> Vec<SubaccountBalance> {
    SUBACCOUNTS.with(|s| s.borrow().iter().map(|(_, v)| v).collect())
}

#[query]
fn get_subaccount_balance(name: String) -> Option<u128> {
    SUBACCOUNTS.with(|s| s.borrow().get(&name).map(|v| v.balance))
}

#[query]
fn get_fee_log(from_index: u64, limit: u64) -> Vec<FeeLogEntry> {
    let limit = limit.min(200);
    FEE_LOG.with(|log| {
        let map = log.borrow();
        (from_index..from_index + limit)
            .filter_map(|i| map.get(&i))
            .collect()
    })
}

// ── Withdrawal proposals ──────────────────────────────────────────────────────

#[update]
fn propose_withdrawal(subaccount_name: String, recipient: Principal, amount: u128, description: String) -> u64 {
    let controller = CONTROLLER.with(|c| c.borrow().unwrap());
    assert_eq!(ic_cdk::caller(), controller, "Only controller may propose withdrawals");

    // Verify subaccount exists and has sufficient balance
    let balance = SUBACCOUNTS.with(|s| s.borrow().get(&subaccount_name).map(|v| v.balance).unwrap_or(0));
    assert!(balance >= amount, "Insufficient balance in subaccount '{}'", subaccount_name);

    // Insurance subaccount requires the higher DEF-068 policy timelock
    let timelock = if subaccount_name == "insurance" {
        INSURANCE_WITHDRAWAL_TIMELOCK_NS
    } else {
        WITHDRAWAL_TIMELOCK_NS
    };

    let id = alloc_proposal_id();
    let now = time();
    let proposal = WithdrawalProposal {
        id, proposer: ic_cdk::caller(),
        subaccount_name, recipient, amount, description,
        created_at_ns: now,
        execute_after_ns: now + timelock,
        status: ProposalStatus::Pending,
    };
    PROPOSALS.with(|p| p.borrow_mut().insert(id, proposal));
    id
}

#[update]
async fn execute_withdrawal(proposal_id: u64) -> Result<(), String> {
    let controller = CONTROLLER.with(|c| c.borrow().unwrap());
    assert_eq!(ic_cdk::caller(), controller, "Only controller may execute withdrawals");

    // ── W2 2-6 §2(9g)(ii): the TERMINAL-RETIRED gate, checked FIRST ──────────
    //
    // Before reservation work, the fee query, admission, encumbrance, or ANY
    // pool call — and with NO state mutation whatsoever. A retired proposal id
    // is dead at the pool: it is not re-executable, and every replay
    // (sequential or concurrent-later) must get the SAME typed error
    // deterministically rather than re-walking a path that could churn state.
    // Paying the intended recipient requires a NEW proposal with a NEW id; the
    // proposal here is still `Pending` and is rejectable, which is the expected
    // operator action.
    if reservation_is_retired(proposal_id) {
        return Err(RefusalCode::Retired.msg(format!(
            "proposal {} id retired at the pool; not re-executable; reject and re-propose \
             with a new id",
            proposal_id
        )));
    }

    let proposal = PROPOSALS.with(|p| p.borrow().get(&proposal_id))
        .ok_or("Proposal not found")?;

    if proposal.status != ProposalStatus::Pending {
        return Err(format!("Proposal is {:?}, not Pending", proposal.status));
    }
    if time() < proposal.execute_after_ns {
        let remaining = (proposal.execute_after_ns - time()) / 1_000_000_000;
        return Err(format!("Timelock active — {} seconds remaining", remaining));
    }

    // ── Option 2 custody: disburse via the pool ───────────────────────────────
    //
    // Treasury holds NO real STSH (invariant: icrc1_balance_of(treasury) == 0).
    // The pool custodies the reserves and performs the actual icrc1_transfer; the
    // treasury bucket is an accounting view that we debit only AFTER the pool
    // confirms the disbursement (post-success-debit). Treasury never calls
    // icrc1_transfer from its own account, and there is no icrc2 allowance path.
    let pool = POOL_CANISTER.with(|c| c.borrow().ok_or("Pool canister not set".to_string()))?;
    let token = TOKEN_CANISTER.with(|t| t.borrow().ok_or("Token canister not set".to_string()))?;

    // Only the three reserve buckets the pool tracks are disbursable under Option 2.
    let bucket = reserve_bucket_for(&proposal.subaccount_name).ok_or_else(|| format!(
        "subaccount '{}' has no pool reserve under Option 2 — only operations, \
         insurance, and staking_rewards are disbursable via the pool",
        proposal.subaccount_name
    ))?;

    // ── Durable INFLIGHT reservation (F-1) — one in-flight execution per
    //    proposal_id, durable across traps and upgrades ───────────────────────
    //
    // Essential for no-double-debit under concurrency: without it, two concurrent
    // execute_withdrawal calls for the same Pending proposal would both reach the
    // pool, get Executed + AlreadyExecuted (both "success"), and both debit the
    // treasury bucket. The reservation admits exactly one turn; a second call on
    // a Reserved record returns "already executing".
    //
    // Unlike the retired heap gate, the record is inserted into STABLE memory
    // HERE — before the icrc1_fee await below — so the reservation commits with
    // this pre-await segment. A trap in a later continuation (or an upgrade
    // mid-execution) leaves the durable record behind instead of silently
    // clearing the gate; post_upgrade sweeps such orphans to OutcomeUnknown so
    // a retry re-reserves and the pool's idempotency returns the prior result.
    // Records are never deleted; failure paths settle the status forward.
    let fingerprint = args_fingerprint(&proposal);
    // W2 2-6 §2(9a)/(9b): the attempt class is decided and DURABLY recorded
    // here — an unknown-retry moves the record to `RetryingUnknown`, never back
    // to `Reserved` — so the response handler below can classify without
    // guessing, even after a trap or an upgrade.
    let attempt = reserve_withdrawal(proposal_id, fingerprint, time())?;

    // ── Determine the ledger fee the pool will charge ─────────────────────────
    // The pool re-validates expected_ledger_fee against its own icrc1_fee query and
    // rejects on mismatch. NOTE: expected_ledger_fee is part of the pool's
    // idempotency fingerprint, so if the ledger fee changes between a first attempt
    // that reached the pool and a later retry, the retry's fingerprint won't match
    // and the pool returns IdempotencyKeyConflict (handled below as a failure, no
    // debit). ICRC fees are network-wide / slow-changing, so this fails closed and
    // is rare; flagged for Lane A coordination.
    let fee_result: Result<(Nat,), _> = call(token, "icrc1_fee", ()).await;
    let ledger_fee: u128 = match fee_result {
        Ok((f,)) => match f.0.to_u128() {
            Some(v) => v,
            None => { settle_local_refusal(proposal_id, attempt); return Err("icrc1_fee: returned value exceeds u128".to_string()); }
        },
        Err((_, e)) => { settle_local_refusal(proposal_id, attempt); return Err(format!("icrc1_fee call failed: {}", e)); }
    };

    // ── W2 2-6 §2(9c): FROZEN ARGUMENTS on a non-legacy unknown-retry ────────
    //
    // A retry REUSES the `total_debit` the original attempt encumbered — the
    // original ledger fee is `encumbered_total_debit − proposal.amount` — and
    // does NOT let a live re-derived fee into the pool arguments. Without this,
    // a fee change between the original attempt and the retry produces a
    // different fingerprint and the pool answers `IdempotencyKeyConflict` — a
    // MANUFACTURED conflict on a proposal that may well have executed. The live
    // `icrc1_fee` above is still queried, and is still used for diagnostics and
    // for legacy retries that have no frozen total; it just cannot enter the
    // args here.
    //
    // A LEGACY unknown-retry (no frozen total) re-derives as before (§2(9f));
    // its classification below is unchanged, and its legacy blocker persists.
    let frozen = match attempt {
        AttemptClass::UnknownRetry { frozen_total_debit } => frozen_total_debit,
        AttemptClass::Fresh => None,
    };

    let (total_debit, ledger_fee) = match frozen {
        Some(frozen_total) => {
            let frozen_fee = match frozen_total.checked_sub(proposal.amount) {
                Some(f) => f,
                None => {
                    // The encumbered total is below the proposal amount — the
                    // record disagrees with the proposal. Fail closed WITHOUT
                    // releasing: this is an unknown-retry, so the prior attempt
                    // may have executed.
                    settle_reservation(proposal_id, ReservationStatus::OutcomeUnknown);
                    return Err(format!(
                        "Proposal {} frozen encumbrance {} is below the proposal amount {}; \
                         refusing to reconstruct the original ledger fee. Reservation left \
                         OutcomeUnknown (the prior attempt may have executed).",
                        proposal_id, frozen_total, proposal.amount,
                    ));
                }
            };
            (frozen_total, frozen_fee)
        }
        None => {
            let total = match proposal.amount.checked_add(ledger_fee) {
                Some(v) => v,
                None => {
                    settle_local_refusal(proposal_id, attempt);
                    return Err("total_debit overflow: amount + ledger_fee exceeds u128".to_string());
                }
            };
            (total, ledger_fee)
        }
    };

    // ── Local accounting precheck (fast-fail; the pool enforces its own reserve)
    // Failure leaves the proposal Pending (top up + retry, or reject_proposal()).
    let balance = SUBACCOUNTS.with(|s| s.borrow().get(&proposal.subaccount_name).map(|v| v.balance).unwrap_or(0));
    if balance < total_debit {
        settle_local_refusal(proposal_id, attempt);
        return Err(format!(
            "Insufficient balance: subaccount '{}' has {} but total_debit is {} (amount {} + ledger_fee {})",
            proposal.subaccount_name, balance, total_debit, proposal.amount, ledger_fee,
        ));
    }

    // ── W2 2-6 §2(2): BUCKET-LEVEL ADMISSION + durable encumbrance commit ────
    //
    // THIS is the SSA-S1S4-001 fix. The precheck above compares against the
    // then-current balance only, so two proposals on the same bucket could each
    // pass it against the SAME funds and both reach the pool — the pool debits
    // each `total_debit` exactly and checked, so the over-admission settles as a
    // treasury under-debit and S1−S4 diverges.
    //
    // Admission is `balance ≥ total_debit + E[b]`, where `E[b]` sums every OTHER
    // active reservation's recorded encumbrance on this bucket, evaluated and
    // COMMITTED in this same await-free segment — the one that read `balance`,
    // and before the pool await below. Fail-closed: over-refusing is acceptable,
    // over-admitting is the defect.
    if let Err(refusal) = admit_and_encumber(
        proposal_id, &proposal.subaccount_name, total_debit, balance,
    ) {
        settle_local_refusal(proposal_id, attempt);
        return Err(refusal);
    }

    // ── Disburse via the pool (proposal_id = fingerprint-bound idempotency key) ─
    let disburse_args = TreasuryDisburseArgs {
        proposal_id,
        bucket,
        recipient: proposal.recipient,
        recipient_subaccount: None,
        amount: proposal.amount,
        expected_ledger_fee: ledger_fee,
    };
    let call_result: Result<(Result<TreasuryDisburseResult, PoolError>,), _> =
        call(pool, "treasury_disburse", (disburse_args,)).await;

    match call_result {
        // Executed and AlreadyExecuted are BOTH successful disbursement outcomes.
        // Post-success-debit: the treasury bucket is debited here, atomically with
        // the status flip, exactly once. claim_execution is the exactly-once
        // witness: only the first turn to move the durable record to Executed
        // performs the debit; a replay (or a concurrent twin that reached the
        // pool's AlreadyExecuted) observes the prior result and does not debit.
        Ok((Ok(TreasuryDisburseResult::Executed { .. }),))
        | Ok((Ok(TreasuryDisburseResult::AlreadyExecuted { .. }),)) => {
            if claim_execution(proposal_id) {
                debit_subaccount(&proposal.subaccount_name, total_debit);
                update_proposal_status(proposal_id, ProposalStatus::Executed);
            }
            Ok(())
        }
        // ── W2 2-6 §2(9e′)/(9g): the ONE narrow terminal-release exception ───
        //
        // Matched as a VARIANT, never as text. `DisbursementProposalIdRetired`
        // is the pool's TERMINAL non-execution decision: the tombstone gate
        // returns `AlreadyExecuted` for (Executed, Some(block_index)) and this
        // variant for everything else, and at the build pin the only tombstone
        // writers are the Executed-reconcile path (which always records a block
        // index) and the ambiguous NotExecuted-reconcile path. So `Retired` ⇒
        // the pool terminally decided NON-execution (reserve re-credited or
        // never debited), and the treasury-side release is symmetric.
        //
        // ONE atomic settlement: release the encumbrance (and the legacy
        // blocker, if legacy) by writing the TERMINAL `RetiredNotExecuted`
        // status. Not `Failed` — `Failed` is re-reservable, and a re-reservation
        // of a retired id would walk the whole path again to earn the same
        // error while churning state. The proposal stays `Pending` and is now
        // rejectable, which is the expected operator action.
        Ok((Err(PoolError::DisbursementProposalIdRetired),)) => {
            settle_reservation(proposal_id, ReservationStatus::RetiredNotExecuted);
            Err(RefusalCode::Retired.msg(format!(
                "proposal {} id retired at the pool; not re-executable; reject and \
                 re-propose with a new id",
                proposal_id
            )))
        }
        // ── W2 2-6 §2(9d): every OTHER pool error, on an UNKNOWN-RETRY ───────
        //
        // RETAIN. At the build pin the pool reports in-progress
        // (`PendingValidation` / `PendingTransfer`), stuck legacy `Pending`, and
        // `TransportUnknown` states as generic `TransferFailed` TEXT, and a
        // fingerprint mismatch as `IdempotencyKeyConflict`. None of those prove
        // non-execution, and string-matching them is forbidden — so no pool
        // error releases an unknown-retry. There is deliberately NO "definite
        // non-execution" error class on this path in this lane, and the legacy
        // blocker of a legacy record therefore also persists (§2(9f)).
        Ok((Err(e),)) if matches!(attempt, AttemptClass::UnknownRetry { .. }) => {
            settle_reservation(proposal_id, ReservationStatus::OutcomeUnknown);
            Err(format!(
                "treasury_disburse failed on an unknown-retry for proposal {} ({:?}); the \
                 original attempt's outcome is still unknown, so the reservation is \
                 retained as OutcomeUnknown and nothing is released. Resolve at the pool \
                 with reconcile_treasury_disburse, then retry.",
                proposal_id, e
            ))
        }
        // Same proposal_id, different parameters — conflict, NOT success. No debit.
        // FRESH attempts only: a pool `Err` before any record existed is
        // non-execution by construction (§2(9d) last bullet).
        Ok((Err(PoolError::IdempotencyKeyConflict),)) => {
            settle_reservation(proposal_id, ReservationStatus::Failed);
            Err(format!(
                "Pool reported IdempotencyKeyConflict for proposal {} (same id, different \
                 parameters). No debit; reconcile before retrying.",
                proposal_id
            ))
        }
        // Any other pool error on a FRESH attempt: disbursement did not happen.
        // No debit; stay Pending.
        Ok((Err(e),)) => {
            settle_reservation(proposal_id, ReservationStatus::Failed);
            Err(format!("treasury_disburse failed: {:?}", e))
        }
        // Transport failure: outcome unknown. No debit; stay Pending. A retry is
        // safe — the pool's idempotency returns AlreadyExecuted if it did disburse.
        Err((_, e)) => {
            settle_reservation(proposal_id, ReservationStatus::OutcomeUnknown);
            Err(format!(
                "treasury_disburse call failed (proposal {} left Pending for retry): {}",
                proposal_id, e
            ))
        }
    }
}

/// RB-SWARM-A2 (L3-2): typed failure modes for `reject_proposal`.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RejectProposalError {
    /// No proposal exists with this id. Previously this was a SILENT no-op:
    /// `update_proposal_status` matched nothing and returned unit, so the caller
    /// could not distinguish "rejected" from "never existed".
    NotFound,
    /// The proposal is not `Pending`. Rejection is a Pending-only transition —
    /// notably `Executed → Rejected` must never happen: an executed proposal is
    /// the surviving record that real funds moved, and overwriting it destroys
    /// that evidence.
    NotPending { current: ProposalStatus },
    /// An `execute_withdrawal` turn holds the INFLIGHT reservation for this
    /// proposal. Its outcome is not yet known, so its status is not yet settled;
    /// rejecting now could overwrite a status the in-flight turn is about to
    /// write (or mark as rejected a proposal that in fact disbursed).
    InFlight,
}

/// RB-SWARM-A2 (L3-2): reject a proposal — guarded, and typed.
///
/// Previously this called `update_proposal_status(id, Rejected)` unconditionally:
/// any proposal in any status, including `Executed`, could be overwritten to
/// `Rejected`, and the call returned unit so nothing was reportable. This is the
/// STANDALONE L3-2 fix. It does NOT on its own close the compound L7-C2/L8-F2 —
/// in the corrected failure sequence the treasury proposal is `Pending`
/// throughout, so there is no `Executed` witness here for this guard to protect.
/// The compound is closed by the shielded-pool reconciliation tombstone.
#[update]
fn reject_proposal(proposal_id: u64) -> Result<(), RejectProposalError> {
    let controller = CONTROLLER.with(|c| c.borrow().unwrap());
    assert_eq!(ic_cdk::caller(), controller, "Only controller may reject");

    // INFLIGHT check first: an in-flight proposal's status is unsettled, so
    // reading its (still `Pending`) status and acting on it would be a race.
    if reservation_is_inflight(proposal_id) {
        return Err(RejectProposalError::InFlight);
    }

    let status = PROPOSALS
        .with(|p| p.borrow().get(&proposal_id).map(|v| v.status))
        .ok_or(RejectProposalError::NotFound)?;
    if status != ProposalStatus::Pending {
        return Err(RejectProposalError::NotPending { current: status });
    }

    update_proposal_status(proposal_id, ProposalStatus::Rejected);
    Ok(())
}

#[query]
fn list_proposals() -> Vec<WithdrawalProposal> {
    PROPOSALS.with(|p| p.borrow().iter().map(|(_, v)| v).collect())
}

/// W2 2-6 §2(4): per-bucket debit-exactness and admission integrity.
///
/// A plain ungated `#[query]`, consistent with the `get_subaccount_balances` /
/// `get_treasury_notification_stats` precedent — everything here is already
/// derivable from public balances and proposals.
///
/// Rows are UNION-scoped: every subaccount, plus any bucket that carries a
/// shortfall record or an active/retired reservation, so a bucket can never
/// hide by having no balance row. Encumbrance and counts are computed from the
/// reservation records themselves — the truth source — not from a cache.
#[query]
fn get_treasury_admission_integrity() -> Vec<BucketIntegrity> {
    use std::collections::BTreeMap;

    // (encumbered_total, legacy_active_count, retired_count) per bucket.
    let mut agg: BTreeMap<String, (u128, u64, u64)> = BTreeMap::new();
    // Fail-closed reporting mate of the admission scan: an ACTIVE legacy record
    // whose bucket is underivable blocks GLOBALLY, so it is counted against
    // EVERY reported bucket rather than being silently dropped from the view.
    let mut global_legacy: u64 = 0;

    INFLIGHT_RESERVATIONS.with(|m| {
        for (_, r) in m.borrow().iter() {
            match (r.status, r.encumbered_total_debit) {
                (ReservationStatus::RetiredNotExecuted, _) => {
                    if let Some(b) = reservation_bucket(&r) {
                        agg.entry(b).or_default().2 += 1;
                    }
                }
                (s, Some(amount)) if s.is_active() => {
                    if let Some(b) = reservation_bucket(&r) {
                        let e = agg.entry(b).or_default();
                        // Saturating in the OBSERVATIONAL view only: the
                        // admission path uses checked arithmetic and refuses.
                        e.0 = e.0.saturating_add(amount);
                    }
                }
                (s, None) if s.is_active() => match reservation_bucket(&r) {
                    Some(b) => agg.entry(b).or_default().1 += 1,
                    None => global_legacy += 1,
                },
                _ => {}
            }
        }
    });

    let shortfalls: BTreeMap<String, BucketShortfall> =
        BUCKET_SHORTFALLS.with(|b| b.borrow().iter().collect());

    let mut names: std::collections::BTreeSet<String> =
        SUBACCOUNTS.with(|s| s.borrow().iter().map(|(k, _)| k).collect());
    names.extend(agg.keys().cloned());
    names.extend(shortfalls.keys().cloned());

    names
        .into_iter()
        .map(|name| {
            let (encumbered_total, legacy_active_count, retired_count) =
                agg.get(&name).cloned().unwrap_or_default();
            let sf = shortfalls.get(&name).cloned().unwrap_or_default();
            BucketIntegrity {
                subaccount_name:      name,
                shortfall_total:      sf.shortfall_total,
                shortfall_events:     sf.shortfall_events,
                shortfall_overflowed: sf.shortfall_overflowed,
                encumbered_total,
                legacy_active_count:  legacy_active_count.saturating_add(global_legacy),
                retired_count,
            }
        })
        .collect()
}

// ── Canonical authority read-back (custody-vault freeze V6 §6, lane L3a) ─────

/// Canonical stored authority principals: TOKEN, POOL, CONTROLLER — the exact
/// values held in the CANISTER_REFS eager cell (MemoryId 4), set once at init.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CanisterRefsReadback {
    pub token_canister: Principal,
    pub pool_canister:  Principal,
    pub controller:     Principal,
}

/// Read the CANISTER_REFS cell directly (never the heap mirrors, so the answer
/// cannot diverge from durable state). `None` IS the fail-closed case: the
/// sentinel survived (uninit), or the region is corrupt and decoded to the
/// sentinel. No default is ever substituted.
fn read_canister_refs() -> Option<[Principal; 3]> {
    CANISTER_REFS.with(|c| c.borrow().get().get().copied())
}

/// PUBLIC per the freeze ruling (§6): each returned principal is public
/// post-launch, and the purpose is externally verifiable proof the
/// born-under-vault wiring is real. Mutation-free. FAILS CLOSED — traps on
/// sentinel/uninitialised/corrupt state rather than returning a default.
#[query]
fn get_canister_refs_readback() -> CanisterRefsReadback {
    match read_canister_refs() {
        Some([token_canister, pool_canister, controller]) => {
            CanisterRefsReadback { token_canister, pool_canister, controller }
        }
        None => ic_cdk::trap(
            "get_canister_refs_readback: CANISTER_REFS sentinel survived — no initialised \
             canister references in stable memory (MemoryId 4 absent, unwritten, or \
             corrupt). Refusing to substitute a default.",
        ),
    }
}

// ── Build info ────────────────────────────────────────────────────────────────

#[query]
fn get_build_info() -> String {
    format!("treasury v{}", env!("CARGO_PKG_VERSION"))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Atomically credit several named subaccounts with overflow checking.
/// Phase 1 validates every credit with checked_add (reading each entry once);
/// phase 2 applies them. An overflow on any bucket aborts with Err and mutates
/// nothing. Precondition: `credits` must target DISTINCT subaccount names (the
/// three protocol buckets always are); duplicates would validate against the
/// pre-credit balance and silently drop one credit.
fn credit_many(credits: &[(&str, u128)]) -> Result<(), String> {
    SUBACCOUNTS.with(|s| {
        let mut map = s.borrow_mut();
        let mut staged: Vec<(String, SubaccountBalance)> = Vec::new();
        for (name, amount) in credits {
            if *amount == 0 { continue; }
            if let Some(mut entry) = map.get(&name.to_string()) {
                entry.balance = entry.balance.checked_add(*amount)
                    .ok_or_else(|| format!("credit overflow on subaccount '{}'", name))?;
                staged.push((name.to_string(), entry));
            }
        }
        for (name, entry) in staged {
            map.insert(name, entry);
        }
        Ok(())
    })
}

/// Maps a treasury subaccount name to the pool's reserve bucket. Only the three
/// reserve buckets the pool tracks (operations / insurance / staking_rewards) are
/// disbursable under Option 2; the other named buckets (audit, bug_bounty,
/// liquidity, community) have no pool reserve and are never funded by
/// receive_fee_split, so they return None.
fn reserve_bucket_for(subaccount_name: &str) -> Option<TreasuryReserveBucket> {
    match subaccount_name {
        "operations"      => Some(TreasuryReserveBucket::Operations),
        "insurance"       => Some(TreasuryReserveBucket::Insurance),
        "staking_rewards" => Some(TreasuryReserveBucket::StakingRewards),
        _ => None,
    }
}

// ── F-1 reservation helpers ───────────────────────────────────────────────────
//
// None of these `await`; each runs inside one atomic message segment. The map
// is insert-once: NO removal function exists anywhere in this crate, so a
// reservation record can never be deleted — including by an upgrade, since the
// map is stable and `post_upgrade` only sweeps statuses forward.

/// Deterministic FNV-1a-64 over the candid encoding of the proposal fields the
/// disbursement depends on. Pure and host-testable; NOT cryptographic — the
/// authoritative same-id/different-args check is the pool's own fingerprint
/// binding. This fingerprint makes a reused proposal_id with different
/// disbursement args fail closed at the treasury gate as well.
fn args_fingerprint(proposal: &WithdrawalProposal) -> u64 {
    let bytes = candid::encode_one((
        proposal.id,
        &proposal.subaccount_name,
        proposal.recipient,
        proposal.amount,
    ))
    .expect("args_fingerprint: candid encode of fixed-shape tuple cannot fail");
    // FNV-1a 64: offset basis 14695981039346656037, prime 1099511628211.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Acquire the durable reservation for `proposal_id`, inserting the record
/// BEFORE the first `await` of `execute_withdrawal`.
///
/// - No record: insert `{Reserved}` — this is the crash boundary; the insert
///   commits with the pre-await segment even if a later continuation traps.
/// - `Reserved` (same fingerprint): a turn is in flight (or trapped after the
///   pre-await commit without an intervening upgrade) → reject, exactly as the
///   old heap gate did.
/// - `Failed` / `OutcomeUnknown`: the prior attempt settled without a
///   confirmed disbursement; this retry re-reserves (status moves back to
///   `Reserved` with a fresh timestamp). The pool's idempotency makes the
///   retry return the prior result if the disbursement did in fact happen.
/// - `Executed`: replay — return Ok and let the caller observe the recorded
///   outcome via `claim_execution`, which refuses a second debit.
/// - Different fingerprint on the same id: fail closed.
/// W2 2-6 §2(9a): the attempt class, which decides the error handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttemptClass {
    /// Reservation newly created, or re-reserved from `Failed` (or an
    /// `Executed` replay). No prior ambiguity: a pool `Err` before any record
    /// existed is non-execution by construction, so it settles `Failed`.
    Fresh,
    /// Re-entry while the reservation was `OutcomeUnknown`. The prior attempt
    /// may have executed, so NO pool error releases it (§2(9d)) — with the one
    /// ruled exception of `DisbursementProposalIdRetired` (§2(9e′)/(9g)).
    UnknownRetry {
        /// The encumbrance frozen by the original attempt, if it recorded one.
        /// §2(9c): a non-legacy unknown-retry REUSES this `total_debit` for the
        /// pool arguments instead of re-deriving a live fee, so fee drift can
        /// no longer manufacture an `IdempotencyKeyConflict`.
        frozen_total_debit: Option<u128>,
    },
}

fn reserve_withdrawal(
    proposal_id: u64,
    fingerprint: u64,
    now_ns: u64,
) -> Result<AttemptClass, String> {
    INFLIGHT_RESERVATIONS.with(|m| {
        let mut map = m.borrow_mut();
        match map.get(&proposal_id) {
            None => {
                map.insert(proposal_id, InflightWithdrawalReservation {
                    proposal_id,
                    args_fingerprint: fingerprint,
                    reserved_at_ns: now_ns,
                    status: ReservationStatus::Reserved,
                    subaccount_name: None,
                    encumbered_total_debit: None,
                });
                Ok(AttemptClass::Fresh)
            }
            Some(r) => {
                if r.args_fingerprint != fingerprint {
                    return Err(format!(
                        "Proposal {} reservation fingerprint conflict (same id, different \
                         args). No retry; reconcile before proceeding.",
                        proposal_id
                    ));
                }
                match r.status {
                    // `RetryingUnknown` is in flight exactly as `Reserved` is.
                    ReservationStatus::Reserved | ReservationStatus::RetryingUnknown => {
                        Err(format!("Proposal {} is already executing", proposal_id))
                    }
                    ReservationStatus::Executed => Ok(AttemptClass::Fresh),
                    // §2(9g)(ii): a dead end by design. Unlike `Failed` /
                    // `OutcomeUnknown`, this never re-reserves.
                    ReservationStatus::RetiredNotExecuted => {
                        Err(RefusalCode::RetiredNotReReservable.msg(format!(
                            "proposal {} was terminally retired at the pool; its \
                             reservation is not re-reservable. Reject the proposal and \
                             re-propose with a new id.",
                            proposal_id
                        )))
                    }
                    ReservationStatus::Failed => {
                        map.insert(proposal_id, InflightWithdrawalReservation {
                            status: ReservationStatus::Reserved,
                            reserved_at_ns: now_ns,
                            ..r
                        });
                        Ok(AttemptClass::Fresh)
                    }
                    // §2(9b): an unknown-retry moves to `RetryingUnknown` in
                    // the pre-await segment — NEVER back to `Reserved`, so the
                    // class is durably distinguishable at response time.
                    ReservationStatus::OutcomeUnknown => {
                        let frozen_total_debit = r.encumbered_total_debit;
                        map.insert(proposal_id, InflightWithdrawalReservation {
                            status: ReservationStatus::RetryingUnknown,
                            reserved_at_ns: now_ns,
                            ..r
                        });
                        Ok(AttemptClass::UnknownRetry { frozen_total_debit })
                    }
                }
            }
        }
    })
}

// ── W2 2-6: bucket-level admission via per-reservation encumbrance ───────────

/// The bucket a reservation encumbers. Prefers the durably recorded name; for a
/// LEGACY record (`subaccount_name == None`) it is derived from the proposal
/// map, which holds `subaccount_name` for the same `proposal_id` (§2(5a)).
/// `None` means the bucket is UNDERIVABLE — which must fail closed GLOBALLY,
/// never be silently skipped.
fn reservation_bucket(r: &InflightWithdrawalReservation) -> Option<String> {
    if let Some(name) = &r.subaccount_name {
        return Some(name.clone());
    }
    PROPOSALS.with(|p| p.borrow().get(&r.proposal_id).map(|v| v.subaccount_name))
}

/// The outcome of scanning every OTHER reservation for admission purposes.
struct BucketEncumbrance {
    /// Checked sum of recorded encumbrances of ACTIVE reservations on the bucket.
    /// `None` = the sum overflowed → fail closed (§2(7)).
    total: Option<u128>,
    /// Proposal ids of ACTIVE reservations with NO recorded encumbrance that
    /// block this admission: those on the same bucket, plus (fail-closed) every
    /// one whose bucket could not be derived at all.
    legacy_blockers: Vec<u64>,
}

/// Scan the reservation records — the truth source — for bucket `bucket` on
/// behalf of `self_id`, which is EXCLUDED (it is already in the map, holding
/// its own `Reserved`/`RetryingUnknown` status; `E[b]` is the encumbrance of
/// every OTHER reservation).
///
/// No cached aggregate exists: §2(2) permits scanning the map at admission
/// because admission is controller-driven and rare, and a cache that cannot be
/// provably rebuilt is ruled out.
fn scan_bucket_encumbrance(self_id: u64, bucket: &str) -> BucketEncumbrance {
    INFLIGHT_RESERVATIONS.with(|m| {
        let mut total: Option<u128> = Some(0);
        let mut legacy_blockers: Vec<u64> = Vec::new();
        for (id, r) in m.borrow().iter() {
            if id == self_id || !r.status.is_active() {
                continue;
            }
            match r.encumbered_total_debit {
                // Recorded encumbrance: counts only against its own bucket.
                Some(amount) => {
                    if reservation_bucket(&r).as_deref() == Some(bucket) {
                        total = total.and_then(|t| t.checked_add(amount));
                    }
                }
                // LEGACY ACTIVE (§2(5a)) — never read as zero encumbrance.
                None => match reservation_bucket(&r) {
                    Some(b) if b == bucket => legacy_blockers.push(id),
                    // Bucket underivable (should be impossible): refuse
                    // GLOBALLY until reconciled. Fail closed.
                    None => legacy_blockers.push(id),
                    // A legacy record on a DIFFERENT bucket blocks that bucket,
                    // not this one — the blocker is bucket-scoped.
                    Some(_) => {}
                },
            }
        }
        BucketEncumbrance { total, legacy_blockers }
    })
}

/// W2 2-6 §2(2)+(5a)+(7): the admission decision and the durable encumbrance
/// commit, as ONE await-free unit. The caller must invoke this in the same
/// message segment that read `balance`, and before the pool await.
///
/// Fail-closed order: legacy blocker → checked sum → checked comparison. On
/// admission the reservation's own bucket and `total_debit` are written into
/// its record here, so the encumbrance is durable before any yield.
///
/// Returns the refusal message on refusal; the CALLER settles the reservation
/// (`Failed`) so the settle policy stays in one place.
fn admit_and_encumber(
    proposal_id: u64,
    bucket: &str,
    total_debit: u128,
    balance: u128,
) -> Result<(), String> {
    let scan = scan_bucket_encumbrance(proposal_id, bucket);

    if !scan.legacy_blockers.is_empty() {
        return Err(RefusalCode::LegacyBlocked.msg(format!(
            "subaccount '{}' has unresolved pre-W2-2-6 active reservation(s) with no \
             recorded encumbrance (proposal id(s) {:?}); admission is refused until they \
             resolve through a defined transition (retry re-reserves and records the \
             encumbrance, the reservation settles Failed, or it executes). No admission \
             is computed around an unresolved legacy record.",
            bucket, scan.legacy_blockers,
        )));
    }

    let encumbered = match scan.total {
        Some(v) => v,
        None => {
            return Err(RefusalCode::AdmissionOverflow.msg(format!(
                "summing outstanding encumbrances for subaccount '{}' overflowed u128; \
                 no wrapped or saturated sum may participate in an admission decision",
                bucket,
            )))
        }
    };

    let required = match total_debit.checked_add(encumbered) {
        Some(v) => v,
        None => {
            return Err(RefusalCode::AdmissionOverflow.msg(format!(
                "total_debit {} + outstanding encumbrance {} on subaccount '{}' overflows \
                 u128",
                total_debit, encumbered, bucket,
            )))
        }
    };

    if balance < required {
        return Err(RefusalCode::BucketEncumbered.msg(format!(
            "subaccount '{}' has {} but this withdrawal needs total_debit {} on top of {} \
             already encumbered by outstanding reservations (required {})",
            bucket, balance, total_debit, encumbered, required,
        )));
    }

    // Admitted — commit the encumbrance durably, in this same segment.
    INFLIGHT_RESERVATIONS.with(|m| {
        let mut map = m.borrow_mut();
        if let Some(mut r) = map.get(&proposal_id) {
            r.subaccount_name = Some(bucket.to_string());
            r.encumbered_total_debit = Some(total_debit);
            map.insert(proposal_id, r);
        }
    });
    Ok(())
}

/// W2 2-6: settle a LOCAL (pre-pool-call) refusal according to the attempt
/// class.
///
/// A FRESH attempt has no prior ambiguity — nothing was disbursed, so `Failed`
/// releases the encumbrance and a retry may re-reserve, exactly as before.
///
/// An UNKNOWN-RETRY must RETAIN. The reasoning of §2(9d) applies a fortiori to
/// a local refusal: the ORIGINAL attempt may have executed at the pool, and
/// releasing the encumbrance because *this* retry could not proceed locally
/// would be an over-admission of the very funds that may already be gone. It
/// goes back to `OutcomeUnknown` (never `Failed`), so a later retry can still
/// reach the claiming outcome.
fn settle_local_refusal(proposal_id: u64, attempt: AttemptClass) {
    let status = match attempt {
        AttemptClass::Fresh => ReservationStatus::Failed,
        AttemptClass::UnknownRetry { .. } => ReservationStatus::OutcomeUnknown,
    };
    settle_reservation(proposal_id, status);
}

/// Settle the reservation after a definite local/pool failure (`Failed`), a
/// transport-ambiguous one (`OutcomeUnknown`), or the pool's terminal
/// non-execution decision (`RetiredNotExecuted`, §2(9g)). Never removes the
/// record.
fn settle_reservation(proposal_id: u64, status: ReservationStatus) {
    debug_assert!(
        matches!(
            status,
            ReservationStatus::Failed
                | ReservationStatus::OutcomeUnknown
                | ReservationStatus::RetiredNotExecuted
        ),
        "settle_reservation is only for non-executed terminal-attempt statuses",
    );
    INFLIGHT_RESERVATIONS.with(|m| {
        let mut map = m.borrow_mut();
        if let Some(mut r) = map.get(&proposal_id) {
            r.status = status;
            map.insert(proposal_id, r);
        }
    });
}

/// Claim the exactly-once execution commit. Returns true iff THIS call moved
/// the record to `Executed` — the caller must perform the debit + status flip
/// only on true. A replay that finds the record already `Executed` gets false:
/// it observes the prior result and MUST NOT debit again.
fn claim_execution(proposal_id: u64) -> bool {
    INFLIGHT_RESERVATIONS.with(|m| {
        let mut map = m.borrow_mut();
        match map.get(&proposal_id) {
            Some(mut r) if r.status != ReservationStatus::Executed => {
                r.status = ReservationStatus::Executed;
                map.insert(proposal_id, r);
                true
            }
            _ => false,
        }
    })
}

/// The `reject_proposal` guard — W2 2-6 §2(6a) WIDENS it to every ACTIVE
/// status, not just `Reserved`.
///
/// Rejecting an `OutcomeUnknown` proposal makes it non-`Pending`,
/// `execute_withdrawal` then refuses it, and the only path that can resolve the
/// attempt (retry → `AlreadyExecuted`, or a terminal pool decision) becomes
/// unreachable — the encumbrance would be permanent. Silently releasing on
/// rejection is ruled OUT: the pool may have executed, so release =
/// over-admission.
///
/// `Failed`, `Executed` and `RetiredNotExecuted` do NOT block: nothing is left
/// to resolve, and for a retired id rejecting the proposal is the EXPECTED
/// operator action (§2(9g)(ii)).
fn reservation_is_inflight(proposal_id: u64) -> bool {
    INFLIGHT_RESERVATIONS.with(|m| {
        m.borrow()
            .get(&proposal_id)
            .map(|r| r.status.is_active())
            .unwrap_or(false)
    })
}

/// W2 2-6 §2(9g)(ii): is this proposal id terminally retired at the pool?
/// Read-only, and checked FIRST in `execute_withdrawal` — before reservation
/// work, the fee query, admission, encumbrance, or any pool call.
fn reservation_is_retired(proposal_id: u64) -> bool {
    INFLIGHT_RESERVATIONS.with(|m| {
        matches!(
            m.borrow().get(&proposal_id).map(|r| r.status),
            Some(ReservationStatus::RetiredNotExecuted)
        )
    })
}

/// Upgrade-scan cap. Treasury-local copy of the EXACT numeric value of the
/// shielded pool's `MAX_UPGRADE_SCAN` (`canisters/shielded-pool/src/lib.rs`,
/// `const MAX_UPGRADE_SCAN: usize = 1_000;`) at base
/// ca7409182a62f634f8cce117a4ae241878e3f0f4. Copied by value deliberately — no
/// pool crate dependency, no shared-constants refactor.
const MAX_UPGRADE_SCAN: usize = 1_000;

/// `post_upgrade` sweep: a `Reserved` (or `RetryingUnknown`) record that
/// survives an upgrade belonged to a turn that died with the old Wasm — its
/// outcome is unknown by construction. Move it to `OutcomeUnknown` so a retry
/// can re-reserve and let the pool's idempotency return the prior result.
/// Forward-only; no record is ever removed.
///
/// W2 2-6 §2(9b): `RetryingUnknown` qualifies EXACTLY like `Reserved` — it is
/// an in-flight turn, so it is swept and it counts toward the scan cap.
/// §2(9g)(ii): `RetiredNotExecuted` is preserved as-is and is NOT counted — it
/// is terminal and inactive, there is no turn to fold, and counting a dead
/// record toward the cap would let inert history block upgrades.
///
/// W2 2-2: bounded by `MAX_UPGRADE_SCAN`, mirroring the pool's cap-and-trap
/// discipline. At most `MAX_UPGRADE_SCAN + 1` qualifying entries are collected;
/// over the cap the upgrade TRAPS before any record is rewritten — never a
/// partial migration, never an unbounded scan that would exceed the instruction
/// limit and brick the canister.
fn sweep_reserved_reservations_on_upgrade() {
    INFLIGHT_RESERVATIONS.with(|m| {
        let mut map = m.borrow_mut();
        let stale: Vec<(u64, InflightWithdrawalReservation)> = map
            .iter()
            .filter(|(_, r)| {
                matches!(
                    r.status,
                    ReservationStatus::Reserved | ReservationStatus::RetryingUnknown
                )
            })
            .take(MAX_UPGRADE_SCAN + 1)
            .collect();
        if stale.len() > MAX_UPGRADE_SCAN {
            ic_cdk::trap(&format!(
                "post_upgrade: INFLIGHT_RESERVATIONS exceeds the upgrade-scan cap \
                 ({MAX_UPGRADE_SCAN} in-flight Reserved / RetryingUnknown records). \
                 Aborting to bound the sweep and \
                 prevent an instruction-limit brick. Settle / reconcile in-flight \
                 reservations below the cap, then retry the upgrade."
            ));
        }
        for (id, mut r) in stale {
            r.status = ReservationStatus::OutcomeUnknown;
            map.insert(id, r);
        }
    });
}

/// W2 2-6 §2(1): exact debit with a durable shortfall record — never a silent
/// clamp, never a trap.
///
/// The `saturating_sub` this replaces made a debit exceeding the balance vanish
/// in part with no trace, which is precisely how a concurrent over-admission
/// settled as a treasury UNDER-debit (SSA-S1S4-001): S4 diverged upward and the
/// history was not reconstructable afterwards.
///
/// It must NOT trap: it runs in the post-success segment, AFTER the pool has
/// already debited its reserve and moved real funds — refusing there would lose
/// more state than recording does. With bucket-level admission (§2(2)) in place
/// a shortfall is unreachable in theory; this record is defence in depth and
/// follows the ruled asymmetry: may over-report trouble, must never
/// under-report it.
fn debit_subaccount(name: &str, amount: u128) {
    SUBACCOUNTS.with(|s| {
        let mut map = s.borrow_mut();
        if let Some(mut entry) = map.get(&name.to_string()) {
            let applied = entry.balance.min(amount);
            let shortfall = amount - applied;
            entry.balance -= applied;
            map.insert(name.to_string(), entry);
            if shortfall > 0 {
                record_debit_shortfall(name, shortfall);
            }
        }
    });
}

/// W2 2-6 §2(7) cumulative-counter contract: SATURATE and set a durable
/// `shortfall_overflowed` flag. A saturated value with the flag set means "at
/// least this much; the exact total is no longer representable"; without the
/// flag, values are exact. Never traps, never wraps.
fn record_debit_shortfall(name: &str, shortfall: u128) {
    BUCKET_SHORTFALLS.with(|b| {
        let mut map = b.borrow_mut();
        let key = name.to_string();
        let mut rec = map.get(&key).unwrap_or_default();

        match rec.shortfall_total.checked_add(shortfall) {
            Some(v) => rec.shortfall_total = v,
            None => {
                rec.shortfall_total = u128::MAX;
                rec.shortfall_overflowed = true;
            }
        }
        match rec.shortfall_events.checked_add(1) {
            Some(v) => rec.shortfall_events = v,
            None => {
                rec.shortfall_events = u64::MAX;
                rec.shortfall_overflowed = true;
            }
        }

        map.insert(key, rec);
    });
}

fn update_proposal_status(id: u64, status: ProposalStatus) {
    PROPOSALS.with(|p| {
        let mut map = p.borrow_mut();
        if let Some(mut proposal) = map.get(&id) {
            proposal.status = status;
            map.insert(id, proposal);
        }
    });
}

// ── Upgrade hooks ─────────────────────────────────────────────────────────────
//
// ── MIGRATION LOG ─────────────────────────────────────────────────────────────
//
// STATE_VERSION 1  (pre-A2 P4 fix — 2026-06-09)
//   Initial stable-persist.  First version to survive a Wasm upgrade without
//   state loss.
//
//   Serialised into TreasuryStableState (stable Cell, MEM_STABLE_STATE = MemoryId 3):
//     Canister refs (3): token_canister, pool_canister, controller
//     Counters (2): next_proposal_id, fee_log_index
//
//   Pre-#90 blobs also contained shield_routing, transfer_routing, unshield_routing
//   (FeeRoutingConfig) fields.  Candid ignores these extra fields when decoding
//   into the current (smaller) TreasuryStableState — no migration handler needed.
//
//   Survive upgrade automatically (StableBTreeMap, no serialisation needed):
//     SUBACCOUNTS  (MemoryId 0) — named treasury subaccount balances
//     PROPOSALS    (MemoryId 1) — pending/executed withdrawal proposals
//     FEE_LOG      (MemoryId 2) — fee receipt audit log
//
//   Upgrade from pre-P4 code: NOT SUPPORTED.  Reinitialise after settling
//   all in-flight withdrawals.
//
// #120 execute_withdrawal accounting fix (2026-06-18) — no STATE_VERSION bump
//   - debit_subaccount now uses total_debit = amount + ledger_fee (not amount only)
//   - INFLIGHT_PROPOSALS gate added (heap-only HashSet<u64>, cleared on upgrade)
//   - No DID or stable-struct changes.
//
//   (The heap-only INFLIGHT upgrade behaviour described here historically was
//   superseded by lane L3a below — the reservation is durable now.)
//
// Lane B v2 — Option 2 custody migration (2026-06-21) — no STATE_VERSION bump
//   - execute_withdrawal no longer transfers from treasury's own ledger account.
//     It calls the shielded-pool treasury_disburse entrypoint (Lane A v2 5e62f75);
//     the pool custodies reserves and performs the on-ledger transfer. Treasury
//     holds no real STSH (invariant: icrc1_balance_of(treasury) == 0).
//   - Debit model is now POST-SUCCESS-DEBIT: the treasury bucket is debited only
//     after the pool returns Executed/AlreadyExecuted (both success), atomically
//     with the status flip. No debit on any failure path — the old pre-debit +
//     re-credit dance and credit_subaccount() are removed. "No double-debit on
//     disbursement failure" therefore holds by construction.
//   - proposal_id is the pool's fingerprint-bound idempotency key; same id with
//     different parameters -> PoolError::IdempotencyKeyConflict (treated as failure).
//   - Disbursable buckets are limited to the pool's reserve set
//     (operations/insurance/staking_rewards); other named buckets have no pool
//     reserve under Option 2.
//   - No DID or stable-struct changes (TreasuryStableState unchanged).

// Upgrade-persistence hardening Phase 2 (2026-07-31) — no STATE_VERSION bump
//   - `pre_upgrade` REMOVED. The checkpoint cell (MemoryId 3) is retired and
//     frozen. Every former-checkpoint field is now written EAGERLY at its
//     existing mutation point:
//       token/pool/controller  → CANISTER_REFS      (MemoryId 4, grouped)
//       next_proposal_id       → NEXT_PROPOSAL_ID_CELL (MemoryId 5)
//       fee_log_index          → FEE_LOG_INDEX_CELL    (MemoryId 6)
//   - `post_upgrade` is now a fail-closed sentinel gate: an absent or corrupt
//     eager region decodes to the impossible sentinel and traps, rather than
//     silently resurrecting the canister with default refs and reset counters.
//   - Upgrading ACROSS the conversion boundary (from a pre-Phase-2 Wasm) traps
//     by design: those regions were never allocated, so the sentinel survives.
//     Nothing is on mainnet; a local/rehearsal canister must be wiped and
//     reinstalled, never upgraded across the boundary.
//   - No DID change: no endpoint signature or Candid type moved.
//
// Lane L3a — custody-vault F-1 + read-back (2026-08-04) — no STATE_VERSION bump
//   - The heap-only `INFLIGHT_PROPOSALS: HashSet<u64>` gate is REPLACED by
//     `INFLIGHT_RESERVATIONS`, a StableBTreeMap over MemoryId 7
//     (INFLIGHT_WITHDRAWAL_RESERVATION, L0's campaign allocation). Records
//     `{proposal_id, args_fingerprint, reserved_at_ns, status}` are inserted
//     BEFORE the first `await` in `execute_withdrawal` and are NEVER deleted
//     (no removal API exists); only `status` moves forward
//     (Reserved → Executed | Failed | OutcomeUnknown).
//   - `post_upgrade` sweeps surviving Reserved records to OutcomeUnknown: such
//     a record's turn died with the old Wasm, so its outcome is unknown; a
//     retry re-reserves and the pool's fingerprint-bound idempotency returns
//     the prior result. `claim_execution` makes the post-success debit
//     exactly-once even against a replayed/concurrent AlreadyExecuted.
//   - MemoryId 7 was never written by any earlier Wasm, so an upgrade from
//     Phase-2 code simply sees an empty map — no migration handler needed.
//   - DID change: ADDITIVE query `get_canister_refs_readback` (freeze V6 §6) —
//     no existing signature or Candid type moved.

// ── ATOMICITY: the live mutation paths ───────────────────────────────────────
//
// V2 acceptance #2, made real (Phase 2). Unlike the Phase-1 set-once trio, both
// treasury counters have LIVE mutation paths, so "a rejected operation persists
// no partial scalar" is a claim about running code, not a vacuity.
//
// PROOF OBLIGATION, discharged by construction and covered by
// `integration-tests/tests/eager_cell_phase2_tests.rs`:
//
//   1. `alloc_proposal_id` and `alloc_fee_log_index` are the ONLY writers of
//      their cells after `init`. Both are `await`-free, and their callers do
//      not `await` between the allocation and the map insert that consumes it,
//      so a DEFINITE local rejection (trap or early `Err`) rolls back the whole
//      message segment — the counter cell included. A half-written counter is
//      not representable.
//   2. `propose_withdrawal` validates the subaccount, the balance and the
//      caller BEFORE `alloc_proposal_id`; `receive_fee_split` authenticates the
//      pool and credits every bucket BEFORE `alloc_fee_log_index`. A rejected
//      call therefore never reaches the allocation at all.
//   3. The two counters are in SEPARATE cells deliberately. They are mutated by
//      different operations, and `Cell::set` rewrites the entire cell, so
//      grouping them would make each fee receipt rewrite the proposal counter
//      (and vice versa) for no benefit — the Phase-0 grouping win (2 370 vs
//      4 119) only applies to fields written in the SAME operation, which these
//      never are.
//   4. Retry cannot double-apply. `execute_withdrawal` — the only path with an
//      external `await` — mutates NEITHER counter; the pool's `proposal_id` is
//      its idempotency key and the treasury debit stays POST-success exactly as
//      Option 2 requires. Nothing was moved ahead of that await to persist it
//      earlier.
//
// OUT OF SCOPE, deliberately: transport-UNKNOWN idempotency of
// `receive_fee_split`. That interface has no idempotency key, and retrofitting
// one is a chartered lane of its own (request identity, payload binding,
// durable outcomes, Candid impact, retry rules) — exactly as P-STK C-A5 was for
// staking. Phase 2 covers definite local rejection and existing idempotent
// paths only, and does not improvise ingress idempotency here.

#[post_upgrade]
fn post_upgrade() {
    // Fail-closed sentinel gate — see stsh-eager-cell for the contract.
    // Every cell is validated BEFORE any heap mirror is populated, so a
    // surviving sentinel can never become observable through a getter.
    let refs = CANISTER_REFS.with(|c| *c.borrow().get());
    let Some([token_canister, pool_canister, controller]) = refs.get().copied() else {
        ic_cdk::trap(
            "post_upgrade: CANISTER_REFS sentinel survived — no initialised canister \
             references in stable memory (MemoryId 4 absent or unwritten). This canister \
             was never initialised, or is being upgraded from a pre-hardening Wasm that \
             predates the eager cell. Aborting to prevent silent state loss.",
        );
    };

    let proposal_counter = NEXT_PROPOSAL_ID_CELL.with(|c| *c.borrow().get());
    let Some(next_proposal_id) = proposal_counter.get().copied().and_then(|[w]| decode_id_counter(w))
    else {
        ic_cdk::trap(
            "post_upgrade: NEXT_PROPOSAL_ID did not validate — the proposal counter region \
             (MemoryId 5) is absent, unwritten, zero, or above u64::MAX. Resuming would \
             restart proposal ids (or narrow a truncated one) and let a new proposal \
             collide with a stored one. Aborting.",
        );
    };

    let index_counter = FEE_LOG_INDEX_CELL.with(|c| *c.borrow().get());
    let Some(fee_log_index) = index_counter.get().copied().and_then(|[w]| decode_index_counter(w))
    else {
        ic_cdk::trap(
            "post_upgrade: FEE_LOG_INDEX did not validate — the fee-log index region \
             (MemoryId 6) is absent, unwritten, or above u64::MAX. Resuming would overwrite \
             existing fee log entries. Aborting.",
        );
    };

    TOKEN_CANISTER.with(|t|   *t.borrow_mut() = Some(token_canister));
    POOL_CANISTER.with(|p|    *p.borrow_mut() = Some(pool_canister));
    CONTROLLER.with(|c|       *c.borrow_mut() = Some(controller));
    NEXT_PROPOSAL_ID.with(|n| *n.borrow_mut() = next_proposal_id);
    FEE_LOG_INDEX.with(|f|    *f.borrow_mut() = fee_log_index);

    // F-1: any Reserved reservation that survived the upgrade belonged to a
    // turn that died with the old Wasm — sweep it to OutcomeUnknown so a retry
    // re-reserves and the pool's idempotency returns the prior result.
    sweep_reserved_reservations_on_upgrade();
}

// suppress unused-import warning for MAX_FEE_BPS (kept for future fee-cap logic)
const _: u32 = MAX_FEE_BPS;

// =============================================================================
// TEST-ONLY ENDPOINTS — absent from production builds (no --features testing)
// =============================================================================

// Pre-seeds a Reserved durable reservation for a single proposal_id to simulate
// the post-reservation-insert / pre-icrc1_fee-yield state deterministically in
// PocketIC. Allows test_77 to prove execute_withdrawal returns "already
// executing" for a second call on the same proposal_id without requiring true
// concurrent execution. The fingerprint is computed from the stored proposal so
// the simulated record is indistinguishable from a real pre-await reservation.
#[cfg(feature = "testing")]
#[update]
fn inject_inflight_proposal_for_test(proposal_id: u64) {
    let controller = CONTROLLER.with(|c| c.borrow().unwrap());
    assert_eq!(ic_cdk::caller(), controller, "controller-only");
    let fingerprint = PROPOSALS
        .with(|p| p.borrow().get(&proposal_id))
        .map(|proposal| args_fingerprint(&proposal))
        .unwrap_or(0);
    INFLIGHT_RESERVATIONS.with(|m| {
        m.borrow_mut().insert(proposal_id, InflightWithdrawalReservation {
            proposal_id,
            args_fingerprint: fingerprint,
            reserved_at_ns: time(),
            status: ReservationStatus::Reserved,
            // Deliberately a LEGACY-shaped record (no recorded encumbrance) —
            // unchanged from the pre-W2-2-6 hook so the W2 2-2 cap-and-trap
            // suite keeps staging exactly what it staged before.
            subaccount_name: None,
            encumbered_total_debit: None,
        });
    });
}

/// W2 2-6 staging hook: write a reservation in an ARBITRARY status, with or
/// without a recorded encumbrance, so the suites can stage the states the
/// packet's acceptance criteria name — a LEGACY ACTIVE record (`None`
/// encumbrance), an `OutcomeUnknown` awaiting retry, a `RetryingUnknown`
/// mid-flight record, or a terminal `RetiredNotExecuted` — deterministically,
/// without needing a real interleaved turn or a pre-W2-2-6 Wasm.
///
/// `status_tag`: 0 Reserved, 1 Executed, 2 Failed, 3 OutcomeUnknown,
/// 4 RetryingUnknown, 5 RetiredNotExecuted.
///
/// The fingerprint is computed from the stored proposal, so a staged record is
/// indistinguishable from one a real turn wrote. Test-only: absent from every
/// deployable build, proved by the Wasm export scan.
#[cfg(feature = "testing")]
#[update]
fn stage_reservation_for_test(
    proposal_id: u64,
    status_tag: u8,
    subaccount_name: Option<String>,
    encumbered_total_debit: Option<u128>,
) {
    let controller = CONTROLLER.with(|c| c.borrow().unwrap());
    assert_eq!(ic_cdk::caller(), controller, "controller-only");
    let status = match status_tag {
        0 => ReservationStatus::Reserved,
        1 => ReservationStatus::Executed,
        2 => ReservationStatus::Failed,
        3 => ReservationStatus::OutcomeUnknown,
        4 => ReservationStatus::RetryingUnknown,
        5 => ReservationStatus::RetiredNotExecuted,
        other => ic_cdk::trap(&format!("stage_reservation_for_test: bad status_tag {other}")),
    };
    let fingerprint = PROPOSALS
        .with(|p| p.borrow().get(&proposal_id))
        .map(|proposal| args_fingerprint(&proposal))
        .unwrap_or(0);
    INFLIGHT_RESERVATIONS.with(|m| {
        m.borrow_mut().insert(proposal_id, InflightWithdrawalReservation {
            proposal_id,
            args_fingerprint: fingerprint,
            reserved_at_ns: time(),
            status,
            subaccount_name,
            encumbered_total_debit,
        });
    });
}

/// W2 2-6: drive `debit_subaccount` directly, so the exact-debit / shortfall
/// path can be exercised past the balance without first having to manufacture
/// a pool disbursement. Read-write by design — it IS the function under test.
#[cfg(feature = "testing")]
#[update]
fn debit_subaccount_for_test(name: String, amount: u128) {
    let controller = CONTROLLER.with(|c| c.borrow().unwrap());
    assert_eq!(ic_cdk::caller(), controller, "controller-only");
    debit_subaccount(&name, amount);
}

/// W2 2-6: seed the durable shortfall counters near their ceiling so the
/// saturate-and-flag contract can be observed at the boundary instead of being
/// argued from the source.
#[cfg(feature = "testing")]
#[update]
fn seed_bucket_shortfall_for_test(name: String, total: u128, events: u64, overflowed: bool) {
    let controller = CONTROLLER.with(|c| c.borrow().unwrap());
    assert_eq!(ic_cdk::caller(), controller, "controller-only");
    BUCKET_SHORTFALLS.with(|b| {
        b.borrow_mut().insert(name, BucketShortfall {
            shortfall_total: total,
            shortfall_events: events,
            shortfall_overflowed: overflowed,
        });
    });
}

// ── Test-only eager-cell probe (feature = "testing") ─────────────────────────
//
// Exposes the RAW encoded bytes of an eager cell so the cross-Wasm sentinel and
// atomicity tests can assert on the DURABLE layout directly rather than
// inferring persistence from a downstream getter.
//
// BUILD-GATED OFF BY DEFAULT — absent from every deployed Wasm, proved (not
// asserted) by `integration-tests/tests/eager_cell_feature_isolation_tests.rs`,
// which scans the shipped binaries for the export name. Read-only: it cannot
// write, clear, or weaken the sentinel path.
//
// `which` selects the cell: "refs" | "next_proposal_id" | "fee_log_index".
#[cfg(feature = "testing")]
#[query]
fn eager_cell_probe_for_test(which: String) -> Vec<u8> {
    match which.as_str() {
        "refs" => CANISTER_REFS.with(|c| c.borrow().get().to_bytes().into_owned()),
        "next_proposal_id" => {
            NEXT_PROPOSAL_ID_CELL.with(|c| c.borrow().get().to_bytes().into_owned())
        }
        "fee_log_index" => FEE_LOG_INDEX_CELL.with(|c| c.borrow().get().to_bytes().into_owned()),
        other => ic_cdk::trap(&format!("eager_cell_probe_for_test: unknown cell `{other}`")),
    }
}

// Returns the current durable reservation count (records are never deleted, so
// this counts every reservation ever inserted, in any status).
// Used by test_77 to assert the gate blocks correctly and is settled on exit.
#[cfg(feature = "testing")]
#[query]
fn inflight_proposals_count_for_test() -> u64 {
    let controller = CONTROLLER.with(|c| c.borrow().unwrap());
    assert_eq!(ic_cdk::caller(), controller, "controller-only");
    INFLIGHT_RESERVATIONS.with(|m| m.borrow().len())
}

/// SI-11 (R-8): the reservation status of ONE proposal id, read by the POOL
/// mid-flight from inside its own `treasury_disburse` handler.
///
/// This is what makes SI-11's guarantee observable across a real canister
/// boundary: the pool asks treasury, while treasury is still parked awaiting
/// the pool, whether the durable reservation for this proposal already exists.
/// It cannot answer from treasury's uncommitted continuation — a replicated
/// query executes against committed state — so a `Some(Reserved)` here is
/// proof the reservation was written and committed in the pre-await segment.
///
/// The caller check admits the controller (the convention every other
/// `_for_test` query in this block follows) AND the two canisters that
/// actually observe mid-flight: the configured POOL and the configured TOKEN.
/// Neither is the controller — `execute_withdrawal`'s own controller-only
/// assertion would be self-defeating if either were.
///
/// R-8 V1a adds the TOKEN. Treasury's FIRST await is its `icrc1_fee` call, not
/// the pool call, so the token's own handler is the only vantage point on the
/// earlier boundary; without it here, the second observer's call traps and the
/// stronger half of SI-11 cannot be observed at all. Read-only: it cannot
/// insert, remove, or re-status anything.
#[cfg(feature = "testing")]
#[query]
fn reservation_status_for_test(proposal_id: u64) -> Option<ReservationStatus> {
    let controller = CONTROLLER.with(|c| c.borrow().unwrap());
    let pool = POOL_CANISTER.with(|c| c.borrow().unwrap());
    let token = TOKEN_CANISTER.with(|c| c.borrow().unwrap());
    let caller = ic_cdk::caller();
    assert!(
        caller == controller || caller == pool || caller == token,
        "controller-, pool- or token-only"
    );
    INFLIGHT_RESERVATIONS.with(|m| m.borrow().get(&proposal_id).map(|r| r.status))
}

// Returns durable reservation counts BY STATUS as
// (Reserved, Executed, Failed, OutcomeUnknown).
//
// W2 2-2 (SSA corrective): `inflight_proposals_count_for_test` is status-
// INSENSITIVE — it proves no record was removed, not that any record was
// swept. Proving the post_upgrade sweep is UNIVERSAL (every Reserved record
// became OutcomeUnknown) and that a trapped over-cap upgrade wrote NOTHING
// requires exact per-status counts over the whole map, not a probe of one
// proposal_id.
//
// Read-only: it cannot insert, remove, or re-status any reservation, so it
// cannot weaken or mask the sweep it is used to observe.
#[cfg(feature = "testing")]
#[query]
fn reservation_status_counts_for_test() -> (u64, u64, u64, u64) {
    let controller = CONTROLLER.with(|c| c.borrow().unwrap());
    assert_eq!(ic_cdk::caller(), controller, "controller-only");
    let c = reservation_status_counts_all();
    (c.0, c.1, c.2, c.3)
}

/// W2 2-6: the SAME census widened to the two statuses this lane adds, as
/// `(Reserved, Executed, Failed, OutcomeUnknown, RetryingUnknown,
/// RetiredNotExecuted)`.
///
/// The 4-tuple probe above is kept verbatim so the W2 2-2 cap-and-trap suite
/// keeps asserting exactly what it asserted at its own pin; this one is what
/// proves the widened sweep (RetryingUnknown folded like Reserved) and the
/// terminal marker's survival (RetiredNotExecuted preserved, never swept).
#[cfg(feature = "testing")]
#[query]
fn reservation_status_counts_v2_for_test() -> (u64, u64, u64, u64, u64, u64) {
    let controller = CONTROLLER.with(|c| c.borrow().unwrap());
    assert_eq!(ic_cdk::caller(), controller, "controller-only");
    reservation_status_counts_all()
}

#[cfg(feature = "testing")]
fn reservation_status_counts_all() -> (u64, u64, u64, u64, u64, u64) {
    INFLIGHT_RESERVATIONS.with(|m| {
        let mut counts = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
        for (_, r) in m.borrow().iter() {
            match r.status {
                ReservationStatus::Reserved           => counts.0 += 1,
                ReservationStatus::Executed           => counts.1 += 1,
                ReservationStatus::Failed             => counts.2 += 1,
                ReservationStatus::OutcomeUnknown     => counts.3 += 1,
                ReservationStatus::RetryingUnknown    => counts.4 += 1,
                ReservationStatus::RetiredNotExecuted => counts.5 += 1,
            }
        }
        counts
    })
}

// =============================================================================
// UNIT TESTS (host target)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Lane L3a (F-1): durable inflight-withdrawal reservation ──────────────
    //
    // These exercise the pure reservation helpers natively; each #[test] runs
    // on its own thread, so the thread_local stable map starts empty per test.
    // The on-Wasm crash-boundary and upgrade paths are covered structurally:
    // the insert happens in `reserve_withdrawal`, called before any `await` in
    // `execute_withdrawal`, and the map is stable (MemoryId 7).

    fn test_proposal(id: u64, amount: u128) -> WithdrawalProposal {
        WithdrawalProposal {
            id,
            proposer: Principal::from_slice(&[1]),
            subaccount_name: "operations".to_string(),
            recipient: Principal::from_slice(&[2]),
            amount,
            description: "t".to_string(),
            created_at_ns: 1,
            execute_after_ns: 2,
            status: ProposalStatus::Pending,
        }
    }

    fn reservation_of(id: u64) -> Option<InflightWithdrawalReservation> {
        INFLIGHT_RESERVATIONS.with(|m| m.borrow().get(&id))
    }

    #[test]
    fn f1_reservation_is_durable_before_the_first_await() {
        // The crash-boundary guarantee: reserve_withdrawal is synchronous and
        // inserts the record immediately — this is the exact call
        // execute_withdrawal makes BEFORE the icrc1_fee await, so by the time
        // any yield happens the reservation is already committed stable state.
        let fp = args_fingerprint(&test_proposal(7, 100));
        reserve_withdrawal(7, fp, 111).unwrap();
        let r = reservation_of(7).expect("record must exist before any await");
        assert_eq!(r.proposal_id, 7);
        assert_eq!(r.args_fingerprint, fp);
        assert_eq!(r.reserved_at_ns, 111);
        assert_eq!(r.status, ReservationStatus::Reserved);
        assert!(reservation_is_inflight(7));
    }

    #[test]
    fn f1_second_turn_on_reserved_record_is_rejected() {
        let fp = args_fingerprint(&test_proposal(8, 100));
        reserve_withdrawal(8, fp, 1).unwrap();
        let err = reserve_withdrawal(8, fp, 2).unwrap_err();
        assert!(err.contains("already executing"), "got: {err}");
        // And the rejection mutated nothing.
        let r = reservation_of(8).unwrap();
        assert_eq!(r.status, ReservationStatus::Reserved);
        assert_eq!(r.reserved_at_ns, 1, "rejection must not re-stamp the record");
    }

    #[test]
    fn f1_replay_after_execution_returns_prior_result_without_redebit() {
        let fp = args_fingerprint(&test_proposal(9, 100));
        reserve_withdrawal(9, fp, 1).unwrap();
        // First (and only) claim performs the debit.
        assert!(claim_execution(9), "first claim must win the debit right");
        // Every later claim observes the prior result and must NOT debit again.
        assert!(!claim_execution(9), "replay must not claim a second debit");
        // A replayed reserve on the executed record is admitted (Ok) and the
        // claim still refuses — "replay returns the prior result".
        reserve_withdrawal(9, fp, 2).unwrap();
        assert!(!claim_execution(9));
        assert_eq!(reservation_of(9).unwrap().status, ReservationStatus::Executed);
        assert!(!reservation_is_inflight(9), "Executed must not block reject_proposal");
    }

    #[test]
    fn f1_retry_after_definite_failure_rereserves() {
        let fp = args_fingerprint(&test_proposal(10, 100));
        reserve_withdrawal(10, fp, 1).unwrap();
        settle_reservation(10, ReservationStatus::Failed);
        assert!(!reservation_is_inflight(10), "Failed must not block reject_proposal");
        // Retry: re-reserved with a fresh timestamp; record never deleted.
        reserve_withdrawal(10, fp, 2).unwrap();
        let r = reservation_of(10).unwrap();
        assert_eq!(r.status, ReservationStatus::Reserved);
        assert_eq!(r.reserved_at_ns, 2);
        assert_eq!(r.args_fingerprint, fp, "fingerprint is immutable across retries");
    }

    #[test]
    fn f1_retry_after_outcome_unknown_rereserves() {
        // W2 2-6 §2(9b) REVISES this contract: a retry out of `OutcomeUnknown`
        // is an UNKNOWN-RETRY, and it moves to `RetryingUnknown` — never back
        // to `Reserved`. The class must be durably distinguishable at response
        // time so the conservative retain-on-every-pool-error rule (§2(9d))
        // applies to retries WITHOUT also applying to fresh attempts. The
        // record is still re-reserved and still active; only the marker
        // differs, and `RetryingUnknown` blocks a second turn exactly as
        // `Reserved` did.
        let fp = args_fingerprint(&test_proposal(11, 100));
        assert_eq!(reserve_withdrawal(11, fp, 1).unwrap(), AttemptClass::Fresh);
        settle_reservation(11, ReservationStatus::OutcomeUnknown);
        assert_eq!(
            reserve_withdrawal(11, fp, 2).unwrap(),
            AttemptClass::UnknownRetry { frozen_total_debit: None },
            "a retry out of OutcomeUnknown is an UNKNOWN-RETRY, not a fresh attempt",
        );
        let r = reservation_of(11).unwrap();
        assert_eq!(r.status, ReservationStatus::RetryingUnknown);
        assert_eq!(r.reserved_at_ns, 2, "the retry re-reserves with a fresh timestamp");
        assert!(
            reservation_is_inflight(11),
            "RetryingUnknown is in-flight: it must block a second turn and rejection",
        );
    }

    #[test]
    fn f1_post_upgrade_sweep_moves_only_reserved_to_outcome_unknown() {
        // Simulates the post_upgrade sweep over a map in every status: records
        // survive the upgrade (stable map) and only Reserved moves forward.
        let fp = |i| args_fingerprint(&test_proposal(i, 100));
        reserve_withdrawal(1, fp(1), 1).unwrap();                                  // stays Reserved? no — swept
        reserve_withdrawal(2, fp(2), 1).unwrap(); claim_execution(2);              // Executed
        reserve_withdrawal(3, fp(3), 1).unwrap(); settle_reservation(3, ReservationStatus::Failed);
        reserve_withdrawal(4, fp(4), 1).unwrap(); settle_reservation(4, ReservationStatus::OutcomeUnknown);

        sweep_reserved_reservations_on_upgrade();

        assert_eq!(reservation_of(1).unwrap().status, ReservationStatus::OutcomeUnknown,
            "a Reserved record surviving upgrade means its turn died — outcome unknown");
        assert_eq!(reservation_of(2).unwrap().status, ReservationStatus::Executed,
            "Executed is terminal; the sweep must not touch it");
        assert_eq!(reservation_of(3).unwrap().status, ReservationStatus::Failed);
        assert_eq!(reservation_of(4).unwrap().status, ReservationStatus::OutcomeUnknown);
        // All four records still present — the sweep never deletes.
        INFLIGHT_RESERVATIONS.with(|m| assert_eq!(m.borrow().len(), 4));
    }

    /// BR-10 (lane R-11) — the `post_upgrade` sweep's per-call scan cap is
    /// enforced by construction, and the enforcement path actually RUNS.
    ///
    /// The claim on `sweep_reserved_reservations_on_upgrade` is that the sweep
    /// is partial rather than unbounded, so it stays inside the upgrade budget.
    /// Its true content is a COUNT property, not a derived cost: `.take(MAX_UPGRADE_SCAN + 1)` collects at most one entry more than
    /// the cap and traps over it, BEFORE any record is rewritten. This test
    /// exercises both sides of the boundary.
    ///
    /// Positive control (the half a trap-only test cannot give): exactly
    /// `MAX_UPGRADE_SCAN` qualifying records complete WITHOUT trapping and every
    /// one is moved to `OutcomeUnknown` — so a regression that simply trapped
    /// always, or swept nothing, fails here rather than passing quietly.
    ///
    /// Negative control: one record past the cap traps, and the map is left
    /// untouched — never a partial migration.
    #[test]
    fn r11_treasury_migration_scan_per_call_cap_is_enforced() {
        let fp = |i| args_fingerprint(&test_proposal(i, 100));

        // ── at the cap: completes, sweeps everything ──────────────────────
        for i in 1..=(MAX_UPGRADE_SCAN as u64) {
            reserve_withdrawal(i, fp(i), 1).unwrap();
        }
        assert_eq!(
            INFLIGHT_RESERVATIONS.with(|m| m.borrow().len()),
            MAX_UPGRADE_SCAN as u64,
            "seed must place exactly MAX_UPGRADE_SCAN qualifying records"
        );
        sweep_reserved_reservations_on_upgrade();
        for i in 1..=(MAX_UPGRADE_SCAN as u64) {
            assert_eq!(
                reservation_of(i).unwrap().status,
                ReservationStatus::OutcomeUnknown,
                "at the cap the sweep must complete and move record {i}"
            );
        }

        // ── one past the cap: traps before rewriting anything ─────────────
        // The already-swept records are `OutcomeUnknown` and no longer qualify,
        // so the qualifying population is exactly the freshly reserved run.
        let base = MAX_UPGRADE_SCAN as u64 + 1;
        for k in 0..=(MAX_UPGRADE_SCAN as u64) {
            let i = base + k;
            reserve_withdrawal(i, fp(i), 1).unwrap();
        }
        let qualifying = INFLIGHT_RESERVATIONS.with(|m| {
            m.borrow()
                .iter()
                .filter(|(_, r)| {
                    matches!(
                        r.status,
                        ReservationStatus::Reserved | ReservationStatus::RetryingUnknown
                    )
                })
                .count()
        });
        assert_eq!(
            qualifying,
            MAX_UPGRADE_SCAN + 1,
            "the over-cap seed must place exactly MAX_UPGRADE_SCAN + 1 qualifying records"
        );

        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let trapped =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                sweep_reserved_reservations_on_upgrade,
            ))
            .is_err();
        std::panic::set_hook(prev);
        assert!(
            trapped,
            "MAX_UPGRADE_SCAN + 1 qualifying records must abort the upgrade, not be swept \
             unboundedly"
        );
        // Never a PARTIAL migration: the trap fires before any rewrite, so every
        // over-cap record is still exactly as seeded.
        for k in 0..=(MAX_UPGRADE_SCAN as u64) {
            assert_eq!(
                reservation_of(base + k).unwrap().status,
                ReservationStatus::Reserved,
                "the trap must precede every rewrite — record {} was mutated",
                base + k
            );
        }
    }

    #[test]
    fn f1_reservations_are_never_deletable() {
        // Structural proof: the crate exposes no removal path. Every failure
        // and success path above leaves the record in the map; this test drives
        // each settle path and asserts the map only grows.
        let fp = |i| args_fingerprint(&test_proposal(i, 100));
        reserve_withdrawal(1, fp(1), 1).unwrap();
        settle_reservation(1, ReservationStatus::Failed);
        reserve_withdrawal(2, fp(2), 1).unwrap();
        settle_reservation(2, ReservationStatus::OutcomeUnknown);
        reserve_withdrawal(3, fp(3), 1).unwrap();
        claim_execution(3);
        sweep_reserved_reservations_on_upgrade();
        INFLIGHT_RESERVATIONS.with(|m| {
            let map = m.borrow();
            assert_eq!(map.len(), 3, "no path may remove a reservation record");
            for id in [1u64, 2, 3] {
                assert!(map.get(&id).is_some(), "record {id} must be permanent");
            }
        });
    }

    #[test]
    fn f1_fingerprint_conflict_on_same_id_fails_closed() {
        let p_a = test_proposal(12, 100);
        let mut p_b = test_proposal(12, 100);
        p_b.amount = 101; // same id, different disbursement args
        reserve_withdrawal(12, args_fingerprint(&p_a), 1).unwrap();
        settle_reservation(12, ReservationStatus::Failed);
        let err = reserve_withdrawal(12, args_fingerprint(&p_b), 2).unwrap_err();
        assert!(err.contains("fingerprint conflict"), "got: {err}");
        // Original record untouched.
        assert_eq!(reservation_of(12).unwrap().args_fingerprint, args_fingerprint(&p_a));
    }

    #[test]
    fn f1_fingerprint_is_deterministic_and_args_sensitive() {
        let base = test_proposal(13, 100);
        assert_eq!(args_fingerprint(&base), args_fingerprint(&base));
        for mutated in [
            { let mut p = base.clone(); p.amount = 101; p },
            { let mut p = base.clone(); p.recipient = Principal::from_slice(&[9]); p },
            { let mut p = base.clone(); p.subaccount_name = "insurance".to_string(); p },
            { let mut p = base.clone(); p.id = 14; p },
        ] {
            assert_ne!(args_fingerprint(&base), args_fingerprint(&mutated));
        }
    }

    #[test]
    fn f1_reservations_survive_stable_map_reinit() {
        // post_upgrade survival, host-side: a StableBTreeMap re-initialised
        // over the SAME memory (what a fresh Wasm's thread_local does after an
        // upgrade) reads back the exact record the old map wrote. Uses the
        // MemoryManager directly so the crate's own thread_local map (same
        // region) is not aliased mid-test.
        let mem = MEMORY_MANAGER.with(|m| m.borrow().get(MEM_INFLIGHT_WITHDRAWAL_RESERVATION));
        let fp = args_fingerprint(&test_proposal(21, 100));
        {
            let mut map: StableBTreeMap<u64, InflightWithdrawalReservation, Mem> =
                StableBTreeMap::init(mem);
            map.insert(21, InflightWithdrawalReservation {
                proposal_id: 21,
                args_fingerprint: fp,
                reserved_at_ns: 42,
                status: ReservationStatus::Executed,
                subaccount_name: Some("operations".to_string()),
                encumbered_total_debit: Some(100),
            });
        } // dropped — simulates the old Wasm's heap vanishing
        let mem2 = MEMORY_MANAGER.with(|m| m.borrow().get(MEM_INFLIGHT_WITHDRAWAL_RESERVATION));
        let map2: StableBTreeMap<u64, InflightWithdrawalReservation, Mem> =
            StableBTreeMap::init(mem2);
        let r = map2.get(&21).expect("reservation must survive re-init (upgrade)");
        assert_eq!(r.args_fingerprint, fp);
        assert_eq!(r.reserved_at_ns, 42);
        assert_eq!(r.status, ReservationStatus::Executed);
    }

    // ── Lane L3a: get_canister_refs_readback fail-closed contract ────────────

    #[test]
    fn readback_fails_closed_on_uninitialised_sentinel() {
        // Fresh thread ⇒ CANISTER_REFS holds the sentinel (never init'd).
        // The read-back must surface None (the query traps on it) — never a
        // default, never a partial value.
        assert_eq!(read_canister_refs(), None);
    }

    #[test]
    fn readback_fails_closed_on_corrupt_layout() {
        // Anything that is not exactly the versioned layout decodes to the
        // sentinel (eager-cell contract) — this is the decode the read-back
        // relies on, so corrupt bytes must yield None, not garbage principals.
        for garbage in [
            vec![0xAA; 7],
            vec![0x00; 91],          // right length, wrong version/magic
            vec![0xFF; 91],          // sentinel itself
            vec![0x01, 0x02],
        ] {
            let decoded = PrincipalRefs::<3>::from_bytes(Cow::Owned(garbage));
            assert!(decoded.get().is_none(), "corrupt layout must decode to sentinel");
            assert!(decoded.is_sentinel());
        }
    }

    #[test]
    fn readback_returns_canonical_stored_values() {
        let refs: [Principal; 3] = [
            Principal::from_slice(&[10]),
            Principal::from_slice(&[20]),
            Principal::from_slice(&[30]),
        ];
        set_canister_refs(refs[0], refs[1], refs[2]);
        assert_eq!(read_canister_refs(), Some(refs));
    }


    //
    // Neither case below is reachable through the public interface — an
    // oversized word needs a corrupted stable region, and exhaustion needs 2^64
    // operations — so a native test is the only place the rule can be
    // exercised at all. The post_upgrade hooks and the allocators call exactly
    // these functions, so the trap sites inherit what is proved here.
    //
    // The pre-fix code narrowed with `as u64`, which is fail-OPEN: the first
    // assertion below is the regression, and it fails on that code.
    #[test]
    fn oversized_counter_words_are_rejected_not_truncated() {
        // The exact adversarial shape: a word whose low 64 bits look like a
        // perfectly ordinary counter. `as u64` yields 1 here — a plausible id
        // that would silently re-issue over stored records.
        let hostile = (1u128 << 64) | 1;
        assert_eq!(hostile as u64, 1, "this is what the fail-open narrowing produced");
        assert_eq!(
            decode_id_counter(hostile), None,
            "a word above u64::MAX must be REJECTED, never truncated to a usable id"
        );

        for w in [u64::MAX as u128 + 1, u128::MAX, 1u128 << 127] {
            assert_eq!(decode_id_counter(w), None, "word {w} must not narrow");
        }
    }

    #[test]
    fn zero_is_not_a_legal_id_counter() {
        // Both id counters are seeded at 1 and only increment, so a durable
        // zero means a wrapped or corrupt region. Resuming on it would hand out
        // id 1 again, on top of a stored record.
        assert_eq!(decode_id_counter(0), None, "zero must be rejected");
        assert_eq!(decode_id_counter(1), Some(1), "the seeded value must be accepted");
        assert_eq!(decode_id_counter(u64::MAX as u128), Some(u64::MAX), "the max u64 is legal");
    }

    #[test]
    fn counter_exhaustion_is_checked_not_wrapped() {
        assert_eq!(bump_counter(u64::MAX), None, "exhaustion must be caught, not wrapped to 0");
        assert_eq!(bump_counter(0), Some(1));
        assert_eq!(bump_counter(u64::MAX - 1), Some(u64::MAX), "the last legal step still works");
    }

    #[test]
    fn zero_is_a_legal_fee_log_index_but_oversized_is_not() {
        // Asymmetry with the id counters, and it is deliberate: a treasury that
        // has never received a fee split sits at index 0 legitimately.
        assert_eq!(decode_index_counter(0), Some(0), "an unused fee log is index 0");
        assert_eq!(decode_index_counter(7), Some(7));
        assert_eq!(
            decode_index_counter(u64::MAX as u128 + 1), None,
            "an oversized index must still be rejected, not truncated"
        );
    }

    // Under Option 2 only the three buckets the pool tracks are disbursable.
    #[test]
    fn test_reserve_bucket_for_maps_only_pool_reserves() {
        assert_eq!(reserve_bucket_for("operations"), Some(TreasuryReserveBucket::Operations));
        assert_eq!(reserve_bucket_for("insurance"), Some(TreasuryReserveBucket::Insurance));
        assert_eq!(reserve_bucket_for("staking_rewards"), Some(TreasuryReserveBucket::StakingRewards));
        // Named buckets with no pool reserve (and never funded by receive_fee_split):
        for name in ["audit", "bug_bounty", "liquidity", "community", "", "Operations"] {
            assert_eq!(reserve_bucket_for(name), None, "'{}' must not map to a pool reserve", name);
        }
    }

    // B4 — pool->treasury PoolError conformance guard (FALLBACK mechanism).
    //
    // The treasury mirror `PoolError` (above) must contain every variant the pool can emit
    // across the `treasury_disburse` reply — else a reply carrying a missing variant fails
    // Candid decode and the treasury never sees the real pool error.
    //
    // MECHANISM NOTE: the brief's PRIMARY guard (reference `shielded_pool::PoolError` as a
    // Rust type via an rlib dev-dep) is NOT usable here — `shielded_pool` and `treasury` are
    // both canister crates that macro-export `canister_init` / `canister_pre_upgrade` /
    // `canister_post_upgrade` / `canister_query.*`, so linking the pool's rlib into
    // treasury's test binary fails with duplicate-symbol link errors. Per the brief's
    // fallback: reference the pool's authoritative **`shielded_pool.did`** instead. This
    // guards against `.did` drift (slightly weaker than the Rust type — but the `.did` is
    // the client-facing contract and is currently complete), and both sides are still
    // derived dynamically — the pool set from the checked-in `.did`, the mirror set from its
    // own `CandidType` — never a hand-copied variant list.
    //
    // Decode succeeds when the value's type is a subtype of the reader's; for variants that
    // means every pool case must be present in the treasury mirror. So: assert
    // pool-`.did` variant names ⊆ treasury-mirror variant names.
    #[test]
    fn test_treasury_poolerror_mirror_covers_pool_did() {
        use candid::types::{Label, TypeInner};
        use candid::CandidType;
        use std::collections::BTreeSet;

        // ── Mirror side: variant labels from the in-crate PoolError's own Candid type. ──
        let mirror_ty = <PoolError as CandidType>::ty();
        let mirror: BTreeSet<String> = match &*mirror_ty {
            TypeInner::Variant(fields) => fields
                .iter()
                .map(|f| match &*f.id {
                    Label::Named(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect(),
            other => panic!("treasury mirror PoolError must be a Candid variant, got {:?}", other),
        };

        // ── Pool side: variant labels parsed from the authoritative shielded_pool.did. ──
        let did = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../shielded-pool/shielded_pool.did"
        ));
        let pool = did_poolerror_variant_labels(did);

        // Sanity: the parse must have actually found the enum (a broken parser that returns
        // {} would vacuously pass the subset check below). Pin the newest variant + a floor.
        assert!(
            pool.contains("WithdrawalPayoutObligation") && pool.len() >= 60,
            "shielded_pool.did PoolError parse looks wrong: {} labels parsed",
            pool.len()
        );

        let missing: Vec<&String> = pool.difference(&mirror).collect();
        assert!(
            missing.is_empty(),
            "treasury PoolError mirror is missing pool PoolError variant(s) present in \
             shielded_pool.did — a treasury_disburse reply carrying one would fail Candid \
             decode. Add each (byte-identical payload) to the treasury mirror: {:?}",
            missing
        );
    }

    /// Extract the top-level variant labels of `type PoolError = variant { .. }` from a
    /// candid `.did` source. Brace-depth aware so nested `record { a; b }` payloads do not
    /// split as variants; strips `//` line comments.
    #[cfg(test)]
    fn did_poolerror_variant_labels(did: &str) -> std::collections::BTreeSet<String> {
        let start = did
            .find("type PoolError")
            .expect("`type PoolError` not found in shielded_pool.did");
        let brace_open = start
            + did[start..]
                .find('{')
                .expect("no opening brace for PoolError variant");

        // Collect the body between PoolError's outer braces (nested record braces kept).
        let mut depth: i32 = 0;
        let mut body = String::new();
        let mut closed = false;
        for c in did[brace_open..].chars() {
            match c {
                '{' => {
                    depth += 1;
                    if depth > 1 {
                        body.push(c);
                    }
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        closed = true;
                        break;
                    }
                    body.push(c);
                }
                _ => body.push(c),
            }
        }
        assert!(closed, "unterminated PoolError variant block in shielded_pool.did");

        // Strip // line comments.
        let cleaned: String = body
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Split entries at depth-0 ';' (nested record ';' are at depth >= 1).
        let mut labels = std::collections::BTreeSet::new();
        let mut depth: i32 = 0;
        let mut seg = String::new();
        for c in cleaned.chars() {
            match c {
                '{' => {
                    depth += 1;
                    seg.push(c);
                }
                '}' => {
                    depth -= 1;
                    seg.push(c);
                }
                ';' if depth == 0 => {
                    let name = seg.split(':').next().unwrap_or("").trim();
                    if !name.is_empty() {
                        labels.insert(name.to_string());
                    }
                    seg.clear();
                }
                _ => seg.push(c),
            }
        }
        labels
    }

    // ═════════════════════════════════════════════════════════════════════════
    // W2 2-6 — treasury debit exactness + bucket-level admission (SSA-S1S4-001)
    // ═════════════════════════════════════════════════════════════════════════
    //
    // Native coverage of the pieces that are pure state machines: the exact
    // debit, the shortfall counters and their saturate-and-flag contract, the
    // checked admission arithmetic, the legacy fail-closed blocker, and the
    // terminal `RetiredNotExecuted` rules. The cross-Wasm and pool-response
    // halves are in integration-tests/tests/w2_2_6_treasury_debit_exactness_tests.rs
    // — native durability is a KNOWN BLIND SPOT (thread-locals survive
    // in-process) and does not discharge the upgrade criteria.

    fn credit(name: &str, balance: u128) {
        SUBACCOUNTS.with(|s| {
            s.borrow_mut().insert(
                name.to_string(),
                SubaccountBalance { name: name.to_string(), balance },
            );
        });
    }

    fn balance_of(name: &str) -> u128 {
        SUBACCOUNTS.with(|s| s.borrow().get(&name.to_string()).map(|v| v.balance).unwrap_or(0))
    }

    fn shortfall_of(name: &str) -> BucketShortfall {
        BUCKET_SHORTFALLS.with(|b| b.borrow().get(&name.to_string()).unwrap_or_default())
    }

    fn integrity_of(name: &str) -> BucketIntegrity {
        get_treasury_admission_integrity()
            .into_iter()
            .find(|r| r.subaccount_name == name)
            .unwrap_or_else(|| panic!("no integrity row for bucket '{name}'"))
    }

    /// Stage a proposal so a reservation's bucket is derivable from the
    /// proposal map — which is exactly how the legacy blocker derives it.
    fn stage_proposal(id: u64, bucket: &str, amount: u128) {
        let mut p = test_proposal(id, amount);
        p.subaccount_name = bucket.to_string();
        PROPOSALS.with(|m| m.borrow_mut().insert(id, p));
    }

    fn stage_reservation(
        id: u64,
        status: ReservationStatus,
        bucket: Option<&str>,
        encumbered: Option<u128>,
    ) {
        INFLIGHT_RESERVATIONS.with(|m| {
            m.borrow_mut().insert(id, InflightWithdrawalReservation {
                proposal_id: id,
                args_fingerprint: 0,
                reserved_at_ns: 1,
                status,
                subaccount_name: bucket.map(|b| b.to_string()),
                encumbered_total_debit: encumbered,
            });
        });
    }

    // ── §2(1): exact debit + durable shortfall (acceptance 2) ────────────────

    #[test]
    fn w226_debit_is_exact_and_records_no_shortfall_within_balance() {
        credit("operations", 1_000);
        debit_subaccount("operations", 400);
        assert_eq!(balance_of("operations"), 600, "an in-range debit is applied exactly");
        assert_eq!(
            shortfall_of("operations"), BucketShortfall::default(),
            "no shortfall may be recorded when the balance covered the debit",
        );
    }

    #[test]
    fn w226_debit_beyond_balance_applies_the_remainder_and_records_the_shortfall() {
        // THE SSA-S1S4-001 SIGNATURE: at the pin this vanished silently via
        // `saturating_sub`. Now the balance still floors at zero (the pool has
        // already moved the funds; trapping here would lose more state), but
        // the missing amount is recorded durably instead of disappearing.
        credit("operations", 100);
        debit_subaccount("operations", 250);
        assert_eq!(balance_of("operations"), 0, "applied = min(balance, amount)");
        let sf = shortfall_of("operations");
        assert_eq!(sf.shortfall_total, 150, "shortfall = amount - applied");
        assert_eq!(sf.shortfall_events, 1);
        assert!(!sf.shortfall_overflowed, "an exact value must NOT carry the flag");

        // Cumulative across events, and reported by the integrity query.
        debit_subaccount("operations", 25);
        let sf = shortfall_of("operations");
        assert_eq!((sf.shortfall_total, sf.shortfall_events), (175, 2));
        let row = integrity_of("operations");
        assert_eq!((row.shortfall_total, row.shortfall_events), (175, 2));
        assert!(!row.shortfall_overflowed);
    }

    #[test]
    fn w226_debit_never_traps_and_ignores_unknown_buckets() {
        // Runs in the post-success segment: it must never trap, whatever it is
        // handed. An unknown bucket has no row to debit and records nothing —
        // unchanged from the pin.
        debit_subaccount("no-such-bucket", u128::MAX);
        assert_eq!(shortfall_of("no-such-bucket"), BucketShortfall::default());
        credit("operations", 0);
        debit_subaccount("operations", u128::MAX);
        assert_eq!(shortfall_of("operations").shortfall_total, u128::MAX);
    }

    // ── §2(7): counters saturate WITH a truthful flag (acceptance 10b/10c) ───

    #[test]
    fn w226_shortfall_total_saturates_and_sets_the_overflow_flag() {
        credit("insurance", 0);
        BUCKET_SHORTFALLS.with(|b| {
            b.borrow_mut().insert("insurance".to_string(), BucketShortfall {
                shortfall_total: u128::MAX - 5,
                shortfall_events: 3,
                shortfall_overflowed: false,
            });
        });
        debit_subaccount("insurance", 10);           // shortfall 10 > 5 headroom
        let sf = shortfall_of("insurance");
        assert_eq!(sf.shortfall_total, u128::MAX, "saturates, never wraps");
        assert_eq!(sf.shortfall_events, 4);
        assert!(
            sf.shortfall_overflowed,
            "a saturated total MUST set the flag: the value now means 'at least this much'",
        );
        assert!(integrity_of("insurance").shortfall_overflowed, "the query exposes the flag");
    }

    #[test]
    fn w226_shortfall_event_count_saturates_and_sets_the_overflow_flag() {
        credit("staking_rewards", 0);
        BUCKET_SHORTFALLS.with(|b| {
            b.borrow_mut().insert("staking_rewards".to_string(), BucketShortfall {
                shortfall_total: 0,
                shortfall_events: u64::MAX,
                shortfall_overflowed: false,
            });
        });
        debit_subaccount("staking_rewards", 7);
        let sf = shortfall_of("staking_rewards");
        assert_eq!(sf.shortfall_events, u64::MAX, "saturates, never wraps to 0");
        assert!(sf.shortfall_overflowed);
    }

    // ── §2(2): bucket-level admission (acceptance 1, native half) ────────────

    #[test]
    fn w226_admission_refuses_a_second_proposal_against_the_same_funds() {
        // The SSA-S1S4-001 schedule, at the admission-decision level: balance
        // covers P or Q alone, not both. P holds the encumbrance; Q is refused
        // while it is outstanding, and admitted once P settles.
        credit("operations", 1_000);
        stage_proposal(101, "operations", 600);
        stage_proposal(102, "operations", 600);
        stage_reservation(101, ReservationStatus::Reserved, Some("operations"), Some(600));
        stage_reservation(102, ReservationStatus::Reserved, None, None);

        let err = admit_and_encumber(102, "operations", 600, 1_000)
            .expect_err("Q must be refused while P's encumbrance is outstanding");
        assert!(err.starts_with("W226-BUCKET-ENCUMBERED:"), "got: {err}");
        assert_eq!(
            reservation_of(102).unwrap().encumbered_total_debit, None,
            "a refused admission must not encumber",
        );

        // P settles Failed → inactive → its encumbrance is released.
        settle_reservation(101, ReservationStatus::Failed);
        admit_and_encumber(102, "operations", 600, 1_000)
            .expect("Q must be admitted once P is settled");
        let q = reservation_of(102).unwrap();
        assert_eq!(q.encumbered_total_debit, Some(600));
        assert_eq!(q.subaccount_name.as_deref(), Some("operations"));
    }

    #[test]
    fn w226_encumbrance_is_bucket_scoped_and_excludes_self() {
        credit("operations", 1_000);
        // An active reservation on ANOTHER bucket must not encumber this one.
        stage_reservation(111, ReservationStatus::Reserved, Some("insurance"), Some(900));
        stage_reservation(112, ReservationStatus::Reserved, Some("operations"), Some(700));
        admit_and_encumber(112, "operations", 700, 1_000)
            .expect("a reservation must not be encumbered by itself, nor by other buckets");
        assert_eq!(integrity_of("insurance").encumbered_total, 900);
        assert_eq!(integrity_of("operations").encumbered_total, 700);
    }

    #[test]
    fn w226_only_active_statuses_encumber() {
        credit("operations", 1_000);
        stage_reservation(121, ReservationStatus::Executed, Some("operations"), Some(900));
        stage_reservation(122, ReservationStatus::Failed, Some("operations"), Some(900));
        stage_reservation(123, ReservationStatus::RetiredNotExecuted, Some("operations"), Some(900));
        stage_reservation(124, ReservationStatus::Reserved, None, None);
        stage_proposal(124, "operations", 800);

        admit_and_encumber(124, "operations", 800, 1_000).expect(
            "Executed / Failed / RetiredNotExecuted are terminal — they release the \
             encumbrance and must not block a later admission",
        );
        let row = integrity_of("operations");
        assert_eq!(row.encumbered_total, 800, "only the live reservation encumbers");
        assert_eq!(row.retired_count, 1, "the dead reservation is still reported");
        assert_eq!(row.legacy_active_count, 0);
    }

    #[test]
    fn w226_retrying_unknown_encumbers_exactly_like_reserved() {
        credit("operations", 1_000);
        stage_reservation(131, ReservationStatus::RetryingUnknown, Some("operations"), Some(600));
        stage_reservation(132, ReservationStatus::Reserved, None, None);
        stage_proposal(132, "operations", 600);
        let err = admit_and_encumber(132, "operations", 600, 1_000)
            .expect_err("a RetryingUnknown reservation is ACTIVE and must encumber");
        assert!(err.starts_with("W226-BUCKET-ENCUMBERED:"), "got: {err}");
    }

    #[test]
    fn w226_outcome_unknown_retains_its_encumbrance() {
        // The ruled asymmetry: OutcomeUnknown RETAINS (the pool may yet have
        // executed), so it keeps blocking conflicting admission.
        credit("operations", 1_000);
        stage_reservation(141, ReservationStatus::OutcomeUnknown, Some("operations"), Some(600));
        stage_reservation(142, ReservationStatus::Reserved, None, None);
        stage_proposal(142, "operations", 600);
        let err = admit_and_encumber(142, "operations", 600, 1_000)
            .expect_err("OutcomeUnknown must retain its encumbrance");
        assert!(err.starts_with("W226-BUCKET-ENCUMBERED:"), "got: {err}");
        assert_eq!(integrity_of("operations").encumbered_total, 600);
    }

    // ── §2(7): checked admission arithmetic (acceptance 10a) ─────────────────

    #[test]
    fn w226_admission_sum_overflow_refuses_and_never_wraps() {
        credit("operations", u128::MAX);
        stage_reservation(151, ReservationStatus::Reserved, Some("operations"), Some(u128::MAX));
        stage_reservation(152, ReservationStatus::Reserved, Some("operations"), Some(u128::MAX));
        stage_reservation(153, ReservationStatus::Reserved, None, None);
        stage_proposal(153, "operations", 1);

        let err = admit_and_encumber(153, "operations", 1, u128::MAX)
            .expect_err("a wrapped E[b] must never reach an admission decision");
        assert!(err.starts_with("W226-ADMISSION-OVERFLOW:"), "got: {err}");
        assert_eq!(reservation_of(153).unwrap().encumbered_total_debit, None);
    }

    #[test]
    fn w226_total_debit_plus_encumbrance_overflow_refuses() {
        credit("operations", u128::MAX);
        stage_reservation(161, ReservationStatus::Reserved, Some("operations"), Some(u128::MAX));
        stage_reservation(162, ReservationStatus::Reserved, None, None);
        stage_proposal(162, "operations", 5);
        let err = admit_and_encumber(162, "operations", 5, u128::MAX)
            .expect_err("total_debit + E[b] must be checked, not saturated");
        assert!(err.starts_with("W226-ADMISSION-OVERFLOW:"), "got: {err}");
    }

    // ── §2(5a): legacy fail-closed blocker (acceptance 8) ────────────────────

    #[test]
    fn w226_legacy_active_record_blocks_its_bucket_and_only_its_bucket() {
        credit("operations", 1_000_000);
        credit("insurance", 1_000_000);
        // A pre-W2-2-6 record: active, no recorded encumbrance. Its bucket is
        // derivable from the proposal map even though the record predates the
        // `subaccount_name` field.
        stage_proposal(171, "operations", 10);
        stage_reservation(171, ReservationStatus::Reserved, None, None);
        stage_reservation(172, ReservationStatus::Reserved, None, None);
        stage_proposal(172, "operations", 10);
        stage_reservation(173, ReservationStatus::Reserved, None, None);
        stage_proposal(173, "insurance", 10);

        let err = admit_and_encumber(172, "operations", 10, 1_000_000)
            .expect_err("a legacy active record must fail-close its bucket");
        assert!(err.starts_with("W226-LEGACY-BLOCKED:"), "got: {err}");
        assert!(err.contains("171"), "the refusal must name the blocking proposal id; got: {err}");
        // Both 171 and 172 are legacy-shaped active records on this bucket.
        // The QUERY is a global view and counts both; the ADMISSION scan
        // excludes the reservation being admitted, which is why 172's own
        // legacy shape does not block 172 — 171 does.
        assert_eq!(
            integrity_of("operations").legacy_active_count, 2,
            "the blocker is observable, not just enforced",
        );

        // A DIFFERENT bucket is unaffected — the blocker is bucket-scoped.
        admit_and_encumber(173, "insurance", 10, 1_000_000)
            .expect("a legacy record on 'operations' must not block 'insurance'");

        // Resolution through a defined transition unblocks the bucket. Decode
        // success alone never discharges this.
        settle_reservation(171, ReservationStatus::Failed);
        admit_and_encumber(172, "operations", 10, 1_000_000)
            .expect("once the legacy record resolves, admission proceeds");
    }

    #[test]
    fn w226_legacy_record_with_underivable_bucket_blocks_globally() {
        // Should be impossible (the proposal map holds every reservation's
        // bucket). If it happens anyway, fail closed EVERYWHERE rather than
        // computing an admission around a record whose bucket is unknown.
        credit("operations", 1_000_000);
        credit("insurance", 1_000_000);
        stage_reservation(181, ReservationStatus::OutcomeUnknown, None, None); // no proposal
        for bucket in ["operations", "insurance"] {
            let err = admit_and_encumber(999, bucket, 1, 1_000_000)
                .expect_err("an underivable legacy record must block globally");
            assert!(err.starts_with("W226-LEGACY-BLOCKED:"), "got: {err}");
        }
        assert!(
            integrity_of("operations").legacy_active_count >= 1
                && integrity_of("insurance").legacy_active_count >= 1,
            "a globally-blocking legacy record must be counted against every bucket",
        );
    }

    #[test]
    fn w226_inactive_legacy_record_does_not_block() {
        credit("operations", 1_000);
        stage_proposal(191, "operations", 10);
        stage_reservation(191, ReservationStatus::Failed, None, None);
        stage_reservation(192, ReservationStatus::Reserved, None, None);
        stage_proposal(192, "operations", 10);
        admit_and_encumber(192, "operations", 10, 1_000)
            .expect("only an ACTIVE legacy record blocks; a settled one is history");
        assert_eq!(integrity_of("operations").legacy_active_count, 0);
    }

    // ── §2(9g): terminal RetiredNotExecuted (acceptance 23, native half) ─────

    #[test]
    fn w226_retired_reservation_is_never_re_reservable() {
        stage_proposal(201, "operations", 10);
        stage_reservation(201, ReservationStatus::RetiredNotExecuted, Some("operations"), Some(10));
        let fp = reservation_of(201).unwrap().args_fingerprint;
        let err = reserve_withdrawal(201, fp, 9)
            .expect_err("RetiredNotExecuted is a dead end — never re-reserve it");
        assert!(err.starts_with("W226-RETIRED-NO-RERESERVE:"), "got: {err}");
        let r = reservation_of(201).unwrap();
        assert_eq!(r.status, ReservationStatus::RetiredNotExecuted, "no state mutation");
        assert_eq!(r.reserved_at_ns, 1, "not even the timestamp moves");
    }

    #[test]
    fn w226_retired_is_inactive_everywhere() {
        credit("operations", 1_000);
        stage_proposal(211, "operations", 900);
        stage_reservation(211, ReservationStatus::RetiredNotExecuted, Some("operations"), Some(900));

        assert!(!reservation_is_inflight(211), "a retired reservation must not block rejection");
        assert!(reservation_is_retired(211));
        let row = integrity_of("operations");
        assert_eq!(row.encumbered_total, 0, "zero encumbrance");
        assert_eq!(row.legacy_active_count, 0, "never counted as legacy active");
        assert_eq!(row.retired_count, 1, "surfaced so operators can reject and re-propose");

        // And it does not block a conflicting admission on its own bucket.
        stage_reservation(212, ReservationStatus::Reserved, None, None);
        stage_proposal(212, "operations", 900);
        admit_and_encumber(212, "operations", 900, 1_000)
            .expect("a retired reservation encumbers nothing");
    }

    #[test]
    fn w226_retired_is_not_swept_and_does_not_count_toward_the_scan_cap() {
        stage_reservation(221, ReservationStatus::RetiredNotExecuted, Some("operations"), Some(1));
        stage_reservation(222, ReservationStatus::Reserved, Some("operations"), Some(1));
        stage_reservation(223, ReservationStatus::RetryingUnknown, Some("operations"), Some(1));
        sweep_reserved_reservations_on_upgrade();
        assert_eq!(
            reservation_of(221).unwrap().status, ReservationStatus::RetiredNotExecuted,
            "terminal and inactive — preserved as-is, never folded to OutcomeUnknown",
        );
        assert_eq!(reservation_of(222).unwrap().status, ReservationStatus::OutcomeUnknown);
        assert_eq!(
            reservation_of(223).unwrap().status, ReservationStatus::OutcomeUnknown,
            "RetryingUnknown is swept exactly like Reserved",
        );
    }

    // ── §2(6a): rejection fails closed (acceptance 9, native half) ───────────

    #[test]
    fn w226_rejection_is_refused_for_every_active_status() {
        for (id, status) in [
            (231, ReservationStatus::Reserved),
            (232, ReservationStatus::OutcomeUnknown),
            (233, ReservationStatus::RetryingUnknown),
        ] {
            stage_reservation(id, status, Some("operations"), Some(1));
            assert!(
                reservation_is_inflight(id),
                "{status:?} is active: rejecting it would strand the encumbrance forever, \
                 because execute_withdrawal refuses a non-Pending proposal and the retry \
                 that could resolve the attempt becomes unreachable",
            );
        }
        for (id, status) in [
            (234, ReservationStatus::Failed),
            (235, ReservationStatus::Executed),
            (236, ReservationStatus::RetiredNotExecuted),
        ] {
            stage_reservation(id, status, Some("operations"), Some(1));
            assert!(!reservation_is_inflight(id), "{status:?} must not block rejection");
        }
    }

    // ── §2(5): migration — old records decode None/None (acceptance 4) ───────

    #[test]
    fn w226_pre_change_records_decode_with_none_fields() {
        // The #90 record-width pattern at the Candid layer: bytes written by
        // the PRE-W2-2-6 record shape decode into the widened struct with both
        // new fields `None` — and such a record is then LEGACY ACTIVE, not
        // zero-encumbrance.
        #[derive(CandidType, Serialize, Deserialize)]
        struct OldReservation {
            proposal_id:      u64,
            args_fingerprint: u64,
            reserved_at_ns:   u64,
            status:           ReservationStatus,
        }
        let old = OldReservation {
            proposal_id: 241,
            args_fingerprint: 77,
            reserved_at_ns: 5,
            status: ReservationStatus::OutcomeUnknown,
        };
        let bytes = candid::encode_one(&old).unwrap();
        let new: InflightWithdrawalReservation = candid::decode_one(&bytes)
            .expect("a pre-W2-2-6 record must still decode");
        assert_eq!(new.proposal_id, 241);
        assert_eq!(new.args_fingerprint, 77);
        assert_eq!(new.status, ReservationStatus::OutcomeUnknown);
        assert_eq!(new.subaccount_name, None);
        assert_eq!(new.encumbered_total_debit, None);
        assert!(new.status.is_active(), "and it is ACTIVE, so it fail-closes its bucket");
    }

    #[test]
    fn w226_integrity_query_reports_buckets_with_no_balance_row() {
        // A bucket can never hide from the query by lacking a balance row.
        stage_proposal(251, "audit", 1);
        stage_reservation(251, ReservationStatus::Reserved, Some("audit"), Some(42));
        assert_eq!(integrity_of("audit").encumbered_total, 42);
    }

}
