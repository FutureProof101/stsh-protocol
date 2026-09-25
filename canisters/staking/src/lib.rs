// =============================================================================
// STSH Staking Canister — Public Staking + Governance + Rewards
// Security classification: GOVERNANCE BOUNDARY
// =============================================================================
//
// RULES (non-negotiable per PM brief):
//   1. Staking rewards come ONLY from: staking_rewards_pool, protocol_fee_revenue,
//      or treasury-approved allocation.
//   2. This canister NEVER creates private notes, credits shielded balances,
//      or modifies pool escrow. It is entirely public.
//   3. Reward pool balance is publicly readable at all times.
//   4. Any displayed rate must disclose funding source.
//   5. VerifierKeyUpgrade proposals require: 14-day timelock + mandatory audit
//      artifact URL + audit hash + circuit source commit + verifier wasm hash.
//      Hard reject if any of these are empty.
//
// GOVERNANCE TIERS:
//   Ordinary proposal    → standard quorum + 7-day timelock
//   Treasury proposal    → higher quorum + 7-day timelock
//   VerifierKeyUpgrade   → highest quorum + 14-day timelock + mandatory audit fields
//
// CAPTURE RESISTANCE:
//   min_proposal_deposit, voting_delay, voting_period,
//   execution_timelock, quorum, approval_threshold — all configurable at init.
// =============================================================================

// Rider 1 (CTO ruling, upgrade-persistence hardening Phase 2): production
// builds of this crate must contain no `unsafe`. `cfg_attr(not(test), ...)`
// keeps the guard off the test cfg only; every shipped Wasm is compiled without
// `test` and therefore under `forbid`. Staking is unsafe-free today, so this is
// a no-op guard that turns a silent future regression into a build failure.
#![cfg_attr(not(test), forbid(unsafe_code))]

use candid::{CandidType, Principal};
use ic_cdk::api::time;
use ic_cdk_macros::{init, post_upgrade, query, update};
use stsh_eager_cell::{PrincipalRefs, Scalars};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    Cell, DefaultMemoryImpl, StableBTreeMap, Storable,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;

// ── Memory IDs ────────────────────────────────────────────────────────────────

const MEM_POSITIONS:  MemoryId = MemoryId::new(0);
const MEM_PROPOSALS:  MemoryId = MemoryId::new(1);
const MEM_VOTES:      MemoryId = MemoryId::new(2);
/// DEF-060: MemoryId 3 is reserved for REWARD_LOG. REWARD_LOG is not currently
/// instantiated — no stable map exists at this slot today. Future reward-log
/// implementation or formal retirement of this reservation requires a separate
/// PM decision. Do not reuse MemoryId 3 for anything else.
const MEM_REWARD_LOG: MemoryId = MemoryId::new(3);
// ── RETIRED, FROZEN FOREVER ──────────────────────────────────────────────────
//
// MemoryId 4 held the pre-hardening `STABLE_STATE` checkpoint cell (Candid
// `StakingStableState`, written by `pre_upgrade`). Retired by
// upgrade-persistence hardening Phase 2 (2026-07-31) and NEVER recycled:
// `ic-stable-structures` would silently hand a new structure the decommissioned
// region's bytes, reinterpreting a dead checkpoint as live state of a different
// type — a durable corruption with no runtime error to catch. Registered as
// `retired` + frozen in docs/MEMORY_ID_REGISTRY.md; the gate lint enforces it.
//
// const MEM_STABLE_STATE: MemoryId = MemoryId::new(4);   // RETIRED — do not reuse
const MEM_PENDING_POSITIONS: MemoryId = MemoryId::new(5);
/// DEF-059: stable cell for VotingWeightState (initialized flag + total).
/// MemoryId(3) is left reserved/unused (MEM_REWARD_LOG declared but never
/// instantiated), so the next free id is 6.
const MEM_VOTING_WEIGHT: MemoryId = MemoryId::new(6);
/// DEF-052: pending lock/unlock operations awaiting reconcile, keyed by op_id.
const MEM_PENDING_LOCK_OPS: MemoryId = MemoryId::new(7);
/// DEF-052: monotonic operation-id counter (StableCell<u64>).
const MEM_OP_ID_COUNTER: MemoryId = MemoryId::new(8);
/// C-A1: per-proposal eligibility snapshot, keyed (proposal_id, position_id).
const MEM_PROPOSAL_SNAPSHOTS: MemoryId = MemoryId::new(9);
/// C-A5: stake-ingress dedup records, keyed (caller, caller-supplied key).
const MEM_STAKE_DEDUP: MemoryId = MemoryId::new(10);

// ── Phase 2 eager cells (upgrade-persistence hardening, 2026-07-31) ──────────
//
// Each former-checkpoint field group gets a FRESH id — the registry rule is
// append-only per canister and a retired id is never recycled.

/// EAGER cell — token/pool/treasury refs, GROUPED (set together in `init`).
const MEM_CANISTER_REFS: MemoryId = MemoryId::new(11);
/// EAGER cell — `next_position_id`. Separate from the proposal counter: the two
/// are mutated by different operations at wildly different frequencies (staking
/// vs governance), and `Cell::set` rewrites the whole cell.
const MEM_NEXT_POSITION_ID: MemoryId = MemoryId::new(12);
/// EAGER cell — `next_proposal_id`.
const MEM_NEXT_PROPOSAL_ID: MemoryId = MemoryId::new(13);
/// EAGER cell — the nine `GovernanceParams` scalars, GROUPED: they are only
/// ever written as a whole validated set (`init`, `GovernanceParamUpdate`), and
/// a half-applied parameter set is exactly what one `Cell::set` makes
/// unrepresentable.
const MEM_GOV_PARAMS: MemoryId = MemoryId::new(14);
/// EAGER cell — the five `RewardState` scalars, GROUPED for the same reason:
/// they are one accounting record with a joint invariant.
const MEM_REWARD_STATE: MemoryId = MemoryId::new(15);

/// Grouped canister-reference cell: token, pool, treasury.
type CanisterRefsCell = PrincipalRefs<3>;
/// A single eager u64 counter, widened to the shared `Scalars` word.
type CounterCell = Scalars<1>;
/// The nine `GovernanceParams` scalars, in declaration order.
type GovParamsCell = Scalars<9>;
/// The five `RewardState` scalars, in declaration order.
type RewardStateCell = Scalars<5>;

type Mem = VirtualMemory<DefaultMemoryImpl>;

// ── Lock bounds (P-STK C-A2; Owner ruling 2026-07-28) ────────────────────────
//
// MIN = 30 days, MAX = 1095 days (3x365). Exactly 30 and exactly 1095 MUST be
// accepted; 0, 29 and 1096 MUST be rejected. The ns values are the ruled
// literals — `validate()` re-asserts them so a typo in either form fails the
// gate rather than silently widening the window.
//
// The MAX duration alone fits u64 comfortably; the overflow risk is at the SUM
// (`lock_start + duration`), which is why `stake` uses `checked_add` on the sum
// rather than trusting the bound.
pub const MIN_LOCK_DAYS: u32 = 30;
pub const MAX_LOCK_DAYS: u32 = 1095;
pub const MIN_LOCK_DURATION_NS: u64 = 2_592_000_000_000_000;      // 30 days
pub const MAX_LOCK_DURATION_NS: u64 = 94_608_000_000_000_000;     // 1095 days
const DAY_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

// ── Stake positions ───────────────────────────────────────────────────────────

/// Lock-period multipliers (basis points, 10000 = 1x)
/// Longer locks earn proportionally more voting weight and rewards
pub fn lock_multiplier_bps(lock_days: u32) -> u32 {
    match lock_days {
        0..=30    => 10000,  // 1.0x
        31..=90   => 12500,  // 1.25x
        91..=180  => 15000,  // 1.5x
        181..=365 => 20000,  // 2.0x
        _         => 25000,  // 2.5x — max for 1y+
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct StakePosition {
    pub position_id:       u64,
    pub holder:            Principal,
    pub amount:            u128,
    pub lock_days:         u32,
    pub lock_end_ns:       u64,
    /// voting_weight = amount * lock_multiplier_bps / 10000
    pub voting_weight:     u128,
    pub rewards_claimed:   u128,
    pub last_claim_ns:     u64,
    pub created_at_ns:     u64,
    pub closed:            bool,
    /// DEF-052: the op_id of an in-flight lock/unlock operation on this position,
    /// if any. `Some` only while the position is in LockPending / UnlockPending
    /// awaiting reconcile; `None` for active/closed positions. Option<u64> so
    /// legacy records (pre-DEF-052, Candid-encoded without this field) decode as
    /// None (proven by the old-layout decode test in `mod tests`).
    #[serde(default)]
    pub op_id:             Option<u64>,
}

impl StakePosition {
    pub fn is_unlockable(&self) -> bool {
        !self.closed && time() >= self.lock_end_ns
    }
}

impl Storable for StakePosition {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum PendingStakeState {
    LockPending,
    UnlockPending,
}

impl Storable for PendingStakeState {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

fn pending_stake_state(position_id: u64) -> Option<PendingStakeState> {
    PENDING_POSITIONS.with(|p| p.borrow().get(&position_id))
}

fn is_active_position(position: &StakePosition) -> bool {
    !position.closed && pending_stake_state(position.position_id).is_none()
}

// ── DEF-052: lock/unlock operation reconcile ────────────────────────────────────
//
// lock_for_staking / unlock_from_staking are cumulative, non-idempotent token
// calls. On a transport-unknown outcome the operation is recorded as a PendingLockOp
// (keyed by a unique op_id) BEFORE the call, together with the exact pre-operation
// position snapshot, so a controller can later assert whether the token side
// executed and the staking-side state is reconciled deterministically — never by a
// blind retry (which could double-lock or double-unlock).

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum LockOpType { Lock, Unlock }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockDecision { Executed, NotExecuted }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingLockOp {
    op_id:           u64,
    position_id:     u64,
    holder:          Principal,
    amount:          u128,
    op_type:         LockOpType,
    initiated_at_ns: u64,
    /// Complete pre-operation position state to promote (Lock/Executed) or restore
    /// (Unlock/NotExecuted) exactly. For a Lock op this is the INTENDED active
    /// position (full voting_weight, op_id None); for an Unlock op this is the
    /// position exactly as it was before the unlock attempt (active, full weight).
    snapshot:        StakePosition,
    /// C-A5 / P1-2: the caller-supplied dedup key this Lock op was created
    /// under, so a RESOLVED-NotExecuted reconcile can release it. Without it,
    /// reconciliation deletes the position but strands the dedup record, and an
    /// identical retry then returns `Ok(position_id)` for a position that no
    /// longer exists with no tokens locked — a phantom success.
    ///
    /// `Option` for the same legacy-decode reason as `StakePosition::op_id`;
    /// `None` on an Unlock op (which never creates a dedup record) and on any
    /// pre-P1-2 record.
    #[serde(default)]
    dedup_key:       Option<Vec<u8>>,
}

impl Storable for PendingLockOp {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

// ── Governance parameters ─────────────────────────────────────────────────────

// DEF-068: governance timelock policy constants — single source of truth.
// The GovernanceParams launch defaults AND the independent validation floors
// (VerifierKeyUpgradePayload::validate, the GovernanceParamUpdate execution
// arm) must reference these; never re-derive them inline — repeated literals
// were the DEF-068 silent-drift finding. The #[cfg(test)] boundary tests
// deliberately keep the 14-day floor as an independent literal so a value
// change here fails those tests instead of drifting silently. Values are
// unchanged from the pre-DEF-068 inline literals.
const STAKING_VOTING_DELAY_NS: u64       = 24 * 60 * 60 * 1_000_000_000;      // 1 day
const STAKING_VOTING_PERIOD_NS: u64      = 7 * 24 * 60 * 60 * 1_000_000_000;  // 7 days
const STAKING_EXECUTION_TIMELOCK_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;  // 7 days
const VK_UPGRADE_MIN_TIMELOCK_NS: u64    = 14 * 24 * 60 * 60 * 1_000_000_000; // 14 days
/// VK old-key grace window: how long the pool accepts BOTH keys after a
/// scheduled VK activation (old_key_cutoff_ns = activation + this). A DISTINCT
/// policy value from STAKING_EXECUTION_TIMELOCK_NS — the 7-day equality is
/// coincidental; do not merge the two constants (that coupling would silently
/// change the grace window if the execution timelock is ever tuned).
const VK_OLD_KEY_GRACE_NS: u64           = 7 * 24 * 60 * 60 * 1_000_000_000;  // 7 days

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct GovernanceParams {
    /// Minimum STSH (base units) staked to create a proposal
    pub min_proposal_deposit: u128,
    /// Delay between proposal creation and voting start (ns)
    pub voting_delay_ns: u64,
    /// Duration of voting period (ns)
    pub voting_period_ns: u64,
    /// Standard execution timelock (ns) — 7 days
    pub execution_timelock_ns: u64,
    /// VerifierKeyUpgrade timelock (ns) — 14 days minimum
    pub vk_upgrade_timelock_ns: u64,
    /// Minimum total voting weight that must vote (basis points of total)
    pub quorum_bps: u32,
    /// Higher quorum for treasury proposals
    pub treasury_quorum_bps: u32,
    /// Highest quorum for VerifierKeyUpgrade proposals
    pub vk_quorum_bps: u32,
    /// Fraction of votes that must approve (basis points — e.g. 5000 = 50%)
    pub approval_threshold_bps: u32,
}

impl GovernanceParams {
    /// K3-015 — the exhaustive nine-point contract.
    ///
    /// Runs at THREE points, not one: `init`, proposal submission, and
    /// immediately before any parameter update is applied. A param set that is
    /// only checked at init can still be replaced by a governance proposal with
    /// values that were never validated, which is the gap this closes.
    ///
    /// Every rejection names the field and the bound, because a governance
    /// param rejection surfaces to a human deciding whether their proposal is
    /// malformed or the policy floor moved.
    pub fn validate(&self) -> Result<(), String> {
        // (1) A zero deposit makes proposal creation free — spam floor gone.
        if self.min_proposal_deposit == 0 {
            return Err("min_proposal_deposit must be > 0".to_string());
        }
        // (2) A zero voting period closes voting in the same instant it opens.
        if self.voting_period_ns == 0 {
            return Err("voting_period_ns must be > 0".to_string());
        }
        // (3) Every proposal timestamp addition must be CHECKED. create_proposal
        //     computes now + delay + period + timelock; if the params alone
        //     cannot be summed without wrapping, no `now` can make it safe.
        let staged = self
            .voting_delay_ns
            .checked_add(self.voting_period_ns)
            .and_then(|v| v.checked_add(self.execution_timelock_ns))
            .and_then(|v| v.checked_add(self.vk_upgrade_timelock_ns));
        if staged.is_none() {
            return Err(
                "proposal timestamp arithmetic overflows u64 \
                 (voting_delay + voting_period + execution_timelock + vk_upgrade_timelock)"
                    .to_string(),
            );
        }
        // (4) Execution timelock policy floor.
        if self.execution_timelock_ns < STAKING_EXECUTION_TIMELOCK_NS {
            return Err(format!(
                "execution_timelock_ns {} is below the policy floor {}",
                self.execution_timelock_ns, STAKING_EXECUTION_TIMELOCK_NS
            ));
        }
        // (5) VK-upgrade timelock >= 14 days. The supply-boundary lesson: a key
        //     swap must never be executable faster than the community can react.
        if self.vk_upgrade_timelock_ns < VK_UPGRADE_MIN_TIMELOCK_NS {
            return Err(format!(
                "vk_upgrade_timelock_ns {} is below the 14-day minimum {}",
                self.vk_upgrade_timelock_ns, VK_UPGRADE_MIN_TIMELOCK_NS
            ));
        }
        // (6) Every quorum and approval value in 1..=10_000 bps. Zero would
        //     mean "no quorum required"; >10_000 is unreachable by construction
        //     and would deadlock governance permanently.
        for (name, bps) in [
            ("quorum_bps", self.quorum_bps),
            ("treasury_quorum_bps", self.treasury_quorum_bps),
            ("vk_quorum_bps", self.vk_quorum_bps),
            ("approval_threshold_bps", self.approval_threshold_bps),
        ] {
            if !(1..=10_000).contains(&bps) {
                return Err(format!("{name} must be within 1..=10000 bps, got {bps}"));
            }
        }
        // (7) Tier ordering: ordinary <= treasury <= VK. An inverted tier would
        //     let the highest-stakes proposal class pass on the lowest bar.
        if self.quorum_bps > self.treasury_quorum_bps {
            return Err(format!(
                "tier ordering violated: quorum_bps {} > treasury_quorum_bps {}",
                self.quorum_bps, self.treasury_quorum_bps
            ));
        }
        if self.treasury_quorum_bps > self.vk_quorum_bps {
            return Err(format!(
                "tier ordering violated: treasury_quorum_bps {} > vk_quorum_bps {}",
                self.treasury_quorum_bps, self.vk_quorum_bps
            ));
        }
        // (8) Lock bounds are EXACTLY the ruled values, in both day and ns form.
        //     Validated here rather than left to the constants alone so that a
        //     typo in either representation fails loudly at init instead of
        //     silently widening or narrowing the accepted window.
        if MIN_LOCK_DAYS != 30 || MAX_LOCK_DAYS != 1095 {
            return Err(format!(
                "lock bounds must be exactly 30 and 1095 days, found {MIN_LOCK_DAYS} and {MAX_LOCK_DAYS}"
            ));
        }
        if MIN_LOCK_DURATION_NS != MIN_LOCK_DAYS as u64 * DAY_NS
            || MAX_LOCK_DURATION_NS != MAX_LOCK_DAYS as u64 * DAY_NS
        {
            return Err("lock bound ns constants disagree with their day constants".to_string());
        }
        // (9) MIN <= MAX.
        if MIN_LOCK_DURATION_NS > MAX_LOCK_DURATION_NS {
            return Err("lock bounds inverted: MIN > MAX".to_string());
        }
        Ok(())
    }
}

impl Default for GovernanceParams {
    fn default() -> Self {
        GovernanceParams {
            min_proposal_deposit: 1_000 * 100_000_000, // 1000 STSH
            voting_delay_ns:      STAKING_VOTING_DELAY_NS,
            voting_period_ns:     STAKING_VOTING_PERIOD_NS,
            execution_timelock_ns: STAKING_EXECUTION_TIMELOCK_NS,
            vk_upgrade_timelock_ns: VK_UPGRADE_MIN_TIMELOCK_NS,
            quorum_bps:           1000, // 10% of total voting weight
            treasury_quorum_bps:  2000, // 20%
            vk_quorum_bps:        3000, // 30% — highest bar
            approval_threshold_bps: 5001, // simple majority + 1
        }
    }
}

// ── Proposal types ────────────────────────────────────────────────────────────

/// VerifierKeyUpgrade payload — all required fields.
/// Hard reject if any are empty. This is the supply-boundary lesson in code.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct VerifierKeyUpgradePayload {
    pub old_verifying_key_hash:  [u8; 32],
    pub new_verifying_key_hash:  [u8; 32],
    pub circuit_version:         u32,
    pub proof_system_id:         String,
    /// URL to the published audit report — REQUIRED, not optional
    pub audit_artifact_url:      String,
    /// SHA-256 of the audit report document — REQUIRED
    pub audit_artifact_hash:     [u8; 32],
    /// Git commit hash of the circuit source — REQUIRED
    pub circuit_source_commit:   String,
    /// SHA-256 of the compiled verifier Wasm — REQUIRED
    pub verifier_wasm_hash:      [u8; 32],
    /// When the new key becomes active (ns timestamp) — REQUIRED, must be in future
    pub activation_timestamp_ns: u64,
    /// Whether emergency disable is supported for this version
    pub emergency_disable_supported: bool,
}

impl VerifierKeyUpgradePayload {
    /// Structural validation — checks all required fields are non-empty/non-zero.
    /// Does NOT check timing (activation date). Use this at execution time.
    ///
    /// P3 FIX: `execute_proposal_action` must call `validate_structural()`, not
    /// `validate()`. At execution time the activation date is likely within 14 days
    /// of now (it was set at creation and time has passed), so re-running the
    /// 14-day check would make every valid VK proposal unexecutable.
    pub fn validate_structural(&self) -> Result<(), String> {
        if self.audit_artifact_url.is_empty() {
            return Err("audit_artifact_url is required for VerifierKeyUpgrade".to_string());
        }
        if self.audit_artifact_hash == [0u8; 32] {
            return Err("audit_artifact_hash is required (all-zeros rejected)".to_string());
        }
        if self.circuit_source_commit.is_empty() {
            return Err("circuit_source_commit is required".to_string());
        }
        if self.verifier_wasm_hash == [0u8; 32] {
            return Err("verifier_wasm_hash is required (all-zeros rejected)".to_string());
        }
        if self.activation_timestamp_ns == 0 {
            return Err("activation_timestamp_ns is required".to_string());
        }
        if self.old_verifying_key_hash == [0u8; 32] {
            return Err("old_verifying_key_hash is required (all-zeros rejected — supply the currently active VK hash)".to_string());
        }
        if self.new_verifying_key_hash == [0u8; 32] {
            return Err("new_verifying_key_hash is required (all-zeros rejected)".to_string());
        }
        if self.proof_system_id.is_empty() {
            return Err("proof_system_id is required".to_string());
        }
        Ok(())
    }

    /// Full creation-time validation — structural checks PLUS 14-day activation window.
    /// Call this when a proposal is first submitted, not at execution.
    /// Calls validate_at(time()) — use validate_at() directly in tests.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_at(time())
    }

    /// Testable creation-time validation with explicit timestamp.
    /// Core logic for tests 11/12/13.
    pub fn validate_at(&self, now_ns: u64) -> Result<(), String> {
        // Structural checks first
        self.validate_structural()?;
        // Enforce 14-day minimum — must be at least 14 days from now at creation time
        let min_activation_ns = now_ns + VK_UPGRADE_MIN_TIMELOCK_NS;
        if self.activation_timestamp_ns < min_activation_ns {
            return Err("activation_timestamp_ns must be at least 14 days in the future".to_string());
        }
        Ok(())
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum ProposalType {
    /// Standard parameter change
    ParameterUpdate { key: String, value: String },
    /// Treasury spending — higher quorum required
    TreasurySpend { subaccount: String, recipient: Principal, amount: u128, reason: String },
    /// Fee schedule update
    FeeUpdate { shield_bps: u32, transfer_bps: u32, unshield_bps: u32 },
    /// Reward schedule update
    RewardScheduleUpdate { new_emission_rate_per_day: u128 },
    /// Emergency pause (scoped — deposits/spends only, not withdrawals)
    EmergencyPause { target: EmergencyPauseTarget, reason: String },
    /// Verifier key upgrade — HIGHEST quorum + 14-day timelock + all fields required
    VerifierKeyUpgrade(VerifierKeyUpgradePayload),
    /// Canister upgrade
    CanisterUpgrade { canister_id: Principal, wasm_hash: [u8; 32], description: String },
    /// Governance parameter update
    GovernanceParamUpdate(GovernanceParams),
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum EmergencyPauseTarget {
    PoolDeposits,
    PoolSpends,
    Both,
}

impl ProposalType {
    /// Returns the quorum tier for this proposal type
    pub fn quorum_bps(&self, params: &GovernanceParams) -> u32 {
        match self {
            ProposalType::VerifierKeyUpgrade(_) => params.vk_quorum_bps,
            ProposalType::TreasurySpend { .. }  => params.treasury_quorum_bps,
            ProposalType::CanisterUpgrade { .. } => params.treasury_quorum_bps,
            _                                    => params.quorum_bps,
        }
    }

    /// Returns the execution timelock for this proposal type
    pub fn timelock_ns(&self, params: &GovernanceParams) -> u64 {
        match self {
            ProposalType::VerifierKeyUpgrade(_) => params.vk_upgrade_timelock_ns,
            _                                   => params.execution_timelock_ns,
        }
    }
}

// ── Proposal record ───────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ProposalStatus {
    VotingPending,   // within voting_delay
    VotingOpen,
    VotingClosed,
    Passed,
    /// DEF-055: execution is in flight. Set BEFORE the first await in
    /// execute_proposal and overwritten with Executed/Rejected when the action
    /// completes within the same message. A second concurrent execute_proposal
    /// call observes this and bails out, so the action runs at most once.
    Executing,
    Rejected,
    Executed,
    Expired,
    Cancelled,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Proposal {
    pub id:                u64,
    pub proposer:          Principal,
    pub proposal_type:     ProposalType,
    pub description:       String,
    pub status:            ProposalStatus,
    pub created_at_ns:     u64,
    pub voting_opens_ns:   u64,
    pub voting_closes_ns:  u64,
    pub execute_after_ns:  u64,
    pub votes_for:         u128,   // total voting weight in favour
    pub votes_against:     u128,
    /// C-A1: the quorum DENOMINATOR, summed from the same synchronous snapshot
    /// that produced the eligible numerator. `Option` so a pre-P-STK proposal
    /// record still decodes; `None` means "no snapshot exists", and
    /// `execute_proposal` FAILS CLOSED on it rather than treating a missing
    /// denominator as zero (which would make quorum trivially satisfiable).
    #[serde(default)]
    pub snapshot_total_weight: Option<u128>,
    pub executed_at_ns:    Option<u64>,
    pub execution_result:  Option<String>,
    /// W2 2-5R: the instant execution STARTED, written in the same await-free
    /// segment as the `Executing` status write so "status says executing" and
    /// "we know when" cannot diverge. `executed_at_ns` is written only AFTER
    /// the await, so it cannot express the age of an in-flight execution, and
    /// `now - execute_after_ns` is an UPPER bound on that age — a threshold
    /// test on it fires too early, which is the wrong direction for a
    /// fail-closed guardrail.
    ///
    /// `Option` + `#[serde(default)]` so a proposal record written before this
    /// lane still decodes; `None` on an `Executing` proposal is the legacy
    /// class handled by the lazy observation stamp in
    /// `reconcile_stuck_proposal` — never a permanent refusal.
    #[serde(default)]
    pub execution_started_at_ns: Option<u64>,
}

impl Storable for Proposal {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

// ── Vote record ───────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct VoteRecord {
    pub proposal_id:   u64,
    /// C-A1: votes are counted by STABLE position, not merely by Principal.
    /// `Option` for the same legacy-decode reason as `StakePosition::op_id`.
    #[serde(default)]
    pub position_id:   Option<u64>,
    pub voter:         Principal,
    pub approve:       bool,
    pub voting_weight: u128,
    pub voted_at_ns:   u64,
}

impl Storable for VoteRecord {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

// ── C-A1: per-proposal eligibility snapshot ──────────────────────────────────
//
// The pre-P-STK model recorded votes by (proposal_id, voter Principal) and read
// the voter's LIVE positions at vote time. Freezing only the denominator does
// not stop a position CREATED, TRANSFERRED or RE-STAKED after proposal creation
// from entering the numerator. The fix is a snapshot: eligibility and weight are
// fixed at proposal creation, keyed by the stable `position_id`.
//
// Scope note (spec): the banned behaviour is counting the same position twice
// WITHIN ONE proposal. Voting once on each of several concurrent proposals with
// the same stake is legitimate and is NOT blocked — a cross-proposal capital
// lock would be a separate governance-policy decision.

/// (proposal_id, position_id) — fixed 16 bytes, big-endian so the map orders by
/// proposal then position, making a proposal's entries one contiguous range.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SnapshotKey {
    proposal_id: u64,
    position_id: u64,
}

impl Storable for SnapshotKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut b = Vec::with_capacity(16);
        b.extend_from_slice(&self.proposal_id.to_be_bytes());
        b.extend_from_slice(&self.position_id.to_be_bytes());
        Cow::Owned(b)
    }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        let mut p = [0u8; 8];
        let mut q = [0u8; 8];
        p.copy_from_slice(&b[0..8]);
        q.copy_from_slice(&b[8..16]);
        SnapshotKey { proposal_id: u64::from_be_bytes(p), position_id: u64::from_be_bytes(q) }
    }
    const BOUND: Bound = Bound::Bounded { max_size: 16, is_fixed_size: true };
}

/// One eligible position, frozen at proposal creation.
///
/// `holder` is the owner AT SNAPSHOT. Only that principal may cast this
/// position's vote, so transferring the position afterwards cannot yield a
/// second counting of the same snapshotted weight.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct SnapshotEntry {
    holder: Principal,
    weight: u128,
}

impl Storable for SnapshotEntry {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

// ── C-A5: stake-ingress idempotency ──────────────────────────────────────────
//
// The dedup key is bound to BOTH the caller and the canonical request payload.
// A reuse of the key with different arguments is rejected outright (it is a
// client bug, and silently honouring it would let one key mask two different
// intents); an identical retry returns the ORIGINAL outcome — never a second
// position, never a double debit.

/// (caller, caller-supplied key). Length-prefixed so no (caller, key) pair can
/// alias another by concatenation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DedupKey(Vec<u8>);

impl DedupKey {
    fn new(caller: Principal, key: &[u8]) -> Self {
        let c = caller.as_slice();
        let mut b = Vec::with_capacity(1 + c.len() + key.len());
        b.push(c.len() as u8);
        b.extend_from_slice(c);
        b.extend_from_slice(key);
        DedupKey(b)
    }
}

impl Storable for DedupKey {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(self.0.clone()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { DedupKey(b.into_owned()) }
    const BOUND: Bound = Bound::Unbounded;
}

/// The canonical payload the key was first used with, plus the outcome.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct DedupRecord {
    /// Canonical request payload — compared field-exact on retry.
    amount: u128,
    lock_days: u32,
    /// The position the first call created. A retry resolves to this, so a
    /// duplicate can never mint a second position.
    position_id: u64,
    /// The lock op, for reconstructing the original in-flight error verbatim.
    op_id: u64,
}

impl Storable for DedupRecord {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

// ── Rewards ───────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct RewardState {
    /// Remaining fixed allocation for staking rewards
    pub rewards_pool_balance: u128,
    /// Rewards funded by protocol fee revenue (tracked separately per §4.2 rule 4)
    pub fee_revenue_balance: u128,
    /// Daily emission rate from fixed allocation
    pub emission_rate_per_day: u128,
    /// When rewards started
    pub rewards_start_ns: u64,
    /// Total rewards distributed to date
    pub total_distributed: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct RewardSourceBreakdown {
    pub incentive_allocation_pct: u32, // % from fixed allocation
    pub fee_revenue_pct: u32,          // % from protocol fees
    pub disclosure: String,            // human-readable — required for transparency
}

// ── DEF-059: stable voting-weight state ─────────────────────────────────────────
//
// TOTAL_VOTING_WEIGHT was previously heap-only and reconstructed O(n) from all
// stake positions in post_upgrade. It is now persisted in a stable Cell so that
// upgrades never re-scan positions. The heap RefCell (TOTAL_VOTING_WEIGHT) is kept
// as a fast in-memory mirror; every mutation funnels through the helpers
// (set/add/sub_total_voting_weight) which write BOTH the heap copy and this cell,
// so the cell is always equal to the sum of active positions' voting weight.
//
// `initialized` is an explicit one-time migration marker. It is NOT a zero
// sentinel: a valid live state can have total == 0 (all stakers unstaked) while
// historical positions still exist, so detecting migration via total == 0 would
// wrongly re-trigger the backfill and overwrite the correct zero. Only the
// pre-DEF-059 → DEF-059 upgrade sees initialized == false and backfills once.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VotingWeightState {
    initialized: bool,
    total:       u128,
}

impl Default for VotingWeightState {
    fn default() -> Self { VotingWeightState { initialized: false, total: 0 } }
}

impl Storable for VotingWeightState {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

// ── Phase 2: raw scalar encoding for the two grouped records ─────────────────
//
// The Encoding rule is normative: eager cells use a fixed raw-byte `Storable`,
// not Candid. (The two exact per-write figures this comment used to quote were
// produced by nothing in the tree and are DELETED rather than measured: staking
// is NOT INSTALLED at launch (D1, 2026-08-14), so measuring them would pin a
// cost no deployed canister pays. Lane R-11.)
//
// Both records are all-numeric, so neither needs a Candid escape hatch: they
// map exactly onto `Scalars<N>` words in DECLARATION ORDER. Narrower fields are
// widened on write and narrowed on read; a word that cannot narrow means the
// region is corrupt, and the decode fails CLOSED (`None`) rather than
// fabricating a governance parameter out of impossible bytes.
//
// Adding, removing or REORDERING a field here changes the durable layout and
// requires a layout-version migration — not a silent edit.

fn gov_params_to_cell(p: &GovernanceParams) -> GovParamsCell {
    GovParamsCell::new([
        p.min_proposal_deposit,
        p.voting_delay_ns as u128,
        p.voting_period_ns as u128,
        p.execution_timelock_ns as u128,
        p.vk_upgrade_timelock_ns as u128,
        p.quorum_bps as u128,
        p.treasury_quorum_bps as u128,
        p.vk_quorum_bps as u128,
        p.approval_threshold_bps as u128,
    ])
}

fn gov_params_from_cell(c: &GovParamsCell) -> Option<GovernanceParams> {
    let w = c.get()?;
    Some(GovernanceParams {
        min_proposal_deposit:  w[0],
        voting_delay_ns:       u64::try_from(w[1]).ok()?,
        voting_period_ns:      u64::try_from(w[2]).ok()?,
        execution_timelock_ns: u64::try_from(w[3]).ok()?,
        vk_upgrade_timelock_ns: u64::try_from(w[4]).ok()?,
        quorum_bps:            u32::try_from(w[5]).ok()?,
        treasury_quorum_bps:   u32::try_from(w[6]).ok()?,
        vk_quorum_bps:         u32::try_from(w[7]).ok()?,
        approval_threshold_bps: u32::try_from(w[8]).ok()?,
    })
}

// ── Counter narrowing — FAIL CLOSED (SSA P1, 2026-07-31) ────────────────────
//
// `Scalars` stores u128 words; every counter these canisters keep is a u64. A
// bare `as u64` narrowing is FAIL-OPEN: a structurally valid cell holding a
// word above `u64::MAX` would silently truncate to a plausible-looking id, and
// the canister would resume handing out ids that collide with stored records.
// Truncation is exactly the class of silent, durable corruption the sentinel
// exists to prevent, so the narrowing must trap instead.
//
// Kept as PURE functions returning `Option` so the rejection rule is unit-
// testable natively: neither case is reachable through the public interface
// (one needs a corrupted region, the other 2^64 operations), so a native test
// is the only place the rule can actually be exercised.

/// An id counter: must narrow to u64 AND be non-zero. Zero is not a legal
/// value for `next_position_id` / `next_proposal_id` — both are seeded at 1 and
/// only ever increment, so a durable zero means a wrapped or corrupt region,
/// and resuming on it would re-issue id 1 over a stored record.
fn decode_id_counter(word: u128) -> Option<u64> {
    match u64::try_from(word) {
        Ok(0) => None,
        Ok(v) => Some(v),
        Err(_) => None,
    }
}

/// One step of a monotonic counter. `checked_add` because wrapping at
/// exhaustion would restart the sequence at zero and enable id REUSE — the
/// same failure mode as recycling a MemoryId, and just as silent.
fn bump_counter(cur: u64) -> Option<u64> {
    cur.checked_add(1)
}

fn reward_state_to_cell(r: &RewardState) -> RewardStateCell {
    RewardStateCell::new([
        r.rewards_pool_balance,
        r.fee_revenue_balance,
        r.emission_rate_per_day,
        r.rewards_start_ns as u128,
        r.total_distributed,
    ])
}

fn reward_state_from_cell(c: &RewardStateCell) -> Option<RewardState> {
    let w = c.get()?;
    Some(RewardState {
        rewards_pool_balance:  w[0],
        fee_revenue_balance:   w[1],
        emission_rate_per_day: w[2],
        rewards_start_ns:      u64::try_from(w[3]).ok()?,
        total_distributed:     w[4],
    })
}

// ── State ─────────────────────────────────────────────────────────────────────

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static POSITIONS: RefCell<StableBTreeMap<u64, StakePosition, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_POSITIONS)))
    );
    static PENDING_POSITIONS: RefCell<StableBTreeMap<u64, PendingStakeState, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_PENDING_POSITIONS)))
    );
    static PROPOSALS_MAP: RefCell<StableBTreeMap<u64, Proposal, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_PROPOSALS)))
    );
    /// Key: proposal_id || voter_principal_bytes
    static VOTES: RefCell<StableBTreeMap<Vec<u8>, VoteRecord, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_VOTES)))
    );

    static TOKEN_CANISTER:   RefCell<Option<Principal>> = RefCell::new(None);
    static POOL_CANISTER:    RefCell<Option<Principal>> = RefCell::new(None);
    static TREASURY_CANISTER: RefCell<Option<Principal>> = RefCell::new(None);

    static GOV_PARAMS: RefCell<GovernanceParams> = RefCell::new(GovernanceParams::default());
    static REWARD_STATE: RefCell<RewardState> = RefCell::new(RewardState {
        rewards_pool_balance: 0,
        fee_revenue_balance: 0,
        emission_rate_per_day: 0,
        rewards_start_ns: 0,
        total_distributed: 0,
    });

    static TOTAL_VOTING_WEIGHT: RefCell<u128>  = RefCell::new(0);
    static NEXT_POSITION_ID:    RefCell<u64>   = RefCell::new(1);
    static NEXT_PROPOSAL_ID:    RefCell<u64>   = RefCell::new(1);

    // ── Phase 2 eager cells — the durable source of truth for every field the
    //    retired STABLE_STATE checkpoint used to carry. Each defaults to the
    //    impossible sentinel on a fresh region so an absent cell fails closed.

    static CANISTER_REFS: RefCell<Cell<CanisterRefsCell, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_CANISTER_REFS)),
            CanisterRefsCell::sentinel(),
        ).expect("CANISTER_REFS: Cell::init failed — stable memory corrupt")
    );

    static NEXT_POSITION_ID_CELL: RefCell<Cell<CounterCell, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_NEXT_POSITION_ID)),
            CounterCell::sentinel(),
        ).expect("NEXT_POSITION_ID_CELL: Cell::init failed — stable memory corrupt")
    );

    static NEXT_PROPOSAL_ID_CELL: RefCell<Cell<CounterCell, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_NEXT_PROPOSAL_ID)),
            CounterCell::sentinel(),
        ).expect("NEXT_PROPOSAL_ID_CELL: Cell::init failed — stable memory corrupt")
    );

    static GOV_PARAMS_CELL: RefCell<Cell<GovParamsCell, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_GOV_PARAMS)),
            GovParamsCell::sentinel(),
        ).expect("GOV_PARAMS_CELL: Cell::init failed — stable memory corrupt")
    );

    static REWARD_STATE_CELL: RefCell<Cell<RewardStateCell, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_REWARD_STATE)),
            RewardStateCell::sentinel(),
        ).expect("REWARD_STATE_CELL: Cell::init failed — stable memory corrupt")
    );

    /// DEF-059: durable source of truth for TOTAL_VOTING_WEIGHT. Defaults to
    /// { initialized: false, total: 0 } on a fresh memory region so that a
    /// pre-DEF-059 canister triggers exactly one backfill in post_upgrade.
    static VOTING_WEIGHT_CELL: RefCell<Cell<VotingWeightState, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_VOTING_WEIGHT)),
            VotingWeightState::default(),
        ).expect("VOTING_WEIGHT_CELL: Cell::init failed — stable memory corrupt")
    );

    /// DEF-052: pending lock/unlock operations awaiting controller reconcile.
    static PENDING_LOCK_OPS: RefCell<StableBTreeMap<u64, PendingLockOp, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_PENDING_LOCK_OPS)))
    );

    /// DEF-052: monotonic op_id counter. Defaults to 1 on a fresh region, so op_ids
    /// start at 1 (0 is never a valid op_id). Persists across upgrades.
    /// C-A1: (proposal_id, position_id) -> frozen eligibility entry.
    static PROPOSAL_SNAPSHOTS: RefCell<StableBTreeMap<SnapshotKey, SnapshotEntry, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_PROPOSAL_SNAPSHOTS)))
    );

    /// C-A5: (caller, dedup key) -> canonical payload + original outcome.
    static STAKE_DEDUP: RefCell<StableBTreeMap<DedupKey, DedupRecord, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_STAKE_DEDUP)))
    );

    static OP_ID_COUNTER: RefCell<Cell<u64, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_OP_ID_COUNTER)),
            1u64,
        ).expect("OP_ID_COUNTER: Cell::init failed — stable memory corrupt")
    );
}

// ── DEF-052: op-id allocation + controller gate ─────────────────────────────────

/// Allocate the next unique operation id and persist the incremented counter.
fn next_op_id() -> u64 {
    OP_ID_COUNTER.with(|c| {
        let cur = *c.borrow().get();
        c.borrow_mut()
            .set(cur.saturating_add(1))
            .expect("next_op_id: stable counter write failed");
        cur
    })
}

/// DEF-052: IC canister-controller gate for the reconcile operator endpoints.
/// Staking has no app-level stored-CONTROLLER model (unlike shielded-pool), so
/// this mirrors nullifier-registry's assert_ic_controller: it gates to the
/// canister's IC controllers. Returns Err (not trap) so reconcile endpoints can
/// report a clean typed rejection without mutating any state.
fn ensure_ic_controller() -> Result<(), String> {
    if ic_cdk::api::is_controller(&ic_cdk::caller()) {
        Ok(())
    } else {
        Err("caller is not an IC controller".to_string())
    }
}

// ── DEF-059: voting-weight mutation helpers ─────────────────────────────────────
//
// Every change to active voting weight MUST go through these so the heap mirror
// and the stable cell stay in lock-step. set_ writes both; add_/sub_ read the
// current heap value (kept in sync) and write both. saturating_* matches the
// prior inline semantics (weight is bounded by TOTAL_SUPPLY × max multiplier, so
// it never actually saturates; saturating only guarantees no wrap on an edge).
fn set_total_voting_weight(total: u128) {
    TOTAL_VOTING_WEIGHT.with(|w| *w.borrow_mut() = total);
    VOTING_WEIGHT_CELL.with(|c| {
        c.borrow_mut()
            .set(VotingWeightState { initialized: true, total })
            .expect("set_total_voting_weight: stable cell write failed");
    });
}

fn add_total_voting_weight(delta: u128) {
    let cur = TOTAL_VOTING_WEIGHT.with(|w| *w.borrow());
    set_total_voting_weight(cur.saturating_add(delta));
}

fn sub_total_voting_weight(delta: u128) {
    let cur = TOTAL_VOTING_WEIGHT.with(|w| *w.borrow());
    set_total_voting_weight(cur.saturating_sub(delta));
}

// ── Phase 2: eager write-through helpers ─────────────────────────────────────
//
// The DEF-059 / DEF-052 precedents above (`set_total_voting_weight`,
// `next_op_id`) are exactly the shape Phase 2 generalises: every former-
// checkpoint field now funnels through a helper that writes the stable cell
// FIRST and the heap mirror only on success. A failed stable write traps with
// the heap untouched, so the two can never disagree, and there is no window in
// which an upgrade loses a mutation the caller already observed.
//
// None of these `await`. Each is a single atomic message segment, so a DEFINITE
// local rejection (trap or early `Err`) rolls back the whole segment including
// the cell write — a half-written counter is not representable.

/// GROUPED: the three refs are set together (only in `init`) and are
/// meaningless individually, so ONE `Cell::set` makes a half-applied authority
/// record unrepresentable. Phase 0 measured a grouped two-field raw write at
/// 2 370 instructions against 4 119 for separate cells — grouping co-mutated
/// fields is cheaper as well as atomic.
fn set_canister_refs(token: Principal, pool: Principal, treasury: Principal) {
    CANISTER_REFS.with(|c| {
        c.borrow_mut()
            .set(CanisterRefsCell::new([token, pool, treasury]))
            .expect("set_canister_refs: stable cell write failed");
    });
    TOKEN_CANISTER.with(|t| *t.borrow_mut() = Some(token));
    POOL_CANISTER.with(|p| *p.borrow_mut() = Some(pool));
    TREASURY_CANISTER.with(|t| *t.borrow_mut() = Some(treasury));
}

/// GROUPED: `GovernanceParams` is written only as a whole VALIDATED set, and a
/// half-applied parameter set (say, a new quorum without its matching timelock)
/// is a governance hazard. One `Cell::set` removes the possibility.
fn set_gov_params(params: GovernanceParams) {
    GOV_PARAMS_CELL.with(|c| {
        c.borrow_mut()
            .set(gov_params_to_cell(&params))
            .expect("set_gov_params: stable cell write failed");
    });
    GOV_PARAMS.with(|g| *g.borrow_mut() = params);
}

/// GROUPED: `RewardState` is one accounting record with a joint invariant
/// (balances against total distributed). Splitting it across cells would allow
/// a durable state where a debit landed and its counterpart did not.
fn set_reward_state(state: RewardState) {
    REWARD_STATE_CELL.with(|c| {
        c.borrow_mut()
            .set(reward_state_to_cell(&state))
            .expect("set_reward_state: stable cell write failed");
    });
    REWARD_STATE.with(|r| *r.borrow_mut() = state);
}

/// Read-modify-write the reward record through the eager cell. The closure runs
/// against the heap mirror (which the helpers keep equal to the cell), and the
/// result is persisted as ONE write.
fn mutate_reward_state(f: impl FnOnce(&mut RewardState)) {
    let mut state = REWARD_STATE.with(|r| r.borrow().clone());
    f(&mut state);
    set_reward_state(state);
}

/// Allocate the next position id and persist the incremented counter.
///
/// SEMANTIC ORDERING: this sits at the DEF-052 write-before-call point that
/// already exists — `stake` claims the id (and the op id) BEFORE the
/// `lock_for_staking` call precisely so a transport-unknown outcome can be
/// reconciled rather than blindly retried. Persisting the counter here CLAIMS
/// the id with the same intent; nothing contingent on confirmed success (the
/// lock, the voting weight, the position promotion) is moved ahead of the await.
fn alloc_position_id() -> u64 {
    let id = NEXT_POSITION_ID.with(|n| *n.borrow());
    let next = bump_counter(id)
        .unwrap_or_else(|| ic_cdk::trap("alloc_position_id: position id space exhausted"));
    NEXT_POSITION_ID_CELL.with(|c| {
        c.borrow_mut()
            .set(CounterCell::new([next as u128]))
            .expect("alloc_position_id: stable cell write failed");
    });
    NEXT_POSITION_ID.with(|n| *n.borrow_mut() = next);
    id
}

/// Allocate the next proposal id and persist the incremented counter. The C-A1
/// snapshot and the proposal record are written in the SAME no-`await` segment,
/// so the id, the snapshot and the proposal are durable together or not at all.
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

/// Seed both id counters at their initial values. Called ONLY from `init`: the
/// sentinel must be replaced with real state at install time, or the first
/// upgrade of a never-mutated canister would trap on a surviving sentinel even
/// though the install was perfectly legitimate.
fn seed_counters() {
    NEXT_POSITION_ID_CELL.with(|c| {
        c.borrow_mut()
            .set(CounterCell::new([1]))
            .expect("seed_counters: NEXT_POSITION_ID_CELL write failed");
    });
    NEXT_PROPOSAL_ID_CELL.with(|c| {
        c.borrow_mut()
            .set(CounterCell::new([1]))
            .expect("seed_counters: NEXT_PROPOSAL_ID_CELL write failed");
    });
}

// ── Stable state snapshot ─────────────────────────────────────────────────────
//
// DEF-059: TOTAL_VOTING_WEIGHT is no longer recomputed in post_upgrade. It is
// persisted in its own VOTING_WEIGHT_CELL (MemoryId 6) and kept current inline on
// every weight-changing operation. It is therefore intentionally NOT part of
// StakingStableState. All other heap-only fields are serialised explicitly here.

// ── Init ──────────────────────────────────────────────────────────────────────

#[derive(CandidType, Deserialize)]
pub struct InitArgs {
    pub token_canister:    Principal,
    pub pool_canister:     Principal,
    pub treasury_canister: Principal,
    /// Initial rewards pool balance (from genesis allocation)
    pub initial_rewards_pool: u128,
    /// Initial emission rate (base STSH units per day)
    pub initial_emission_rate_per_day: u128,
    pub governance_params: Option<GovernanceParams>,
}

#[init]
fn init(args: InitArgs) {
    set_canister_refs(args.token_canister, args.pool_canister, args.treasury_canister);
    seed_counters();

    // K3-015 call site 1/3 — INIT. Trap rather than fall back to defaults: a
    // canister silently coming up on different parameters than the operator
    // asked for is worse than a failed install.
    //
    // Phase 2: the params are persisted eagerly EITHER WAY — the compiled
    // defaults are just as much live state as an operator-supplied set, and
    // leaving the cell on its sentinel would make the first upgrade of a
    // default-configured canister trap.
    let params = if let Some(params) = args.governance_params {
        if let Err(e) = params.validate() {
            ic_cdk::trap(&format!("init: invalid governance params — {e}"));
        }
        params
    } else {
        let defaults = GovernanceParams::default();
        if let Err(e) = defaults.validate() {
            // The compiled defaults must themselves satisfy the contract; if
            // they do not, every deployment is misconfigured and that must fail
            // loudly.
            ic_cdk::trap(&format!("init: compiled default governance params are invalid — {e}"));
        }
        defaults
    };
    set_gov_params(params);

    set_reward_state(RewardState {
        rewards_pool_balance: args.initial_rewards_pool,
        fee_revenue_balance: 0,
        emission_rate_per_day: args.initial_emission_rate_per_day,
        rewards_start_ns: time(),
        total_distributed: 0,
    });

    // DEF-059: a freshly-installed canister has no positions, so active voting
    // weight is authoritatively 0. Mark the cell initialized now so the first
    // upgrade of a canister deployed on DEF-059 code never runs the backfill scan.
    set_total_voting_weight(0);
}

// ── Staking ───────────────────────────────────────────────────────────────────

/// Create a stake position.
///
/// `dedup_key` (C-A5) is caller-supplied and bound to BOTH the caller and the
/// canonical payload `(amount, lock_days)`. An identical retry returns the
/// ORIGINAL outcome; the same key with different arguments is rejected.
#[update]
async fn stake(amount: u128, lock_days: u32, dedup_key: Vec<u8>) -> Result<u64, String> {
    let holder = ic_cdk::caller();

    // ── C-A2: reject at the ENTRY POINT, before any token call ─────────────
    //
    // Zero amount first: a zero stake would create a weightless position and a
    // no-op token lock, which is indistinguishable downstream from a real one.
    if amount == 0 {
        return Err("stake amount must be greater than zero".to_string());
    }
    // Duration bounds at BOTH edges. `checked_mul` because lock_days is
    // caller-supplied u32 and the ns product would otherwise wrap.
    let duration_ns = (lock_days as u64)
        .checked_mul(DAY_NS)
        .ok_or("lock duration overflow")?;
    if duration_ns < MIN_LOCK_DURATION_NS {
        return Err(format!(
            "lock_days {lock_days} is below the {MIN_LOCK_DAYS}-day minimum"
        ));
    }
    if duration_ns > MAX_LOCK_DURATION_NS {
        return Err(format!(
            "lock_days {lock_days} exceeds the {MAX_LOCK_DAYS}-day maximum"
        ));
    }

    if dedup_key.is_empty() {
        return Err("dedup_key must not be empty".to_string());
    }
    if dedup_key.len() > 64 {
        return Err("dedup_key must be at most 64 bytes".to_string());
    }

    // ── C-A5: resolve the dedup key BEFORE doing anything else ─────────────
    let ddk = DedupKey::new(holder, &dedup_key);
    if let Some(prior) = STAKE_DEDUP.with(|m| m.borrow().get(&ddk)) {
        // Field-exact payload comparison. Reusing a key with different
        // arguments is a client bug; honouring it would let one key stand for
        // two different intents.
        if prior.amount != amount || prior.lock_days != lock_days {
            return Err(format!(
                "dedup_key already used with different arguments \
                 (original amount={} lock_days={}, retry amount={amount} lock_days={lock_days})",
                prior.amount, prior.lock_days
            ));
        }
        // Identical retry — return the ORIGINAL outcome, never a second
        // position and never a second debit. A still-pending original replays
        // its in-flight error verbatim so the caller reconciles rather than
        // re-locking.
        //
        // P1-2 belt-and-braces: NEVER report success for a position that does
        // not exist. reconcile_lock(NotExecuted) releases the key, so this
        // should be unreachable — but if a record is ever stranded by another
        // path, treat it as stale, drop it, and fall through to a fresh stake
        // rather than returning a phantom position id.
        let prior_exists = POSITIONS.with(|p| p.borrow().contains_key(&prior.position_id));
        if prior_exists {
            return match pending_stake_state(prior.position_id) {
                Some(PendingStakeState::LockPending) => Err(format!(
                    "LockPending: lock_for_staking outcome unknown (op_id={}): duplicate \
                     request, original still awaiting reconcile",
                    prior.op_id
                )),
                _ => Ok(prior.position_id),
            };
        }
        STAKE_DEDUP.with(|m| m.borrow_mut().remove(&ddk));
    }

    let token = get_token()?;

    // Compute voting weight up-front (before locking) so an arithmetic overflow
    // aborts before any tokens are locked — never leaving locked tokens without
    // a matching position.
    let multiplier = lock_multiplier_bps(lock_days);
    let voting_weight = amount
        .checked_mul(multiplier as u128)
        .ok_or("voting weight overflow")?
        / 10000;

    // DEF-052 write-before-call. lock_for_staking is cumulative and NOT idempotent,
    // so the op + position are durably recorded BEFORE the token call. Order:
    //   0. finish ALL validation that can still return Err (see lock_end_ns below)
    //   1. allocate position_id + op_id
    //   2. write PendingLockOp (carrying the INTENDED active-position snapshot)
    //   3. write the position into POSITIONS in LockPending state (zero weight, op_id set)
    //   4. only then call lock_for_staking
    // On a confirmed outcome we finalize (Ok) or revert (definite inner Err) and
    // remove the pending op; on transport-unknown we leave the PendingLockOp +
    // LockPending position for reconcile_lock — never a blind retry (which could
    // double-lock). No voting weight is credited until the lock is confirmed.
    let now = time();
    // C-A2: the SUM is where the overflow lives — MAX duration alone fits u64
    // comfortably, but a lock_start near u64::MAX still wraps. Checked, not
    // bounded-and-trusted.
    //
    // ORDER IS LOAD-BEARING (SSA P1, 2026-07-31): this check runs BEFORE
    // `alloc_position_id` / `next_op_id`. Both of those write a stable cell
    // EAGERLY, and this rejection returns an ordinary `Err` rather than
    // trapping — so the message segment COMMITS. Allocating first would durably
    // consume a position id (and an op id) for an operation that was rejected,
    // which is exactly the partial-scalar case the Phase 2 atomicity criterion
    // forbids. Every remaining rejection in this function is upstream of here.
    let lock_end_ns = now
        .checked_add(duration_ns)
        .ok_or("lock_end_ns overflow: lock_start too close to u64::MAX")?;

    let position_id = alloc_position_id();
    let op_id = next_op_id();

    // The intended ACTIVE position (full weight, no in-flight op) — promoted on a
    // confirmed lock or by reconcile_lock(Executed).
    let active_position = StakePosition {
        position_id, holder, amount, lock_days, lock_end_ns,
        voting_weight,
        rewards_claimed: 0,
        last_claim_ns: now,
        created_at_ns: now,
        closed: false,
        op_id: None,
    };
    // The position actually held during the lock window: zero weight, op_id set.
    let pending_position = StakePosition {
        voting_weight: 0,
        op_id: Some(op_id),
        ..active_position.clone()
    };

    // C-A5: the dedup record lands BEFORE the token call, alongside the
    // PendingLockOp — so a retry that arrives while the first call is still
    // in flight resolves to the original position instead of starting a second.
    STAKE_DEDUP.with(|m| m.borrow_mut().insert(ddk.clone(), DedupRecord {
        amount, lock_days, position_id, op_id,
    }));
    PENDING_LOCK_OPS.with(|m| m.borrow_mut().insert(op_id, PendingLockOp {
        op_id, position_id, holder, amount,
        op_type: LockOpType::Lock, initiated_at_ns: now,
        snapshot: active_position.clone(),
        dedup_key: Some(dedup_key.clone()),
    }));
    POSITIONS.with(|p| p.borrow_mut().insert(position_id, pending_position));
    PENDING_POSITIONS.with(|p| p.borrow_mut().insert(position_id, PendingStakeState::LockPending));

    let lock_call: Result<(Result<(), String>,), _> = ic_cdk::api::call::call(
        token, "lock_for_staking", (holder, amount)
    ).await;

    match lock_call {
        Ok((Ok(()),)) => {
            // Confirmed lock — promote to the active position and credit weight.
            POSITIONS.with(|p| p.borrow_mut().insert(position_id, active_position));
            // DEF-059: heap mirror + stable cell together. saturating_add: weight is
            // bounded by TOTAL_SUPPLY × max multiplier (<< u128::MAX).
            add_total_voting_weight(voting_weight);
            PENDING_POSITIONS.with(|p| p.borrow_mut().remove(&position_id));
            PENDING_LOCK_OPS.with(|m| m.borrow_mut().remove(&op_id));
            Ok(position_id)
        }
        Ok((Err(e),)) => {
            // Definite inner rejection — the lock did NOT happen. Remove the position
            // entirely (no weight was ever credited) and drop the pending op.
            // C-A5: also release the dedup key. A definitively failed stake must
            // not burn the caller's key — nothing was created, so a genuine
            // retry is a NEW request, not a duplicate.
            STAKE_DEDUP.with(|m| m.borrow_mut().remove(&ddk));
            POSITIONS.with(|p| p.borrow_mut().remove(&position_id));
            PENDING_POSITIONS.with(|p| p.borrow_mut().remove(&position_id));
            PENDING_LOCK_OPS.with(|m| m.borrow_mut().remove(&op_id));
            Err(e)
        }
        Err((_, e)) => {
            // Transport-unknown — leave the LockPending position + PendingLockOp in
            // place for reconcile_lock. No weight credited.
            Err(format!("LockPending: lock_for_staking outcome unknown (op_id={}): {}", op_id, e))
        }
    }
}

#[update]
async fn unstake(position_id: u64) -> Result<(), String> {
    let holder = ic_cdk::caller();
    let mut position = POSITIONS.with(|p| p.borrow().get(&position_id))
        .ok_or("Position not found")?;

    if position.holder != holder {
        return Err("Not your position".to_string());
    }
    if position.closed {
        return Err("Position already closed".to_string());
    }
    if let Some(pending) = pending_stake_state(position_id) {
        return Err(format!("Position pending reconciliation: {:?}", pending));
    }
    if !position.is_unlockable() {
        let remaining = (position.lock_end_ns.saturating_sub(time())) / 1_000_000_000;
        return Err(format!("Lock period active — {} seconds remaining", remaining));
    }

    // Claim any pending rewards first. claim_rewards_internal is intentionally
    // gated to NotImplemented (no silent debit), so its Err is expected and
    // ignored here — unstaking must still proceed.
    let _ = claim_rewards_internal(&mut position).await;

    let token = get_token()?;

    // DEF-052 write-before-call. unlock_from_staking is cumulative and NOT
    // idempotent. Snapshot the pre-unlock ACTIVE position (full weight) for an exact
    // revert, allocate an op_id, and durably record the pending unlock BEFORE the
    // token call. Active weight is removed up-front so an ambiguous outcome never
    // leaves governance power on a maybe-unlocked position; reconcile_unlock
    // restores it exactly from the snapshot on NotExecuted.
    let pre_unlock_snapshot = position.clone(); // active, voting_weight = W, op_id None
    let op_id = next_op_id();
    let now = time();

    PENDING_LOCK_OPS.with(|m| m.borrow_mut().insert(op_id, PendingLockOp {
        op_id, position_id, holder, amount: pre_unlock_snapshot.amount,
        op_type: LockOpType::Unlock, initiated_at_ns: now,
        snapshot: pre_unlock_snapshot.clone(),
        // Unlock ops never create a dedup record — there is no key to release.
        dedup_key: None,
    }));
    // DEF-059: remove active weight now (heap mirror + stable cell together).
    sub_total_voting_weight(pre_unlock_snapshot.voting_weight);
    let pending_position = StakePosition {
        voting_weight: 0,
        op_id: Some(op_id),
        ..pre_unlock_snapshot.clone()
    };
    POSITIONS.with(|p| p.borrow_mut().insert(position_id, pending_position));
    PENDING_POSITIONS.with(|p| p.borrow_mut().insert(position_id, PendingStakeState::UnlockPending));

    let unlock_call: Result<(Result<(), String>,), _> = ic_cdk::api::call::call(
        token, "unlock_from_staking", (holder, pre_unlock_snapshot.amount)
    ).await;

    match unlock_call {
        Ok((Ok(()),)) => {
            // Confirmed unlock — close the position; weight already removed above.
            let closed = StakePosition {
                voting_weight: 0,
                closed: true,
                op_id: None,
                ..pre_unlock_snapshot.clone()
            };
            POSITIONS.with(|p| p.borrow_mut().insert(position_id, closed));
            PENDING_POSITIONS.with(|p| p.borrow_mut().remove(&position_id));
            PENDING_LOCK_OPS.with(|m| m.borrow_mut().remove(&op_id));
            Ok(())
        }
        Ok((Err(e),)) => {
            // Definite inner rejection — unlock did NOT happen. Restore the exact
            // pre-unlock active position and re-credit its weight.
            POSITIONS.with(|p| p.borrow_mut().insert(position_id, pre_unlock_snapshot.clone()));
            add_total_voting_weight(pre_unlock_snapshot.voting_weight);
            PENDING_POSITIONS.with(|p| p.borrow_mut().remove(&position_id));
            PENDING_LOCK_OPS.with(|m| m.borrow_mut().remove(&op_id));
            Err(e)
        }
        Err((_, e)) => {
            // Transport-unknown — leave the UnlockPending position + PendingLockOp in
            // place for reconcile_unlock.
            Err(format!("UnlockPending: unlock_from_staking outcome unknown (op_id={}): {}", op_id, e))
        }
    }
}

// ── DEF-052: reconcile endpoints (controller-only operator recovery) ────────────
//
// RECONCILE TRUST: reconcile_lock / reconcile_unlock are MANUAL recovery tools. The
// controller asserts — after external/on-chain verification of the token canister's
// staking_locked_balance — whether the token-side lock/unlock executed. These
// endpoints DO NOT retry or re-issue the token call; they only reconcile local
// staking state (position + voting weight + pending maps). A wrong Executed/
// NotExecuted decision diverges staking state from the token ledger, so the token
// side MUST be verified externally before calling. Documented in the deliverable report.

/// Verify the full op↔position binding before any mutation. Returns the pending op
/// and the current (pending) position, or Err describing the first failed check.
fn load_and_verify_pending_op(op_id: u64, expected: LockOpType) -> Result<(PendingLockOp, StakePosition), String> {
    let op = PENDING_LOCK_OPS.with(|m| m.borrow().get(&op_id))
        .ok_or_else(|| format!("No pending lock op with op_id {}", op_id))?;
    if op.op_type != expected {
        return Err(format!("op_id {} is a {:?} op, not {:?} — wrong reconcile endpoint", op_id, op.op_type, expected));
    }
    let position = POSITIONS.with(|p| p.borrow().get(&op.position_id))
        .ok_or_else(|| format!("op_id {} references missing position {}", op_id, op.position_id))?;
    if position.op_id != Some(op_id) {
        return Err(format!("position {} does not reference op_id {} (found {:?})", op.position_id, op_id, position.op_id));
    }
    if position.holder != op.holder {
        return Err(format!("holder mismatch for op_id {} on position {}", op_id, op.position_id));
    }
    if op.amount != position.amount {
        return Err(format!("amount mismatch for op_id {} on position {}", op_id, op.position_id));
    }
    let expected_state = match expected {
        LockOpType::Lock   => PendingStakeState::LockPending,
        LockOpType::Unlock => PendingStakeState::UnlockPending,
    };
    match pending_stake_state(op.position_id) {
        Some(s) if s == expected_state => {}
        other => return Err(format!("position {} is not in {:?} (found {:?}) — not reconcilable", op.position_id, expected_state, other)),
    }
    Ok((op, position))
}

/// Resolve a transport-unknown `lock_for_staking` (LockPending). Controller-only.
#[update]
fn reconcile_lock(op_id: u64, decision: LockDecision) -> Result<(), String> {
    ensure_ic_controller()?;
    let (op, _position) = load_and_verify_pending_op(op_id, LockOpType::Lock)?;
    match decision {
        LockDecision::Executed => {
            // Token-side lock confirmed. Promote the position to its intended active
            // state and credit its voting weight (none was credited during pending).
            let active = StakePosition { op_id: None, ..op.snapshot.clone() };
            let weight = active.voting_weight;
            POSITIONS.with(|p| p.borrow_mut().insert(op.position_id, active));
            add_total_voting_weight(weight);
            PENDING_POSITIONS.with(|p| p.borrow_mut().remove(&op.position_id));
            PENDING_LOCK_OPS.with(|m| m.borrow_mut().remove(&op_id));
            Ok(())
        }
        LockDecision::NotExecuted => {
            // Token-side lock did NOT happen. Cancel the position; no weight was ever
            // credited, so TOTAL_VOTING_WEIGHT is unchanged.
            //
            // P1-2: RELEASE the dedup key. This is a RESOLVED definite failure —
            // nothing was created and nothing was locked — so an identical retry
            // is a genuine new request, not a duplicate. Leaving the key would
            // make that retry return Ok(position_id) for a position that no
            // longer exists, reporting success while locking nothing.
            //
            // Transport-UNKNOWN deliberately KEEPS the key (the original may yet
            // have executed); only a resolved NotExecuted releases it.
            if let Some(key) = &op.dedup_key {
                STAKE_DEDUP.with(|m| m.borrow_mut().remove(&DedupKey::new(op.holder, key)));
            }
            POSITIONS.with(|p| p.borrow_mut().remove(&op.position_id));
            PENDING_POSITIONS.with(|p| p.borrow_mut().remove(&op.position_id));
            PENDING_LOCK_OPS.with(|m| m.borrow_mut().remove(&op_id));
            Ok(())
        }
    }
}

/// Resolve a transport-unknown `unlock_from_staking` (UnlockPending). Controller-only.
#[update]
fn reconcile_unlock(op_id: u64, decision: LockDecision) -> Result<(), String> {
    ensure_ic_controller()?;
    let (op, _position) = load_and_verify_pending_op(op_id, LockOpType::Unlock)?;
    match decision {
        LockDecision::Executed => {
            // Token-side unlock confirmed. Finalize as closed; the weight was already
            // removed when the position entered UnlockPending, so TOTAL is unchanged.
            let closed = StakePosition { voting_weight: 0, closed: true, op_id: None, ..op.snapshot.clone() };
            POSITIONS.with(|p| p.borrow_mut().insert(op.position_id, closed));
            PENDING_POSITIONS.with(|p| p.borrow_mut().remove(&op.position_id));
            PENDING_LOCK_OPS.with(|m| m.borrow_mut().remove(&op_id));
            Ok(())
        }
        LockDecision::NotExecuted => {
            // Token-side unlock did NOT happen. Restore the EXACT pre-unlock active
            // position from the snapshot and re-credit the weight removed at
            // UnlockPending entry.
            let restored = op.snapshot.clone(); // active, full weight, op_id None
            let weight = restored.voting_weight;
            POSITIONS.with(|p| p.borrow_mut().insert(op.position_id, restored));
            add_total_voting_weight(weight);
            PENDING_POSITIONS.with(|p| p.borrow_mut().remove(&op.position_id));
            PENDING_LOCK_OPS.with(|m| m.borrow_mut().remove(&op_id));
            Ok(())
        }
    }
}

// ── W2 2-5R: stuck-`Executing` proposal reconcile ────────────────────────────
//
// THE DEFECT. `execute_proposal` writes `Executing` durably BEFORE its await
// and writes the terminal status + `executed_at_ns` only after it. If the
// continuation dies — a trap on the post-await write, or an UPGRADE across the
// await — the record stays `Executing` forever, and both guards in
// `execute_proposal` then reject every future attempt: `executed_at_ns.is_some()`
// is false but `status == Executing` is true. That is deliberate fail-closed
// behaviour (the outbound action may have landed, so it must NOT be retried),
// and this endpoint is the manual reconcile that comment anticipates.
//
// THIS ENDPOINT NEVER RETRIES THE ACTION. It never calls
// `execute_proposal_action`. It records a human's off-chain determination of
// whether the action landed, and it writes `executed_at_ns` in the SAME atomic
// insert as the terminal status — without that write, a later public
// `execute_proposal` would pass BOTH guards and issue the action a second time,
// breaking the very no-retry property this endpoint exists to honour.

/// Age a proposal must have spent in `Executing` before a terminal
/// reconciliation decision may be made. RATIFIED 2026-08-19 (CTO) at 24 h.
///
/// This is a BOUNDED-WAIT POLICY PARAMETER, never a proof parameter: it is not
/// evidence that the action did or did not land. Healthy execution completes
/// inside a single message, and a killed continuation never recovers by
/// waiting, so the threshold exists to give the off-chain verification time and
/// to make premature human adjudication harder. The error is asymmetric — too
/// long merely delays recovery of an already-permanently-stuck record, too
/// short authorizes a terminal no-retry decision against a live execution.
pub const STUCK_PROPOSAL_RECONCILE_THRESHOLD_NS: u64 = 86_400_000_000_000; // 24 h

/// Provenance prefix stamped into the EXISTING `execution_result : opt text`.
/// An operator reading a record later must be able to tell "this proposal
/// executed" from "a human adjudicated it"; the provenance lives on the record,
/// not in a runbook. No retype of the published field.
pub const RECONCILED_RESULT_PREFIX: &str = "RECONCILED:";

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ProposalReconcileDecision {
    /// The operator determined the action DID land.
    Executed,
    /// The operator determined the action did NOT land. Still terminal — the
    /// proposal is never re-opened for retry.
    NotExecuted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ProposalReconciled {
    pub status: ProposalStatus,
    pub executed_at_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ProposalTerminalReplay {
    pub status: ProposalStatus,
    /// `None` is HISTORY, not a gap: the approval-failure path writes
    /// `Rejected` with no stored result. Never synthesised.
    pub execution_result: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum ProposalReconcileResult {
    /// A state-changing transition was performed (from `Executing` only).
    Reconciled(ProposalReconciled),
    /// The proposal was already terminal. Nothing was mutated.
    TerminalReplay(ProposalTerminalReplay),
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum ProposalReconcileError {
    NotController,
    ProposalNotFound,
    /// The source state is neither `Executing` nor terminal. Names the state.
    NotStuck { status: ProposalStatus },
    /// Age below the ratified threshold. Both numbers are named so the operator
    /// need not compute the gap.
    TooYoung { age_ns: u64, threshold_ns: u64 },
    /// Legacy `Executing` record carrying no start stamp: the age clock has now
    /// been initialized from this observation. A decision becomes possible only
    /// after the FULL threshold has elapsed from that stamp.
    LegacyClockInitialized { observed_at_ns: u64, threshold_ns: u64 },
}

/// Reconcile a proposal stuck in `Executing`. Controller-only.
///
/// GATING. `ic_cdk::api::is_controller`, returning a typed `Err` rather than
/// trapping — the same IC canister-controller boundary `reconcile_lock` /
/// `reconcile_unlock` carry, and the same one vesting's `reconcile_claim`
/// documents. It is NOT signer-quorum-gated: quorum authorizes a proposal, and
/// this is not an authorization question but an operator's determination of a
/// transport outcome. It is not open.
///
/// SEMANTICS, typed apart per the custody-types precedent:
///   * from `Executing`             → STATE-CHANGING transition (one atomic write)
///   * from `Executed` / `Rejected` → TERMINAL REPLAY, mutates nothing
///   * any other status             → typed rejection naming the source state
///
/// LEGACY CLOCK. An `Executing` record whose `execution_started_at_ns` is
/// `None` (written before this lane, or stranded by the very upgrade that
/// introduced the field) is NOT refused forever. The first controller
/// observation stamps the field with `time()` — an OBSERVATION instant, not a
/// claimed start — and refuses; the full threshold then runs from that stamp.
/// This is safe in the correct direction: the true start is no later than the
/// observation, so elapsed-since-observation UNDERSTATES the true age and can
/// only ever refuse too long, never permit too early. THE STAMP IS WRITE-ONCE:
/// it is written only when the field is `None` and is never advanced or
/// overwritten, so repeated calls cannot push the decision further away.
///
/// NOTE: this is a state-changing act on an otherwise-refusing path. It is said
/// here rather than left to read like a query.
/// What a reconcile call decides, computed as a PURE function of the stored
/// record, the operator's decision and the current time.
///
/// Split out so every branch is exercisable in a native unit test: the endpoint
/// itself needs an IC environment for `caller()`/`time()` and a stable map, and
/// a rule that can only be tested through a canister boundary tends not to be
/// tested at every branch. The endpoint below is a thin applier of this.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ReconcileOutcome {
    /// Already terminal — return stored history, mutate nothing.
    Replay { status: ProposalStatus, execution_result: Option<String> },
    /// Refuse without mutating.
    Refuse(ProposalReconcileErrorKind),
    /// Legacy `Executing + None`: stamp the observation clock write-once, then
    /// refuse. The ONLY refusing branch that writes.
    InitializeClock { observed_at_ns: u64 },
    /// Perform the single atomic terminal write.
    Commit { status: ProposalStatus, executed_at_ns: u64, execution_result: String },
}

/// Refusal kinds, separated from the Candid error type so the pure core stays
/// free of wire concerns. Mapped 1:1 onto `ProposalReconcileError`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ProposalReconcileErrorKind {
    NotStuck(ProposalStatus),
    TooYoung { age_ns: u64, threshold_ns: u64 },
}

/// The whole rule, in one place, with no I/O.
pub(crate) fn decide_reconcile(
    proposal: &Proposal,
    decision: &ProposalReconcileDecision,
    now: u64,
) -> ReconcileOutcome {
    match proposal.status {
        // Terminal replay. Note the supplied `decision` is deliberately NOT
        // consulted: history is reported, never re-decided.
        ProposalStatus::Executed | ProposalStatus::Rejected => {
            return ReconcileOutcome::Replay {
                status: proposal.status.clone(),
                execution_result: proposal.execution_result.clone(),
            };
        }
        ProposalStatus::Executing => {}
        ref other => {
            return ReconcileOutcome::Refuse(ProposalReconcileErrorKind::NotStuck(other.clone()));
        }
    }

    let started_at = match proposal.execution_started_at_ns {
        None => return ReconcileOutcome::InitializeClock { observed_at_ns: now },
        Some(started_at) => started_at,
    };

    // Non-wrapping age. `saturating_sub` also disposes of an invalid stamp in
    // the future — it yields 0, which refuses as TooYoung rather than
    // underflowing into a huge age that would admit immediately.
    let age_ns = now.saturating_sub(started_at);
    if age_ns < STUCK_PROPOSAL_RECONCILE_THRESHOLD_NS {
        return ReconcileOutcome::Refuse(ProposalReconcileErrorKind::TooYoung {
            age_ns,
            threshold_ns: STUCK_PROPOSAL_RECONCILE_THRESHOLD_NS,
        });
    }

    let (status, verdict) = match decision {
        ProposalReconcileDecision::Executed => (ProposalStatus::Executed, "Executed"),
        ProposalReconcileDecision::NotExecuted => (ProposalStatus::Rejected, "NotExecuted"),
    };
    ReconcileOutcome::Commit {
        status,
        executed_at_ns: now,
        execution_result: format!(
            "{}{} — operator reconciliation of a stuck Executing proposal; the action was NOT re-issued",
            RECONCILED_RESULT_PREFIX, verdict
        ),
    }
}

#[update]
fn reconcile_stuck_proposal(
    proposal_id: u64,
    decision: ProposalReconcileDecision,
) -> Result<ProposalReconcileResult, ProposalReconcileError> {
    if !ic_cdk::api::is_controller(&ic_cdk::caller()) {
        return Err(ProposalReconcileError::NotController);
    }

    let mut proposal = PROPOSALS_MAP
        .with(|p| p.borrow().get(&proposal_id))
        .ok_or(ProposalReconcileError::ProposalNotFound)?;

    match decide_reconcile(&proposal, &decision, time()) {
        ReconcileOutcome::Replay { status, execution_result } => {
            Ok(ProposalReconcileResult::TerminalReplay(ProposalTerminalReplay {
                status,
                execution_result,
            }))
        }
        ReconcileOutcome::Refuse(kind) => Err(match kind {
            ProposalReconcileErrorKind::NotStuck(status) => {
                ProposalReconcileError::NotStuck { status }
            }
            ProposalReconcileErrorKind::TooYoung { age_ns, threshold_ns } => {
                ProposalReconcileError::TooYoung { age_ns, threshold_ns }
            }
        }),
        ReconcileOutcome::InitializeClock { observed_at_ns } => {
            // Write-once by construction: this branch is reachable only when
            // the field is None, and it is the only writer of the stamp outside
            // execute_proposal.
            proposal.execution_started_at_ns = Some(observed_at_ns);
            PROPOSALS_MAP.with(|p| p.borrow_mut().insert(proposal_id, proposal));
            Err(ProposalReconcileError::LegacyClockInitialized {
                observed_at_ns,
                threshold_ns: STUCK_PROPOSAL_RECONCILE_THRESHOLD_NS,
            })
        }
        ReconcileOutcome::Commit { status, executed_at_ns, execution_result } => {
            // ONE atomic write carrying all three of: terminal status,
            // `executed_at_ns`, and the provenance-bearing result. The
            // `executed_at_ns` write is what makes the no-retry property hold
            // against `execute_proposal`'s FIRST guard; without it the record
            // would pass both guards and the action could be issued again.
            proposal.status = status.clone();
            proposal.executed_at_ns = Some(executed_at_ns);
            proposal.execution_result = Some(execution_result);
            PROPOSALS_MAP.with(|p| p.borrow_mut().insert(proposal_id, proposal));
            Ok(ProposalReconcileResult::Reconciled(ProposalReconciled {
                status,
                executed_at_ns,
            }))
        }
    }
}

/// Operator view of unresolved lock/unlock operations. Controller-only — pending-op
/// metadata (principal, amount, timing) is operator information, so this mirrors
/// nullifier-registry's IC-controller gating on sensitive reads. Only genuinely
/// unresolved ops appear here; every finalize/revert/reconcile path removes its entry.
#[query]
fn list_pending_lock_ops() -> Vec<PendingLockOp> {
    if !ic_cdk::api::is_controller(&ic_cdk::caller()) {
        ic_cdk::trap("list_pending_lock_ops: caller is not an IC controller");
    }
    PENDING_LOCK_OPS.with(|m| m.borrow().iter().map(|(_, v)| v).collect())
}

#[update]
async fn claim_rewards(position_id: u64) -> Result<u128, String> {
    let holder = ic_cdk::caller();
    let mut position = POSITIONS.with(|p| p.borrow().get(&position_id))
        .ok_or("Position not found")?;

    if position.holder != holder { return Err("Not your position".to_string()); }
    if position.closed { return Err("Position closed".to_string()); }
    if let Some(pending) = pending_stake_state(position_id) {
        return Err(format!("Position pending reconciliation: {:?}", pending));
    }

    claim_rewards_internal(&mut position).await
}

// SAFETY GATE (Task 5): reward claiming is disabled until the reward token
// transfer path is wired.
//
// The previous body debited rewards_pool_balance / fee_revenue_balance and
// incremented rewards_claimed, but the actual token.icrc1_transfer to the holder
// was a TODO. That is a SILENT DEBIT: the staker's accounting shows rewards
// "claimed" while they receive no STSH. For mainnet safety a silent debit is
// unacceptable, and a half-wired transfer-then-debit is worse than an honest
// "not yet".
//
// Per the Lane B charter we bias to NotImplemented: only wire the transfer once
// a funded staking-reward token account AND an idempotent transfer-first path
// exist. Neither is in place (the staking canister holds no verified reward token
// account, and icrc1_transfer is not idempotent without dedup), so we gate OFF:
// compute claimable for visibility, then return WITHOUT touching REWARD_STATE or
// the position. Reward accounting is left fully intact (no silent debit).
async fn claim_rewards_internal(position: &mut StakePosition) -> Result<u128, String> {
    let claimable = calculate_claimable(position);
    if claimable == 0 { return Ok(0); }

    Err(format!(
        "NotImplemented: reward claiming is disabled until the staking-reward \
         token transfer path is wired (claimable={}). No reward-pool debit and no \
         rewards_claimed mutation has occurred.",
        claimable
    ))
}

fn calculate_claimable(position: &StakePosition) -> u128 {
    let total_weight = TOTAL_VOTING_WEIGHT.with(|w| *w.borrow());
    if total_weight == 0 || position.closed || pending_stake_state(position.position_id).is_some() { return 0; }

    let elapsed_ns = time().saturating_sub(position.last_claim_ns);
    let elapsed_days = elapsed_ns / (24 * 60 * 60 * 1_000_000_000);

    let daily_emission = REWARD_STATE.with(|r| r.borrow().emission_rate_per_day);
    let pool_balance = REWARD_STATE.with(|r| r.borrow().rewards_pool_balance + r.borrow().fee_revenue_balance);

    // Position's share = voting_weight / total_weight * daily_emission * elapsed_days
    let gross = position.voting_weight
        .saturating_mul(daily_emission)
        .saturating_mul(elapsed_days as u128)
        / total_weight;

    gross.min(pool_balance) // never exceed remaining pool
}

// ── Governance ────────────────────────────────────────────────────────────────

#[update]
fn create_proposal(proposal_type: ProposalType, description: String) -> Result<u64, String> {
    let proposer = ic_cdk::caller();
    let params = GOV_PARAMS.with(|g| g.borrow().clone());

    // ── P1-1: proposer eligibility is SNAPSHOT-ELIGIBLE stake, not live stake ──
    //
    // Live staked amount counts positions that are active but snapshot-INELIGIBLE
    // (notably legacy sub-30-day locks). A holder made entirely of such positions
    // could clear the deposit bar, create a proposal, and be excluded from the
    // snapshot — producing a zero-weight snapshot. Measuring the proposer against
    // the SAME eligibility rule the snapshot uses removes the mismatch at source.
    //
    // Computed against the same `voting_closes_ns` the snapshot below will use,
    // so "eligible to propose" and "eligible to vote" cannot disagree.

    // VerifierKeyUpgrade: hard validation of all required fields
    if let ProposalType::VerifierKeyUpgrade(ref payload) = proposal_type {
        payload.validate()?;
    }

    // K3-015: the live params must satisfy the contract at SUBMISSION, not only
    // at init — a param set installed by an earlier proposal is otherwise never
    // re-checked before it governs a new one.
    params.validate()?;

    let now = time();
    let timelock = proposal_type.timelock_ns(&params);

    // K3-015: every proposal timestamp addition is CHECKED. `validate()` proves
    // the params sum without wrapping; these guard the sum with `now` on top.
    let voting_opens_ns = now
        .checked_add(params.voting_delay_ns)
        .ok_or("proposal timestamp overflow: voting_opens_ns")?;
    let voting_closes_ns = voting_opens_ns
        .checked_add(params.voting_period_ns)
        .ok_or("proposal timestamp overflow: voting_closes_ns")?;
    let execute_after_ns = voting_closes_ns
        .checked_add(timelock)
        .ok_or("proposal timestamp overflow: execute_after_ns")?;

    let proposer_eligible_stake: u128 = POSITIONS.with(|p| {
        p.borrow()
            .iter()
            .map(|(_, pos)| pos)
            .filter(|pos| pos.holder == proposer && snapshot_eligible(pos, voting_closes_ns))
            .map(|pos| pos.amount)
            .sum()
    });
    if proposer_eligible_stake < params.min_proposal_deposit {
        return Err(format!(
            "Proposer must have >= {} STSH in SNAPSHOT-ELIGIBLE stake (locked through the \
             close of voting and meeting the {}-day minimum). Currently eligible: {}",
            params.min_proposal_deposit, MIN_LOCK_DAYS, proposer_eligible_stake
        ));
    }

    let id = alloc_proposal_id();

    // ── C-A1 SNAPSHOT — synchronous, single pass, no await ──────────────────
    //
    // The numerator (which positions may vote, and with what weight) and the
    // denominator (`snapshot_total_weight`) are produced by THIS ONE traversal.
    // There is no await and no observable intermediate state between "proposal
    // created" and "snapshot fixed": the proposal record is written after, in
    // the same message, so no caller can ever see a proposal without its
    // snapshot.
    let mut snapshot_total_weight: u128 = 0;
    let eligible: Vec<(u64, SnapshotEntry)> = POSITIONS.with(|p| {
        p.borrow()
            .iter()
            .map(|(_, pos)| pos)
            .filter(|pos| snapshot_eligible(pos, voting_closes_ns))
            .map(|pos| (pos.position_id, SnapshotEntry { holder: pos.holder, weight: pos.voting_weight }))
            .collect()
    });
    for (position_id, entry) in &eligible {
        // Saturating: total eligible weight is bounded by TOTAL_SUPPLY x max
        // multiplier, far below u128::MAX; saturating here cannot mask a real
        // overflow but does keep proposal creation infallible once past checks.
        snapshot_total_weight = snapshot_total_weight.saturating_add(entry.weight);
        PROPOSAL_SNAPSHOTS.with(|m| {
            m.borrow_mut().insert(
                SnapshotKey { proposal_id: id, position_id: *position_id },
                entry.clone(),
            )
        });
    }

    // P1-1: a zero-weight snapshot is unadjudicable — with a zero denominator
    // `votes * 10000 >= 0 * bps` is trivially true, so the proposal would pass
    // quorum AND approval with no votes at all. Refuse to create it. (Execution
    // rejects Some(0) independently — two guards, because this one can only stop
    // proposals created after the fix.)
    if snapshot_total_weight == 0 {
        return Err(
            "No eligible voting weight exists for this proposal — refusing to create a \
             proposal that could pass with no votes. Positions must meet the minimum lock \
             and remain locked through the close of voting."
                .to_string(),
        );
    }

    let proposal = Proposal {
        id, proposer, proposal_type, description,
        status: ProposalStatus::VotingPending,
        created_at_ns: now,
        voting_opens_ns,
        voting_closes_ns,
        execute_after_ns,
        votes_for: 0,
        votes_against: 0,
        snapshot_total_weight: Some(snapshot_total_weight),
        executed_at_ns: None,
        execution_result: None,
        // W2 2-5R: no execution has started at creation time.
        execution_started_at_ns: None,
    };

    PROPOSALS_MAP.with(|p| p.borrow_mut().insert(id, proposal));
    Ok(id)
}

#[update]
fn vote(proposal_id: u64, approve: bool) -> Result<(), String> {
    let voter = ic_cdk::caller();
    let now = time();

    let mut proposal = PROPOSALS_MAP.with(|p| p.borrow().get(&proposal_id))
        .ok_or("Proposal not found")?;

    if now < proposal.voting_opens_ns {
        return Err("Voting has not opened yet".to_string());
    }
    if now > proposal.voting_closes_ns {
        return Err("Voting has closed".to_string());
    }

    // ── C-A1 — vote by SNAPSHOTTED POSITION ────────────────────────────────
    //
    // The caller votes with every position that was eligible AT SNAPSHOT and is
    // still owned by them per that snapshot, excluding any already counted for
    // this proposal. Weight comes from the snapshot, never from live state, so
    // a position created / transferred / re-staked after proposal creation
    // contributes nothing.
    let entries: Vec<(u64, SnapshotEntry)> = PROPOSAL_SNAPSHOTS.with(|m| {
        m.borrow()
            .range(SnapshotKey { proposal_id, position_id: 0 }..)
            .take_while(|(k, _)| k.proposal_id == proposal_id)
            .filter(|(_, e)| e.holder == voter)
            .map(|(k, e)| (k.position_id, e))
            .collect()
    });

    if entries.is_empty() {
        return Err(
            "No eligible snapshotted positions for this proposal — a position must have \
             existed at proposal creation, be locked through the close of voting, and meet \
             the 30-day minimum lock (relock a legacy shorter position to become eligible)"
                .to_string(),
        );
    }

    // Each snapshotted position votes AT MOST ONCE per proposal. Voting the same
    // stake once on each of several concurrent proposals stays legitimate — the
    // key is scoped to (proposal, position).
    let unvoted: Vec<(u64, SnapshotEntry)> = entries
        .into_iter()
        .filter(|(position_id, _)| {
            let k = make_vote_key(proposal_id, *position_id);
            !VOTES.with(|v| v.borrow().contains_key(&k))
        })
        .collect();

    if unvoted.is_empty() {
        return Err("Already voted on this proposal".to_string());
    }

    let mut cast_weight: u128 = 0;
    for (position_id, entry) in unvoted {
        let record = VoteRecord {
            proposal_id,
            position_id: Some(position_id),
            voter,
            approve,
            voting_weight: entry.weight,
            voted_at_ns: now,
        };
        VOTES.with(|v| v.borrow_mut().insert(make_vote_key(proposal_id, position_id), record));
        cast_weight = cast_weight.saturating_add(entry.weight);
    }

    if approve {
        proposal.votes_for = proposal.votes_for.saturating_add(cast_weight);
    } else {
        proposal.votes_against = proposal.votes_against.saturating_add(cast_weight);
    }

    // Update proposal status
    proposal.status = ProposalStatus::VotingOpen;
    PROPOSALS_MAP.with(|p| p.borrow_mut().insert(proposal_id, proposal));

    Ok(())
}

#[update]
async fn execute_proposal(proposal_id: u64) -> Result<(), String> {
    let now = time();
    let mut proposal = PROPOSALS_MAP.with(|p| p.borrow().get(&proposal_id))
        .ok_or("Proposal not found")?;

    // DEF-055: double-execution / reentrancy guard. `executed_at_ns` guards a
    // completed attempt; the `Executing` status (set below, BEFORE the first
    // await) guards an in-flight one. execute_proposal_action awaits inter-canister
    // calls for VerifierKeyUpgrade and EmergencyPause; without the Executing gate a
    // second call could interleave during that await window — both passing the
    // `executed_at_ns.is_some()` check (still None until the await returns) — and
    // run the action twice.
    if proposal.executed_at_ns.is_some() {
        return Err("Already executed".to_string());
    }
    if proposal.status == ProposalStatus::Executing {
        return Err("Proposal is already executing — concurrent execute_proposal rejected".to_string());
    }
    if now < proposal.voting_closes_ns {
        return Err("Voting still open".to_string());
    }
    if now < proposal.execute_after_ns {
        let remaining = (proposal.execute_after_ns - now) / 1_000_000_000;
        return Err(format!("Timelock active — {} seconds remaining", remaining));
    }

    // Check quorum and approval
    let params = GOV_PARAMS.with(|g| g.borrow().clone());
    // C-A1: the denominator comes from the SAME snapshot as the numerator, not
    // from live TOTAL_VOTING_WEIGHT (which moves as people stake/unstake during
    // the voting window). A proposal with no snapshot predates P-STK and cannot
    // be adjudicated — fail CLOSED rather than defaulting the denominator to 0,
    // which would make quorum trivially satisfiable.
    // P1-1: fail closed on BOTH a missing snapshot and a zero-weight one. A zero
    // denominator makes `total_votes * 10000 >= 0` trivially true, so quorum and
    // approval would both "pass" on zero votes.
    let total_weight = match proposal.snapshot_total_weight {
        None => {
            return Err(
                "Proposal has no eligibility snapshot (created before P-STK) — cannot be \
                 executed"
                    .to_string(),
            )
        }
        Some(0) => {
            return Err(
                "Proposal snapshot has zero eligible voting weight — cannot be executed \
                 (a zero quorum denominator would pass on no votes)"
                    .to_string(),
            )
        }
        Some(w) => w,
    };
    let required_quorum_bps = proposal.proposal_type.quorum_bps(&params);
    let total_votes = proposal.votes_for + proposal.votes_against;
    let quorum_met = total_votes * 10000 >= total_weight * required_quorum_bps as u128;
    let approved = proposal.votes_for * 10000 >= total_votes * params.approval_threshold_bps as u128;

    if !quorum_met {
        proposal.status = ProposalStatus::Rejected;
        proposal.execution_result = Some("Quorum not met".to_string());
        PROPOSALS_MAP.with(|p| p.borrow_mut().insert(proposal_id, proposal));
        return Err("Quorum not met".to_string());
    }
    if !approved {
        proposal.status = ProposalStatus::Rejected;
        PROPOSALS_MAP.with(|p| p.borrow_mut().insert(proposal_id, proposal));
        return Err("Approval threshold not met".to_string());
    }

    // DEF-055: commit to execution by persisting `Executing` BEFORE the first
    // await. `await` is an IC commit point, so this write is durable once
    // execute_proposal_action issues its inter-canister call; a concurrent caller
    // then sees `Executing` at the guard above and is rejected. The action runs at
    // most once.
    //
    // Trap edge: if the post-await continuation traps (e.g. the final status write
    // OOMs) the `Executing` write persists but `executed_at_ns` does not, leaving
    // the proposal stuck in `Executing`. That is intentional fail-closed behaviour
    // — the outbound call may have landed, so we must NOT re-open it for retry.
    // Recovery (if ever needed) is a manual reconcile, out of DEF-055 scope.
    proposal.status = ProposalStatus::Executing;
    // W2 2-5R: stamp the execution-start instant on the SAME record instance,
    // before the SAME single insert, so a record can never say "Executing"
    // without saying when. `time()` is captured fresh here rather than reusing
    // the `now` bound at the top of this function: that value is message-entry
    // time, taken before the voting/timelock/quorum checks, and this field must
    // mean "when execution started" without a reader having to prove it.
    proposal.execution_started_at_ns = Some(time());
    PROPOSALS_MAP.with(|p| p.borrow_mut().insert(proposal_id, proposal.clone()));

    // Execute
    let result = execute_proposal_action(&proposal.proposal_type).await;
    proposal.executed_at_ns = Some(now);
    // On failure we deliberately move to a terminal Rejected state (with
    // executed_at_ns set) rather than reverting to a re-executable state: the
    // outbound action may have reached the pool, so re-execution must be blocked.
    proposal.status = if result.is_ok() { ProposalStatus::Executed } else { ProposalStatus::Rejected };
    proposal.execution_result = Some(result.clone().unwrap_or_else(|e| e));
    PROPOSALS_MAP.with(|p| p.borrow_mut().insert(proposal_id, proposal));

    result.map(|_| ())
}

// GOVERNANCE SCOPE (QA-DEF-004): staking governance → shielded-pool admin authority.
//
// Staking governance HAS a deliberate, bounded authority path into pool admin
// operations. It is exercised only here, only by an already-passed proposal, and
// only for the endpoints listed below. There are no other pool-admin paths from
// this canister, and there is no silent/undocumented path.
//
//   Who may propose : any principal with >= GovernanceParams.min_proposal_deposit
//                     STSH actively staked (enforced in `create_proposal`).
//   Who may vote    : any staker; vote power = sum of active (non-pending) position
//                     voting_weight (enforced in `vote` via get_total_voting_weight_for).
//   What triggers   : `execute_proposal` requires, in order: not already executed,
//   execution         voting closed, execution timelock elapsed (7d standard /
//                     14d VerifierKeyUpgrade), quorum met (tiered: quorum_bps 10% /
//                     treasury_quorum_bps 20% for TreasurySpend+CanisterUpgrade /
//                     vk_quorum_bps 30% for VerifierKeyUpgrade) AND approval_threshold
//                     (approval_threshold_bps, default 50%+1). `execute_proposal` is
//                     callable by anyone, but only fires the action once all of the
//                     above hold — the caller cannot bypass the vote/timelock.
//   Reachable pool  : exactly TWO pool endpoints are reachable from governance —
//   endpoints         • `schedule_vk_activation`        (ProposalType::VerifierKeyUpgrade)
//                     • `emergency_pause_deposits` /
//                       `emergency_pause_spends`        (ProposalType::EmergencyPause)
//                     No other pool-admin endpoint is invoked from staking. The
//                     ParameterUpdate / TreasurySpend / FeeUpdate / CanisterUpgrade
//                     variants are NOT yet implemented and HARD-ERROR at execution
//                     (DEF-084) — no pretend-success, no silent ignore, and they
//                     exercise NO pool authority. There is deliberately no `_` arm:
//                     adding a proposal variant forces an explicit execution decision.
//   Trust boundary  : the pool itself authenticates that these calls originate from
//                     this staking canister (pool-side controller/governance check,
//                     Lane 1 / shielded-pool — out of scope here). This handler only
//                     guarantees an action is reached after a valid, timelocked vote.
async fn execute_proposal_action(proposal_type: &ProposalType) -> Result<String, String> {
    match proposal_type {
        ProposalType::VerifierKeyUpgrade(payload) => {
            // P3 FIX: validate structural fields only — do NOT re-run the 14-day timing
            // check. By execution time the activation date will be within that window
            // (time passed since creation), so re-running validate() would make every
            // valid VK proposal permanently unexecutable.
            payload.validate_structural()?;
            let pool = POOL_CANISTER.with(|p| p.borrow().ok_or("Pool canister not set".to_string()))?;
            // P3 FIX: old_key_cutoff_ns must be > activation_timestamp_ns so the pool
            // accepts both keys during the grace window (DEF-068: named policy value).
            let old_key_cutoff_ns = payload.activation_timestamp_ns + VK_OLD_KEY_GRACE_NS;
            let _: (Result<(), String>,) = ic_cdk::api::call::call(
                pool,
                "schedule_vk_activation",
                (payload.circuit_version, payload.new_verifying_key_hash, payload.activation_timestamp_ns, old_key_cutoff_ns)
            ).await.map_err(|(_, e)| e)?;
            Ok(format!("VK upgrade scheduled for activation at {}", payload.activation_timestamp_ns))
        }
        ProposalType::RewardScheduleUpdate { new_emission_rate_per_day } => {
            mutate_reward_state(|r| r.emission_rate_per_day = *new_emission_rate_per_day);
            Ok("Emission rate updated".to_string())
        }
        ProposalType::GovernanceParamUpdate(new_params) => {
            // Prevent reducing VK timelock below the DEF-068 policy floor.
            // RETAINED as an independent literal check (DEF-068 rationale) even
            // though validate() also covers it — two independent guards on the
            // Supply-lesson floor is deliberate, not redundancy to collapse.
            let min_vk_timelock = VK_UPGRADE_MIN_TIMELOCK_NS;
            if new_params.vk_upgrade_timelock_ns < min_vk_timelock {
                return Err("VK upgrade timelock cannot be less than 14 days".to_string());
            }
            // K3-015 call site 3/3 — IMMEDIATELY BEFORE APPLYING. A proposal
            // validated at submission can still be executed days later, and the
            // contract must hold at the moment the params take effect.
            new_params.validate()?;
            set_gov_params(new_params.clone());
            Ok("Governance parameters updated".to_string())
        }
        ProposalType::EmergencyPause { target, reason } => {
            let pool = POOL_CANISTER.with(|p| p.borrow().ok_or("Pool canister not set".to_string()))?;
            match target {
                EmergencyPauseTarget::PoolDeposits => {
                    let _: () = ic_cdk::api::call::call(pool, "emergency_pause_deposits", ()).await
                        .map_err(|(_, e)| e)?;
                }
                EmergencyPauseTarget::PoolSpends => {
                    let (pause_result,): (Result<(), String>,) =
                        ic_cdk::api::call::call(pool, "emergency_pause_spends", ()).await
                            .map_err(|(_, e)| e)?;
                    pause_result?;
                }
                EmergencyPauseTarget::Both => {
                    let _: () = ic_cdk::api::call::call(pool, "emergency_pause_deposits", ()).await
                        .map_err(|(_, e)| e)?;
                    let (pause_result,): (Result<(), String>,) =
                        ic_cdk::api::call::call(pool, "emergency_pause_spends", ()).await
                            .map_err(|(_, e)| e)?;
                    pause_result?;
                }
            }
            Ok(format!("Emergency pause applied: {}", reason))
        }
        // DEF-084: inert governance actions must hard-error, never pretend-success.
        // A proposal for an unimplemented action can pass quorum and timelock, but
        // executing it returns a clear Err — voters are never told "executed" for
        // an action that did nothing. No `_` arm: a future variant must add an
        // explicit execution arm here or fail to compile.
        ProposalType::ParameterUpdate { .. } => Err(
            "Unsupported: ParameterUpdate proposal actions are not yet active (DEF-084)".to_string(),
        ),
        ProposalType::TreasurySpend { .. } => Err(
            "Unsupported: TreasurySpend proposal actions are not yet active (DEF-084)".to_string(),
        ),
        ProposalType::FeeUpdate { .. } => Err(
            "Unsupported: FeeUpdate proposal actions are not yet active (DEF-084)".to_string(),
        ),
        ProposalType::CanisterUpgrade { .. } => Err(
            "Unsupported: CanisterUpgrade proposal actions are not yet active (DEF-084)".to_string(),
        ),
    }
}

// ── Queries ───────────────────────────────────────────────────────────────────

#[query]
fn get_stake_positions(holder: Principal) -> Vec<StakePosition> {
    POSITIONS.with(|p| {
        p.borrow().iter()
            .map(|(_, v)| v)
            .filter(|pos| pos.holder == holder)
            .collect()
    })
}

#[query]
fn get_rewards_pool_balance() -> u128 {
    REWARD_STATE.with(|r| r.borrow().rewards_pool_balance)
}

#[query]
fn get_pending_rewards(holder: Principal) -> u128 {
    POSITIONS.with(|p| {
        p.borrow().iter()
            .map(|(_, v)| v)
            .filter(|pos| pos.holder == holder && is_active_position(pos))
            .map(|pos| calculate_claimable(&pos))
            .sum()
    })
}

/// Must disclose funding source breakdown — PM requirement §4.2 rule 4
#[query]
fn get_reward_source_breakdown() -> RewardSourceBreakdown {
    let state = REWARD_STATE.with(|r| r.borrow().clone());
    let total = state.rewards_pool_balance + state.fee_revenue_balance;
    if total == 0 {
        return RewardSourceBreakdown {
            incentive_allocation_pct: 0,
            fee_revenue_pct: 0,
            disclosure: "No rewards pool funded yet".to_string(),
        };
    }
    let incentive_pct = (state.rewards_pool_balance * 100 / total) as u32;
    let fee_pct = (state.fee_revenue_balance * 100 / total) as u32;
    RewardSourceBreakdown {
        incentive_allocation_pct: incentive_pct,
        fee_revenue_pct: fee_pct,
        disclosure: "Early rewards funded by fixed genesis allocation. Protocol fees supplement over time. Not guaranteed sustainable yield.".to_string(),
    }
}

#[query]
fn get_total_voting_weight() -> u128 {
    TOTAL_VOTING_WEIGHT.with(|w| *w.borrow())
}

#[query]
fn list_proposals_by_status(status: Option<ProposalStatus>) -> Vec<Proposal> {
    PROPOSALS_MAP.with(|p| {
        p.borrow().iter()
            .map(|(_, v)| v)
            .filter(|prop| status.as_ref().map(|s| &prop.status == s).unwrap_or(true))
            .collect()
    })
}

#[query]
fn get_governance_params() -> GovernanceParams {
    GOV_PARAMS.with(|g| g.borrow().clone())
}

/// Build info for watcher
#[query]
fn get_build_info() -> String {
    format!("staking v{}", env!("CARGO_PKG_VERSION"))
}

// ── Fee revenue receipt ───────────────────────────────────────────────────────

/// Called by treasury when staker fee share is routed here
#[update]
fn receive_fee_revenue(amount: u128) {
    let treasury = TREASURY_CANISTER.with(|t| t.borrow().unwrap());
    assert_eq!(ic_cdk::caller(), treasury, "Only treasury may call receive_fee_revenue");
    // saturating_add: receive_fee_revenue's signature is `-> ()` (no error
    // channel) and amount is bounded by protocol fee revenue (<< u128::MAX), so
    // this never saturates; saturating prevents wrap without a signature change.
    mutate_reward_state(|s| s.fee_revenue_balance = s.fee_revenue_balance.saturating_add(amount));
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn get_total_voting_weight_for(holder: Principal) -> u128 {
    POSITIONS.with(|p| {
        p.borrow().iter()
            .map(|(_, v)| v)
            .filter(|pos| pos.holder == holder && is_active_position(pos))
            .map(|pos| pos.voting_weight)
            .sum()
    })
}

fn get_total_staked_for(holder: Principal) -> u128 {
    POSITIONS.with(|p| {
        p.borrow().iter()
            .map(|(_, v)| v)
            .filter(|pos| pos.holder == holder && is_active_position(pos))
            .map(|pos| pos.amount)
            .sum()
    })
}

/// C-A1: votes are keyed by (proposal_id, POSITION), not (proposal_id, voter).
/// This is what makes "each snapshotted weight counted at most once for that
/// proposal" enforceable — a Principal-keyed vote cannot express it, because
/// the same principal's position set is not stable over the voting window.
fn make_vote_key(proposal_id: u64, position_id: u64) -> Vec<u8> {
    let mut key = proposal_id.to_be_bytes().to_vec();
    key.extend_from_slice(&position_id.to_be_bytes());
    key
}

/// Is this position eligible for a proposal whose voting closes at
/// `voting_closes_ns`? Evaluated ONCE, at proposal creation.
///
/// Four conditions, each from the spec:
///   - active (not closed, no in-flight lock/unlock op)
///   - non-zero snapshotted weight
///   - lock term at least the 30-day minimum — legacy sub-30d positions are
///     ineligible until relocked compliantly
///   - still locked through the close of voting, so a position cannot vote and
///     then unlock before the outcome it influenced is decided
fn snapshot_eligible(pos: &StakePosition, voting_closes_ns: u64) -> bool {
    is_active_position(pos)
        && pos.voting_weight > 0
        && pos.lock_days >= MIN_LOCK_DAYS
        && pos.lock_end_ns >= voting_closes_ns
}

fn get_token() -> Result<Principal, String> {
    TOKEN_CANISTER.with(|t| t.borrow().ok_or("Token canister not configured".to_string()))
}

// ── Upgrade hooks ─────────────────────────────────────────────────────────────
//
// ── MIGRATION LOG ─────────────────────────────────────────────────────────────
//
// STATE_VERSION 1  (M3 Track C — 2026-06-08)
//   Initial stable-persist.  First version to survive a Wasm upgrade without
//   state loss.
//
//   Serialised into StakingStableState (stable Cell, MEM_STABLE_STATE = MemoryId 4):
//     Canister refs (3): token_canister, pool_canister, treasury_canister
//     Governance (2): gov_params, reward_state
//     Counters (2): next_position_id, next_proposal_id
//
//   Survive upgrade automatically (StableBTreeMap, no serialisation needed):
//     POSITIONS    (MemoryId 0) — all stake positions
//     PENDING_POSITIONS (MemoryId 5) — lock/unlock outcomes pending reconciliation
//     PROPOSALS_MAP (MemoryId 1) — governance proposals
//     VOTES        (MemoryId 2) — per-proposal vote records
//
//   NOT persisted / not live (DEF-060):
//     MemoryId 3 — RESERVED for REWARD_LOG. Not currently instantiated; no
//       stable map exists at this slot today, so nothing survives (or needs to
//       survive) an upgrade here. Future reward-log implementation or formal
//       retirement of the reservation requires a separate PM decision.
//
//   Persisted in a dedicated stable Cell (DEF-059):
//     VOTING_WEIGHT_CELL (MemoryId 6) — TOTAL_VOTING_WEIGHT as { initialized, total }.
//       Updated inline (heap mirror + cell) on every stake/unstake. post_upgrade
//       reads it directly; it backfills from POSITIONS exactly ONCE, on the first
//       upgrade from pre-DEF-059 code (cell decodes to initialized == false). Every
//       subsequent upgrade skips the O(n) scan. Was previously re-derived by
//       summing POSITIONS on every upgrade.
//
//   DEF-052 (no STATE_VERSION bump):
//     PENDING_LOCK_OPS (MemoryId 7, StableBTreeMap<u64, PendingLockOp>) — pending
//       lock/unlock operations awaiting controller reconcile. Survives upgrade
//       automatically. Only genuinely unresolved ops are present.
//     OP_ID_COUNTER (MemoryId 8, StableCell<u64>, default 1) — monotonic op_id
//       source. Survives upgrade automatically; never reused across upgrades.
//     StakePosition gained `op_id: Option<u64>` — a Candid-backward-compatible
//       record extension (legacy records decode as op_id = None; proven by the
//       old-layout decode test in `mod tests`). Not in StakingStableState.
//
//   Upgrade from pre-Track-C code: NOT SUPPORTED.  Attempting an upgrade from
//   code with no pre_upgrade checkpoint triggers the bootstrap trap.  Recovery
//   requires reinstall (init) after settling all in-flight operations.
//
// To add a new version: increment STATE_VERSION, add a migration arm in
// post_upgrade that accepts stored_version == N-1 and upgrades the struct,
// then bump STATE_VERSION to N.  Never rely on field defaults for missing values.

// Upgrade-persistence hardening Phase 2 (2026-07-31) — checkpoint RETIRED
//   - `pre_upgrade` REMOVED. The checkpoint cell (MemoryId 4) is retired and
//     frozen. Every former-checkpoint field is now written EAGERLY at its
//     existing mutation point:
//       token/pool/treasury refs → CANISTER_REFS         (MemoryId 11, grouped)
//       next_position_id         → NEXT_POSITION_ID_CELL (MemoryId 12)
//       next_proposal_id         → NEXT_PROPOSAL_ID_CELL (MemoryId 13)
//       gov_params               → GOV_PARAMS_CELL       (MemoryId 14, grouped)
//       reward_state             → REWARD_STATE_CELL     (MemoryId 15, grouped)
//     This is the DEF-059 / DEF-052 precedent (VOTING_WEIGHT at MemoryId 6,
//     OP_ID_COUNTER at 8 — both already eager and already excluded from the
//     checkpoint) generalised to the whole struct. `StakingStableState` and
//     STATE_VERSION are gone with it: there is no snapshot left to version.
//   - `post_upgrade` is now a fail-closed sentinel gate. An absent or corrupt
//     eager region decodes to the impossible sentinel and traps, rather than
//     silently resurrecting the canister on default governance params and reset
//     id counters.
//   - Upgrading ACROSS the conversion boundary (from a pre-Phase-2 Wasm) traps
//     by design: those regions were never allocated, so the sentinel survives.
//     Nothing is on mainnet; a local/rehearsal canister must be wiped and
//     reinstalled, never upgraded across the boundary.
//   - P-STK's PROPOSAL_SNAPSHOTS (9) and STAKE_DEDUP (10) are already eager
//     stable maps and are untouched. Their atomicity comes from living in the
//     same no-`await` message segment as the mutation that writes them — NOT
//     from any cell, and grouping a map into a cell is not possible.
//   - No DID change: no endpoint signature or Candid type moved.

// ── ATOMICITY: the live mutation paths ───────────────────────────────────────
//
// V2 acceptance #2, made real (Phase 2). `next_position_id` and
// `next_proposal_id` have LIVE mutation paths, so "a rejected operation
// persists no partial scalar" is a claim about running code.
//
// PROOF OBLIGATION, discharged by construction and covered by
// `integration-tests/tests/eager_cell_phase2_tests.rs`:
//
//   1. `alloc_position_id` / `alloc_proposal_id` are the ONLY writers of their
//      cells after `init`. Both are `await`-free, so a DEFINITE local rejection
//      rolls back the whole message segment — the counter cell included.
//   2. Every entry-point rejection in `stake` (C-A2 lock bounds, C-A5 dedup
//      conflict, zero amount) happens BEFORE `alloc_position_id`, and every
//      rejection in `create_proposal` (params validation, proposer eligibility,
//      timestamp overflow) happens BEFORE `alloc_proposal_id`. A rejected call
//      never reaches the allocation at all.
//   3. Retry cannot double-apply. `stake` is the only counter path with an
//      external `await`, and C-A5 makes it idempotent: an identical retry
//      resolves through STAKE_DEDUP to the ORIGINAL position and never reaches
//      `alloc_position_id` a second time. Nothing contingent on confirmed
//      success — the lock, the voting weight, the promotion out of LockPending
//      — was moved ahead of that await in order to persist it earlier; the
//      DEF-052 ordering is unchanged.
//   4. The two id counters are in SEPARATE cells deliberately: different
//      operations at very different frequencies, and `Cell::set` rewrites the
//      whole cell, so grouping would make every stake rewrite the governance
//      counter. The Phase-0 grouping win (2 370 against 4 119) applies only to
//      fields written in the SAME operation — which `gov_params` and
//      `reward_state` are internally, and these two are not.

#[post_upgrade]
fn post_upgrade() {
    // ── Fail-closed sentinel gate — see stsh-eager-cell for the contract ──────
    //
    // EVERY cell is validated BEFORE any heap mirror is populated, so a
    // surviving sentinel can never become observable through a getter.

    let refs = CANISTER_REFS.with(|c| *c.borrow().get());
    let Some([token_canister, pool_canister, treasury_canister]) = refs.get().copied() else {
        ic_cdk::trap(
            "post_upgrade: CANISTER_REFS sentinel survived — no initialised canister \
             references in stable memory (MemoryId 11 absent or unwritten). This canister \
             was never initialised, or is being upgraded from a pre-hardening Wasm that \
             predates the eager cell. Aborting to prevent silent state loss.",
        );
    };

    let position_counter = NEXT_POSITION_ID_CELL.with(|c| *c.borrow().get());
    let Some(next_position_id) = position_counter.get().copied().and_then(|[w]| decode_id_counter(w))
    else {
        ic_cdk::trap(
            "post_upgrade: NEXT_POSITION_ID did not validate — the position counter region \
             (MemoryId 12) is absent, unwritten, zero, or above u64::MAX. Resuming would \
             restart position ids (or narrow a truncated one) and let a new stake overwrite \
             an existing position. Aborting.",
        );
    };

    let proposal_counter = NEXT_PROPOSAL_ID_CELL.with(|c| *c.borrow().get());
    let Some(next_proposal_id) = proposal_counter.get().copied().and_then(|[w]| decode_id_counter(w))
    else {
        ic_cdk::trap(
            "post_upgrade: NEXT_PROPOSAL_ID did not validate — the proposal counter region \
             (MemoryId 13) is absent, unwritten, zero, or above u64::MAX. Resuming would \
             restart proposal ids (or narrow a truncated one) and let a new proposal \
             collide with a stored one and its snapshot. Aborting.",
        );
    };

    let gov_params_cell = GOV_PARAMS_CELL.with(|c| *c.borrow().get());
    let Some(gov_params) = gov_params_from_cell(&gov_params_cell) else {
        ic_cdk::trap(
            "post_upgrade: GOV_PARAMS sentinel survived — the governance parameter region \
             (MemoryId 14) is absent, unwritten, or does not decode. Resuming on compiled \
             defaults would silently replace the parameters governance actually voted in. \
             Aborting.",
        );
    };

    let reward_state_cell = REWARD_STATE_CELL.with(|c| *c.borrow().get());
    let Some(reward_state) = reward_state_from_cell(&reward_state_cell) else {
        ic_cdk::trap(
            "post_upgrade: REWARD_STATE sentinel survived — the reward accounting region \
             (MemoryId 15) is absent, unwritten, or does not decode. Resuming on a zeroed \
             record would erase the reward pool balance. Aborting.",
        );
    };

    // ── Restore all heap mirrors — NO defaults ────────────────────────────────

    TOKEN_CANISTER.with(|s|    *s.borrow_mut() = Some(token_canister));
    POOL_CANISTER.with(|s|     *s.borrow_mut() = Some(pool_canister));
    TREASURY_CANISTER.with(|s| *s.borrow_mut() = Some(treasury_canister));
    GOV_PARAMS.with(|s|        *s.borrow_mut() = gov_params);
    REWARD_STATE.with(|s|      *s.borrow_mut() = reward_state);
    NEXT_POSITION_ID.with(|s|  *s.borrow_mut() = next_position_id);
    NEXT_PROPOSAL_ID.with(|s|  *s.borrow_mut() = next_proposal_id);

    // ── DEF-059: restore TOTAL_VOTING_WEIGHT from the stable cell ──────────────
    //
    // No O(n) reconstruction on normal upgrades. The cell is authoritative once
    // initialized. The ONLY scan is the one-time backfill for a canister upgraded
    // from pre-DEF-059 code, where the cell region is fresh and decodes to the
    // default { initialized: false, total: 0 }. After that single backfill the
    // marker is set true and every subsequent upgrade skips the scan entirely.
    //
    // The marker — not a total == 0 sentinel — gates the backfill: a live state can
    // legitimately be total == 0 (all stakers unstaked) with positions still in the
    // map; a zero sentinel would wrongly re-scan and overwrite the correct zero.
    let vw = VOTING_WEIGHT_CELL.with(|c| c.borrow().get().clone());
    if vw.initialized {
        // Authoritative — load into the heap mirror, no scan.
        TOTAL_VOTING_WEIGHT.with(|w| *w.borrow_mut() = vw.total);
    } else {
        // One-time backfill from POSITIONS (active, non-pending only), then persist
        // with initialized = true so this path is unreachable on future upgrades.
        let backfilled: u128 = POSITIONS.with(|p| {
            p.borrow().iter()
                .filter(|(_, pos)| is_active_position(pos))
                .map(|(_, pos)| pos.voting_weight)
                .sum()
        });
        set_total_voting_weight(backfilled);
    }
}

// =============================================================================
// NEGATIVE / SECURITY TESTS — M1.5 Acceptance Gate
// Tests 11-15 per PM brief.
// Tests 14-15 require pocket-ic (cross-canister governance) — marked #[ignore].
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── SSA P1 (2026-07-31): counter decoding must FAIL CLOSED ───────────────
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

    const TEST_NOW_NS: u64 = 2_000_000_000_000_000_000u64; // arbitrary fixed timestamp

    // DEF-052: prove `op_id: Option<u64>` is a backward-compatible Candid record
    // extension. A position serialized with the pre-DEF-052 layout (no op_id) must
    // decode into the current StakePosition with op_id = None — never panic, never
    // produce a wrong value. Existing Active positions must therefore survive the
    // upgrade without becoming unreconcilable.
    #[test]
    fn def052_legacy_stake_position_decodes_with_none_op_id() {
        #[derive(CandidType, Serialize, Deserialize)]
        struct LegacyStakePosition {
            position_id:     u64,
            holder:          Principal,
            amount:          u128,
            lock_days:       u32,
            lock_end_ns:     u64,
            voting_weight:   u128,
            rewards_claimed: u128,
            last_claim_ns:   u64,
            created_at_ns:   u64,
            closed:          bool,
        }

        let legacy = LegacyStakePosition {
            position_id: 7, holder: Principal::anonymous(), amount: 100, lock_days: 30,
            lock_end_ns: 123, voting_weight: 100, rewards_claimed: 0, last_claim_ns: 1,
            created_at_ns: 1, closed: false,
        };
        let bytes = candid::encode_one(&legacy).expect("encode legacy position");
        let decoded: StakePosition =
            candid::decode_one(&bytes).expect("legacy position must decode into the new struct");

        assert_eq!(decoded.position_id, 7);
        assert_eq!(decoded.amount, 100);
        assert_eq!(decoded.voting_weight, 100);
        assert!(!decoded.closed);
        assert_eq!(decoded.op_id, None, "legacy StakePosition must decode with op_id = None");
    }

    // ── P-STK P1-2: PendingLockOp gained `dedup_key` inside an EXISTING stable
    //    map (MemoryId 7), so a record written by the pre-fix code must still
    //    decode. Same backward-compatible-Candid-extension proof as DEF-052
    //    above, for the field the P1-2 fix added.
    //
    //    This matters operationally: a pending lock op stranded mid-flight by an
    //    upgrade is exactly the record a controller needs to reconcile, and a
    //    decode failure there would make it permanently unreconcilable.
    #[test]
    fn pstk_legacy_pending_lock_op_decodes_with_none_dedup_key() {
        /// The PendingLockOp layout as it existed at 0b88405 — no `dedup_key`.
        #[derive(CandidType, Serialize, Deserialize)]
        struct LegacyPendingLockOp {
            op_id:           u64,
            position_id:     u64,
            holder:          Principal,
            amount:          u128,
            op_type:         LockOpType,
            initiated_at_ns: u64,
            snapshot:        StakePosition,
        }

        let snapshot = StakePosition {
            position_id: 11, holder: Principal::anonymous(), amount: 500,
            lock_days: MIN_LOCK_DAYS, lock_end_ns: 999, voting_weight: 500,
            rewards_claimed: 0, last_claim_ns: 0, created_at_ns: 0, closed: false,
            op_id: None,
        };
        let legacy = LegacyPendingLockOp {
            op_id: 3, position_id: 11, holder: Principal::anonymous(), amount: 500,
            op_type: LockOpType::Lock, initiated_at_ns: 42, snapshot: snapshot.clone(),
        };

        let bytes = candid::encode_one(&legacy).expect("encode legacy pending op");
        let decoded: PendingLockOp =
            candid::decode_one(&bytes).expect("legacy PendingLockOp must decode into the new struct");

        assert_eq!(decoded.op_id, 3);
        assert_eq!(decoded.position_id, 11);
        assert_eq!(decoded.amount, 500);
        assert_eq!(decoded.op_type, LockOpType::Lock);
        assert_eq!(decoded.snapshot.position_id, snapshot.position_id);
        assert_eq!(
            decoded.dedup_key, None,
            "a pre-P1-2 PendingLockOp must decode with dedup_key = None — reconciliation \
             then simply has no key to release, which is correct: the record predates \
             dedup tracking entirely"
        );
    }

    /// A new-layout op round-trips its key, so the release path in
    /// `reconcile_lock(NotExecuted)` receives the bytes it was given.
    #[test]
    fn pstk_new_pending_lock_op_roundtrips_dedup_key() {
        let snapshot = StakePosition {
            position_id: 12, holder: Principal::anonymous(), amount: 1,
            lock_days: MIN_LOCK_DAYS, lock_end_ns: 1, voting_weight: 1,
            rewards_claimed: 0, last_claim_ns: 0, created_at_ns: 0, closed: false,
            op_id: Some(4),
        };
        let op = PendingLockOp {
            op_id: 4, position_id: 12, holder: Principal::anonymous(), amount: 1,
            op_type: LockOpType::Lock, initiated_at_ns: 0, snapshot,
            dedup_key: Some(b"round-trip".to_vec()),
        };
        let decoded: PendingLockOp =
            candid::decode_one(&candid::encode_one(&op).unwrap()).expect("round-trip");
        assert_eq!(decoded.dedup_key.as_deref(), Some(&b"round-trip"[..]));
    }

    // A new-layout position round-trips its op_id.
    #[test]
    fn def052_new_stake_position_roundtrips_op_id() {
        let pos = StakePosition {
            position_id: 9, holder: Principal::anonymous(), amount: 50, lock_days: 0,
            lock_end_ns: 0, voting_weight: 50, rewards_claimed: 0, last_claim_ns: 0,
            created_at_ns: 0, closed: false, op_id: Some(42),
        };
        let bytes = candid::encode_one(&pos).expect("encode new position");
        let decoded: StakePosition = candid::decode_one(&bytes).expect("decode new position");
        assert_eq!(decoded.op_id, Some(42));
    }

    /// Helper: construct a fully valid VK upgrade payload.
    fn valid_vk_payload() -> VerifierKeyUpgradePayload {
        VerifierKeyUpgradePayload {
            old_verifying_key_hash:      [1u8; 32],
            new_verifying_key_hash:      [2u8; 32],
            circuit_version:             2,
            proof_system_id:             "groth16-bn254".to_string(),
            audit_artifact_url:          "https://audit.example.com/stsh-v2.pdf".to_string(),
            audit_artifact_hash:         [3u8; 32],
            circuit_source_commit:       "abc1234567890abcdef1234567890abcdef123456".to_string(),
            verifier_wasm_hash:          [4u8; 32],
            // 15 days from TEST_NOW_NS — comfortably above the 14-day floor
            activation_timestamp_ns:     TEST_NOW_NS + 15 * 24 * 60 * 60 * 1_000_000_000u64,
            emergency_disable_supported: true,
        }
    }

    // ── Test 11: VK upgrade with empty audit_artifact_url is hard-rejected ─────
    //
    // INVARIANT (PM brief §5): VerifierKeyUpgrade proposals must carry a published
    // audit artifact URL. Any empty URL must be rejected at proposal creation.
    // This prevents governance from silently upgrading the circuit without an audit trail.
    #[test]
    fn test_11_vk_empty_audit_url_rejected() {
        let mut payload = valid_vk_payload();
        payload.audit_artifact_url = String::new();

        let result = payload.validate_at(TEST_NOW_NS);

        assert!(result.is_err(), "Empty audit_artifact_url must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("audit_artifact_url"),
            "Error must name the failing field; got: {:?}", err
        );
    }

    // ── Test 12: VK upgrade with all-zeros audit_artifact_hash is hard-rejected ─
    //
    // INVARIANT: The audit hash must be the actual SHA-256 of the audit document.
    // All-zeros is a sentinel "not provided" value — must be rejected.
    // This prevents proposals that reference a URL but haven't committed to a hash.
    #[test]
    fn test_12_vk_zero_audit_hash_rejected() {
        let mut payload = valid_vk_payload();
        payload.audit_artifact_hash = [0u8; 32]; // all-zeros sentinel

        let result = payload.validate_at(TEST_NOW_NS);

        assert!(result.is_err(), "All-zeros audit_artifact_hash must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("audit_artifact_hash"),
            "Error must name the failing field; got: {:?}", err
        );
    }

    // ── Test 13: VK activation_timestamp less than 14 days away is rejected ────
    //
    // INVARIANT (PM brief §5): minimum 14-day activation window is mandatory.
    // This gives governance / community time to detect and challenge suspect upgrades.
    // "14 days" is the boundary: 13 days must fail, exactly 14 days must pass.
    #[test]
    fn test_13_vk_activation_before_14days_rejected() {
        let mut payload = valid_vk_payload();
        // 13 days 23 hours 59 minutes 59 seconds — one second short of 14 days
        payload.activation_timestamp_ns =
            TEST_NOW_NS + 14 * 24 * 60 * 60 * 1_000_000_000u64 - 1;

        let result = payload.validate_at(TEST_NOW_NS);

        assert!(result.is_err(), "Activation < 14 days must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("14 days"),
            "Error must cite the 14-day requirement; got: {:?}", err
        );
    }

    // ── Test 13b: Activation exactly 14 days from now is accepted (boundary) ───
    #[test]
    fn test_13b_vk_activation_exactly_14days_accepted() {
        let mut payload = valid_vk_payload();
        payload.activation_timestamp_ns =
            TEST_NOW_NS + 14 * 24 * 60 * 60 * 1_000_000_000u64; // exact boundary

        let result = payload.validate_at(TEST_NOW_NS);

        assert!(
            result.is_ok(),
            "Activation exactly 14 days from now must be accepted; got: {:?}", result
        );
    }

    // Tests 14-17: P3 fix — validate_structural vs validate_at split
    //
    // The core invariant: validate_at() enforces the 14-day window at proposal creation;
    // validate_structural() omits timing so execute_proposal_action() can call it after
    // time has elapsed without re-blocking a legitimately scheduled proposal.

    // ── Test 14: validate_structural passes when activation is in the past ────────
    //
    // INVARIANT (P3 fix): By execution time, activation_timestamp is close (may even be
    // past). validate_structural() must not check timing. If it did, every valid VK
    // proposal would become permanently unexecutable once its activation window passed.
    #[test]
    fn test_14_validate_structural_ignores_past_activation() {
        let mut payload = valid_vk_payload();
        // Set activation to exactly NOW — clearly within the 14-day rejection window
        payload.activation_timestamp_ns = TEST_NOW_NS;

        // validate_at should reject this (timing check)
        assert!(
            payload.validate_at(TEST_NOW_NS).is_err(),
            "validate_at must reject activation == now (< 14 days)"
        );

        // validate_structural must accept it (no timing check)
        let result = payload.validate_structural();
        assert!(
            result.is_ok(),
            "validate_structural must accept payload with past activation; got: {:?}", result
        );
    }

    // ── Test 15: validate_structural still rejects empty audit URL ────────────────
    //
    // INVARIANT: validate_structural runs full field checks — it only skips timing.
    // A payload with an empty audit_artifact_url must still be rejected at execution.
    #[test]
    fn test_15_validate_structural_rejects_empty_audit_url() {
        let mut payload = valid_vk_payload();
        payload.audit_artifact_url = String::new();

        let result = payload.validate_structural();

        assert!(result.is_err(), "validate_structural must reject empty audit_artifact_url");
        let err = result.unwrap_err();
        assert!(
            err.contains("audit_artifact_url"),
            "Error must name audit_artifact_url; got: {:?}", err
        );
    }

    // ── Test 16: validate_structural still rejects zero new_verifying_key_hash ────
    //
    // INVARIANT: A zero hash is a sentinel "not provided" value. Even at execution
    // time, validate_structural must reject it.
    #[test]
    fn test_16_validate_structural_rejects_zero_new_vk_hash() {
        let mut payload = valid_vk_payload();
        payload.new_verifying_key_hash = [0u8; 32];

        let result = payload.validate_structural();

        assert!(result.is_err(), "validate_structural must reject zero new_verifying_key_hash");
        let err = result.unwrap_err();
        assert!(
            err.contains("new_verifying_key_hash"),
            "Error must name new_verifying_key_hash; got: {:?}", err
        );
    }

    // ── Test 17: validate_at delegates to validate_structural for field checks ────
    //
    // INVARIANT: validate_at is validate_structural + timing. A payload that fails a
    // structural check (empty proof_system_id) must be rejected by validate_at with
    // the same field-level error, not swallowed by the timing check.
    #[test]
    fn test_17_validate_at_propagates_structural_errors() {
        let mut payload = valid_vk_payload();
        payload.proof_system_id = String::new(); // structural failure

        // Both validators must reject, but for the same field reason
        let structural_err = payload.validate_structural().unwrap_err();
        let full_err = payload.validate_at(TEST_NOW_NS).unwrap_err();

        assert!(
            structural_err.contains("proof_system_id"),
            "validate_structural error must name proof_system_id; got: {:?}", structural_err
        );
        assert_eq!(
            structural_err, full_err,
            "validate_at must propagate structural errors unchanged"
        );
    }

    // Tests for governance privilege separation via cross-canister round-trips
    // (e.g. VK proposal executes after full timelock, ordinary proposals cannot
    // schedule VK) are in integration-tests/tests/security_tests.rs — require
    // real PocketIC multi-canister deployment.
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
// `which` selects the cell: "refs" | "next_position_id" | "next_proposal_id" |
// "gov_params" | "reward_state".
#[cfg(feature = "testing")]
#[query]
fn eager_cell_probe_for_test(which: String) -> Vec<u8> {
    match which.as_str() {
        "refs" => CANISTER_REFS.with(|c| c.borrow().get().to_bytes().into_owned()),
        "next_position_id" => {
            NEXT_POSITION_ID_CELL.with(|c| c.borrow().get().to_bytes().into_owned())
        }
        "next_proposal_id" => {
            NEXT_PROPOSAL_ID_CELL.with(|c| c.borrow().get().to_bytes().into_owned())
        }
        "gov_params" => GOV_PARAMS_CELL.with(|c| c.borrow().get().to_bytes().into_owned()),
        "reward_state" => REWARD_STATE_CELL.with(|c| c.borrow().get().to_bytes().into_owned()),
        other => ic_cdk::trap(&format!("eager_cell_probe_for_test: unknown cell `{other}`")),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  W3 3-3 — PUBLISHED-FIELD LOCK (field drift, RA2)
//
//  Same contract as the pool's lock (see shielded-pool/src/lib.rs): the .did
//  and the Rust record must carry the SAME field set, so a field removed from
//  either side fails the gate. Candid subtyping makes the omission silent
//  otherwise, and the did-vs-exports lint is method-level only.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod w3_33_did_field_lock_tests {
    use super::*;
    use candid::types::{Type, TypeEnv, TypeInner};
    use std::collections::BTreeSet;

    const STAKING_DID: &str = include_str!("../staking.did");

    fn did_record(name: &str) -> Vec<(String, String)> {
        let prog: candid_parser::IDLProg = STAKING_DID.parse().expect("staking.did must parse");
        let mut env = TypeEnv::new();
        candid_parser::check_prog(&mut env, &prog)
            .expect("staking.did must type-check")
            .expect("staking.did must have an actor");
        let mut t: Type = env
            .find_type(name)
            .unwrap_or_else(|_| panic!("{name} must be declared in staking.did"))
            .clone();
        loop {
            let next = match &*t {
                TypeInner::Var(n) => env
                    .find_type(n)
                    .unwrap_or_else(|_| panic!("type var {n} not found"))
                    .clone(),
                _ => break,
            };
            t = next;
        }
        match &*t {
            TypeInner::Record(fields) => fields
                .iter()
                .map(|f| (f.id.to_string(), f.ty.to_string()))
                .collect(),
            other => panic!("expected {name} to be a record, got {other:?}"),
        }
    }

    fn rust_field_names<T: CandidType>() -> BTreeSet<String> {
        match &*T::ty() {
            TypeInner::Record(fields) => fields.iter().map(|f| f.id.to_string()).collect(),
            other => panic!("expected a Rust record type, got {other:?}"),
        }
    }

    fn names(fields: &[(String, String)]) -> BTreeSet<String> {
        fields.iter().map(|(n, _)| n.clone()).collect()
    }

    fn ty_of(fields: &[(String, String)], field: &str) -> String {
        fields
            .iter()
            .find(|(n, _)| n == field)
            .unwrap_or_else(|| panic!("field `{field}` missing from the .did record"))
            .1
            .clone()
    }

    #[test]
    fn proposal_did_publishes_every_rust_field() {
        assert_eq!(
            names(&did_record("Proposal")),
            rust_field_names::<Proposal>(),
            "Proposal field drift between staking.did and the Rust record"
        );
    }

    #[test]
    fn pending_lock_op_did_publishes_every_rust_field() {
        assert_eq!(
            names(&did_record("PendingLockOp")),
            rust_field_names::<PendingLockOp>(),
            "PendingLockOp field drift between staking.did and the Rust record"
        );
    }

    #[test]
    fn w3_33_published_staking_fields_carry_the_declared_types() {
        // The quorum DENOMINATOR: `opt` because null is the fail-closed legacy
        // marker execute_proposal refuses on — a reader must be able to see it.
        assert_eq!(
            ty_of(&did_record("Proposal"), "snapshot_total_weight"),
            "opt nat",
            "Proposal.snapshot_total_weight"
        );
        // The dedup key a RESOLVED-NotExecuted reconcile releases.
        assert_eq!(
            ty_of(&did_record("PendingLockOp"), "dedup_key"),
            "opt blob",
            "PendingLockOp.dedup_key"
        );
    }
}

#[cfg(test)]
mod w2_2_5r_reconcile_tests {
    use super::*;

        // ── W2 2-5R: stuck-Executing reconcile, every branch ─────────────────────
        //
        // These exercise `decide_reconcile`, the pure core the endpoint applies.
        // The endpoint itself is a thin wrapper (controller gate + map read + apply
        // + map write), so a branch proved here is the branch that runs on-chain.

        const T: u64 = STUCK_PROPOSAL_RECONCILE_THRESHOLD_NS;

        fn proposal_in(status: ProposalStatus, started: Option<u64>, result: Option<String>) -> Proposal {
            Proposal {
                id: 1,
                proposer: Principal::anonymous(),
                proposal_type: ProposalType::ParameterUpdate { key: "k".into(), value: "v".into() },
                description: "t".into(),
                status,
                created_at_ns: 0,
                voting_opens_ns: 0,
                voting_closes_ns: 0,
                execute_after_ns: 0,
                votes_for: 0,
                votes_against: 0,
                snapshot_total_weight: Some(1),
                executed_at_ns: None,
                execution_result: result,
                execution_started_at_ns: started,
            }
        }

        #[test]
        fn reconcile_executed_arm_writes_terminal_status_and_executed_at() {
            let p = proposal_in(ProposalStatus::Executing, Some(0), None);
            match decide_reconcile(&p, &ProposalReconcileDecision::Executed, T) {
                ReconcileOutcome::Commit { status, executed_at_ns, execution_result } => {
                    assert_eq!(status, ProposalStatus::Executed);
                    // The load-bearing half of R2: without executed_at_ns a later
                    // execute_proposal passes BOTH guards and re-issues the action.
                    assert_eq!(executed_at_ns, T, "executed_at_ns must be written, not left None");
                    assert!(
                        execution_result.starts_with(RECONCILED_RESULT_PREFIX),
                        "provenance must be on the record: {execution_result}"
                    );
                }
                other => panic!("expected Commit, got {other:?}"),
            }
        }

        #[test]
        fn reconcile_not_executed_arm_is_terminal_and_never_retries() {
            let p = proposal_in(ProposalStatus::Executing, Some(0), None);
            match decide_reconcile(&p, &ProposalReconcileDecision::NotExecuted, T) {
                ReconcileOutcome::Commit { status, executed_at_ns, execution_result } => {
                    // Rejected, NOT back to a re-executable state: the outbound
                    // action may have landed (lib.rs no-retry comment).
                    assert_eq!(status, ProposalStatus::Rejected);
                    assert_eq!(executed_at_ns, T, "the NotExecuted arm must also close the retry guard");
                    assert!(execution_result.contains("NotExecuted"));
                    assert!(execution_result.starts_with(RECONCILED_RESULT_PREFIX));
                }
                other => panic!("expected Commit, got {other:?}"),
            }
        }

        #[test]
        fn reconciled_result_is_distinguishable_from_an_ordinary_execution_result() {
            // An operator reading execution_result later must be able to tell
            // "this executed" from "a human adjudicated it".
            let p = proposal_in(ProposalStatus::Executing, Some(0), None);
            let ordinary = "action applied";
            match decide_reconcile(&p, &ProposalReconcileDecision::Executed, T) {
                ReconcileOutcome::Commit { execution_result, .. } => {
                    assert!(!ordinary.starts_with(RECONCILED_RESULT_PREFIX));
                    assert!(execution_result.starts_with(RECONCILED_RESULT_PREFIX));
                }
                other => panic!("expected Commit, got {other:?}"),
            }
        }

        #[test]
        fn terminal_replay_from_executed_mutates_nothing_and_returns_stored_result() {
            let stored = Some("action applied".to_string());
            let p = proposal_in(ProposalStatus::Executed, Some(0), stored.clone());
            assert_eq!(
                decide_reconcile(&p, &ProposalReconcileDecision::NotExecuted, T + 1),
                ReconcileOutcome::Replay { status: ProposalStatus::Executed, execution_result: stored },
                "replay must return history and ignore the supplied decision"
            );
        }

        #[test]
        fn terminal_replay_from_rejected_with_no_stored_result_returns_none_not_a_fabrication() {
            // The approval-failure path writes Rejected with NO execution_result.
            // Replay must report that absence as history, never synthesise a string.
            let p = proposal_in(ProposalStatus::Rejected, None, None);
            assert_eq!(
                decide_reconcile(&p, &ProposalReconcileDecision::Executed, T + 1),
                ReconcileOutcome::Replay { status: ProposalStatus::Rejected, execution_result: None }
            );
        }

        #[test]
        fn illegal_source_states_are_refused_by_name_without_mutation() {
            for status in [
                ProposalStatus::VotingPending,
                ProposalStatus::VotingOpen,
                ProposalStatus::VotingClosed,
                ProposalStatus::Passed,
                ProposalStatus::Expired,
                ProposalStatus::Cancelled,
            ] {
                let p = proposal_in(status.clone(), Some(0), None);
                assert_eq!(
                    decide_reconcile(&p, &ProposalReconcileDecision::Executed, T + 1),
                    ReconcileOutcome::Refuse(ProposalReconcileErrorKind::NotStuck(status.clone())),
                    "{status:?} must be refused by name"
                );
            }
        }

        #[test]
        fn threshold_boundary_t_minus_one_refuses_and_t_admits() {
            let p = proposal_in(ProposalStatus::Executing, Some(0), None);
            match decide_reconcile(&p, &ProposalReconcileDecision::Executed, T - 1) {
                ReconcileOutcome::Refuse(ProposalReconcileErrorKind::TooYoung { age_ns, threshold_ns }) => {
                    assert_eq!(age_ns, T - 1);
                    assert_eq!(threshold_ns, T, "the error names both numbers");
                }
                other => panic!("T-1 must refuse, got {other:?}"),
            }
            assert!(
                matches!(
                    decide_reconcile(&p, &ProposalReconcileDecision::Executed, T),
                    ReconcileOutcome::Commit { .. }
                ),
                "exactly T must admit"
            );
        }

        #[test]
        fn a_future_stamp_refuses_rather_than_underflowing_into_an_admitting_age() {
            // A stamp ahead of `now` must not wrap into a huge age. Non-wrapping
            // arithmetic yields 0 and refuses.
            let p = proposal_in(ProposalStatus::Executing, Some(u64::MAX), None);
            match decide_reconcile(&p, &ProposalReconcileDecision::Executed, 1_000) {
                ReconcileOutcome::Refuse(ProposalReconcileErrorKind::TooYoung { age_ns, .. }) => {
                    assert_eq!(age_ns, 0, "a future stamp must read as age 0, never as wrapped-huge");
                }
                other => panic!("a future stamp must refuse, got {other:?}"),
            }
        }

        #[test]
        fn legacy_executing_without_a_stamp_initializes_the_clock_instead_of_refusing_forever() {
            // The class the lane exists to recover: stranded by the very upgrade
            // that introduced the field, or by the documented trap edge.
            let legacy = proposal_in(ProposalStatus::Executing, None, None);
            assert_eq!(
                decide_reconcile(&legacy, &ProposalReconcileDecision::Executed, 5_000),
                ReconcileOutcome::InitializeClock { observed_at_ns: 5_000 },
                "a legacy record must start a clock, not be refused permanently"
            );
        }

        #[test]
        fn legacy_clock_sequence_stamp_then_refuse_then_decide_and_never_advance() {
            // (i) first observation stamps and refuses
            let legacy = proposal_in(ProposalStatus::Executing, None, None);
            let observed = 5_000u64;
            assert_eq!(
                decide_reconcile(&legacy, &ProposalReconcileDecision::Executed, observed),
                ReconcileOutcome::InitializeClock { observed_at_ns: observed }
            );

            // The endpoint applies that stamp; from here the record carries it.
            let stamped = proposal_in(ProposalStatus::Executing, Some(observed), None);

            // (ii) a second call before the threshold still refuses...
            match decide_reconcile(&stamped, &ProposalReconcileDecision::Executed, observed + T - 1) {
                ReconcileOutcome::Refuse(ProposalReconcileErrorKind::TooYoung { age_ns, .. }) => {
                    assert_eq!(age_ns, T - 1);
                }
                other => panic!("expected TooYoung, got {other:?}"),
            }

            // (iii) ...and (iv) no intervening call advanced the stamp: the full
            // threshold is measured from the ORIGINAL observation, so the decision
            // becomes possible exactly at observed + T. If a repeated call had
            // re-stamped, this would still be refusing.
            assert!(
                matches!(
                    decide_reconcile(&stamped, &ProposalReconcileDecision::Executed, observed + T),
                    ReconcileOutcome::Commit { .. }
                ),
                "decidable at observed + T; a re-stamping implementation would refuse here"
            );

            // And the stamp branch is unreachable once the field is Some — the
            // structural reason the stamp can never be advanced.
            assert!(
                !matches!(
                    decide_reconcile(&stamped, &ProposalReconcileDecision::Executed, observed + 1),
                    ReconcileOutcome::InitializeClock { .. }
                ),
                "a stamped record must never re-enter the clock-initializing branch"
            );
        }

        #[test]
        fn a_legacy_stamp_can_only_understate_the_true_age_never_overstate_it() {
            // Safety direction: the true start is no later than the observation, so
            // elapsed-since-observation <= true age. It can refuse too long; it can
            // never permit too early. Contrast with `now - execute_after_ns`, an
            // UPPER bound, which would admit while the true age is far below T.
            let true_start = 1_000u64;
            let observed_at = 9_000u64; // observation is later than the true start
            let now = observed_at + T;
            let age_from_observation = now.saturating_sub(observed_at);
            let true_age = now.saturating_sub(true_start);
            assert!(age_from_observation <= true_age, "observation-based age must understate");

            let upper_bound_age = now.saturating_sub(0); // now - execute_after_ns shape
            assert!(upper_bound_age >= true_age, "the rejected substitute overstates — fires too early");
        }

    // §1.2a item 2 — the old-layout decode test. A Proposal serialized WITHOUT
    // `execution_started_at_ns` must decode with the field as None, not fail.
    // This is what makes the legacy `Executing + None` class real evidence
    // rather than an assumption: those records must decode before they can be
    // reconciled at all, and a decode failure would make exactly the records
    // this lane exists to recover permanently unreadable.
    #[test]
    fn w2_2_5r_legacy_proposal_decodes_with_none_execution_started_at_ns() {
        /// The Proposal layout as it existed before this lane.
        #[derive(CandidType, Serialize, Deserialize)]
        struct LegacyProposal {
            id: u64,
            proposer: Principal,
            proposal_type: ProposalType,
            description: String,
            status: ProposalStatus,
            created_at_ns: u64,
            voting_opens_ns: u64,
            voting_closes_ns: u64,
            execute_after_ns: u64,
            votes_for: u128,
            votes_against: u128,
            snapshot_total_weight: Option<u128>,
            executed_at_ns: Option<u64>,
            execution_result: Option<String>,
        }

        let legacy = LegacyProposal {
            id: 7,
            proposer: Principal::anonymous(),
            proposal_type: ProposalType::ParameterUpdate { key: "k".into(), value: "v".into() },
            description: "stranded by the upgrade that added the field".into(),
            status: ProposalStatus::Executing,
            created_at_ns: 1,
            voting_opens_ns: 2,
            voting_closes_ns: 3,
            execute_after_ns: 4,
            votes_for: 10,
            votes_against: 0,
            snapshot_total_weight: Some(10),
            executed_at_ns: None,
            execution_result: None,
        };

        let bytes = candid::encode_one(&legacy).expect("encode legacy proposal");
        let decoded: Proposal = candid::decode_one(&bytes).expect("legacy proposal must still decode");

        assert_eq!(decoded.execution_started_at_ns, None, "absent field must decode as None");
        assert_eq!(decoded.status, ProposalStatus::Executing);
        assert_eq!(decoded.executed_at_ns, None);

        // And such a record is exactly the legacy class the endpoint recovers.
        assert_eq!(
            decide_reconcile(&decoded, &ProposalReconcileDecision::Executed, 12_345),
            ReconcileOutcome::InitializeClock { observed_at_ns: 12_345 },
        );
    }
}
