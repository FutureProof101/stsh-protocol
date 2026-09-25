// =============================================================================
// STSH Vesting Canister
// Build plan: M1 — Supply Allocation Canisters
// =============================================================================
//
// Manages cliff + linear vesting schedules for team and advisor allocations.
// All schedules are public and readable by anyone.
//
// Team:    12-month cliff, then 36-month linear (48 months total)
// Advisors: 6-month cliff, then 24-month linear (30 months total)
//
// Cliff: no tokens claimable until cliff_end
// Linear: after cliff, (elapsed / total_linear_period) * total_amount claimable
// =============================================================================

use candid::{CandidType, Nat, Principal};
use stsh_eager_cell::PrincipalRefs;
use ic_cdk::api::{call::call, time};
use ic_cdk_macros::{init, post_upgrade, query, update};
use ic_stable_structures::{
    cell::Cell,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    DefaultMemoryImpl, StableBTreeMap, Storable,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;

const MEM_SCHEDULES:    MemoryId = MemoryId::new(0);
// ── RETIRED MemoryId — NEVER RECYCLE ─────────────────────────────────────────
//
// MemoryId 1 held the pre-hardening `STABLE_STATE` checkpoint cell (Candid
// `VestingStableState`, written by `pre_upgrade`). Retired by upgrade-persistence
// hardening Phase 1. Deliberately NOT allocated, and MUST NEVER be reused —
// recycling it would silently reinterpret the old checkpoint bytes as a new
// type. Frozen forever — see docs/MEMORY_ID_REGISTRY.md.
//
// const MEM_STABLE_STATE: MemoryId = MemoryId::new(1);   // RETIRED
const MEM_TRANSFER_OUTCOME_UNKNOWN: MemoryId = MemoryId::new(2);

/// Eager cell holding BOTH canister references (replaces the MemoryId 1
/// checkpoint).
const MEM_CANISTER_REFS: MemoryId = MemoryId::new(3);

// ── L0 custody-vault allocation for lane L3b (F-3) ───────────────────────────
// MemoryId 4: terminal claim tombstone (CUSTODY_VAULT_INTERFACE_FREEZE_V6 §7).
// Allocated by L0 in the single campaign-wide MemoryId change so the registry
// lint and docs/MEMORY_ID_REGISTRY.md agree. Lane L3b lands the tombstone
// itself here: an insert-once durable record, mirroring the pool's
// `write_reconciliation_tombstone` pattern, that replaces marker removal as
// the claim-resolution evidence trail. Never deletable, never prunable,
// survives post_upgrade (StableBTreeMap, no serialization needed).
const MEM_TERMINAL_CLAIM_TOMBSTONES: MemoryId = MemoryId::new(4);

/// `PrincipalRefs<2>` — [token_canister, controller], GROUPED deliberately.
///
/// These two are set together, exactly once, in `init`, and are meaningless
/// apart: a vesting canister with a token but no controller (or vice versa) is
/// not a valid state. Grouping makes them one atomic durable write, so they can
/// never be observed half-applied. Phase 0 measured grouping as *cheaper* too
/// (2 370 vs 4 119 instructions for two separate raw cells) — but atomicity is
/// the reason, not cost. Fields that mutate INDEPENDENTLY must not be grouped:
/// `Cell::set` rewrites the whole cell.
type CanisterRefsCell = PrincipalRefs<2>;
type Mem = VirtualMemory<DefaultMemoryImpl>;


// ── Upgrade-stable state snapshot ─────────────────────────────────────────────


// DEF-051 / QA-DEF-005: enriched with `pending_amount` so a controller reconcile
// can revert `claimed` by exactly the stuck amount on NotExecuted. The new field
// is Option<u128> so legacy markers (pre-DEF-051, Candid-encoded with only
// `unknown`) still decode — they decode with pending_amount = None (proven by the
// old-layout decode test in `mod tests`). `unknown` keeps its original meaning:
// true = transport-unknown / stuck (blocks claims and zeroes claimable_amount
// until a controller reconciles). A marker with unknown = false is an in-flight
// pre-await record, cleared on a definite outcome.
//
// Lane L3b (F-2, custody-vault freeze V6): enriched again with `claim_seq` and
// `created_at_time_ns`, the per-OPERATION ledger identity frozen before the
// transfer await — `created_at_time_ns` is the ICRC dedup stamp sent with the
// icrc1_transfer, and `claim_seq` (the per-beneficiary operation sequence
// number) is bound into the transfer memo. Both are Option so pre-L3b markers
// (DEF-051 layout) still decode with None; a stuck legacy marker carries no
// frozen stamp and remains manual-reconcile only, exactly as before.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TransferOutcomeMarker {
    unknown: bool,
    pending_amount: Option<u128>,
    claim_seq: Option<u64>,
    created_at_time_ns: Option<u64>,
}

impl Storable for TransferOutcomeMarker {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

// ── F-3 (lane L3b): terminal claim tombstones ─────────────────────────────────
//
// Mirrors the pool's `TreasuryReconciliationTombstone` / insert-once pattern
// (shielded-pool `write_reconciliation_tombstone`): when a claim resolves —
// definite ledger success, definite ledger rejection, or controller reconcile
// (Executed / NotExecuted) — the blocking marker in TRANSFER_OUTCOME_UNKNOWN is
// removed (claims must unblock), but the resolution is FIRST recorded as a
// permanent tombstone keyed by the operation identity (beneficiary, claim_seq).
// The tombstone is the durable evidence trail that marker removal used to
// erase. There is deliberately NO update, delete, or prune counterpart
// anywhere in this canister: the record must survive the very privilege that
// performs the reconciliation (the controller / Vault), or it is not a
// witness. Being a StableBTreeMap on MemoryId 4 it survives post_upgrade with
// no serialization.

/// How a claim operation terminated.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum ClaimResolution {
    /// Tokens moved (or the controller asserted they moved): definite ledger
    /// success, or reconcile_claim(Executed).
    Executed,
    /// No tokens moved: definite ledger rejection (claimable restored), or
    /// reconcile_claim(NotExecuted) with `claimed` reverted.
    Reverted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TerminalClaimTombstone {
    /// Per-beneficiary operation sequence number. None ONLY for a legacy
    /// pre-L3b marker (no frozen identity was ever recorded for it).
    claim_seq:          Option<u64>,
    /// The claim amount. None only for a legacy marker with no recorded
    /// pending_amount.
    amount:             Option<u128>,
    /// The frozen ICRC dedup stamp sent as `created_at_time`. None only for
    /// legacy markers; post-L3b operations always carry it (F-2).
    created_at_time_ns: Option<u64>,
    resolution:         ClaimResolution,
    recorded_at_ns:     u64,
}

impl Storable for TerminalClaimTombstone {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

/// Tombstone map key for one claim operation: length-prefixed beneficiary
/// bytes, then the big-endian claim_seq. The length prefix makes distinct
/// principals prefix-free, so a per-beneficiary range scan can never bleed
/// into another beneficiary's keys (raw principal bytes are NOT prefix-free:
/// [0x01] is a prefix of [0x01, 0x02]).
fn tombstone_key(beneficiary: Principal, claim_seq: u64) -> Vec<u8> {
    let b = beneficiary.as_slice();
    debug_assert!(b.len() <= 29, "principal longer than 29 bytes");
    let mut key = Vec::with_capacity(1 + b.len() + 8);
    key.push(b.len() as u8);
    key.extend_from_slice(b);
    key.extend_from_slice(&claim_seq.to_be_bytes());
    key
}

/// F-2: canonical memo binding a claim transfer to its individual OPERATION
/// identity (beneficiary, claim_seq) — mirrors the pool's
/// `treasury_disburse_memo(proposal_id)`. Together with the frozen
/// `created_at_time_ns` this is the token's `transfer_dedup_key` input
/// (sha256 over from/to/amount/fee/memo/created_at_time): a retry of THIS
/// claim replays the identical key and dedups; a later legitimate claim has a
/// different claim_seq and therefore a different key and is NEVER dropped as
/// a duplicate. Gotcha 3 / ARTIFACT3 OP-4: the identity is per-OPERATION,
/// never per-schedule.
fn claim_memo(beneficiary: Principal, claim_seq: u64) -> Vec<u8> {
    let b = beneficiary.as_slice();
    let mut memo = Vec::with_capacity(19 + 1 + b.len() + 8);
    memo.extend_from_slice(b"STSH-VESTING-CLAIM\0");
    memo.push(b.len() as u8);
    memo.extend_from_slice(b);
    memo.extend_from_slice(&claim_seq.to_be_bytes());
    memo
}

// ── ICRC-1 transfer types (mirror of token ledger interface) ──────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct IcrcAccount {
    owner:      Principal,
    subaccount: Option<[u8; 32]>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct IcrcTransferArgs {
    from_subaccount: Option<[u8; 32]>,
    to:              IcrcAccount,
    amount:          Nat,
    fee:             Option<Nat>,
    memo:            Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum IcrcTransferError {
    BadFee             { expected_fee: Nat },
    BadBurn            { min_burn_amount: Nat },
    InsufficientFunds  { balance: Nat },
    TooOld,
    CreatedInFuture    { ledger_time: u64 },
    Duplicate          { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError       { error_code: Nat, message: String },
}

const NS_PER_MONTH: u64 = 30 * 24 * 60 * 60 * 1_000_000_000;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct VestingSchedule {
    pub beneficiary:      Principal,
    pub total_amount:     u128,       // base STSH units
    pub cliff_end_ns:     u64,        // nanoseconds timestamp
    pub vesting_end_ns:   u64,        // nanoseconds timestamp
    pub claimed:          u128,
    pub start_ns:         u64,
}

impl VestingSchedule {
    pub fn claimable_at(&self, now_ns: u64) -> u128 {
        if now_ns < self.cliff_end_ns {
            return 0;
        }
        let linear_duration = self.vesting_end_ns.saturating_sub(self.cliff_end_ns);
        let elapsed = now_ns.saturating_sub(self.cliff_end_ns).min(linear_duration);
        let vested = if linear_duration == 0 {
            self.total_amount
        } else {
            (self.total_amount as u128)
                .saturating_mul(elapsed as u128)
                / linear_duration as u128
        };
        vested.saturating_sub(self.claimed)
    }
}

impl Storable for VestingSchedule {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(candid::encode_one(self).unwrap()) }
    fn from_bytes(b: Cow<[u8]>) -> Self { candid::decode_one(&b).unwrap() }
    const BOUND: Bound = Bound::Unbounded;
}

// Encode Principal as Vec<u8> for StableBTreeMap key
fn principal_key(p: Principal) -> Vec<u8> { p.as_slice().to_vec() }

fn transfer_outcome_unknown(key: &[u8]) -> bool {
    TRANSFER_OUTCOME_UNKNOWN.with(|m| {
        m.borrow()
            .get(&key.to_vec())
            .map(|marker| marker.unknown)
            .unwrap_or(false)
    })
}

/// F-2: the per-beneficiary claim sequence number for the NEXT operation =
/// the number of terminal tombstones already recorded for this beneficiary.
/// Safe because at most one claim operation per beneficiary can be unresolved
/// at a time: an in-flight or stuck marker makes every later claim return 0
/// claimable (claimed was pre-incremented) or fail closed, so the tombstone
/// count cannot be overtaken by a concurrent operation. The seq is therefore
/// unique per operation and never reused — a later legitimate claim always
/// gets a fresh ledger identity (gotcha 3: never schedule-wide).
fn next_claim_seq(beneficiary: Principal) -> u64 {
    let lo = tombstone_key(beneficiary, 0);
    // Exclusive upper bound: any key for this beneficiary with seq < 2^64-1 is
    // strictly below tombstone_key(.., u64::MAX); counting range(lo..hi) is
    // the count of all recorded operations for this beneficiary.
    let hi = tombstone_key(beneficiary, u64::MAX);
    TERMINAL_CLAIM_TOMBSTONES.with(|m| m.borrow().range(lo..hi).count() as u64)
}

/// F-3: resolve a claim marker into a TERMINAL TOMBSTONE, then remove the
/// marker. INSERT-ONCE, mirroring the pool's `write_reconciliation_tombstone`:
/// if a tombstone already exists for the operation key it is left exactly as
/// written, never overwritten or merged. The tombstone is written BEFORE the
/// marker is removed, so no trap window can leave a resolved claim with its
/// evidence erased. `recorded_at_ns` is passed in by the caller (time() at the
/// resolution site) so this helper stays pure and host-testable.
fn resolve_marker_with_tombstone(
    key: &[u8],
    marker: &TransferOutcomeMarker,
    resolution: ClaimResolution,
    recorded_at_ns: u64,
) {
    let beneficiary = Principal::from_slice(key);
    // Legacy markers (pre-L3b) carry no claim_seq; key them at the seq the
    // operation WOULD have had (the current tombstone count) and record
    // claim_seq: None honestly in the value.
    let seq = marker.claim_seq.unwrap_or_else(|| next_claim_seq(beneficiary));
    let tkey = tombstone_key(beneficiary, seq);
    TERMINAL_CLAIM_TOMBSTONES.with(|m| {
        let mut map = m.borrow_mut();
        if !map.contains_key(&tkey) {
            map.insert(
                tkey,
                TerminalClaimTombstone {
                    claim_seq: marker.claim_seq,
                    amount: marker.pending_amount,
                    created_at_time_ns: marker.created_at_time_ns,
                    resolution,
                    recorded_at_ns,
                },
            );
        }
    });
    TRANSFER_OUTCOME_UNKNOWN.with(|m| {
        m.borrow_mut().remove(&key.to_vec());
    });
}

/// L3-INT-02 `post_upgrade` sweep (mirrors L3a treasury's
/// `sweep_reserved_reservations_on_upgrade`): a marker that survives an
/// upgrade with `unknown == false` was awaiting an icrc1_transfer callback
/// whose turn died with the old Wasm. That callback can never classify the
/// result, so the outcome is unknown BY CONSTRUCTION — advance the marker to
/// `unknown == true` (stuck) BEFORE ingress resumes, so claims block until a
/// controller reconciles. Forward-only: the marker is never removed and its
/// frozen per-operation identity (claim_seq / created_at_time_ns /
/// pending_amount) is carried across verbatim — that identity is exactly what
/// the controller uses to resolve the outcome objectively against the ledger.
fn sweep_inflight_markers_on_upgrade() {
    TRANSFER_OUTCOME_UNKNOWN.with(|m| {
        let mut map = m.borrow_mut();
        let stale: Vec<(Vec<u8>, TransferOutcomeMarker)> = map
            .iter()
            .filter(|(_, marker)| !marker.unknown)
            .collect();
        for (key, mut marker) in stale {
            marker.unknown = true;
            map.insert(key, marker);
        }
    });
}

/// Claim guard: ANY surviving marker — stuck (unknown=true) or in-flight
/// (unknown=false, reachable only across an upgrade boundary, see
/// sweep_inflight_markers_on_upgrade) — blocks a new claim for that
/// beneficiary. Checking key presence (not just the stuck flag) makes the
/// no-overwrite rule structural: a later claim can never replace the only
/// witness of an unresolved operation (L3-INT-02).
fn marker_blocks_claim(key: &[u8]) -> bool {
    TRANSFER_OUTCOME_UNKNOWN.with(|m| m.borrow().contains_key(&key.to_vec()))
}

/// Revert a schedule's pre-incremented `claimed` by exactly `amount`
/// (saturating — the amount came from the marker that recorded the
/// pre-increment, so the subtraction is exact on every reachable path).
/// Shared by claim()'s definite-rejection arm and reconcile_claim(NotExecuted)
/// so tests drive the same code the endpoints run.
fn revert_claimed(key: &[u8], amount: u128) {
    SCHEDULES.with(|s| {
        let mut map = s.borrow_mut();
        if let Some(mut schedule) = map.get(&key.to_vec()) {
            schedule.claimed = schedule.claimed.saturating_sub(amount);
            map.insert(key.to_vec(), schedule);
        }
    });
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static SCHEDULES: RefCell<StableBTreeMap<Vec<u8>, VestingSchedule, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_SCHEDULES)))
    );
    static TRANSFER_OUTCOME_UNKNOWN: RefCell<StableBTreeMap<Vec<u8>, TransferOutcomeMarker, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_TRANSFER_OUTCOME_UNKNOWN)))
    );

    /// F-3: permanent terminal claim tombstones (MemoryId 4). INSERT-ONCE,
    /// never updated, never deleted — see `resolve_marker_with_tombstone`.
    static TERMINAL_CLAIM_TOMBSTONES: RefCell<StableBTreeMap<Vec<u8>, TerminalClaimTombstone, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_TERMINAL_CLAIM_TOMBSTONES)))
    );

    /// EAGER durable source of truth for TOKEN_CANISTER + CONTROLLER.
    /// Sentinel default on a fresh region so an absent cell fails closed.
    static CANISTER_REFS: RefCell<Cell<CanisterRefsCell, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_CANISTER_REFS)),
            CanisterRefsCell::sentinel(),
        ).expect("CANISTER_REFS: Cell::init failed — stable memory corrupt")
    );

    static TOKEN_CANISTER: RefCell<Option<Principal>> = RefCell::new(None);
    static CONTROLLER:     RefCell<Option<Principal>> = RefCell::new(None);
}

/// LAUNCH-HARDEN-04 O-7: the vesting UPGRADE argument, read RAW in
/// `post_upgrade` as `(opt VestingUpgradeArg)`. `rebind_controller = Some(p)`
/// re-binds the reconcile-claim controller; everything else preserves.
#[derive(CandidType, Deserialize)]
pub struct VestingUpgradeArg {
    pub rebind_controller: Option<Principal>,
}

#[derive(CandidType, Deserialize)]
pub struct InitArgs {
    pub token_canister: Principal,
    pub controller:     Principal,
    pub schedules:      Vec<NewSchedule>,
}

#[derive(CandidType, Deserialize)]
pub struct NewSchedule {
    pub beneficiary:    Principal,
    pub total_amount:   u128,
    pub cliff_months:   u32,
    pub linear_months:  u32,
}

/// K3-003: hard cap on total schedule duration (cliff + linear), in fixed
/// 30-day months. 480 months = 40 years — far above any real schedule, far
/// below the u64-ns wrap horizon.
pub const MAX_SCHEDULE_MONTHS: u32 = 480;

/// K3-003: pure validation for init schedules — extracted for testability;
/// init() traps on any error, aborting the install (typed reject).
///
/// - nonzero amount
/// - both-zero duration rejected (cliff 0 + linear 0); zero-cliff allowed
/// - `cliff_months + linear_months <= MAX_SCHEDULE_MONTHS` (checked in u64 —
///   two u32s cannot wrap there)
/// - duplicate beneficiaries rejected: SCHEDULES is beneficiary-keyed, so a
///   duplicate would silently overwrite the earlier schedule.
pub fn validate_init_schedules(schedules: &[NewSchedule]) -> Result<(), String> {
    let mut seen: std::collections::HashSet<Principal> = std::collections::HashSet::new();
    for s in schedules {
        if s.total_amount == 0 {
            return Err(format!("vesting schedule for {} has zero amount", s.beneficiary));
        }
        if s.cliff_months == 0 && s.linear_months == 0 {
            return Err(format!(
                "vesting schedule for {} has zero total duration (cliff 0 + linear 0)",
                s.beneficiary
            ));
        }
        let total_months = s.cliff_months as u64 + s.linear_months as u64;
        if total_months > MAX_SCHEDULE_MONTHS as u64 {
            return Err(format!(
                "vesting schedule for {}: cliff {} + linear {} months exceeds MAX_SCHEDULE_MONTHS {}",
                s.beneficiary, s.cliff_months, s.linear_months, MAX_SCHEDULE_MONTHS
            ));
        }
        if !seen.insert(s.beneficiary) {
            return Err(format!(
                "duplicate vesting beneficiary {} — schedules are beneficiary-keyed; a duplicate would silently overwrite the earlier schedule",
                s.beneficiary
            ));
        }
    }
    Ok(())
}

/// K3-003: checked month→ns conversion + checked start/cliff/end additions.
/// Never wraps, never clamps — any overflow is a typed error and the install
/// aborts. With MAX_SCHEDULE_MONTHS enforced these cannot fire in practice;
/// they exist so arithmetic safety never silently depends on the cap.
pub fn build_schedule(now_ns: u64, s: &NewSchedule) -> Result<VestingSchedule, String> {
    let cliff_ns = (s.cliff_months as u64)
        .checked_mul(NS_PER_MONTH)
        .ok_or_else(|| format!("cliff_months {} overflows ns conversion", s.cliff_months))?;
    let linear_ns = (s.linear_months as u64)
        .checked_mul(NS_PER_MONTH)
        .ok_or_else(|| format!("linear_months {} overflows ns conversion", s.linear_months))?;
    let cliff_end_ns = now_ns
        .checked_add(cliff_ns)
        .ok_or_else(|| "cliff end timestamp overflows u64 ns".to_string())?;
    let vesting_end_ns = cliff_end_ns
        .checked_add(linear_ns)
        .ok_or_else(|| "vesting end timestamp overflows u64 ns".to_string())?;
    Ok(VestingSchedule {
        beneficiary: s.beneficiary,
        total_amount: s.total_amount,
        cliff_end_ns,
        vesting_end_ns,
        claimed: 0,
        start_ns: now_ns,
    })
}

#[init]
fn init(args: InitArgs) {
    set_canister_refs(args.token_canister, args.controller);

    // K3-003: typed validation before ANY schedule is written — trap aborts
    // the install; no partial schedule set can exist.
    if let Err(e) = validate_init_schedules(&args.schedules) {
        ic_cdk::trap(&e);
    }

    let now = time();
    SCHEDULES.with(|s| {
        let mut map = s.borrow_mut();
        for schedule in args.schedules {
            let vs = match build_schedule(now, &schedule) {
                Ok(vs) => vs,
                Err(e) => ic_cdk::trap(&e),
            };
            let key = principal_key(schedule.beneficiary);
            map.insert(key, vs);
        }
    });
}

#[query]
fn claimable_amount(beneficiary: Principal) -> Nat {
    let key = principal_key(beneficiary);
    let now = time();
    if transfer_outcome_unknown(&key) {
        return Nat::from(0u32);
    }
    SCHEDULES.with(|s| {
        s.borrow().get(&key)
            .map(|schedule| Nat::from(schedule.claimable_at(now)))
            .unwrap_or(Nat::from(0u32))
    })
}

#[query]
fn get_schedule(beneficiary: Principal) -> Option<VestingSchedule> {
    let key = principal_key(beneficiary);
    SCHEDULES.with(|s| s.borrow().get(&key))
}

#[query]
fn list_schedules() -> Vec<VestingSchedule> {
    SCHEDULES.with(|s| s.borrow().iter().map(|(_, v)| v).collect())
}

// ── Canonical read-back (lane L3b, freeze V6 §6) ─────────────────────────────

/// Canonical read-back payload for the two authority principals this canister
/// holds (vesting/src storage — the CANISTER_REFS eager cell, MemoryId 3).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CanisterRefsReadback {
    pub token_canister: Principal,
    pub controller:     Principal,
}

/// Fail-closed interpretation of the stored cell: the sentinel (uninitialised,
/// absent, or corrupt — all decode to the sentinel per the eager-cell
/// contract) is an error, never a fabricated or default principal.
fn refs_readback_from(stored: CanisterRefsCell) -> Result<CanisterRefsReadback, String> {
    match stored.get() {
        Some([token_canister, controller]) => Ok(CanisterRefsReadback {
            token_canister: *token_canister,
            controller:     *controller,
        }),
        None => Err(
            "CANISTER_REFS uninitialised or corrupt (sentinel survived) — refusing to \
             fabricate canister references".to_string(),
        ),
    }
}

/// Freeze V6 §6 canonical read-back: returns the canonical STORED
/// TOKEN_CANISTER + CONTROLLER, read directly from the durable eager cell
/// (never a caller-supplied expectation, never a launch default). PUBLIC —
/// both principals are public post-launch and the endpoint's purpose is
/// externally verifiable proof of the born-under-vault wiring. Mutation-free;
/// fails closed on sentinel/uninit/corrupt.
#[query]
fn get_canister_refs_readback() -> Result<CanisterRefsReadback, String> {
    let stored = CANISTER_REFS.with(|c| *c.borrow().get());
    refs_readback_from(stored)
}

// ── W2 2-5R: outstanding claim-marker visibility (DEF-096) ───────────────────
//
// THE GAP. Before this surface no endpoint could answer the operator's
// pre-upgrade question — "is a claim in flight or stuck, and for whom". The
// existing reads cannot: `claimable_amount` returns 0 when a marker exists,
// which is the SAME value as "nothing vested", so it collapses "blocked" into
// "nothing to do"; `get_schedule`/`list_schedules` publish no marker field; and
// `claim()` itself mutates. Answering by calling `claim` would be answering a
// read with a write.
//
// READ-ONLY, AND MEANT TO BE CHECKABLE AS SUCH. This is a `#[query]`. It takes
// no `borrow_mut`, performs no insert or remove, and makes no `ic_cdk::call` on
// any path. Two consecutive calls across a state the operator did not change
// return identical results and leave every observable untouched.

/// One outstanding marker, as the operator needs to read it.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OutstandingClaimMarker {
    pub beneficiary: Principal,
    pub state: ClaimMarkerState,
    /// The three fields below are returned EXACTLY as stored. They keep their
    /// `Option` shape because `TransferOutcomeMarker` stores them that way;
    /// default-filling them would invent data the canister does not have.
    pub pending_amount: Option<u128>,
    pub claim_seq: Option<u64>,
    pub created_at_time_ns: Option<u64>,
}

/// Typed state discriminator — deliberately NOT the raw `unknown: bool`.
/// `unknown = true/false` is an internal field name whose polarity an operator
/// under time pressure will misread; `InFlight`/`Stuck` cannot be misread.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ClaimMarkerState {
    /// `unknown == false` — a claim is in flight. Post-L3-INT-02 this can only
    /// persist within a single message: `post_upgrade` sweeps survivors to
    /// stuck before ingress resumes.
    InFlight,
    /// `unknown == true` — the transfer outcome is unknown and the schedule
    /// awaits `reconcile_claim`.
    Stuck,
}

/// Authorization failures, TYPED (SSA checkpoint-1 binding ruling).
///
/// RETAINED for decode compatibility; no longer returned. LAUNCH-HARDEN-04 O-7
/// made `list_outstanding_claim_markers` anonymous-readable: every field it
/// returns is already public (the un-gated schedule queries and the ledger), so
/// the controller gate protected nothing. The `Result` shape and this type stay
/// so existing clients keep decoding.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum OutstandingClaimMarkerError {
    /// (No longer returned.) The caller was not the stored application controller.
    NotController,
    /// (No longer returned.) No controller was configured.
    ControllerNotConfigured,
}

/// Every outstanding claim marker. Read-only, and — since LAUNCH-HARDEN-04 O-7 —
/// ANONYMOUS-READABLE: nothing it returns is non-public (beneficiary, amount and
/// timing are already exposed by `get_schedule` / `list_schedules` and the
/// ledger). Always `Ok`.
///
/// ORDER IS DETERMINISTIC: rows come out in `StableBTreeMap` key order, i.e.
/// ascending by the beneficiary principal's raw bytes. Repeated reads return
/// the same sequence, so an operator diffing two readings sees real change
/// rather than reordering.
///
/// An empty result is an EMPTY VECTOR, never an error: "nothing outstanding" is
/// a successful answer and the most common one.
#[query]
fn list_outstanding_claim_markers()
    -> Result<Vec<OutstandingClaimMarker>, OutstandingClaimMarkerError>
{
    Ok(TRANSFER_OUTCOME_UNKNOWN.with(|m| {
        m.borrow()
            .iter()
            .map(|(key, marker)| OutstandingClaimMarker {
                // The map key IS the principal's raw slice (`principal_key`),
                // so the subject is recovered exactly, not reconstructed.
                beneficiary: Principal::from_slice(&key),
                state: if marker.unknown {
                    ClaimMarkerState::Stuck
                } else {
                    ClaimMarkerState::InFlight
                },
                pending_amount: marker.pending_amount,
                claim_seq: marker.claim_seq,
                created_at_time_ns: marker.created_at_time_ns,
            })
            .collect()
    }))
}

#[update]
async fn claim() -> Result<Nat, String> {
    let beneficiary = ic_cdk::caller();
    let key = principal_key(beneficiary);
    let now = time();

    // L3-INT-02: block on ANY surviving marker, not only a stuck one — a
    // marker is the sole witness of an unresolved operation and must never be
    // overwritten by a later claim. (Post-sweep every surviving marker is
    // unknown=true; this guard makes the no-overwrite rule structural rather
    // than dependent on the sweep having run.)
    if marker_blocks_claim(&key) {
        return Err("TransferOutcomeUnknown: previous claim transfer outcome requires reconciliation".to_string());
    }

    let claimable = SCHEDULES.with(|s| {
        s.borrow().get(&key)
            .map(|schedule| schedule.claimable_at(now))
            .unwrap_or(0)
    });

    if claimable == 0 {
        return Err("Nothing claimable".to_string());
    }

    // Pre-increment claimed BEFORE the await. If a concurrent claim arrives at
    // the await point, claimable_at will return 0 and that call will return
    // "Nothing claimable" without executing a second transfer.
    SCHEDULES.with(|s| {
        let mut map = s.borrow_mut();
        if let Some(mut schedule) = map.get(&key) {
            // checked_add: claimed + claimable <= total_amount by construction
            // (claimable = vested.saturating_sub(claimed)), so overflow is
            // unreachable; check defensively and abort before the transfer.
            schedule.claimed = schedule.claimed.checked_add(claimable)
                .ok_or("vesting claimed overflow")?;
            map.insert(key.clone(), schedule);
        }
        Ok::<(), String>(())
    })?;

    // DEF-051 / QA-DEF-005: durably record the in-flight claim amount BEFORE the
    // await (unknown = false = in-flight, not yet stuck). If the call returns a
    // transport-unknown outcome we flip the SAME marker to unknown = true below;
    // reconcile_claim(NotExecuted) then reverts `claimed` by exactly this amount.
    // On resolution (definite outcome or reconcile) the marker is cleared via
    // resolve_marker_with_tombstone, which first writes a permanent tombstone.
    //
    // F-2 (lane L3b): freeze the per-OPERATION ledger identity NOW, before the
    // await — claim_seq (per-beneficiary operation sequence) + a one-time
    // created_at_time stamp — and persist both on the marker, exactly as the
    // pool freezes (memo, created_at_time) on its disbursement record. The
    // stamp is bound to THIS operation and stable across any retry of it;
    // later claims get a later claim_seq, so ICRC dedup can never drop them
    // (per-OPERATION, never per-schedule — gotcha 3).
    let claim_seq = next_claim_seq(beneficiary);
    let created_at_time_ns = time();
    let op_marker = TransferOutcomeMarker {
        unknown: false,
        pending_amount: Some(claimable),
        claim_seq: Some(claim_seq),
        created_at_time_ns: Some(created_at_time_ns),
    };
    TRANSFER_OUTCOME_UNKNOWN.with(|m| {
        m.borrow_mut().insert(key.clone(), op_marker.clone());
    });

    let token = TOKEN_CANISTER.with(|t| t.borrow().unwrap());
    let xfer_result: Result<(Result<Nat, IcrcTransferError>,), _> = call(
        token,
        "icrc1_transfer",
        (IcrcTransferArgs {
            from_subaccount: None,
            to: IcrcAccount { owner: beneficiary, subaccount: None },
            amount: Nat::from(claimable),
            fee: None,
            // F-2: memo + created_at_time together are the token's dedup-key
            // input, both frozen per operation above.
            memo: Some(claim_memo(beneficiary, claim_seq)),
            created_at_time: Some(created_at_time_ns),
        },),
    ).await;

    match xfer_result {
        Ok((Ok(_block),)) => {
            // Definite success — tombstone the operation as Executed and clear
            // the in-flight marker; `claimed` stays.
            resolve_marker_with_tombstone(&key, &op_marker, ClaimResolution::Executed, time());
            Ok(Nat::from(claimable))
        }
        Ok((Err(IcrcTransferError::Duplicate { .. }),)) => {
            // F-2 consequence: the ledger's dedup matched this operation's
            // frozen (memo, created_at_time) identity, which means an earlier
            // submission of THIS SAME operation COMMITTED (the token records a
            // dedup entry only after a transfer commits). The tokens moved —
            // treat as definite success: `claimed` stays, tombstone Executed,
            // clear the marker. Reverting here would let the beneficiary
            // re-claim tokens already paid.
            resolve_marker_with_tombstone(&key, &op_marker, ClaimResolution::Executed, time());
            Ok(Nat::from(claimable))
        }
        Ok((Err(e),)) => {
            // Ledger rejected (definite) — revert the pre-increment so tokens remain
            // claimable, tombstone the operation as Reverted, and clear the
            // in-flight marker (no reconciliation needed).
            revert_claimed(&key, claimable);
            resolve_marker_with_tombstone(&key, &op_marker, ClaimResolution::Reverted, time());
            Err(format!("icrc1_transfer rejected: {:?}", e))
        }
        Err((_, e)) => {
            // Transport outcome is ambiguous: the ledger may have committed before
            // the reject/trap reached us. Flip the marker to stuck (keep the
            // pre-increment AND the recorded amount AND the frozen F-2 identity)
            // so this claim cannot be retried and double-paid; a controller
            // resolves it via reconcile_claim. The frozen (memo,
            // created_at_time) identity lets the controller verify the outcome
            // objectively against the ledger before deciding.
            TRANSFER_OUTCOME_UNKNOWN.with(|m| {
                let mut stuck = op_marker.clone();
                stuck.unknown = true;
                m.borrow_mut().insert(key.clone(), stuck);
            });
            Err(format!("TransferOutcomeUnknown: icrc1_transfer call failed: {}", e))
        }
    }
}

// ── Claim reconcile (DEF-051 / QA-DEF-005) ──────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum ClaimDecision { Executed, NotExecuted }

/// Controller-only recovery for a vesting claim whose transfer outcome is
/// transport-unknown — the icrc1_transfer call neither confirmed success nor
/// confirmed failure, leaving the schedule stuck (claimed pre-incremented, marker
/// unknown=true, future claims blocked). This is the ONLY path out of that state.
///
/// This endpoint does NOT re-issue the transfer. The controller asserts, after
/// external verification, whether the original transfer executed. Since lane
/// L3b (F-2) every claim transfer carries a frozen per-operation (memo,
/// created_at_time) identity recorded on the stuck marker, so the verification
/// can be objective: look the operation up on the ledger by its frozen
/// identity instead of relying on an unverifiable off-chain fact.
///
// RECONCILE TRUST: reconcile_claim(Executed) is an operator assertion, made after
// external/on-chain verification that the token transfer executed. This endpoint
// does NOT issue a transfer. A wrong Executed decision marks the beneficiary as
// settled without delivery of tokens — this trust boundary must be verified
// externally before calling. Documented in the deliverable report.
#[update]
fn reconcile_claim(beneficiary: Principal, decision: ClaimDecision) -> Result<(), String> {
    let controller = CONTROLLER.with(|c| c.borrow().ok_or("controller not configured".to_string()))?;
    if ic_cdk::caller() != controller {
        return Err("Only the controller may reconcile claims".to_string());
    }

    let key = principal_key(beneficiary);

    // The schedule must exist...
    if !SCHEDULES.with(|s| s.borrow().contains_key(&key)) {
        return Err("No vesting schedule for that beneficiary".to_string());
    }

    // ...and the claim must actually be stuck (transport-unknown). Any other state
    // — no marker, or an in-flight unknown==false marker — is not reconcilable, so
    // this also rejects a second reconcile on an already-resolved schedule.
    // (Post-L3-INT-02, an unknown==false marker can only survive within a single
    // in-flight message: post_upgrade sweeps them to stuck before ingress
    // resumes.)
    let marker = match TRANSFER_OUTCOME_UNKNOWN.with(|m| m.borrow().get(&key)) {
        Some(m) if m.unknown => m,
        _ => return Err(
            "Schedule is not in a transport-unknown (stuck) state — nothing to reconcile".to_string()
        ),
    };

    match decision {
        ClaimDecision::Executed => {
            // Operator asserts the original transfer executed. No token movement;
            // `claimed` stays incremented (settled). Tombstone the operation as
            // Executed (permanent witness), then clear the stuck marker.
            resolve_marker_with_tombstone(&key, &marker, ClaimResolution::Executed, time());
            Ok(())
        }
        ClaimDecision::NotExecuted => {
            // Operator asserts the transfer did NOT execute. Revert `claimed` by
            // exactly the recorded stuck amount so the beneficiary can re-claim.
            // A legacy marker without a recorded amount cannot be safely reverted.
            let amount = marker.pending_amount.ok_or(
                "Legacy stuck marker carries no recorded pending amount; NotExecuted \
                 cannot safely revert without it. Verify externally and resolve via \
                 Executed, or correct the amount before reverting.".to_string()
            )?;
            revert_claimed(&key, amount);
            // Tombstone the operation as Reverted (permanent witness), then
            // clear the stuck marker.
            resolve_marker_with_tombstone(&key, &marker, ClaimResolution::Reverted, time());
            Ok(())
        }
    }
}

// ── Upgrade hooks ─────────────────────────────────────────────────────────────
//
// ── MIGRATION LOG ─────────────────────────────────────────────────────────────
//
// STATE_VERSION 1  (pre-A2 P4 fix — 2026-06-09)
//   Initial stable-persist.  First version to survive a Wasm upgrade without
//   state loss.
//
//   Serialised into VestingStableState (stable Cell, MEM_STABLE_STATE = MemoryId 1):
//     Canister refs (2): token_canister, controller
//
//   Survive upgrade automatically (StableBTreeMap, no serialisation needed):
//     SCHEDULES  (MemoryId 0) — all vesting schedules including claimed amounts
//     TRANSFER_OUTCOME_UNKNOWN (MemoryId 2) — beneficiaries whose latest claim
//       transfer returned an ambiguous transport outcome and must be reconciled
//
//   DEF-051 / QA-DEF-005 (no STATE_VERSION bump, no new MemoryId):
//     TransferOutcomeMarker gained `pending_amount: Option<u128>`. This is a
//     Candid-backward-compatible record extension — legacy markers (only `unknown`)
//     decode with pending_amount = None (see `mod tests`). The reconcile path
//     (reconcile_claim) consumes the marker; no schedule schema change.
//
//   Note: VestingSchedule.claimed is inside the StableBTreeMap and therefore
//   persists automatically. The upgrade hook only needs to restore heap scalars.
//
// Lane L3b (F-2/F-3, custody-vault freeze V6; no STATE_VERSION bump, one L0-
// allocated MemoryId consumed):
//   TransferOutcomeMarker gained `claim_seq: Option<u64>` +
//   `created_at_time_ns: Option<u64>` — the same Candid-backward-compatible
//   record-extension pattern DEF-051 used for `pending_amount`; legacy markers
//   decode with both None.
//   TERMINAL_CLAIM_TOMBSTONES (StableBTreeMap, MemoryId 4) is new durable
//   state; fresh regions initialise empty, and as a StableBTreeMap it survives
//   post_upgrade with no serialization and no hook change.
//
// L3-INT-02 (no STATE_VERSION bump, no new MemoryId):
//   post_upgrade now sweeps surviving in-flight (unknown=false) markers to
//   stuck (unknown=true) — their transfer callbacks died with the old Wasm.
//   Forward-only in-place flag flip; identity fields preserved.

// ── Durable ref write-through ────────────────────────────────────────────────
//
// ATOMICITY (V2 acceptance #2): ONE `Cell::set` covers both refs, so they are
// durable together or not at all — no partial scalar can be persisted. The
// stable write lands FIRST and the heap mirrors follow only on success, so a
// failed write leaves heap and stable state consistent. No `await` here: the
// whole write-through is a single atomic message segment, and re-running it is
// idempotent (it is a set, not an increment — a retry cannot double-apply).
fn set_canister_refs(token_canister: Principal, controller: Principal) {
    CANISTER_REFS.with(|c| {
        c.borrow_mut()
            .set(CanisterRefsCell::new([token_canister, controller]))
            .expect("set_canister_refs: stable cell write failed");
    });
    TOKEN_CANISTER.with(|t| *t.borrow_mut() = Some(token_canister));
    CONTROLLER.with(|c| *c.borrow_mut() = Some(controller));
}

// ── ATOMICITY: the post-init writer (LAUNCH-HARDEN-04 O-7) ───────────────────
//
// V2 acceptance #2 asks for "a rejected operation persists no partial scalar".
// Until LAUNCH-HARDEN-04 that case was VACUOUS here: `set_canister_refs` had
// exactly one caller, `#[init]`.
//
// THE VACUITY HAS ENDED, as the old note required it be recorded. There is now
// a SECOND writer: `post_upgrade(rebind_controller)` — a typed
// `VestingUpgradeArg` read RAW from the upgrade argument — which re-binds the
// reconcile-claim controller (to the Vault, cpdab-…). It is not a callable
// endpoint: it runs only inside a controller-gated upgrade (on mainnet, a Vault
// 2-of-3 `Management` Upgrade with a hash-bound arg), so it grants no power the
// upgrade authority does not already hold. Its rejected-op atomicity is PROVEN,
// not waved: a refused rebind (anonymous, self, the token, or a principal that
// is not an IC controller) TRAPS the whole upgrade — the old Wasm keeps serving
// and the cell is byte-identical (integration-tests
// harden04_vesting_vault_reconcile_tests, T3). The write itself is still ONE
// `Cell::set` covering both refs.

#[post_upgrade]
fn post_upgrade() {
    // Fail-closed sentinel gate — see stsh-eager-cell for the contract.
    // Validation runs BEFORE the sentinel could become observable: the heap
    // mirrors are populated only on the validated path.
    let restored = CANISTER_REFS.with(|c| *c.borrow().get());

    let Some([token_canister, controller]) = restored.get().copied() else {
        ic_cdk::trap(
            "post_upgrade: CANISTER_REFS sentinel survived — no initialised canister \
             references in stable memory (MemoryId 3 absent or unwritten). This canister \
             was never initialised, or is being upgraded from a pre-hardening Wasm that \
             predates the eager cell. Aborting to prevent silent state loss.",
        );
    };

    TOKEN_CANISTER.with(|t| *t.borrow_mut() = Some(token_canister));
    CONTROLLER.with(|c| *c.borrow_mut() = Some(controller));

    // ── LAUNCH-HARDEN-04 O-7: optional reconcile-controller REBIND ───────────
    //
    // The arg is read RAW so the arg-less `post_upgrade` signature (and every
    // existing upgrade caller) is unchanged. Empty bytes, `()`, `(null)` and a
    // record without `rebind_controller` change nothing. `Some(p)` rebinds the
    // controller to `p` — only if `p` is a non-anonymous IC CONTROLLER of this
    // canister distinct from itself and the token; anything else TRAPS the
    // upgrade (the whole upgrade rolls back).
    let raw = ic_cdk::api::call::arg_data_raw();
    if !raw.is_empty() {
        let arg: Option<VestingUpgradeArg> =
            candid::decode_args::<(Option<VestingUpgradeArg>,)>(&raw)
                .map(|(a,)| a)
                .unwrap_or_else(|e| {
                    ic_cdk::trap(&format!("post_upgrade: undecodable upgrade arg ({e})"))
                });
        if let Some(VestingUpgradeArg { rebind_controller: Some(new_controller) }) = arg {
            if new_controller == Principal::anonymous()
                || new_controller == ic_cdk::id()
                || new_controller == token_canister
                || !ic_cdk::api::is_controller(&new_controller)
            {
                ic_cdk::trap(
                    "post_upgrade: rebind_controller must be a non-anonymous IC controller of \
                     this canister, distinct from itself and the token",
                );
            }
            set_canister_refs(token_canister, new_controller);
        }
    }

    // L3-INT-02: sweep any in-flight (unknown=false) claim marker to stuck
    // (unknown=true) BEFORE ingress resumes. Its icrc1_transfer callback died
    // with the old Wasm and can never classify the result; left at
    // unknown=false the marker would neither block claims nor be reconcilable,
    // and a later claim could overwrite the only witness of an unresolved
    // token-moving operation. Identity fields are preserved verbatim.
    sweep_inflight_markers_on_upgrade();
}

// =============================================================================
// UNIT TESTS (host target)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // DEF-051 / QA-DEF-005: prove the enriched TransferOutcomeMarker is a
    // backward-compatible Candid record extension. A legacy marker encoded with
    // only `unknown` must decode into the new struct with pending_amount = None
    // (never panic, never produce a wrong value).
    #[test]
    fn def051_legacy_marker_decodes_with_none_pending_amount() {
        // Reproduce the pre-DEF-051 on-disk layout: a record with a single field.
        #[derive(CandidType, Serialize, Deserialize)]
        struct LegacyMarker { unknown: bool }

        for unknown in [true, false] {
            let legacy = LegacyMarker { unknown };
            let bytes = candid::encode_one(&legacy).expect("encode legacy marker");
            let decoded: TransferOutcomeMarker =
                candid::decode_one(&bytes).expect("legacy marker must decode into the new struct");
            assert_eq!(decoded.unknown, unknown, "legacy `unknown` must round-trip");
            assert_eq!(
                decoded.pending_amount, None,
                "legacy marker must decode with pending_amount = None"
            );
        }
    }

    // A new-layout marker must of course round-trip its recorded amount.
    #[test]
    fn def051_new_marker_roundtrips_pending_amount() {
        let m = TransferOutcomeMarker {
            unknown: true,
            pending_amount: Some(1234u128),
            claim_seq: Some(7),
            created_at_time_ns: Some(1_800_000_000_000_000_000),
        };
        let bytes = candid::encode_one(&m).expect("encode new marker");
        let decoded: TransferOutcomeMarker = candid::decode_one(&bytes).expect("decode new marker");
        assert!(decoded.unknown);
        assert_eq!(decoded.pending_amount, Some(1234u128));
        assert_eq!(decoded.claim_seq, Some(7));
        assert_eq!(decoded.created_at_time_ns, Some(1_800_000_000_000_000_000));
    }

    // Lane L3b (F-2): the intermediate DEF-051 layout (unknown + pending_amount,
    // no claim identity fields) must still decode, with the new fields None.
    #[test]
    fn l3b_def051_layout_marker_decodes_with_none_claim_identity() {
        #[derive(CandidType, Serialize, Deserialize)]
        struct Def051Marker { unknown: bool, pending_amount: Option<u128> }

        let legacy = Def051Marker { unknown: true, pending_amount: Some(42u128) };
        let bytes = candid::encode_one(&legacy).expect("encode DEF-051 marker");
        let decoded: TransferOutcomeMarker =
            candid::decode_one(&bytes).expect("DEF-051 marker must decode into the L3b struct");
        assert!(decoded.unknown);
        assert_eq!(decoded.pending_amount, Some(42u128));
        assert_eq!(decoded.claim_seq, None, "pre-L3b marker has no frozen claim_seq");
        assert_eq!(decoded.created_at_time_ns, None, "pre-L3b marker has no frozen stamp");
    }

    // ── K3-003 (P-ARITH) boundary tests ───────────────────────────────────────

    fn beneficiary(n: u8) -> Principal {
        let mut bytes = [0u8; 29];
        bytes[0] = n;
        Principal::from_slice(&bytes)
    }

    fn schedule(n: u8, amount: u128, cliff: u32, linear: u32) -> NewSchedule {
        NewSchedule {
            beneficiary: beneficiary(n),
            total_amount: amount,
            cliff_months: cliff,
            linear_months: linear,
        }
    }

    #[test]
    fn k3003_duration_cap_boundaries() {
        // MAX accepted (0 + 480 and 480 + 0), MAX+1 rejected.
        assert!(validate_init_schedules(&[schedule(1, 1, 0, MAX_SCHEDULE_MONTHS)]).is_ok());
        assert!(validate_init_schedules(&[schedule(1, 1, MAX_SCHEDULE_MONTHS, 0)]).is_ok());
        assert!(validate_init_schedules(&[schedule(1, 1, 6, 30)]).is_ok()); // founders shape
        let err = validate_init_schedules(&[schedule(1, 1, 1, MAX_SCHEDULE_MONTHS)])
            .expect_err("481 months must be rejected");
        assert!(err.contains("exceeds MAX_SCHEDULE_MONTHS"));
        // u32::MAX months cannot wrap the u64 total-months check.
        let err = validate_init_schedules(&[schedule(1, 1, u32::MAX, u32::MAX)])
            .expect_err("u32::MAX months must be rejected");
        assert!(err.contains("exceeds MAX_SCHEDULE_MONTHS"));
    }

    #[test]
    fn k3003_zero_duration_and_amount_rules() {
        let err = validate_init_schedules(&[schedule(1, 1, 0, 0)])
            .expect_err("both-zero duration must be rejected");
        assert!(err.contains("zero total duration"));
        // Zero cliff with nonzero linear is explicitly allowed.
        assert!(validate_init_schedules(&[schedule(1, 1, 0, 12)]).is_ok());
        let err = validate_init_schedules(&[schedule(1, 0, 6, 30)])
            .expect_err("zero amount must be rejected");
        assert!(err.contains("zero amount"));
    }

    #[test]
    fn k3003_duplicate_beneficiary_rejected_typed() {
        let err = validate_init_schedules(&[schedule(7, 10, 6, 30), schedule(7, 20, 0, 12)])
            .expect_err("duplicate beneficiary must be rejected, never silently overwritten");
        assert!(err.contains("duplicate vesting beneficiary"));
        // Distinct beneficiaries are fine.
        assert!(validate_init_schedules(&[schedule(7, 10, 6, 30), schedule(8, 20, 0, 12)]).is_ok());
    }

    #[test]
    fn k3003_build_schedule_checked_never_wraps() {
        // Nominal: founders shape at a realistic install time.
        let now = 1_700_000_000_000_000_000u64;
        let vs = build_schedule(now, &schedule(1, 10, 6, 30)).expect("founders shape builds");
        assert_eq!(vs.start_ns, now);
        assert_eq!(vs.cliff_end_ns, now + 6 * NS_PER_MONTH);
        assert_eq!(vs.vesting_end_ns, now + 36 * NS_PER_MONTH);
        assert!(vs.vesting_end_ns > vs.cliff_end_ns && vs.cliff_end_ns > vs.start_ns);

        // Overflow paths are typed errors, never wrapped timestamps
        // (reachable only if the cap were bypassed — checked independently).
        let err = build_schedule(now, &schedule(1, 10, u32::MAX, 0))
            .expect_err("u32::MAX cliff months must not wrap");
        assert!(err.contains("overflows"));
        let err = build_schedule(u64::MAX, &schedule(1, 10, 1, 0))
            .expect_err("start near u64::MAX must not wrap");
        assert!(err.contains("overflows"));
    }

    // ── Lane L3b: F-2 per-operation identity + F-3 tombstones + read-back ─────

    fn marker(unknown: bool, amount: u128, seq: u64, stamp: u64) -> TransferOutcomeMarker {
        TransferOutcomeMarker {
            unknown,
            pending_amount: Some(amount),
            claim_seq: Some(seq),
            created_at_time_ns: Some(stamp),
        }
    }

    fn tombstone(b: Principal, seq: u64) -> Option<TerminalClaimTombstone> {
        TERMINAL_CLAIM_TOMBSTONES.with(|m| m.borrow().get(&tombstone_key(b, seq)))
    }

    // F-2: per-OPERATION identity — two claims against the SAME schedule must
    // produce different transfer identities (gotcha 3: never per-schedule).
    #[test]
    fn f2_claim_identity_unique_per_operation() {
        let b = beneficiary(1);
        let m0 = claim_memo(b, 0);
        let m1 = claim_memo(b, 1);
        assert_ne!(m0, m1, "two claims of one schedule must have distinct memos");
        assert_ne!(claim_memo(b, 0), claim_memo(beneficiary(2), 0),
            "same seq, different beneficiary must differ");
        assert_eq!(m0, claim_memo(b, 0), "memo is deterministic for the same operation");
        // Tombstone keys are per-operation too, and prefix-free across
        // beneficiaries whose raw bytes prefix each other ([0x01] vs [0x01,0x02]).
        assert_ne!(tombstone_key(b, 0), tombstone_key(b, 1));
        let short = Principal::from_slice(&[0x01]);
        let long = Principal::from_slice(&[0x01, 0x02]);
        assert_ne!(tombstone_key(short, 0), tombstone_key(long, 0));
    }

    // F-2 dedup behaviour: mirror the token's transfer_dedup_key semantics
    // (equality over from/to/amount/fee/memo/created_at_time, token
    // src/lib.rs:1567) and prove (a) a retry of the SAME operation dedups,
    // (b) a later LEGITIMATE claim of the same amount against the same
    // schedule is NOT dropped — even if the ledger clock returned the very
    // same created_at_time stamp for both.
    #[test]
    fn f2_dedup_never_drops_legitimate_later_claims() {
        type DedupKey<'a> = (Principal, Principal, u128, Option<u64>, Vec<u8>, u64);
        let mut ledger_dedup: std::collections::HashSet<DedupKey> = std::collections::HashSet::new();

        let vesting = beneficiary(200); // stands in for the vesting canister (from)
        let b = beneficiary(1);
        let amount = 500u128;
        let stamp = 1_800_000_000_000_000_000u64;

        // Operation 0 (seq 0) at stamp T, and a byte-identical retry of it.
        let op0 = (vesting, b, amount, None, claim_memo(b, 0), stamp);
        assert!(ledger_dedup.insert(op0.clone()), "first submission commits");
        assert!(!ledger_dedup.insert(op0), "retry of the SAME op dedups (no double-pay)");

        // Operation 1 (seq 1): same beneficiary, same amount, SAME stamp —
        // the worst case for a schedule-wide identity. Must NOT dedup.
        let op1 = (vesting, b, amount, None, claim_memo(b, 1), stamp);
        assert!(ledger_dedup.insert(op1),
            "later legitimate claim must NOT be dropped by dedup");

        // A schedule-WIDE identity (the forbidden gotcha-3 shape: same memo
        // for every claim) WOULD drop op1 — assert the contrast explicitly.
        let schedule_wide_op1 = (vesting, b, amount, None, claim_memo(b, 0), stamp);
        assert!(!ledger_dedup.insert(schedule_wide_op1),
            "control: a schedule-wide identity would indeed drop the later claim");
    }

    // F-3: resolving a marker writes a permanent tombstone and clears the
    // marker; the tombstone carries the frozen per-operation identity.
    #[test]
    fn f3_resolution_writes_tombstone_and_clears_marker() {
        let b = beneficiary(3);
        let key = principal_key(b);
        TRANSFER_OUTCOME_UNKNOWN.with(|m| {
            m.borrow_mut().insert(key.clone(), marker(true, 500, 0, 111));
        });

        resolve_marker_with_tombstone(&key, &marker(true, 500, 0, 111), ClaimResolution::Executed, 999);

        assert!(!TRANSFER_OUTCOME_UNKNOWN.with(|m| m.borrow().contains_key(&key)),
            "marker must be cleared so claims unblock");
        let t = tombstone(b, 0).expect("tombstone must exist");
        assert_eq!(t.claim_seq, Some(0));
        assert_eq!(t.amount, Some(500));
        assert_eq!(t.created_at_time_ns, Some(111), "frozen F-2 stamp preserved");
        assert_eq!(t.resolution, ClaimResolution::Executed);
        assert_eq!(t.recorded_at_ns, 999);
        // Next operation on the same schedule gets seq 1.
        assert_eq!(next_claim_seq(b), 1);
    }

    // F-3: INSERT-ONCE — a second resolution of the same operation key never
    // overwrites the first tombstone (mirrors the pool's pattern).
    #[test]
    fn f3_tombstone_is_insert_once() {
        let b = beneficiary(4);
        let key = principal_key(b);
        let m0 = marker(true, 500, 0, 111);
        resolve_marker_with_tombstone(&key, &m0, ClaimResolution::Executed, 999);
        // Adversarial second write: same op key, different resolution/amount.
        let m0_hostile = marker(true, 1, 0, 111);
        resolve_marker_with_tombstone(&key, &m0_hostile, ClaimResolution::Reverted, 1000);
        let t = tombstone(b, 0).expect("tombstone must exist");
        assert_eq!(t.resolution, ClaimResolution::Executed, "first tombstone wins");
        assert_eq!(t.amount, Some(500), "first tombstone amount preserved");
        assert_eq!(t.recorded_at_ns, 999, "first tombstone timestamp preserved");
        assert_eq!(next_claim_seq(b), 1, "insert-once must not double-count the operation");
    }

    // F-3: tombstones live in a StableBTreeMap on MemoryId 4 — rebuilding the
    // map from stable memory (exactly what the thread_local re-init does
    // across post_upgrade) must read them back unchanged.
    #[test]
    fn f3_tombstone_survives_stable_reinit() {
        let b = beneficiary(5);
        let key = principal_key(b);
        let m0 = marker(true, 777, 0, 222);
        resolve_marker_with_tombstone(&key, &m0, ClaimResolution::Executed, 888);

        // Simulate the upgrade: drop the Rust handle and re-init a fresh
        // StableBTreeMap over the SAME stable memory region.
        let rebuilt: StableBTreeMap<Vec<u8>, TerminalClaimTombstone, Mem> =
            MEMORY_MANAGER.with(|mm| StableBTreeMap::init(mm.borrow().get(MEM_TERMINAL_CLAIM_TOMBSTONES)));
        let t = rebuilt.get(&tombstone_key(b, 0)).expect("tombstone must survive re-init");
        assert_eq!(t.amount, Some(777));
        assert_eq!(t.created_at_time_ns, Some(222));
        assert_eq!(t.resolution, ClaimResolution::Executed);
    }

    // F-3: a legacy pre-L3b stuck marker (no frozen identity) still resolves:
    // tombstone records claim_seq/created_at_time as None honestly.
    #[test]
    fn f3_legacy_marker_resolves_with_none_identity() {
        let b = beneficiary(6);
        let key = principal_key(b);
        let legacy = TransferOutcomeMarker {
            unknown: true,
            pending_amount: Some(10),
            claim_seq: None,
            created_at_time_ns: None,
        };
        TRANSFER_OUTCOME_UNKNOWN.with(|m| {
            m.borrow_mut().insert(key.clone(), legacy.clone());
        });
        resolve_marker_with_tombstone(&key, &legacy, ClaimResolution::Executed, 5);
        let t = tombstone(b, 0).expect("legacy resolution must tombstone");
        assert_eq!(t.claim_seq, None);
        assert_eq!(t.created_at_time_ns, None);
        assert_eq!(t.amount, Some(10));
        assert!(!TRANSFER_OUTCOME_UNKNOWN.with(|m| m.borrow().contains_key(&key)));
    }

    // Read-back: positive — returns exactly the STORED token + controller.
    #[test]
    fn readback_returns_canonical_stored_refs() {
        let token = beneficiary(100);
        let controller = beneficiary(101);
        set_canister_refs(token, controller);
        let rb = get_canister_refs_readback().expect("initialised refs must read back");
        assert_eq!(rb, CanisterRefsReadback { token_canister: token, controller });
    }

    // Read-back: fail-closed on uninitialised (sentinel) state. This test runs
    // on a fresh thread with no init, so the cell holds the sentinel.
    #[test]
    fn readback_fails_closed_on_sentinel() {
        let err = get_canister_refs_readback()
            .expect_err("sentinel state must fail closed, never fabricate refs");
        assert!(err.contains("sentinel"));
    }

    // Read-back: fail-closed on CORRUPT state — garbage bytes decode to the
    // sentinel per the eager-cell contract, and the read-back errors.
    #[test]
    fn readback_fails_closed_on_corrupt() {
        let width = stsh_eager_cell::encoded_len(2);
        for garbage in [vec![0u8; width], vec![0x11u8; width], vec![0x07u8; width - 1]] {
            let corrupt = CanisterRefsCell::from_bytes(std::borrow::Cow::Owned(garbage));
            assert!(corrupt.is_sentinel(), "corrupt region must decode as sentinel");
            assert!(refs_readback_from(corrupt).is_err(),
                "corrupt state must fail closed, never fabricate refs");
        }
    }

    // ── L3-INT-02: upgrade boundary with an in-flight claim ──────────────────

    // Seed a schedule + an in-flight (unknown=false) marker exactly as claim()
    // leaves them at the await point, and return the marker.
    fn seed_inflight_claim(b: Principal, claimed: u128, amount: u128, seq: u64, stamp: u64) -> TransferOutcomeMarker {
        let key = principal_key(b);
        SCHEDULES.with(|s| {
            s.borrow_mut().insert(key.clone(), VestingSchedule {
                beneficiary: b,
                total_amount: 10_000,
                cliff_end_ns: 0,
                vesting_end_ns: 1,
                claimed,
                start_ns: 0,
            });
        });
        let m = marker(false, amount, seq, stamp);
        TRANSFER_OUTCOME_UNKNOWN.with(|mm| {
            mm.borrow_mut().insert(key, m.clone());
        });
        m
    }

    fn get_marker(b: Principal) -> Option<TransferOutcomeMarker> {
        TRANSFER_OUTCOME_UNKNOWN.with(|m| m.borrow().get(&principal_key(b)))
    }

    fn get_claimed(b: Principal) -> u128 {
        SCHEDULES.with(|s| s.borrow().get(&principal_key(b)).unwrap().claimed)
    }

    // The sweep advances ONLY in-flight markers to stuck, preserving the frozen
    // per-operation identity verbatim; already-stuck markers are untouched and
    // nothing is ever removed.
    #[test]
    fn l3int02_sweep_advances_inflight_preserving_identity() {
        let inflight_b = beneficiary(11);
        let stuck_b = beneficiary(12);
        let m_inflight = seed_inflight_claim(inflight_b, 500, 500, 0, 111);
        let m_stuck = marker(true, 700, 0, 222);
        TRANSFER_OUTCOME_UNKNOWN.with(|m| {
            m.borrow_mut().insert(principal_key(stuck_b), m_stuck.clone());
        });

        sweep_inflight_markers_on_upgrade();

        let after = get_marker(inflight_b).expect("in-flight marker must survive the sweep");
        assert!(after.unknown, "in-flight marker must be advanced to stuck");
        assert_eq!(after.pending_amount, m_inflight.pending_amount, "amount preserved");
        assert_eq!(after.claim_seq, m_inflight.claim_seq, "claim_seq preserved");
        assert_eq!(after.created_at_time_ns, m_inflight.created_at_time_ns, "frozen stamp preserved");
        let stuck_after = get_marker(stuck_b).expect("stuck marker untouched");
        assert!(stuck_after.unknown);
        assert_eq!(stuck_after.created_at_time_ns, Some(222));
        assert_eq!(
            TRANSFER_OUTCOME_UNKNOWN.with(|m| m.borrow().len()),
            2,
            "sweep never removes a marker"
        );
    }

    // Subsequent-claim blocking: after the sweep, the beneficiary's next claim
    // is blocked by the guard and the marker can never be overwritten.
    #[test]
    fn l3int02_claim_blocked_after_sweep_no_overwrite() {
        let b = beneficiary(13);
        seed_inflight_claim(b, 500, 500, 0, 111);
        // Pre-sweep the stuck-only query gate would NOT have fired...
        assert!(!transfer_outcome_unknown(&principal_key(b)));
        // ...but the claim guard blocks on ANY marker, even pre-sweep.
        assert!(marker_blocks_claim(&principal_key(b)),
            "in-flight marker must block a new claim even before the sweep");
        sweep_inflight_markers_on_upgrade();
        assert!(marker_blocks_claim(&principal_key(b)), "swept marker blocks claims");
        assert!(transfer_outcome_unknown(&principal_key(b)),
            "post-sweep the marker reads as transport-unknown everywhere");
        // The witness is still there with its identity — nothing overwrote it.
        let m = get_marker(b).unwrap();
        assert_eq!(m.claim_seq, Some(0));
        assert_eq!(m.created_at_time_ns, Some(111));
    }

    // Upgrade-boundary outcome A: the transfer EXECUTED on the ledger. The
    // controller verifies objectively via the frozen (memo, created_at_time)
    // identity and reconciles Executed: claimed stays, the tombstone carries
    // the frozen identity, and the witness is written before the marker goes.
    #[test]
    fn l3int02_upgrade_boundary_transfer_executed() {
        let b = beneficiary(14);
        let m = seed_inflight_claim(b, 500, 500, 0, 333);
        sweep_inflight_markers_on_upgrade();
        let stuck = get_marker(b).unwrap();
        assert!(stuck.unknown);

        // Controller lookup on the ledger by the frozen identity: the memo and
        // stamp the tombstone must carry are exactly what claim() sent.
        assert_eq!(claim_memo(b, stuck.claim_seq.unwrap()), claim_memo(b, 0));
        assert_eq!(stuck.created_at_time_ns, Some(333));

        // reconcile_claim(Executed) semantics (controller gate is not
        // host-reachable; the state transition is the endpoint's body):
        resolve_marker_with_tombstone(&principal_key(b), &stuck, ClaimResolution::Executed, 444);

        assert_eq!(get_claimed(b), 500, "Executed: claimed stays incremented — no double path");
        assert!(get_marker(b).is_none(), "marker cleared after tombstone");
        let t = tombstone(b, 0).expect("tombstone written");
        assert_eq!(t.resolution, ClaimResolution::Executed);
        assert_eq!(t.claim_seq, Some(0));
        assert_eq!(t.created_at_time_ns, Some(333), "frozen identity on the permanent witness");
        assert_eq!(t.amount, Some(500));
        let _ = m;
    }

    // Upgrade-boundary outcome B: the transfer did NOT execute. Reconcile
    // NotExecuted reverts claimed by EXACTLY the recorded pending amount and
    // tombstones Reverted; the beneficiary can then claim again (new seq).
    #[test]
    fn l3int02_upgrade_boundary_transfer_not_executed() {
        let b = beneficiary(15);
        seed_inflight_claim(b, 500, 500, 0, 555);
        sweep_inflight_markers_on_upgrade();
        let stuck = get_marker(b).unwrap();

        revert_claimed(&principal_key(b), stuck.pending_amount.unwrap());
        resolve_marker_with_tombstone(&principal_key(b), &stuck, ClaimResolution::Reverted, 666);

        assert_eq!(get_claimed(b), 0, "NotExecuted: claimed reverted by exactly pending_amount");
        let t = tombstone(b, 0).expect("tombstone written");
        assert_eq!(t.resolution, ClaimResolution::Reverted);
        assert_eq!(t.created_at_time_ns, Some(555));
        // The re-claim path is open again and gets a FRESH operation identity.
        assert!(get_marker(b).is_none());
        assert!(!marker_blocks_claim(&principal_key(b)));
        assert_eq!(next_claim_seq(b), 1, "next claim is a new operation (seq 1)");
    }

    // Tombstone-first ordering: resolve_marker_with_tombstone writes the
    // permanent witness BEFORE clearing the marker — observable end state is
    // tombstone present + marker absent, and a second resolution of the same
    // operation key is insert-once (first witness wins).
    #[test]
    fn l3int02_resolution_is_tombstone_first_then_marker_clear() {
        let b = beneficiary(16);
        seed_inflight_claim(b, 900, 900, 0, 777);
        sweep_inflight_markers_on_upgrade();
        let stuck = get_marker(b).unwrap();

        resolve_marker_with_tombstone(&principal_key(b), &stuck, ClaimResolution::Executed, 888);
        assert!(tombstone(b, 0).is_some(), "tombstone must exist");
        assert!(get_marker(b).is_none(), "marker must be gone");

        // Re-resolving the same operation identity cannot rewrite the witness.
        resolve_marker_with_tombstone(&principal_key(b), &marker(true, 1, 0, 999), ClaimResolution::Reverted, 1000);
        let t = tombstone(b, 0).unwrap();
        assert_eq!(t.resolution, ClaimResolution::Executed, "first witness wins");
        assert_eq!(t.created_at_time_ns, Some(777));
    }
}

// ── Test-only eager-cell probe (feature = "testing") ─────────────────────────
//
// Exposes the RAW encoded bytes of the eager cell so the cross-Wasm sentinel
// tests can assert on the durable layout directly rather than inferring it.
//
// BUILD-GATED OFF BY DEFAULT. The production build does not enable `testing`,
// so this export is absent from every deployed Wasm — proved, not asserted, by
// `integration-tests/tests/eager_cell_feature_isolation_tests.rs`, which scans
// the shipped binaries for the export name. It is read-only: it cannot write,
// clear, or weaken the sentinel path.
#[cfg(feature = "testing")]
#[query]
fn eager_cell_probe_for_test() -> Vec<u8> {
    CANISTER_REFS.with(|c| c.borrow().get().to_bytes().into_owned())
}

// ── W2 2-5R: published-field lock for the new visibility record ──────────────
//
// WHY THIS EXISTS, given vesting.did is already custody-pinned. The custody
// fixture compares the FIXTURE against the DID, so it catches fixture-vs-DID
// drift. It cannot catch Rust-vs-DID drift: if the Rust record later gains or
// loses a field, the fixture and the DID would still agree with each other and
// both would be wrong. That is exactly the class W3 3-3 closed for staking, and
// at this pin vesting had NO such test (a grep for `w3_33` here returned zero).
//
// Both sides are DERIVED — the real `candid_parser` on one, `T::ty()` on the
// other — so nothing is a hand-transcribed list that could drift on its own.
#[cfg(test)]
mod w2_2_5r_did_field_lock_tests {
    use super::*;
    use candid::types::{Type, TypeEnv, TypeInner};
    use std::collections::BTreeSet;

    const VESTING_DID: &str = include_str!("../vesting.did");

    fn did_type(name: &str) -> Type { did_env_type(name).1 }

    fn did_env_type(name: &str) -> (TypeEnv, Type) {
        let prog: candid_parser::IDLProg = VESTING_DID.parse().expect("vesting.did must parse");
        let mut env = TypeEnv::new();
        candid_parser::check_prog(&mut env, &prog)
            .expect("vesting.did must type-check")
            .expect("vesting.did must have an actor");
        let mut t: Type = env
            .find_type(name)
            .unwrap_or_else(|_| panic!("{name} must be declared in vesting.did"))
            .clone();
        t = resolve(&env, &t);
        (env, t)
    }

    /// Resolve a type through any chain of `Var` aliases, so the DID side and
    /// the Rust side are compared in the SAME representation. Without this a
    /// DID field declared as a named alias renders as the alias while the Rust
    /// field renders as its structure, and every comparison would be noise.
    fn resolve(env: &TypeEnv, t: &Type) -> Type {
        let mut t = t.clone();
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
        t
    }

    /// `(field name, RESOLVED field type)` for a record declared in the DID.
    fn did_record(name: &str) -> Vec<(String, String)> {
        let (env, t) = did_env_type(name);
        match &*t {
            TypeInner::Record(fields) => fields
                .iter()
                .map(|f| (f.id.to_string(), resolve(&env, &f.ty).to_string()))
                .collect(),
            other => panic!("expected {name} to be a record, got {other:?}"),
        }
    }

    /// `(field name, field type)` derived from the RUST record via `T::ty()`.
    ///
    /// R2: an earlier version of this lock mapped `T::ty()` to NAMES only and
    /// threw the Rust field types away, then compared the DID's own strings to
    /// literals. That let a Rust field change type while the static DID stayed
    /// put and the tests still passed — i.e. it did not close the Rust-vs-DID
    /// TYPE-drift class it existed to close.
    fn rust_record_fields<T: CandidType>() -> Vec<(String, String)> {
        match &*T::ty() {
            TypeInner::Record(fields) => fields
                .iter()
                .map(|f| (f.id.to_string(), f.ty.to_string()))
                .collect(),
            other => panic!("expected a Rust record type, got {other:?}"),
        }
    }

    fn did_variant(name: &str) -> BTreeSet<String> {
        match &*did_type(name) {
            TypeInner::Variant(fields) => fields.iter().map(|f| f.id.to_string()).collect(),
            other => panic!("expected {name} to be a variant, got {other:?}"),
        }
    }

    fn rust_field_names<T: CandidType>() -> BTreeSet<String> {
        match &*T::ty() {
            TypeInner::Record(fields) => fields.iter().map(|f| f.id.to_string()).collect(),
            other => panic!("expected a Rust record type, got {other:?}"),
        }
    }

    fn rust_variant_names<T: CandidType>() -> BTreeSet<String> {
        match &*T::ty() {
            TypeInner::Variant(fields) => fields.iter().map(|f| f.id.to_string()).collect(),
            other => panic!("expected a Rust variant type, got {other:?}"),
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

    // LAUNCH-HARDEN-04 O-7: the marker listing is anonymous-readable, so the
    // `authorize_marker_listing` decision and its four unit arms are REMOVED
    // with it (the endpoint behaviour is proven in PocketIC:
    // harden04_vesting_vault_reconcile_tests T4 and the w2_2_5r suites).

    #[test]
    fn outstanding_claim_marker_did_publishes_every_rust_field() {
        assert_eq!(
            names(&did_record("OutstandingClaimMarker")),
            rust_field_names::<OutstandingClaimMarker>(),
            "OutstandingClaimMarker field drift between vesting.did and the Rust record"
        );
    }

    #[test]
    fn w2_2_5r_published_marker_fields_carry_the_declared_types() {
        let did = did_record("OutstandingClaimMarker");
        let rust = rust_record_fields::<OutstandingClaimMarker>();

        // Set equality on names, as before.
        assert_eq!(
            names(&did),
            rust.iter().map(|(n, _)| n.clone()).collect::<BTreeSet<_>>(),
            "OutstandingClaimMarker field drift between vesting.did and the Rust record"
        );

        // R2: and every RUST field type must equal its DID counterpart, with
        // DID aliases resolved. This is the half that was missing: without it a
        // Rust field can change type against an unchanged DID undetected.
        for (name, rust_ty) in &rust {
            let did_ty = ty_of(&did, name);
            assert_eq!(
                &did_ty, rust_ty,
                "field `{name}` type drift: vesting.did says `{did_ty}`, Rust says `{rust_ty}`"
            );
        }

        // The explicit published contract, kept as literals so a change to BOTH
        // sides at once still has to argue with this test.
        assert_eq!(ty_of(&did, "beneficiary"), "principal");
        // The three stored fields MUST stay optional: the marker stores them as
        // Option, and publishing them as required would force a default-fill
        // that invents data.
        assert_eq!(ty_of(&did, "pending_amount"), "opt nat");
        assert_eq!(ty_of(&did, "claim_seq"), "opt nat64");
        assert_eq!(ty_of(&did, "created_at_time_ns"), "opt nat64");
        // `state` resolves through the ClaimMarkerState alias to its variant.
        assert!(
            ty_of(&did, "state").contains("InFlight") && ty_of(&did, "state").contains("Stuck"),
            "state must resolve to the InFlight|Stuck variant, got {}", ty_of(&did, "state")
        );
    }

    #[test]
    fn marker_state_and_error_variants_match_the_did_exactly() {
        assert_eq!(
            did_variant("ClaimMarkerState"),
            rust_variant_names::<ClaimMarkerState>(),
            "ClaimMarkerState drift between vesting.did and Rust"
        );
        // SSA checkpoint-1 binding ruling: a TYPED authorization error, not text.
        assert_eq!(
            did_variant("OutstandingClaimMarkerError"),
            rust_variant_names::<OutstandingClaimMarkerError>(),
            "OutstandingClaimMarkerError drift between vesting.did and Rust"
        );
        assert_eq!(
            rust_variant_names::<OutstandingClaimMarkerError>(),
            ["ControllerNotConfigured".to_string(), "NotController".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            "the ruled error contract is exactly NotController | ControllerNotConfigured"
        );
    }

    /// LAUNCH-HARDEN-04 §R — the vesting Vault-Upgrade arg, recomputed from the
    /// AS-BUILT `VestingUpgradeArg`, and round-tripped through the exact decode
    /// `post_upgrade` performs.
    #[test]
    fn harden04_packet_vesting_upgrade_arg_bytes() {
        let vault = Principal::from_text("cpdab-saaaa-aaaar-qca2q-cai").unwrap();
        let bytes = candid::encode_args((Some(VestingUpgradeArg {
            rebind_controller: Some(vault),
        }),))
        .unwrap();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "4449444c036e016c01cbf98cb604026e6801000101010a00000000023010350101");
        // (The sha256 of these bytes is asserted in
        // integration-tests/tests/harden04_vesting_vault_reconcile_tests.rs —
        // this crate carries no sha2 dependency and this lane adds none.)
        let (a,): (Option<VestingUpgradeArg>,) = candid::decode_args(&bytes).unwrap();
        assert_eq!(a.and_then(|a| a.rebind_controller), Some(vault));
        // V-4: the no-arg shapes decode as "no rebind".
        let (e,): (Option<VestingUpgradeArg>,) =
            candid::decode_args(&candid::encode_args(()).unwrap()).unwrap();
        assert!(e.is_none());
    }
}
