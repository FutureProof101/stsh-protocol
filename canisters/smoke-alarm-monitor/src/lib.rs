// =============================================================================
// STSH Smoke Alarm — standalone solvency monitor canister
// Brief: BRIEF_SMOKE_ALARM_MONITOR.md (2026-07-10)
// =============================================================================
//
// A standalone, independently-verifiable canister that lets anyone check STSH
// supply integrity + pool holdings via CERTIFIED queries. Reads ONLY
// already-public data from the token canister:
//
//   - verify_supply_invariant()          (public query on the token)
//   - icrc1_balance_of(pool_principal)   (public query on the token)
//
// It makes ZERO calls to, and requires ZERO changes on, the other backend
// canisters (shielded-pool / token / verifier / nullifier-registry /
// merkle-tree). The full escrow-vs-liability solvency delta is NOT proven here
// — that needs the deferred pool-side solvency_attestation() (brief §4,
// docs/SOLVENCY_ATTESTATION_SPEC.md), wired only after the external review.
//
// Mechanism (certified variables):
//   A certified query cannot make inter-canister calls or set certified data,
//   so an ic_cdk_timers interval timer periodically (1) reads the two token
//   queries, (2) stores a SolvencySnapshot, (3) rebuilds the certified RbTree
//   and calls set_certified_data(root). Certified queries then return
//   { snapshot, canonical_bytes, certificate, witness }; the frontend verifies
//   the certificate against the IC root key and parses the VERIFIED leaf bytes.
//
// Fail-closed rules (the load-bearing part):
//   - healthy == true ONLY when status == Fresh AND both source calls
//     succeeded AND the token supply invariant holds.
//   - A failed refresh writes a NEW snapshot (SourceCallFailed/RefreshFailed,
//     healthy = false). It never silently retains the last good green.
//   - A certified `Stale` status cannot exist: if the timer is dead, nothing
//     can write. Staleness is therefore enforced by the READER: the certified
//     leaf commits to refreshed_at_ns + max_staleness_ns, and the certificate
//     carries the subnet-signed /time — the client MUST show red/unknown when
//     cert_time − refreshed_at_ns > max_staleness_ns. `Stale` appears only in
//     the init placeholder (no refresh yet) and in derived views
//     (get_health_status), both healthy = false.
//
// Blackhole (launch gate, NOT during build/test — see OPERATIONS.md):
//   No controller-gated methods exist and the init config is immutable, so the
//   canister can be blackholed once production IDs are final. Anyone can still
//   top up cycles (deposit_cycles needs no controller rights).
// =============================================================================

use candid::{CandidType, Nat, Principal};
use ic_cdk::api::{data_certificate, time};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_certified_map::{AsHashTree, RbTree};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    Cell, DefaultMemoryImpl,
};
use num_traits::cast::ToPrimitive;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::Duration;

// ── Canonical, domain-separated snapshot encoding ─────────────────────────────
//
// The certified tree commits to EXACTLY these bytes under TREE_KEY. The
// frontend parses the witness-verified leaf bytes (never a reconstruction of
// its own), so canister and frontend can never disagree. Any layout change
// bumps SCHEMA_VERSION and the domain tag together with the frontend parser
// and CERTIFIED_SNAPSHOT_ENCODING.md — all in the same change.
//
// Layout (all integers big-endian, fixed width; total 89 bytes):
//   [ 0..19]  DOMAIN_TAG  b"stsh-smoke-alarm-v1"
//   [19..23]  schema_version           u32
//   [23    ]  status                   u8   (0 Fresh, 1 Stale, 2 RefreshFailed,
//                                            3 SourceCallFailed)
//   [24    ]  flags                    u8   (bit0 supply_invariant_holds,
//                                            bit1 healthy,
//                                            bit2 pool_delta_healthy (v2),
//                                            bit3 stray funds present (v2),
//                                            bit4 supply_invariant_unavailable
//                                                 (v3), bits 5-7 reserved)
//   [25..41]  fixed_max_supply_e8s     u128
//   [41..57]  sum_all_balances_e8s     u128
//   [57..73]  pool_balance_e8s         u128
//   [73..81]  refreshed_at_ns          u64
//   [81..89]  max_staleness_ns         u64

const DOMAIN_TAG: &[u8; 19] = b"stsh-smoke-alarm-v1";
// v2 (D-2 + D-4): the snapshot gains the pool solvency attestation (RED source)
// and the treasury stray-funds read (YELLOW). The DOMAIN TAG IS UNCHANGED on
// purpose — the encoding doc reserves a tag change for an incompatible redesign,
// and this is an additive layout under a bumped schema_version. A v2 parser
// still rejects v1 bytes on BOTH length and schema_version, so nothing that
// predates this change can be misread as current.
// v3 (R-4 / S-c): ONE additive flag bit — bit 4 `supply_invariant_unavailable`,
// set iff the token's report carried `arithmetic_error = Some(_)`. Domain tag
// unchanged (the v2 precedent: an additive layout under a bumped
// schema_version is not an incompatible redesign). No new field bytes; the
// length is unchanged.
//
// WHY a schema bump for one bit: the v2 reader REJECTS any of bits 4-7 set, by
// design, so setting bit 4 under schema_version 2 makes every leaf structurally
// unparseable to a v2 page. That rejection is the reason the rollout is
// PAGE-FIRST — the dual-accept page must be live before this constant moves to
// 3. See MAINNET_DEPLOYMENT.md "## Solvency surface: schema-3 transition (R-4)".
const SCHEMA_VERSION: u32 = 3;
const CANONICAL_LEN: usize = 131;

/// The pool's attestation timestamp is floored to a 300 s bucket, so a freshly
/// committed attestation can already appear up to (but strictly less than) one
/// bucket old. The reader threshold is widened by exactly one bucket to
/// compensate — see `attestation_is_stale`.
const ATTESTATION_BUCKET_NS: u64 = 300_000_000_000;
/// Schema of the pool attestation this monitor understands. A pool publishing
/// anything else is Malformed, never silently accepted.
const POOL_ATTESTATION_SCHEMA: u32 = 1;

/// Key of the snapshot leaf inside the certified RbTree.
const TREE_KEY: &str = "solvency_snapshot";

// ── Config / state types ──────────────────────────────────────────────────────

/// Init config — target canister IDs are init args, NEVER hardcoded.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct MonitorInit {
    pub token_canister: Principal,
    pub pool_principal: Principal,
    /// v2 (D-4): the treasury account whose stray balance drives YELLOW. Read
    /// via the TOKEN's icrc1_balance_of — the monitor never calls the treasury.
    pub treasury_principal: Principal,
    /// v2 (D-2): the canister exposing `get_solvency_attestation`. Its own init
    /// arg rather than a reuse of `pool_principal` because the two are different
    /// claims — one is a ledger account to weigh, the other an attestation
    /// authority to trust — and an operator must be able to see both.
    pub pool_attestation_source: Principal,
    pub refresh_interval_ns: u64,
    pub max_staleness_ns: u64,
    /// Bounded ring buffer (e.g. 288 = 24h @ 5-min cadence).
    pub history_capacity: u32,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotStatus {
    Fresh,
    /// Never written by a refresh (a dead timer can't write) — used only for
    /// the init placeholder and reader-side derived views. See header note.
    Stale,
    /// Refresh ran but produced unusable data (e.g. Nat out of u128 range).
    RefreshFailed,
    /// An inter-canister read of the token was rejected.
    SourceCallFailed,
}

/// Per-source outcome for the two v2 reads. Distinct from `SnapshotStatus`,
/// which describes the refresh as a whole: a treasury read can fail while the
/// pool attestation is fine, and collapsing the two would lose exactly the
/// distinction the YELLOW/RED split exists to make.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceReadStatus {
    Ok,
    /// The inter-canister call was rejected.
    CallFailed,
    /// The call returned, but the payload was unusable (bad schema, out of
    /// range, or bytes that do not match the record).
    Malformed,
    /// The attestation is older than the monitor's tolerance. Pool-only.
    Stale,
}

impl SourceReadStatus {
    fn as_u8(self) -> u8 {
        match self {
            SourceReadStatus::Ok => 0,
            SourceReadStatus::CallFailed => 1,
            SourceReadStatus::Malformed => 2,
            SourceReadStatus::Stale => 3,
        }
    }
}

/// Reader-side staleness for the POOL ATTESTATION, per the SSA GREEN.
///
///   stale  <=>  observed_age > max_staleness_ns + 300 s
///
/// The added bucket is not slack for its own sake: flooring makes a just-issued
/// attestation look between 0 and one bucket old, so without the widening a
/// perfectly fresh pool would read stale at the phase edge. Cost of the
/// widening: stale detection is delayed by at most one bucket.
///
/// CHECKED — a configured `max_staleness_ns` near u64::MAX must not wrap into a
/// tiny tolerance. On overflow this returns TRUE (fail closed to RED/unknown),
/// never a permissive false.
fn attestation_is_stale(now_ns: u64, attested_at_ns: u64, max_staleness_ns: u64) -> bool {
    let observed_age = now_ns.saturating_sub(attested_at_ns);
    match max_staleness_ns.checked_add(ATTESTATION_BUCKET_NS) {
        Some(tolerance) => observed_age > tolerance,
        None => true,
    }
}

impl SnapshotStatus {
    fn as_u8(self) -> u8 {
        match self {
            SnapshotStatus::Fresh => 0,
            SnapshotStatus::Stale => 1,
            SnapshotStatus::RefreshFailed => 2,
            SnapshotStatus::SourceCallFailed => 3,
        }
    }
}

/// Base units, integers — no floats. See brief §1 schema.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SolvencySnapshot {
    pub supply_invariant_holds: bool,
    pub fixed_max_supply_e8s: u128,
    pub sum_all_balances_e8s: u128,
    /// icrc1_balance_of(pool_principal) on the token.
    pub pool_balance_e8s: u128,
    // ── v2 (D-2): the pool solvency attestation — THE RED SOURCE ────────────
    /// Outcome of reading `get_solvency_attestation`. Anything but `Ok` is
    /// unhealthy; it is never silently treated as fine.
    pub pool_attestation_source_status: SourceReadStatus,
    /// The pool's own healthy bit, computed there on the RAW delta.
    pub pool_delta_healthy: bool,
    /// `min(raw_delta, 0)` as published by the pool: 0 in every healthy state,
    /// a negative violation magnitude otherwise. The monitor forwards it — it
    /// does not recompute or reinterpret it.
    pub pool_public_delta_e8s: i128,
    /// The pool's bucketed attestation time (300 s granularity).
    pub pool_attested_at_ns: u64,
    // ── v2 (D-4): treasury stray funds — YELLOW, never RED ──────────────────
    /// Outcome of the treasury balance read.
    pub treasury_read_status: SourceReadStatus,
    /// Stray funds sitting in the treasury account. FOREIGN BY DEFINITION:
    /// excluded from custody accounting, excluded from the solvency delta, and
    /// excluded from `healthy`. Nonzero is a YELLOW note that backing is
    /// unaffected — not a solvency signal.
    pub treasury_stray_funds_e8s: u128,
    // ── v3 (R-4): UNAVAILABLE, distinct from VIOLATED ──────────────────────
    /// TRUE iff the token's `verify_supply_invariant` report carried
    /// `arithmetic_error = Some(_)` — i.e. the invariant could not be
    /// EVALUATED, as opposed to evaluated and found false.
    ///
    /// It is bound to `arithmetic_error`, NOT to `!supply_invariant_holds`:
    /// the latter is true for an ordinary first-law violation too, and reporting
    /// that as "could not compute" would be a different, false claim. `healthy`
    /// is unaffected — both states are unhealthy and always were.
    ///
    /// A pre-v3 stable checkpoint has no such field, and `false` ("no
    /// arithmetic error was reported") is the correct reading of a snapshot
    /// taken before the field existed. That migration is performed by the
    /// EXPLICIT version arm in `post_upgrade`, NOT by `#[serde(default)]`:
    /// serde's default does not make a Candid record field optional during
    /// subtype checking, so `candid::decode_one` of a v2 checkpoint into this
    /// type rejects with "field supply_invariant_unavailable is not optional
    /// field". That was SSA landed-diff round-1 RED-1 (a launch-path cutover
    /// failure); see `post_upgrade` and `MonitorStableStatePreV3`.
    pub supply_invariant_unavailable: bool,
    pub refreshed_at_ns: u64,
    pub max_staleness_ns: u64,
    pub status: SnapshotStatus,
    /// TRUE only if status == Fresh AND source calls succeeded AND the supply
    /// invariant holds.
    pub healthy: bool,
    pub schema_version: u32,
}

impl SolvencySnapshot {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CANONICAL_LEN);
        out.extend_from_slice(DOMAIN_TAG);
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out.push(self.status.as_u8());
        // bit2 is the pool's delta verdict; bit3 says stray funds are present.
        // The AMOUNT is not derivable from bit3 — it is a presence bit, and the
        // magnitude lives in its own field for a reader that wants to show it.
        // bit4 (v3) is the UNAVAILABLE signal and is derived from the token's
        // arithmetic_error ALONE — never from `!supply_invariant_holds`, which
        // is also true for an ordinary violation.
        let flags = (self.supply_invariant_holds as u8)
            | ((self.healthy as u8) << 1)
            | ((self.pool_delta_healthy as u8) << 2)
            | (((self.treasury_stray_funds_e8s > 0) as u8) << 3)
            | ((self.supply_invariant_unavailable as u8) << 4);
        out.push(flags);
        out.extend_from_slice(&self.fixed_max_supply_e8s.to_be_bytes());
        out.extend_from_slice(&self.sum_all_balances_e8s.to_be_bytes());
        out.extend_from_slice(&self.pool_balance_e8s.to_be_bytes());
        out.extend_from_slice(&self.refreshed_at_ns.to_be_bytes());
        out.extend_from_slice(&self.max_staleness_ns.to_be_bytes());
        // ── v2 tail, appended so every v1 offset above is unmoved ───────────
        out.push(self.pool_attestation_source_status.as_u8());
        out.push(self.treasury_read_status.as_u8());
        out.extend_from_slice(&self.pool_public_delta_e8s.to_be_bytes());
        out.extend_from_slice(&self.pool_attested_at_ns.to_be_bytes());
        out.extend_from_slice(&self.treasury_stray_funds_e8s.to_be_bytes());
        debug_assert_eq!(out.len(), CANONICAL_LEN);
        out
    }
}

/// Mirror of the token's SupplyInvariantReport (public query return type).
#[derive(CandidType, Deserialize, Clone, Debug)]
struct SupplyInvariantReport {
    fixed_max_supply: u128,
    sum_all_balances: u128,
    staking_locked_total: u128,
    fee_reserve_total: u128,
    invariant_holds: bool,
    checked_at_ns: u64,
    violation_detail: Option<String>,
    /// K3-002b (P-ARITH): per-site overflow attribution. Non-null means the
    /// invariant could not be soundly evaluated — treated as UNHEALTHY here
    /// even if `invariant_holds` were (incorrectly) true.
    arithmetic_error: Option<ArithmeticErrorReport>,
}

/// K3-002b mirror of the token's per-site overflow record.
#[derive(CandidType, Deserialize, Clone, Debug)]
struct ArithmeticErrorReport {
    balances_overflow: bool,
    staking_locks_overflow: bool,
    balances_plus_fee_overflow: bool,
}

/// Wire mirror of the pool's `SolvencyAttestation` (v2, D-2). Private: it is a
/// call-path type, never returned from an endpoint here.
#[derive(CandidType, Deserialize, Clone, Copy, Debug)]
struct SolvencyAttestationMirror {
    public_delta_e8s: i128,
    healthy: bool,
    attested_at_ns: u64,
    schema_version: u32,
}

/// Wire mirror of the pool's `CertifiedSolvencyAttestation`.
#[derive(CandidType, Deserialize, Clone, Debug)]
struct CertifiedSolvencyAttestationMirror {
    attestation: SolvencyAttestationMirror,
    canonical_bytes: ByteBuf,
    certificate: Option<ByteBuf>,
    witness: ByteBuf,
}

/// ICRC-1 Account — mirrors the token canister Account type.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account {
    owner: Principal,
    subaccount: Option<[u8; 32]>,
}

// ── Query response types ──────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct CertifiedSolvencySnapshot {
    pub snapshot: SolvencySnapshot,
    /// The exact leaf bytes committed under TREE_KEY (see layout above).
    pub canonical_bytes: ByteBuf,
    /// Subnet certificate — None when called in replicated (update) context;
    /// clients MUST treat None as unverifiable (red/unknown).
    pub certificate: Option<ByteBuf>,
    /// Self-describing CBOR HashTree witness for TREE_KEY.
    pub witness: ByteBuf,
}

/// Reader-side derived health — recomputes staleness against time(). This
/// query is UNCERTIFIED convenience data; trust decisions belong to the
/// certified snapshot + client-side checks.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct HealthStatus {
    pub healthy: bool,
    pub status: SnapshotStatus,
    pub snapshot_age_ns: u64,
    pub cycles_balance: u128,
}

// ── Storage ───────────────────────────────────────────────────────────────────

/// Single-value stable cell — serialized MonitorStableState (Candid bytes).
const MEM_STABLE_STATE: MemoryId = MemoryId::new(0);

/// Stable-checkpoint layout version. Bumped 1 -> 2 by R-4 when
/// `SolvencySnapshot` gained `supply_invariant_unavailable`.
///
/// It is bumped, rather than the field being widened to `Option<bool>` in the
/// DEF-080 style, because `SolvencySnapshot` is ALSO the public Candid return
/// type of `get_snapshot`/`get_history` and the source of the certified leaf:
/// widening it there would push an `opt bool` onto the page's wire contract for
/// a value that is never actually unknown after this migration. The cost is one
/// frozen legacy struct plus one explicit arm, both below.
const STATE_VERSION: u32 = 2;

/// The pre-R-4 checkpoint layout (schema-2 monitor, 115526d and earlier).
const STATE_VERSION_PRE_V3: u32 = 1;

/// Hard cap on the configurable history ring buffer.
const MAX_HISTORY_CAPACITY: u32 = 4096;

/// Minimum allowed refresh interval — protects against a zero/degenerate
/// config burning cycles every round.
const MIN_REFRESH_INTERVAL_NS: u64 = 1_000_000_000; // 1 s

/// A manual request_refresh is accepted at most once per minute (cycle-drain
/// protection — the canister pays for the token reads, not the caller).
const MANUAL_REFRESH_MIN_GAP_NS: u64 = 60 * 1_000_000_000;

/// An in-flight refresh guard older than this is considered leaked (e.g. a
/// trapped callback rolled back the clear) and is ignored.
const REFRESH_GUARD_EXPIRY_NS: u64 = 5 * 60 * 1_000_000_000;

type Mem = VirtualMemory<DefaultMemoryImpl>;

#[derive(CandidType, Deserialize)]
struct MonitorStableState {
    version: u32,
    config: MonitorInit,
    snapshot: SolvencySnapshot,
    history: Vec<SolvencySnapshot>,
    last_refresh_attempt_ns: u64,
}

/// Reads ONLY the leading `version` discriminator out of a stable checkpoint.
///
/// Candid record decoding ignores source fields the target does not declare, so
/// this decodes against EVERY layout this canister has ever written, which is
/// what lets `post_upgrade` dispatch on an explicit version instead of guessing
/// via a fallible try-this-then-that decode chain.
#[derive(CandidType, Deserialize)]
struct StateVersionProbe {
    version: u32,
}

/// FROZEN: the exact `SolvencySnapshot` layout written by the schema-2 monitor.
/// Do not add fields to this struct — it exists to decode bytes that already
/// exist on mainnet. A future field goes on `SolvencySnapshot` plus a new arm.
#[derive(CandidType, Deserialize, Clone, Debug)]
struct SolvencySnapshotPreV3 {
    supply_invariant_holds: bool,
    fixed_max_supply_e8s: u128,
    sum_all_balances_e8s: u128,
    pool_balance_e8s: u128,
    pool_attestation_source_status: SourceReadStatus,
    pool_delta_healthy: bool,
    pool_public_delta_e8s: i128,
    pool_attested_at_ns: u64,
    treasury_read_status: SourceReadStatus,
    treasury_stray_funds_e8s: u128,
    refreshed_at_ns: u64,
    max_staleness_ns: u64,
    status: SnapshotStatus,
    healthy: bool,
    schema_version: u32,
}

/// FROZEN: the `STATE_VERSION_PRE_V3` checkpoint record.
#[derive(CandidType, Deserialize)]
struct MonitorStableStatePreV3 {
    version: u32,
    config: MonitorInit,
    snapshot: SolvencySnapshotPreV3,
    history: Vec<SolvencySnapshotPreV3>,
    last_refresh_attempt_ns: u64,
}

impl From<SolvencySnapshotPreV3> for SolvencySnapshot {
    fn from(v2: SolvencySnapshotPreV3) -> Self {
        SolvencySnapshot {
            supply_invariant_holds: v2.supply_invariant_holds,
            fixed_max_supply_e8s: v2.fixed_max_supply_e8s,
            sum_all_balances_e8s: v2.sum_all_balances_e8s,
            pool_balance_e8s: v2.pool_balance_e8s,
            pool_attestation_source_status: v2.pool_attestation_source_status,
            pool_delta_healthy: v2.pool_delta_healthy,
            pool_public_delta_e8s: v2.pool_public_delta_e8s,
            pool_attested_at_ns: v2.pool_attested_at_ns,
            treasury_read_status: v2.treasury_read_status,
            treasury_stray_funds_e8s: v2.treasury_stray_funds_e8s,
            // The schema-2 monitor never read `arithmetic_error`, so it never
            // observed an UNAVAILABLE. `false` is the truthful reading of a
            // snapshot taken before the signal existed — NOT a claim that the
            // invariant was evaluated successfully at that moment.
            supply_invariant_unavailable: false,
            refreshed_at_ns: v2.refreshed_at_ns,
            max_staleness_ns: v2.max_staleness_ns,
            status: v2.status,
            healthy: v2.healthy,
            // Re-stamped: this record is now expressed in, and re-encoded by,
            // the v3 layout, in which bit 4 is defined and clear. Publishing a
            // v3-encoded leaf under a `2` tag would misdescribe the very bytes
            // `canonical_bytes` is about to emit.
            schema_version: SCHEMA_VERSION,
        }
    }
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static STABLE_STATE_CELL: RefCell<Cell<Vec<u8>, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_STABLE_STATE)),
            vec![],
        ).expect("STABLE_STATE_CELL: Cell::init failed — stable memory corrupt")
    );

    static CONFIG: RefCell<Option<MonitorInit>> = RefCell::new(None);

    /// Latest snapshot — always Some after init (placeholder until the first
    /// refresh lands).
    static SNAPSHOT: RefCell<Option<SolvencySnapshot>> = RefCell::new(None);

    /// Bounded ring buffer of refresh results (placeholder excluded).
    static HISTORY: RefCell<VecDeque<SolvencySnapshot>> = RefCell::new(VecDeque::new());

    /// Certified tree — TREE_KEY → canonical snapshot bytes.
    static TREE: RefCell<RbTree<&'static str, Vec<u8>>> = RefCell::new(RbTree::new());

    /// Heap-only owner of the refresh currently awaiting its sources. The
    /// generation prevents a late callback from an expired attempt from
    /// committing over, or releasing, its replacement.
    static REFRESH_OWNER: RefCell<Option<RefreshOwner>> = RefCell::new(None);
    static NEXT_REFRESH_GENERATION: RefCell<u64> = RefCell::new(0);

    /// Last refresh attempt (timer or manual) — rate-limits request_refresh.
    static LAST_REFRESH_ATTEMPT_NS: RefCell<u64> = RefCell::new(0);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RefreshOwner {
    generation: u64,
    sample_started_at_ns: u64,
}

fn config() -> MonitorInit {
    CONFIG.with(|c| c.borrow().clone().expect("monitor not initialised"))
}

fn current_snapshot() -> SolvencySnapshot {
    SNAPSHOT.with(|s| s.borrow().clone().expect("monitor not initialised"))
}

fn acquire_refresh_owner(now_ns: u64) -> Option<RefreshOwner> {
    REFRESH_OWNER.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some(owner) = *slot {
            if now_ns.saturating_sub(owner.sample_started_at_ns) < REFRESH_GUARD_EXPIRY_NS {
                return None;
            }
        }
        let generation = NEXT_REFRESH_GENERATION.with(|next| {
            let mut next = next.borrow_mut();
            let generation = next.checked_add(1)?;
            *next = generation;
            Some(generation)
        })?;
        let owner = RefreshOwner { generation, sample_started_at_ns: now_ns };
        *slot = Some(owner);
        Some(owner)
    })
}

fn commit_and_release_if_owner(owner: RefreshOwner, snapshot: SolvencySnapshot) -> bool {
    REFRESH_OWNER.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref() != Some(&owner) {
            return false;
        }
        commit_snapshot(snapshot, true);
        *slot = None;
        true
    })
}

/// Store a new snapshot, append it to history (if from a real refresh),
/// rebuild the certified tree, and re-certify the root.
fn commit_snapshot(snapshot: SolvencySnapshot, record_in_history: bool) {
    if record_in_history {
        let cap = config().history_capacity as usize;
        HISTORY.with(|h| {
            let mut h = h.borrow_mut();
            while h.len() >= cap {
                h.pop_front();
            }
            h.push_back(snapshot.clone());
        });
    }
    let bytes = snapshot.canonical_bytes();
    SNAPSHOT.with(|s| *s.borrow_mut() = Some(snapshot));
    TREE.with(|t| {
        let mut t = t.borrow_mut();
        t.insert(TREE_KEY, bytes);
        publish_certified_data(&t.root_hash());
    });
}

/// Rebuild the certified tree from the stored snapshot (post_upgrade path).
fn publish_certified_data(root: &[u8; 32]) {
    #[cfg(target_arch = "wasm32")]
    ic_cdk::api::set_certified_data(root);
    #[cfg(all(not(target_arch = "wasm32"), test))]
    TEST_CERTIFIED_DATA.with(|value| *value.borrow_mut() = *root);
}

fn attempt_is_overlong(started_at_ns: u64, completed_at_ns: u64, max_staleness_ns: u64) -> bool {
    completed_at_ns.saturating_sub(started_at_ns) > max_staleness_ns
}

fn enforce_attempt_age(
    previous: &SolvencySnapshot,
    cfg: &MonitorInit,
    started_at_ns: u64,
    completed_at_ns: u64,
    candidate: SolvencySnapshot,
) -> SolvencySnapshot {
    if attempt_is_overlong(started_at_ns, completed_at_ns, cfg.max_staleness_ns) {
        failure_snapshot(previous, cfg, started_at_ns, SnapshotStatus::RefreshFailed)
    } else {
        candidate
    }
}

fn recertify_from_state() {
    let bytes = current_snapshot().canonical_bytes();
    TREE.with(|t| {
        let mut t = t.borrow_mut();
        t.insert(TREE_KEY, bytes);
        publish_certified_data(&t.root_hash());
    });
}

fn start_timers(immediate_first_refresh: bool) {
    let interval = Duration::from_nanos(config().refresh_interval_ns);
    ic_cdk_timers::set_timer_interval(interval, || ic_cdk::spawn(run_refresh()));
    // On init: replace the placeholder without waiting a full interval. On
    // post_upgrade the restored snapshot was current at pre_upgrade time, so
    // the interval cadence alone is enough.
    if immediate_first_refresh {
        ic_cdk_timers::set_timer(Duration::ZERO, || ic_cdk::spawn(run_refresh()));
    }
}

// ── Refresh (timer-driven update context) ─────────────────────────────────────

async fn run_refresh() {
    let sample_started_at_ns = time();
    let Some(owner) = acquire_refresh_owner(sample_started_at_ns) else { return; };
    LAST_REFRESH_ATTEMPT_NS.with(|l| *l.borrow_mut() = sample_started_at_ns);

    let cfg = config();
    let previous = current_snapshot();

    // (1) Token supply-invariant report.
    let supply: Result<(SupplyInvariantReport,), _> =
        ic_cdk::call(cfg.token_canister, "verify_supply_invariant", ()).await;

    // (2) Pool holdings on the token ledger.
    let pool_account = Account { owner: cfg.pool_principal, subaccount: None };
    let balance: Result<(Nat,), _> =
        ic_cdk::call(cfg.token_canister, "icrc1_balance_of", (pool_account,)).await;

    // (3) v2 (D-2): the pool's certified solvency attestation — the RED source.
    let attestation: Result<(CertifiedSolvencyAttestationMirror,), _> = ic_cdk::call(
        cfg.pool_attestation_source,
        "get_solvency_attestation",
        (),
    )
    .await;

    // (4) v2 (D-4): stray funds in the treasury account — YELLOW only. Read off
    // the TOKEN ledger, so the monitor still makes zero calls to the treasury.
    let treasury_account = Account { owner: cfg.treasury_principal, subaccount: None };
    let treasury_balance: Result<(Nat,), _> =
        ic_cdk::call(cfg.token_canister, "icrc1_balance_of", (treasury_account,)).await;

    // Completion time independently governs pool-source and attempt age.
    // The stored timestamp is the conservative start of the serial sample.
    let completed_at_ns = time();
    let refreshed_at_ns = sample_started_at_ns;

    // Fail closed: any failure writes a NEW unhealthy snapshot. Numeric fields
    // carry the previous snapshot's figures for dashboard continuity — status
    // and healthy are authoritative, and status != Fresh means "figures are
    // from the last successful refresh, not this attempt".
    // ── Fold the pool attestation. Every non-Ok outcome is unhealthy ────────
    let (pool_attestation_source_status, pool_delta_healthy, pool_public_delta_e8s,
         pool_attested_at_ns) = match attestation {
        Ok((certified,)) => {
            let a = certified.attestation;
            if a.schema_version != POOL_ATTESTATION_SCHEMA {
                // A pool speaking a schema we do not understand is Malformed —
                // never read optimistically through a version we cannot check.
                (SourceReadStatus::Malformed, false, 0, 0)
            } else if solvency_attestation_bytes_mismatch(&certified) {
                // The committed leaf and the display record disagree. One of
                // them is a lie and we cannot tell which, so neither is used.
                (SourceReadStatus::Malformed, false, 0, a.attested_at_ns)
            } else if attestation_is_stale(completed_at_ns, a.attested_at_ns, cfg.max_staleness_ns) {
                (SourceReadStatus::Stale, false, a.public_delta_e8s, a.attested_at_ns)
            } else {
                (
                    SourceReadStatus::Ok,
                    a.healthy,
                    a.public_delta_e8s,
                    a.attested_at_ns,
                )
            }
        }
        Err(_) => (SourceReadStatus::CallFailed, false, 0, 0),
    };

    // ── Fold the treasury read. NEVER touches `healthy` ─────────────────────
    let (treasury_read_status, treasury_stray_funds_e8s) = match treasury_balance {
        Ok((nat,)) => match nat.0.to_u128() {
            Some(v) => (SourceReadStatus::Ok, v),
            // Out of u128 — unusable, reported explicitly rather than as zero.
            // Zero and "unknown" must not render the same: zero means no stray
            // funds, unknown means we could not tell.
            None => (SourceReadStatus::Malformed, 0),
        },
        Err(_) => (SourceReadStatus::CallFailed, 0),
    };

    let candidate = match (supply, balance) {
        (Ok((report,)), Ok((pool_nat,))) => match pool_nat.0.to_u128() {
            Some(pool_balance_e8s) => {
                // K3-002b: a non-null arithmetic_error means the invariant
                // could not be soundly evaluated — UNHEALTHY regardless of
                // what invariant_holds claims. Fail closed.
                let fresh_and_sound =
                    report.invariant_holds && report.arithmetic_error.is_none();
                // v3 (R-4): carry the REASON into the wire encoding. The
                // conjunct above already reads arithmetic_error for `healthy`;
                // until now nothing propagated it, so the page could not tell
                // "could not compute" from "computed, and it is false".
                let supply_invariant_unavailable = report.arithmetic_error.is_some();
                // v2: RED is now backing-broken as well as supply-broken. The
                // pool's attestation must have been READ SOUNDLY *and* say the
                // backing holds; either half missing is unhealthy. The treasury
                // stray-funds read is deliberately absent from this expression —
                // it is YELLOW, and folding it in would make foreign funds able
                // to turn the alarm red.
                let pool_backing_sound =
                    pool_attestation_source_status == SourceReadStatus::Ok && pool_delta_healthy;
                SolvencySnapshot {
                    supply_invariant_holds: fresh_and_sound,
                    fixed_max_supply_e8s: report.fixed_max_supply,
                    sum_all_balances_e8s: report.sum_all_balances,
                    pool_balance_e8s,
                    pool_attestation_source_status,
                    pool_delta_healthy,
                    pool_public_delta_e8s,
                    pool_attested_at_ns,
                    treasury_read_status,
                    treasury_stray_funds_e8s,
                    supply_invariant_unavailable,
                    refreshed_at_ns,
                    max_staleness_ns: cfg.max_staleness_ns,
                    status: SnapshotStatus::Fresh,
                    healthy: fresh_and_sound && pool_backing_sound,
                    schema_version: SCHEMA_VERSION,
                }
            }
            // Balance outside u128 — unusable data, fail closed.
            None => failure_snapshot(&previous, &cfg, refreshed_at_ns, SnapshotStatus::RefreshFailed),
        },
        _ => failure_snapshot(&previous, &cfg, refreshed_at_ns, SnapshotStatus::SourceCallFailed),
    };
    let snapshot = enforce_attempt_age(
        &previous,
        &cfg,
        sample_started_at_ns,
        completed_at_ns,
        candidate,
    );

    commit_and_release_if_owner(owner, snapshot);
}

fn failure_snapshot(
    previous: &SolvencySnapshot,
    cfg: &MonitorInit,
    refreshed_at_ns: u64,
    status: SnapshotStatus,
) -> SolvencySnapshot {
    SolvencySnapshot {
        supply_invariant_holds: false,
        fixed_max_supply_e8s: previous.fixed_max_supply_e8s,
        sum_all_balances_e8s: previous.sum_all_balances_e8s,
        pool_balance_e8s: previous.pool_balance_e8s,
        // v2: the numeric fields keep the last successful figures for dashboard
        // continuity (v1's rule, unchanged), but every STATUS field is reset to
        // a failure value. Carrying a stale `Ok` next to a stale figure is what
        // would let a dead refresh read as a live green.
        pool_attestation_source_status: SourceReadStatus::CallFailed,
        pool_delta_healthy: false,
        pool_public_delta_e8s: previous.pool_public_delta_e8s,
        pool_attested_at_ns: previous.pool_attested_at_ns,
        treasury_read_status: SourceReadStatus::CallFailed,
        treasury_stray_funds_e8s: previous.treasury_stray_funds_e8s,
        // A failed refresh read NO report, so it observed no arithmetic error.
        // `status` is the authoritative field for "this attempt did not
        // succeed"; claiming an arithmetic error the token never reported would
        // be a fabricated reason.
        supply_invariant_unavailable: false,
        refreshed_at_ns,
        max_staleness_ns: cfg.max_staleness_ns,
        status,
        healthy: false,
        schema_version: SCHEMA_VERSION,
    }
}

/// Does the pool's committed leaf disagree with the record it shipped alongside?
///
/// The monitor re-encodes the pool's canonical layout from the DISPLAY record
/// and compares. A mismatch means the certified bytes and the Candid record are
/// not the same statement — the one failure a certified read is supposed to make
/// impossible — so the attestation is Malformed and unusable.
///
/// This is a consistency check on the pool's own two representations. It is NOT
/// certificate verification: the monitor cannot verify another canister's
/// certificate in a query context, and the WEBSITE does that end-to-end.
fn solvency_attestation_bytes_mismatch(c: &CertifiedSolvencyAttestationMirror) -> bool {
    const POOL_TAG: &[u8; 24] = b"stsh-pool-attestation-v1";
    const POOL_LEN: usize = 53;
    let a = &c.attestation;
    let mut expect = Vec::with_capacity(POOL_LEN);
    expect.extend_from_slice(POOL_TAG);
    expect.extend_from_slice(&a.schema_version.to_be_bytes());
    expect.push(a.healthy as u8);
    expect.extend_from_slice(&a.public_delta_e8s.to_be_bytes());
    expect.extend_from_slice(&a.attested_at_ns.to_be_bytes());
    c.canonical_bytes.as_ref() != expect.as_slice()
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

fn validate_config(cfg: &MonitorInit) {
    assert!(
        cfg.token_canister != Principal::anonymous()
            && cfg.token_canister != Principal::management_canister(),
        "token_canister must be a real canister principal"
    );
    assert!(
        cfg.pool_principal != Principal::anonymous(),
        "pool_principal must be a real principal"
    );
    // v2: the config is IMMUTABLE and the canister is blackholed at launch, so a
    // placeholder principal here is permanent. Reject it at install, where it is
    // still fixable, rather than shipping a monitor that can never read its
    // RED source.
    assert!(
        cfg.treasury_principal != Principal::anonymous(),
        "treasury_principal must be a real principal"
    );
    assert!(
        cfg.pool_attestation_source != Principal::anonymous()
            && cfg.pool_attestation_source != Principal::management_canister(),
        "pool_attestation_source must be a real canister principal"
    );
    assert!(
        cfg.refresh_interval_ns >= MIN_REFRESH_INTERVAL_NS,
        "refresh_interval_ns below minimum ({MIN_REFRESH_INTERVAL_NS} ns)"
    );
    // A staleness bound tighter than the refresh cadence guarantees permanent
    // red — reject the misconfiguration up front (it is permanent once
    // blackholed).
    assert!(
        cfg.max_staleness_ns >= cfg.refresh_interval_ns,
        "max_staleness_ns must be >= refresh_interval_ns"
    );
    assert!(
        cfg.history_capacity >= 1 && cfg.history_capacity <= MAX_HISTORY_CAPACITY,
        "history_capacity must be in 1..={MAX_HISTORY_CAPACITY}"
    );
}

#[init]
fn init(cfg: MonitorInit) {
    validate_config(&cfg);
    CONFIG.with(|c| *c.borrow_mut() = Some(cfg.clone()));

    // Fail-closed placeholder until the first refresh lands: Stale, unhealthy,
    // zeroed figures. Not recorded in history (it is not a refresh result).
    let placeholder = SolvencySnapshot {
        supply_invariant_holds: false,
        fixed_max_supply_e8s: 0,
        sum_all_balances_e8s: 0,
        pool_balance_e8s: 0,
        // v2: before the first refresh the monitor has read NOTHING, so both
        // sources report CallFailed rather than a zero that could be mistaken
        // for "read it, found nothing".
        pool_attestation_source_status: SourceReadStatus::CallFailed,
        pool_delta_healthy: false,
        pool_public_delta_e8s: 0,
        pool_attested_at_ns: 0,
        treasury_read_status: SourceReadStatus::CallFailed,
        treasury_stray_funds_e8s: 0,
        supply_invariant_unavailable: false,
        refreshed_at_ns: time(),
        max_staleness_ns: cfg.max_staleness_ns,
        status: SnapshotStatus::Stale,
        healthy: false,
        schema_version: SCHEMA_VERSION,
    };
    commit_snapshot(placeholder, false);
    start_timers(true);
}

#[pre_upgrade]
fn pre_upgrade() {
    let state = MonitorStableState {
        version: STATE_VERSION,
        config: config(),
        snapshot: current_snapshot(),
        history: HISTORY.with(|h| h.borrow().iter().cloned().collect()),
        last_refresh_attempt_ns: LAST_REFRESH_ATTEMPT_NS.with(|l| *l.borrow()),
    };
    let bytes = candid::encode_one(&state).expect("pre_upgrade: state encode failed");
    STABLE_STATE_CELL.with(|c| {
        c.borrow_mut()
            .set(bytes)
            .expect("pre_upgrade: stable cell write failed");
    });
}

#[post_upgrade]
fn post_upgrade() {
    let bytes = STABLE_STATE_CELL.with(|c| c.borrow().get().clone());

    // EXPLICIT VERSION ARM (SSA landed-diff round-1 RED-1). The v2 -> v3 field
    // addition is NOT Candid-compatible in the decode direction: a required
    // (non-`opt`) record field absent from the stored bytes fails subtyping, so
    // decoding a live schema-2 checkpoint straight into `MonitorStableState`
    // traps and the mainnet upgrade is rejected. Probe the version first, then
    // decode the layout that version actually names.
    let probed: StateVersionProbe =
        candid::decode_one(&bytes).expect("post_upgrade: state version probe failed");
    let state: MonitorStableState = match probed.version {
        STATE_VERSION => {
            candid::decode_one(&bytes).expect("post_upgrade: state decode failed")
        }
        STATE_VERSION_PRE_V3 => {
            let old: MonitorStableStatePreV3 = candid::decode_one(&bytes)
                .expect("post_upgrade: pre-v3 state decode failed");
            MonitorStableState {
                version: STATE_VERSION,
                config: old.config,
                snapshot: old.snapshot.into(),
                history: old.history.into_iter().map(Into::into).collect(),
                last_refresh_attempt_ns: old.last_refresh_attempt_ns,
            }
        }
        v => ic_cdk::trap(&format!("post_upgrade: unknown state version {v}")),
    };
    assert_eq!(state.version, STATE_VERSION, "post_upgrade: unknown state version");

    validate_config(&state.config);
    let cap = state.config.history_capacity as usize;
    CONFIG.with(|c| *c.borrow_mut() = Some(state.config));
    SNAPSHOT.with(|s| *s.borrow_mut() = Some(state.snapshot));
    HISTORY.with(|h| {
        let mut restored: VecDeque<SolvencySnapshot> = state.history.into();
        while restored.len() > cap {
            restored.pop_front();
        }
        *h.borrow_mut() = restored;
    });
    LAST_REFRESH_ATTEMPT_NS.with(|l| *l.borrow_mut() = state.last_refresh_attempt_ns);

    // Certified data is cleared on upgrade — re-establish it, then restart the
    // timers (they do not survive upgrades either).
    recertify_from_state();
    start_timers(false);
}

// ── Public API ────────────────────────────────────────────────────────────────

/// The certified read: snapshot + the exact committed leaf bytes + subnet
/// certificate + Merkle witness. Clients verify the certificate against the IC
/// root key, check freshness (cert /time vs refreshed_at_ns), and parse the
/// witness-verified leaf bytes.
#[query]
fn get_certified_snapshot() -> CertifiedSolvencySnapshot {
    let snapshot = current_snapshot();
    let canonical = snapshot.canonical_bytes();

    let witness_cbor = TREE.with(|t| {
        let t = t.borrow();
        let witness = t.witness(TREE_KEY.as_bytes());
        let mut out = Vec::new();
        let mut serializer = serde_cbor::Serializer::new(&mut out);
        serializer
            .self_describe()
            .expect("witness CBOR self-describe failed");
        witness
            .serialize(&mut serializer)
            .expect("witness CBOR serialization failed");
        out
    });

    CertifiedSolvencySnapshot {
        snapshot,
        canonical_bytes: ByteBuf::from(canonical),
        certificate: data_certificate().map(ByteBuf::from),
        witness: ByteBuf::from(witness_cbor),
    }
}

/// Uncertified convenience read of the latest snapshot.
#[query]
fn get_snapshot() -> SolvencySnapshot {
    current_snapshot()
}

/// Uncertified refresh history (oldest first, bounded by history_capacity).
#[query]
fn get_history() -> Vec<SolvencySnapshot> {
    HISTORY.with(|h| h.borrow().iter().cloned().collect())
}

/// Reader-side derived health: applies the staleness rule against time().
/// Uncertified — the certified snapshot is the trust anchor.
#[query]
fn get_health_status() -> HealthStatus {
    let snapshot = current_snapshot();
    let age = time().saturating_sub(snapshot.refreshed_at_ns);
    let stale = age > snapshot.max_staleness_ns;
    HealthStatus {
        healthy: snapshot.healthy && !stale,
        status: if stale { SnapshotStatus::Stale } else { snapshot.status },
        snapshot_age_ns: age,
        cycles_balance: ic_cdk::api::canister_balance128(),
    }
}

/// The immutable init config (public transparency — verifiable target IDs).
#[query]
fn get_config() -> MonitorInit {
    config()
}

/// Anyone may kick a refresh (liveness safety valve for the blackholed
/// canister), rate-limited to protect the cycle reserve. Also re-arms the
/// refresh guard path; returns Err when rate-limited or already running.
#[update]
async fn request_refresh() -> Result<(), String> {
    let now = time();
    let last = LAST_REFRESH_ATTEMPT_NS.with(|l| *l.borrow());
    if now.saturating_sub(last) < MANUAL_REFRESH_MIN_GAP_NS {
        return Err("rate-limited: try again later".to_string());
    }
    run_refresh().await;
    Ok(())
}


#[cfg(test)]
thread_local! {
    static TEST_CERTIFIED_DATA: RefCell<[u8; 32]> = RefCell::new([0; 32]);
}

#[cfg(test)]
mod l09_tests {
    use super::*;

    fn principal(byte: u8) -> Principal {
        Principal::from_slice(&[byte])
    }

    fn cfg() -> MonitorInit {
        MonitorInit {
            token_canister: principal(1),
            pool_principal: principal(2),
            treasury_principal: principal(3),
            pool_attestation_source: principal(4),
            refresh_interval_ns: MIN_REFRESH_INTERVAL_NS,
            max_staleness_ns: REFRESH_GUARD_EXPIRY_NS,
            history_capacity: 8,
        }
    }

    fn snapshot(marker: u128, started_at_ns: u64, status: SnapshotStatus) -> SolvencySnapshot {
        SolvencySnapshot {
            supply_invariant_holds: status == SnapshotStatus::Fresh,
            fixed_max_supply_e8s: marker,
            sum_all_balances_e8s: marker,
            pool_balance_e8s: marker,
            pool_attestation_source_status: SourceReadStatus::Ok,
            pool_delta_healthy: status == SnapshotStatus::Fresh,
            pool_public_delta_e8s: 0,
            pool_attested_at_ns: started_at_ns,
            treasury_read_status: SourceReadStatus::Ok,
            treasury_stray_funds_e8s: 0,
            supply_invariant_unavailable: false,
            refreshed_at_ns: started_at_ns,
            max_staleness_ns: REFRESH_GUARD_EXPIRY_NS,
            status,
            healthy: status == SnapshotStatus::Fresh,
            schema_version: SCHEMA_VERSION,
        }
    }

    fn reset() {
        CONFIG.with(|v| *v.borrow_mut() = Some(cfg()));
        SNAPSHOT.with(|v| *v.borrow_mut() = Some(snapshot(0, 0, SnapshotStatus::Stale)));
        HISTORY.with(|v| v.borrow_mut().clear());
        TREE.with(|v| *v.borrow_mut() = RbTree::new());
        REFRESH_OWNER.with(|v| *v.borrow_mut() = None);
        NEXT_REFRESH_GENERATION.with(|v| *v.borrow_mut() = 0);
        TEST_CERTIFIED_DATA.with(|v| *v.borrow_mut() = [0; 32]);
    }

    #[test]
    fn l09_expiry_boundary_and_generation_overflow_refuse_without_owner_loss() {
        reset();
        let a = acquire_refresh_owner(10).expect("A acquires");
        assert!(acquire_refresh_owner(10 + REFRESH_GUARD_EXPIRY_NS - 1).is_none());
        let b = acquire_refresh_owner(10 + REFRESH_GUARD_EXPIRY_NS).expect("equality permits B");
        assert!(b.generation > a.generation);
        REFRESH_OWNER.with(|v| assert_eq!(*v.borrow(), Some(b)));

        NEXT_REFRESH_GENERATION.with(|v| *v.borrow_mut() = u64::MAX);
        assert!(acquire_refresh_owner(
            b.sample_started_at_ns + REFRESH_GUARD_EXPIRY_NS
        ).is_none());
        REFRESH_OWNER.with(|v| assert_eq!(*v.borrow(), Some(b)));
    }

    #[test]
    fn l09_late_a_success_or_failure_cannot_mutate_or_release_after_b_commits() {
        for late_status in [SnapshotStatus::Fresh, SnapshotStatus::RefreshFailed] {
            reset();
            let a = acquire_refresh_owner(0).expect("A acquires");
            let b = acquire_refresh_owner(REFRESH_GUARD_EXPIRY_NS).expect("B replaces expired A");
            assert!(commit_and_release_if_owner(
                b,
                snapshot(22, b.sample_started_at_ns, SnapshotStatus::Fresh),
            ));

            let before_snapshot = current_snapshot().canonical_bytes();
            let before_history: Vec<Vec<u8>> = HISTORY.with(|v| {
                v.borrow().iter().map(SolvencySnapshot::canonical_bytes).collect()
            });
            let before_tree = TREE.with(|v| v.borrow().root_hash());
            let before_certified = TEST_CERTIFIED_DATA.with(|v| *v.borrow());
            assert!(!commit_and_release_if_owner(
                a,
                snapshot(11, a.sample_started_at_ns, late_status),
            ));
            assert_eq!(current_snapshot().canonical_bytes(), before_snapshot);
            let after_history: Vec<Vec<u8>> = HISTORY.with(|v| {
                v.borrow().iter().map(SolvencySnapshot::canonical_bytes).collect()
            });
            assert_eq!(after_history, before_history);
            assert_eq!(TREE.with(|v| v.borrow().root_hash()), before_tree);
            assert_eq!(TEST_CERTIFIED_DATA.with(|v| *v.borrow()), before_certified);
            REFRESH_OWNER.with(|v| assert!(v.borrow().is_none()));
        }
    }

    #[test]
    fn l09_late_a_failure_cannot_release_b_still_in_flight() {
        reset();
        let a = acquire_refresh_owner(0).expect("A acquires");
        let b = acquire_refresh_owner(REFRESH_GUARD_EXPIRY_NS).expect("B replaces expired A");
        assert!(!commit_and_release_if_owner(a, snapshot(11, 0, SnapshotStatus::SourceCallFailed)));
        REFRESH_OWNER.with(|v| assert_eq!(*v.borrow(), Some(b)));
        assert!(commit_and_release_if_owner(b, snapshot(22, b.sample_started_at_ns, SnapshotStatus::RefreshFailed)));
    }

    #[test]
    fn l09_freshness_and_attempt_age_boundaries_are_strict() {
        let max = 100;
        assert!(!attempt_is_overlong(1_000, 1_000 + max, max));
        assert!(attempt_is_overlong(1_000, 1_000 + max + 1, max));
        let config = cfg();
        let previous = snapshot(7, 999, SnapshotStatus::Fresh);
        let candidate = snapshot(8, 1_000, SnapshotStatus::Fresh);
        let at_boundary = enforce_attempt_age(
            &previous,
            &config,
            1_000,
            1_000 + config.max_staleness_ns,
            candidate.clone(),
        );
        assert_eq!(at_boundary.status, SnapshotStatus::Fresh);
        let overlong = enforce_attempt_age(
            &previous,
            &config,
            1_000,
            1_000 + config.max_staleness_ns + 1,
            candidate,
        );
        assert_eq!(overlong.status, SnapshotStatus::RefreshFailed);
        assert!(!overlong.healthy);
        assert_eq!(overlong.refreshed_at_ns, 1_000);

        let tolerance = max + ATTESTATION_BUCKET_NS;
        assert!(!attestation_is_stale(2_000 + tolerance, 2_000, max));
        assert!(attestation_is_stale(2_000 + tolerance + 1, 2_000, max));
        assert!(attestation_is_stale(u64::MAX, 0, u64::MAX));
    }
}
