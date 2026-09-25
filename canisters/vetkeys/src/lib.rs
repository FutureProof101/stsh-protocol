// =============================================================================
// stsh_vetkeys — II-anchored vetKeys key-manager canister
// =============================================================================
//
// Derives a per-user vetKey (BLS12-381 G2 vetKD) from the caller's Internet
// Identity principal, via the `ic-vetkeys` KeyManager library. This one key is
// the mechanism behind cross-device access, viewing keys, and recovery:
// any device that authenticates the same II principal re-derives the identical
// key, re-derives the identical note secrets from it, and rebuilds the wallet's
// note set from public on-chain data alone (merkle-tree `get_payloads`, whose
// public/paginated status is the reviewed DEF-073 policy).
//
// BACKEND COUPLING (freeze-compatible — BRIEF_VETKEYS_CROSSDEVICE §0, as
// amended by LAUNCH-HARDEN-04 O-1(b)): this canister calls only the IC
// management canister (vetkd_public_key / vetkd_derive_key) and the token's
// read-only `icrc1_balance_of` (§D). It never calls the shielded-pool,
// verifier, nullifier-registry, or merkle-tree canisters. It IS called by
// exactly one of them: the shielded pool's `private_spend` device gate queries
// `has_active_device`, answered ONLY to the principal configured in MemoryId 20. Note payloads remain
// opaque `Vec<u8>` to the backend; only their (wallet-side) encryption scheme
// changes to IBE-to-principal.
//
// SECURITY MODEL
// - Key id = (caller principal, KEY_NAME). The derivation input is built from
//   the caller's OWN principal, and KeyManager's `ensure_user_can_read` only
//   admits the owner or an explicitly-granted principal. No sharing endpoints
//   are exposed in v1, so no grants can exist → strictly owner-only. A caller
//   cannot obtain another user's key by construction (asserted in the
//   cross-device integration tests).
// - Anonymous callers are rejected before any derivation.
// - The context (domain separator) and key name are PINNED constants and must
//   byte-match the wallet (`wallet/src/crypto/vetkeys.ts`). A mismatch silently
//   breaks decryption — the wallet asserts them against `get_config()`.
//
// DEPENDENCY NOTE: this crate uses ic-cdk 0.20 (required by ic-vetkeys 0.7)
// while the audited canisters pin ic-cdk 0.16. Safe: each canister is its own
// Wasm; the majors never meet in one binary. See Cargo.toml.
//
// CYCLES: `vetkd_derive_key` attaches its own cycles cost internally
// (ic-cdk-management-canister computes it via `cost_vetkd_derive_key`;
// ~26B cycles on the production `key_1`). `vetkd_public_key` attaches ZERO —
// but zero ATTACHED is not free: it is still a real, awaited inter-canister
// round trip to the management canister, paid out of this canister's own
// execution budget on every call. R-5 (L04-02) caches its result in
// MemoryId 18 so that round trip happens once, not once per wallet session.
// =============================================================================

use std::cell::RefCell;

use candid::{CandidType, Deserialize, Principal};
use ic_cdk::{init, post_upgrade, query, update};
use ic_cdk_management_canister::{VetKDCurve, VetKDKeyId};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Blob;
use ic_stable_structures::DefaultMemoryImpl;
use ic_vetkeys::key_manager::KeyManager;
use ic_vetkeys::types::{AccessRights, TransportKey};

use sha2::{Digest, Sha256};

use crate::state::{
    DeviceApprovalPolicyV1, DEVICE_APPROVAL_POLICY,
    AdmissionState, ApprovedBy, DeviceIdKey, DeviceKey, DeviceRecord, DeviceStatus, NonceKey,
    NonceExpiryKey, PrincipalKey, WrappedSecret, ADMISSION, BOOTSTRAP_TICKETS, CONSUMED_NONCES,
    DEVICES, NONCE_EXPIRY_INDEX,
    ESTABLISHED, REGISTRATIONS, REPLACEMENTS, REVOCATION_RATE, WRAPPED_SECRETS,
    RebootstrapPolicyV1, RE_BOOTSTRAP_POLICY,
};

// W-VETKEYS two-layer (D-1): the lane's frozen encodings and stable layouts.
// `pins` and `transcript` are pure; `state` owns MemoryIds 3–9. None of the
// three is wired into an endpoint yet — commit 1 is the freeze, per the
// amount-rows precedent.
//
// `#[allow(dead_code)]` is scoped to these three modules and is a COMMIT-1-ONLY
// state: nothing calls them yet because the freeze deliberately lands ahead of
// behaviour. The allow comes OFF in the commit that wires the admission machine
// into `get_encrypted_vetkey`; if it is still here after that, the modules are
// genuinely dead and that is a finding, not a warning.
mod admission;
mod fence;
mod pins;
mod registry;
// The commit-1 `#[allow(dead_code)]` is GONE, as its own note required: commit 2
// wires `sightings` into `check_first_derive_eligibility`, so every item in it is
// reachable from a shipped path and the compiler is now the one enforcing that.
mod sightings;
mod state;
mod tickets;
mod transcript;
mod verify;

pub(crate) type Memory = VirtualMemory<DefaultMemoryImpl>;

/// vetKD context / domain separator — PINNED (brief §2). Must byte-match the
/// wallet's `CONTEXT` in `wallet/src/crypto/vetkeys.ts`. Changing it re-keys
/// every user (all previously encrypted payloads become undecryptable).
const DOMAIN_SEPARATOR: &str = "stsh.wallet.notes.v1";

/// Key name inside the (principal, name) key id — PINNED. Part of the vetKD
/// derivation input `len(principal) || principal || KEY_NAME`, and therefore
/// part of the wallet's OFFLINE IBE identity for encrypting payloads to a
/// recipient principal. Must byte-match the wallet.
const KEY_NAME: &[u8] = b"notes";

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static KEY_MANAGER: RefCell<Option<KeyManager<AccessRights>>> = const { RefCell::new(None) };
}

/// Take the `MemoryId` itself, not a `u8`, so every allocation is written as a
/// literal AT THE CALL SITE. Hiding `MemoryId::new(id)` behind a helper made
/// these three allocations invisible to the registry lint — they were absent
/// from both the code inventory and docs/MEMORY_ID_REGISTRY.md, so the gate
/// passed vacuously for all three. See the P1 hardening in
/// scripts/verify_memory_ids.
pub(crate) fn mem(id: MemoryId) -> Memory {
    MEMORY_MANAGER.with(|m| m.borrow().get(id))
}

fn init_key_manager(vetkd_key_name: String) {
    let key_id = VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: vetkd_key_name,
    };
    KEY_MANAGER.with_borrow_mut(|km| {
        km.replace(KeyManager::init(
            DOMAIN_SEPARATOR,
            key_id,
            mem(MemoryId::new(0)), // KeyManager config (StableCell)
            mem(MemoryId::new(1)), // access-control map
            mem(MemoryId::new(2)), // shared-keys map
        ));
    });
}

/// `vetkd_key_name`: `"test_key_1"` (or `"dfx_test_key"`) for local/testnet,
/// `"key_1"` for production mainnet — an install-time decision, not code.
///
/// `token_canister` (§D, CTO adjudication b216902b…): the token canister whose
/// `icrc1_balance_of` answers first-derive eligibility. TRAILING and OPTIONAL,
/// so the pre-existing one-argument install stays candid-compatible. `None`
/// leaves the cell ABSENT, which fails CLOSED at the eligibility check — an
/// unconfigured canister refuses first derives rather than admitting them.
///
/// `device_check_caller` (LAUNCH-HARDEN-04 O-1(b), MemoryId 20): the ONE
/// principal (the shielded pool) allowed to ask `has_active_device`. A SECOND
/// trailing optional, the exact `token_canister` precedent: `None` leaves the
/// cell ABSENT, which `has_active_device` REFUSES (`CallerNotConfigured`).
/// Anonymous or this canister's own id TRAPS the install.
#[init]
fn init(
    vetkd_key_name: String,
    token_canister: Option<Principal>,
    device_check_caller: Option<Principal>,
) {
    init_key_manager(vetkd_key_name);
    if let Some(token) = token_canister {
        state::set_token_canister(token);
    }
    if let Some(c) = device_check_caller {
        validate_device_check_caller(c);
        state::set_device_check_caller(c);
    }
    // The ephemeral observability counters start their epoch here (§3). The
    // epoch is part of the surface's CONTRACT, not a convenience: a consumer
    // that cannot see the reset would read a restart as a rate falling to zero.
    reset_stats_epoch(ic_cdk::api::time());
}

/// H-2 (A1): a key name that can NEVER be a real, deployable vetKD key name. A leading
/// NUL guarantees non-collision with `"key_1"` / `"test_key_1"` / `"dfx_test_key"` (all
/// printable ASCII) and any future IC vetKD key name (registry identifiers, never
/// NUL-prefixed). NUL is valid UTF-8, so it round-trips the config StableCell's Candid
/// `String` encoding (exercised end-to-end by the A2 case-3 fresh-cell upgrade test). It
/// exists only transiently inside `post_upgrade`: if it survives into the retained config
/// it PROVES the cell was fresh (stable config absent), and `post_upgrade` traps before
/// returning — so it is never persisted to a live canister and never reaches a derive.
const POST_UPGRADE_SENTINEL_KEY_NAME: &str =
    "\0__stsh_post_upgrade_sentinel__never_a_deployable_key__";

/// H-2 (A1): validate the `KeyManagerConfig` retained across an upgrade. PURE — no traps,
/// no I/O, no mutation — so it is unit-testable directly; `post_upgrade` maps `Err` to a
/// trap. Fail-closed:
///   - sentinel survived → the config StableCell was FRESH (stable config absent);
///   - domain separator mismatch → wrong/absent namespace;
///   - curve not `Bls12_381_G2` → wrong curve.
/// A legitimately installed key (`"key_1"` or an explicitly installed local test key)
/// passes and is preserved unchanged (this function never mutates anything).
fn validate_retained_config(
    domain_separator: &str,
    key_name: &str,
    curve: &VetKDCurve,
) -> Result<(), String> {
    if key_name == POST_UPGRADE_SENTINEL_KEY_NAME {
        return Err(
            "post_upgrade: the sentinel key name survived — the KeyManager stable config was \
             ABSENT (fresh cell). Accepting it would silently create a NEW cryptographic \
             namespace and permanently brick every user's notes. Aborting the upgrade. (A \
             reinstall must re-run #[init] with an explicit key name; a genuine upgrade must \
             carry a persisted config.)"
                .to_string(),
        );
    }
    if domain_separator != DOMAIN_SEPARATOR {
        return Err(format!(
            "post_upgrade: retained domain separator {domain_separator:?} != pinned \
             {DOMAIN_SEPARATOR:?} — namespace mismatch. Aborting to avoid re-keying every user."
        ));
    }
    if !matches!(curve, VetKDCurve::Bls12_381_G2) {
        return Err(format!(
            "post_upgrade: retained vetKD curve {curve:?} is not Bls12_381_G2. Aborting."
        ));
    }
    Ok(())
}

/// `token_canister` (§D): the SAME trailing optional argument as `#[init]`, so
/// configuration never requires a REINSTALL — which for this canister is the
/// catastrophic operation the H-2 machinery below exists to prevent.
///
///   * `Some(p)` — write the cell (set it, or replace what is there).
///   * `None`    — PRESERVE the cell untouched. Absent stays absent, set stays
///                 set. A routine upgrade must never silently unconfigure the
///                 canister, and must never silently configure it either.
///
/// `device_check_caller` (LAUNCH-HARDEN-04 O-1(b), MemoryId 20): a SECOND
/// trailing optional with the SAME semantics — `Some(p)` writes, `None`
/// PRESERVES. It is validated (anonymous / self → trap) BEFORE any write, and
/// only after the H-2 namespace validation. The trailing-`opt` extension is
/// candid-compatible with every existing caller (`()` and `(opt principal)`
/// both decode with the missing trailing opts as `None`).
#[post_upgrade]
fn post_upgrade(token_canister: Option<Principal>, device_check_caller: Option<Principal>) {
    // H-2 (A1) — fail CLOSED. Initialize with a non-deployable sentinel: on an
    // already-initialized StableCell (a genuine upgrade) KeyManager retains the STORED
    // config and ignores this default; on a FRESH cell the sentinel is what gets stored.
    // Then synchronously inspect the RETAINED config (no management-canister call — the
    // persisted KeyManagerConfig holds the domain separator + VetKDKeyId) and trap unless
    // it is a legitimately installed, correctly-namespaced key. The stored config is NEVER
    // mutated here. This replaces the prior unconditional `init_key_manager("test_key_1")`,
    // which leaned on the (unverified-at-runtime) StableCell-preserve assumption and would
    // silently re-key every user to the test key if that assumption ever broke (G1).
    init_key_manager(POST_UPGRADE_SENTINEL_KEY_NAME.to_string());
    let validation = with_key_manager(|km| {
        let config = km.config.get();
        validate_retained_config(
            &config.domain_separator,
            &config.key_id.name,
            &config.key_id.curve,
        )
    });
    if let Err(reason) = validation {
        ic_cdk::trap(&reason);
    }
    // L04-07 MIGRATION: NONE, and that is the design rather than an omission.
    // `RE_BOOTSTRAP_POLICY` (MemoryId 17) is a fresh region: on an upgrade from
    // a pre-lane build it is simply empty, every principal reads as having no
    // row, and an absent row is exactly the fail-closed "not authorized" the
    // gates want. Backfilling it would be the wrong direction — it would hand
    // out the authorization the lane exists to withhold. Nothing to write here.

    // AFTER the namespace validation, deliberately: a trap above must leave the
    // upgrade with no side effects at all. The device-check caller is VALIDATED
    // before either write, so a rejected arg traps with nothing written.
    if let Some(c) = device_check_caller {
        validate_device_check_caller(c);
    }
    if let Some(token) = token_canister {
        state::set_token_canister(token);
    }
    if let Some(c) = device_check_caller {
        state::set_device_check_caller(c);
    }
    // A new epoch for the ephemeral counters (§3). An upgrade genuinely does
    // reset them — they are heap — and `stats_epoch_ns` is what makes that
    // visible instead of silent. Deliberately AFTER the validation trap above,
    // for the same reason the token write is: a trapped upgrade leaves nothing
    // behind.
    reset_stats_epoch(ic_cdk::api::time());
}

/// LAUNCH-HARDEN-04 O-1(b): traps (rolling back the whole install/upgrade) on
/// the anonymous principal or this canister itself.
fn validate_device_check_caller(c: Principal) {
    if c == Principal::anonymous() || c == ic_cdk::api::canister_self() {
        ic_cdk::trap("device_check_caller must be a non-anonymous principal other than this canister");
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// R6-1 (lane A-2) — PER-CALLER METERING ON `get_encrypted_vetkey`
// ═════════════════════════════════════════════════════════════════════════════
//
// THE FINDING. `vetkd_derive_key` attaches ~26B cycles internally on the
// production `key_1` (see the file header). Before this metering, ANY
// authenticated principal could loop `get_encrypted_vetkey` and burn the
// canister's cycle balance to the freezing threshold — a Critical availability
// drain requiring one II identity and no special access.
//
// THE DESIGN — bounded table, fail-closed (CTO_RULING_A-2_saturation_residual).
// A per-principal counter over a rolling window, held in a BOUNDED heap table.
// Over budget → reject. Table full of live entries → reject. Both refusals are
// cheap and happen BEFORE the derivation is paid for.
//
// RESIDUAL, STATED ACCURATELY (do not soften this):
//   Each abandoned entry expires within one window. But an ACTIVE attacker can
//   refill slots as fast as they expire and hold the table saturated
//   INDEFINITELY, denying `get_encrypted_vetkey` to principals not already in
//   the table, for as long as the attack is sustained and funded.
// Sustaining it costs ~MAX_TRACKED_PRINCIPALS ingress messages per window —
// ~100,000 signed ingress messages/hour from 100,000 distinct principals. Real,
// not prohibitive. Compensating controls: lane A-6's monitor is the DETECTION
// path (hence `cycle_balance` below is load-bearing, not a convenience); the
// failure is fail-closed (no mint, no spend, no key leak, no drain — only
// delayed derivations for NEW callers); and recovery is automatic when the
// attack stops. The durable fix is anti-sybil eligibility, registered
// post-launch as A-2-PL1. See NOTE_A-2_table_saturation.md.
//
// NOT evict-and-admit: that is trivially defeated by principal rotation and
// degenerates to no metering at all — i.e. back to the Critical finding.

/// Derivations permitted per principal per window. The wallet generates a FRESH
/// transport key per session (`fetch_user_vet_key` in wallet/src/crypto/vetkeys.ts),
/// so a legitimate principal derives ONCE per session; 5/hour covers re-login,
/// multi-device and recovery churn with margin. Worst case per principal is
/// 5 × ~26B ≈ 130B cycles/hour, against unbounded today.
pub const MAX_DERIVATIONS_PER_WINDOW: u32 = 5;

/// The rolling window, in nanoseconds (1 hour).
pub const METER_WINDOW_NS: u64 = 3_600_000_000_000;

/// Hard cap on tracked principals — bounds heap growth. Reaching it rejects new
/// principals fail-closed rather than growing without limit.
pub const MAX_TRACKED_PRINCIPALS: usize = 100_000;

/// Minimum interval between full-table eviction sweeps (SSA-A2-D1).
///
/// THE DEFECT THIS CLOSES. Before this bound, every untracked caller arriving at
/// a full table ran `retain` across all `MAX_TRACKED_PRINCIPALS` entries — which
/// reclaims NOTHING when they are all live — and was then rejected. Rotating
/// principals could therefore force a 100,000-entry scan on every cheap rejected
/// ingress, indefinitely, without ever reaching or paying for vetKD. That is an
/// instruction-burn drain on the fail-closed path, i.e. the same category as the
/// R6-1 cycle drain this lane exists to close, sitting on the path taken MOST
/// under attack.
///
/// With this bound the sweep runs at most once per interval regardless of
/// arrival pattern, so repeated newcomer rejection is O(1) amortized. The cost is
/// bounded BY CONSTRUCTION rather than by an argument about arrival order, which
/// is why it is a cooldown rather than a cleverer predicate: an
/// "is reclamation possible?" check keyed on the oldest entry can be driven
/// stale by a tracked caller's window reset, and would hand the attacker back a
/// scan every other message.
///
/// TRADE, stated: an expired entry may linger up to this interval past its
/// expiry before being reclaimed, so a legitimate newcomer can be refused for up
/// to 60 s longer than strictly necessary. Against the 1-hour window that is
/// negligible, it is bounded, and it does not change the fail-closed bound or
/// the availability residual in NOTE_A-2_table_saturation.md.
pub const SWEEP_MIN_INTERVAL_NS: u64 = 60_000_000_000; // 60 s

/// Why a call was refused. One variant per limb, carrying what an operator (and
/// the wallet) needs to act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeterRejection {
    /// The caller has spent its window budget. `retry_after_ns` is the time
    /// remaining until this principal's window rolls over.
    OverBudget { retry_after_ns: u64 },
    /// The tracking table is full of LIVE (unexpired) entries. Fail-closed: a
    /// principal not already tracked cannot be admitted. See the residual above.
    TableSaturated,
}

impl MeterRejection {
    /// Operator/wallet-facing text. The variant is the machine-readable limb;
    /// this is the human half.
    pub fn message(&self) -> String {
        match self {
            MeterRejection::OverBudget { retry_after_ns } => format!(
                "rate limit: at most {} vetKey derivations per principal per {} s; \
                 retry in {} s",
                MAX_DERIVATIONS_PER_WINDOW,
                METER_WINDOW_NS / 1_000_000_000,
                retry_after_ns.div_ceil(1_000_000_000),
            ),
            MeterRejection::TableSaturated => format!(
                "rate-limit table saturated ({} tracked principals): the canister is \
                 refusing NEW derivations to protect its cycle balance. This is \
                 fail-closed and self-healing; retry shortly.",
                MAX_TRACKED_PRINCIPALS
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MeterEntry {
    window_start_ns: u64,
    count: u32,
}

/// The metering table.
///
/// **Deliberately exposes NO decrement, refund, release or remove-single-entry
/// API.** The only path that reduces a counter is expiry — either the per-entry
/// window reset or the eviction sweep, both inside `meter_admit`. A refund on a
/// failure branch therefore cannot be written without ADDING a method here,
/// which is visible in any diff review. That is the structural half of the
/// no-refund guarantee; the causal half is the charge-before-await ordering in
/// `get_encrypted_vetkey` and the E9 PocketIC proof.
#[derive(Default)]
pub struct MeterState {
    entries: std::collections::HashMap<Principal, MeterEntry>,
    /// When the last full-table sweep ran. `None` until the first one.
    last_sweep_ns: Option<u64>,
    /// Full-table sweeps performed. Monotonic.
    sweeps: u64,
    /// Total entries examined by sweeps. This is the COST observable: it is what
    /// SSA-A2-D1 is about, and it is what the bite proof asserts a bound on.
    entries_examined: u64,
}

impl MeterState {
    /// Read-only size, for tests and for the saturation limb. Not a mutator.
    pub fn tracked(&self) -> usize {
        self.entries.len()
    }

    /// Full-table sweeps performed so far. READ-ONLY STATISTIC.
    ///
    /// Justified as production-visible per CTO_RULING_A-2_sweep_amplification:
    /// the bite proof must be deterministic and countable rather than timed, and
    /// sweep cost is not observable from outside the struct. It is not a
    /// decrement, refund, release or remove-single-entry API — it cannot reduce
    /// any counter — so the no-refund structural guarantee is intact.
    pub fn sweeps(&self) -> u64 {
        self.sweeps
    }

    /// Entries examined by sweeps so far. READ-ONLY STATISTIC; same rationale.
    pub fn entries_examined(&self) -> u64 {
        self.entries_examined
    }
}

/// The metering decision — **PURE**: no `ic_cdk` call, no I/O, no await.
///
/// Mirrors the `validate_retained_config` idiom already used by this crate: the
/// decision is a pure function the endpoint maps onto its error channel, so
/// every limb is provable by a plain unit test with no PocketIC and no test-only
/// feature flag.
///
/// Limbs, each independently mutation-provable (see the package's §7 table):
/// 1. **per-entry window reset** — an entry whose window has elapsed starts a
///    fresh window at zero.
/// 2. **over-budget rejection** — at `MAX_DERIVATIONS_PER_WINDOW`, refuse.
/// 3. **per-principal keying** — the table is keyed by caller; one principal's
///    exhaustion cannot affect another's.
/// 4. **eviction sweep** — under table pressure, expired entries are reclaimed.
/// 5. **saturation rejection** — if the table is still full of LIVE entries,
///    refuse fail-closed.
///
/// ORDERING NOTE (deviation from the brief's literal sketch, disclosed in the
/// package and in NOTE_A-2_eviction_ordering.md): the brief's §4.2 sketches
/// "on every call: first evict expired entries; then, if at MAX, reject". This
/// implementation instead sweeps ONLY under pressure — when a NEW principal
/// arrives and the table is already full. Two reasons: (a) an unconditional
/// O(MAX_TRACKED_PRINCIPALS) sweep on every call is itself cheaply attacker-
/// triggerable, since the rejection paths are the cheap ones; (b) sweeping first
/// would make the per-entry window reset unreachable — an expired caller would
/// be evicted and then re-inserted as "new" — collapsing limbs 1 and 4 into one
/// and making the per-limb mutation table dishonest. The fail-closed bound is
/// identical: the table never exceeds MAX_TRACKED_PRINCIPALS live entries.
pub fn meter_admit(
    now_ns: u64,
    caller: Principal,
    state: &mut MeterState,
) -> Result<(), MeterRejection> {
    if let Some(entry) = state.entries.get_mut(&caller) {
        // Limb 1 — per-entry window reset.
        if now_ns.saturating_sub(entry.window_start_ns) >= METER_WINDOW_NS {
            entry.window_start_ns = now_ns;
            entry.count = 0;
        }
        // Limb 2 — over-budget rejection.
        if entry.count >= MAX_DERIVATIONS_PER_WINDOW {
            return Err(MeterRejection::OverBudget {
                retry_after_ns: METER_WINDOW_NS
                    .saturating_sub(now_ns.saturating_sub(entry.window_start_ns)),
            });
        }
        entry.count = entry.count.saturating_add(1);
        return Ok(());
    }

    // A principal not currently tracked. Limb 4 — reclaim expired entries, but
    // only under pressure (see ORDERING NOTE) AND at most once per
    // SWEEP_MIN_INTERVAL_NS (SSA-A2-D1).
    //
    // The cooldown is what makes repeated newcomer rejection O(1) AMORTIZED
    // instead of a full-table scan per ingress. Without it, a rotating stream of
    // fresh principals against a full LIVE table forces 100,000 examinations per
    // cheap rejected message forever — the sweep reclaims nothing when every
    // entry is live, so the work is pure loss on the path an attacker takes most.
    if state.entries.len() >= MAX_TRACKED_PRINCIPALS {
        let sweep_due = state
            .last_sweep_ns
            .is_none_or(|last| now_ns.saturating_sub(last) >= SWEEP_MIN_INTERVAL_NS);
        if sweep_due {
            state.sweeps += 1;
            state.entries_examined =
                state.entries_examined.saturating_add(state.entries.len() as u64);
            state
                .entries
                .retain(|_, e| now_ns.saturating_sub(e.window_start_ns) < METER_WINDOW_NS);
            state.last_sweep_ns = Some(now_ns);
        }
    }
    // Limb 5 — still full of LIVE entries: fail closed.
    if state.entries.len() >= MAX_TRACKED_PRINCIPALS {
        return Err(MeterRejection::TableSaturated);
    }
    // Limb 3 — keyed by caller.
    state.entries.insert(caller, MeterEntry { window_start_ns: now_ns, count: 1 });
    Ok(())
}

thread_local! {
    /// EPHEMERAL — heap, not stable memory. This is a decision, not a default;
    /// the three reasons are recorded in the package and summarised here:
    ///   1. No MemoryId is consumed, so docs/MEMORY_ID_REGISTRY.md needs no edit
    ///      and the BLOCKING registry lint stays green inside this lane's fence.
    ///   2. A stable per-principal counter is itself an attack surface: an
    ///      attacker with N fresh principals would write N PERMANENT,
    ///      non-reclaimable stable entries — trading a bounded cycle drain for
    ///      unbounded state growth. Ephemeral bounds the cost to heap and to one
    ///      window.
    ///   3. The upgrade reset is acceptable and is stated as such: an upgrade
    ///      clears the budget, but upgrades are controller-only and NOT
    ///      attacker-reachable, so the worst case is one extra window's
    ///      allowance immediately after a controller-initiated upgrade.
    static METER: RefCell<MeterState> = RefCell::new(MeterState::default());
}

// The A-2 `charge_caller` shell was REMOVED, not weakened: the meter charge is
// now the first limb of `admission::preflight`, which borrows the meter and the
// §H′ state together in one synchronous step. The meter's own decision
// (`meter_admit`), its no-refund structure and its message are untouched — what
// moved is only WHERE the shell lives, so that the meter-first ordering the CTO
// adjudication pins is expressible as one pure function and provable on the
// admission state's bytes.

fn with_key_manager<R>(f: impl FnOnce(&KeyManager<AccessRights>) -> R) -> R {
    KEY_MANAGER.with_borrow(|km| f(km.as_ref().expect("KeyManager not initialised")))
}

// ═════════════════════════════════════════════════════════════════════════════
// C-26 REMEDY — CYCLE FLOOR + GLOBAL DERIVE BUDGET (A1 fix brief V3)
// ═════════════════════════════════════════════════════════════════════════════

/// The LIVE derive price, from the KeyManager's CONFIGURED key id — never a
/// literal (`"key_1"` hardcoded here would be a RED, brief V3 §1): the name is
/// install-time config and the curve is the configured `Bls12_381_G2`.
/// `cost_vetkd_derive_key` is SYNCHRONOUS (an ic0 cost query, not a call).
/// An `Err` is surfaced, never defaulted — `fence::resolve_live_cost` maps it
/// to a fail-closed refusal.
fn price_from_key_manager_config() -> Result<u128, String> {
    with_key_manager(|km| {
        let config = km.config.get();
        let curve: u32 = config.key_id.curve.clone().into();
        ic_cdk::api::cost_vetkd_derive_key(&config.key_id.name, curve)
            .map_err(|e| format!("{e:?}"))
    })
}

/// THE DISPATCH FENCE — the impure five-line wrapper (brief V3 §2.2).
///
/// Takes NO balance and NO cost parameter, deliberately: both live values are
/// read HERE, at the wrapper's own call site, in the same synchronous message
/// step that immediately precedes the management await. A stale (pre-await)
/// value is therefore not expressible at the call site — reintroducing one
/// requires editing THIS body, which is visible in diff review. Structural
/// guarantee, not a behavioural proof (the same claim, in the same terms, the
/// crate makes for `MeterState`'s missing refund API); the behavioural proof
/// is the §6.2 causal harness in `fence::tests`.
///
/// CHECK all three limbs (§H′ revalidation, live floor, global budget), then
/// COMMIT all three (phase flip + dispatch timestamp), in one synchronous
/// block with no await inside it. A refusal commits nothing.
fn dispatch_fence(
    now_ns: u64,
    caller: Principal,
    reservation_id: u64,
    first_derive: bool,
) -> Result<(), VetkeysError> {
    let liquid = ic_cdk::api::canister_liquid_cycle_balance(); // read HERE, net of the reserve
    let live_cost = fence::resolve_live_cost(liquid, price_from_key_manager_config())?; // read HERE
    with_admission(caller, |st| {
        state::GLOBAL_DERIVE_BUDGET_WINDOW.with_borrow_mut(|cell| {
            let mut win = cell.get().clone();
            match fence::fence_decide(
                now_ns,
                reservation_id,
                liquid,
                live_cost,
                st,
                &win,
                state::PrincipalKey::new(caller),
            ) {
                fence::FenceDecision::Refuse(e) => Err(e),
                fence::FenceDecision::Commit => {
                    // COMMIT, all-or-nothing: the ONLY transition to
                    // `Dispatched`, plus exactly one fleet-capacity charge.
                    admission::revalidate_for_dispatch(st, reservation_id)
                        .map_err(|_| VetkeysError::AdmissionLapsed)?;
                    fence::prune_window(now_ns, &mut win);
                    fence::record_dispatch(
                        now_ns,
                        state::PrincipalKey::new(caller),
                        first_derive,
                        &mut win,
                    );
                    cell.set(win);
                    Ok(())
                }
            }
        })
    })
}

// ═════════════════════════════════════════════════════════════════════════════
// W-VETKEYS — TYPED ERROR CHANNEL (brief V1 §4, V2 §B/§D, V4 §H′)
// ═════════════════════════════════════════════════════════════════════════════
//
// The brief pins TYPED refusals, not strings: the wallet must be able to tell
// "you are out of quota, here is when to come back" from "your call lapsed,
// just retry" from "you are not eligible" WITHOUT parsing English.
//
// TWO RATE LIMITS, TWO VARIANTS — deliberately (CTO adjudication 7cd63a14…,
// item A). `RateLimited` is the A-2 meter (5/principal/HOUR, ephemeral,
// bounded table) which runs FIRST as a cheap pre-filter and carries its own
// operator-facing message verbatim. `DerivationQuotaExceeded` is the ruled §H′
// quota (5/principal/rolling 24 h, stable). `remaining` and `retry_after_ns`
// are reported from §H′ ONLY — the meter never populates them. Collapsing the
// two would make it impossible to tell which mechanism refused, which is
// exactly how an acceptance arm ends up proving the wrong one.
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum VetkeysError {
    /// Rejected before anything else, as today.
    AnonymousCaller,
    /// The A-2 (R6-1) per-hour meter refused. Carries `MeterRejection::message`
    /// verbatim so the operator-facing text and its saturation limb survive the
    /// move to a typed channel unchanged.
    RateLimited(String),
    /// The ruled §H′ rolling-24 h quota refused. `retry_after_ns` is EXACT: a
    /// call at `now + retry_after_ns` is admitted, at one ns less it is not.
    DerivationQuotaExceeded { retry_after_ns: u64 },
    /// V4 §H′.2(2)/(3): this call's reservation no longer exists in the phase
    /// it needs. Either it was TTL-pruned while parked (so it must die BEFORE
    /// the management dispatch), or its callback arrived after a stale charge
    /// (so its result is discarded). Retryable, and nothing was charged for it
    /// beyond what was already counted.
    AdmissionLapsed,
    /// The transport public key is not a valid 48-byte BLS12-381 G1 encoding.
    InvalidTransportKey(String),
    /// The KeyManager refused the read (owner-only access control).
    NotAuthorized(String),
    /// A caller-supplied field is malformed or out of bounds. Refused while it
    /// is still a mistake, rather than trapping on a Storable bound later.
    InvalidRequest(String),
    /// §B: no ticket / expired / already consumed (brief V2 §B names this
    /// variant and its `reason`).
    BootstrapNotAuthorized { reason: String },
    /// §C: the device-signed approval or revocation was refused — expired,
    /// replayed, wrong issuer, revoked issuer, or a signature that does not
    /// verify (including a high-S one).
    ApprovalRejected(String),
    /// §E: this principal's `register_device` window is spent.
    RegistrationRateExceeded { retry_after_ns: u64 },
    /// Opus-round RED-2: this principal's `revoke_device` window is spent.
    /// Its own variant, not `RegistrationRateExceeded` — a refusal must name
    /// the operation it refuses (distinct-typed-refusal requirement).
    RevocationRateExceeded { retry_after_ns: u64 },
    /// The per-principal ACTIVE device cap (brief V2 §E) is reached.
    DeviceLimitReached { active: u32 },
    /// No such device for this caller.
    UnknownDevice,
    /// The device exists but is revoked: neither the envelope nor a working
    /// read path is available to it.
    DeviceRevoked,
    /// §D: the authoritative balance query answered, and this principal is
    /// below the first-derive floor. A DEFINITE "no".
    PrincipalNotEligible(String),
    /// §D: eligibility is INDETERMINATE — the token canister is unconfigured,
    /// unreachable, or answered unintelligibly. Retryable, fail-closed, and
    /// deliberately NOT `PrincipalNotEligible`: "we could not ask" and "we
    /// asked and the answer was no" are different facts, and collapsing them
    /// would let an infrastructure outage read as a verdict about a user.
    EligibilityCheckUnavailable(String),
    /// C-26 remedy R1 (brief V3 §3): the canister's LIQUID cycle balance
    /// (already net of the freezing reserve) is below `live_cost + FLOOR`, so
    /// the derive is refused BEFORE any management-cycle spend. About the
    /// CANISTER, not the caller — deliberately not `RateLimited`, and it does
    /// not consume the caller's hourly allowance when raised by the advisory
    /// pre-check. No new disclosure: `cycle_balance` is already an open public
    /// query declared non-sensitive in vetkeys.did. `u128` fields encode as
    /// Candid `nat` — numbers, not text, so the monitor and wallet can parse.
    CycleFloorReached { liquid_cycles: u128, required_cycles: u128 },
    /// C-26 remedy R2 (brief V3 §4): the fleet-wide rolling-hour dispatch
    /// budget is spent. A FLEET refusal with its own variant — collapsing it
    /// into a per-principal one would repeat the mistake the two-rate-limit
    /// split above exists to prevent. `retry_after_ns` is EXACT (§4.2): a call
    /// at `now + retry_after_ns` finds a slot free, one ns earlier it does not.
    GlobalDerivationBudgetExceeded { retry_after_ns: u64 },
    /// V5 §6 — the caller's FIRST derive is refused because the required
    /// balance has not been held long enough yet (`pins::ELIGIBILITY_MIN_AGE_NS`).
    ///
    /// NOT A REUSE OF `PrincipalNotEligible`, deliberately, and the distinction
    /// is the point: `PrincipalNotEligible` is an authoritative "below the
    /// floor" with NO retry — nothing changes until the user is funded. This
    /// one is "not yet, come back at T", and the wallet's response to it is a
    /// wait, not a funding prompt. Collapsing them would make the wallet tell a
    /// funded user to go get tokens.
    ///
    /// Shape precedent: `RegistrationRateExceeded` / `RevocationRateExceeded`.
    /// `retry_after_ns` is EXACT: a call at `now + retry_after_ns` is admitted,
    /// one ns earlier is not.
    ///
    /// ESTABLISHED PRINCIPALS CAN NEVER SEE THIS. The age test sits inside the
    /// `!established` branch, so recovery is untouched by it.
    EligibilityAgeNotMet { retry_after_ns: u64 },
    /// LAUNCH-HARDEN-04 O-3: this principal's derive dispatches in the rolling
    /// hour reached `PER_PRINCIPAL_HOURLY_DERIVE_CAP`. `retry_after_ns` is EXACT
    /// (same contract as the others). A fence refusal: the §H′ slot is released
    /// and no management cycles were spent.
    PrincipalHourlyDerivationCapExceeded { retry_after_ns: u64 },
}

/// A successful derive: the encrypted vetKey plus the caller's REMAINING §H′
/// allowance in the rolling window. The wallet warns at
/// `remaining <= pins::QUOTA_WARN_REMAINING` (brief V1 §4).
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EncryptedVetKeyReply {
    pub encrypted_key: Vec<u8>,
    pub remaining: u8,
}

/// Read-modify-write one principal's `AdmissionState`, atomically inside the
/// CURRENT message. Every §H′ step goes through here, so no step can
/// accidentally span an await: the borrow is taken and dropped synchronously.
///
/// An ABSENT row reads as `AdmissionState::default()` — an empty window, which
/// is correct for a principal that has never derived, and is the ONLY lenient
/// default in this lane. It is safe precisely because the stable decoder
/// refuses to invent it: a row that EXISTS but cannot be decoded traps rather
/// than reading as empty (see `state.rs`).
fn with_admission<R>(caller: Principal, f: impl FnOnce(&mut AdmissionState) -> R) -> R {
    ADMISSION.with_borrow_mut(|map| {
        let key = PrincipalKey::new(caller);
        let mut st = map.get(&key).unwrap_or_default();
        let out = f(&mut st);
        map.insert(key, st);
        out
    })
}

/// The canister-scoped vetKD public key (canister + context derived, BLS12-381
/// G2). The wallet uses it to (a) verify encrypted vetKeys after transport
/// decryption and (b) IBE-encrypt note payloads OFFLINE to any recipient
/// principal — no canister call at encryption time. Update method because the
/// underlying `vetkd_public_key` is a management-canister call: ZERO cycles
/// are ATTACHED to it, but it is still a real, awaited inter-canister round
/// trip this canister pays for out of its own execution budget on every cache
/// miss. That is what R-5 (L04-02) amortises: the key is per-canister, not
/// per-caller and not per-session (P6), so it is read once and served from
/// MemoryId 18 thereafter.
#[update]
async fn get_vetkey_verification_key() -> Vec<u8> {
    // R6-1 (lane A-2): reject the anonymous principal. This endpoint had NO
    // caller check at all.
    //
    // Rejection is a TRAP, deliberately, not a change of return type to
    // `Result`: the signature is `() -> (blob)` in vetkeys.did, and widening it
    // would move the DID and the blocking did-vs-exports gate for no
    // behavioural gain — the caller learns "refused" either way.
    //
    // VERIFIED against the wallet before writing this (brief §4.5): the only
    // caller is `fetchUserVetKey` (wallet/src/crypto/vetkeys.ts:126-142), which
    // is reached from shieldFlow/spendFlow with an authenticated
    // `deps.principal`, over the session agent built in
    // wallet/src/session/session.ts:106. There is NO pre-authentication caller.
    if ic_cdk::api::msg_caller() == Principal::anonymous() {
        ic_cdk::trap(
            "anonymous callers cannot request the vetKey verification key — \
             authenticate with Internet Identity",
        );
    }
    // CACHE READ. An empty value is "no cache", not "the empty key" — the cell
    // is only ever written with a real management-canister reply.
    let cached = state::VETKEY_VERIFICATION_KEY_CACHE.with_borrow(|c| c.get().0.clone());
    if !cached.is_empty() {
        return cached;
    }
    let fut = with_key_manager(|km| km.get_vetkey_verification_key());
    let key: Vec<u8> = fut.await.into();
    state::set_verification_key_cache(key.clone());
    STATS.with_borrow_mut(|c| {
        c.verification_key_management_calls_total =
            c.verification_key_management_calls_total.saturating_add(1)
    });
    key
}

/// CONTROLLER-ONLY. The operational escape hatch for a future re-keying: forces
/// a real management-canister call and overwrites MemoryId 18. Never called by
/// the wallet, and not expected to be called in ordinary operation — the key
/// does not rotate absent a controller-driven change of the configured key id,
/// and there is no `set_config` / `rotate_key` endpoint in this crate.
///
/// A non-controller TRAPS rather than getting a typed refusal, for the same
/// reason `get_vetkey_verification_key`'s anonymous check traps: the signature
/// is `() -> (blob)` and widening it to a `Result` would move the DID for no
/// behavioural gain.
#[update]
async fn refresh_vetkey_verification_key_cache() -> Vec<u8> {
    if !ic_cdk::api::is_controller(&ic_cdk::api::msg_caller()) {
        ic_cdk::trap("refresh_vetkey_verification_key_cache: caller is not a controller");
    }
    let fut = with_key_manager(|km| km.get_vetkey_verification_key());
    let key: Vec<u8> = fut.await.into();
    state::set_verification_key_cache(key.clone());
    STATS.with_borrow_mut(|c| {
        c.verification_key_management_calls_total =
            c.verification_key_management_calls_total.saturating_add(1)
    });
    key
}

/// Derive THIS CALLER's encrypted vetKey, secured to the supplied transport
/// public key (48-byte BLS12-381 G1; generate a FRESH transport key per
/// session — never reuse). The derivation input is the caller's own principal:
/// a caller cannot request another user's key by construction, and the
/// KeyManager access check enforces owner-only read on top.
#[update]
async fn get_encrypted_vetkey(
    transport_public_key: Vec<u8>,
) -> Result<EncryptedVetKeyReply, VetkeysError> {
    let caller = ic_cdk::api::msg_caller();
    if caller == Principal::anonymous() {
        return Err(VetkeysError::AnonymousCaller);
    }

    // ── LIMB 2 (C-26 §2.5): ADVISORY floor pre-check ────────────────────────
    //
    // Explicitly ADVISORY (brief V3 §2.3): a cheap early refusal, NOT the
    // security check — that is the dispatch fence below, which re-reads both
    // live values at its own call site. Removing this block must change no
    // security property. It runs BEFORE the meter, deliberately: a floor
    // refusal is about the CANISTER, not the caller, and must not consume a
    // caller's hourly allowance (CTO adjudication 7cd63a14 §A, same rule).
    {
        let liquid = ic_cdk::api::canister_liquid_cycle_balance();
        let live_cost = fence::resolve_live_cost(liquid, price_from_key_manager_config())?;
        if !fence::cycle_floor_admits(liquid, live_cost) {
            return Err(VetkeysError::CycleFloorReached {
                liquid_cycles: liquid,
                required_cycles: live_cost.saturating_add(pins::DERIVE_CYCLE_FLOOR_CYCLES),
            });
        }
    }

    // ── R-5 (L04-01): TRANSPORT-KEY VALIDITY — before METER/admission ───────
    //
    // Moved here from the old STEP 3, which sat AFTER `admission::preflight`
    // and released the reservation it had just taken. Two stable writes for a
    // call that can never become a derive.
    //
    // The check is a pure function of the caller's own Candid argument — no
    // meter, admission or preflight value feeds it — so nothing blocks the
    // reorder. It sits strictly BEFORE `METER`/`with_admission` are entered,
    // not merely before `admit()` inside `preflight`: `with_admission`'s
    // `map.insert(key, st)` commits UNCONDITIONALLY on entry, whatever its
    // closure returns, so the only way a malformed key writes NOTHING is for
    // `with_admission` never to be called for it. `meter_admit` is therefore
    // not reached either: a malformed key no longer spends the caller's hourly
    // allowance, because there is no longer anything for the meter to protect.
    //
    // ORDER, stated precisely: the LIMB 2 floor pre-check above still runs
    // FIRST, in this order as in the old one. Below the floor a malformed key
    // still returns `CycleFloorReached`, not `InvalidTransportKey`. C-3b's
    // measured refusal is cheap because it stops before
    // `METER`/`with_admission`/`preflight`, not because it precedes the floor.
    //
    // Meter-before-§H′ (CTO adjudication 7cd63a14… item A) is UNTOUCHED: this
    // check sits before BOTH limbs, and does not reorder either against the
    // other.
    if !ic_vetkeys::is_valid_transport_public_key_encoding(&transport_public_key) {
        return Err(VetkeysError::InvalidTransportKey(
            "invalid transport public key encoding (expected a 48-byte BLS12-381 G1 point)"
                .to_string(),
        ));
    }

    // ── STEPS 1+2: meter pre-filter, THEN §H′ admission ─────────────────────
    //
    // Order pinned by CTO adjudication 7cd63a14… item A. The A-2 meter keeps
    // its charge-before-await ordering and its no-refund structure unchanged;
    // what the adjudication adds is that a meter refusal must land BEFORE any
    // §H′ reservation is written, so it can neither consume nor leak §H′
    // capacity.
    // Both limbs run inside ONE call to `admission::preflight`, which is where
    // the ordering is expressed and proved: the meter's refusal returns before
    // `admit` is reachable, so it can neither write nor leak a §H′ reservation.
    // Both states are borrowed synchronously, pre-await, and released here.
    let now_ns = ic_cdk::api::time();
    let admitted = METER
        .with_borrow_mut(|meter| {
            with_admission(caller, |st| admission::preflight(now_ns, caller, meter, st))
        })
        .map_err(|e| match e {
            admission::PreflightRejection::Meter(rejection) => {
                VetkeysError::RateLimited(rejection.message())
            }
            admission::PreflightRejection::Quota { retry_after_ns } => {
                VetkeysError::DerivationQuotaExceeded { retry_after_ns }
            }
        })?;

    // ── STEP 3b: §D first-derive eligibility ────────────────────────────────
    //
    // ONLY for a principal with no `established_principal` bit. An established
    // principal is recovering, not bootstrapping: ownership was proved by the
    // first ceremony and re-proving it would make recovery depend on the user
    // still holding tokens, which is exactly the case recovery exists for.
    //
    // THIS AWAIT IS THE ONE THE §H′ PHASE TAG EXISTS FOR. A call parked here
    // can outlive its own reservation's TTL; when it resumes, the dispatch
    // fence below refuses it. Failures here RELEASE — no cycles were spent.
    let established = ESTABLISHED.with_borrow(|map| map.contains_key(&PrincipalKey::new(caller)));
    if !established {
        if let Err(rejection) = check_first_derive_eligibility(caller).await {
            let _ = with_admission(caller, |st| admission::release(st, admitted.reservation_id));
            return Err(rejection);
        }
    }

    let key_name: Blob<32> = Blob::try_from(KEY_NAME).expect("KEY_NAME fits in Blob<32>");
    let fut = with_key_manager(|km| {
        km.get_encrypted_vetkey(
            caller,
            (caller, key_name),
            TransportKey::from(transport_public_key),
        )
    });
    let fut = match fut {
        Ok(f) => f,
        Err(reason) => {
            let _ = with_admission(caller, |st| admission::release(st, admitted.reservation_id));
            return Err(VetkeysError::NotAuthorized(reason));
        }
    };

    // ── STEP 4: the dispatch fence (C-26 remedy, brief V3 §2) ───────────────
    //
    // §H′.2(2) + §2.2. Building the future above does NOT dispatch; awaiting
    // it does. The fence runs HERE, synchronously, in the same message step
    // that immediately precedes the await, and decides all three limbs at once
    // — the reservation still `PreDispatch`, the LIVE liquid balance against
    // the floor (re-read inside `dispatch_fence`, never carried across the §D
    // await above), and the fleet-wide budget — then commits the phase flip
    // and the capacity charge together, or nothing at all.
    //
    // A fence refusal is PRE-dispatch: no management cycles were spent, so the
    // §H′ slot is returned exactly as the other pre-dispatch failures return
    // theirs (for a lapsed reservation the release is a structural no-op).
    // The METER charge stands, per the uniform every-call-costs-one rule.
    // `!established` is the first-derive tag the V2 window records (§3). It is
    // read from the SAME `established` value the §D branch above decided on, so
    // the tag and the eligibility path can never disagree about which this was.
    if let Err(e) =
        dispatch_fence(ic_cdk::api::time(), caller, admitted.reservation_id, !established)
    {
        // ONLY the fleet-budget limb moves this counter (SSA carried item 2).
        // The floor and §H′ revalidation limbs refuse for reasons that are not
        // "the budget is spent", and folding them in would make the
        // refusal-spike rule fire on conditions it does not describe.
        if matches!(e, VetkeysError::GlobalDerivationBudgetExceeded { .. }) {
            STATS.with_borrow_mut(|c| {
                c.refusals_budget_total = c.refusals_budget_total.saturating_add(1)
            });
        }
        let _ = with_admission(caller, |st| admission::release(st, admitted.reservation_id));
        return Err(e);
    }

    // After this await, `finalize` may still discard a late result — the
    // global-budget charge correctly STANDS in that case, because the cycles
    // were genuinely spent (§2.4). No refund path exists.
    let encrypted_key: Vec<u8> = fut.await.into();

    // ── STEP 5: finalize ────────────────────────────────────────────────────
    //
    // §H′.2(3). If the id is ABSENT it was stale-charged while this call was
    // in flight: the charge already counted this derive, so the result is
    // DISCARDED — no key returned, and (once they exist) no ticket minted and
    // no established bit set. A late callback can never produce an uncounted
    // key.
    let finalized = with_admission(caller, |st| {
        admission::finalize(ic_cdk::api::time(), st, admitted.reservation_id)
    });
    if !finalized {
        return Err(VetkeysError::AdmissionLapsed);
    }

    // ── STEP 6: mint the §B bootstrap ticket ────────────────────────────────
    //
    // Strictly AFTER a successful, finalized derive — which is itself strictly
    // after admission (and, once §D lands, after eligibility). This ordering is
    // the whole of RED-2: it is what makes "this registration rode a real
    // derive" a state check the canister can perform, instead of a claim about
    // the client's session that it cannot.
    //
    // Deliberately NOT reached on the discard path above: a late callback whose
    // reservation was stale-charged returns before here, so it mints nothing.
    // One live ticket per principal — this overwrites any prior row, so a
    // re-derive replaces rather than accumulates authorization.
    //
    // L04-07 MINT-TIME GATE. A principal that has revoked its way to ZERO
    // active devices gets NO ticket unless it holds a re-bootstrap policy row.
    // Skipping the mint rather than failing the derive is deliberate: the
    // vetKey itself is the user's own key material and they are entitled to
    // it — what is withheld is the CAPABILITY to enrol a device with no
    // existing device's signature. The refusal therefore surfaces where the
    // capability is used, as `BootstrapNotAuthorized`, not as a failed derive.
    if bootstrap_path_open(PrincipalKey::new(caller), ic_cdk::api::time()) {
        BOOTSTRAP_TICKETS.with_borrow_mut(|map| {
            map.insert(PrincipalKey::new(caller), tickets::mint(ic_cdk::api::time()));
        });
    }

    // ── STEP 7: the §D established bit ──────────────────────────────────────
    //
    // Written ONLY here: after an admitted, eligible, successful, FINALIZED
    // ceremony. This is its single writer, which is what makes "never writable
    // by any other path" structural rather than a claim. It authorizes exactly
    // one thing — skipping the balance query on a later recovery — and can
    // never be evidence for a first derive, because a first derive is by
    // definition the call that creates it.
    ESTABLISHED.with_borrow_mut(|map| {
        map.insert(PrincipalKey::new(caller), ic_cdk::api::time());
    });

    // §6.5 — the sighting row has done its job: delete it from BOTH structures.
    // HERE, beside the established bit and after the same finalize, so the two
    // can never disagree about whether this principal is still bootstrapping.
    // This is what makes the rows transient by construction rather than a table
    // that only ever grows toward its cap.
    sightings::clear_on_success(PrincipalKey::new(caller));

    // `remaining` is reported from §H′ only — never from the meter.
    Ok(EncryptedVetKeyReply { encrypted_key, remaining: admitted.remaining })
}

// ═════════════════════════════════════════════════════════════════════════════
// W-VETKEYS LAYER 1 — DEVICE REGISTRY (brief V1 §2, V2 §B/§C/§E)
// ═════════════════════════════════════════════════════════════════════════════
//
// THE POINT OF LAYER 1: ordinary logins, sessions and device additions perform
// ZERO vetKD derives. A registered device fetches its own wrapped envelope,
// unwraps it with a non-extractable WebCrypto key, and proceeds. The canister
// holds the envelope and never the plaintext; the device holds the unwrap key
// and never the envelope's contents in storage. Split knowledge: a passive
// canister compromise reads nothing, and a stolen offline device reads nothing.
//
// NO AWAITS ANYWHERE IN THIS SECTION. Every endpoint below is one atomic
// message, which is why the §H′ reservation machinery has no analogue here
// (brief V3 §H.4, stated to close the class rather than the instance).

/// The ICRC-1 account shape, declared locally — this is the ONE outbound
/// coupling the brief authorizes, and it is a two-field record; taking a
/// dependency on a ledger crate to obtain it would be a larger change than the
/// coupling itself.
#[derive(CandidType, Deserialize, Debug, Clone)]
struct Icrc1Account {
    owner: Principal,
    subaccount: Option<Vec<u8>>,
}

/// §D — first-derive eligibility: EXACTLY ONE outbound read-only balance query.
///
/// THE FENCE (brief V1 §5 as GREENed, V2 §D): this is the only call this
/// canister makes to anything but the management canister. It is read-only, it
/// is made only when the principal has no `established_principal` bit, and no
/// second coupling may be added without a new ruling.
///
/// FAIL-CLOSED, WITH THE DISTINCTION INTACT. Three outcomes:
///   * unconfigured / call failed / undecodable reply → `EligibilityCheckUnavailable`
///     (indeterminate, retryable — we could not ask);
///   * balance below the floor → `PrincipalNotEligible` (we asked; the answer is no);
///   * at or above the floor → eligible.
/// Only the middle one is a statement about the user.
async fn check_first_derive_eligibility(caller: Principal) -> Result<(), VetkeysError> {
    let Some(token) = state::token_canister() else {
        return Err(VetkeysError::EligibilityCheckUnavailable(
            "the token canister is not configured on this deployment, so first-derive \
             eligibility cannot be established — this is retryable infrastructure state, not \
             a decision about this principal"
                .to_string(),
        ));
    };
    let account = Icrc1Account { owner: caller, subaccount: None };
    let response = ic_cdk::call::Call::unbounded_wait(token, "icrc1_balance_of")
        .with_arg(&account)
        .await
        .map_err(|e| {
            VetkeysError::EligibilityCheckUnavailable(format!(
                "the eligibility balance query failed ({e:?}) — retryable"
            ))
        })?;
    let balance: candid::Nat = response.candid().map_err(|e| {
        VetkeysError::EligibilityCheckUnavailable(format!(
            "the eligibility balance query returned an undecodable reply ({e:?}) — retryable"
        ))
    })?;
    // `Nat` is arbitrary-precision; compare in that domain rather than
    // truncating it into a u128 first.
    if balance < candid::Nat::from(pins::ELIGIBILITY_MIN_BALANCE_E8S) {
        // §6.2 step 1: an authoritative BELOW-FLOOR answer writes NOTHING — no
        // sighting, no index row, and no prune (SSA GREEN-2). A principal we
        // have never seen at or above the floor has no age to accumulate, and
        // recording one would start a clock on evidence that does not exist.
        // The `EligibilityCheckUnavailable` returns above write nothing either,
        // for the stronger reason: we could not ask.
        return Err(VetkeysError::PrincipalNotEligible(format!(
            "a first key derivation requires a token balance of at least {} e8s",
            pins::ELIGIBILITY_MIN_BALANCE_E8S
        )));
    }

    // ── §6 — HELD-BALANCE-AGE ADMISSION ─────────────────────────────────────
    //
    // The balance is proven AT OR ABOVE the floor at this instant. That is a
    // point-in-time fact: the ledger has no history query, so how long it has
    // been held is not something we can ask — only something this canister
    // accumulates. Everything below runs in ONE non-awaiting sequence, which is
    // what makes each two-structure mutation atomic.
    //
    // WHAT THIS GATE ACTUALLY BUYS (V5 §6.4, SSA GREEN-1, D-1) — stated here
    // because the code is where the claim gets over-read: under two-point
    // sampling with a hard-coded ZERO ledger fee, ONE 0.1 STSH float satisfies
    // arbitrarily many principals. This delivers PRE-FUNDING VISIBILITY,
    // COLD-START BURST DAMPING and RE-TOOLING LATENCY. It is NOT a capital
    // requirement and it does NOT price the attack; `GLOBAL_DERIVE_BUDGET`
    // remains the wall.
    let now_ns = ic_cdk::api::time();
    match sightings::decide(now_ns, PrincipalKey::new(caller)) {
        sightings::SightingOutcome::Admitted => Ok(()),
        // A new age-in period BEGAN. Both limbs count (SSA adjudication 5):
        // an expired row's renewal starts a clock exactly as a first sighting
        // does, and counting only the first would under-report a wave made of
        // returning principals. Never on the valid-row branches, which begin
        // nothing.
        sightings::SightingOutcome::Inserted | sightings::SightingOutcome::Renewed => {
            STATS.with_borrow_mut(|c| {
                c.sightings_recorded_total = c.sightings_recorded_total.saturating_add(1);
                c.age_refusals_total = c.age_refusals_total.saturating_add(1);
            });
            Err(VetkeysError::EligibilityAgeNotMet {
                retry_after_ns: pins::ELIGIBILITY_MIN_AGE_NS,
            })
        }
        sightings::SightingOutcome::NotYet { retry_after_ns }
        | sightings::SightingOutcome::Anomalous { retry_after_ns } => {
            STATS.with_borrow_mut(|c| {
                c.age_refusals_total = c.age_refusals_total.saturating_add(1)
            });
            Err(VetkeysError::EligibilityAgeNotMet { retry_after_ns })
        }
        // LAUNCH-HARDEN-04 O-2: there is no `CapReached` arm any more — a full
        // sighting table EVICTS its oldest unconverted row and the caller is
        // `Inserted` (above). The wire result for a new principal is unchanged.
    }
}

/// A device's public halves, as returned to its owner. Private key material
/// never exists canister-side, so there is nothing to redact here.
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeviceView {
    pub device_id: String,
    pub enc_pubkey_spki: Vec<u8>,
    pub sign_pubkey_spki: Vec<u8>,
    pub active: bool,
    pub added_at_ns: u64,
    pub revoked_at_ns: Option<u64>,
    /// `None` = registered by consuming a §B bootstrap ticket; `Some(id)` = the
    /// existing device whose ApprovalV1 signature authorized it.
    pub approved_by_device: Option<String>,
}

/// A device-signed authorization (brief V2 §C). The transcript itself is NOT
/// transmitted: the canister REBUILDS it from the fields it is about to act on
/// and verifies the signature over that. A caller therefore cannot have a
/// signature checked against one set of bytes and applied to another.
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignedApproval {
    pub issuer_device_id: String,
    /// 16 bytes, single-use, scoped to (principal, issuer_device_id).
    pub nonce: Vec<u8>,
    pub expiry_ns: u64,
    /// P-256 ECDSA, fixed 64-byte `r || s`, LOW-S REQUIRED (high-S is refused,
    /// never normalized — see `verify.rs`).
    pub signature: Vec<u8>,
}

/// How a registration is authorized (brief V1 §2).
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DeviceApproval {
    /// First device for this principal: consumes a §B bootstrap ticket, which
    /// only a completed Layer-2 ceremony can have minted.
    Bootstrap,
    /// Every later device: signed by an existing ACTIVE device.
    Device(SignedApproval),
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn device_id_key(device_id: &str) -> Result<DeviceIdKey, VetkeysError> {
    DeviceIdKey::new(device_id).ok_or_else(|| {
        VetkeysError::InvalidRequest(format!(
            "device_id must be 1..={} UTF-8 bytes",
            pins::MAX_DEVICE_ID_BYTES
        ))
    })
}

/// Every ACTIVE device of one owner, and the total count. One range scan over
/// the owner's contiguous block.
fn active_devices(owner: PrincipalKey) -> Vec<(DeviceIdKey, DeviceRecord)> {
    let (lo, hi) = DeviceKey::owner_range(owner);
    DEVICES.with_borrow(|map| {
        map.range(lo..=hi)
            .map(|entry| (entry.key().device_id, entry.value()))
            .filter(|(_, rec)| rec.status == DeviceStatus::Active)
            .collect()
    })
}

/// L04-07 — has this principal EVER enrolled a device?
///
/// Revocation retains the `DeviceRecord` and only flips its status, which is
/// exactly what makes this question answerable: a row in the owner's range is
/// permanent evidence of a past enrolment. `active_devices` cannot answer it —
/// it filters the retained rows out, so "never enrolled" and "revoked to zero"
/// both read as an empty vector there, and those two are the cases the
/// bootstrap gate has to tell apart.
fn has_ever_enrolled(owner: PrincipalKey) -> bool {
    let (lo, hi) = DeviceKey::owner_range(owner);
    DEVICES.with_borrow(|map| map.range(lo..=hi).next().is_some())
}

/// L04-07 — may this principal take the BOOTSTRAP path right now?
///
/// Three cases, and only the middle one is new:
///   · never enrolled            → yes. A first device has nothing to sign for
///                                 it; this is what the ticket is for.
///   · has ≥1 ACTIVE device      → yes, unchanged. Nothing has been revoked to
///                                 zero, so there is no reversal to authorize.
///   · enrolled, zero ACTIVE     → ONLY with `allow_re_bootstrap`. Otherwise
///                                 whoever holds the II — including whoever
///                                 stole it, the usual reason the devices were
///                                 revoked — could undo the revocation by
///                                 simply enrolling again.
///
/// An ABSENT policy row is "not authorized": that is the state every
/// pre-this-lane enrolment is in, the state after the row has been SPENT by
/// the registration it authorised, and the fail-closed direction.
///
/// The active-device count comes from `active_devices`, the SAME predicate the
/// device cap consults, so the two cannot drift into disagreeing about what
/// "active" means.
///
/// LAUNCH-HARDEN-04 O-8: in the ≥1-ACTIVE-device branch ONLY, a set
/// "require device approval" flag (MemoryId 19) closes the bootstrap path — a
/// new device must then be approved by an existing one. The zero-active
/// branches are UNCHANGED (the flag is ignored there).
fn bootstrap_path_open(owner: PrincipalKey, now_ns: u64) -> bool {
    if !active_devices(owner).is_empty() {
        return !device_approval_required(owner, now_ns);
    }
    if !has_ever_enrolled(owner) {
        return true;
    }
    RE_BOOTSTRAP_POLICY
        .with_borrow(|map| map.get(&owner))
        .map(|p| p.allow_re_bootstrap)
        .unwrap_or(false)
}

/// LAUNCH-HARDEN-04 O-8 — is the "require device approval" flag in force for
/// `owner` at `now`? Absent row → false. A set flag with a MATURED II-only
/// clear (`now >= pending_clear_at_ns`, inclusive) → false.
fn device_approval_required(owner: PrincipalKey, now_ns: u64) -> bool {
    DEVICE_APPROVAL_POLICY
        .with_borrow(|m| m.get(&owner))
        .is_some_and(|p| {
            p.require_device_approval && !p.pending_clear_at_ns.is_some_and(|t| now_ns >= t)
        })
}

/// LAUNCH-HARDEN-04 O-8 — the consume-time refusal reason for the flag.
const DEVICE_APPROVAL_REQUIRED: &str =
    "this principal requires an existing device to approve new devices — approve from an enrolled \
     device, or request a policy clear (takes effect after 24 hours)";

/// The refusal reason both L04-07 gates carry, written once so the mint-time
/// and consume-time halves cannot describe the same rule differently.
const RE_BOOTSTRAP_NOT_AUTHORIZED: &str =
    "every device of this principal has been revoked — a further bootstrap \
     registration needs an authorize_re_bootstrap approval signed by a device \
     that was active before the revocation";

/// Consume a single-use approval nonce, or refuse.
///
/// ORDERED BEFORE ANY STATE WRITE (brief V2 §C). The nonce is what makes a
/// captured, still-unexpired transcript unusable a second time, so it must be
/// burned before the operation it authorizes can leave any trace.
fn consume_nonce(
    owner: PrincipalKey,
    issuer: DeviceIdKey,
    nonce: [u8; 16],
    expiry_ns: u64,
    now_ns: u64,
) -> Result<(), VetkeysError> {
    // RED-1: reclaim a BOUNDED number of expired rows at each admission. Runs
    // before the replay check so the set cannot grow monotonically even on a
    // path where every consume is a replay refusal.
    prune_expired_nonces(now_ns);

    let key = NonceKey { owner, issuer_device_id: issuer, nonce };
    if CONSUMED_NONCES.with_borrow(|map| map.contains_key(&key)) {
        // The ONLY `Err` this function returns, and it happens BEFORE either
        // map has been touched by this consume — a refused consume mutates
        // neither structure (RED-1 both-or-neither: no Err after one side has
        // moved).
        return Err(VetkeysError::ApprovalRejected(
            "this approval nonce has already been used — an approval authorizes exactly \
             one operation"
                .to_string(),
        ));
    }
    // Both-or-neither, structurally: this function is called only from
    // non-awaiting messages, so the two inserts commit together — and any
    // invariant failure between them TRAPS, which rolls the whole message
    // back and leaves NEITHER row.
    //
    // The VALUE of the primary row is the transcript's expiry, which is what
    // makes the set prunable rather than unbounded: past expiry a nonce can
    // never be replayed anyway, because the expiry check refuses first. The
    // INDEX row carries the same expiry as its ordered prefix (BE-encoded in
    // the key), which is what makes the prune bounded.
    CONSUMED_NONCES.with_borrow_mut(|map| map.insert(key, expiry_ns));
    NONCE_EXPIRY_INDEX.with_borrow_mut(|ix| {
        let prior = ix.insert(NonceExpiryKey { expiry_ns, nonce_key: key }, ());
        // Collision check: the primary row did not exist, so this index row
        // cannot have either — if it does, the bijection was already broken
        // and continuing would compound it.
        if prior.is_some() {
            ic_cdk::trap(
                "NONCE_EXPIRY_INDEX invariant violated: index row existed without its \
                 primary row",
            );
        }
    });
    Ok(())
}

/// Remove AT MOST `pins::NONCE_PRUNE_MAX` (`K = 16`) expired consumed-nonce
/// rows, from BOTH structures. The index orders by big-endian `expiry_ns`
/// first, so the expired candidates are exactly the low prefix — cost is
/// `O(K log N)` per call, and a backlog larger than `K` drains over repeated
/// calls, never in one. The predicate is `expiry_ns < now`: a row AT `now` is
/// retained until a later call — conservative and bounded, not replay
/// authority (the half-open expiry check already refuses the transcript at
/// `now == expiry`).
fn prune_expired_nonces(now_ns: u64) {
    let victims: Vec<state::NonceExpiryKey> = NONCE_EXPIRY_INDEX.with_borrow(|ix| {
        ix.iter()
            .map(|entry| *entry.key())
            .take_while(|k| k.expiry_ns < now_ns)
            .take(pins::NONCE_PRUNE_MAX)
            .collect()
    });
    for k in victims {
        let index_row = NONCE_EXPIRY_INDEX.with_borrow_mut(|ix| ix.remove(&k));
        let primary_expiry = CONSUMED_NONCES.with_borrow_mut(|map| map.remove(&k.nonce_key));
        // Both-or-neither on the way OUT as well: a row present in one
        // structure but not the other is a broken bijection, and a trap rolls
        // this message back rather than committing a half-removal.
        if index_row.is_none() || primary_expiry != Some(k.expiry_ns) {
            ic_cdk::trap(
                "CONSUMED_NONCES/NONCE_EXPIRY_INDEX bijection violated during prune",
            );
        }
    }
}

/// The shared §C preamble for both signed operations: the issuer must be a
/// live device of THIS caller, the transcript must not have expired, and the
/// nonce must be fresh. Returns the issuing device's record so the caller can
/// verify against its signing key.
fn check_issuer(
    owner: PrincipalKey,
    signed: &SignedApproval,
    now_ns: u64,
) -> Result<(DeviceIdKey, DeviceRecord, [u8; 16]), VetkeysError> {
    let issuer_key = device_id_key(&signed.issuer_device_id)?;
    let nonce: [u8; 16] = signed.nonce.as_slice().try_into().map_err(|_| {
        VetkeysError::InvalidRequest("an approval nonce is exactly 16 bytes".to_string())
    })?;
    if signed.signature.len() != verify::SIGNATURE_BYTES {
        return Err(VetkeysError::ApprovalRejected(
            verify::SignatureRejection::MalformedSignature.reason().to_string(),
        ));
    }
    // Expiry is half-open, like the ticket and the §H′ window: valid while
    // `now < expiry`, dead AT `expiry`. The predicate lives in `registry` so
    // the nanosecond boundary is unit-provable (a PocketIC client cannot pin
    // the canister's clock precisely enough to test it from outside).
    if !registry::approval_is_live(now_ns, signed.expiry_ns) {
        return Err(VetkeysError::ApprovalRejected(
            "the approval has expired".to_string(),
        ));
    }
    let record = DEVICES
        .with_borrow(|map| map.get(&DeviceKey { owner, device_id: issuer_key }))
        .ok_or_else(|| {
            VetkeysError::ApprovalRejected(
                "the approving device is not registered to this principal".to_string(),
            )
        })?;
    // A revoked device cannot approve anything. This is the single most
    // load-bearing line in the revocation story: without it, revocation would
    // only stop reads and a revoked device could re-admit itself.
    if record.status != DeviceStatus::Active {
        return Err(VetkeysError::ApprovalRejected(
            "the approving device has been revoked".to_string(),
        ));
    }
    Ok((issuer_key, record, nonce))
}

/// Register a device for the CALLER.
///
/// One atomic message: rate limit, validation, authorization, nonce/ticket
/// consumption and the device+envelope write all land together or not at all.
/// That atomicity is what closes the substitution window SSA named in RED-2 —
/// there is no interval in which an authorization exists unbound to the exact
/// fields being written.
#[update]
fn register_device(
    device_id: String,
    enc_pubkey_spki: Vec<u8>,
    sign_pubkey_spki: Vec<u8>,
    wrapped_secret: Vec<u8>,
    approval: DeviceApproval,
) -> Result<(), VetkeysError> {
    let caller = ic_cdk::api::msg_caller();
    if caller == Principal::anonymous() {
        return Err(VetkeysError::AnonymousCaller);
    }
    let owner = PrincipalKey::new(caller);
    let now_ns = ic_cdk::api::time();

    // §E rate limit FIRST, before validation — the same uniform rule the A-2
    // meter uses: every call past the anonymous check costs one unit whatever
    // its outcome, so the failure path cannot be looped for free against a
    // caller-writable stable surface.
    REGISTRATIONS.with_borrow_mut(|map| {
        let mut window = map.get(&owner).unwrap_or_default();
        let out = registry::charge_registration(now_ns, &mut window);
        map.insert(owner, window);
        out
    })
    .map_err(|retry_after_ns| VetkeysError::RegistrationRateExceeded { retry_after_ns })?;

    let new_device = device_id_key(&device_id)?;
    if enc_pubkey_spki.is_empty() || sign_pubkey_spki.is_empty() {
        return Err(VetkeysError::InvalidRequest(
            "both device public keys are required (SPKI DER)".to_string(),
        ));
    }
    if wrapped_secret.is_empty() {
        return Err(VetkeysError::InvalidRequest(
            "the wrapped master-secret envelope is required".to_string(),
        ));
    }
    // Bounds are the Storable bounds: exceeding one would TRAP on insert, so it
    // is refused as a typed error while it is still a caller mistake.
    if !state::wrapped_secret_fits(wrapped_secret.len()) {
        return Err(VetkeysError::InvalidRequest(
            "the wrapped envelope exceeds the maximum stored size".to_string(),
        ));
    }
    if !state::device_record_fits(enc_pubkey_spki.len(), sign_pubkey_spki.len()) {
        return Err(VetkeysError::InvalidRequest(
            "the device public keys exceed the maximum stored size".to_string(),
        ));
    }

    let key = DeviceKey { owner, device_id: new_device };
    if DEVICES.with_borrow(|map| map.contains_key(&key)) {
        return Err(VetkeysError::InvalidRequest(
            "a device with this id is already registered to this principal (revoked ids are \
             retained as evidence and are never reusable)"
                .to_string(),
        ));
    }
    let active = active_devices(owner);
    if registry::active_cap_reached(active.len()) {
        return Err(VetkeysError::DeviceLimitReached {
            active: active.len() as u32,
        });
    }

    let approved_by = match &approval {
        DeviceApproval::Bootstrap => {
            // The ticket is checked and consumed HERE, in the same message as
            // the write it authorizes.
            // L04-07 CONSUME-TIME RE-CHECK — independently load-bearing.
            // The mint-time gate reads the device state as it was when the
            // ticket was minted; the ticket then lives for its TTL. A
            // revocation to zero INSIDE that window would otherwise be
            // reversible by a ticket minted moments before it, so the same
            // predicate is re-evaluated here, against the state as it is at
            // the write it authorizes.
            //
            // LAUNCH-HARDEN-04 O-8: each refusal names its OWN rule — the
            // device-approval flag (≥1 active device) or L04-07 (zero active).
            if !bootstrap_path_open(owner, now_ns) {
                let reason = if !active_devices(owner).is_empty() {
                    DEVICE_APPROVAL_REQUIRED
                } else {
                    RE_BOOTSTRAP_NOT_AUTHORIZED
                };
                return Err(VetkeysError::BootstrapNotAuthorized { reason: reason.to_string() });
            }
            let existing = BOOTSTRAP_TICKETS.with_borrow(|map| map.get(&owner));
            let ticket = tickets::check_consumable(existing, now_ns).map_err(|r| {
                VetkeysError::BootstrapNotAuthorized { reason: r.reason().to_string() }
            })?;
            BOOTSTRAP_TICKETS.with_borrow_mut(|map| map.insert(owner, tickets::consume(ticket)));
            // L04-07 ONE-SHOT — the policy row is CONSUMED here, with the
            // ticket it authorised (SSA landed-diff R-8 V1 AMBER-2; CTO ruling
            // cto-ruling-r8-landed-diff-fix-wave-2026-09-06 item 3).
            //
            // `ReBootstrapV1`'s own doc says the capability it grants is "one
            // future bootstrap registration for this principal". The nonce
            // makes the TRANSCRIPT single-use, but until this removal the
            // EFFECT was unbounded: a principal that legitimately recovered
            // once had the gate permanently disabled, so every LATER
            // revocation to zero was undoable by whoever held the II — which
            // is the exact threat the gate exists to close, re-opened by the
            // recovery it granted.
            //
            // Unconditional, and safe to be: the row's only meaning is
            // "one bootstrap registration is authorised", and this IS that
            // registration. `remove` on an absent key is a no-op, so the
            // never-enrolled and still-has-active-devices cases — which reach
            // this arm without a row — are unaffected.
            //
            // A principal that needs to recover a SECOND time signs a second
            // `authorize_re_bootstrap` from a device that is active at that
            // time, exactly as it did the first.
            let _ = RE_BOOTSTRAP_POLICY.with_borrow_mut(|map| map.remove(&owner));
            ApprovedBy::Bootstrap
        }
        DeviceApproval::Device(signed) => {
            let (issuer_key, issuer, nonce) = check_issuer(owner, signed, now_ns)?;
            // The transcript is REBUILT from the exact bytes about to be
            // written — including `wrapped_secret_hash`, which is what closes
            // the envelope-substitution hole (RED-3).
            let transcript = transcript::ApprovalV1 {
                canister_id: ic_cdk::api::canister_self(),
                principal: caller,
                issuer_device_id: signed.issuer_device_id.clone(),
                new_device_id: device_id.clone(),
                enc_pubkey_hash: sha256(&enc_pubkey_spki),
                sign_pubkey_hash: sha256(&sign_pubkey_spki),
                // D-1b v3 §2(5): this hashes the FINAL SERIALIZED ENVELOPE —
                // the exact bytes stored — not an inner ciphertext. In passcode
                // mode the envelope is the AES-GCM wrapping of the RSA
                // ciphertext, and it is that outer blob the signature commits
                // to, so a mode swap cannot slip past a registration signature.
                wrapped_secret_hash: sha256(&wrapped_secret),
                nonce,
                expiry_ns: signed.expiry_ns,
            }
            .encode();
            verify::verify_transcript(&issuer.sign_pubkey_spki, &transcript, &signed.signature)
                .map_err(|r| VetkeysError::ApprovalRejected(r.reason().to_string()))?;
            consume_nonce(owner, issuer_key, nonce, signed.expiry_ns, now_ns)?;
            ApprovedBy::Device(issuer_key)
        }
    };

    DEVICES.with_borrow_mut(|map| {
        map.insert(
            key,
            DeviceRecord {
                enc_pubkey_spki,
                sign_pubkey_spki,
                status: DeviceStatus::Active,
                added_at_ns: now_ns,
                revoked_at_ns: None,
                approved_by,
            },
        )
    });
    WRAPPED_SECRETS.with_borrow_mut(|map| map.insert(key, WrappedSecret(wrapped_secret)));
    Ok(())
}

/// Revoke one of the CALLER's devices, authorized by another (or the same)
/// ACTIVE device of the same principal.
///
/// HONEST FORWARD CUTOFF (brief V1 §2, adapting a prior published taxonomy):
/// revocation deletes the device's envelope and closes its read path from this
/// moment on. It CANNOT undo exposure a compromised device already had — that
/// device held the master note secret in memory. The remedy for
/// all-devices-compromised is note migration (spend-to-self under fresh notes),
/// NOT re-keying: the master secret is derivation-deterministic and cannot
/// rotate without re-keying the user's entire note history. This code must not
/// be described as retroactive erasure anywhere.
#[update]
fn revoke_device(device_id: String, approval: SignedApproval) -> Result<(), VetkeysError> {
    let caller = ic_cdk::api::msg_caller();
    if caller == Principal::anonymous() {
        return Err(VetkeysError::AnonymousCaller);
    }
    let owner = PrincipalKey::new(caller);
    let now_ns = ic_cdk::api::time();

    // RED-2: rate limit IMMEDIATELY after the anonymous check and BEFORE
    // device-id parsing, stable reads, transcript construction or P-256
    // verification — the uniform rule the other metered endpoints follow:
    // every call past the anonymous check costs one unit whatever its outcome,
    // so the expensive failure path cannot be looped for free. Its OWN window
    // (MemoryId 12): revocation must not consume the registration or
    // replacement allowance, nor they it.
    REVOCATION_RATE
        .with_borrow_mut(|map| {
            let mut window = map.get(&owner).unwrap_or_default();
            let out = registry::charge_revocation(now_ns, &mut window);
            map.insert(owner, window);
            out
        })
        .map_err(|retry_after_ns| VetkeysError::RevocationRateExceeded { retry_after_ns })?;

    let target = device_id_key(&device_id)?;

    let (issuer_key, issuer, nonce) = check_issuer(owner, &approval, now_ns)?;
    let transcript = transcript::RevokeV1 {
        canister_id: ic_cdk::api::canister_self(),
        principal: caller,
        issuer_device_id: approval.issuer_device_id.clone(),
        target_device_id: device_id.clone(),
        nonce,
        expiry_ns: approval.expiry_ns,
    }
    .encode();
    verify::verify_transcript(&issuer.sign_pubkey_spki, &transcript, &approval.signature)
        .map_err(|r| VetkeysError::ApprovalRejected(r.reason().to_string()))?;

    let key = DeviceKey { owner, device_id: target };
    let mut record = DEVICES
        .with_borrow(|map| map.get(&key))
        .ok_or(VetkeysError::UnknownDevice)?;
    if record.status != DeviceStatus::Active {
        return Err(VetkeysError::InvalidRequest(
            "that device is already revoked".to_string(),
        ));
    }

    consume_nonce(owner, issuer_key, nonce, approval.expiry_ns, now_ns)?;
    record.status = DeviceStatus::Revoked;
    record.revoked_at_ns = Some(now_ns);
    DEVICES.with_borrow_mut(|map| map.insert(key, record));
    // The envelope is DELETED; the record is retained as evidence.
    WRAPPED_SECRETS.with_borrow_mut(|map| map.remove(&key));
    Ok(())
}

/// Replace the CALLER's OWN device envelope (D-1b v3 §2).
///
/// WHAT THIS EXISTS FOR: the opt-in wallet passcode. Turning it on re-wraps the
/// same device envelope under an Argon2id-derived key; turning it off restores
/// the II-only form. Both are a REPLACEMENT of the stored blob, and both must
/// go through here — a wallet-local wrapper that left the canister blob bare
/// would mean the passcode protected nothing that an attacker with the canister
/// blob could not simply ignore. That is why this endpoint exists rather than
/// the toggle being a client-side concern.
///
/// SELF-SERVICE, NOT CROSS-DEVICE: the signer IS the subject. A device replaces
/// only its own envelope, so no device can rewrite another's — which would be
/// an envelope-substitution surface with extra steps.
///
/// ANTI-ROLLBACK: `old_envelope_hash` must equal the hash of what is stored at
/// this instant. A captured earlier envelope therefore cannot be re-installed
/// (its hash is no longer current), and two concurrent replacements cannot
/// silently overwrite one another — the loser's `old_envelope_hash` is stale.
/// Combined with the single-use nonce, replaying a captured ReplaceV1 fails on
/// both counts independently.
///
/// HONESTY, NOT A SECURITY CLAIM (D-1b v3 §1 / v4 §1): the swap makes the old
/// envelope unrecoverable CANISTER-SIDE. It does not un-copy an envelope an
/// attacker already took. Nothing here is a cryptographic cutoff.
#[update]
fn replace_envelope(
    device_id: String,
    new_envelope: Vec<u8>,
    approval: SignedApproval,
) -> Result<(), VetkeysError> {
    let caller = ic_cdk::api::msg_caller();
    if caller == Principal::anonymous() {
        return Err(VetkeysError::AnonymousCaller);
    }
    let owner = PrincipalKey::new(caller);
    let now_ns = ic_cdk::api::time();

    // Rate limit FIRST and uniformly, as everywhere else in this canister: a
    // failing path must not be loopable against a caller-writable stable
    // surface. Its OWN window (MemoryId 11), so a toggle cannot eat the
    // allowance a user needs to register a device.
    REPLACEMENTS
        .with_borrow_mut(|map| {
            let mut window = map.get(&owner).unwrap_or_default();
            let out = registry::charge_replacement(now_ns, &mut window);
            map.insert(owner, window);
            out
        })
        .map_err(|retry_after_ns| VetkeysError::RegistrationRateExceeded { retry_after_ns })?;

    let subject = device_id_key(&device_id)?;
    if new_envelope.is_empty() || !state::wrapped_secret_fits(new_envelope.len()) {
        return Err(VetkeysError::InvalidRequest(
            "the replacement envelope is empty or exceeds the maximum stored size".to_string(),
        ));
    }
    // The signer must be the subject itself. Checked BEFORE `check_issuer` so
    // the refusal names the real rule rather than "unknown issuer".
    if approval.issuer_device_id != device_id {
        return Err(VetkeysError::ApprovalRejected(
            "a device may replace only its OWN envelope — the signing device and the subject \
             device must be the same"
                .to_string(),
        ));
    }
    // Reuses the §C preamble verbatim: Active-device check, expiry, nonce
    // width, signature width. One implementation, so the two signed operations
    // cannot drift apart on who may sign.
    let (device_key, record, nonce) = check_issuer(owner, &approval, now_ns)?;

    let key = DeviceKey { owner, device_id: subject };
    let current = WRAPPED_SECRETS
        .with_borrow(|map| map.get(&key))
        .ok_or(VetkeysError::UnknownDevice)?;

    let transcript = transcript::ReplaceV1 {
        canister_id: ic_cdk::api::canister_self(),
        principal: caller,
        device_id: device_id.clone(),
        old_envelope_hash: sha256(&current.0),
        new_envelope_hash: sha256(&new_envelope),
        nonce,
        expiry_ns: approval.expiry_ns,
    }
    .encode();
    // Built from the CURRENT stored envelope and the bytes about to be written,
    // so a signature over any other pair simply does not verify. That is the
    // anti-rollback check and the binding check in one step — there is no
    // separate comparison to forget.
    verify::verify_transcript(&record.sign_pubkey_spki, &transcript, &approval.signature).map_err(
        |r| {
            VetkeysError::ApprovalRejected(format!(
                "{} (a stale `old_envelope_hash` — a rollback or a lost update — fails here \
                 too, because the canister rebuilds the transcript from what is stored NOW)",
                r.reason()
            ))
        },
    )?;

    consume_nonce(owner, device_key, nonce, approval.expiry_ns, now_ns)?;
    // Atomic in this message: the old envelope is gone the instant the new one
    // lands, and no state is left half-swapped on any refusal above.
    WRAPPED_SECRETS.with_borrow_mut(|map| map.insert(key, WrappedSecret(new_envelope)));
    Ok(())
}

/// Fetch the caller's own wrapped master-secret envelope for one of its ACTIVE
/// devices. Opaque bytes: without that device's non-extractable private key
/// they are useless, which is the canister half of split knowledge.
#[query]
fn get_wrapped_secret(device_id: String) -> Result<Vec<u8>, VetkeysError> {
    let caller = ic_cdk::api::msg_caller();
    if caller == Principal::anonymous() {
        return Err(VetkeysError::AnonymousCaller);
    }
    let owner = PrincipalKey::new(caller);
    let key = DeviceKey { owner, device_id: device_id_key(&device_id)? };
    let record = DEVICES
        .with_borrow(|map| map.get(&key))
        .ok_or(VetkeysError::UnknownDevice)?;
    if record.status != DeviceStatus::Active {
        // A revoked device receives neither the blob nor a working read path.
        return Err(VetkeysError::DeviceRevoked);
    }
    WRAPPED_SECRETS
        .with_borrow(|map| map.get(&key))
        .map(|w| w.0)
        .ok_or(VetkeysError::UnknownDevice)
}

/// The caller's OWN devices only. There is no endpoint that returns another
/// principal's devices, by construction: the range is keyed on the caller.
#[query]
fn list_devices() -> Vec<DeviceView> {
    let caller = ic_cdk::api::msg_caller();
    if caller == Principal::anonymous() {
        return Vec::new();
    }
    let (lo, hi) = DeviceKey::owner_range(PrincipalKey::new(caller));
    DEVICES.with_borrow(|map| {
        map.range(lo..=hi)
            .map(|entry| {
                let (k, rec) = (entry.key(), entry.value());
                DeviceView {
                device_id: k.device_id.as_str(),
                enc_pubkey_spki: rec.enc_pubkey_spki,
                sign_pubkey_spki: rec.sign_pubkey_spki,
                active: rec.status == DeviceStatus::Active,
                added_at_ns: rec.added_at_ns,
                revoked_at_ns: rec.revoked_at_ns,
                approved_by_device: match rec.approved_by {
                    ApprovedBy::Bootstrap => None,
                    ApprovedBy::Device(id) => Some(id.as_str()),
                },
                }
            })
            .collect()
    })
}

/// Pinned config surface: `(domain_separator, vetkd_key_name)`. The wallet
/// asserts the domain separator against its own compiled-in constant at
/// startup — a mismatch means silently undecryptable payloads, so fail loudly.
#[query]
fn get_config() -> (String, String) {
    with_key_manager(|km| {
        let config = km.config.get();
        (
            config.domain_separator.clone(),
            config.key_id.name.clone(),
        )
    })
}

/// The configured §D token canister, or `null` when unconfigured.
///
/// Read-only and non-sensitive (a canister id is public), like `cycle_balance`.
/// It exists because the upgrade-PRESERVE semantics must be provable by
/// comparing the STORED principal — not by observing that queries still behave
/// the same, which would pass even if the cell had been rewritten to another
/// canister that happens to answer alike.
#[query]
fn get_token_canister() -> Option<Principal> {
    state::token_canister()
}

// ═════════════════════════════════════════════════════════════════════════════
// LAUNCH-HARDEN-04 O-1(b) — `has_active_device`, answered ONLY to the pool
// ═════════════════════════════════════════════════════════════════════════════

/// The configured `has_active_device` caller (MemoryId 20), or `null`.
/// Read-only, non-sensitive (a canister id is public). Exists so the packet can
/// prove the STORED principal after the upgrade, as `get_token_canister` does.
#[query]
fn get_device_check_caller() -> Option<Principal> {
    state::device_check_caller()
}

/// LAUNCH-HARDEN-04 O-1(b) (CTO Addendum 2 V-1; SSA C-1). Refusals are TYPED so
/// "unconfigured" / "not you" can never be confused with a real user state —
/// the `EligibilityCheckUnavailable`-vs-`PrincipalNotEligible` doctrine.
/// Candid is structural: the pool's mirror of this type must use exactly these
/// variant NAMES (drift-locked by `has_active_device_wire_pinned` here and
/// `o1b_device_check_wire_pinned` in the pool).
#[derive(CandidType, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCheckRefusal {
    /// MemoryId 20 is absent — never configured with an authorized caller.
    /// Fail closed.
    CallerNotConfigured,
    /// MemoryId 20 is set and the caller is not it. Nothing about `principal`
    /// is revealed.
    CallerNotAuthorized,
}

/// PURE of ic_cdk (native-testable): the caller is passed in. The check ORDER is
/// load-bearing: configuration and caller are checked BEFORE any device read,
/// so an unauthorized caller learns nothing about `principal`.
fn has_active_device_for(
    caller: Principal,
    principal: Principal,
) -> Result<bool, DeviceCheckRefusal> {
    let Some(authorized) = state::device_check_caller() else {
        return Err(DeviceCheckRefusal::CallerNotConfigured);
    };
    if caller != authorized {
        return Err(DeviceCheckRefusal::CallerNotAuthorized);
    }
    if principal == Principal::anonymous() {
        return Ok(false);
    }
    let (lo, hi) = DeviceKey::owner_range(PrincipalKey::new(principal));
    Ok(DEVICES.with_borrow(|m| {
        m.range(lo..=hi).any(|e| e.value().status == DeviceStatus::Active)
    }))
}

/// True iff `principal` has at least one ACTIVE device — answered ONLY to the
/// configured caller (the pool). Same "active" predicate as `active_devices`,
/// short-circuiting. WHY RESTRICTED: the ledger keeps no transaction history,
/// so "this principal uses the pool" is not otherwise public.
#[query]
fn has_active_device(principal: Principal) -> Result<bool, DeviceCheckRefusal> {
    has_active_device_for(ic_cdk::api::msg_caller(), principal)
}

// ═════════════════════════════════════════════════════════════════════════════
// LAUNCH-HARDEN-04 O-8 — "require device approval" flag (RW-02)
// ═════════════════════════════════════════════════════════════════════════════
//
// ACCEPTED SCOPE: the flag blocks NEW-DEVICE ENROLMENT WITHOUT AN EXISTING
// DEVICE'S APPROVAL, and nothing else. It does NOT stop a live, hijacked
// Internet Identity session from deriving the vetKey (the II session is the
// identity boundary).

/// Set (`require = true`) or clear (`require = false`) the CALLER's "require
/// device approval" flag, signed by one of the caller's ACTIVE devices.
///
/// Full §C discipline, the `authorize_re_bootstrap` template: anonymous
/// refused, `REVOCATION_RATE` charge FIRST, `check_issuer` (an ACTIVE issuer —
/// so the flag can never be set from zero devices), transcript rebuilt and
/// verified, nonce burned, then the write.
///
///   * `true`  → insert the row; effective immediately; cancels any pending
///               II-only clear.
///   * `false` → DELETE the row; effective IMMEDIATELY (CTO Addendum 2 V-3b).
///               Idempotent: with no row it is `Ok(())` and the nonce is still
///               consumed. A device holder can already approve any new device
///               instantly, so an immediate device-signed clear grants nothing
///               new.
#[update]
fn set_device_approval_policy(
    require: bool,
    approval: SignedApproval,
) -> Result<(), VetkeysError> {
    let caller = ic_cdk::api::msg_caller();
    if caller == Principal::anonymous() {
        return Err(VetkeysError::AnonymousCaller);
    }
    let owner = PrincipalKey::new(caller);
    let now_ns = ic_cdk::api::time();

    REVOCATION_RATE
        .with_borrow_mut(|map| {
            let mut window = map.get(&owner).unwrap_or_default();
            let out = registry::charge_revocation(now_ns, &mut window);
            map.insert(owner, window);
            out
        })
        .map_err(|retry_after_ns| VetkeysError::RevocationRateExceeded { retry_after_ns })?;

    let (issuer_key, issuer, nonce) = check_issuer(owner, &approval, now_ns)?;
    let transcript = transcript::SetDeviceApprovalPolicyV1 {
        canister_id: ic_cdk::api::canister_self(),
        principal: caller,
        issuer_device_id: approval.issuer_device_id.clone(),
        require_device_approval: require,
        nonce,
        expiry_ns: approval.expiry_ns,
    }
    .encode();
    verify::verify_transcript(&issuer.sign_pubkey_spki, &transcript, &approval.signature)
        .map_err(|r| VetkeysError::ApprovalRejected(r.reason().to_string()))?;
    consume_nonce(owner, issuer_key, nonce, approval.expiry_ns, now_ns)?;

    DEVICE_APPROVAL_POLICY.with_borrow_mut(|map| {
        if require {
            map.insert(
                owner,
                DeviceApprovalPolicyV1 {
                    require_device_approval: true,
                    set_by_device: issuer_key,
                    set_at_ns: now_ns,
                    pending_clear_at_ns: None,
                },
            );
        } else {
            map.remove(&owner);
        }
    });
    Ok(())
}

/// The II-ONLY clear path: no device needed, so a user who lost every device is
/// never locked out. Sets a pending clear that takes effect after
/// `pins::DEVICE_APPROVAL_CLEAR_DELAY_NS` (24 h); an existing pending clear is
/// returned unchanged (never reset, never extended). A held device can cancel
/// it at any time with a device-signed `set_device_approval_policy(true)`.
/// Returns the instant (ns) at which the clear takes effect.
#[update]
fn request_device_approval_policy_clear() -> Result<u64, VetkeysError> {
    let caller = ic_cdk::api::msg_caller();
    if caller == Principal::anonymous() {
        return Err(VetkeysError::AnonymousCaller);
    }
    let owner = PrincipalKey::new(caller);
    let now_ns = ic_cdk::api::time();

    REVOCATION_RATE
        .with_borrow_mut(|map| {
            let mut window = map.get(&owner).unwrap_or_default();
            let out = registry::charge_revocation(now_ns, &mut window);
            map.insert(owner, window);
            out
        })
        .map_err(|retry_after_ns| VetkeysError::RevocationRateExceeded { retry_after_ns })?;

    let Some(mut row) = DEVICE_APPROVAL_POLICY.with_borrow(|m| m.get(&owner)) else {
        return Err(VetkeysError::InvalidRequest(
            "no device-approval policy is set".to_string(),
        ));
    };
    if let Some(existing) = row.pending_clear_at_ns {
        return Ok(existing);
    }
    let at = now_ns
        .checked_add(pins::DEVICE_APPROVAL_CLEAR_DELAY_NS)
        .unwrap_or(u64::MAX);
    row.pending_clear_at_ns = Some(at);
    DEVICE_APPROVAL_POLICY.with_borrow_mut(|m| m.insert(owner, row));
    Ok(at)
}

/// The Candid-safe projection of a `DeviceApprovalPolicyV1` row.
/// `set_by_device` is deliberately NOT exposed.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeviceApprovalPolicyView {
    pub require_device_approval: bool,
    pub set_at_ns: u64,
    pub pending_clear_effective_at_ns: Option<u64>,
}

/// The CALLER's OWN device-approval policy row, or `null` (flag off).
/// Caller-scoped by construction — no owner argument.
#[query]
fn device_approval_policy() -> Option<DeviceApprovalPolicyView> {
    let owner = PrincipalKey::new(ic_cdk::api::msg_caller());
    DEVICE_APPROVAL_POLICY
        .with_borrow(|map| map.get(&owner))
        .map(|p| DeviceApprovalPolicyView {
            require_device_approval: p.require_device_approval,
            set_at_ns: p.set_at_ns,
            pending_clear_effective_at_ns: p.pending_clear_at_ns,
        })
}

/// L04-07 — authorize this principal to re-open the BOOTSTRAP path, on the
/// signature of a device that is ACTIVE at the moment of signing.
///
/// THE RECOVERY IT EXISTS FOR: a user with two devices loses one, revokes it,
/// then loses the second. Between those two revocations the second device is
/// still active and can sign this authorization, which is what makes the
/// eventual revoked-to-zero state recoverable at all. A principal that revokes
/// its LAST device without having signed one first is deliberately stuck —
/// there is nobody left who can vouch, and inventing an escape hatch here
/// would be exactly the hole the gate exists to close.
///
/// CALLER-SCOPED. `target` is carried as an explicit argument (the policy row
/// it writes is the target's), but the caller MUST be the target: otherwise a
/// third party could drive the target's rate-limit window, and the row's
/// subject would not be the party paying for the call.
///
/// FULL §C DISCIPLINE, not just an issuer lookup: rate limit first, then
/// `check_issuer` (registered, ACTIVE, unexpired, well-formed), then the
/// transcript is REBUILT from the exact bytes this call is acting on and the
/// signature verified against the issuer's own signing key, then the nonce is
/// burned. Anything less would let a captured `RevokeV1` or `ApprovalV1` be
/// replayed as a re-bootstrap authorization.
///
/// The rate-limit window is REVOCATION_RATE (MemoryId 12), not REGISTRATIONS:
/// this call is the last step of the revocation story and the user needs their
/// registration allowance INTACT immediately afterwards to re-enrol.
///
/// ONE-SHOT. The row this writes authorises exactly ONE bootstrap
/// registration and is REMOVED by it (`register_device`'s `Bootstrap` arm).
/// A sticky row would permanently disable the gate for any principal that
/// ever recovered once — see the removal site for the full reasoning.
#[update]
fn authorize_re_bootstrap(
    target: Principal,
    approval: SignedApproval,
) -> Result<(), VetkeysError> {
    let caller = ic_cdk::api::msg_caller();
    if caller == Principal::anonymous() {
        return Err(VetkeysError::AnonymousCaller);
    }
    if caller != target {
        return Err(VetkeysError::InvalidRequest(
            "authorize_re_bootstrap is caller-scoped: target must be the caller".to_string(),
        ));
    }
    let owner = PrincipalKey::new(target);
    let now_ns = ic_cdk::api::time();

    REVOCATION_RATE
        .with_borrow_mut(|map| {
            let mut window = map.get(&owner).unwrap_or_default();
            let out = registry::charge_revocation(now_ns, &mut window);
            map.insert(owner, window);
            out
        })
        .map_err(|retry_after_ns| VetkeysError::RevocationRateExceeded { retry_after_ns })?;

    let (issuer_key, issuer, nonce) = check_issuer(owner, &approval, now_ns)?;
    let transcript = transcript::ReBootstrapV1 {
        canister_id: ic_cdk::api::canister_self(),
        principal: target,
        issuer_device_id: approval.issuer_device_id.clone(),
        nonce,
        expiry_ns: approval.expiry_ns,
    }
    .encode();
    verify::verify_transcript(&issuer.sign_pubkey_spki, &transcript, &approval.signature)
        .map_err(|r| VetkeysError::ApprovalRejected(r.reason().to_string()))?;
    consume_nonce(owner, issuer_key, nonce, approval.expiry_ns, now_ns)?;

    RE_BOOTSTRAP_POLICY.with_borrow_mut(|map| {
        map.insert(
            owner,
            RebootstrapPolicyV1 {
                allow_re_bootstrap: true,
                authorized_by_device: Some(issuer_key),
                authorized_at_ns: now_ns,
            },
        )
    });
    Ok(())
}

/// The Candid-safe projection of a `RebootstrapPolicyV1` row: `bool` and `u64`
/// only. `authorized_by_device` is deliberately NOT exposed — it is forensic
/// evidence, `DeviceIdKey` derives no `CandidType`, and the caller already
/// knows its own devices.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct RebootstrapPolicyView {
    pub allow_re_bootstrap: bool,
    pub authorized_at_ns: u64,
}

/// L04-07 — the CALLER's OWN re-bootstrap policy row, or `null` if it has none.
///
/// CALLER-SCOPED BY CONSTRUCTION: there is no owner argument, so no principal
/// can read another's row. Same posture as `list_devices`.
///
/// `null` is the pre-this-lane state of every existing enrolment, and both the
/// mint-time and consume-time gates read it as NOT AUTHORIZED — so a caller
/// reading `null` here and a canister refusing a bootstrap are reporting the
/// same fact.
///
/// ONE-SHOT: the row is REMOVED by the bootstrap registration it authorises,
/// so this query returns `null` again afterwards. A caller reading `null` has
/// either never authorised one, or already spent the one it authorised.
#[query]
fn re_bootstrap_policy() -> Option<RebootstrapPolicyView> {
    let owner = PrincipalKey::new(ic_cdk::api::msg_caller());
    RE_BOOTSTRAP_POLICY
        .with_borrow(|map| map.get(&owner))
        .map(|p| RebootstrapPolicyView {
            allow_re_bootstrap: p.allow_re_bootstrap,
            authorized_at_ns: p.authorized_at_ns,
        })
}

/// The canister's own cycle balance — the interface CONTRACT lane A-6's fleet
/// monitor consumes (`GAP-U9-1`). Additive query; no state, no caller check
/// (the value is not sensitive and the monitor may be unauthenticated).
///
/// This surface is also load-bearing for the A-2 saturation residual: table
/// saturation is detected as an ingress-rate and cycle-burn anomaly, so A-6 is
/// the DETECTION half of the compensating controls, not a convenience.
///
/// API: `ic_cdk::api::canister_cycle_balance()` — this crate pins ic-cdk 0.20.2
/// (NOT the workspace's 0.16; that mismatch is why the crate is workspace-
/// excluded). It returns `u128`, which Candid encodes as `nat`.
#[query]
fn cycle_balance() -> u128 {
    ic_cdk::api::canister_cycle_balance()
}

// ═════════════════════════════════════════════════════════════════════════════
// OBSERVABILITY — `derive_budget_stats` (A1 fix brief V5 §3, §6.7)
// ═════════════════════════════════════════════════════════════════════════════
//
// WHY A QUERY AND NOT A LOG. The C-26 remedy's budget is a wall the fleet can
// hit for two completely different reasons — organic growth, or an attack — and
// the operator's response to those is opposite (raise the on-ramp, versus sit
// out and DO NOT top up). Nothing in the refusal itself distinguishes them. This
// surface exists so the monitor can, and so the answer is a machine-readable
// fact rather than an inference from a graph.
//
// PRIVACY: COUNTS ONLY (§3, SSA GREEN-4). No principal ids, no hashes of them,
// no buckets narrow enough to intersect across calls. Every field below is a
// cardinality or a magnitude. The cycle figures are already public through the
// `cycle_balance` query this canister has shipped since lane A-2, so the floor
// view discloses nothing new.
//
// FLOOR IS DERIVED, NEVER COUNTED (§3): it is read at query time from the live
// platform values, exactly as the fence reads them, so it cannot go stale and
// there is no counter to keep in step.

/// The cycle-floor position, with EVERY platform outcome representable (§3).
///
/// Three variants, not two, because there are genuinely three states and
/// collapsing any pair would make the monitor assert something it cannot see:
///
///   * `Live` — both the liquid balance and the live derive price were
///     readable, so the fence's own predicate could be evaluated. `admits` IS
///     that verdict.
///   * `FloorOnly` — the live price query returned an `Err`, so the ADMISSION
///     verdict cannot be computed. **The weaker verdict still can**, and is
///     reported: `meets_pinned_floor` is `liquid >= DERIVE_CYCLE_FLOOR_CYCLES`.
///     Returning only an error string here would collapse a DEFINITE
///     below-floor condition into "the price was unavailable", and the monitor
///     would be unable to tell a hard-floor event from an indeterminate cost
///     component — a distinction it must act on differently (SSA RED-1).
///   * `Unavailable` — the position could not be established at all (no
///     initialised `KeyManager`, so there is no configured key id and no price
///     to ask for). **This maps to the monitor's `Incomplete`, never to `Ok`**:
///     "could not tell" is not "fine", which is the rule the whole monitor is
///     built on.
///
/// **NO RAW CYCLE MAGNITUDES — VERDICTS INSTEAD.** V5 §7.1 leaves each
/// variant's field list to the builder. Carrying `liquid_cycles` /
/// `live_cost_cycles` / `floor_cycles` here would create a NEW raw-amount
/// boundary on a public return — the amount-boundary census (C4 §4 rule 2)
/// flags exactly that, and enrolling one is expressly not a builder's call. So
/// this type carries the two VERDICTS a consumer cannot compute for itself,
/// which is also the §3-faithful reading: "floor DERIVED, never counted".
///
/// **AND `cycle_balance` IS NOT A SUBSTITUTE FOR THEM (SSA RED-1).** That query
/// returns the GROSS balance; the fence and this view use
/// `canister_liquid_cycle_balance`, already NET of the freezing reserve. A
/// consumer that compared the gross balance against the pinned floor would be
/// answering a different question — the exact substitution the C-26 remedy
/// rejected. The liquid position is knowable ONLY here, which is why the
/// verdicts are the payload and no external cross-check can stand in for them.
///
/// (`CycleFloorReached`'s figures are unaffected: they ride the ERROR half of a
/// `Result`, which the census excludes by design.)
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum CycleFloorView {
    Live {
        /// The fence's own predicate (`fence::cycle_floor_admits`), evaluated
        /// on the live figures at query time — called, never restated, so a
        /// second copy of the comparison cannot drift from the deciding one.
        admits: bool,
    },
    FloorOnly {
        /// `liquid >= DERIVE_CYCLE_FLOOR_CYCLES`, from the SHARED predicate
        /// `fence::meets_pinned_floor` — never a second copy of the comparison.
        ///
        /// **THIS IS NOT AN ADMISSION VERDICT** and a consumer must never read
        /// it as one: the live cost is unknown on this branch, so `true` means
        /// "above the reserve floor, cost component unavailable", never "a
        /// derive would succeed". `false` is a DEFINITE hard-floor condition.
        meets_pinned_floor: bool,
        /// Why the live price was unavailable — the `Err` text, verbatim.
        reason: String,
    },
    Unavailable(String),
}

/// The observability surface. Read-only, no caller check (the monitor may be
/// unauthenticated, exactly as for `cycle_balance`), and the window prune is
/// computed on a COPY — a query must never mutate, and a query that pruned
/// would also be a free way to move the fleet's capacity.
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeriveBudgetStats {
    /// The rolling window, ns (`pins::GLOBAL_DERIVE_WINDOW_NS`).
    pub window_ns: u64,
    /// The admission pin (`pins::GLOBAL_DERIVE_BUDGET`).
    pub budget: u32,
    /// Retained dispatches in the window — EXACT, and INCLUDING any untagged
    /// V1 carry. An untagged entry genuinely consumed fleet capacity, so
    /// omitting it here would under-report the wall.
    pub consumed: u32,
    /// `fence::global_retry_after_ns` — 0 while the budget admits.
    pub retry_after_ns: u64,
    /// The subset of `consumed` that carries attribution. `consumed -
    /// tagged_consumed` is the untagged remainder, and the three attribution
    /// fields below are computed over the TAGGED subset only.
    pub tagged_consumed: u32,
    /// Distinct principals among the tagged subset.
    pub distinct_principals: u32,
    /// The largest number of tagged dispatches held by any one principal — the
    /// concentration numerator.
    pub max_by_one_principal: u32,
    /// Tagged dispatches that were that principal's FIRST-ever derive.
    pub first_derive_dispatches: u32,
    /// Budget refusals since `stats_epoch_ns`. **Ephemeral heap counter** — the
    /// A-2 meter precedent (registry row 7): a refusal must never cause a
    /// stable write, or refusing would itself become a way to make the canister
    /// do durable work. Reset by an upgrade, which is what `stats_epoch_ns` is
    /// for.
    pub refusals_budget_total: u64,
    /// Actual management-canister `vetkd_public_key` round trips since
    /// `stats_epoch_ns` (R-5, L04-02): incremented on a cache MISS and on an
    /// explicit controller refresh, never on a cache hit. **Ephemeral heap
    /// counter**, the same discipline as `refusals_budget_total`.
    pub verification_key_management_calls_total: u64,
    /// When the ephemeral counters above and below were last reset (install or
    /// upgrade). A consumer comparing two samples MUST check this: across an
    /// epoch change the counters are not comparable and a difference is not a
    /// rate.
    pub stats_epoch_ns: u64,
    /// The live cycle-floor position (§3) — derived, not counted.
    pub floor: CycleFloorView,

    // ── §6.7 — the funding-wave rows ────────────────────────────────────────
    /// New age-in periods begun since `stats_epoch_ns`. **Ephemeral heap**, the
    /// same discipline as `refusals_budget_total`.
    ///
    /// COUNTS BOTH a new insertion AND an expired-row RENEWAL (SSA
    /// adjudication 5): both begin an age-in period, and counting only the
    /// first would under-report a wave made of returning principals.
    pub sightings_recorded_total: u64,
    /// Age refusals since `stats_epoch_ns`. **Ephemeral heap.**
    pub age_refusals_total: u64,
    /// Live rows in `ELIGIBILITY_SIGHTINGS` — a COUNT, bounded by
    /// `pins::MAX_SIGHTINGS`. No ids, per §3.
    pub sightings_pending: u32,
}

/// EPHEMERAL, EPOCH-SCOPED COUNTERS (§3, §6.7).
///
/// Heap, never stable, and the reason is not tidiness: a counter written on a
/// refusal path turns "refuse this caller" into "make this canister perform a
/// durable write", which is a cheaper attack than the one being refused. The
/// A-2 meter (registry row 7) is heap for exactly this reason and this follows
/// it. `stats_epoch_ns` is what keeps the reset honest — a consumer that sees a
/// new epoch knows the counters restarted rather than the rate falling.
#[derive(Debug, Clone, Copy, Default)]
struct StatsCounters {
    epoch_ns: u64,
    refusals_budget_total: u64,
    /// Actual management-canister `vetkd_public_key` round trips made by
    /// `get_vetkey_verification_key` / `refresh_vetkey_verification_key_cache`
    /// since `epoch_ns` (R-5, L04-02). A cache HIT never moves this.
    verification_key_management_calls_total: u64,
    sightings_recorded_total: u64,
    age_refusals_total: u64,
}

thread_local! {
    static STATS: RefCell<StatsCounters> = const { RefCell::new(StatsCounters {
        epoch_ns: 0,
        refusals_budget_total: 0,
        verification_key_management_calls_total: 0,
        sightings_recorded_total: 0,
        age_refusals_total: 0,
    }) };
}

/// Start (or restart) the counter epoch. Called from `#[init]` and
/// `#[post_upgrade]` only — the two moments at which the heap is genuinely
/// fresh, so the epoch and the counters can never disagree.
fn reset_stats_epoch(now_ns: u64) {
    STATS.with_borrow_mut(|c| *c = StatsCounters { epoch_ns: now_ns, ..Default::default() });
}

/// The live floor position, read at query time from the same platform calls the
/// fence uses. NEVER PANICS: an uninitialised `KeyManager` is `Unavailable`,
/// not a trap — a monitor query that traps tells the operator nothing, and
/// `with_key_manager`'s `expect` is deliberately not used here.
fn floor_view_from(liquid: u128, price: Option<Result<u128, String>>) -> CycleFloorView {
    match price {
        // No configured key id at all — nothing to price, so nothing to say.
        None => CycleFloorView::Unavailable(
            "the KeyManager is not initialised on this deployment, so there is no configured \
             key id and no live derive price to quote — indeterminate, not healthy"
                .to_string(),
        ),
        // Both inputs present: the FULL admission verdict, from the fence's own
        // predicate — called rather than restated, so a second copy of the
        // comparison cannot drift from the one that decides.
        Some(Ok(live_cost_cycles)) => {
            CycleFloorView::Live { admits: fence::cycle_floor_admits(liquid, live_cost_cycles) }
        }
        // Price unknown, balance known: the WEAKER verdict is still computable
        // and is reported (SSA RED-1). Dropping it would collapse a definite
        // below-floor condition into price unavailability.
        Some(Err(reason)) => CycleFloorView::FloorOnly {
            meets_pinned_floor: fence::meets_pinned_floor(liquid),
            reason,
        },
    }
}

/// The impure reader — the ONLY part of the floor view that touches the
/// platform, kept to three lines so the mapping above stays pure and every
/// branch of it is drivable without a canister (SSA RED-2).
///
/// LIQUID, NOT GROSS: `canister_liquid_cycle_balance` is already net of the
/// freezing reserve, and it is the same call the fence makes. Substituting the
/// gross balance here would silently answer a different question.
fn cycle_floor_view() -> CycleFloorView {
    let liquid = ic_cdk::api::canister_liquid_cycle_balance();
    let price = KEY_MANAGER.with_borrow(|km| {
        km.as_ref().map(|km| {
            let config = km.config.get();
            let curve: u32 = config.key_id.curve.clone().into();
            ic_cdk::api::cost_vetkd_derive_key(&config.key_id.name, curve)
                .map_err(|e| format!("{e:?}"))
        })
    });
    floor_view_from(liquid, price)
}

/// §3 — the observability query.
///
/// READ-ONLY AND NON-MUTATING, including the window prune: the retained set is
/// computed over a COPY of the cell. A query that pruned would mutate fleet
/// capacity, and a caller who could trigger that would have a free way to move
/// the wall.
///
/// No caller check, by the same reasoning `cycle_balance` carries: the monitor
/// is unauthenticated and every field is a count or a magnitude, never an
/// identity.
#[query]
fn derive_budget_stats() -> DeriveBudgetStats {
    let now_ns = ic_cdk::api::time();
    // A COPY. `cell.get()` hands back a reference into the stable cell; the
    // clone is what keeps the prune below off the stored value.
    let mut window = state::GLOBAL_DERIVE_BUDGET_WINDOW.with_borrow(|cell| cell.get().clone());
    let retry_after_ns = fence::global_retry_after_ns(now_ns, &window);
    fence::prune_window(now_ns, &mut window);

    let consumed = window.dispatched.len() as u32;
    let tagged: Vec<state::PrincipalKey> =
        window.dispatched.iter().filter_map(|r| r.who).collect();
    let first_derive_dispatches =
        window.dispatched.iter().filter(|r| r.who.is_some() && r.first_derive).count() as u32;

    // Distinct and max-by-one over the TAGGED subset only (§3): an untagged V1
    // carry has no principal, and attributing it to one — even to a synthetic
    // "unknown" — would make both numbers assert something the cell never said.
    let mut distinct: Vec<state::PrincipalKey> = tagged.clone();
    distinct.sort_unstable();
    distinct.dedup();
    let max_by_one_principal = distinct
        .iter()
        .map(|d| tagged.iter().filter(|t| *t == d).count() as u32)
        .max()
        .unwrap_or(0);

    let counters = STATS.with_borrow(|c| *c);
    DeriveBudgetStats {
        window_ns: pins::GLOBAL_DERIVE_WINDOW_NS,
        budget: pins::GLOBAL_DERIVE_BUDGET,
        consumed,
        retry_after_ns,
        tagged_consumed: tagged.len() as u32,
        distinct_principals: distinct.len() as u32,
        max_by_one_principal,
        first_derive_dispatches,
        refusals_budget_total: counters.refusals_budget_total,
        verification_key_management_calls_total: counters.verification_key_management_calls_total,
        stats_epoch_ns: counters.epoch_ns,
        floor: cycle_floor_view(),
        sightings_recorded_total: counters.sightings_recorded_total,
        age_refusals_total: counters.age_refusals_total,
        sightings_pending: state::ELIGIBILITY_SIGHTINGS.with_borrow(|m| m.len()) as u32,
    }
}

ic_cdk::export_candid!();

#[cfg(test)]
mod tests {
    use super::*;

    // ── SSA RED-2 — the floor-view mapping, forced through every branch ──────
    //
    // `floor_view_from` is PURE, so each branch is driven directly rather than
    // hoped for from a platform. These arms carry obligation (2) of the RED-2
    // closure: force `FloorOnly` and `Unavailable` and check their exact
    // mappings, including both `meets_pinned_floor` edges.
    //
    // FLOOR and COST are written as their own literals here. Reading
    // `DERIVE_CYCLE_FLOOR_CYCLES` would move the expectation with the constant
    // and could not RED on a mutation of it.
    const F_FLOOR: u128 = 500_000_000_000;
    const F_COST: u128 = 26_000_000_000;

    /// Both inputs present → `Live`, carrying the FULL admission verdict, at
    /// both sides of the boundary.
    #[test]
    fn floor_view_maps_a_readable_price_to_the_live_admission_verdict() {
        assert_eq!(
            floor_view_from(F_FLOOR + F_COST, Some(Ok(F_COST))),
            CycleFloorView::Live { admits: true },
            "exactly cost + floor admits"
        );
        assert_eq!(
            floor_view_from(F_FLOOR + F_COST - 1, Some(Ok(F_COST))),
            CycleFloorView::Live { admits: false },
            "one cycle less does not — and it is still a LIVE reading, not a downgrade"
        );
    }

    /// **The `FloorOnly` branch, forced, with BOTH `meets_pinned_floor` edges.**
    ///
    /// This is the RED-1 closure made executable: a canister below its reserve
    /// floor whose price query happens to fail must still report a DEFINITE
    /// below-floor condition. Collapsing that into a bare error string is what
    /// the shipped shape must not do.
    #[test]
    fn floor_view_reports_the_weaker_verdict_when_the_price_is_unavailable() {
        let err = || Some(Err("cost query failed".to_string()));

        // Above the floor: floor met, but this is NOT an admission verdict —
        // the cost component is unknown and the type says so by construction.
        assert_eq!(
            floor_view_from(F_FLOOR, err()),
            CycleFloorView::FloorOnly {
                meets_pinned_floor: true,
                reason: "cost query failed".to_string()
            },
            "equality MEETS the pinned floor"
        );
        assert_eq!(
            floor_view_from(F_FLOOR + F_COST * 100, err()),
            CycleFloorView::FloorOnly {
                meets_pinned_floor: true,
                reason: "cost query failed".to_string()
            }
        );

        // Below the floor: a DEFINITE hard-floor event, still observable even
        // though the price is not. This is the reading the previous shape threw
        // away.
        assert_eq!(
            floor_view_from(F_FLOOR - 1, err()),
            CycleFloorView::FloorOnly {
                meets_pinned_floor: false,
                reason: "cost query failed".to_string()
            },
            "one cycle below the floor is a definite below-floor condition"
        );
        assert_eq!(
            floor_view_from(0, err()),
            CycleFloorView::FloorOnly {
                meets_pinned_floor: false,
                reason: "cost query failed".to_string()
            }
        );

        // The reason is carried VERBATIM — the branch-specific observable.
        match floor_view_from(0, Some(Err("a specific platform reason".to_string()))) {
            CycleFloorView::FloorOnly { reason, .. } => {
                assert_eq!(reason, "a specific platform reason");
            }
            other => panic!("expected FloorOnly, got {other:?}"),
        }
    }

    /// No configured key id → `Unavailable`, with a non-empty reason.
    ///
    /// DISTINCT FROM `FloorOnly`, and the distinction is operational: here NO
    /// verdict is offered at all, which the monitor must map to `Incomplete`.
    /// A `FloorOnly { meets_pinned_floor: false }` is an ALERT; this is "could
    /// not tell", and the two must never collapse.
    #[test]
    fn floor_view_maps_an_absent_key_manager_to_unavailable() {
        for liquid in [0u128, F_FLOOR - 1, F_FLOOR, u128::MAX] {
            match floor_view_from(liquid, None) {
                CycleFloorView::Unavailable(reason) => {
                    assert!(!reason.trim().is_empty(), "indeterminate must still say why");
                }
                other => panic!("an absent KeyManager must be Unavailable, got {other:?}"),
            }
        }
    }

    /// **RED-2 obligation (3), made executable: what a `Live` → `FloorOnly`
    /// mutation actually produces.**
    ///
    /// The target-platform probe (`f1`) asserts `Live` EXACTLY and panics on
    /// any other variant. This arm shows, on the same mapping, that forcing the
    /// price limb to `Err` yields `FloorOnly` — a variant `f1` refuses. The two
    /// together are the drift lock: the mutation's effect is demonstrated here,
    /// and the probe that it breaks is asserted there, so neither half is an
    /// argument.
    #[test]
    fn forcing_the_price_query_to_err_changes_the_variant_the_platform_probe_demands() {
        let liquid = F_FLOOR + F_COST;
        let live = floor_view_from(liquid, Some(Ok(F_COST)));
        let mutated = floor_view_from(liquid, Some(Err("forced".to_string())));

        assert!(matches!(live, CycleFloorView::Live { .. }), "the unmutated mapping is Live");
        assert!(
            !matches!(mutated, CycleFloorView::Live { .. }),
            "forcing the price to Err must move the variant OFF Live — which is what makes \
             f1's exact-variant assertion a lock rather than a comment"
        );
        assert!(matches!(mutated, CycleFloorView::FloorOnly { meets_pinned_floor: true, .. }));
        assert_ne!(live, mutated, "and the two readings are not interchangeable");
    }

    // ── RED-1 (VK-L1): consumed-nonce reclamation via the expiry index ──────
    //
    // Native tests over the thread-local stable structures: each #[test] runs
    // on its own thread, so each sees a fresh pair of maps.

    fn test_owner(n: u8) -> PrincipalKey {
        let mut b = [0u8; 29];
        b[0] = n;
        PrincipalKey::new(Principal::from_slice(&b))
    }

    fn consume(n: u8, expiry_ns: u64, now_ns: u64) -> Result<(), VetkeysError> {
        consume_nonce(
            test_owner(0x11),
            DeviceIdKey::new("issuer").unwrap(),
            [n; 16],
            expiry_ns,
            now_ns,
        )
    }

    fn nonce_counts() -> (u64, u64) {
        (
            CONSUMED_NONCES.with_borrow(|m| m.len()),
            NONCE_EXPIRY_INDEX.with_borrow(|ix| ix.len()),
        )
    }

    /// Every index row's `nonce_key` resolves in the primary map with the SAME
    /// expiry, and the two maps have equal cardinality — the bijection.
    fn assert_nonce_bijection() {
        let (primary, index) = nonce_counts();
        assert_eq!(primary, index, "primary/index cardinality must match");
        NONCE_EXPIRY_INDEX.with_borrow(|ix| {
            CONSUMED_NONCES.with_borrow(|m| {
                for entry in ix.iter() {
                    let k = entry.key();
                    assert_eq!(
                        m.get(&k.nonce_key),
                        Some(k.expiry_ns),
                        "index row without a matching primary row"
                    );
                }
            })
        });
    }

    /// A successful consume inserts BOTH rows; a replay-refused consume (the
    /// only `Err`) mutates NEITHER structure.
    #[test]
    fn l1_consume_inserts_both_and_a_refusal_inserts_neither() {
        let now = 1_000;
        consume(1, 5_000, now).expect("fresh nonce");
        assert_eq!(nonce_counts(), (1, 1));
        assert_nonce_bijection();

        let err = consume(1, 5_000, now).expect_err("replay refused");
        assert!(matches!(err, VetkeysError::ApprovalRejected(_)));
        assert_eq!(nonce_counts(), (1, 1), "a refused consume must move neither map");
        assert_nonce_bijection();
    }

    /// The prune predicate is EXACT (mutation-RED at the shipped expiry
    /// boundary): a row with `expiry < now` is reclaimed, a row AT `now` is
    /// retained until a later call, and live rows survive.
    #[test]
    fn l1_prune_boundary_is_exact_and_live_rows_survive() {
        consume(1, 2_000, 1_000).expect("will expire");
        consume(2, 3_000, 1_000).expect("expires AT the probe instant");
        consume(3, 9_000, 1_000).expect("stays live");
        assert_eq!(nonce_counts(), (3, 3));

        // now == 3_000: nonce 1 (expiry 2_000 < now) goes; nonce 2
        // (expiry == now) is conservatively retained; nonce 3 lives.
        consume(4, 9_000, 3_000).expect("the consuming call carries the prune");
        assert_eq!(nonce_counts(), (3, 3), "one expired pruned, one at-boundary kept, one added");
        assert!(
            CONSUMED_NONCES.with_borrow(|m| m.get(&NonceKey {
                owner: test_owner(0x11),
                issuer_device_id: DeviceIdKey::new("issuer").unwrap(),
                nonce: [2; 16],
            }) == Some(3_000)),
            "expiry == now is retained by the < now predicate"
        );
        assert!(
            CONSUMED_NONCES.with_borrow(|m| !m.contains_key(&NonceKey {
                owner: test_owner(0x11),
                issuer_device_id: DeviceIdKey::new("issuer").unwrap(),
                nonce: [1; 16],
            })),
            "expiry < now is reclaimed"
        );
        assert_nonce_bijection();

        // One ns later the boundary row is reclaimable too.
        consume(5, 9_000, 3_001).expect("consume");
        assert_eq!(nonce_counts(), (3, 3), "the at-boundary row went one ns later");
        assert_nonce_bijection();
    }

    /// A backlog LARGER than `K` costs at most `K` removals per call and
    /// drains over repeated calls, never in one (mutation-RED at `K`: this arm
    /// counts exactly `NONCE_PRUNE_MAX` removals on the first call).
    #[test]
    fn l1_backlog_over_k_drains_at_most_k_per_call_across_calls() {
        let backlog = pins::NONCE_PRUNE_MAX as u64 + 7; // 23 expired rows
        for i in 0..backlog {
            consume(i as u8, 2_000 + i, 1_000).expect("build the backlog");
        }
        assert_eq!(nonce_counts(), (backlog, backlog));

        // All 23 are expired at now = 500_000. The first consuming call
        // removes EXACTLY K of them (plus adds itself).
        consume(0xF0, 900_000, 500_000).expect("first draining call");
        let expect_after_first = backlog - pins::NONCE_PRUNE_MAX as u64 + 1;
        assert_eq!(
            nonce_counts(),
            (expect_after_first, expect_after_first),
            "exactly K = {} removals on the first call",
            pins::NONCE_PRUNE_MAX
        );

        // The second call drains the remaining 7.
        consume(0xF1, 900_000, 500_000).expect("second draining call");
        assert_eq!(nonce_counts(), (2, 2), "backlog fully drained across calls");
        assert_nonce_bijection();
    }

    // H-2 (A1): unit coverage of the pure validator that post_upgrade traps on —
    // SUPPLEMENTARY to the A2 PocketIC upgrade tests, which exercise the real fresh-cell
    // (trap) and preservation paths on the production Wasm (the load-bearing proof).
    #[test]
    fn validate_accepts_legit_installed_keys() {
        for name in ["key_1", "test_key_1", "dfx_test_key"] {
            assert!(
                validate_retained_config(DOMAIN_SEPARATOR, name, &VetKDCurve::Bls12_381_G2).is_ok(),
                "a legitimately installed key {name:?} must be preserved (Ok)"
            );
        }
    }

    #[test]
    fn validate_traps_on_surviving_sentinel() {
        // Fresh/absent config: the sentinel is what KeyManager stored as the default.
        let r = validate_retained_config(
            DOMAIN_SEPARATOR,
            POST_UPGRADE_SENTINEL_KEY_NAME,
            &VetKDCurve::Bls12_381_G2,
        );
        assert!(r.is_err(), "a surviving sentinel proves absent stable config → must reject");
        assert!(r.unwrap_err().contains("ABSENT"), "reason names the absent-config cause");
    }

    #[test]
    fn validate_traps_on_domain_mismatch() {
        assert!(
            validate_retained_config("stsh.wallet.notes.v2", "key_1", &VetKDCurve::Bls12_381_G2)
                .is_err(),
            "a namespace/domain mismatch must reject (would re-key every user)"
        );
    }

    // Note: `ic_cdk_management_canister::VetKDCurve` currently has only `Bls12_381_G2`, so a
    // wrong-curve fixture is not constructible here; the curve guard is a defensive one-way
    // check that activates if the IC ever adds another vetKD curve.

    // ── R6-1 metering (lane A-2) — E1..E5 ────────────────────────────────────
    //
    // `meter_admit` is PURE, so every limb below is provable here with no
    // PocketIC, no vetKD and no test-only feature flag. That is what makes the
    // per-limb mutation table cheap enough to be honest. The limbs that
    // genuinely need the canister boundary (anon rejects, charge-before-await,
    // no-refund-on-failure, the balance query) live in
    // tests/crossdevice_acceptance.rs as E6..E10.

    fn user(n: u8) -> Principal {
        let mut b = [0u8; 29];
        b[0] = n;
        Principal::from_slice(&b)
    }

    /// E1 — the budget-th call is admitted; the next is refused, with the
    /// over-budget variant and a retry hint.
    #[test]
    fn e1_over_budget_rejected_after_the_window_allowance() {
        let mut st = MeterState::default();
        let a = user(0xA1);
        for i in 0..MAX_DERIVATIONS_PER_WINDOW {
            assert_eq!(
                meter_admit(1_000, a, &mut st),
                Ok(()),
                "call {} of {} must be admitted",
                i + 1,
                MAX_DERIVATIONS_PER_WINDOW
            );
        }
        match meter_admit(1_000, a, &mut st) {
            Err(MeterRejection::OverBudget { retry_after_ns }) => {
                assert!(retry_after_ns > 0, "an over-budget refusal must carry a retry hint");
                assert!(retry_after_ns <= METER_WINDOW_NS);
            }
            other => panic!("expected OverBudget, got {other:?}"),
        }
    }

    /// E2 — after the window elapses, the same principal is admitted again.
    /// This is the PER-ENTRY RESET limb: the entry is still in the table.
    #[test]
    fn e2_window_expiry_resets_the_same_principal() {
        let mut st = MeterState::default();
        let a = user(0xA1);
        let t0 = 5_000_000u64;
        for _ in 0..MAX_DERIVATIONS_PER_WINDOW {
            meter_admit(t0, a, &mut st).expect("initial budget");
        }
        assert!(meter_admit(t0, a, &mut st).is_err(), "budget must be spent");

        // One nanosecond short of the window: still refused.
        assert!(
            meter_admit(t0 + METER_WINDOW_NS - 1, a, &mut st).is_err(),
            "the window must not roll over early"
        );
        // Exactly at the window: admitted, and the full allowance is back.
        assert_eq!(meter_admit(t0 + METER_WINDOW_NS, a, &mut st), Ok(()));
        assert_eq!(st.tracked(), 1, "the entry is RESET in place, not evicted");
        for _ in 1..MAX_DERIVATIONS_PER_WINDOW {
            meter_admit(t0 + METER_WINDOW_NS, a, &mut st).expect("full fresh allowance");
        }
        assert!(meter_admit(t0 + METER_WINDOW_NS, a, &mut st).is_err());
    }

    /// E3 — per-principal keying: A exhausting its budget does not affect B.
    #[test]
    fn e3_budgets_are_per_principal() {
        let mut st = MeterState::default();
        let (a, b) = (user(0xA1), user(0xB2));
        for _ in 0..MAX_DERIVATIONS_PER_WINDOW {
            meter_admit(1_000, a, &mut st).expect("A's budget");
        }
        assert!(meter_admit(1_000, a, &mut st).is_err(), "A is exhausted");
        for i in 0..MAX_DERIVATIONS_PER_WINDOW {
            assert_eq!(
                meter_admit(1_000, b, &mut st),
                Ok(()),
                "B call {} must be unaffected by A",
                i + 1
            );
        }
        assert_eq!(st.tracked(), 2, "two distinct principals tracked");
    }

    /// E4 — table saturation rejects new principals fail-closed; expired
    /// entries are reclaimed under pressure and a post-eviction admit succeeds.
    ///
    /// Uses a reduced local cap by filling to `MAX_TRACKED_PRINCIPALS` with
    /// synthetic principals; 100_000 entries is cheap in a unit test.
    #[test]
    fn e4_table_saturation_rejects_then_eviction_admits() {
        let mut st = MeterState::default();
        let t0 = 9_000_000u64;
        for i in 0..MAX_TRACKED_PRINCIPALS {
            let mut b = [0u8; 29];
            b[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            meter_admit(t0, Principal::from_slice(&b), &mut st).expect("filling the table");
        }
        assert_eq!(st.tracked(), MAX_TRACKED_PRINCIPALS);

        // A genuinely new principal, while every entry is LIVE: fail closed.
        // Distinguished at byte 20 so it CANNOT collide with the fill set,
        // which only ever writes bytes 0..8.
        let newcomer = {
            let mut b = [0u8; 29];
            b[20] = 0xFE;
            Principal::from_slice(&b)
        };
        assert_eq!(st.tracked(), MAX_TRACKED_PRINCIPALS, "newcomer is genuinely untracked");
        assert_eq!(
            meter_admit(t0, newcomer, &mut st),
            Err(MeterRejection::TableSaturated),
            "a full table of live entries must refuse new principals"
        );
        // An ALREADY-TRACKED principal is still served — saturation denies new
        // callers, it does not break existing ones.
        let mut b0 = [0u8; 29];
        b0[0..8].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(meter_admit(t0, Principal::from_slice(&b0), &mut st), Ok(()));

        // POST-EVICTION HALF: once the entries expire, the sweep reclaims them
        // and the newcomer is admitted.
        let t1 = t0 + METER_WINDOW_NS;
        assert_eq!(
            meter_admit(t1, newcomer, &mut st),
            Ok(()),
            "expired entries must be reclaimed under pressure and the newcomer admitted"
        );
        assert!(
            st.tracked() < MAX_TRACKED_PRINCIPALS,
            "the sweep must actually shrink the table, got {}",
            st.tracked()
        );
    }

    /// E5 — the constants are PINNED. A silent loosening to 5_000/hour must fail
    /// a test, not pass review.
    #[test]
    fn e5_metering_constants_are_pinned() {
        assert_eq!(MAX_DERIVATIONS_PER_WINDOW, 5, "derivations per principal per window");
        assert_eq!(METER_WINDOW_NS, 3_600_000_000_000, "one hour, in nanoseconds");
        assert_eq!(MAX_TRACKED_PRINCIPALS, 100_000, "bounded tracking table");
        assert_eq!(SWEEP_MIN_INTERVAL_NS, 60_000_000_000, "sweep cooldown, 60 s");
    }

    /// E11 (SSA-A2-D1) — REPEATED NEWCOMER REJECTION IS AMORTIZED, NOT A SCAN
    /// PER INGRESS.
    ///
    /// The defect: every untracked caller arriving at a full LIVE table used to
    /// run `retain` over all 100,000 entries, reclaim nothing, and be rejected —
    /// so rotating principals forced a full-table scan per cheap ingress,
    /// indefinitely, without reaching or paying for vetKD.
    ///
    /// THE OBSERVABLE IS DETERMINISTIC AND COUNTABLE, never timed
    /// (CTO_RULING_A-2_sweep_amplification): `entries_examined()` counts entries
    /// walked by sweeps. Wall-clock thresholds would measure the harness's mood.
    ///
    /// MAGNITUDES, per CAMPAIGN RULE 2 — a cost test against a table of ten
    /// proves nothing about a table of a hundred thousand, so this runs at the
    /// SHIPPED cap with `REJECTIONS` rotating newcomers, all at one instant so
    /// no entry can expire:
    /// ```text
    ///   table = MAX_TRACKED_PRINCIPALS = 100_000 (all live), REJECTIONS = 50
    ///     with the cooldown (SHIPPED) : sweeps = 1,  entries_examined = 100_000
    ///     cooldown removed (mutation) : sweeps = 50, entries_examined = 5_000_000  → REDs
    /// ```
    #[test]
    fn e11_repeated_newcomer_rejection_does_not_rescan_the_table() {
        const REJECTIONS: u64 = 50;
        let mut st = MeterState::default();
        let t0 = 7_000_000u64;
        for i in 0..MAX_TRACKED_PRINCIPALS {
            let mut b = [0u8; 29];
            b[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            meter_admit(t0, Principal::from_slice(&b), &mut st).expect("filling the table");
        }
        assert_eq!(st.tracked(), MAX_TRACKED_PRINCIPALS);
        let examined_before = st.entries_examined();

        // Rotating fresh principals, all at the SAME instant so every entry is
        // live and no sweep can reclaim anything.
        for i in 0..REJECTIONS {
            let mut b = [0u8; 29];
            b[20] = 0xFE;
            b[21..29].copy_from_slice(&i.to_le_bytes());
            assert_eq!(
                meter_admit(t0, Principal::from_slice(&b), &mut st),
                Err(MeterRejection::TableSaturated),
                "newcomer {i} must be refused fail-closed"
            );
        }

        let examined = st.entries_examined() - examined_before;
        assert!(
            examined <= MAX_TRACKED_PRINCIPALS as u64,
            "{REJECTIONS} rejections examined {examined} entries — more than one table's \
             worth means the sweep is re-running per ingress, which is the O(n)-per-cheap-\
             message amplification SSA-A2-D1 is about (a full scan each time would be {})",
            REJECTIONS * MAX_TRACKED_PRINCIPALS as u64
        );
        assert!(
            st.sweeps() <= 1,
            "at most one sweep may run inside the cooldown window; got {}",
            st.sweeps()
        );

        // NON-VACUITY: the bound is not achieved by never sweeping at all. Once
        // the cooldown has elapsed AND entries have expired, a sweep runs and
        // reclaims, so a newcomer is admitted.
        let t1 = t0 + METER_WINDOW_NS;
        let mut b = [0u8; 29];
        b[20] = 0xFF;
        assert_eq!(
            meter_admit(t1, Principal::from_slice(&b), &mut st),
            Ok(()),
            "after expiry the sweep must still reclaim and admit"
        );
        assert!(st.sweeps() >= 2, "the post-expiry sweep must actually have run");
    }

    // ── LAUNCH-HARDEN-04 O-1(b) — `has_active_device`, native ─────────────────

    fn put_device(owner: Principal, id: &str, active: bool) {
        DEVICES.with_borrow_mut(|m| {
            m.insert(
                DeviceKey { owner: PrincipalKey::new(owner), device_id: DeviceIdKey::new(id).unwrap() },
                DeviceRecord {
                    enc_pubkey_spki: vec![1],
                    sign_pubkey_spki: vec![2],
                    status: if active { DeviceStatus::Active } else { DeviceStatus::Revoked },
                    added_at_ns: 1,
                    revoked_at_ns: if active { None } else { Some(2) },
                    approved_by: ApprovedBy::Bootstrap,
                },
            )
        });
    }

    #[test]
    fn has_active_device_truth_table() {
        let pool = user(0x50);
        state::set_device_check_caller(pool);
        let (none, act, rev, mixed) = (user(1), user(2), user(3), user(4));
        put_device(act, "d1", true);
        put_device(rev, "d1", false);
        put_device(mixed, "d1", false);
        put_device(mixed, "d2", true);
        assert_eq!(has_active_device_for(pool, none), Ok(false), "no devices");
        assert_eq!(has_active_device_for(pool, act), Ok(true), "active");
        assert_eq!(has_active_device_for(pool, rev), Ok(false), "revoked-only");
        assert_eq!(has_active_device_for(pool, mixed), Ok(true), "mixed");
        assert_eq!(has_active_device_for(pool, Principal::anonymous()), Ok(false), "anonymous");
    }

    #[test]
    fn has_active_device_unconfigured_refuses() {
        let u = user(2);
        put_device(u, "d1", true);
        assert_eq!(state::device_check_caller(), None);
        for caller in [user(0x50), u, Principal::anonymous()] {
            assert_eq!(
                has_active_device_for(caller, u),
                Err(DeviceCheckRefusal::CallerNotConfigured),
                "an unconfigured cell must REFUSE, never answer Ok(false)/Ok(true)"
            );
        }
    }

    #[test]
    fn has_active_device_wrong_caller_refuses() {
        let (p, q, u) = (user(0x50), user(0x51), user(2));
        state::set_device_check_caller(p);
        put_device(u, "d1", true);
        assert_eq!(has_active_device_for(q, u), Err(DeviceCheckRefusal::CallerNotAuthorized));
        assert_eq!(has_active_device_for(p, u), Ok(true), "non-vacuity: the right caller is answered");
    }

    /// CROSS-CRATE DRIFT LOCK — the same four literal hex strings as the
    /// pool's `o1b_device_check_wire_pinned`. A renamed variant on either side
    /// fails one of the two suites.
    #[test]
    fn has_active_device_wire_pinned() {
        let enc = |r: Result<bool, DeviceCheckRefusal>| {
            candid::encode_one(r).unwrap().iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        assert_eq!(enc(Ok(true)), "4449444c026b02bc8a017ec5fed201016b02e3d3f4b9087f86f6afc10b7f01000001");
        assert_eq!(enc(Ok(false)), "4449444c026b02bc8a017ec5fed201016b02e3d3f4b9087f86f6afc10b7f01000000");
        assert_eq!(
            enc(Err(DeviceCheckRefusal::CallerNotConfigured)),
            "4449444c026b02bc8a017ec5fed201016b02e3d3f4b9087f86f6afc10b7f01000101"
        );
        assert_eq!(
            enc(Err(DeviceCheckRefusal::CallerNotAuthorized)),
            "4449444c026b02bc8a017ec5fed201016b02e3d3f4b9087f86f6afc10b7f01000100"
        );
    }

    // ── LAUNCH-HARDEN-04 O-8 — device-approval flag, native ──────────────────

    fn set_flag(owner: Principal, pending: Option<u64>) {
        DEVICE_APPROVAL_POLICY.with_borrow_mut(|m| {
            m.insert(
                PrincipalKey::new(owner),
                DeviceApprovalPolicyV1 {
                    require_device_approval: true,
                    set_by_device: DeviceIdKey::new("d1").unwrap(),
                    set_at_ns: 5,
                    pending_clear_at_ns: pending,
                },
            )
        });
    }

    #[test]
    fn device_approval_required_truth_table() {
        let t: u64 = 1_000_000;
        let (absent, set, pend) = (user(1), user(2), user(3));
        set_flag(set, None);
        set_flag(pend, Some(t));
        assert!(!device_approval_required(PrincipalKey::new(absent), t), "absent → false");
        assert!(device_approval_required(PrincipalKey::new(set), t), "set, no pending → true");
        assert!(device_approval_required(PrincipalKey::new(pend), t - 1), "pending not matured (t−1) → true");
        assert!(!device_approval_required(PrincipalKey::new(pend), t), "matured exactly at t → false");
        assert!(!device_approval_required(PrincipalKey::new(pend), t + 1), "past t → false");
    }

    /// (active 0 | ≥1) × (ever enrolled) × (L04-07 row) × (flag state).
    #[test]
    fn bootstrap_path_open_truth_table() {
        let now: u64 = 10_000;
        let rb = |owner: Principal| {
            RE_BOOTSTRAP_POLICY.with_borrow_mut(|m| {
                m.insert(
                    PrincipalKey::new(owner),
                    RebootstrapPolicyV1 {
                        allow_re_bootstrap: true,
                        authorized_by_device: None,
                        authorized_at_ns: 1,
                    },
                )
            });
        };
        let mut n = 0u8;
        let mut fresh = || {
            n += 1;
            user(0x80 + n)
        };
        for flag in [None, Some(None), Some(Some(now)), Some(Some(now + 1))] {
            // flag: None = no row; Some(None) = set; Some(Some(t)) = set with pending clear at t.
            let apply = |p: Principal| {
                if let Some(pending) = flag {
                    set_flag(p, pending);
                }
            };
            let flag_in_force = matches!(flag, Some(None)) || matches!(flag, Some(Some(t)) if now < t);

            // ≥1 active: the flag decides.
            let a = fresh();
            put_device(a, "d1", true);
            apply(a);
            assert_eq!(bootstrap_path_open(PrincipalKey::new(a), now), !flag_in_force, "≥1 active, flag {flag:?}");
            // ≥1 active + L04-07 row: the row is irrelevant in this branch.
            let a2 = fresh();
            put_device(a2, "d1", true);
            rb(a2);
            apply(a2);
            assert_eq!(bootstrap_path_open(PrincipalKey::new(a2), now), !flag_in_force);

            // never enrolled: open, whatever the flag says.
            let ne = fresh();
            apply(ne);
            assert!(bootstrap_path_open(PrincipalKey::new(ne), now), "never enrolled, flag {flag:?}");

            // revoked to zero, no L04-07 row: closed, whatever the flag says.
            let rz = fresh();
            put_device(rz, "d1", false);
            apply(rz);
            assert!(!bootstrap_path_open(PrincipalKey::new(rz), now), "revoked-to-zero, flag {flag:?}");

            // revoked to zero WITH an L04-07 row: open, whatever the flag says.
            let rzr = fresh();
            put_device(rzr, "d1", false);
            rb(rzr);
            apply(rzr);
            assert!(bootstrap_path_open(PrincipalKey::new(rzr), now), "revoked-to-zero + row, flag {flag:?}");
        }
    }
}




