// =============================================================================
// W-VETKEYS two-layer — PINNED CONSTANTS (brief V2 §E, V4 §H′.1)
// =============================================================================
//
// COMMIT-1 FREEZE. Every value here is a SHIPPED constant the SSA-GREENed brief
// V4 pins by number, and every one is mutation-RED'd in `pins::tests` below.
//
// The mutation-RED rule (V2 §E, restated because it is easy to violate
// silently): a test may NEVER assert a constant against itself, nor against a
// derived expression that reads it. Each assertion below REGENERATES its
// expected value from first principles at the point of use — the unit
// arithmetic is written out (`24 * 60 * 60 * 1_000_000_000`), so moving the
// constant moves the test to RED instead of moving the expectation with it.
//
// SCOPE FENCE: these are the W-VETKEYS Layer-2 admission pins. They are NOT
// the R6-1 lane A-2 metering constants (`MAX_DERIVATIONS_PER_WINDOW`,
// `METER_WINDOW_NS`, …), which remain in `lib.rs` untouched by this commit.
//
// THIRD CLASS (C-26 remedy, A1 brief V3 §7.3): CANISTER-AVAILABILITY pins —
// `DERIVE_CYCLE_FLOOR_CYCLES`, `GLOBAL_DERIVE_BUDGET`,
// `GLOBAL_DERIVE_WINDOW_NS`, `PER_PRINCIPAL_HOURLY_DERIVE_CAP` (LAUNCH-HARDEN-04
// O-3). These are neither Layer-2 admission pins nor A-2
// metering constants: they bound what the CANISTER as a whole may spend or
// dispatch, not what any principal may do. Named here explicitly rather than
// filed under a fence that excludes them.

/// Derives admitted per principal per rolling 24 h (brief V1 §4, V4 §H′.2(1)).
/// The admission bound is over `len(committed) + len(reservations)`.
pub const DERIVE_QUOTA: u32 = 5;

/// The rolling derive window, in nanoseconds (24 h).
pub const DERIVE_WINDOW_NS: u64 = 86_400_000_000_000;

/// Bootstrap ticket lifetime, in nanoseconds (10 min — brief V2 §B).
pub const BOOTSTRAP_TICKET_TTL_NS: u64 = 600_000_000_000;

/// `register_device` calls admitted per principal per rolling 24 h, successful
/// or not (brief V2 §E).
pub const REGISTRATION_QUOTA: u32 = 5;

/// The rolling registration window, in nanoseconds (24 h). Same magnitude as
/// `DERIVE_WINDOW_NS` but a SEPARATE constant: they are separate pins in the
/// brief and either may move without the other.
pub const REGISTRATION_WINDOW_NS: u64 = 86_400_000_000_000;

/// `replace_envelope` calls admitted per principal per rolling 24 h (D-1b v3
/// §2). Its OWN counter, not the registration one: replacing an envelope is a
/// different operation with a different failure mode, and sharing a window
/// would let a passcode toggle consume a user's ability to add a device.
pub const REPLACE_QUOTA: u32 = 5;

/// The rolling replacement window, in nanoseconds (24 h).
pub const REPLACE_WINDOW_NS: u64 = 86_400_000_000_000;

/// `revoke_device` calls admitted per principal per rolling 24 h, successful
/// or not (Opus-round fix brief V2, RED-2). Its OWN counter: revocation was
/// the only update endpoint with no meter, and sharing the registration or
/// replacement window would let revocations consume an unrelated allowance.
pub const REVOKE_QUOTA: u32 = 5;

/// The rolling revocation window, in nanoseconds (24 h). Same magnitude as the
/// registration and replacement windows but a SEPARATE constant — separate
/// pins, either may move without the others.
pub const REVOKE_WINDOW_NS: u64 = 86_400_000_000_000;

/// Maximum expired consumed-nonce rows reclaimed per admission (Opus-round fix
/// brief V2, RED-1 — pinned `K`). A backlog larger than this drains over
/// repeated calls, never in one: the cap is what bounds the attacker-path cost
/// of reclamation at `O(K log N)` per call.
pub const NONCE_PRUNE_MAX: usize = 16;

/// Maximum `Active` devices per principal (brief V1 §2, V2 §E).
pub const MAX_ACTIVE_DEVICES: usize = 10;

/// How long a `PreDispatch` reservation may sit before admission prunes it
/// (5 min — brief V4 §H′.1). Pruning it is safe ONLY because a call that
/// resumes past the prune must revalidate its id in that phase and abort
/// (§H′.2(2)); the TTL is never applied to a `Dispatched` reservation.
pub const STALE_PREDISPATCH_TTL_NS: u64 = 300_000_000_000;

/// Age at which a `Dispatched` reservation is CHARGED (converted to a committed
/// timestamp at its own `created_at`) rather than freed — brief V4 §H′.3(c).
/// Pinned to the quota window itself, deliberately: conversion at the window
/// edge is capacity-neutral at the moment it happens.
pub const STALE_DISPATCHED_CHARGE_NS: u64 = 86_400_000_000_000;

/// §D first-derive eligibility floor, in e8s: the token balance a principal
/// must hold before its FIRST-EVER derive (brief V2 §D — "balance ≥ shield-fee
/// floor").
///
/// BOUND TO A REPO CONSTANT, NOT INVENTED. The brief names a floor without a
/// number; the only canonical "shield fee floor" in this tree is
/// `stsh_fee_policy::FLAT_MINIMUM_FEE_FLOOR_E8S` — 0.1 STSH, RULED by
/// JONNI_RULING_FEE_MODEL_CONSOLIDATED_2026-08-21. It is MIRRORED here rather
/// than imported: `canisters/vetkeys` is a workspace-EXCLUDED crate (ic-cdk
/// 0.20 vs the workspace's 0.16) and taking a path dependency on a workspace
/// member is a dependency addition this lane is not authorized to make.
///
/// A mirrored constant is a drift risk, so it is DRIFT-LOCKED: the test below
/// reads the fee-policy source at compile time and re-derives this number from
/// it. If the ruled floor moves and this does not, the vetkeys leg goes RED.
pub const ELIGIBILITY_MIN_BALANCE_E8S: u128 = 10_000_000;

/// C-26 remedy R1 (brief V3 §3) — the cycle floor below which
/// `get_encrypted_vetkey` refuses BEFORE any management-cycle spend.
///
/// The refusal predicate is `liquid < live_cost + FLOOR`, over
/// `canister_liquid_cycle_balance()` (already net of the freezing reserve) and
/// the live `cost_vetkd_derive_key` price — never a cached value (§2.2).
///
/// Derivation: ≥ the measured minimum install cost 301,691,759,530
/// (tests/crossdevice_acceptance.rs, e9b measurement table), so a drained
/// canister can still take the upgrade that remedies it, + measurement jitter,
/// + ~198.3e9 Layer-1 headroom ≈ 7.6 derive-equivalents at 26e9. Trade,
/// stated: 5.0 % of a 10T balance is reserved and never spendable on derives.
///
/// GUARDED: `get_encrypted_vetkey` only — the sole management-cycle spender.
/// ALIVE BELOW THE FLOOR: every Layer-1 endpoint, every query, and
/// `get_vetkey_verification_key` (§5) — which attaches ZERO cycles to its
/// management call, though the awaited round trip itself is still paid for out
/// of this canister's execution budget on a cache miss (R-5, L04-02).
pub const DERIVE_CYCLE_FLOOR_CYCLES: u128 = 500_000_000_000;

/// C-26 remedy R2 — fleet-wide derive dispatches admitted per rolling hour.
///
/// **PIN: 100/h**, ratified by the Owner 2026-09-24 ("Sound good") in
/// RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24.md (sha256
/// 249f551b8417b8d372e08a3263594c5c0620dd5f044a16ea043ec83abec417) —
/// LAUNCH-HARDEN-04 O-3. That record SUPERSEDES the 20/h launch on-ramp of
/// RATIFICATION_GLOBAL_DERIVE_BUDGET_20_LAUNCH_ONRAMP_2026-09-01.md (sha256
/// addd59af78c5805ef2f941a2aa89eb46fcfc502764f6fd0b14eb95e10c2a8b93). Charged
/// ONLY at actual dispatch, inside the fence's commit phase (§2.4). The
/// per-principal half of the same ratification is
/// `PER_PRINCIPAL_HOURLY_DERIVE_CAP` below.
///
/// Max burn per window: 100 × 26e9 = 2.6e12 cycles/h (~$83.6/day worst case,
/// ~$2,508 per 30 days, at the same $/cycle rate as the prior figure); a
/// max-rate attack takes ~3.65 h (13,153 s) from a 10 T balance to reach the
/// floor, inside which the A-6 monitor samples ~43 times. The prior Erlang-B
/// occupancy sentence was derived for B = 20 and is to be re-derived for
/// B = 100 (packet debt (iii), LAUNCH-HARDEN-04).
///
/// **THIS IS ADMISSION, NOT STORAGE.** It may move by ratification without any
/// layout change, because the stable window is sized by
/// `GLOBAL_DERIVE_WINDOW_MAX_ENTRIES` instead. At 100 it EQUALS that storage
/// bound, so any further raise is a layout migration, not a re-pin.
pub const GLOBAL_DERIVE_BUDGET: u32 = 100;

/// LAUNCH-HARDEN-04 O-3 — derive DISPATCHES admitted per principal per rolling
/// `GLOBAL_DERIVE_WINDOW_NS` (1 h), counting ALL derives (first-derive or not;
/// CTO Addendum V-2 confirmed). Owner-ratified 2026-09-24 in
/// RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24.md (sha256 249f551b…ec417).
///
/// Rationale: an enrolled device uses Layer-1 and never derives; a new device or
/// a recovery is exactly one derive. With the fleet budget at 100/h, holding
/// the whole fleet budget for an hour needs ≥ 50 derive-capable principals.
/// Enforced as limb (d) of `fence::fence_decide`, from the tagged entries of
/// the same stable window (untagged legacy entries never count).
pub const PER_PRINCIPAL_HOURLY_DERIVE_CAP: u32 = 2;

/// STORAGE bound for the fleet-wide derive window — the number of timestamps a
/// stored cell may hold. **NEVER SHRINKS.**
///
/// WHY THIS IS A SEPARATE CONSTANT FROM THE BUDGET, AND WHY IT IS THE POINT OF
/// THIS LANE. Before the split, the stable cell's byte bound and its decode
/// assertion were both derived from `GLOBAL_DERIVE_BUDGET`, so LOWERING the
/// budget made every cell holding more than the new budget undecodable — a trap
/// inside `post_upgrade`, with no way back, on the very upgrade that tightens
/// the ceiling. A cell written at 100/h holds up to 100 entries; an upgrade to
/// 20/h would have met one and trapped.
///
/// Decoupling them means admission can move by ruling while the layout stays
/// put. Shrinking THIS constant re-creates exactly the same trap, so it is
/// pinned at the widest value any shipped release has used and is only ever
/// raised — above 100 is a migration of its own, not a re-pin.
pub const GLOBAL_DERIVE_WINDOW_MAX_ENTRIES: usize = 100;

/// The global derive window, in nanoseconds (1 rolling hour). A SEPARATE
/// constant from `METER_WINDOW_NS` (same magnitude, different pin — either may
/// move without the other, the `pins.rs` rule the admission windows follow).
pub const GLOBAL_DERIVE_WINDOW_NS: u64 = 3_600_000_000_000;

/// Maximum accepted `device_id` length, in UTF-8 bytes. Not a brief pin — a
/// storage-bound the brief's "storage-exhaustion guard on a caller-writable
/// surface" (V1 §2) requires a number for. Disclosed as a builder choice in the
/// commit-1 freeze note.
pub const MAX_DEVICE_ID_BYTES: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
// HELD-BALANCE-AGE ADMISSION (A1 fix brief V5 §6, §7.2) — FOURTH CLASS
// ─────────────────────────────────────────────────────────────────────────────
//
// A FOURTH class of pin, named explicitly rather than filed under one of the
// three above. These are neither Layer-2 admission pins, nor A-2 metering
// constants, nor canister-availability bounds: they govern WHEN a principal's
// first derive becomes admissible, and how the evidence for that decision is
// stored and reclaimed.
//
// THE RULED TRUE CLAIM, WHICH THESE NUMBERS DO NOT EXCEED (V5 §6.4, SSA
// GREEN-1, D-1). Under two-point sampling with a hard-coded ZERO ledger fee
// (canisters/token/src/lib.rs), ONE 0.1 STSH float satisfies arbitrarily many
// principals: it visits P₁…P_n at t and again at t + T, and all of them age in.
// The gate therefore delivers PRE-FUNDING VISIBILITY (the sightings land T
// before the derive wave — a leading indicator), COLD-START BURST DAMPING
// (a freshly minted principal cannot derive for T), and RE-TOOLING LATENCY
// (every new principal set costs T before it produces). It is NOT a capital
// requirement, NOT a sunk cost, and NOT a float-multiplication defence.
// `GLOBAL_DERIVE_BUDGET` remains the wall. Nothing here may be described as
// pricing the attack.

/// How long a proven ≥ `ELIGIBILITY_MIN_BALANCE_E8S` balance must have been
/// OBSERVED by this canister before a principal's FIRST derive is admitted
/// (T = 2 min — RULING_RECORD_VETKEYS_ELIGIBILITY_AGE_2MIN_FROM_LOGIN
/// 2026-09-22, sha256 559b411e…, which supersedes the T = 15 min VALUE ONLY of
/// RULING_RECORD_HELD_BALANCE_AGE_D1_PROCEED_D2_COPY_15MIN 2026-09-01, sha256
/// 6b60d432…; D-1 "proceed" and the balance floor are unchanged).
///
/// OBSERVED, not READ: the ledger has no history query, so age is not a fact
/// this canister can ask for — it is one it accumulates. The first proven
/// balance writes a sighting and REFUSES; a later call at or past T admits.
pub const ELIGIBILITY_MIN_AGE_NS: u64 = 120_000_000_000;

/// How long a sighting row survives without being used (7 days).
///
/// WHY THE ROW EXISTS: so a user who funds and walks away is not silently
/// restarted. Seven days covers a full week — fund on a Friday, return the next
/// Friday, still aged in. It is 5040 × T, unambiguously generous.
///
/// THE TRADE, STATED: longer retention lets an attacker pre-age a pool for
/// longer. But the pool is bounded by `MAX_SIGHTINGS` regardless, so retention
/// governs HONEST-USER CHURN, not attacker capacity — which is why the generous
/// value is the right one here and the cap is where the bound lives.
pub const SIGHTING_RETENTION_NS: u64 = 604_800_000_000_000;

/// Hard ceiling on live rows in `ELIGIBILITY_SIGHTINGS` (MemoryId 15).
///
/// At the ratified 100/h budget (2,400/day) the table no longer covers
/// multi-day admission; a full table EVICTS the oldest unconverted row
/// (LAUNCH-HARDEN-04 O-2, RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24). The
/// value itself (10,000) is unchanged and Owner-ratified; it bounds stable
/// growth at ≈760 KB across both maps (30 + 8 primary, 38 index ≈ 76 B/row).
///
/// THE CAP APPLIES ONLY TO A NEW INSERTION (V5 §6.2, SSA GREEN-2). A caller
/// that already holds a row needs no slot, so a full table still admits it; a
/// caller that needs a slot at a full table evicts the OLDEST row (lowest
/// expiry) and is inserted — the cap no longer refuses.
pub const MAX_SIGHTINGS: usize = 10_000;

/// Maximum sighting rows EXAMINED per admission during the bounded prune
/// (K — V5 §6.5). Examined, not merely removed: the bound is over the walk.
///
/// Same magnitude as `NONCE_PRUNE_MAX` deliberately and for the same reason —
/// it bounds attacker-path reclamation cost at `O(K log N)` — but it is a
/// SEPARATE pin and either may move alone. A backlog larger than K drains
/// across successive calls, never in one.
pub const SIGHTING_PRUNE_MAX: usize = 16;

/// LAUNCH-HARDEN-04 O-8 — the delay before an II-ONLY
/// `request_device_approval_policy_clear` takes effect (24 h). It applies to the
/// II-only clear path ONLY: a device-signed `set_device_approval_policy(false)`
/// clears immediately (CTO Addendum 2 V-3b).
pub const DEVICE_APPROVAL_CLEAR_DELAY_NS: u64 = 86_400_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    /// §E mutation-RED — derive quota. Regenerated at point of use: five.
    #[test]
    fn derive_quota_is_pinned_at_five() {
        assert_eq!(DERIVE_QUOTA, 5, "brief V1 §4 pins the derive quota at 5 per rolling 24 h");
    }

    /// §E mutation-RED — the rolling window is 24 h, written as its unit
    /// arithmetic so the expectation cannot be silently re-derived from the
    /// constant under test.
    #[test]
    fn derive_window_is_pinned_at_twenty_four_hours() {
        let twenty_four_hours_ns: u64 = 24 * 60 * 60 * 1_000_000_000;
        assert_eq!(DERIVE_WINDOW_NS, twenty_four_hours_ns);
    }

    /// §B/§E mutation-RED — bootstrap ticket expiry, 10 min.
    #[test]
    fn bootstrap_ticket_ttl_is_pinned_at_ten_minutes() {
        let ten_minutes_ns: u64 = 10 * 60 * 1_000_000_000;
        assert_eq!(BOOTSTRAP_TICKET_TTL_NS, ten_minutes_ns);
    }

    /// §E mutation-RED — registration rate limit, 5 per rolling 24 h.
    #[test]
    fn registration_rate_is_pinned_at_five_per_twenty_four_hours() {
        let twenty_four_hours_ns: u64 = 24 * 60 * 60 * 1_000_000_000;
        assert_eq!(REGISTRATION_QUOTA, 5);
        assert_eq!(REGISTRATION_WINDOW_NS, twenty_four_hours_ns);
    }

    /// RED-2 mutation-RED — revocation rate limit, 5 per rolling 24 h.
    #[test]
    fn revocation_rate_is_pinned_at_five_per_twenty_four_hours() {
        let twenty_four_hours_ns: u64 = 24 * 60 * 60 * 1_000_000_000;
        assert_eq!(REVOKE_QUOTA, 5);
        assert_eq!(REVOKE_WINDOW_NS, twenty_four_hours_ns);
    }

    /// §E mutation-RED — device cap.
    #[test]
    fn active_device_cap_is_pinned_at_ten() {
        assert_eq!(MAX_ACTIVE_DEVICES, 10);
    }

    /// RED-1 mutation-RED — the per-admission nonce-reclamation cap `K`.
    #[test]
    fn nonce_prune_cap_is_pinned_at_sixteen() {
        assert_eq!(NONCE_PRUNE_MAX, 16);
    }

    /// D-1b v3 §2 mutation-RED — envelope replacement rate.
    #[test]
    fn replacement_rate_is_pinned_at_five_per_twenty_four_hours() {
        let twenty_four_hours_ns: u64 = 24 * 60 * 60 * 1_000_000_000;
        assert_eq!(REPLACE_QUOTA, 5);
        assert_eq!(REPLACE_WINDOW_NS, twenty_four_hours_ns);
    }

    /// §H′ mutation-RED — stale pre-dispatch TTL, 5 min.
    #[test]
    fn stale_predispatch_ttl_is_pinned_at_five_minutes() {
        let five_minutes_ns: u64 = 5 * 60 * 1_000_000_000;
        assert_eq!(STALE_PREDISPATCH_TTL_NS, five_minutes_ns);
    }

    /// §H′.3(c) — the stale-`Dispatched` CHARGE age is the quota window itself.
    /// Asserted as its own unit arithmetic AND as the §H′.3(c) relation, which
    /// is the load-bearing half: a charge age shorter than the window would
    /// convert a live callback's reservation while it still bears capacity.
    #[test]
    fn stale_dispatched_charge_age_is_the_quota_window() {
        let twenty_four_hours_ns: u64 = 24 * 60 * 60 * 1_000_000_000;
        assert_eq!(STALE_DISPATCHED_CHARGE_NS, twenty_four_hours_ns);
        assert!(
            STALE_DISPATCHED_CHARGE_NS >= DERIVE_WINDOW_NS,
            "V4 §H′.3(c): a Dispatched reservation may only be charge-converted at or beyond \
             the quota window, so the conversion is capacity-neutral when it happens"
        );
        assert!(
            STALE_DISPATCHED_CHARGE_NS > STALE_PREDISPATCH_TTL_NS,
            "the two phases must never share a deadline — the whole point of the phase tag"
        );
    }

    /// Builder-chosen bound, pinned so it cannot drift unnoticed.
    #[test]
    fn device_id_bound_is_pinned() {
        assert_eq!(MAX_DEVICE_ID_BYTES, 64);
    }

    /// §D floor — pinned as its own arithmetic: 0.1 STSH at 8 decimals.
    #[test]
    fn eligibility_floor_is_a_tenth_of_one_stsh() {
        let e8s_per_stsh: u128 = 100_000_000;
        assert_eq!(ELIGIBILITY_MIN_BALANCE_E8S, e8s_per_stsh / 10);
    }

    // ── C-26 remedy — canister-availability pins (brief V3 §7.3) ─────────────

    /// R1 mutation-RED — the cycle floor, as its own unit arithmetic (500 G),
    /// never as a read-back of the constant under test.
    #[test]
    fn cycle_floor_is_pinned_at_five_hundred_billion() {
        let five_hundred_billion: u128 = 500 * 1_000_000_000;
        assert_eq!(DERIVE_CYCLE_FLOOR_CYCLES, five_hundred_billion);
    }

    /// R1 relation arm — the floor strictly exceeds the measured minimum
    /// install cost, written as its OWN literal (the e9b measurement,
    /// tests/crossdevice_acceptance.rs measurement table: 298.2e9 fails,
    /// 301.2e9 installs, measured minimum 301,691,759,530 at the branch-final
    /// W-VETKEYS Wasm). A floor at or below that number could refuse the very
    /// upgrade that remedies a drain.
    #[test]
    fn cycle_floor_strictly_exceeds_the_measured_install_cost() {
        // Re-measured for the LAUNCH-HARDEN-04 Wasm (larger module): 301_918_725_530
        // (PocketIC install deficit method; tests/crossdevice_acceptance.rs
        // MEASURED_MIN_INSTALL_CYCLES). Still far below the floor.
        let measured_install_cost: u128 = 301_918_725_530;
        assert!(
            DERIVE_CYCLE_FLOOR_CYCLES > measured_install_cost,
            "the floor must leave room for the remedial upgrade itself \
             (crossdevice_acceptance.rs e9b measurement: {measured_install_cost})"
        );
    }

    /// R2 mutation-RED — the ratified fleet-wide budget.
    /// (RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24.md, sha256
    /// 249f551b8417b8d372e08a3263594c5c0620dd5f044a16ea043ec83abec417 —
    /// supersedes RATIFICATION_GLOBAL_DERIVE_BUDGET_20_LAUNCH_ONRAMP_2026-09-01.md,
    /// sha256 addd59af78c5805ef2f941a2aa89eb46fcfc502764f6fd0b14eb95e10c2a8b93.)
    #[test]
    fn global_derive_budget_is_pinned_at_one_hundred() {
        assert_eq!(
            GLOBAL_DERIVE_BUDGET, 100,
            "Owner 2026-09-24: \"Sound good\" (RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24)"
        );
    }

    /// LAUNCH-HARDEN-04 O-3 mutation-RED — the per-principal hourly derive cap
    /// (RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24.md, sha256 249f551b…ec417).
    #[test]
    fn per_principal_hourly_derive_cap_is_pinned_at_two() {
        assert_eq!(PER_PRINCIPAL_HOURLY_DERIVE_CAP, 2);
    }

    /// O-3 relation arms — the per-principal hourly cap is no looser than the
    /// §H′ daily quota, and strictly below the fleet budget (one principal can
    /// never hold the whole fleet hour).
    #[test]
    fn per_principal_cap_relations() {
        assert!(PER_PRINCIPAL_HOURLY_DERIVE_CAP <= DERIVE_QUOTA);
        assert!(PER_PRINCIPAL_HOURLY_DERIVE_CAP < GLOBAL_DERIVE_BUDGET);
    }

    /// O-3 sybil arithmetic — holding the full fleet budget for an hour needs at
    /// least 100 / 2 = 50 derive-capable principals. Literals written out; the
    /// constants are checked against them.
    #[test]
    fn a_sybil_set_needs_fifty_principals_per_hour() {
        let budget: u32 = 100;
        let cap: u32 = 2;
        assert_eq!(GLOBAL_DERIVE_BUDGET, budget);
        assert_eq!(PER_PRINCIPAL_HOURLY_DERIVE_CAP, cap);
        assert_eq!(budget.div_ceil(cap), 50);
    }

    /// THE SPLIT, asserted as a RELATION: admission may never exceed storage.
    ///
    /// This is the arm that keeps the §3 trap closed. A future re-pin that
    /// raised the budget past the stored layout would produce cells the encode
    /// assertion refuses to write; one that shrank the storage constant would
    /// re-create the original decode trap. Either way this fails first.
    #[test]
    fn admission_never_exceeds_the_storage_bound() {
        assert!(
            GLOBAL_DERIVE_BUDGET as usize <= GLOBAL_DERIVE_WINDOW_MAX_ENTRIES,
            "the budget ({GLOBAL_DERIVE_BUDGET}) must fit the stored window \
             ({GLOBAL_DERIVE_WINDOW_MAX_ENTRIES})"
        );
    }

    /// The storage constant is pinned at the widest value any shipped release
    /// has used. Lowering it is what the whole lane exists to prevent, so the
    /// number is asserted directly rather than derived from anything.
    #[test]
    fn storage_window_entries_is_pinned_at_one_hundred() {
        assert_eq!(
            GLOBAL_DERIVE_WINDOW_MAX_ENTRIES, 100,
            "shrinking this re-creates the post_upgrade decode trap this lane closes"
        );
    }

    /// R2 economic arm — with the per-derive cost (26e9), the reference balance
    /// (10e12) and the monitor cadence (300 s) written out as literals, a
    /// max-rate attack must take ≥ 3 h to reach the floor and be sampled ≥ 36
    /// times by the A-6 monitor on the way down.
    #[test]
    fn global_budget_bounds_a_max_rate_attack_to_hours_not_minutes() {
        let per_derive_cost: u128 = 26_000_000_000;
        let reference_balance: u128 = 10_000_000_000_000;
        let spendable = reference_balance - DERIVE_CYCLE_FLOOR_CYCLES;
        let burn_per_hour = GLOBAL_DERIVE_BUDGET as u128 * per_derive_cost;
        // Time to floor, in seconds (integer arithmetic, floor division —
        // conservative in the attacker's favour).
        let time_to_floor_secs = spendable * 3_600 / burn_per_hour;
        assert!(
            time_to_floor_secs >= 3 * 3_600,
            "a max-rate attack reaches the floor in {time_to_floor_secs}s — under 3 h"
        );
        let monitor_cadence_secs: u128 = 300;
        assert!(
            time_to_floor_secs / monitor_cadence_secs >= 36,
            "fewer than 36 monitor samples inside the attack window"
        );
    }

    /// R2 relation arm — the fleet budget must exceed the per-principal quota,
    /// or one principal's allowance could not even fit inside the fleet's.
    #[test]
    fn global_budget_exceeds_the_per_principal_quota() {
        assert!(GLOBAL_DERIVE_BUDGET > DERIVE_QUOTA);
    }

    /// R2 mutation-RED — the global window is 1 h, as unit arithmetic.
    #[test]
    fn global_derive_window_is_pinned_at_one_hour() {
        let one_hour_ns: u64 = 60 * 60 * 1_000_000_000;
        assert_eq!(GLOBAL_DERIVE_WINDOW_NS, one_hour_ns);
    }

    /// DRIFT LOCK — the mirrored floor is re-derived from the fee-policy
    /// SOURCE, not from this crate's own constant.
    ///
    /// `include_str!` reads the file at compile time, so this needs no
    /// dependency on the fee-policy crate and no runtime I/O. The test parses
    /// the two declarations it depends on and fails loudly if either the value
    /// or the DECLARATION SHAPE changes — a shape change means the parse is no
    /// longer checking what it claims to check, which is the way a drift lock
    /// silently stops biting.
    #[test]
    fn eligibility_floor_tracks_the_ruled_fee_policy_floor() {
        const FEE_POLICY_SRC: &str = include_str!("../../fee-policy/src/lib.rs");

        let e8s_line = FEE_POLICY_SRC
            .lines()
            .find(|l| l.trim_start().starts_with("pub const E8S_PER_STSH"))
            .expect(
                "fee-policy no longer declares E8S_PER_STSH — this drift lock cannot verify                  the mirrored §D floor and must be repaired, not deleted",
            );
        let e8s_per_stsh: u128 = e8s_line
            .rsplit('=')
            .next()
            .and_then(|v| v.trim().trim_end_matches(';').replace('_', "").parse().ok())
            .expect("E8S_PER_STSH is no longer a plain integer literal");

        let floor_line = FEE_POLICY_SRC
            .lines()
            .find(|l| l.trim_start().starts_with("pub const FLAT_MINIMUM_FEE_FLOOR_E8S"))
            .expect(
                "fee-policy no longer declares FLAT_MINIMUM_FEE_FLOOR_E8S — repair this drift                  lock rather than removing it",
            );
        assert!(
            floor_line.contains("E8S_PER_STSH / 10"),
            "the ruled shield-fee floor is no longer `E8S_PER_STSH / 10` ({floor_line:?}). The              §D eligibility floor mirrors it and must be re-derived by hand, with a ruling."
        );

        assert_eq!(
            ELIGIBILITY_MIN_BALANCE_E8S,
            e8s_per_stsh / 10,
            "the §D eligibility floor has drifted from the ruled fee-policy floor"
        );
    }

    // ── Held-balance-age admission pins (V5 §6, §7.2) ───────────────────────
    //
    // Rule 2 throughout: each expectation is REGENERATED from unit arithmetic
    // at the point of use, so moving a constant moves the test to RED instead
    // of moving the expectation with it.

    /// V5 §6.1 mutation-RED — T is 2 minutes, as its own unit arithmetic.
    ///
    /// Ruled 2026-09-22 (559b411e…, superseding the 15-minute value of
    /// 6b60d432…). Deliberately NOT written as a reference to any other pin:
    /// binding independent pins here would make them move together.
    #[test]
    fn eligibility_min_age_is_pinned_at_two_minutes() {
        let two_minutes_ns: u64 = 2 * 60 * 1_000_000_000;
        assert_eq!(
            ELIGIBILITY_MIN_AGE_NS, two_minutes_ns,
            "559b411e… pins T at 2 minutes; the wallet's preparation copy reports the \
             canister's returned wait, never a fixed duration"
        );
    }

    /// V5 §6.5 mutation-RED — sighting retention is 7 days, as unit arithmetic.
    #[test]
    fn sighting_retention_is_pinned_at_seven_days() {
        let seven_days_ns: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;
        assert_eq!(
            SIGHTING_RETENTION_NS, seven_days_ns,
            "the row exists so a user who funds and walks away is not silently restarted; \
             a full week covers fund-on-Friday, return-next-Friday"
        );
    }

    /// V5 §7.2 relation arm — retention must OUTLIVE the age it protects.
    ///
    /// The load-bearing half. A retention shorter than T would expire every row
    /// before it could ever admit, turning the gate into a permanent refusal
    /// for every honest first-derive.
    #[test]
    fn retention_strictly_outlives_the_age_it_protects() {
        assert!(
            SIGHTING_RETENTION_NS > ELIGIBILITY_MIN_AGE_NS,
            "a sighting must survive long enough to become admissible"
        );
        // The generosity claim the brief states, checked rather than asserted
        // in prose: 5040 written out, not derived from either constant.
        let stated_multiple: u64 = 5040;
        assert_eq!(
            SIGHTING_RETENTION_NS / ELIGIBILITY_MIN_AGE_NS,
            stated_multiple,
            "V5 §6.5 states retention is 5040 × T; if either pin moves alone this claim \
             must be re-derived, not quietly rescaled"
        );
    }

    /// V5 §6.5 mutation-RED — the live-row ceiling.
    #[test]
    fn max_sightings_is_pinned_at_ten_thousand() {
        assert_eq!(MAX_SIGHTINGS, 10_000);
    }

    /// LAUNCH-HARDEN-04 O-2 — the eviction-starvation rate. With a full table
    /// EVICTING its oldest row (not refusing), an attacker can only keep an
    /// honest pending sighting from maturing by pushing ≥ MAX_SIGHTINGS newer
    /// insertions through inside one age-in period T: ≥ 10,000 / 120 s ≥ 50
    /// inserts per second (≈ 83/s exactly). Replaces the B = 20
    /// "twenty days of admission capacity" arm, which the ratified B = 100
    /// retired (RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24).
    #[test]
    fn eviction_starvation_rate_is_at_least_fifty_inserts_per_second() {
        let max_sightings: u64 = 10_000;
        let ns_per_s: u64 = 1_000_000_000;
        let t_ns: u64 = 120_000_000_000;
        assert_eq!(MAX_SIGHTINGS as u64, max_sightings);
        assert_eq!(ELIGIBILITY_MIN_AGE_NS, t_ns);
        assert!(max_sightings * ns_per_s / t_ns >= 50);
    }

    /// LAUNCH-HARDEN-04 O-8 mutation-RED — the II-only clear delay is 24 h.
    #[test]
    fn device_approval_clear_delay_is_pinned_at_twenty_four_hours() {
        let twenty_four_hours_ns: u64 = 24 * 60 * 60 * 1_000_000_000;
        assert_eq!(DEVICE_APPROVAL_CLEAR_DELAY_NS, twenty_four_hours_ns);
    }

    /// V5 §6.5 mutation-RED — the per-admission examination cap `K`.
    ///
    /// Asserted as its OWN literal, deliberately not as `NONCE_PRUNE_MAX`: the
    /// two share a magnitude for the same reason but are separate pins, and
    /// either may move alone.
    #[test]
    fn sighting_prune_cap_is_pinned_at_sixteen() {
        assert_eq!(SIGHTING_PRUNE_MAX, 16);
    }

    /// V5 §7.2 relation arm — the prune cap can never exceed the table it
    /// walks, or the "bounded work per admission" claim would be vacuous.
    #[test]
    fn prune_cap_never_exceeds_the_table_it_walks() {
        assert!(SIGHTING_PRUNE_MAX <= MAX_SIGHTINGS);
    }

}
