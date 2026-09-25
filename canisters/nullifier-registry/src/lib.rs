// =============================================================================
// STSH Nullifier Registry Canister
// Build plan: M2 — Shielded Pool Testnet
// =============================================================================
//
// Stores nullifiers for all spent notes. Prevents double-spend.
//
// Design choices:
//   - Separate canister from shielded pool for clean scaling boundary.
//   - Nullifiers are NEVER removed — only inserted.
//   - insert_nullifier is atomic: duplicate → error, no partial state.
//   - BTreeMap<[u8;32], u64>: nullifier hash → insertion timestamp (ns).
//   - Sharding plan: prefix-shard by first byte if registry >4GB (deferred).
//   - Certified queries via IC certified data API (TODO: enable in M2).
//
// Access control:
//   - Only the shielded_pool canister may call insert_nullifier.
//   - contains_nullifier is a public query (anyone can read).
// =============================================================================

use ic_cdk::api::time;
use ic_cdk_macros::{init, post_upgrade, query, update};
use stsh_field_utils::is_canonical_fr_le;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    Cell, DefaultMemoryImpl, StableBTreeMap, Storable,
};
use std::borrow::Cow;
use std::cell::RefCell;
use candid::Principal;
use stsh_eager_cell::PrincipalRefs;

// ── Storage ───────────────────────────────────────────────────────────────────

const MEM_NULLIFIERS:   MemoryId = MemoryId::new(0);

// ── RETIRED MemoryId — NEVER RECYCLE ─────────────────────────────────────────
//
// MemoryId 1 held the pre-hardening `STABLE_STATE` checkpoint cell (Candid-
// encoded `NullifierStableState`, written by `pre_upgrade`). Retired by the
// upgrade-persistence hardening campaign, Phase 1 (BRIEF_UPGRADE_PERSISTENCE_
// HARDENING_V2). It is deliberately NOT allocated below and MUST NEVER be
// reused: recycling it would silently reinterpret the old Candid checkpoint
// bytes as whatever new type took the ID. Frozen forever — see the retire list
// in `docs/MEMORY_ID_REGISTRY.md` (canonical, in-repo, enforced by the blocking
// `verify_memory_ids` gate check).
//
// const MEM_STABLE_STATE: MemoryId = MemoryId::new(1);   // RETIRED — do not restore

/// Eager cell holding the pool-canister reference (replaces the MemoryId 1
/// checkpoint). Written through on every mutation; survives upgrade with no
/// `pre_upgrade` hook.
const MEM_POOL_REF: MemoryId = MemoryId::new(2);

type Mem = VirtualMemory<DefaultMemoryImpl>;

// ── Eager canister-ref cell ──────────────────────────────────────────────────
//
// `PrincipalRefs<1>` from the shared `stsh-eager-cell` crate: fixed raw-byte
// layout (CTO rule — never Candid on an eager cell) with an all-0xFF sentinel
// that no initialised state can encode to. The sentinel contract is proved
// once, in that crate's test suite, rather than re-proved per canister.
type PoolRefCell = PrincipalRefs<1>;

/// 32-byte nullifier key
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct NullifierKey([u8; 32]);

impl Storable for NullifierKey {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(self.0.to_vec()) }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        NullifierKey(arr)
    }
    const BOUND: Bound = Bound::Bounded { max_size: 32, is_fixed_size: true };
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// nullifier → insertion_timestamp_ns
    static NULLIFIERS: RefCell<StableBTreeMap<NullifierKey, u64, Mem>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_NULLIFIERS))
        )
    );

    /// Only this principal may insert nullifiers
    static POOL_CANISTER: RefCell<Option<Principal>> = RefCell::new(None);

    /// EAGER durable source of truth for POOL_CANISTER. Written through by
    /// `init`; read back by `post_upgrade`. Defaults to the impossible
    /// sentinel on a fresh region so an absent cell fails closed.
    static POOL_REF: RefCell<Cell<PoolRefCell, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_POOL_REF)),
            PoolRefCell::sentinel(),
        ).expect("POOL_REF: Cell::init failed — stable memory corrupt")
    );
}

// ── Durable ref write-through ────────────────────────────────────────────────
//
// ATOMICITY (V2 acceptance #2): the stable write happens FIRST and the heap
// mirror is updated only after it succeeds. A failed stable write therefore
// leaves heap and stable state consistent (both still holding the prior value)
// rather than a heap that has moved ahead of durable state. There is no
// `await` in this path — the whole write-through is one atomic message
// segment, so no interleaving is possible.
fn set_pool_canister(pool_canister: Principal) {
    POOL_REF.with(|c| {
        c.borrow_mut()
            .set(PoolRefCell::new([pool_canister]))
            .expect("set_pool_canister: stable cell write failed");
    });
    POOL_CANISTER.with(|p| *p.borrow_mut() = Some(pool_canister));
}

// ── Init ──────────────────────────────────────────────────────────────────────

#[init]
fn init(pool_canister: Principal) {
    set_pool_canister(pool_canister);
}

// ── Access control helper ─────────────────────────────────────────────────────

fn assert_pool_canister() {
    let caller = ic_cdk::caller();
    let pool = POOL_CANISTER.with(|p| p.borrow().unwrap());
    assert_eq!(caller, pool, "Only shielded pool canister may insert nullifiers");
}

/// DEF-074: IC canister-controller check. Deliberately NOT named `assert_controller()`
/// — this canister has no app-level stored-CONTROLLER model (unlike shielded-pool),
/// and reusing that name would conflate two different authority models. This gates
/// only the timing-revealing `spent_at` read to the canister's IC controllers.
fn assert_ic_controller() {
    if !ic_cdk::api::is_controller(&ic_cdk::caller()) {
        ic_cdk::trap("caller is not an IC controller");
    }
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Check if a nullifier has already been spent.
/// Public query — any canister or user may call this.
#[query]
fn contains_nullifier(nullifier: Vec<u8>) -> bool {
    let Ok(key) = to_nullifier_key(&nullifier) else { return false; };
    NULLIFIERS.with(|n| n.borrow().contains_key(&key))
}

/// Insert a nullifier. Only callable by the shielded pool canister.
/// Returns Err if the nullifier was already inserted (double-spend attempt).
#[update]
fn insert_nullifier(nullifier: Vec<u8>) -> Result<(), String> {
    assert_pool_canister();
    let key = to_nullifier_key(&nullifier)?;

    NULLIFIERS.with(|n| {
        let mut map = n.borrow_mut();
        if map.contains_key(&key) {
            return Err("NullifierAlreadySpent".to_string());
        }
        map.insert(key, time());
        Ok(())
    })
}

/// Batch insert nullifiers.  Only callable by the shielded pool canister.
///
/// All-or-nothing semantics:
///   1. Every nullifier in the batch is checked for freshness.
///   2. If ANY nullifier is already spent → return Err("NullifierAlreadySpent:<hex>"),
///      insert NOTHING.
///   3. If all are fresh → insert all with the current timestamp.
///
/// Also rejects batches that contain the same nullifier more than once (internal duplicate).
#[update]
fn insert_batch(nullifiers: Vec<Vec<u8>>) -> Result<(), String> {
    assert_pool_canister();
    insert_batch_impl(nullifiers, time())
}

/// DEF-088: endpoint core, extracted so unit tests can exercise the batch
/// semantics natively (assert_pool_canister and time() both trap outside a
/// canister runtime). Behaviour is identical to the pre-extraction endpoint.
fn insert_batch_impl(nullifiers: Vec<Vec<u8>>, now: u64) -> Result<(), String> {
    // Build keys — validate length and canonicality as we go
    let mut keys: Vec<NullifierKey> = Vec::with_capacity(nullifiers.len());
    for nf in &nullifiers {
        let key = to_nullifier_key(nf)?;
        keys.push(key);
    }

    NULLIFIERS.with(|n| {
        let mut map = n.borrow_mut();

        // Phase 1: check all nullifiers are fresh (registry + intra-batch uniqueness)
        let mut seen: std::collections::BTreeSet<NullifierKey> = std::collections::BTreeSet::new();
        for key in &keys {
            // Registry check
            if map.contains_key(key) {
                return Err(format!("NullifierAlreadySpent:{}", hex::encode(&key.0)));
            }
            // Intra-batch duplicate check
            if !seen.insert(key.clone()) {
                return Err(format!("NullifierAlreadySpent:{}", hex::encode(&key.0)));
            }
        }

        // Phase 2: insert all
        for key in keys {
            map.insert(key, now);
        }
        Ok(())
    })
}

/// Batch containment check (useful for wallet pre-flight validation)
#[query]
fn contains_nullifiers_batch(nullifiers: Vec<Vec<u8>>) -> Vec<bool> {
    nullifiers.iter().map(|nf| {
        let Ok(key) = to_nullifier_key(nf) else { return false; };
        NULLIFIERS.with(|n| n.borrow().contains_key(&key))
    }).collect()
}

/// Total nullifiers stored (pool size proxy)
#[query]
fn count() -> u64 {
    NULLIFIERS.with(|n| n.borrow().len())
}

/// P-NUL (L0-F): page cap for get_nullifiers_page — rejects rather than
/// truncates, so a wallet can never silently receive a partial view (S-20).
const MAX_NULLIFIERS_PAGE_SIZE: u64 = 500;

/// P-NUL (L0-F): exact full-set pagination of the spent-nullifier set.
///
/// - Stable LEXICOGRAPHIC order over the raw 32-byte values (the underlying
///   StableBTreeMap iterates in key order; NullifierKey's Ord is bytewise).
/// - EXCLUSIVE cursor: `start_after` is not re-returned; a cursor not present
///   in the set starts the page at the next greater key.
/// - CANONICAL 32-byte cursor enforced: any other length, or 32 bytes that are
///   not a canonical BN254 Fr little-endian value (the same validation inserts
///   get), is rejected — cursor injection fails closed.
/// - NONZERO CAPPED limit: 0 and > MAX_NULLIFIERS_PAGE_SIZE are rejected
///   (never silently truncated). The page is naturally short at the tail.
/// - No Bloom filter, no digest: the wallet downloads the exact set and
///   enforces count-before/after + strict ordering locally (S-20).
#[query]
fn get_nullifiers_page(
    start_after: Option<Vec<u8>>,
    limit: u64,
) -> Result<Vec<Vec<u8>>, String> {
    get_nullifiers_page_impl(start_after, limit)
}

/// Endpoint core, extracted so unit tests can exercise the pagination
/// semantics natively (mirrors the insert_batch/insert_batch_impl pattern).
fn get_nullifiers_page_impl(
    start_after: Option<Vec<u8>>,
    limit: u64,
) -> Result<Vec<Vec<u8>>, String> {
    if limit == 0 {
        return Err("InvalidLimit: limit must be nonzero".to_string());
    }
    if limit > MAX_NULLIFIERS_PAGE_SIZE {
        return Err(format!(
            "PageTooLarge: requested limit {} exceeds MAX_NULLIFIERS_PAGE_SIZE {}",
            limit, MAX_NULLIFIERS_PAGE_SIZE
        ));
    }
    let start = match &start_after {
        Some(bytes) => Some(to_nullifier_key(bytes)?),
        None => None,
    };
    NULLIFIERS.with(|n| {
        let map = n.borrow();
        let page: Vec<Vec<u8>> = match &start {
            Some(key) => map
                .range((
                    std::ops::Bound::Excluded(key.clone()),
                    std::ops::Bound::Unbounded,
                ))
                .take(limit as usize)
                .map(|(k, _)| k.0.to_vec())
                .collect(),
            None => map
                .iter()
                .take(limit as usize)
                .map(|(k, _)| k.0.to_vec())
                .collect(),
        };
        Ok(page)
    })
}

/// Lookup insertion timestamp for an already-spent nullifier
#[query]
fn spent_at(nullifier: Vec<u8>) -> Option<u64> {
    // DEF-074: spent_at exposes nullifier timing metadata. Until nullifier-registry
    // receives an app-level controller model, this endpoint is restricted to IC canister
    // controllers only. contains_nullifier remains public.
    assert_ic_controller();
    spent_at_impl(&nullifier)
}

/// Custody Vault (interface freeze V6 §6): mutation-free UPDATE twin of
/// `spent_at`, for the Vault's `NullifierReadSpentAt` read-model variant.
/// Identical gate (`assert_ic_controller`) and identical read semantics; the
/// update mode exists because a query's single-node response is not
/// consensus-verified evidence for a custody read model. Never mutates the
/// registry.
#[update]
fn spent_at_for_controller_update(nullifier: Vec<u8>) -> Option<u64> {
    assert_ic_controller();
    spent_at_impl(&nullifier)
}

/// Endpoint core shared by `spent_at` (query) and
/// `spent_at_for_controller_update` (update). Read-only: never mutates the
/// registry or any cell. Extracted so unit tests can exercise the read
/// semantics natively (assert_ic_controller and time() both trap outside a
/// canister runtime — the insert_batch/insert_batch_impl pattern).
fn spent_at_impl(nullifier: &[u8]) -> Option<u64> {
    let Ok(key) = to_nullifier_key(nullifier) else { return None; };
    NULLIFIERS.with(|n| n.borrow().get(&key))
}

// ── Canonical authority read-back (Custody Vault, freeze V6 §6) ──────────────

/// Canonical read-back of the durable authority principal this canister holds:
/// the shielded-pool peer (`POOL_CANISTER`, the only principal this canister
/// stores).
///
/// PUBLIC by ruling (freeze V6 §6): the value is public post-launch and the
/// endpoint's purpose is externally verifiable proof that the born-under-vault
/// wiring is real. Reads the DURABLE eager cell (`POOL_REF`, MemoryId 2) —
/// never a heap mirror — and FAILS CLOSED on sentinel / uninitialised /
/// corrupt state: it never substitutes a launch default and takes no argument,
/// so it can never echo a caller's expectation.
#[query]
fn get_authority_refs() -> Principal {
    let stored = POOL_REF.with(|c| *c.borrow().get());
    read_pool_ref_fail_closed(stored)
}

/// The canister's own cycle balance — the interface CONTRACT lane A-6's fleet
/// monitor consumes (GAP-U9-1). Additive query; no state read, no caller check
/// (the value is not sensitive and the monitor may be unauthenticated).
///
/// API: ic-cdk 0.16 — `canister_balance128()` returns u128 -> Candid `nat`.
/// (vetkeys' `canister_cycle_balance()` is 0.20-only; see brief A-6b §1.)
#[query]
fn cycle_balance() -> u128 {
    ic_cdk::api::canister_balance128()
}

/// Fail-closed decode of the durable pool-ref cell, shared by
/// `get_authority_refs` and `restore_pool_canister_from_stable`. A surviving
/// sentinel means the region was absent, unwritten, or corrupt — trap rather
/// than fabricate an authority principal out of a default or partial bytes.
fn read_pool_ref_fail_closed(stored: PoolRefCell) -> Principal {
    let Some([pool_canister]) = stored.get().copied() else {
        ic_cdk::trap(
            "POOL_REF sentinel survived — no initialised pool-canister reference \
             found in stable memory (MemoryId 2 absent, unwritten, or corrupt). \
             Failing closed: an authority principal is never synthesized from a \
             default or a caller expectation.",
        );
    };
    pool_canister
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn to_nullifier_key(bytes: &[u8]) -> Result<NullifierKey, String> {
    if bytes.len() != 32 {
        return Err(format!("InvalidNullifier: expected 32 bytes, got {}", bytes.len()));
    }
    let arr: [u8; 32] = bytes.try_into().unwrap();
    // #116 defense-in-depth: the pool already rejects non-canonical nullifiers before
    // calling the registry, but we enforce it here as well so the registry never stores
    // a non-canonical key regardless of which caller path is taken.
    if !is_canonical_fr_le(&arr) {
        return Err("NonCanonicalNullifier: bytes >= BN254 Fr modulus".to_string());
    }
    Ok(NullifierKey(arr))
}

// ── Upgrade hooks ─────────────────────────────────────────────────────────────
//
// ── MIGRATION LOG ─────────────────────────────────────────────────────────────
//
// STATE_VERSION 1  (M3 Track C — 2026-06-08)  — SUPERSEDED, see below
//   Initial stable-persist via a `pre_upgrade` → `STABLE_STATE_CELL` checkpoint
//   (Candid `NullifierStableState`, MemoryId 1).
//
// EAGER CONVERSION (upgrade-persistence hardening Phase 1 — 2026-07-28)
//   The checkpoint hook is GONE. `pool_canister` is now written through to its
//   own eager stable cell (`POOL_REF`, MemoryId 2) at the moment it is set, so
//   there is no upgrade-time work to do and no instruction ceiling to hit.
//   MemoryId 1 is RETIRED and permanently frozen (see the retirement note at
//   the top of this file).
//
//   Survive upgrade automatically (StableBTreeMap, no serialisation needed):
//     NULLIFIERS (MemoryId 0) — permanent spent-nullifier set
//
//   FAILURE MODEL (corrected per V2): there is no longer a `pre_upgrade` that
//   can trap, so the "upgrade aborts, old Wasm keeps running" mode is gone for
//   this canister. `post_upgrade` CAN still trap — and unlike `pre_upgrade`
//   that DOES block forward progress — which is why the sentinel must cleanly
//   distinguish "fresh install" from "absent/corrupt state". It does: the
//   sentinel is unrepresentable as valid state (see `PoolRefCell`).
//
//   Upgrade from any pre-conversion Wasm: NOT SUPPORTED, and fails CLOSED.
//   A pre-conversion canister never allocated MemoryId 2, so the region is
//   fresh, the sentinel survives `Cell::init`, and `post_upgrade` traps. This
//   is intended: nothing is on mainnet yet, so there is no legacy state to
//   migrate, and a silent reset of POOL_CANISTER to None would be far worse.
//   DEF-095 still applies: reinstall WIPES stable memory including the
//   NULLIFIERS spent-set; losing it re-admits every spent nullifier — a
//   catastrophic double-spend window. Reinstall is safe ONLY for a genuinely
//   fresh deployment that has never stored a nullifier.

// ── ATOMICITY: no post-init mutation path exists for this cell ───────────────
//
// V2 acceptance #2 asks for "a rejected operation persists no partial scalar".
// For this canister that case is VACUOUS, and this note exists so that is
// recorded explicitly rather than left implied (Architect, 2026-07-28).
//
// PROOF OBLIGATION: `set_pool_canister` is the ONLY writer of the eager cell, and its
// only caller is `#[init]`. There is no update endpoint, no governance path,
// and no recovery path that mutates it. The cell is therefore set-once: there
// is no operation that can be rejected midway, hence no partial scalar to
// persist and no counter a retry could double-apply.
//
// If a future change adds ANY post-init writer to this cell, that vacuity ends
// and a real rejected-op atomicity test becomes mandatory — as it already is
// for Phase 2 (treasury `fee_log_index` / `next_proposal_id`, staking
// `next_position_id`), where live mutation paths do exist and the case must be
// tested, not waved.

#[post_upgrade]
fn post_upgrade() {
    restore_pool_canister_from_stable();
}

/// Re-populate the `POOL_CANISTER` heap mirror from the durable eager cell
/// after an upgrade. Fail-closed sentinel gate: `Cell::init` (in the POOL_REF
/// thread_local) has already run by the time this borrow resolves — on
/// retained state it decoded the stored principal; on an ABSENT region it
/// stored the impossible sentinel. A surviving sentinel therefore proves the
/// cell was never written by an `init`, and `read_pool_ref_fail_closed` traps
/// rather than letting the canister run with POOL_CANISTER reset to None,
/// which would panic every insert_nullifier call.
///
/// Validation runs BEFORE the sentinel could become observable: the heap
/// mirror is only populated on the validated path. `get_authority_refs` reads
/// the durable cell directly (never the mirror) through the same fail-closed
/// decode.
fn restore_pool_canister_from_stable() {
    let stored = POOL_REF.with(|c| *c.borrow().get());
    let pool_canister = read_pool_ref_fail_closed(stored);
    POOL_CANISTER.with(|p| *p.borrow_mut() = Some(pool_canister));
}

// =============================================================================
// DEF-088 — insert_batch unit tests
// =============================================================================
//
// These exercise insert_batch_impl (the endpoint core) natively. NULLIFIERS is
// a thread_local over DefaultMemoryImpl, which is heap-backed outside wasm, so
// the real StableBTreeMap code paths run. Under `--test-threads=1` all tests
// share one thread (and therefore one NULLIFIERS instance), so every test uses
// nullifier values from its own disjoint range — no test asserts on global
// registry size.

#[cfg(test)]
mod tests {
    use super::*;

    /// 32-byte little-endian nullifier from a (range, n) pair. Small LE values
    /// are trivially canonical (< BN254 Fr modulus). `range` keeps each test's
    /// values disjoint from every other test's.
    fn nf(range: u8, n: u8) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        b[0] = n;
        b[1] = range;
        b
    }

    fn contains(nullifier: &[u8]) -> bool {
        let key = to_nullifier_key(nullifier).expect("test nullifier must be canonical");
        NULLIFIERS.with(|n| n.borrow().contains_key(&key))
    }

    #[test]
    fn test_insert_batch_single() {
        let a = nf(1, 1);
        assert!(!contains(&a), "fresh nullifier must not be pre-spent");

        insert_batch_impl(vec![a.clone()], 1_000).expect("first insert must succeed");
        assert!(contains(&a), "inserted nullifier must be marked spent");

        // Second insert of the same nullifier → dedup error, still spent.
        let err = insert_batch_impl(vec![a.clone()], 2_000)
            .expect_err("re-insert of a spent nullifier must fail");
        assert!(
            err.starts_with("NullifierAlreadySpent:"),
            "dedup error must be NullifierAlreadySpent:<hex>, got: {err}"
        );
        assert!(contains(&a), "nullifier must remain spent after rejected re-insert");
    }

    #[test]
    fn test_insert_batch_multi() {
        let batch: Vec<Vec<u8>> = (1..=5).map(|n| nf(2, n)).collect();

        insert_batch_impl(batch.clone(), 1_000).expect("multi-insert must succeed");
        for nullifier in &batch {
            assert!(contains(nullifier), "every batch member must be marked spent");
        }

        // Re-inserting ONE member from the committed batch (inside a new batch
        // with an otherwise-fresh value) must fail atomically: the fresh value
        // must NOT be committed.
        let fresh = nf(2, 6);
        let err = insert_batch_impl(vec![fresh.clone(), batch[2].clone()], 2_000)
            .expect_err("batch containing a spent nullifier must fail");
        assert!(err.starts_with("NullifierAlreadySpent:"), "got: {err}");
        assert!(
            !contains(&fresh),
            "all-or-nothing violated: fresh member of a rejected batch was committed"
        );
    }

    #[test]
    fn test_insert_batch_duplicate_within_batch() {
        // Documented contract (see insert_batch doc comment): a batch containing
        // the same nullifier twice is rejected atomically — NOTHING commits,
        // including the non-duplicated members.
        let a = nf(3, 1);
        let b = nf(3, 2);

        let err = insert_batch_impl(vec![a.clone(), b.clone(), a.clone()], 1_000)
            .expect_err("intra-batch duplicate must be rejected");
        assert!(err.starts_with("NullifierAlreadySpent:"), "got: {err}");

        assert!(!contains(&a), "no partial commit: duplicated member must not be spent");
        assert!(!contains(&b), "no partial commit: unique member must not be spent");

        // The same values remain insertable once the batch is well-formed.
        insert_batch_impl(vec![a.clone(), b.clone()], 2_000)
            .expect("well-formed retry after rejected duplicate batch must succeed");
        assert!(contains(&a) && contains(&b));
    }

    // ── P-NUL (L0-F) — get_nullifiers_page unit tests ─────────────────────────
    //
    // Same thread-local discipline as the DEF-088 tests above: disjoint value
    // ranges per test. Walk tests assert GLOBAL strict ordering (the whole map
    // is lexicographic) plus presence/uniqueness of the test's own values.

    /// Walk the whole registry in `limit`-sized pages; returns every entry in
    /// page order. Asserts the page mechanics on every hop: exclusive cursor
    /// (page head strictly greater than the cursor that produced it) and a
    /// naturally short/empty final page.
    fn walk_all(limit: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            let page = get_nullifiers_page_impl(cursor.clone(), limit)
                .expect("page walk must not error");
            if let (Some(prev), Some(head)) = (&cursor, page.first()) {
                assert!(
                    head > prev,
                    "exclusive cursor: page head {:02x?} must be > cursor {:02x?}",
                    &head[..2],
                    &prev[..2]
                );
            }
            let done = (page.len() as u64) < limit;
            out.extend(page);
            if done {
                break;
            }
            cursor = out.last().cloned();
        }
        out
    }

    fn assert_strictly_increasing_and_unique(walk: &[Vec<u8>]) {
        for w in walk.windows(2) {
            assert!(w[1] > w[0], "walk must be strictly increasing: {:02x?} then {:02x?}", &w[0][..2], &w[1][..2]);
        }
        let mut dedup = walk.to_vec();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), walk.len(), "walk must contain no duplicates");
    }

    #[test]
    fn test_pagination_limit_validation() {
        assert_eq!(
            get_nullifiers_page_impl(None, 0),
            Err("InvalidLimit: limit must be nonzero".to_string()),
            "limit 0 must be rejected"
        );
        let too_big = get_nullifiers_page_impl(None, MAX_NULLIFIERS_PAGE_SIZE + 1)
            .expect_err("limit above the cap must be rejected");
        assert!(too_big.starts_with("PageTooLarge:"), "got: {too_big}");
        // The cap itself is accepted (registry contents irrelevant here).
        assert!(get_nullifiers_page_impl(None, MAX_NULLIFIERS_PAGE_SIZE).is_ok());
    }

    #[test]
    fn test_pagination_cursor_validation() {
        // Wrong lengths rejected.
        for len in [0usize, 1, 31, 33, 64] {
            let err = get_nullifiers_page_impl(Some(vec![0xAAu8; len]), 10)
                .expect_err(&format!("cursor of length {len} must be rejected"));
            assert!(
                err.starts_with("InvalidNullifier: expected 32 bytes"),
                "len {len}: got: {err}"
            );
        }
        // 32 bytes but not a canonical BN254 Fr value (all-0xFF >= modulus).
        let err = get_nullifiers_page_impl(Some(vec![0xFFu8; 32]), 10)
            .expect_err("non-canonical 32-byte cursor must be rejected");
        assert_eq!(err, "NonCanonicalNullifier: bytes >= BN254 Fr modulus".to_string());
    }

    #[test]
    fn test_pagination_order_completeness_exclusivity() {
        // Insert OUT of lexicographic order within this test's disjoint range.
        let mine: Vec<Vec<u8>> = [9u8, 3, 7, 1, 5].map(|n| nf(4, n)).to_vec();
        insert_batch_impl(mine.clone(), 1_000).expect("seed inserts must succeed");

        // Walk the WHOLE registry (includes other tests' values) in tiny pages.
        let walk = walk_all(2);
        assert_strictly_increasing_and_unique(&walk);

        // Every value this test inserted appears exactly once, in order.
        let mut mine_sorted = mine.clone();
        mine_sorted.sort();
        let found: Vec<Vec<u8>> = walk
            .iter()
            .filter(|v| v.get(1) == Some(&4u8))
            .cloned()
            .collect();
        assert_eq!(found, mine_sorted, "walk must cover this test's values lexicographically");

        // The walk covers the entire registry — nothing missed.
        let total = NULLIFIERS.with(|n| n.borrow().len());
        assert_eq!(walk.len() as u64, total, "walk length must equal registry size");
    }

    #[test]
    fn test_pagination_exclusive_and_unset_cursor() {
        let a = nf(5, 1);
        let b = nf(5, 3);
        let c = nf(5, 5);
        insert_batch_impl(vec![a.clone(), b.clone(), c.clone()], 1_000).expect("seed inserts");

        // Cursor == a present key: that key is NOT re-returned (exclusive).
        let page = get_nullifiers_page_impl(Some(b.clone()), 10).expect("page after b");
        assert!(
            !page.contains(&b),
            "exclusive range: the cursor itself must not be re-returned"
        );
        assert_eq!(page.first(), Some(&c), "the next greater key starts the page");

        // Cursor NOT in the set (between b and c): page starts at the next
        // greater key — a valid cursor skips the prefix by design, but never
        // causes repeats or a wrong start in a disciplined walk.
        let unset = nf(5, 4);
        let page2 = get_nullifiers_page_impl(Some(unset), 10).expect("page after unset cursor");
        assert_eq!(page2.first(), Some(&c), "unset cursor resolves to the next greater key");

        // Cursor at/past the tail: empty page (clean walk termination).
        let tail = get_nullifiers_page_impl(Some(c.clone()), 10).expect("page after tail");
        assert!(tail.iter().all(|v| *v > c), "only greater keys after the tail cursor");
    }
}

// =============================================================================
// Upgrade-persistence hardening Phase 1 — sentinel construction contract
// =============================================================================
//
// These prove the SENTINEL half of the contract natively (encoding-level).
// The cross-Wasm halves — absent cell traps, retained state passes unchanged —
// live in integration-tests/tests/upgrade_tests.rs, because a same-Wasm test
// cannot establish them.

#[cfg(test)]
mod sentinel_contract_tests {
    use super::*;

    fn principal(n: u8) -> Principal {
        let mut b = [0u8; 29];
        b[0] = n;
        Principal::from_slice(&b)
    }

    /// ATOMICITY (V2 acceptance #2): the write-through is single-valued and has
    /// no `await`, so a caller can never observe a half-applied ref. Re-running
    /// it is idempotent — a retry cannot double-apply.
    #[test]
    fn write_through_is_idempotent_and_single_valued() {
        let p = principal(7);
        set_pool_canister(p);
        let after_first = POOL_REF.with(|c| c.borrow().get().clone());
        set_pool_canister(p);
        let after_retry = POOL_REF.with(|c| c.borrow().get().clone());
        assert_eq!(after_first, after_retry, "retry must not change durable state");
        assert_eq!(
            POOL_CANISTER.with(|c| *c.borrow()),
            Some(p),
            "heap mirror agrees with the durable cell"
        );
    }
}

// =============================================================================
// L3d — Custody Vault target-side endpoints (freeze V6 §6)
// =============================================================================
//
// Native tests for the two additive endpoints:
//   - spent_at_for_controller_update (update twin of spent_at), and
//   - get_authority_refs (canonical POOL_CANISTER read-back).
//
// The CONTROLLER GATE itself (`assert_ic_controller` → ic_cdk caller /
// is_controller) cannot execute outside a canister runtime, so the controller
// positive and every non-controller negative case run cross-Wasm under
// PocketIC in the integration suite (same split as DEF-074's spent_at gate,
// exercised in integration-tests/tests/query_surface_tests.rs). What CAN be
// proved natively is proved here: identical read semantics for both spent_at
// paths, mutation-freedom, fail-closed read-back, and upgrade persistence.
// Same thread-local discipline as the DEF-088 tests (--test-threads=1):
// disjoint nullifier ranges, and every authority-ref test re-establishes the
// cell state it depends on.

#[cfg(test)]
mod l3d_custody_tests {
    use super::*;

    /// Same disjoint-range discipline as the DEF-088 tests: range 6 belongs to
    /// this module's spent_at tests.
    fn nf(range: u8, n: u8) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        b[0] = n;
        b[1] = range;
        b
    }

    fn principal(n: u8) -> Principal {
        let mut b = [0u8; 29];
        b[0] = n;
        Principal::from_slice(&b)
    }

    // ── spent_at_impl: identical semantics for the query and the update twin ──

    #[test]
    fn spent_at_impl_returns_inserted_timestamp_and_none_for_unknown() {
        let a = nf(6, 1);
        let b = nf(6, 2);
        insert_batch_impl(vec![a.clone()], 123_456).expect("seed insert must succeed");

        assert_eq!(spent_at_impl(&a), Some(123_456), "spent nullifier returns its insertion timestamp");
        assert_eq!(spent_at_impl(&b), None, "unspent nullifier returns None");
    }

    #[test]
    fn spent_at_impl_rejects_malformed_input_as_none() {
        // Wrong lengths → None (never a trap, matching the pre-existing query).
        for len in [0usize, 1, 31, 33, 64] {
            assert_eq!(spent_at_impl(&vec![0xAAu8; len]), None, "len {len} must read as None");
        }
        // 32 bytes but non-canonical (all-0xFF >= BN254 Fr modulus) → None.
        assert_eq!(spent_at_impl(&vec![0xFFu8; 32]), None, "non-canonical nullifier must read as None");
    }

    #[test]
    fn spent_at_impl_is_mutation_free() {
        let a = nf(6, 9);
        insert_batch_impl(vec![a.clone()], 777).expect("seed insert must succeed");
        let before_len = NULLIFIERS.with(|n| n.borrow().len());
        let cell_before = POOL_REF.with(|c| c.borrow().get().to_bytes().into_owned());

        // Exercise every read path: hit, miss, malformed.
        assert_eq!(spent_at_impl(&a), Some(777));
        assert_eq!(spent_at_impl(&nf(6, 10)), None);
        assert_eq!(spent_at_impl(&[0u8; 3]), None);

        let after_len = NULLIFIERS.with(|n| n.borrow().len());
        let cell_after = POOL_REF.with(|c| c.borrow().get().to_bytes().into_owned());
        assert_eq!(before_len, after_len, "read must not change registry size");
        assert_eq!(spent_at_impl(&a), Some(777), "read must not alter the stored timestamp");
        assert_eq!(cell_before, cell_after, "read must not touch the authority cell");
    }

    // ── get_authority_refs: canonical, fail-closed, never a default ──────────

    #[test]
    fn get_authority_refs_returns_the_durable_stored_value() {
        let p = principal(0xD3);
        set_pool_canister(p);
        assert_eq!(get_authority_refs(), p, "read-back returns the canonical stored principal");

        // It reads the DURABLE cell, not the heap mirror: with the mirror
        // cleared (the post-upgrade heap state), the read-back still returns
        // the stored value.
        POOL_CANISTER.with(|m| *m.borrow_mut() = None);
        assert_eq!(get_authority_refs(), p, "read-back is served from the durable cell, not the mirror");
        // Restore the mirror so later tests on this shared thread see a
        // consistent state.
        POOL_CANISTER.with(|m| *m.borrow_mut() = Some(p));
    }

    #[test]
    fn get_authority_refs_is_mutation_free() {
        let p = principal(0xD4);
        set_pool_canister(p);
        let cell_before = POOL_REF.with(|c| c.borrow().get().to_bytes().into_owned());
        let mirror_before = POOL_CANISTER.with(|m| *m.borrow());

        assert_eq!(get_authority_refs(), p);

        let cell_after = POOL_REF.with(|c| c.borrow().get().to_bytes().into_owned());
        let mirror_after = POOL_CANISTER.with(|m| *m.borrow());
        assert_eq!(cell_before, cell_after, "read-back must not write the durable cell");
        assert_eq!(mirror_before, mirror_after, "read-back must not touch the heap mirror");
    }

    /// Fail-closed on the sentinel: an absent/uninitialised region traps
    /// rather than returning a fabricated principal.
    #[test]
    #[should_panic]
    fn read_pool_ref_fails_closed_on_sentinel() {
        read_pool_ref_fail_closed(PoolRefCell::sentinel());
    }

    /// Fail-closed on corrupt regions: every malformed byte shape decodes to
    /// the sentinel (proved in the eager-cell crate) and the read-back traps.
    #[test]
    fn read_pool_ref_fails_closed_on_corrupt_encodings() {
        let width = stsh_eager_cell::encoded_len(1);
        let corrupt: Vec<Vec<u8>> = vec![
            vec![0u8; width],                    // all-zero (zeroed page)
            vec![0u8; width - 1],                // short
            vec![0u8; width + 1],                // long
            {
                let mut v = vec![0u8; width];
                v[0] = 0x02;                     // wrong layout version
                v
            },
            {
                let mut v = PoolRefCell::new([principal(1)]).to_bytes().into_owned();
                v[1] = 30;                       // impossible principal length (> 29)
                v
            },
        ];
        for (i, bytes) in corrupt.into_iter().enumerate() {
            let decoded = PoolRefCell::from_bytes(std::borrow::Cow::Owned(bytes));
            assert!(decoded.is_sentinel(), "corrupt case {i} must decode as sentinel");
            let result = std::panic::catch_unwind(|| read_pool_ref_fail_closed(decoded));
            assert!(result.is_err(), "corrupt case {i} must fail closed (trap), never return a principal");
        }
    }

    // ── Upgrade persistence: the value survives post_upgrade ─────────────────

    #[test]
    fn pool_canister_survives_post_upgrade_restore() {
        let p = principal(0xD5);
        set_pool_canister(p);

        // Simulate the post-upgrade heap: every thread_local heap mirror is
        // fresh (None); only stable memory retains state.
        POOL_CANISTER.with(|m| *m.borrow_mut() = None);

        // The exact code path post_upgrade runs.
        restore_pool_canister_from_stable();

        assert_eq!(
            POOL_CANISTER.with(|m| *m.borrow()),
            Some(p),
            "heap mirror is restored from the durable cell"
        );
        assert_eq!(
            get_authority_refs(),
            p,
            "read-back returns the same canonical value after the upgrade restore"
        );
    }

    /// A post_upgrade onto stable memory where the cell was never written
    /// fails closed (the pre-hardening / never-initialised case).
    #[test]
    fn restore_fails_closed_when_cell_never_written() {
        // Establish real state first (this shared thread may run this test
        // before any other writer), save it, then overwrite the cell with the
        // sentinel to simulate an absent region.
        let p = principal(0xD6);
        set_pool_canister(p);
        let saved = POOL_REF.with(|c| c.borrow().get().clone());
        assert!(!saved.is_sentinel(), "precondition: real state is present");

        POOL_REF.with(|c| {
            c.borrow_mut().set(PoolRefCell::sentinel()).expect("test sentinel write");
        });
        let result = std::panic::catch_unwind(restore_pool_canister_from_stable);
        assert!(result.is_err(), "restore over an unwritten cell must trap, not run with None");

        // Re-establish real state so later tests on this shared thread are
        // unaffected.
        POOL_REF.with(|c| {
            c.borrow_mut().set(saved).expect("test state restore");
        });
        restore_pool_canister_from_stable();
        assert_eq!(POOL_CANISTER.with(|m| *m.borrow()), Some(p));
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
    POOL_REF.with(|c| c.borrow().get().to_bytes().into_owned())
}
