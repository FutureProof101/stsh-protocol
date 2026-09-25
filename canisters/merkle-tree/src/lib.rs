#![cfg_attr(not(test), forbid(unsafe_code))]
// =============================================================================
// STSH Merkle Tree Canister
// Build plan: M2 — Shielded Pool Testnet
// =============================================================================
//
// Stores note commitments in an incremental Merkle tree (depth 32).
// Supports up to 2^32 ≈ 4B note commitments.
//
// Key design points:
//   - Poseidon hash (ZK-friendly) — fewer constraints than SHA-256 in circuit.
//   - Retains last ROOT_HISTORY_SIZE roots — valid spends can anchor to any.
//   - Archive rollover: when canister approaches 2GB state, snapshot & restart.
//   - get_root_at_height returns IC certified data response (TODO: M2).
//   - Encrypted payloads stored alongside commitments for wallet trial-decrypt.
// =============================================================================

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use candid::{CandidType, Principal};
use stsh_eager_cell::PrincipalRefs;
use ic_cdk_macros::{init, post_upgrade, query, update};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    Cell, DefaultMemoryImpl, StableBTreeMap, Storable,
};
use light_poseidon::{Poseidon, PoseidonHasher};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;
// DEF-041: canonical BN254 Fr little-endian check (shared with nullifier-registry / pool).
use stsh_field_utils::is_canonical_fr_le;

mod poseidon_params;
// ── Constants ─────────────────────────────────────────────────────────────────

const TREE_DEPTH: usize = 32;
/// Number of historical roots retained for proof anchoring
const ROOT_HISTORY_SIZE: usize = 100;

/// DEF-007: maximum number of leaves a depth-32 tree can hold. `encode_node_key`
/// masks the index to 32 bits, so an append at leaf_count == 2^32 would alias slot 0
/// of each level and corrupt roots. Appends past this bound are rejected (typed Err,
/// no trap) BEFORE any `encode_node_key` call.
const MAX_TREE_LEAVES: u64 = 1u64 << TREE_DEPTH; // 2^32
/// DEF-044 L2: maximum commitments per `append_commitments` batch. Pools send at most
/// 2 outputs per spend; 10 is generous without permitting catastrophic single-call
/// ring-buffer over-eviction.
const MAX_BATCH_SIZE: usize = 10;
/// P-MRK (L0-E): maximum number of public scan entries returned by one query.
/// Requests above the cap are rejected rather than silently truncated so a
/// wallet cannot mistake a partial response for the complete requested range.
const MAX_SCAN_PAGE_SIZE: u64 = 500;

// ── Memory IDs ────────────────────────────────────────────────────────────────

const MEM_COMMITMENTS:  MemoryId = MemoryId::new(0);
const MEM_PAYLOADS:     MemoryId = MemoryId::new(1);
const MEM_ROOT_HISTORY: MemoryId = MemoryId::new(2);
const MEM_TREE_NODES:   MemoryId = MemoryId::new(3);
// ── RETIRED MemoryId — NEVER RECYCLE ─────────────────────────────────────────
//
// MemoryId 4 held the pre-hardening `STABLE_STATE` checkpoint cell (Candid
// `MerkleStableState`, written by `pre_upgrade`). Retired by upgrade-persistence
// hardening Phase 1. Deliberately NOT allocated, and MUST NEVER be reused:
// recycling it would silently reinterpret the old checkpoint bytes as whatever
// new type took the ID. Frozen forever — see docs/MEMORY_ID_REGISTRY.md.
//
// const MEM_STABLE_STATE: MemoryId = MemoryId::new(4);   // RETIRED

/// Eager cell holding the pool-canister reference (replaces the MemoryId 4
/// checkpoint). Written through by `init`; no `pre_upgrade` hook.
const MEM_POOL_REF: MemoryId = MemoryId::new(5);

/// `PrincipalRefs<1>` from the shared `stsh-eager-cell` crate — fixed raw-byte
/// layout with an all-0xFF sentinel no initialised state can encode to.
type PoolRefCell = PrincipalRefs<1>;

// ── Upgrade state versioning ──────────────────────────────────────────────────


type Mem = VirtualMemory<DefaultMemoryImpl>;

// ── Storable wrappers ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Hash32([u8; 32]);

impl Storable for Hash32 {
    fn to_bytes(&self) -> Cow<[u8]> { Cow::Owned(self.0.to_vec()) }
    fn from_bytes(b: Cow<[u8]>) -> Self {
        let mut a = [0u8; 32]; a.copy_from_slice(&b); Hash32(a)
    }
    const BOUND: Bound = Bound::Bounded { max_size: 32, is_fixed_size: true };
}

// ── State ─────────────────────────────────────────────────────────────────────

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// leaf_index → commitment hash
    static COMMITMENTS: RefCell<StableBTreeMap<u64, Hash32, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_COMMITMENTS)))
    );

    /// leaf_index → encrypted note payload
    static PAYLOADS: RefCell<StableBTreeMap<u64, Vec<u8>, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_PAYLOADS)))
    );

    /// sequential_index → root hash (ring buffer, mod ROOT_HISTORY_SIZE)
    static ROOT_HISTORY: RefCell<StableBTreeMap<u64, Hash32, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_ROOT_HISTORY)))
    );

    /// tree node storage: (level, index) encoded as u64 → hash
    static TREE_NODES: RefCell<StableBTreeMap<u64, Hash32, Mem>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_TREE_NODES)))
    );

    static LEAF_COUNT: RefCell<u64> = RefCell::new(0);
    static ROOT_INDEX: RefCell<u64> = RefCell::new(0);
    static POOL_CANISTER: RefCell<Option<Principal>> = RefCell::new(None);

    /// EAGER durable source of truth for POOL_CANISTER. Written through by
    /// `init`; read back by `post_upgrade`. Sentinel default on a fresh region
    /// so an absent cell fails closed.
    static POOL_REF: RefCell<Cell<PoolRefCell, Mem>> = RefCell::new(
        Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEM_POOL_REF)),
            PoolRefCell::sentinel(),
        ).expect("POOL_REF: Cell::init failed — stable memory corrupt")
    );
}

/// Precomputed Poseidon zero values for all 33 Merkle levels (depth 0–32).
///
/// Computed once on first thread access (33 Poseidon hash calls).
/// ZERO_VALUES[0]  = Poseidon(Fr::zero(), Fr::zero())  — canonical empty leaf
/// ZERO_VALUES[i]  = Poseidon(ZERO_VALUES[i-1], ZERO_VALUES[i-1])
/// ZERO_VALUES[32] — canonical Poseidon empty-tree root, stored by init()
///
/// All values are BN254/Fr elements encoded as little-endian 32-byte arrays.
/// Field parameters match circuits/spend.circom — see POSEIDON_PARAMS.md.
///
/// SECURITY: [0u8;32] does NOT appear anywhere in this table.
/// After M4, is_valid_anchor([0u8;32]) == false on any correctly migrated canister.
thread_local! {
    static ZERO_VALUES: [[u8; 32]; 33] = compute_zero_values_raw();
}

// ── Stable state snapshot ─────────────────────────────────────────────────────
//
// LEAF_COUNT and ROOT_INDEX are re-derived from stable structures on post_upgrade
// (COMMITMENTS.len() and ROOT_HISTORY.len() are authoritative) rather than being
// stored separately — this avoids a split-brain if the two ever drift.
// POOL_CANISTER cannot be derived and must be explicitly serialised.


// ── Public scan types ─────────────────────────────────────────────────────────

/// Atomic public-sync checkpoint. Both fields are captured by one query message
/// with no await/inter-canister boundary between them.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct ScanHead {
    leaf_count: u64,
    root: Vec<u8>,
}

/// One dense public-sync stream entry. This intentionally contains only the
/// pre-existing DEF-073 public scan data plus its sequential index.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct ScanPageEntry {
    index: u64,
    leaf: Vec<u8>,
    encrypted_payload: Vec<u8>,
}

// ── Init ──────────────────────────────────────────────────────────────────────

#[init]
fn init(pool_canister: Principal) {
    set_pool_canister(pool_canister);
    // Insert initial empty root
    let empty_root = zero_value(TREE_DEPTH);
    store_root(empty_root);
}

// ── Write interface (pool canister only) ──────────────────────────────────────

/// QA-DEF-008 defense-in-depth: storage-layer cap on the persisted encrypted
/// payload, matching the shielded-pool's MAX_ENCRYPTED_PAYLOAD_BYTES. The pool
/// (the sole authorized caller — see assert_pool) already enforces this before
/// calling, so it never fires for legitimate traffic; it bounds this canister's
/// permanent stable memory even if that caller is ever changed or bypassed.
const MAX_ENCRYPTED_PAYLOAD_BYTES: usize = 1024;

/// DEF-007: returns Err("TreeFull: ...") iff appending `batch_len` more leaves would
/// push leaf_count past the 2^32 capacity (i.e. write at an index that
/// `encode_node_key` would alias to 32 bits). Standalone + pure so the capacity
/// boundary is unit-testable without a canister environment. Filling to EXACTLY
/// 2^32 leaves (indices 0..2^32-1, all 32-bit-representable) is allowed.
fn ensure_capacity_for_append(leaf_count: u64, batch_len: u64) -> Result<(), String> {
    match leaf_count.checked_add(batch_len) {
        Some(total) if total <= MAX_TREE_LEAVES => Ok(()),
        _ => Err(format!(
            "TreeFull: appending {} leaf/leaves at leaf_count {} would exceed capacity {}",
            batch_len, leaf_count, MAX_TREE_LEAVES
        )),
    }
}

/// DEF-041 + DEF-044 L1: validate a commitment is exactly 32 bytes AND a canonical
/// BN254 Fr little-endian encoding (value < field modulus). Non-canonical bytes
/// reduce silently via `Fr::from_le_bytes_mod_order`, so the stored bytes and the
/// circuit field element would diverge by a modular alias (commitment identity
/// ambiguity). Returns the 32-byte array on success; typed Err (never a trap).
fn validate_commitment_bytes(commitment: &[u8]) -> Result<[u8; 32], String> {
    if commitment.len() != 32 {
        return Err(format!(
            "InvalidLength: commitment must be 32 bytes, got {}",
            commitment.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(commitment);
    if !is_canonical_fr_le(&arr) {
        return Err(
            "InvalidCommitment: non-canonical BN254 field element (bytes >= field modulus)"
                .to_string(),
        );
    }
    Ok(arr)
}

#[update]
fn append_commitment(commitment: Vec<u8>, encrypted_payload: Vec<u8>) -> Result<u64, String> {
    assert_pool();

    // DEF-044 L1 (wrong-length → typed Err, not trap) + DEF-041 (reject non-canonical
    // field elements) — validated BEFORE any state mutation.
    let arr = validate_commitment_bytes(&commitment)?;

    // QA-DEF-008 defense-in-depth: reject an oversized payload BEFORE any storage
    // write, returning an error rather than persisting it (no restructure).
    if encrypted_payload.len() > MAX_ENCRYPTED_PAYLOAD_BYTES {
        return Err(format!(
            "encrypted_payload {} exceeds MAX_ENCRYPTED_PAYLOAD_BYTES {}",
            encrypted_payload.len(),
            MAX_ENCRYPTED_PAYLOAD_BYTES
        ));
    }

    // DEF-007: capacity guard BEFORE encode_node_key / any tree mutation.
    let leaf_count = LEAF_COUNT.with(|c| *c.borrow());
    ensure_capacity_for_append(leaf_count, 1)?;

    let index = LEAF_COUNT.with(|c| { let i = *c.borrow(); *c.borrow_mut() = i + 1; i });

    let hash = Hash32(arr);
    COMMITMENTS.with(|c| c.borrow_mut().insert(index, hash.clone()));
    PAYLOADS.with(|p| p.borrow_mut().insert(index, encrypted_payload));

    // Update tree path and recompute root
    let new_root = update_tree(index, hash);
    store_root(new_root);

    // Update IC certified data (TODO: M2 — enables certified queries)
    // ic_cdk::api::set_certified_data(&new_root.0);

    Ok(index)
}

/// A2 (QA-DEF-034/036): atomically append a batch of commitments in a SINGLE
/// message. Either ALL are appended (returns their leaf indices, in order) or NONE
/// — a validation error returns Err before any mutation, and a trap mid-loop rolls
/// the whole message back. The shielded-pool uses this to promote a private_spend's
/// output commitments only after the parent nullifier is finalized, so the active
/// tree never holds an un-finalized commitment. Single-message atomicity means the
/// pool's transport-unknown recovery is a clean all-or-nothing determination.
#[update]
fn append_commitments(items: Vec<(Vec<u8>, Vec<u8>)>) -> Result<Vec<u64>, String> {
    assert_pool();

    // DEF-044 L2: cap the batch size. An unbounded batch could over-evict the
    // ROOT_HISTORY ring buffer in a single call (more than ROOT_HISTORY_SIZE roots
    // stored at once) and is far larger than any legitimate spend (≤2 outputs).
    if items.len() > MAX_BATCH_SIZE {
        return Err(format!(
            "BatchTooLarge: {} items exceeds MAX_BATCH_SIZE {}",
            items.len(),
            MAX_BATCH_SIZE
        ));
    }

    // DEF-007: capacity guard for the WHOLE batch BEFORE any mutation, so the batch
    // is rejected atomically rather than aliasing mid-loop.
    let leaf_count = LEAF_COUNT.with(|c| *c.borrow());
    ensure_capacity_for_append(leaf_count, items.len() as u64)?;

    // Validate ALL items BEFORE any state mutation (clean all-or-nothing on bad input).
    // DEF-044 L1 (length) + DEF-041 (canonical field element) per item.
    let mut validated: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(items.len());
    for (commitment, encrypted_payload) in items {
        let arr = validate_commitment_bytes(&commitment)?;
        if encrypted_payload.len() > MAX_ENCRYPTED_PAYLOAD_BYTES {
            return Err(format!(
                "encrypted_payload {} exceeds MAX_ENCRYPTED_PAYLOAD_BYTES {}",
                encrypted_payload.len(),
                MAX_ENCRYPTED_PAYLOAD_BYTES
            ));
        }
        validated.push((arr, encrypted_payload));
    }

    let mut indices = Vec::with_capacity(validated.len());
    for (arr, encrypted_payload) in validated {
        let index = LEAF_COUNT.with(|c| {
            let i = *c.borrow();
            *c.borrow_mut() = i + 1;
            i
        });
        let hash = Hash32(arr);
        COMMITMENTS.with(|c| c.borrow_mut().insert(index, hash.clone()));
        PAYLOADS.with(|p| p.borrow_mut().insert(index, encrypted_payload));
        let new_root = update_tree(index, hash);
        store_root(new_root);
        indices.push(index);
    }
    Ok(indices)
}

// ── Read interface (public queries) ──────────────────────────────────────────

#[query]
fn get_root() -> Vec<u8> {
    current_root().0.to_vec()
}

/// P-MRK (L0-E): return one coherent public-sync checkpoint.
///
/// IC messages run against one canister-state snapshot until they return or
/// await. This synchronous query performs no await and does not compose the
/// result by calling the separately exported get_root / leaf_count endpoints,
/// so an append cannot interleave between the two field reads.
#[query]
fn get_scan_head() -> ScanHead {
    let leaf_count = LEAF_COUNT.with(|c| *c.borrow());
    let root = current_root().0.to_vec();
    ScanHead { leaf_count, root }
}

/// P-MRK (L0-E): fetch a dense page of the public commitment/payload stream.
///
/// The requested upper bound is checked before it is used. At the current tail,
/// the page is naturally shorter than limit; within the snapshotted live range
/// every index must have BOTH a commitment and payload or the entire call fails.
#[query]
fn get_scan_page(from: u64, limit: u64) -> Result<Vec<ScanPageEntry>, String> {
    if limit > MAX_SCAN_PAGE_SIZE {
        return Err(format!(
            "PageTooLarge: requested limit {} exceeds MAX_SCAN_PAGE_SIZE {}",
            limit, MAX_SCAN_PAGE_SIZE
        ));
    }

    let requested_end = from.checked_add(limit).ok_or_else(|| {
        format!(
            "RangeOverflow: from {} + limit {} exceeds u64",
            from, limit
        )
    })?;

    // Snapshot the tail once. The query has no await, so an append cannot
    // interleave while the paired stable-map reads below are in progress.
    let leaf_count = LEAF_COUNT.with(|c| *c.borrow());
    let end = requested_end.min(leaf_count);
    let mut result = Vec::with_capacity((end - from.min(end)) as usize);

    COMMITMENTS.with(|commitments| {
        PAYLOADS.with(|payloads| {
            let commitments = commitments.borrow();
            let payloads = payloads.borrow();
            for index in from..end {
                let leaf = commitments.get(&index).ok_or_else(|| {
                    format!(
                        "ScanInvariantViolation: missing commitment at index {}",
                        index
                    )
                })?;
                let encrypted_payload = payloads.get(&index).ok_or_else(|| {
                    format!(
                        "ScanInvariantViolation: missing encrypted payload at index {}",
                        index
                    )
                })?;
                result.push(ScanPageEntry {
                    index,
                    leaf: leaf.0.to_vec(),
                    encrypted_payload,
                });
            }
            Ok(result)
        })
    })
}

/// DEF-043: return the Merkle root produced AFTER leaf `index` was appended.
///
/// Index semantics (regression-protected by `merkle_hardening_tests.rs`):
///   - `index` is a 0-based LEAF index. `store_root` records the empty-tree root in
///     slot 0 at init, then one root per appended leaf; so the root after leaf
///     `index` is the `(index + 1)`-th root stored → ROOT_HISTORY slot
///     `(index + 1) % ROOT_HISTORY_SIZE`.
///   - `None` if `index >= leaf_count` — that leaf-root was never produced (previously
///     this aliased into the ring buffer and returned a stale/foreign root).
///   - `None` if `index < leaf_count - ROOT_HISTORY_SIZE` — evicted; only the most
///     recent `ROOT_HISTORY_SIZE` leaf-roots are retained.
///   - Otherwise `Some(root)` for that exact leaf index.
#[query]
fn get_root_at_index(index: u64) -> Option<Vec<u8>> {
    let leaf_count = LEAF_COUNT.with(|c| *c.borrow());
    if index >= leaf_count {
        return None; // root for this leaf was never produced
    }
    if index < leaf_count.saturating_sub(ROOT_HISTORY_SIZE as u64) {
        return None; // evicted from the ring buffer
    }
    let slot = (index + 1) % ROOT_HISTORY_SIZE as u64;
    ROOT_HISTORY.with(|r| r.borrow().get(&slot).map(|h| h.0.to_vec()))
}

/// Check if a root hash is in the retained history (valid anchor check).
///
/// Pure ring-buffer lookup — no value is special-cased.
/// A root is valid if and only if it was explicitly stored in ROOT_HISTORY
/// by a prior `store_root()` call (triggered by `init()` or `append_commitment()`).
/// See `zero_value()` for why `[0u8;32]` is accepted on a fresh canister.
#[query]
fn is_valid_anchor(root: Vec<u8>) -> bool {
    if root.len() != 32 { return false; }
    let target = Hash32(root.try_into().unwrap());
    ROOT_HISTORY.with(|r| {
        let map = r.borrow();
        for i in 0..ROOT_HISTORY_SIZE as u64 {
            if let Some(h) = map.get(&i) {
                if h == target { return true; }
            }
        }
        false
    })
}

// PRIVACY POLICY (DEF-073): leaf_count, get_leaf, and get_payloads are intentionally
// public to support client-side wallet scanning. Wallets must scan the full commitment
// tree to discover their own notes without revealing which notes they are looking for.
//
// Commitment hashes (get_leaf) and encrypted payloads (get_payloads) do not reveal
// depositor identity on their own. The identity-binding link (leaf_index -> depositor
// principal) was removed in Phase A by gating get_deposit_status to depositor-or-controller.
//
// This is a conscious privacy tradeoff. Do not remove public access to these endpoints
// without a replacement scanning mechanism.
#[query]
fn leaf_count() -> u64 {
    LEAF_COUNT.with(|c| *c.borrow())
}

/// Fetch the commitment bytes at a specific leaf index, if present.
///
/// Pure read of the COMMITMENTS stable map (leaf_index → commitment hash).
/// Returns the 32-byte commitment as a Vec, or None if no leaf has been
/// appended at that index yet (index >= leaf_count, or never written).
///
/// A2 (QA-DEF-034/036): the shielded-pool uses this for deterministic
/// recovery of an `ActiveAppendUnknown` spend — after a transport-unknown
/// append it compares get_leaf(expected_first_leaf_index) against the staged
/// output commitment bytes to decide whether the append committed, without
/// relying on leaf_count alone (which a concurrent append could have advanced).
#[query]
fn get_leaf(index: u64) -> Option<Vec<u8>> {
    COMMITMENTS.with(|c| c.borrow().get(&index).map(|h| h.0.to_vec()))
}

/// Fetch a page of encrypted payloads for wallet trial-decryption scanning
#[query]
fn get_payloads(from_index: u64, limit: u64) -> Vec<(u64, Vec<u8>)> {
    let limit = limit.min(500); // cap page size
    let mut result = Vec::new();
    PAYLOADS.with(|p| {
        let map = p.borrow();
        for i in from_index..from_index + limit {
            if let Some(payload) = map.get(&i) {
                result.push((i, payload));
            }
        }
    });
    result
}

/// P-MRK test-only fault injector. It deliberately removes one or both members
/// of a stored scan pair so PocketIC can prove get_scan_page fails the whole
/// range rather than silently returning a gap. Absent from production Wasm.
#[cfg(feature = "testing")]
#[update]
fn remove_scan_pair_member_for_test(
    index: u64,
    remove_leaf: bool,
    remove_payload: bool,
) -> Result<(), String> {
    assert_pool();

    if !remove_leaf && !remove_payload {
        return Err("remove_scan_pair_member_for_test: select at least one member".to_string());
    }
    let leaf_count = LEAF_COUNT.with(|c| *c.borrow());
    if index >= leaf_count {
        return Err(format!(
            "remove_scan_pair_member_for_test: index {} outside leaf_count {}",
            index, leaf_count
        ));
    }

    // Validate every requested removal before mutating either stable map.
    if remove_leaf && COMMITMENTS.with(|c| c.borrow().get(&index).is_none()) {
        return Err(format!("commitment at index {} is already missing", index));
    }
    if remove_payload && PAYLOADS.with(|p| p.borrow().get(&index).is_none()) {
        return Err(format!("encrypted payload at index {} is already missing", index));
    }

    if remove_leaf {
        COMMITMENTS.with(|c| {
            c.borrow_mut().remove(&index);
        });
    }
    if remove_payload {
        PAYLOADS.with(|p| {
            p.borrow_mut().remove(&index);
        });
    }
    Ok(())
}

// ── Incremental Merkle tree logic ─────────────────────────────────────────────

/// Update the tree path from leaf at `index` up to the root.
/// Returns the new root.
fn update_tree(leaf_index: u64, leaf_hash: Hash32) -> Hash32 {
    let mut current = leaf_hash;
    let mut index = leaf_index;

    for level in 0..TREE_DEPTH {
        let node_key = encode_node_key(level as u32, index);
        TREE_NODES.with(|t| t.borrow_mut().insert(node_key, current.clone()));

        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        let sibling_key = encode_node_key(level as u32, sibling_index);
        let sibling = TREE_NODES.with(|t| t.borrow().get(&sibling_key).unwrap_or(zero_value(level)));

        current = if index % 2 == 0 {
            poseidon_hash_pair(&current, &sibling)
        } else {
            poseidon_hash_pair(&sibling, &current)
        };
        index /= 2;
    }
    current
}

fn store_root(root: Hash32) {
    let idx = ROOT_INDEX.with(|r| {
        let i = *r.borrow();
        *r.borrow_mut() = i + 1;
        i
    });
    ROOT_HISTORY.with(|r| {
        r.borrow_mut().insert(idx % ROOT_HISTORY_SIZE as u64, root);
    });
}

fn current_root() -> Hash32 {
    let idx = ROOT_INDEX.with(|r| *r.borrow()).saturating_sub(1);
    ROOT_HISTORY.with(|r| {
        r.borrow().get(&(idx % ROOT_HISTORY_SIZE as u64)).unwrap_or(zero_value(TREE_DEPTH))
    })
}

fn encode_node_key(level: u32, index: u64) -> u64 {
    ((level as u64) << 32) | (index & 0xFFFF_FFFF)
}

/// Circomlib-compatible Poseidon(2) hash of two BN254/Fr field elements.
///
/// Parameters match circuits/spend.circom exactly (see POSEIDON_PARAMS.md):
///   - Variant:  circomlib Poseidon (Grassi et al., 2019)
///   - Field:    BN254 scalar field Fr
///   - Arity:    2  (state width t = 3)
///   - Rounds:   RF = 8 full, RP = 57 partial
///   - Encoding: Fr elements as little-endian 32-byte arrays
///
/// Input ordering — left then right — matches the MerkleProof Switcher in
/// spend.circom: inputs[0] = outL (left), inputs[1] = outR (right).
fn poseidon_hash_pair(left: &Hash32, right: &Hash32) -> Hash32 {
    Hash32(poseidon_hash_pair_inner(left.0, right.0))
}

/// Core Poseidon computation on raw byte arrays.
///
/// Both inputs are interpreted as BN254/Fr field elements (little-endian).
/// Returns the Poseidon hash as a 32-byte little-endian Fr element.
/// Panics only on library init failure (impossible with pinned parameters).
fn poseidon_hash_pair_inner(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let left_fr  = Fr::from_le_bytes_mod_order(&left);
    let right_fr = Fr::from_le_bytes_mod_order(&right);
    let mut hasher = Poseidon::<Fr>::new(poseidon_params::fixed_poseidon_t3_params());
    let result = hasher.hash(&[left_fr, right_fr])
        .expect("Poseidon hash computation failed");
    let bytes = result.into_bigint().to_bytes_le();
    debug_assert_eq!(bytes.len(), 32, "BN254/Fr must produce exactly 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Build the 33-entry ZERO_VALUES table.  Called once on first thread access.
///
/// ZERO_VALUES[0]  = Poseidon(Fr::zero(), Fr::zero()) — canonical empty leaf.
/// ZERO_VALUES[i]  = Poseidon(ZERO_VALUES[i-1], ZERO_VALUES[i-1]).
/// ZERO_VALUES[32] — canonical Poseidon empty-tree root (stored by init()).
fn compute_zero_values_raw() -> [[u8; 32]; 33] {
    let mut z = [[0u8; 32]; 33];
    z[0] = poseidon_hash_pair_inner([0u8; 32], [0u8; 32]);
    for i in 1..33 {
        z[i] = poseidon_hash_pair_inner(z[i - 1], z[i - 1]);
    }
    z
}

/// Return the Poseidon zero value for the given Merkle level.
///
/// Delegates to the precomputed ZERO_VALUES thread_local (33 values, depth 0–32).
/// Level 0 = Poseidon(0, 0) (canonical empty leaf, NOT [0u8;32]).
/// Level TREE_DEPTH (32) = canonical empty-tree root, stored in ROOT_HISTORY by init().
///
/// After M4 migration: is_valid_anchor([0u8;32]) == false on every correctly
/// initialised canister.  See the zero-root regression test (test_54).
fn zero_value(level: usize) -> Hash32 {
    Hash32(ZERO_VALUES.with(|z| z[level]))
}

fn assert_pool() {
    let pool = POOL_CANISTER.with(|p| p.borrow().unwrap());
    assert_eq!(ic_cdk::caller(), pool, "Only pool canister may append commitments");
}

// ── Authority read-back (Custody Vault — L3g) ───────────────────────────────

/// Canonical read-back of the stored authority principal(s). This canister
/// holds exactly one durable authority ref: the POOL_CANISTER peer reference
/// (eager cell, MemoryId 5 — the sole writer is `init`; no setter exists and
/// none may be added per the freeze's no-rebind-setter ruling).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct AuthorityRefs {
    pool_canister: Principal,
}

/// PUBLIC canonical read-back query (Custody Vault Interface Freeze v6 §6).
///
/// Returns the value in the durable eager cell — the canonical stored value,
/// NOT the heap mirror and never a launch default or caller-supplied
/// expectation. Ruled PUBLIC: the principal is public post-launch and the
/// purpose is externally verifiable proof that the born-under-vault wiring
/// is real, so there is intentionally NO caller gate on this query.
///
/// Fails closed: a sentinel (uninitialised), absent, or corrupt cell decodes
/// to the sentinel per the eager-cell contract and yields `Err`, never a
/// substituted value. Mutation-free (a query; no state is written). (On a
/// live canister a corrupt cell additionally traps `post_upgrade`'s sentinel
/// gate before any query is ever served — the decode here is the second,
/// independent layer.)
#[query]
fn get_authority_refs() -> Result<AuthorityRefs, String> {
    decode_authority_refs(POOL_REF.with(|c| *c.borrow().get()))
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

/// Sentinel-gated decode shared by the query and unit tests: the eager-cell
/// contract decodes any non-canonical byte layout (corrupt, foreign, short,
/// or absent-region) to the sentinel, and the sentinel maps to `Err`.
fn decode_authority_refs(stored: PoolRefCell) -> Result<AuthorityRefs, String> {
    let Some([pool_canister]) = stored.get().copied() else {
        return Err(
            "UninitializedAuthorityRefs: POOL_REF eager cell (MemoryId 5) holds the \
             sentinel — no initialised pool-canister reference, or the cell is corrupt"
                .to_string(),
        );
    };
    Ok(AuthorityRefs { pool_canister })
}

// ── Upgrade hooks ─────────────────────────────────────────────────────────────
//
// LEAF_COUNT and ROOT_INDEX are re-derived from the StableBTreeMaps in
// post_upgrade rather than being stored in the stable cell.  The maps survive
// the upgrade untouched, so their lengths are the authoritative source of truth.
// Storing heap counters separately would risk split-brain on any future migration
// that inserts or removes entries from the maps.
//
// POOL_CANISTER has no derivable source — it is serialised explicitly.
//
// ── MIGRATION LOG ─────────────────────────────────────────────────────────────
//
// STATE_VERSION 1  (M3 Track C — 2026-06-08)
//   Initial stable-persist.  First version to survive a Wasm upgrade without
//   state loss.
//
//   Serialised into MerkleStableState (stable Cell, MEM_STABLE_STATE = MemoryId 4):
//     Canister refs (1): pool_canister
//
//   Survive upgrade automatically (StableBTreeMap, no serialisation needed):
//     COMMITMENTS  (MemoryId 0) — authoritative leaf source
//     PAYLOADS     (MemoryId 1) — encrypted note payloads for wallet scanning
//     ROOT_HISTORY (MemoryId 2) — historical root ring buffer
//     TREE_NODES   (MemoryId 3) — internal Merkle node cache
//
//   Re-derived in post_upgrade (not serialised):
//     LEAF_COUNT  — COMMITMENTS.len()
//     ROOT_INDEX  — LEAF_COUNT + 1  (one root written by init(), one per append)
//
//   Upgrade from pre-Track-C code: NOT SUPPORTED.  Attempting an upgrade from
//   code with no pre_upgrade checkpoint triggers the bootstrap trap.  Recovery
//   requires reinstall (init) after settling all in-flight operations.
//
// M4 POSEIDON MIGRATION — same STATE_VERSION 1  (2026-06-08)
//   No schema change — no STATE_VERSION bump required.  This Wasm upgrade
//   changes the hash function used for new leaf insertions and the zero values
//   stored in ROOT_HISTORY.  It does NOT alter any Candid-serialised fields.
//
//   Breaking change for ROOT_HISTORY (runtime, not schema):
//     Any root stored before the M4 upgrade was computed using the SHA-256 stub.
//     Those roots are stale — the circuit uses Poseidon and will never produce a
//     matching anchor.  A fresh reinit (or controlled drain-and-restart) is required
//     for production deployment.  The testnet upgrade path is documented in BUILD_PLAN.md.
//
//   ZERO_VALUES thread_local: computed on first access via compute_zero_values_raw().
//   ZERO_VALUES[0]  = Poseidon(Fr::zero(), Fr::zero())  — canonical empty leaf
//   ZERO_VALUES[32] — canonical Poseidon empty-tree root, stored by init()
//   [0u8;32] is NOT in ZERO_VALUES — is_valid_anchor([0u8;32]) returns false
//   on any post-M4 canister.  Verified by integration test test_54.
//
// To add a new version: increment STATE_VERSION, add a migration arm in
// post_upgrade that accepts stored_version == N-1 and upgrades the struct,
// then bump STATE_VERSION to N.  Never rely on field defaults for missing values.

// ── Durable ref write-through ────────────────────────────────────────────────
//
// ATOMICITY (V2 acceptance #2): the stable write lands FIRST; the heap mirror
// is updated only after it succeeds, so a failed write leaves heap and stable
// state consistent rather than the heap running ahead of durable state. No
// `await` in this path — the whole write-through is one atomic message segment.
fn set_pool_canister(pool_canister: Principal) {
    POOL_REF.with(|c| {
        c.borrow_mut()
            .set(PoolRefCell::new([pool_canister]))
            .expect("set_pool_canister: stable cell write failed");
    });
    POOL_CANISTER.with(|p| *p.borrow_mut() = Some(pool_canister));
}

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
    // Fail-closed sentinel gate. `Cell::init` has already run: on retained
    // state it decoded the stored principal; on an ABSENT region it stored the
    // impossible sentinel. A surviving sentinel proves the cell was never
    // written by an `init` — abort rather than run with POOL_CANISTER reset to
    // None. Validation runs BEFORE the sentinel could become observable: the
    // heap mirror is populated only on the validated path.
    let restored = POOL_REF.with(|c| *c.borrow().get());

    let Some([pool_canister]) = restored.get().copied() else {
        ic_cdk::trap(
            "post_upgrade: POOL_REF sentinel survived — no initialised pool-canister \
             reference in stable memory (MemoryId 5 absent or unwritten). This canister \
             was never initialised, or is being upgraded from a pre-hardening Wasm that \
             predates the eager cell. Aborting to prevent silent state loss.",
        );
    };

    POOL_CANISTER.with(|p| *p.borrow_mut() = Some(pool_canister));

    // ── Re-derive LEAF_COUNT and ROOT_INDEX from stable structures ────────────
    //
    // COMMITMENTS is a StableBTreeMap<u64, Hash32> keyed 0..N-1.
    // The number of committed leaves is the map's length.
    let leaf_count = COMMITMENTS.with(|c| c.borrow().len());
    LEAF_COUNT.with(|lc| *lc.borrow_mut() = leaf_count);

    // ROOT_HISTORY is a StableBTreeMap<u64, Hash32> with keys 0..ROOT_HISTORY_SIZE-1
    // (ring buffer).  ROOT_INDEX is the total number of roots ever stored, used
    // to compute the next write slot (ROOT_INDEX % ROOT_HISTORY_SIZE).
    //
    // We cannot recover the absolute ROOT_INDEX from the ring buffer alone —
    // we only know how many slots are occupied (up to ROOT_HISTORY_SIZE).
    // The correct value is: one root per leaf appended, plus one for the init root.
    // Since leaf_count leaves → leaf_count append_commitment calls → leaf_count
    // roots, plus the initial empty root stored by init(), ROOT_INDEX = leaf_count + 1.
    let root_index = leaf_count + 1;
    ROOT_INDEX.with(|ri| *ri.borrow_mut() = root_index);

    // ── DEF-044 L3: assert the invariants the reconstruction above depends on ──
    //
    // A violated invariant means COMMITMENTS.len() is NOT a faithful leaf count (gap
    // or out-of-range key) or the ring buffer is inconsistent with the leaf count —
    // either of which would silently corrupt anchoring. Trapping here surfaces the
    // corruption during a CI upgrade test instead of in production. The checks are
    // O(1) (no full dense scan): a gap would require a missing tail key or a key at
    // the exclusive upper bound.
    if leaf_count > 0 {
        assert!(
            COMMITMENTS.with(|c| c.borrow().get(&(leaf_count - 1)).is_some()),
            "post_upgrade invariant violated: COMMITMENTS missing tail key {} (leaf_count {})",
            leaf_count - 1,
            leaf_count
        );
    }
    assert!(
        COMMITMENTS.with(|c| c.borrow().get(&leaf_count).is_none()),
        "post_upgrade invariant violated: COMMITMENTS has a key at leaf_count {} \
         (keys must be a dense 0..leaf_count range)",
        leaf_count
    );
    // One-root-per-leaf: ROOT_HISTORY holds the init root plus one per leaf, capped at
    // the ring-buffer size.
    let occupied = ROOT_HISTORY.with(|r| r.borrow().len());
    let expected_roots = root_index.min(ROOT_HISTORY_SIZE as u64);
    assert_eq!(
        occupied, expected_roots,
        "post_upgrade invariant violated: ROOT_HISTORY occupancy {} != expected {} \
         (leaf_count {}, root_index {})",
        occupied, expected_roots, leaf_count, root_index
    );
}

// ── Unit tests ────────────────────────────────────────────────────────────────
//
// These tests run on the host (not inside a Wasm canister) and verify:
//   1. Poseidon parameter self-consistency
//   2. ZERO_VALUES derivation correctness
//   3. [0u8;32] is not a valid zero value (regression for M3 stub behaviour)
//
// Cross-check test vectors against circomlib JS once ZK engineer adds
// circuits/poseidon_test.js.  See POSEIDON_PARAMS.md for the reference script.

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// Decode a 64-char hex string into a 32-byte array (for published-vector asserts).
    fn unhex(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "expected 64 hex chars, got {}", s.len());
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("valid hex");
        }
        out
    }

    /// Little-endian 32-byte encoding of a small integer (a canonical BN254 Fr).
    fn le32(n: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&n.to_le_bytes());
        out
    }

    // ── test_print_zero_values ────────────────────────────────────────────────
    //
    // Prints all 33 ZERO_VALUES as hex so they can be cross-checked against
    // the circomlib JavaScript reference (see POSEIDON_PARAMS.md).
    //
    // Run with: cargo test -p merkle_tree test_print_zero_values -- --nocapture

    #[test]
    fn test_print_zero_values() {
        let z = compute_zero_values_raw();
        println!("ZERO_VALUES (little-endian hex, BN254/Fr circomlib Poseidon(2)):");
        for (i, v) in z.iter().enumerate() {
            println!("  [{:2}] = 0x{}", i, hex(v));
        }
        println!("ZERO_VALUES[32] (empty tree root) = 0x{}", hex(&z[32]));
    }

    // ── test_poseidon_circomlib_vectors ────────────────────────────────────────
    //
    // Self-consistency checks.  These verify our Poseidon implementation is
    // internally coherent.  They do NOT substitute for cross-checking against
    // circomlib test vectors — see POSEIDON_PARAMS.md for the TODO.

    #[test]
    fn test_poseidon_circomlib_vectors() {
        // 1. Poseidon(0, 0) must NOT be the zero byte array.
        //    The SHA-256 stub returned [0u8;32] as zero_value(0), which was wrong.
        //    Poseidon(Fr::zero(), Fr::zero()) is a non-zero field element.
        let zero_hash = poseidon_hash_pair_inner([0u8; 32], [0u8; 32]);
        assert_ne!(
            zero_hash, [0u8; 32],
            "Poseidon(0, 0) must not equal [0u8;32] — SHA-256 stub behaviour regressed"
        );

        // 2. ZERO_VALUES[0] == poseidon_hash_pair([0;32], [0;32])
        let z = compute_zero_values_raw();
        assert_eq!(
            z[0], zero_hash,
            "ZERO_VALUES[0] must equal poseidon_hash_pair_inner([0;32], [0;32])"
        );

        // 3. ZERO_VALUES[1] == Poseidon(ZERO_VALUES[0], ZERO_VALUES[0])
        let z1_expected = poseidon_hash_pair_inner(z[0], z[0]);
        assert_eq!(z[1], z1_expected, "ZERO_VALUES[1] derivation incorrect");

        // 4. ZERO_VALUES[2] == Poseidon(ZERO_VALUES[1], ZERO_VALUES[1])
        let z2_expected = poseidon_hash_pair_inner(z[1], z[1]);
        assert_eq!(z[2], z2_expected, "ZERO_VALUES[2] derivation incorrect");

        // 5. Empty tree root (ZERO_VALUES[32]) is not [0u8;32]
        assert_ne!(
            z[TREE_DEPTH], [0u8; 32],
            "Poseidon empty-tree root must not be [0u8;32]"
        );

        // 6. All 33 levels are distinct (no accidental collision between levels)
        for i in 0..33 {
            for j in (i + 1)..33 {
                assert_ne!(
                    z[i], z[j],
                    "ZERO_VALUES[{i}] == ZERO_VALUES[{j}] — collision in zero value chain"
                );
            }
        }
    }

    // ── test_poseidon_published_vectors (DEF-039) ─────────────────────────────
    //
    // Byte-equality against the EXTERNALLY-published circomlib vectors in
    // POSEIDON_PARAMS.md ("Compatibility test vectors", computed by
    // circomlibjs@0.1.7 / circomlib@2.0.5, t=3, BN254). Unlike
    // test_poseidon_circomlib_vectors (self-consistency only), this pins the
    // canister's Poseidon(2) output to the exact published bytes.
    //
    // The expected values are copied VERBATIM from POSEIDON_PARAMS.md — never
    // recomputed here. If this test fails, the Poseidon parameters have drifted
    // from circomlib: DO NOT edit the constants to make it pass — STOP and report,
    // because a drift means every existing commitment, nullifier, and anchor is
    // incompatible with the circuit.
    //
    // Kept as a merkle-tree crate unit test (not an integration test) because it must
    // call the private poseidon_hash_pair_inner directly, and no public canister query
    // exposes these specific raw Poseidon(2) inputs/outputs. See POSEIDON_PARAMS.md
    // "Implementation files".

    #[test]
    fn test_poseidon_published_vectors() {
        // Published little-endian 32-byte hex (POSEIDON_PARAMS.md).
        let pub_z0 = unhex("6448b64684ee39a823d5fe5fd52431dc81e4817bf2c3ea3cab9e239efbf59820");
        let pub_z1 = unhex("e1f1b1604477a467f08dc69dcb441a26eca784f56f1a30df6322b1cd3d676910");
        let pub_z2 = unhex("38d256b8b27ed528d51d3750ea6e7c460621f7508d753d2eafe27e533133f418");
        let pub_z3 = unhex("2a95bc9d5597acca6582561a5728b7f14523a53be9ff2063d3b017cb37d8f907");
        let pub_p12 = unhex("9a1817447a60199e51453274f217362acfe962966b4cf63d4190d6e7f5c05c11");

        assert_eq!(
            poseidon_hash_pair_inner([0u8; 32], [0u8; 32]), pub_z0,
            "Poseidon(0,0) != published ZERO_VALUES[0] — Poseidon params drifted from circomlib"
        );
        assert_eq!(
            poseidon_hash_pair_inner(pub_z0, pub_z0), pub_z1,
            "Poseidon(Z0,Z0) != published ZERO_VALUES[1]"
        );
        assert_eq!(
            poseidon_hash_pair_inner(pub_z1, pub_z1), pub_z2,
            "Poseidon(Z1,Z1) != published ZERO_VALUES[2]"
        );
        assert_eq!(
            poseidon_hash_pair_inner(pub_z2, pub_z2), pub_z3,
            "Poseidon(Z2,Z2) != published ZERO_VALUES[3]"
        );
        assert_eq!(
            poseidon_hash_pair_inner(le32(1), le32(2)), pub_p12,
            "Poseidon(1,2) != published vector — Poseidon params drifted from circomlib"
        );

        // The canister's derived ZERO_VALUES chain must also equal the published bytes.
        let z = compute_zero_values_raw();
        assert_eq!(z[0], pub_z0, "ZERO_VALUES[0] != published");
        assert_eq!(z[1], pub_z1, "ZERO_VALUES[1] != published");
        assert_eq!(z[2], pub_z2, "ZERO_VALUES[2] != published");
        assert_eq!(z[3], pub_z3, "ZERO_VALUES[3] != published");
    }

    // ── test_ensure_capacity_for_append (DEF-007) ─────────────────────────────
    //
    // The capacity guard rejects exactly when an append would write a leaf at index
    // >= 2^32, where encode_node_key's 32-bit mask aliases. Filling to EXACTLY 2^32
    // leaves is allowed (indices 0..2^32-1 are all 32-bit representable). Exercised as
    // a pure-function unit test per the agreed approach (no production test setter).

    #[test]
    fn test_ensure_capacity_for_append() {
        assert_eq!(MAX_TREE_LEAVES, 1u64 << 32);

        // Empty tree: a normal append is fine.
        assert!(ensure_capacity_for_append(0, 1).is_ok());

        // One short of capacity: a single append fills it exactly → allowed.
        assert!(ensure_capacity_for_append(MAX_TREE_LEAVES - 1, 1).is_ok());

        // One short of capacity: a 2-item batch would overflow → rejected.
        let e = ensure_capacity_for_append(MAX_TREE_LEAVES - 1, 2).unwrap_err();
        assert!(e.contains("TreeFull"), "expected TreeFull, got: {e}");

        // At capacity: any further append is rejected.
        assert!(ensure_capacity_for_append(MAX_TREE_LEAVES, 1)
            .unwrap_err()
            .contains("TreeFull"));

        // A batch that exactly fills from empty is allowed; one more is not.
        assert!(ensure_capacity_for_append(0, MAX_TREE_LEAVES).is_ok());
        assert!(ensure_capacity_for_append(0, MAX_TREE_LEAVES + 1)
            .unwrap_err()
            .contains("TreeFull"));

        // u64 overflow in (leaf_count + batch_len) must not panic — treated as TreeFull.
        assert!(ensure_capacity_for_append(u64::MAX, 5)
            .unwrap_err()
            .contains("TreeFull"));
    }

    // ── test_validate_commitment_bytes (DEF-041 / DEF-044 L1) ─────────────────
    //
    // Canonical field elements (including the all-zero element) are accepted;
    // non-canonical encodings (bytes >= modulus) and wrong lengths are typed Err,
    // never a trap.

    #[test]
    fn test_validate_commitment_bytes() {
        // Canonical: all-zero (Fr::zero) is accepted.
        assert!(validate_commitment_bytes(&[0u8; 32]).is_ok());
        // Canonical: a small value.
        assert!(validate_commitment_bytes(&le32(12345)).is_ok());

        // Non-canonical: all-0xff is >= modulus → InvalidCommitment.
        let e = validate_commitment_bytes(&[0xffu8; 32]).unwrap_err();
        assert!(e.contains("InvalidCommitment"), "expected InvalidCommitment, got: {e}");

        // The field modulus itself (encodes to 0 mod p, but bytes are non-canonical).
        // p (big-endian) per POSEIDON_PARAMS.md; convert to little-endian.
        let p_be =
            unhex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
        let mut p_le = [0u8; 32];
        for i in 0..32 {
            p_le[i] = p_be[31 - i];
        }
        assert!(validate_commitment_bytes(&p_le)
            .unwrap_err()
            .contains("InvalidCommitment"));

        // Wrong length → InvalidLength (not a trap).
        assert!(validate_commitment_bytes(&[0u8; 31])
            .unwrap_err()
            .contains("InvalidLength"));
    }

    // ── test_poseidon_deterministic ───────────────────────────────────────────
    //
    // Same inputs always produce the same output.  Guards against any
    // non-deterministic RNG usage inside the Poseidon library.

    #[test]
    fn test_poseidon_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let h1 = poseidon_hash_pair_inner(a, b);
        let h2 = poseidon_hash_pair_inner(a, b);
        assert_eq!(h1, h2, "Poseidon is not deterministic — library bug");
    }

    // ── test_poseidon_input_ordering ──────────────────────────────────────────
    //
    // hash_pair(left, right) != hash_pair(right, left) for non-equal inputs.
    // Verifies that input ordering is respected (matches circuit Switcher semantics).

    #[test]
    fn test_poseidon_input_ordering() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let h_lr = poseidon_hash_pair_inner(a, b);
        let h_rl = poseidon_hash_pair_inner(b, a);
        assert_ne!(
            h_lr, h_rl,
            "hash_pair(left, right) == hash_pair(right, left) — input ordering lost"
        );
    }

    // ── test_zero_value_accessor ──────────────────────────────────────────────
    //
    // zero_value(level) returns the same bytes as compute_zero_values_raw()[level].

    #[test]
    fn test_zero_value_accessor() {
        let z = compute_zero_values_raw();
        for level in 0..=TREE_DEPTH {
            assert_eq!(
                zero_value(level).0, z[level],
                "zero_value({level}) does not match ZERO_VALUES[{level}]"
            );
        }
    }

    // ── test_empty_root_not_zero_bytes ────────────────────────────────────────
    //
    // M4 REGRESSION: The M3 stub returned [0u8;32] as the empty-tree root,
    // making is_valid_anchor([0u8;32]) == true on a fresh canister.
    // After M4, zero_value(TREE_DEPTH) must not be [0u8;32].

    #[test]
    fn test_empty_root_not_zero_bytes() {
        let empty_root = zero_value(TREE_DEPTH);
        assert_ne!(
            empty_root.0, [0u8; 32],
            "Empty Poseidon tree root must not be [0u8;32] — M3 stub behaviour regressed"
        );
    }

    // ── test_hash_pair_wrapper ────────────────────────────────────────────────
    //
    // poseidon_hash_pair(&Hash32) wraps poseidon_hash_pair_inner consistently.

    #[test]
    fn test_hash_pair_wrapper() {
        let left  = Hash32([3u8; 32]);
        let right = Hash32([7u8; 32]);
        let via_wrapper = poseidon_hash_pair(&left, &right);
        let via_inner   = poseidon_hash_pair_inner(left.0, right.0);
        assert_eq!(via_wrapper.0, via_inner, "poseidon_hash_pair wrapper inconsistent");
    }

    // ── get_authority_refs (Custody Vault L3g) ──────────────────────────────
    //
    // Each #[test] runs on its own thread, so the thread_local state (memory
    // manager, eager cell, stable maps) starts fresh per test — no cross-test
    // contamination.

    /// Positive: after init, the read-back returns the canonical stored
    /// POOL_CANISTER, and the query itself mutates nothing.
    #[test]
    fn test_get_authority_refs_positive() {
        let pool = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
        init(pool);
        let before = LEAF_COUNT.with(|c| *c.borrow());
        let refs = get_authority_refs().expect("initialised canister must return Ok");
        assert_eq!(refs.pool_canister, pool);
        // And it is the durable cell value, not just the heap mirror.
        assert_eq!(POOL_REF.with(|c| c.borrow().get().get().copied()), Some([pool]));
        // Mutation-free: no state moved.
        assert_eq!(LEAF_COUNT.with(|c| *c.borrow()), before);
    }

    /// Fail-closed on uninitialised state: a fresh (sentinel) eager cell must
    /// yield Err, never a substituted default.
    #[test]
    fn test_get_authority_refs_fails_closed_on_sentinel() {
        // No init() — POOL_REF holds the all-0xFF sentinel.
        assert!(POOL_REF.with(|c| c.borrow().get().is_sentinel()));
        let err = get_authority_refs().expect_err("sentinel cell must fail closed");
        assert!(err.contains("UninitializedAuthorityRefs"), "unexpected err: {err}");
    }

    /// Fail-closed on corrupt state: bytes that are not the exact valid layout
    /// decode to the sentinel (eager-cell contract) and the decode helper errs.
    ///
    /// NOTE: `Cell` caches its decoded value, so raw byte corruption is only
    /// ever observed at `Cell::init` — i.e. across an upgrade boundary, which
    /// is exactly where it matters. This test therefore corrupts the raw value
    /// region and re-initialises a fresh `Cell` over the same memory, which is
    /// precisely what `post_upgrade` sees. (On a live canister the existing
    /// `post_upgrade` sentinel gate traps first; the query decode is defence
    /// in depth.)
    #[test]
    fn test_get_authority_refs_fails_closed_on_corrupt() {
        use ic_stable_structures::Memory;
        let pool = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
        init(pool);
        assert!(get_authority_refs().is_ok());
        // Overwrite the raw cell VALUE region (after the 8-byte stable-cell
        // header: 3-byte "SCL" magic + 1 version byte + 4-byte length) with a
        // bad layout-version byte — corrupt, but neither valid nor the
        // all-0xFF absent sentinel.
        let mut junk = [0xABu8; 31]; // encoded_len(1) == 1 + 30
        junk[0] = 0x7E; // != LAYOUT_VERSION (1) and not 0xFF
        MEMORY_MANAGER.with(|m| m.borrow().get(MEM_POOL_REF).write(8, &junk));
        // Re-decode from durable memory, as post_upgrade would.
        let mem = MEMORY_MANAGER.with(|m| m.borrow().get(MEM_POOL_REF));
        let cell = Cell::init(mem, PoolRefCell::sentinel())
            .expect("Cell::init on corrupt value must still open (header intact)");
        assert!(cell.get().is_sentinel(), "corrupt bytes must decode to sentinel");
        let err = decode_authority_refs(*cell.get())
            .expect_err("corrupt cell must fail closed");
        assert!(err.contains("UninitializedAuthorityRefs"), "unexpected err: {err}");
    }

    /// Upgrade persistence: the value written by init survives post_upgrade
    /// (which restores the heap mirror from the same durable cell) and the
    /// read-back still returns the canonical principal afterwards.
    #[test]
    fn test_get_authority_refs_survives_upgrade() {
        let pool = Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap();
        init(pool);
        post_upgrade();
        let refs = get_authority_refs().expect("read-back must succeed after upgrade");
        assert_eq!(refs.pool_canister, pool);
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
