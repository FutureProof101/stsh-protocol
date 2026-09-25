// =============================================================================
// STSH — Merkle hardening tests (PocketIC)
// Covers, via the merkle_tree canister's PUBLIC interface only:
//   DEF-041  canonical BN254 field-element validation on append
//   DEF-043  get_root_at_index bounds + ring-buffer eviction
//   DEF-044  L1 (wrong-length → typed Err, not trap),
//            L2 (append_commitments batch cap),
//            L5 (auth rejection, get_leaf out-of-range, batch atomicity)
//
// DEF-007 (capacity guard at 2^32 leaves) and DEF-039 (published Poseidon vectors)
// are exercised as merkle_tree crate unit tests — reaching 2^32 leaves is infeasible
// here, and the Poseidon vectors must call the private poseidon_hash_pair_inner.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7): the production merkle_tree Wasm
// must be built and MERKLE_WASM set (integration-tests/build.rs). POCKET_IC_BIN set.
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;

// ── Wasm loading ────────────────────────────────────────────────────────────

fn merkle_wasm() -> Vec<u8> {
    std::fs::read(env!("MERKLE_WASM"))
        .unwrap_or_else(|e| panic!("Cannot read merkle_tree Wasm at {}: {}", env!("MERKLE_WASM"), e))
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}
fn anon() -> Principal {
    Principal::anonymous()
}
/// Canonical small BN254 Fr value: low byte set, high bytes zero (well below modulus).
fn fr(b: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0] = b;
    a
}

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

/// Install a merkle_tree canister authorized to `pool` and return its id.
fn install_merkle(pic: &PocketIc, pool: Principal) -> Principal {
    let m = create_canister(pic);
    pic.install_canister(m, merkle_wasm(), candid::encode_one(pool).unwrap(), None);
    m
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}

fn append(pic: &PocketIc, m: Principal, pool: Principal, c: [u8; 32]) -> Result<u64, String> {
    decode(
        "append_commitment",
        pic.update_call(
            m,
            pool,
            "append_commitment",
            candid::encode_args((c.to_vec(), Vec::<u8>::new())).unwrap(),
        ),
    )
}

fn append_bytes(
    pic: &PocketIc,
    m: Principal,
    pool: Principal,
    c: Vec<u8>,
) -> Result<u64, String> {
    decode(
        "append_commitment",
        pic.update_call(
            m,
            pool,
            "append_commitment",
            candid::encode_args((c, Vec::<u8>::new())).unwrap(),
        ),
    )
}

fn append_batch(
    pic: &PocketIc,
    m: Principal,
    pool: Principal,
    items: Vec<[u8; 32]>,
) -> Result<Vec<u64>, String> {
    let payloaded: Vec<(Vec<u8>, Vec<u8>)> =
        items.into_iter().map(|c| (c.to_vec(), Vec::<u8>::new())).collect();
    decode(
        "append_commitments",
        pic.update_call(
            m,
            pool,
            "append_commitments",
            candid::encode_one(payloaded).unwrap(),
        ),
    )
}

fn leaf_count(pic: &PocketIc, m: Principal) -> u64 {
    decode(
        "leaf_count",
        pic.query_call(m, anon(), "leaf_count", candid::encode_args(()).unwrap()),
    )
}

fn get_root(pic: &PocketIc, m: Principal) -> Vec<u8> {
    decode(
        "get_root",
        pic.query_call(m, anon(), "get_root", candid::encode_args(()).unwrap()),
    )
}

fn get_root_at_index(pic: &PocketIc, m: Principal, i: u64) -> Option<Vec<u8>> {
    decode(
        "get_root_at_index",
        pic.query_call(m, anon(), "get_root_at_index", candid::encode_one(i).unwrap()),
    )
}

fn get_leaf(pic: &PocketIc, m: Principal, i: u64) -> Option<Vec<u8>> {
    decode(
        "get_leaf",
        pic.query_call(m, anon(), "get_leaf", candid::encode_one(i).unwrap()),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-041 — canonical BN254 field-element validation on append
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_append_rejects_non_canonical_commitment() {
    let pic = PocketIc::new();
    let pool = p(0xAA);
    let m = install_merkle(&pic, pool);

    // All-0xff encodes a value >= the BN254 Fr modulus → non-canonical → rejected.
    let r = append(&pic, m, pool, [0xffu8; 32]);
    assert!(r.is_err(), "non-canonical commitment must be rejected; got {:?}", r);
    assert!(
        r.unwrap_err().contains("InvalidCommitment"),
        "error must identify a non-canonical commitment"
    );
    assert_eq!(leaf_count(&pic, m), 0, "rejected append must not mutate the tree");

    // The all-zero element (Fr::zero) IS canonical → accepted.
    assert!(append(&pic, m, pool, [0u8; 32]).is_ok(), "zero is a canonical Fr and must be accepted");
    assert_eq!(leaf_count(&pic, m), 1);

    // A small canonical value is accepted.
    assert!(append(&pic, m, pool, fr(0x07)).is_ok());
    assert_eq!(leaf_count(&pic, m), 2);
}

#[test]
fn test_append_commitments_rejects_non_canonical_atomically() {
    let pic = PocketIc::new();
    let pool = p(0xAA);
    let m = install_merkle(&pic, pool);

    // Middle item is non-canonical → the WHOLE batch is rejected, nothing appended.
    let r = append_batch(&pic, m, pool, vec![fr(0x01), [0xffu8; 32], fr(0x03)]);
    assert!(r.is_err(), "batch with a non-canonical item must be rejected; got {:?}", r);
    assert!(r.unwrap_err().contains("InvalidCommitment"));
    assert_eq!(leaf_count(&pic, m), 0, "rejected batch must be all-or-nothing (no partial append)");

    // A fully-canonical batch succeeds.
    let ok = append_batch(&pic, m, pool, vec![fr(0x01), fr(0x02)]);
    assert_eq!(ok, Ok(vec![0, 1]));
    assert_eq!(leaf_count(&pic, m), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-043 — get_root_at_index bounds + ring-buffer eviction
//   index i = the root produced AFTER leaf i; valid iff
//   leaf_count - ROOT_HISTORY_SIZE <= i < leaf_count.
// ─────────────────────────────────────────────────────────────────────────────

const ROOT_HISTORY_SIZE: u64 = 100;

#[test]
fn test_get_root_at_index_fresh_and_one_append() {
    let pic = PocketIc::new();
    let pool = p(0xAA);
    let m = install_merkle(&pic, pool);

    // Fresh tree: no leaf-root has been produced yet.
    assert_eq!(get_root_at_index(&pic, m, 0), None, "fresh tree: index 0 must be None");

    // After one append: index 0 is the root after leaf 0 (== current root); index 1 None.
    assert!(append(&pic, m, pool, fr(0x01)).is_ok());
    let root0 = get_root(&pic, m);
    assert_eq!(
        get_root_at_index(&pic, m, 0),
        Some(root0.clone()),
        "after 1 append, index 0 must be the root after leaf 0"
    );
    assert_eq!(get_root_at_index(&pic, m, 1), None, "after 1 append, index 1 must be None");
}

#[test]
fn test_get_root_at_index_eviction() {
    let pic = PocketIc::new();
    let pool = p(0xAA);
    let m = install_merkle(&pic, pool);

    // Append ROOT_HISTORY_SIZE + 1 leaves so leaf 0's root is evicted from the buffer.
    let n = ROOT_HISTORY_SIZE + 1; // 101
    for i in 0..n {
        // Distinct canonical leaves (i fits a single byte only up to 255; n=101 is fine).
        assert!(append(&pic, m, pool, fr(i as u8)).is_ok(), "append {} must succeed", i);
    }
    assert_eq!(leaf_count(&pic, m), n);

    // Oldest leaf-root (index 0) has been evicted from the ring buffer.
    assert_eq!(get_root_at_index(&pic, m, 0), None, "index 0 must be evicted (None) after SIZE+1 appends");

    // The latest retained leaf-root (index n-1 == SIZE) equals the current root.
    let current = get_root(&pic, m);
    assert_eq!(
        get_root_at_index(&pic, m, n - 1),
        Some(current),
        "index SIZE must be the current (latest) root"
    );

    // One past the last leaf is never-produced → None.
    assert_eq!(get_root_at_index(&pic, m, n), None, "index == leaf_count must be None");
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-044 L1 — wrong-length commitment returns a typed Err (NOT a trap)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_append_wrong_length_returns_err_not_trap() {
    let pic = PocketIc::new();
    let pool = p(0xAA);
    let m = install_merkle(&pic, pool);

    // 31 bytes: the call must DECODE (i.e. not trap) and return Err(InvalidLength).
    let r = append_bytes(&pic, m, pool, vec![0u8; 31]);
    assert!(r.is_err(), "wrong-length commitment must be a typed Err; got {:?}", r);
    assert!(r.unwrap_err().contains("InvalidLength"), "error must identify the bad length");
    assert_eq!(leaf_count(&pic, m), 0, "rejected append must not mutate the tree");
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-044 L2 — append_commitments batch cap
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_append_commitments_batch_cap() {
    let pic = PocketIc::new();
    let pool = p(0xAA);
    let m = install_merkle(&pic, pool);

    // 11 canonical items exceeds MAX_BATCH_SIZE (10) → BatchTooLarge, nothing appended.
    let items: Vec<[u8; 32]> = (1u8..=11).map(fr).collect();
    let r = append_batch(&pic, m, pool, items);
    assert!(r.is_err(), "an over-cap batch must be rejected; got {:?}", r);
    assert!(r.unwrap_err().contains("BatchTooLarge"));
    assert_eq!(leaf_count(&pic, m), 0, "rejected batch must not mutate the tree");

    // Exactly MAX_BATCH_SIZE (10) is accepted.
    let ten: Vec<[u8; 32]> = (1u8..=10).map(fr).collect();
    let ok = append_batch(&pic, m, pool, ten);
    assert!(ok.is_ok(), "a batch of exactly 10 must be accepted; got {:?}", ok);
    assert_eq!(leaf_count(&pic, m), 10);
}

// ─────────────────────────────────────────────────────────────────────────────
// DEF-044 L5 — auth rejection + get_leaf out-of-range
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_append_rejects_unauthorized_caller() {
    let pic = PocketIc::new();
    let pool = p(0xAA);
    let m = install_merkle(&pic, pool);

    // A wrong (non-pool) principal — and the anonymous principal — must NOT be able
    // to append. assert_pool traps, so the inter-canister call is rejected.
    let wrong = pic.update_call(
        m,
        p(0xBB),
        "append_commitment",
        candid::encode_args((fr(0x01).to_vec(), Vec::<u8>::new())).unwrap(),
    );
    assert!(wrong.is_err(), "a non-pool caller must be rejected");

    let anonymous = pic.update_call(
        m,
        anon(),
        "append_commitment",
        candid::encode_args((fr(0x01).to_vec(), Vec::<u8>::new())).unwrap(),
    );
    assert!(anonymous.is_err(), "the anonymous caller must be rejected");

    assert_eq!(leaf_count(&pic, m), 0, "no unauthorized append may mutate the tree");

    // The authorized pool can still append.
    assert!(append(&pic, m, pool, fr(0x01)).is_ok());
    assert_eq!(leaf_count(&pic, m), 1);
}

#[test]
fn test_get_leaf_out_of_range_is_none() {
    let pic = PocketIc::new();
    let pool = p(0xAA);
    let m = install_merkle(&pic, pool);

    // Empty tree: any index, including u64::MAX, is None (no trap, no aliasing).
    assert_eq!(get_leaf(&pic, m, 0), None);
    assert_eq!(get_leaf(&pic, m, u64::MAX), None);

    // After one append, index 0 exists; u64::MAX is still None.
    assert!(append(&pic, m, pool, fr(0x09)).is_ok());
    assert_eq!(get_leaf(&pic, m, 0), Some(fr(0x09).to_vec()));
    assert_eq!(get_leaf(&pic, m, u64::MAX), None, "out-of-range leaf must be None");
}
