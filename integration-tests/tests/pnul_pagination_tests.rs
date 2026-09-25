// =============================================================================
// STSH — P-NUL (L0-F): nullifier-registry exact pagination
// =============================================================================
//
// Covers BRIEF_WALLET_B_PHASE2_FINISH.md §8 and the P-NUL adversarial row:
//   - get_nullifiers_page(start_after, limit): stable LEXICOGRAPHIC order,
//     EXCLUSIVE cursor, canonical 32-byte cursor enforced, nonzero capped
//     limit (rejects, never truncates), no Bloom/digest.
//   - malformed/unset-cursor handling proven (wrong length and non-Fr bytes
//     rejected; unset cursor resolves to the next greater key) · non-
//     lexicographic order → missed nullifier (full-walk completeness) ·
//     unbounded page rejected · upgrade-preservation.
//   - NOTE (R4 wording correction): a VALID cursor intentionally skips the
//     prefix before it — that is normal start_after behavior, not an attack.
//     Spent-set security comes from WALLET discipline: start at None, advance
//     only with the last returned key, enforce strict ordering, and require
//     downloaded length == the stable count. The tests below assert exactly
//     those semantics.
//   - WALLET-side strict checks (the L3b reference algorithm, exercised here
//     against the real canister): strictly increasing order, uniqueness,
//     exact-32-byte values, downloaded length == count; count before/after
//     enforced — a stale snapshot (count changed mid-walk) is discarded and
//     retried, and retry exhaustion FAILS CLOSED (never returns a partial set
//     that could mark an unchecked note spendable).
//
// Stack: nullifier-registry only (init arg = pool principal; inserts are made
// as that principal). Production Wasm; POCKET_IC_BIN must be set.
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::Deserialize;

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(w) => w,
        Err(e) => panic!(
            "read {} wasm at {} failed: {:?} — run the Law-#7 two-phase build first",
            pkg, path, e
        ),
    }
}
fn nullifier_wasm() -> Vec<u8> { load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry") }

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

struct Stack {
    registry: Principal,
    pool: Principal,
}

fn deploy(pic: &PocketIc) -> Stack {
    let pool = p(0xC0);
    let registry = pic.create_canister();
    pic.add_cycles(registry, 2_000_000_000_000u128);
    pic.install_canister(registry, nullifier_wasm(), candid::encode_one(pool).unwrap(), None);
    Stack { registry, pool }
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: candid::CandidType + for<'de> Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {:?}", label, e))
}

/// Canonical 32-byte nullifier (small LE values are trivially < Fr modulus).
fn nf(n: u8, tag: u8) -> Vec<u8> {
    let mut b = vec![0u8; 32];
    b[0] = n;
    b[1] = tag;
    b
}

fn insert(pic: &PocketIc, s: &Stack, nullifiers: Vec<Vec<u8>>) {
    let r: Result<(), String> = decode(
        "insert_batch",
        pic.update_call(s.registry, s.pool, "insert_batch", candid::encode_one(nullifiers).unwrap()),
    );
    assert_eq!(r, Ok(()), "insert_batch must succeed");
}

fn count(pic: &PocketIc, s: &Stack) -> u64 {
    decode(
        "count",
        pic.query_call(s.registry, s.pool, "count", candid::encode_args(()).unwrap()),
    )
}

fn page(pic: &PocketIc, s: &Stack, start_after: Option<Vec<u8>>, limit: u64) -> Result<Vec<Vec<u8>>, String> {
    decode(
        "get_nullifiers_page",
        pic.query_call(
            s.registry,
            s.pool,
            "get_nullifiers_page",
            candid::encode_args((start_after, limit)).unwrap(),
        ),
    )
}

// ── Wallet-side strict download (L3b reference algorithm) ────────────────────
//
// count before → paginated walk with STRICT per-element checks (exactly 32
// bytes, strictly increasing, no duplicates) → count after → mismatch ⇒ the
// snapshot is stale: DISCARD everything and retry from scratch. Retry
// exhaustion FAILS CLOSED with an error — never a partial set.
const WALK_LIMIT: u64 = 5;
const MAX_WALK_RETRIES: u32 = 3;

#[derive(Debug, PartialEq)]
enum WalkOutcome {
    Ok(Vec<Vec<u8>>, u32), // (downloaded set, attempts used)
    StaleExhausted,
}

fn strict_download(
    pic: &PocketIc,
    s: &Stack,
    // Test hook: invoked mid-walk on each attempt (simulates a concurrent
    // insert). The wallet algorithm must detect the resulting count drift.
    mid_walk_mutation: &dyn Fn(u32),
) -> WalkOutcome {
    for attempt in 0..MAX_WALK_RETRIES {
        let count_before = count(pic, s);
        let mut all: Vec<Vec<u8>> = Vec::new();
        let mut cursor: Option<Vec<u8>> = None;
        let mut mutated = false;
        loop {
            let page = page(pic, s, cursor.clone(), WALK_LIMIT).expect("page fetch");
            if !mutated {
                mutated = true;
                mid_walk_mutation(attempt);
            }
            for v in &page {
                assert_eq!(v.len(), 32, "every value must be exactly 32 bytes");
                if let Some(prev) = all.last() {
                    assert!(v > prev, "values must be strictly increasing across page boundaries");
                }
                all.push(v.clone());
            }
            if (page.len() as u64) < WALK_LIMIT {
                break;
            }
            cursor = all.last().cloned();
        }
        let count_after = count(pic, s);
        if count_before == count_after {
            assert_eq!(all.len() as u64, count_after, "downloaded length must equal count");
            return WalkOutcome::Ok(all, attempt + 1);
        }
        // Stale snapshot — DISCARD and retry from scratch.
    }
    WalkOutcome::StaleExhausted
}

// =============================================================================
// Full paginated walk — lexicographic completeness, strict wallet checks,
// downloaded length == count.
// =============================================================================
#[test]
fn pnul_full_walk_strict_checks() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let mine: Vec<Vec<u8>> = [11u8, 2, 7, 4, 9, 1, 12, 5, 3, 10, 6, 8]
        .map(|n| nf(n, 0x11))
        .to_vec();
    insert(&pic, &s, mine.clone());

    let outcome = strict_download(&pic, &s, &|_| {});
    let WalkOutcome::Ok(all, attempts) = outcome else {
        panic!("unmutated walk must succeed on the first attempt; got {:?}", outcome)
    };
    assert_eq!(attempts, 1, "unmutated walk must succeed on the first attempt");
    let mut sorted = mine.clone();
    sorted.sort();
    assert_eq!(all, sorted, "walk must return the exact set, lexicographically ordered, nothing missed");
}

// =============================================================================
// Canonical-32-byte cursor + nonzero capped limit enforcement.
// =============================================================================
#[test]
fn pnul_cursor_and_limit_validation() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    insert(&pic, &s, vec![nf(1, 0x21), nf(2, 0x21)]);

    for len in [0usize, 31, 33, 64] {
        let err = page(&pic, &s, Some(vec![0xAAu8; len]), 10)
            .expect_err(&format!("cursor of length {len} must be rejected"));
        assert!(err.starts_with("InvalidNullifier:"), "len {len}: got {err}");
    }
    let err = page(&pic, &s, Some(vec![0xFFu8; 32]), 10)
        .expect_err("non-canonical 32-byte cursor must be rejected");
    assert!(err.starts_with("NonCanonicalNullifier:"), "got {err}");

    let err = page(&pic, &s, None, 0).expect_err("limit 0 must be rejected");
    assert!(err.starts_with("InvalidLimit:"), "got {err}");
    let err = page(&pic, &s, None, 501).expect_err("limit above the cap must be rejected");
    assert!(err.starts_with("PageTooLarge:"), "got {err}");
    assert!(page(&pic, &s, None, 500).is_ok(), "the cap itself must be accepted");
}

// =============================================================================
// Exclusive-range cursor semantics — a VALID cursor intentionally skips the
// prefix before it (normal start_after behavior, NOT an attack). What must
// hold: the cursor itself is never re-returned, an unset cursor resolves to
// the next greater key (no repeats, no wrong start), and the tail yields an
// empty page. Spent-set security comes from wallet discipline (start at None,
// advance with the last returned key, strict ordering, length == count) —
// exercised by the full-walk tests.
// =============================================================================
#[test]
fn pnul_cursor_exclusive_range_semantics() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let a = nf(1, 0x31);
    let b = nf(3, 0x31);
    let c = nf(5, 0x31);
    insert(&pic, &s, vec![a.clone(), b.clone(), c.clone()]);

    // Present cursor: excluded itself; page starts at the next greater key.
    let p1 = page(&pic, &s, Some(b.clone()), 10).expect("page after b");
    assert_eq!(p1, vec![c.clone()], "exclusive cursor must not re-return the cursor key");

    // Unset cursor between b and c: resolves to the next greater key — a
    // valid cursor skips the prefix by design, but never causes repeats or a
    // wrong start in a disciplined walk.
    let p2 = page(&pic, &s, Some(nf(4, 0x31)), 10).expect("page after unset cursor");
    assert_eq!(p2, vec![c.clone()]);

    // Cursor past the tail: empty page (clean termination, no wrap).
    let p3 = page(&pic, &s, Some(c.clone()), 10).expect("page after tail");
    assert!(p3.is_empty(), "cursor at the tail must yield an empty page");

    // Full walk from the beginning covers everything exactly once.
    let p4 = page(&pic, &s, None, 10).expect("first page");
    assert_eq!(p4, vec![a, b, c]);
}

// =============================================================================
// Stale snapshot: count changes mid-walk → discard + retry → succeed fresh.
// =============================================================================
#[test]
fn pnul_stale_snapshot_discarded_and_retried() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let base: Vec<Vec<u8>> = [1u8, 2, 3, 4, 5, 6, 7, 8].map(|n| nf(n, 0x41)).to_vec();
    insert(&pic, &s, base.clone());

    let extra = nf(9, 0x41);
    let outcome = strict_download(&pic, &s, &|attempt| {
        if attempt == 0 {
            // Concurrent insert during the first attempt's walk.
            let r: Result<(), String> = decode(
                "insert_batch",
                pic.update_call(s.registry, s.pool, "insert_batch", candid::encode_one(vec![extra.clone()]).unwrap()),
            );
            assert_eq!(r, Ok(()));
        }
    });
    let WalkOutcome::Ok(all, attempts) = outcome else {
        panic!("walk must retry the stale snapshot and succeed; got {:?}", outcome)
    };
    assert_eq!(attempts, 2, "first attempt discarded (count drift), second attempt clean");
    let mut sorted = base.clone();
    sorted.push(extra);
    sorted.sort();
    assert_eq!(all, sorted, "the retried snapshot must include the concurrently inserted nullifier");
}

// =============================================================================
// Retry exhaustion: the count keeps changing on EVERY attempt → FAIL CLOSED.
// The error path carries no set — an unchecked note can never be marked
// spendable from a stale download.
// =============================================================================
#[test]
fn pnul_retry_exhaustion_fails_closed() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    insert(&pic, &s, vec![nf(1, 0x51)]);

    let outcome = strict_download(&pic, &s, &|attempt| {
        // Mutate on EVERY attempt: the snapshot never stabilizes.
        let fresh = nf(2 + attempt as u8, 0x51);
        let r: Result<(), String> = decode(
            "insert_batch",
            pic.update_call(s.registry, s.pool, "insert_batch", candid::encode_one(vec![fresh]).unwrap()),
        );
        assert_eq!(r, Ok(()));
    });
    assert_eq!(
        outcome,
        WalkOutcome::StaleExhausted,
        "perpetually-changing snapshot must exhaust retries and fail closed"
    );
}

// =============================================================================
// Upgrade preservation: the spent-set and the pagination over it survive a
// real upgrade (same Wasm, pre/post_upgrade checkpoint path).
//
// EVIDENCE LABEL (R4 honesty): this is a SAME-WASM preservation test — the
// P-NUL Wasm is installed both before and after the upgrade. It is NOT a
// pre-P-NUL → P-NUL transition test. That is sufficient here because the
// P-NUL diff changed neither the stable-memory layout (MemoryIds 0/1
// unchanged) nor the upgrade hooks (byte-identical pre/post_upgrade), so
// there is no new state to migrate — the only upgrade-relevant property is
// that the existing checkpoint path still restores the set the new endpoint
// paginates.
// =============================================================================
#[test]
fn pnul_upgrade_preservation() {
    let pic = PocketIc::new();
    let s = deploy(&pic);
    let mine: Vec<Vec<u8>> = [7u8, 1, 5, 3, 9, 2].map(|n| nf(n, 0x61)).to_vec();
    insert(&pic, &s, mine.clone());
    let mut sorted = mine.clone();
    sorted.sort();
    let count_before = count(&pic, &s);
    let walk_before = page(&pic, &s, None, 500).expect("pre-upgrade full page");

    // Same install-rate-limit handling as the other suites (two back-to-back
    // install_code messages can trip PocketIC's per-canister budget).
    pic.advance_time(std::time::Duration::from_secs(7 * 86_400));
    for _ in 0..5 {
        pic.tick();
    }
    pic.upgrade_canister(s.registry, nullifier_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("registry upgrade must succeed");

    assert_eq!(count(&pic, &s), count_before, "count must survive the upgrade");
    let walk_after = page(&pic, &s, None, 500).expect("post-upgrade full page");
    assert_eq!(walk_after, sorted, "the exact ordered set must survive the upgrade");
    assert_eq!(walk_before, walk_after, "pagination must be identical across the upgrade");

    // Inserts still work post-upgrade (access control restored from checkpoint).
    insert(&pic, &s, vec![nf(10, 0x61)]);
    assert_eq!(count(&pic, &s), count_before + 1);
}
