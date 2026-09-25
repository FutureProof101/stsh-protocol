// =============================================================================
// LAUNCH-HARDEN-04 O-1 — `private_spend` admission control (RT-2 High), PocketIC
// =============================================================================
//
// The pool under test is SHIELDED_POOL_TEST_WASM (for the has_active_device
// mock) pointed at ITSELF through the typed raw upgrade arg; the REAL verifier
// runs the attack arms, the stub the concurrency arm. The exact-ns rolling
// boundary is proven natively (`harden04_tests` in the pool crate); PocketIC
// rounds move the clock, so here the boundary is probed with a 1 s margin.

mod harden04_common;
use harden04_common::*;

use candid::Principal;

const A: u8 = 0xA1;
const B: u8 = 0xB2;
const C: u8 = 0xC3;
const H: u8 = 0xD4;
const WINDOW: u64 = 3_600_000_000_000;

/// PRODUCTION pool, real verifier, vetkeys ref → a stand-in answering Ok(true)
/// (every caller holds an active device). Returns the stand-in too.
fn gated_with() -> (Inst, Principal) {
    let i = setup(pool_wasm(), VerifierKind::Real);
    let stand_in = i.install_device_stand_in(Ok(true));
    (i, stand_in)
}

fn gated() -> Inst {
    gated_with().0
}

fn assert_code(r: &Result<(), PoolError>, code: &str) -> u64 {
    match admission(r) {
        Some((c, retry)) if c == code => retry,
        _ => panic!("expected SPEND_ADMISSION code {code}, got {r:?}"),
    }
}

/// Drive `caller` to 3 recorded failures with junk spends (ids from `base`).
fn three_failures(i: &Inst, caller: u8, base: u64) {
    for k in 0..3u64 {
        let r = i.spend(p(caller), junk(base + k, base + k));
        assert!(matches!(r, Err(PoolError::ProofRejected(_))), "junk {k}: {r:?}");
    }
}

/// §R — the packet's pool arg bytes, applied byte-for-byte on a real upgrade.
#[test]
fn harden04_packet_pool_upgrade_arg_bytes_apply() {
    let vk = Principal::from_text("a7l2d-caaaa-aaaar-qchja-cai").unwrap();
    let bytes = candid::encode_args((Some(PoolUpgradeArg { vetkeys_canister: Some(vk) }),)).unwrap();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "4449444c036e016c018db7f2a701026e6801000101010a00000000023011d20101");
    let i = setup(pool_wasm(), VerifierKind::Real);
    assert_eq!(i.vetkeys_ref(), None, "fresh pool: ref unset (gate skipped)");
    i.upgrade_pool(pool_wasm(), bytes).expect("the packet's exact bytes upgrade the PRODUCTION pool");
    assert_eq!(i.vetkeys_ref(), Some(vk));
    // Routine upgrades preserve it.
    i.upgrade_pool(pool_wasm(), vec![]).expect("empty arg");
    i.upgrade_pool(pool_wasm(), candid::encode_args(()).unwrap()).expect("()");
    assert_eq!(i.vetkeys_ref(), Some(vk));
    // Production traps on anonymous and on self.
    for bad in [Principal::anonymous(), i.pool] {
        let r = i.upgrade_pool(
            pool_wasm(),
            candid::encode_args((Some(PoolUpgradeArg { vetkeys_canister: Some(bad) }),)).unwrap(),
        );
        assert!(r.is_err(), "{bad} must trap the production upgrade");
        assert_eq!(i.vetkeys_ref(), Some(vk), "unchanged");
    }
    // An undecodable arg traps too.
    assert!(i.upgrade_pool(pool_wasm(), vec![0xDE, 0xAD]).is_err());
}

/// T1 attack refused (a), T2 rolling expiry, T3 survives upgrade.
#[test]
fn t1_t2_t3_failed_verify_limit_rolls_and_survives_upgrade() {
    let (i, stand_in) = gated_with();
    three_failures(&i, A, 100);

    // T1: call 4 refused BEFORE the verifier.
    let before = i.verifier_cycles();
    let r4 = i.spend(p(A), junk(103, 103));
    let after = i.verifier_cycles();
    let retry = assert_code(&r4, "FAILED_VERIFY_LIMIT");
    assert!(retry > 0 && retry <= WINDOW, "retry {retry}");
    assert!(before.saturating_sub(after) < 50_000_000, "verifier burned {}", before - after);
    assert!(i.status(p(A), 103).is_none(), "no record written for a refused call");

    // T3: survives an empty-arg upgrade; the ref is preserved.
    i.upgrade_pool(pool_wasm(), vec![]).expect("empty-arg upgrade");
    i.pic.tick();
    assert_eq!(i.vetkeys_ref(), Some(stand_in), "the ref is preserved");
    let r = i.spend(p(A), junk(104, 104));
    assert_code(&r, "FAILED_VERIFY_LIMIT");

    // T2: 1 s before the returned horizon — still refused; at/after it — admitted.
    let horizon = i.now() + retry;
    i.pic.advance_time(std::time::Duration::from_nanos(retry - 1_000_000_000));
    i.pic.tick();
    assert_code(&i.spend(p(A), junk(105, 105)), "FAILED_VERIFY_LIMIT");
    let now = i.now();
    if now < horizon {
        i.pic.advance_time(std::time::Duration::from_nanos(horizon - now));
    }
    i.pic.tick();
    let r = i.spend(p(A), junk(106, 106));
    assert!(matches!(r, Err(PoolError::ProofRejected(_))), "admitted at the horizon: {r:?}");
}

/// T4 isolation: with A blocked, B's valid spend finalizes; B then gets
/// blocked by its own junk and A is unchanged.
#[test]
fn t4_isolation() {
    let i = gated();
    three_failures(&i, A, 200);
    assert_code(&i.spend(p(A), junk(203, 203)), "FAILED_VERIFY_LIMIT");
    i.spend(p(B), valid(210)).expect("B's valid spend");
    assert!(matches!(i.status(p(B), 210).unwrap().status, SpendStatus::Finalized));
    three_failures(&i, B, 220);
    assert_code(&i.spend(p(B), junk(223, 223)), "FAILED_VERIFY_LIMIT");
    assert_code(&i.spend(p(A), junk(224, 224)), "FAILED_VERIFY_LIMIT");
}

/// T5 honest unaffected: successes are never recorded. H finalizes a valid
/// spend in each of six fresh instances; in the last one H's 2 junk + a 3rd
/// junk are all ADMITTED (the success did not count as a failure).
#[test]
fn t5_honest_successes_never_count() {
    for k in 0..6u64 {
        let i = gated();
        i.spend(p(H), valid(300 + k)).unwrap_or_else(|e| panic!("instance {k}: {e:?}"));
        assert!(matches!(i.status(p(H), 300 + k).unwrap().status, SpendStatus::Finalized));
        if k == 5 {
            for j in 0..3u64 {
                let r = i.spend(p(H), junk(310 + j, 310 + j));
                assert!(matches!(r, Err(PoolError::ProofRejected(_))), "H attempt {} admitted: {r:?}", j + 2);
            }
        }
    }
}

/// T6 device gate (b).
#[test]
fn t6_device_gate() {
    let (i, stand_in) = gated_with();
    // C has no active device: refused before the verifier.
    i.set_device_reply(stand_in, Ok(false));
    let before = i.verifier_cycles();
    let r = i.spend(p(C), valid(400));
    assert_code(&r, "NO_ACTIVE_DEVICE");
    assert!(before.saturating_sub(i.verifier_cycles()) < 50_000_000);
    assert!(i.status(p(C), 400).is_none());

    // Typed vetkeys refusals → DEVICE_CHECK_UNAVAILABLE (never "no device").
    for refusal in [DeviceCheckRefusal::CallerNotConfigured, DeviceCheckRefusal::CallerNotAuthorized] {
        i.set_device_reply(stand_in, Err(refusal));
        assert_code(&i.spend(p(A), junk(401, 401)), "DEVICE_CHECK_UNAVAILABLE");
    }
    i.set_device_reply(stand_in, Ok(true));
    let r = i.spend(p(A), junk(402, 402));
    assert!(matches!(r, Err(PoolError::ProofRejected(_))), "an active device → A proceeds: {r:?}");

    // A STOPPED vetkeys → DEVICE_CHECK_UNAVAILABLE (fail closed).
    let dead = i.pic.create_canister();
    i.pic.add_cycles(dead, 1_000_000_000_000);
    i.pic.stop_canister(dead, None).expect("stop");
    i.set_vetkeys_ref(dead);
    assert_code(&i.spend(p(A), junk(403, 403)), "DEVICE_CHECK_UNAVAILABLE");
    // An EMPTY (no module) vetkeys → DEVICE_CHECK_UNAVAILABLE as well.
    let empty = i.pic.create_canister();
    i.pic.add_cycles(empty, 1_000_000_000_000);
    i.set_vetkeys_ref(empty);
    assert_code(&i.spend(p(A), junk(404, 404)), "DEVICE_CHECK_UNAVAILABLE");

    // With the ref UNSET (fresh pool, no arg) the gate is skipped: C proceeds.
    let fresh = setup(pool_wasm(), VerifierKind::Real);
    assert_eq!(fresh.vetkeys_ref(), None);
    fresh.spend(p(C), valid(405)).expect("gate skipped while unset");
    assert!(matches!(fresh.status(p(C), 405).unwrap().status, SpendStatus::Finalized));
}

/// T7 in-flight (d): four concurrent submissions from A → at most 3 proceed,
/// the 4th is INFLIGHT_LIMIT; B is unaffected.
#[test]
fn t7_inflight_cap() {
    let pin = [0x77u8; 32];
    let i = setup(pool_wasm(), VerifierKind::StubAttested { pin });
    i.install_device_stand_in(Ok(true));
    let mk = |id: u64| {
        let mut a = fresh_nullifier(id, id);
        a.envelope.verifying_key_hash = pin;
        a
    };
    let ids: Vec<_> = (0..4u64).map(|k| i.submit(p(A), mk(500 + k))).collect();
    let b_id = i.submit(p(B), mk(510));
    let results: Vec<_> = ids.into_iter().map(|id| i.await_spend(id)).collect();
    let limited = results
        .iter()
        .filter(|r| admission(r).map(|(c, _)| c == "INFLIGHT_LIMIT").unwrap_or(false))
        .count();
    assert_eq!(limited, 1, "exactly the 4th concurrent call is refused: {results:?}");
    let b = i.await_spend(b_id);
    assert!(
        admission(&b).map(|(c, _)| c != "INFLIGHT_LIMIT").unwrap_or(true),
        "B is unaffected: {b:?}"
    );
    // Afterwards (all resolved) A may enter again.
    let r = i.spend(p(A), mk(520));
    assert!(admission(&r).map(|(c, _)| c != "INFLIGHT_LIMIT").unwrap_or(true), "{r:?}");
}

/// T8 same-nullifier (c): two concurrent submissions of the same valid spend
/// (distinct spend_ids) → one reaches the verifier, the other is
/// NullifierReserved with no record written.
#[test]
fn t8_same_nullifier_single_verify() {
    // Calibrate ONE verify's verifier-side cost on a separate instance.
    let cal = gated();
    let c0 = cal.verifier_cycles();
    cal.spend(p(A), valid(599)).expect("calibration spend");
    let one = c0.saturating_sub(cal.verifier_cycles());
    assert!(one > 50_000_000, "a verify is visibly expensive ({one})");

    let i = gated();
    let before = i.verifier_cycles();
    let id1 = i.submit(p(A), valid(600));
    let id2 = i.submit(p(A), valid(601));
    let r1 = i.await_spend(id1);
    let r2 = i.await_spend(id2);
    let burned = before.saturating_sub(i.verifier_cycles());
    let (ok, reserved): (Vec<_>, Vec<_>) = [(600u64, r1), (601u64, r2)]
        .into_iter()
        .partition(|(_, r)| r.is_ok());
    assert_eq!(ok.len(), 1, "exactly one spend finalizes: {ok:?} / {reserved:?}");
    assert_eq!(reserved.len(), 1);
    assert_eq!(reserved[0].1, Err(PoolError::NullifierReserved), "{reserved:?}");
    assert!(i.status(p(A), reserved[0].0).is_none(), "no record for the refused twin");
    assert!(burned * 2 > one, "one verify happened ({burned} vs one = {one})");
    assert!(burned * 2 < one * 3, "and only one ({burned} vs one = {one})");
}

/// T9 pre-change contrast: the same script against the LIVE pre-change pool —
/// call 4 reaches the verifier (the attack was unbounded).
#[test]
fn t9_pre_change_pool_lets_call_four_reach_the_verifier() {
    let i = setup(live_pool_wasm(), VerifierKind::Real);
    three_failures(&i, A, 700);
    let before = i.verifier_cycles();
    let r = i.spend(p(A), junk(703, 703));
    assert!(matches!(r, Err(PoolError::ProofRejected(_))), "pre-change: {r:?}");
    assert!(before.saturating_sub(i.verifier_cycles()) > 50_000_000, "call 4 was verified");
}

/// T10 — the disclosed idempotent-resubmit wart (C-3), pinned exactly as
/// documented: a Finalized spend resubmitted by a principal at 3 failures gets
/// FAILED_VERIFY_LIMIT, and `get_spend_status` still reads Finalized.
#[test]
fn t10_idempotent_resubmit_wart_is_exactly_as_disclosed() {
    let i = gated();
    i.spend(p(H), valid(800)).expect("S finalizes");
    assert_eq!(i.spend(p(H), valid(800)), Ok(()), "idempotent Ok before any failure");
    three_failures(&i, H, 810);
    assert_code(&i.spend(p(H), valid(800)), "FAILED_VERIFY_LIMIT");
    assert!(matches!(i.status(p(H), 800).unwrap().status, SpendStatus::Finalized), "no state effect");
}

/// The production pool ships the readback and carries NO device mock.
#[test]
fn production_pool_ships_the_readback_and_no_device_mock() {
    let prod = pool_wasm();
    let has = |w: &[u8], n: &[u8]| w.windows(n.len()).any(|x| x == n);
    assert!(has(&prod, b"canister_query get_vetkeys_canister"), "the readback ships");
    assert!(!has(&prod, b"canister_query has_active_device"), "the pool never answers the device check");
}

/// The stand-in answers with exactly the pinned wire bytes (the drift lock the
/// pool and vetkeys crates both assert).
#[test]
fn device_stand_in_replies_with_the_pinned_wire_bytes() {
    let pic = pocket_ic::PocketIc::new();
    let c = pic.create_canister();
    pic.add_cycles(c, 1_000_000_000_000);
    pic.install_canister(c, device_stand_in_wasm(&Ok(false)), vec![], None);
    let raw = pic
        .query_call(c, Principal::anonymous(), "has_active_device", candid::encode_one(Principal::anonymous()).unwrap())
        .expect("query");
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "4449444c026b02bc8a017ec5fed201016b02e3d3f4b9087f86f6afc10b7f01000000");
}
