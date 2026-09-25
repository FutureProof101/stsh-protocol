// =============================================================================
// LAUNCH-HARDEN-04 O-5 — verifier VK drift (RZ-3), PocketIC
// =============================================================================
//
// The pool re-attests the verifier's LIVE `vk_hash` against its pin whenever
// its (verifier, pin) attestation cache misses, on the three paths that used to
// skip it: the init-wired verifier, a scheduled pin swap, and an in-place
// verifier Wasm upgrade (caught after a pool upgrade re-arms the revalidation
// timer). The stub verifier accepts every proof and reports a configurable
// `vk_hash`, so a mismatch is the ONLY thing that can refuse these spends.
// No vetkeys reference is set (G-4: the device gate is skipped).

mod harden04_common;
use harden04_common::*;

const P: [u8; 32] = [0x50; 32];
const X: [u8; 32] = [0x58; 32];
const P2: [u8; 32] = [0x52; 32];
const USER_SPENDER: u8 = 0xE1;

fn args_under(pin: [u8; 32], spend_id: u64, seed: u64) -> PrivateSpendArgs {
    let mut a = fresh_nullifier(spend_id, seed);
    a.envelope.verifying_key_hash = pin;
    a
}

fn valid_under(pin: [u8; 32], spend_id: u64) -> PrivateSpendArgs {
    let mut a = valid(spend_id);
    a.envelope.verifying_key_hash = pin;
    a
}

fn reinstall_stub(i: &Inst, vk: [u8; 32]) {
    i.pic
        .reinstall_canister(i.verifier, stub_verifier_wasm(), candid::encode_one(Some(vk)).unwrap(), None)
        .expect("reinstall stub");
}

/// Init path: the InitArgs-wired verifier used to be trusted unattested.
#[test]
fn init_wired_verifier_is_attested_before_the_first_spend() {
    let i = setup(pool_wasm(), VerifierKind::StubViaInit { vk: X, pin: P });
    let who = p(USER_SPENDER);
    let r = i.spend(who, valid_under(P, 1));
    assert_eq!(r, Err(PoolError::VerifierKeyHashMismatch), "{r:?}");
    assert!(i.status(who, 1).is_none(), "no record written");
    reinstall_stub(&i, P);
    i.spend(who, valid_under(P, 1)).expect("the SAME spend_id succeeds once the VK matches");
    assert!(matches!(i.status(who, 1).unwrap().status, SpendStatus::Finalized));
}

/// In-place verifier swap at the same principal, caught after a pool upgrade
/// (the post_upgrade-armed revalidation timer invalidates the stale cache).
#[test]
fn in_place_verifier_swap_is_caught_after_a_pool_upgrade() {
    let i = setup(pool_wasm(), VerifierKind::StubAttested { pin: P });
    let who = p(USER_SPENDER);
    i.spend(who, valid_under(P, 10)).expect("OK at P");
    reinstall_stub(&i, X);
    i.upgrade_pool(pool_wasm(), vec![]).expect("pool upgrade");
    i.pic.tick();
    i.pic.tick();
    let r = i.spend(who, args_under(P, 11, 11));
    assert_eq!(r, Err(PoolError::VerifierKeyHashMismatch), "{r:?}");
}

/// A scheduled pin swap misses the cache key by construction.
#[test]
fn scheduled_pin_swap_forces_reattestation() {
    let i = setup(pool_wasm(), VerifierKind::StubAttested { pin: P });
    let who = p(USER_SPENDER);
    let now = i.now();
    let r: Result<(), String> = decode(
        "schedule_vk_activation",
        i.pic.update_call(
            i.pool,
            p(GOVERNANCE),
            "schedule_vk_activation",
            candid::encode_args((0u32, P2, now + 60_000_000_000, now + 120_000_000_000)).unwrap(),
        ),
    );
    r.expect("schedule");
    i.pic.advance_time(std::time::Duration::from_secs(90));
    i.pic.tick();
    let r = i.spend(who, valid_under(P2, 20));
    assert_eq!(r, Err(PoolError::VerifierKeyHashMismatch), "stub still at P: {r:?}");
    reinstall_stub(&i, P2);
    i.spend(who, valid_under(P2, 21)).expect("stub at P2 → proceeds");
}

/// `set_verifier_canister` to a matching stub stamps the cache; the next spend
/// succeeds.
#[test]
fn set_verifier_canister_to_a_matching_stub_then_spend() {
    let i = setup(pool_wasm(), VerifierKind::StubViaInit { vk: X, pin: P });
    let who = p(USER_SPENDER);
    let other = i.pic.create_canister();
    i.pic.add_cycles(other, 2_000_000_000_000);
    i.pic.install_canister(other, stub_verifier_wasm(), candid::encode_one(Some(P)).unwrap(), None);
    let r: Result<(), PoolError> = decode(
        "set_verifier_canister",
        i.pic.update_call(i.pool, p(CONTROLLER), "set_verifier_canister", candid::encode_args((other, P.to_vec())).unwrap()),
    );
    r.expect("attested set");
    i.spend(who, valid_under(P, 30)).expect("spend through the matching verifier");
}

/// Pre-change contrast: against the LIVE pre-change pool, the in-place swap is
/// NOT caught — the spend proceeds (undetected drift).
#[test]
fn pre_change_pool_does_not_catch_the_in_place_swap() {
    let i = setup(live_pool_wasm(), VerifierKind::StubAttested { pin: P });
    let who = p(USER_SPENDER);
    reinstall_stub(&i, X);
    i.spend(who, valid_under(P, 40)).expect("pre-change: the drifted verifier is used unchecked");
}
