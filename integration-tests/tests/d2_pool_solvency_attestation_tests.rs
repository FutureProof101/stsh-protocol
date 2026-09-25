// =============================================================================
// STSH — D-2: the pool's certified solvency attestation, end to end (PocketIC)
// Smoke-alarm completion lane. Brief V3 (5cd256c8…), SSA GREEN (84bdff2d…).
// =============================================================================
//
// WHY THESE ARE HERE AND NOT NATIVE. The pool's certification is ARMED at
// runtime by init/post_upgrade, so a host build certifies nothing at all — an
// unarmed no-op would "pass" any native assertion about a certified root while
// proving nothing. Every claim about the certificate, the witness, the tree, or
// the root therefore lives in this file, on a real canister. The clamp, the
// bucket arithmetic and the byte layout are separately proven native (see
// `solvency_attestation_tests` in the pool crate) and are NOT re-litigated here.
//
// PRODUCTION Wasm. The pool under test is `POOL_WASM`, the shipped artifact,
// except where a test explicitly needs the accounting injector (POOL_TEST_WASM).
//
// SCOPE, stated up front rather than buried:
//   * The UNHEALTHY transition IS now exercised cross-Wasm (D2-I9..I11), using
//     the testing-feature `inject_accounting_buckets_for_test` authorized by CTO
//     ruling 1 (close-rulings disposition 52b15620…). Before that injector
//     existed the branch was unreachable on a real canister at all: through the
//     pool's own paths escrow_backing and private_liability move together and
//     pending_fee_reimbursements is structurally zero (AR1-11), so raw_delta was
//     always 0 and the pool always healthy.
//   * D2-I12 is the ABSENCE PROOF that pairs with it: the release-profile Wasm
//     exports no injector. Test scaffolding reaching production is precisely the
//     risk of adding a hook to an audited canister, so it is asserted, not
//     argued.
//   * STILL NOT CLAIMED: readability while a withdrawal is `SolvencyBlocked`
//     (brief V2 §1). That state is unreachable — `upgrade_tests::test_48` is
//     `#[ignore]`d because withdraw fails closed on InvalidProof until
//     proof-bound withdraw is restored. DEFERRED by CTO ruling 2 to that lane,
//     which must carry it as a named item. D2-I6 (anonymous readability vs the
//     controller-gated bucket read) is the accepted interim evidence and is NOT
//     relabeled as the briefed test.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   ./run_gate.sh
// =============================================================================

use candid::{CandidType, Deserialize, Principal};
use pocket_ic::PocketIc;
use serde::Serialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

// ── Wasm loading ─────────────────────────────────────────────────────────────

fn load(path: &str, label: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {} Wasm {}: {}", label, path, e))
}
fn pool_wasm() -> Vec<u8> { load(env!("POOL_WASM"), "shielded_pool") }
fn pool_test_wasm() -> Vec<u8> { load(env!("POOL_TEST_WASM"), "shielded_pool_test") }

fn p(b: u8) -> Principal { Principal::from_slice(&[b; 29]) }
fn controller() -> Principal { p(0xC0) }

// ── Type mirrors (independent of the canister crate — a mirror that imported
//    the real types could not detect a wire-shape change) ─────────────────────

#[derive(CandidType, Deserialize, Serialize)]
struct PoolInitArgs {
    token_canister: Principal,
    nullifier_canister: Principal,
    merkle_canister: Principal,
    treasury_canister: Principal,
    staking_canister: Principal,
    controller: Principal,
    initial_vk_hash: [u8; 32],
    initial_proof_system: String,
    verifier_canister: Option<Principal>,
}

fn pool_init() -> PoolInitArgs {
    PoolInitArgs {
        token_canister: p(0x21),
        nullifier_canister: p(0x22),
        merkle_canister: p(0x23),
        treasury_canister: p(0x24),
        staking_canister: p(0x25),
        controller: controller(),
        initial_vk_hash: [0u8; 32],
        initial_proof_system: "groth16-bn254".to_string(),
        verifier_canister: None,
    }
}

#[derive(CandidType, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
struct SolvencyAttestation {
    public_delta_e8s: i128,
    healthy: bool,
    attested_at_ns: u64,
    schema_version: u32,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
struct CertifiedSolvencyAttestation {
    attestation: SolvencyAttestation,
    canonical_bytes: ByteBuf,
    certificate: Option<ByteBuf>,
    witness: ByteBuf,
}

// ── Canonical layout constants — transcribed by hand from
//    docs/SOLVENCY_ATTESTATION_SPEC.md, never imported from the pool ──────────

const DOMAIN_TAG: &[u8; 24] = b"stsh-pool-attestation-v1";
const CANONICAL_LEN: usize = 53;
const TREE_KEY: &[u8] = b"solvency_attestation";
const BUCKET_NS: u64 = 300_000_000_000;

struct ParsedLeaf {
    schema_version: u32,
    healthy: bool,
    public_delta_e8s: i128,
    attested_at_ns: u64,
}

/// Fail-closed parse of the committed leaf, per the spec's parser rules.
fn parse_leaf(b: &[u8]) -> ParsedLeaf {
    assert_eq!(b.len(), CANONICAL_LEN, "canonical leaf length");
    assert_eq!(&b[0..24], DOMAIN_TAG, "domain tag");
    let flags = b[28];
    assert_eq!(flags & !0b1, 0, "reserved flag bits must be zero");
    let public_delta_e8s = i128::from_be_bytes(b[29..45].try_into().unwrap());
    assert!(public_delta_e8s <= 0, "the published delta must never be positive");
    ParsedLeaf {
        schema_version: u32::from_be_bytes(b[24..28].try_into().unwrap()),
        healthy: flags & 0b1 != 0,
        public_delta_e8s,
        attested_at_ns: u64::from_be_bytes(b[45..53].try_into().unwrap()),
    }
}

// ── PocketIC helpers ─────────────────────────────────────────────────────────

fn install_pool(pic: &PocketIc, wasm: Vec<u8>) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 5_000_000_000_000);
    pic.install_canister(cid, wasm, candid::encode_one(pool_init()).unwrap(), None);
    cid
}

fn upgrade_pool(pic: &PocketIc, pool: Principal) {
    pic.upgrade_canister(pool, pool_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("pool upgrade must succeed (pre/post_upgrade hooks must not trap)");
}

/// ANONYMOUS query — the endpoint carries no caller gate by design (unlike
/// `get_accounting_state`), so every read here goes through the anonymous path
/// and the absence of a gate is asserted rather than assumed.
fn get_attestation(pic: &PocketIc, pool: Principal) -> CertifiedSolvencyAttestation {
    let bytes = pic
        .query_call(
            pool,
            Principal::anonymous(),
            "get_solvency_attestation",
            candid::encode_args(()).unwrap(),
        )
        .expect("get_solvency_attestation must be callable anonymously");
    candid::decode_one(&bytes).expect("decode CertifiedSolvencyAttestation")
}

// ── Hash-tree verification (IC spec domain separation) ───────────────────────

use serde_cbor::Value;

fn unwrap_tag(v: &Value) -> &Value {
    match v { Value::Tag(_, inner) => unwrap_tag(inner), other => other }
}
fn node_array(v: &Value) -> &Vec<Value> {
    match unwrap_tag(v) { Value::Array(a) => a, o => panic!("node must be array: {:?}", o) }
}
fn node_tag(a: &[Value]) -> i128 {
    match unwrap_tag(&a[0]) { Value::Integer(i) => *i, o => panic!("tag must be int: {:?}", o) }
}
fn node_bytes(v: &Value) -> Vec<u8> {
    match unwrap_tag(v) { Value::Bytes(b) => b.clone(), o => panic!("expected bytes: {:?}", o) }
}
fn domain_sep(h: &mut Sha256, sep: &str) {
    h.update([sep.len() as u8]);
    h.update(sep.as_bytes());
}
fn tree_digest(v: &Value) -> [u8; 32] {
    let arr = node_array(v);
    let mut h = Sha256::new();
    match node_tag(arr) {
        0 => domain_sep(&mut h, "ic-hashtree-empty"),
        1 => {
            domain_sep(&mut h, "ic-hashtree-fork");
            h.update(tree_digest(&arr[1]));
            h.update(tree_digest(&arr[2]));
        }
        2 => {
            domain_sep(&mut h, "ic-hashtree-labeled");
            h.update(node_bytes(&arr[1]));
            h.update(tree_digest(&arr[2]));
        }
        3 => { domain_sep(&mut h, "ic-hashtree-leaf"); h.update(node_bytes(&arr[1])); }
        4 => return node_bytes(&arr[1]).try_into().expect("pruned hash is 32 bytes"),
        t => panic!("unknown hash tree node tag {}", t),
    }
    h.finalize().into()
}
fn tree_lookup(v: &Value, path: &[&[u8]]) -> Option<Vec<u8>> {
    let arr = node_array(v);
    let tag = node_tag(arr);
    if path.is_empty() {
        return if tag == 3 { Some(node_bytes(&arr[1])) } else { None };
    }
    match tag {
        1 => tree_lookup(&arr[1], path).or_else(|| tree_lookup(&arr[2], path)),
        2 => if node_bytes(&arr[1]) == path[0] { tree_lookup(&arr[2], &path[1..]) } else { None },
        _ => None,
    }
}
fn certified_data_from_certificate(cert: &[u8], canister: Principal) -> Vec<u8> {
    let cert: Value = serde_cbor::from_slice(cert).expect("certificate CBOR decode");
    let map = match unwrap_tag(&cert) {
        Value::Map(m) => m,
        o => panic!("certificate must be a map: {:?}", o),
    };
    let tree = map.get(&Value::Text("tree".to_string())).expect("certificate has no tree");
    tree_lookup(tree, &[b"canister", canister.as_slice(), b"certified_data"])
        .expect("no certified_data for this canister")
}

/// The full chain, in one place: certificate → certified_data → witness root →
/// the leaf under TREE_KEY → the bytes the canister also returned.
/// Returns the witness-verified leaf bytes.
fn verified_leaf(pic: &PocketIc, pool: Principal, c: &CertifiedSolvencyAttestation) -> Vec<u8> {
    let _ = pic;
    let cert = c.certificate.as_ref().expect("a certified query must carry a certificate");
    let certified_data = certified_data_from_certificate(cert, pool);

    let witness: Value = serde_cbor::from_slice(c.witness.as_ref()).expect("witness CBOR decode");
    let witness_root = tree_digest(&witness);
    assert_eq!(
        witness_root.to_vec(),
        certified_data,
        "witness root must equal the certificate's certified_data — otherwise the \
         witness describes a tree the subnet never signed"
    );

    let leaf = tree_lookup(&witness, &[TREE_KEY]).expect("witness has no solvency_attestation leaf");
    assert_eq!(
        leaf,
        c.canonical_bytes.as_ref().to_vec(),
        "the WITNESS-VERIFIED leaf must equal canonical_bytes; a mismatch means the \
         Candid convenience field is not what was certified"
    );
    leaf
}

// ═════════════════════════════════════════════════════════════════════════════
// D2-I1 — the certified read is a real certified read
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn d2_i1_certificate_witness_and_canonical_bytes_agree() {
    let pic = PocketIc::new();
    let pool = install_pool(&pic, pool_wasm());

    let c = get_attestation(&pic, pool);
    let leaf = verified_leaf(&pic, pool, &c);

    // The verified leaf parses, and it says the same thing as the Candid record.
    let parsed = parse_leaf(&leaf);
    assert_eq!(parsed.schema_version, c.attestation.schema_version);
    assert_eq!(parsed.healthy, c.attestation.healthy);
    assert_eq!(parsed.public_delta_e8s, c.attestation.public_delta_e8s);
    assert_eq!(parsed.attested_at_ns, c.attestation.attested_at_ns);
}

// ═════════════════════════════════════════════════════════════════════════════
// D2-I2 — init certifies. A pool that has never been touched is already
//         certified, which is what stops the first reader seeing an empty tree.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn d2_i2_init_certifies_before_any_accounting_activity() {
    let pic = PocketIc::new();
    let pool = install_pool(&pic, pool_wasm());

    let c = get_attestation(&pic, pool);
    // A certificate exists at all — the negative case is a canister that never
    // called set_certified_data, whose data_certificate carries nothing to find.
    let leaf = verified_leaf(&pic, pool, &c);
    assert_eq!(leaf.len(), CANONICAL_LEN);

    // A freshly installed pool is zeroed, hence healthy and publishing zero.
    assert!(c.attestation.healthy, "a zeroed pool is solvent");
    assert_eq!(c.attestation.public_delta_e8s, 0);
    assert_eq!(c.attestation.schema_version, 1);
}

// ═════════════════════════════════════════════════════════════════════════════
// D2-I3 — the timestamp that reaches the public is BUCKETED
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn d2_i3_published_timestamp_is_floored_to_a_bucket_boundary() {
    let pic = PocketIc::new();
    let pool = install_pool(&pic, pool_wasm());

    let c = get_attestation(&pic, pool);
    let t = c.attestation.attested_at_ns;
    assert_eq!(
        t % BUCKET_NS,
        0,
        "attested_at_ns must sit exactly on a 300 s boundary; {t} does not"
    );

    // And it never claims to be newer than the chain: the certified stamp is at
    // or before the canister's own clock.
    let now = pic.get_time().as_nanos_since_unix_epoch();
    assert!(t <= now, "a floored stamp can never be in the future: {t} > {now}");
}

// ═════════════════════════════════════════════════════════════════════════════
// D2-I4 — post_upgrade RE-CERTIFIES.
//
// Certified data does not survive an upgrade. Before this hook existed, a pool
// that had been upgraded would answer queries with a witness whose root no
// longer matched anything the subnet had signed. The assertion below is exactly
// that chain re-verified after the upgrade, not merely "the query still returns".
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn d2_i4_post_upgrade_recertifies_the_attestation() {
    let pic = PocketIc::new();
    let pool = install_pool(&pic, pool_wasm());

    let before = get_attestation(&pic, pool);
    let before_leaf = verified_leaf(&pic, pool, &before);

    // Installing the pool burns enough instructions that a second install_code
    // in the same instant is rate-limited by the subnet. Advance the clock past
    // the limiter before upgrading — this is an artefact of the harness, not of
    // the lane, and skipping it would flake rather than fail honestly.
    for _ in 0..30 {
        pic.advance_time(std::time::Duration::from_secs(60));
        pic.tick();
    }

    // Empty upgrade args, matching the in-tree helper: the pool's post_upgrade
    // takes none. Sender None = the PocketIC canister controller, which is the
    // authority ic00 install_code answers to (NOT the pool's `controller` arg).
    upgrade_pool(&pic, pool);

    let after = get_attestation(&pic, pool);
    // THE POINT: the full certificate → witness → leaf chain verifies again.
    let after_leaf = verified_leaf(&pic, pool, &after);

    // Accounting did not move across the upgrade, so the payload is the same
    // statement; only the bucket may have advanced.
    let (b, a) = (parse_leaf(&before_leaf), parse_leaf(&after_leaf));
    assert_eq!(b.healthy, a.healthy);
    assert_eq!(b.public_delta_e8s, a.public_delta_e8s);
    assert!(a.attested_at_ns >= b.attested_at_ns, "the bucket must not go backwards");
}

// ═════════════════════════════════════════════════════════════════════════════
// D2-I5 — a healthy accounting mutation does NOT move the certified root.
//
// This is the privacy property, executed on a real canister: the piggyback is
// hooked to the accounting funnel, so it RUNS on this mutation — and must still
// publish nothing, because the public payload did not change. A build that
// re-certified on every mutation would move the root here and fail.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn d2_i5_healthy_accounting_mutation_leaves_the_certified_root_unmoved() {
    let pic = PocketIc::new();
    // The injector lives only in the testing build.
    let pool = install_pool(&pic, pool_test_wasm());

    let before = get_attestation(&pic, pool);
    let before_leaf = verified_leaf(&pic, pool, &before);
    let before_root = certified_data_from_certificate(
        before.certificate.as_ref().unwrap(),
        pool,
    );

    // A real accounting mutation through the real funnel: liability and escrow
    // both move to 5_000, which is a HEALTHY state (raw_delta stays 0).
    let _: () = candid::decode_one(
        &pic.update_call(
            pool,
            controller(),
            "inject_private_liability_for_test",
            candid::encode_one(5_000u128).unwrap(),
        )
        .expect("inject must succeed"),
    )
    .expect("inject returns unit");

    let after = get_attestation(&pic, pool);
    let after_leaf = verified_leaf(&pic, pool, &after);
    let after_root =
        certified_data_from_certificate(after.certificate.as_ref().unwrap(), pool);

    assert_eq!(
        before_leaf, after_leaf,
        "a healthy accounting mutation must leave the certified LEAF byte-identical"
    );
    assert_eq!(
        before_root, after_root,
        "and therefore the certified ROOT must not move — moving it would publish \
         the fact that accounting changed, which is the activity signal the clamp \
         and the bucket exist to remove"
    );
    assert!(after.attestation.healthy && after.attestation.public_delta_e8s == 0);
}

/// Set the two solvency-bearing buckets INDEPENDENTLY, through the real funnel.
/// TEST-BUILD ONLY (CTO ruling 1); controller-gated even so. This is the only
/// way to reach an unhealthy pool — see the scope note at the top of the file.
fn inject_buckets(pic: &PocketIc, pool: Principal, escrow: u128, liability: u128) {
    let _: () = candid::decode_one(
        &pic.update_call(
            pool,
            controller(),
            "inject_accounting_buckets_for_test",
            candid::encode_args((escrow, liability)).unwrap(),
        )
        .expect("inject_accounting_buckets_for_test must succeed"),
    )
    .expect("inject returns unit");
}

/// Drive a real accounting mutation through the pool's own funnel.
/// TEST-BUILD ONLY endpoint; controller-gated even so.
fn inject(pic: &PocketIc, pool: Principal, amount: u128) {
    let _: () = candid::decode_one(
        &pic.update_call(
            pool,
            controller(),
            "inject_private_liability_for_test",
            candid::encode_one(amount).unwrap(),
        )
        .expect("inject must succeed"),
    )
    .expect("inject returns unit");
}

// ═════════════════════════════════════════════════════════════════════════════
// D2-I7 — THE ACTIVITY LEAK, closed. A healthy accounting mutation AFTER the
//         bucket has rolled must STILL not move the certified root.
//
// This arm exists because I5 did not catch it. Mutation-testing I5 with an
// unconditionally-publishing piggyback left all six tests green: within one
// bucket, republishing an unchanged payload re-encodes to the same bytes, so the
// root does not move whether the piggyback is conditional or not. I5 therefore
// proves the ROOT is stable, not that the PIGGYBACK is narrow.
//
// The difference only becomes observable once the bucket rolls. An
// unconditional piggyback would stamp the new bucket onto a healthy payload the
// moment accounting moved — publishing "something happened, and roughly when",
// which is precisely the activity signal SSA's GREEN clarification 1 forbids.
// Only the heartbeat may advance a timestamp-only healthy payload.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn d2_i7_healthy_mutation_after_a_bucket_roll_does_not_advance_the_timestamp() {
    let pic = PocketIc::new();

    // OFFSET THE INSTALL FROM THE BUCKET GRID — this is the whole trick, and
    // without it the property is untestable. The heartbeat fires at
    // install + k*300 s while buckets roll at absolute multiples of 300 s. On a
    // fresh PocketIC the clock starts ON a boundary, so the two coincide exactly
    // and every bucket roll is also a heartbeat: an unconditional piggyback and
    // a conditional one are then indistinguishable. Installing 137 s off the
    // grid puts the next boundary 163 s after install and the first heartbeat at
    // 300 s, opening a 137 s window in which a bucket roll has happened and the
    // heartbeat has NOT run.
    pic.advance_time(std::time::Duration::from_secs(137));
    pic.tick();
    let pool = install_pool(&pic, pool_test_wasm());

    // Seed to a non-zero healthy state FIRST, outside the measurement window.
    // Direction matters: `inject_private_liability_for_test` sets liability and
    // then escrow, through the funnel, in that order — so RAISING it passes
    // through a transient (liability > escrow) unhealthy state that legitimately
    // publishes. LOWERING it does not: liability drops first, which only ever
    // raises raw_delta. The measured step below is therefore a lower, chosen so
    // the mutation is healthy at every intermediate commit, not just at its ends.
    // (See d2_i8 — that transient is a real property and is asserted, not hidden.)
    inject(&pic, pool, 7_777);

    let before = get_attestation(&pic, pool);
    let before_leaf = verified_leaf(&pic, pool, &before);
    let before_stamp = before.attestation.attested_at_ns;

    let install_ns = pic.get_time().as_nanos_since_unix_epoch();
    let next_boundary = ((install_ns / BUCKET_NS) + 1) * BUCKET_NS;
    let to_boundary = next_boundary - install_ns;
    assert!(
        to_boundary < 300_000_000_000 - 10_000_000_000,
        "the test needs a window between the bucket roll and the first heartbeat; \
         install landed {to_boundary} ns from the boundary"
    );

    // Cross the boundary, staying well short of the first heartbeat.
    pic.advance_time(std::time::Duration::from_nanos(to_boundary + 2_000_000_000));
    pic.tick();
    assert_ne!(
        pic.get_time().as_nanos_since_unix_epoch() / BUCKET_NS,
        install_ns / BUCKET_NS,
        "the bucket must actually have rolled for this test to mean anything"
    );

    // The measured step: 7_777 -> 0, healthy at every intermediate commit.
    inject(&pic, pool, 0);

    let after = get_attestation(&pic, pool);
    let after_leaf = verified_leaf(&pic, pool, &after);

    assert_eq!(
        after.attestation.attested_at_ns, before_stamp,
        "a healthy accounting mutation advanced the published timestamp across a \
         bucket roll — that publishes WHEN accounting moved, to 300 s. Only the \
         heartbeat may advance a timestamp-only healthy payload (SSA GREEN §4)"
    );
    assert_eq!(
        before_leaf, after_leaf,
        "and the certified leaf must still be byte-identical"
    );
    assert!(after.attestation.healthy && after.attestation.public_delta_e8s == 0);
}

// ═════════════════════════════════════════════════════════════════════════════
// D2-I8 — the exact BOUND on I7's guarantee, measured rather than assumed.
//
// `commit_pool_accounting` runs once per scalar write, so a message writing two
// scalars is evaluated against the state BETWEEN them. Raising the injected
// amount writes liability first, leaving the pool transiently under-backed; the
// piggyback publishes that intermediate, then publishes the healthy end state.
//
// TWO THINGS FOLLOW, and both are asserted below because the first alone would
// read as "transients are harmless":
//   1. WITHIN one bucket the transient is invisible afterwards — the root moves
//      and comes back, so the settled leaf is byte-identical.
//   2. ACROSS a bucket boundary it is NOT invisible: the republish carries the
//      new bucket, so the published timestamp advances on a mutation whose NET
//      payload never changed. That is a (300 s-granular) activity signal.
//
// So I7's guarantee is exactly: no timestamp advance for mutations that are
// healthy at EVERY intermediate commit. NO SHIPPED PATH CREATES SUCH A
// TRANSIENT — `apply_withdrawal_accounting` and `apply_private_spend_accounting`
// debit liability first (which only raises raw_delta) and the deposit path
// credits escrow first. The test-only injector is the sole exception. This arm
// pins that ordering dependency so a future reordering of a real path surfaces
// here instead of quietly widening the signal.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn d2_i8_transient_is_invisible_within_a_bucket_but_advances_the_stamp_across_one() {
    // ── 1. Within one bucket: settled leaf byte-identical ───────────────────
    let pic = PocketIc::new();
    let pool = install_pool(&pic, pool_test_wasm());

    let before = get_attestation(&pic, pool);
    assert!(before.attestation.healthy && before.attestation.public_delta_e8s == 0);
    let before_leaf = verified_leaf(&pic, pool, &before);

    inject(&pic, pool, 4_242); // raises: transient (liability > escrow) mid-message

    let after = get_attestation(&pic, pool);
    let after_leaf = verified_leaf(&pic, pool, &after);
    assert!(
        after.attestation.healthy && after.attestation.public_delta_e8s == 0,
        "the settled state must be healthy: {:?}",
        after.attestation
    );
    assert_eq!(
        before_leaf, after_leaf,
        "inside one bucket the transient must leave no trace in the settled leaf"
    );

    // ── 2. Across a boundary: the stamp DOES advance ────────────────────────
    let pic2 = PocketIc::new();
    pic2.advance_time(std::time::Duration::from_secs(137)); // off the bucket grid
    pic2.tick();
    let pool2 = install_pool(&pic2, pool_test_wasm());

    let base = get_attestation(&pic2, pool2);
    let base_stamp = base.attestation.attested_at_ns;

    let install_ns = pic2.get_time().as_nanos_since_unix_epoch();
    let next_boundary = ((install_ns / BUCKET_NS) + 1) * BUCKET_NS;
    pic2.advance_time(std::time::Duration::from_nanos(
        next_boundary - install_ns + 2_000_000_000,
    ));
    pic2.tick();

    inject(&pic2, pool2, 4_242); // the SAME transient-creating direction

    let rolled = get_attestation(&pic2, pool2);
    assert!(rolled.attestation.healthy && rolled.attestation.public_delta_e8s == 0);
    assert!(
        rolled.attestation.attested_at_ns > base_stamp,
        "a transient-bearing mutation across a bucket boundary DOES advance the \
         published stamp — this is the measured bound on I7, not a contradiction \
         of it. If this ever stops being true the piggyback has been changed and \
         I7's scope statement needs rewriting with it"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// D2-I6 — the read is PUBLIC, and stays public where get_accounting_state does
//         not. Law #2 adjacency: this endpoint reads accounting words and the
//         certified tree only; it takes no lease and touches no withdrawal.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn d2_i6_attestation_is_anonymous_where_accounting_state_is_controller_only() {
    let pic = PocketIc::new();
    let pool = install_pool(&pic, pool_wasm());

    // The attestation answers an anonymous caller.
    let c = get_attestation(&pic, pool);
    assert_eq!(c.canonical_bytes.len(), CANONICAL_LEN);

    // The CONTROL: the raw-bucket read refuses the same caller. If this ever
    // stopped refusing, the attestation's whole reason for existing (publish the
    // delta, never the buckets) would have quietly evaporated.
    let raw = pic.query_call(
        pool,
        Principal::anonymous(),
        "get_accounting_state",
        candid::encode_args(()).unwrap(),
    );
    assert!(
        raw.is_err(),
        "get_accounting_state must still reject an anonymous caller (DEF-076); \
         if it does not, the per-bucket oracle is open and the clamp is moot"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// D2-I9 — healthy → RED is certified PROMPTLY, before the next heartbeat.
//
// This is brief V3 §6's boundary-crossing probe, discharged cross-Wasm. It is
// the whole reason the piggyback exists: waiting up to one 300 s heartbeat to
// certify an insolvency would make the alarm useless at exactly the moment it
// matters. The window is measured, not assumed — the mutation lands well inside
// one heartbeat period of install, so nothing but the piggyback can have
// published it.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn d2_i9_crossing_into_red_is_certified_before_the_next_heartbeat() {
    let pic = PocketIc::new();
    let pool = install_pool(&pic, pool_test_wasm());

    // Healthy, non-zero, so the transition is a real state change.
    inject_buckets(&pic, pool, 10_000, 10_000);
    let healthy = get_attestation(&pic, pool);
    let healthy_leaf = verified_leaf(&pic, pool, &healthy);
    assert!(healthy.attestation.healthy);
    assert_eq!(healthy.attestation.public_delta_e8s, 0, "healthy publishes zero");

    let install_ns = pic.get_time().as_nanos_since_unix_epoch();

    // Break the backing: escrow falls short of liability by 2_500.
    inject_buckets(&pic, pool, 7_500, 10_000);

    let red = get_attestation(&pic, pool);
    let red_leaf = verified_leaf(&pic, pool, &red);

    // Promptness, measured: less than one heartbeat period has elapsed, so the
    // heartbeat cannot be what published this.
    let elapsed = pic.get_time().as_nanos_since_unix_epoch() - install_ns;
    assert!(
        elapsed < BUCKET_NS,
        "the probe must land inside one heartbeat period to prove promptness; \
         {elapsed} ns elapsed"
    );

    assert!(!red.attestation.healthy, "backing is broken and must read unhealthy");
    assert_eq!(
        red.attestation.public_delta_e8s, -2_500,
        "the violation MAGNITUDE is disclosed — an insolvency is what the public must see"
    );
    assert_ne!(healthy_leaf, red_leaf, "the certified leaf must move on the crossing");

    // The RED state is certified, not merely returned: the whole chain verifies.
    let parsed = parse_leaf(&red_leaf);
    assert!(!parsed.healthy);
    assert_eq!(parsed.public_delta_e8s, -2_500);
}

// ═════════════════════════════════════════════════════════════════════════════
// D2-I10 — a changed violation magnitude moves the certified root, while RED.
//
// V3 §6's magnitude probe. Without this, a pool could go insolvent, get worse,
// and publish the original shortfall until the next bucket rolled.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn d2_i10_magnitude_change_while_red_moves_the_certified_root() {
    let pic = PocketIc::new();
    let pool = install_pool(&pic, pool_test_wasm());

    inject_buckets(&pic, pool, 7_500, 10_000);
    let first = get_attestation(&pic, pool);
    let first_leaf = verified_leaf(&pic, pool, &first);
    let first_root =
        certified_data_from_certificate(first.certificate.as_ref().unwrap(), pool);
    assert_eq!(first.attestation.public_delta_e8s, -2_500);

    // It gets worse.
    inject_buckets(&pic, pool, 6_000, 10_000);
    let worse = get_attestation(&pic, pool);
    let worse_leaf = verified_leaf(&pic, pool, &worse);
    let worse_root =
        certified_data_from_certificate(worse.certificate.as_ref().unwrap(), pool);

    assert!(!worse.attestation.healthy);
    assert_eq!(worse.attestation.public_delta_e8s, -4_000);
    assert_ne!(first_leaf, worse_leaf, "a deeper shortfall must move the leaf");
    assert_ne!(first_root, worse_root, "and therefore the certified ROOT");
}

// ═════════════════════════════════════════════════════════════════════════════
// D2-I11 — recovery RED → healthy RE-CLAMPS to zero.
//
// The clamp must hold on the way back, not only on the way out. A pool that
// recovered but kept publishing its last shortfall would be a false alarm; one
// that recovered to a POSITIVE published delta would leak the float the clamp
// exists to hide. Both are excluded here.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn d2_i11_recovery_from_red_reclamps_to_zero() {
    let pic = PocketIc::new();
    let pool = install_pool(&pic, pool_test_wasm());

    inject_buckets(&pic, pool, 6_000, 10_000);
    let red = get_attestation(&pic, pool);
    assert!(!red.attestation.healthy && red.attestation.public_delta_e8s == -4_000);

    // Recover, and OVERSHOOT: escrow now exceeds liability, so raw_delta > 0.
    // The published value must still be exactly 0 — this is the arm that fails
    // if the clamp is applied only to the negative side.
    inject_buckets(&pic, pool, 25_000, 10_000);

    let recovered = get_attestation(&pic, pool);
    let leaf = verified_leaf(&pic, pool, &recovered);
    assert!(recovered.attestation.healthy, "backing is restored");
    assert_eq!(
        recovered.attestation.public_delta_e8s, 0,
        "a recovered — indeed over-collateralised — pool must publish exactly 0, \
         never the surplus"
    );
    let parsed = parse_leaf(&leaf);
    assert!(parsed.healthy && parsed.public_delta_e8s == 0);
}

// ═════════════════════════════════════════════════════════════════════════════
// D2-I12 — ABSENCE PROOF: the release Wasm carries no injector.
//
// Adding a hook to an audited canister is only acceptable if it demonstrably
// cannot reach production. The test-feature build exports it; the release build
// must not. Asserted against the SHIPPED ARTIFACT's bytes — the thing that would
// actually be deployed — not against source, which is what a reviewer could read
// for themselves anyway.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn d2_i12_release_wasm_exports_no_test_injector() {
    const INJECTORS: [&str; 2] = [
        "inject_accounting_buckets_for_test",
        "inject_private_liability_for_test",
    ];

    let release = pool_wasm();
    let testing = pool_test_wasm();

    // POSITIVE CONTROL FIRST. Without it this test would pass just as well
    // against an empty byte string, or if the search were simply broken.
    for name in INJECTORS {
        assert!(
            contains_bytes(&testing, name.as_bytes()),
            "the testing build must export {name} — if it does not, this test's \
             search is broken and its negative result means nothing"
        );
    }

    for name in INJECTORS {
        assert!(
            !contains_bytes(&release, name.as_bytes()),
            "RELEASE Wasm contains {name}: test scaffolding has reached the \
             production artifact"
        );
    }

    // Sanity: the two artifacts really are different modules.
    assert_ne!(release, testing, "release and testing Wasms must not be identical");
}

/// Naive substring search over Wasm bytes. Candid method names appear verbatim
/// in the export section, so a byte search is sufficient and needs no Wasm
/// parser; the positive control above is what makes the negative meaningful.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
