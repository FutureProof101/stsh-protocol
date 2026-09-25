// =============================================================================
// STSH — Smoke Alarm solvency monitor tests (PocketIC)
// Brief: BRIEF_SMOKE_ALARM_MONITOR.md
// =============================================================================
//
// The monitor is a standalone additive canister reading ONLY public token data
// (verify_supply_invariant + icrc1_balance_of). These tests prove:
//
//   test_sam_01 — timer refresh produces a Fresh, healthy certified snapshot
//                 with figures matching the token
//   test_sam_02 — certified query: certificate present, witness root ==
//                 certified_data in the certificate, witness leaf == the
//                 canonical 89-byte encoding, canonical bytes parse back to
//                 the exact snapshot struct (canister/frontend contract)
//   test_sam_03 — fail closed: token stopped → NEW SourceCallFailed snapshot
//                 (healthy=false, never a stale green); recovers to Fresh
//                 after the token restarts; history ring buffer stays bounded
//   test_sam_04 — supply-invariant violation (test-only balance inflation)
//                 → Fresh but healthy=false, supply_invariant_holds=false
//   test_sam_05 — upgrade preserves config/snapshot/history, re-certifies the
//                 tree, and restarts the refresh timer
//   test_sam_06 — request_refresh liveness valve is rate-limited
//   test_sam_07 — fail closed: nonexistent token canister → SourceCallFailed
//                 from the very first refresh (placeholder never turns green)
//   test_sam_10 — REAL cross-Wasm schema-2 → schema-3 upgrade: the module built
//                 from 115526d is installed, populated with real refreshes, and
//                 upgraded to the current one; the checkpoint must decode, the
//                 figures and history survive, the migrated field reads false,
//                 and the certified leaf comes back tagged v3. test_sam_05 is a
//                 SAME-module upgrade and is structurally unable to bind this.
//
// The certificate/witness checks here use an INDEPENDENT hash-tree
// implementation (serde_cbor + sha2, per the IC certification spec), not
// ic-certified-map — so a canister-side encoding bug cannot self-validate.
// Full BLS signature verification against the root key is the frontend's job
// (@dfinity/certificate-verification), exercised at the launch gate.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7):
//   1. cargo build --target wasm32-unknown-unknown --release -p stsh_token --features testing
//      cp target/wasm32-unknown-unknown/release/stsh_token.wasm \
//         target/wasm32-unknown-unknown/release/stsh_token_test.wasm
//   2. cargo build --target wasm32-unknown-unknown --release \
//          -p stsh_token -p smoke_alarm_monitor
//   3. export POCKET_IC_BIN=$HOME/.cache/dfinity/versions/0.28.0/pocket-ic
//      cargo test -p integration-tests --test smoke_alarm_monitor_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Wasm loading
// ─────────────────────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Cannot read {} Wasm at {}: {}.\n\
             Build first (see file header for the two-phase sequence).",
            pkg, path, e
        )
    })
}

fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
fn token_test_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_TEST_WASM"), "stsh_token_test") }
fn monitor_wasm() -> Vec<u8> { load_wasm(env!("MONITOR_WASM"), "smoke_alarm_monitor") }
/// The PRE-schema-3 monitor (built from 115526d, the last commit before the
/// v2->v3 bump). Its stable checkpoint has NO `supply_invariant_unavailable`
/// field — which is the whole point: test_sam_10 upgrades THIS module to the
/// current one, so the decode it exercises is a genuine cross-Wasm migration.
/// A rebuild from current source would carry the v3 field and turn the test
/// into the same-Wasm round trip test_sam_05 already performs.
fn monitor_pre_v3_wasm() -> Vec<u8> {
    load_wasm(env!("MONITOR_PRE_V3_TEST_WASM"), "smoke_alarm_monitor_pre_v3")
}

// ─────────────────────────────────────────────────────────────────────────────
// Type mirrors — token
// ─────────────────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy {
    ImmediatelyLiquid,
    LockedUntil(u64),
    Vested,
    GovernanceLocked,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy { cliff_end_ns: u64, vesting_end_ns: u64 }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllocationCategory {
    category_id:          String,
    category_name:        String,
    amount:               u128,
    recipient:            Principal,
    subaccount:           Option<[u8; 32]>,
    lock_policy:          LockPolicy,
    vesting_policy:       Option<VestingPolicy>,
    created_at_genesis:   bool,
    genesis_timestamp_ns: u64,
}

#[derive(CandidType, Deserialize)]
struct TokenInitArgs {
    allocations:      Vec<AllocationCategory>,
    treasury:         Principal,
    staking_canister: Principal,
}

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;

/// All supply to `recipient` at genesis.
fn all_to(recipient: Principal) -> TokenInitArgs {
    TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id:          "all".to_string(),
            category_name:        "All tokens".to_string(),
            amount:               TOTAL_SUPPLY,
            recipient,
            subaccount:           None,
            lock_policy:          LockPolicy::ImmediatelyLiquid,
            vesting_policy:       None,
            created_at_genesis:   false,
            genesis_timestamp_ns: 0,
        }],
        treasury:         p(0x01),
        staking_canister: p(0x02),
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account {
    owner:      Principal,
    subaccount: Option<[u8; 32]>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Type mirrors — smoke-alarm monitor
// ─────────────────────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct MonitorInit {
    token_canister:          Principal,
    pool_principal:          Principal,
    // v2 (D-4 / D-2)
    treasury_principal:      Principal,
    pool_attestation_source: Principal,
    refresh_interval_ns:     u64,
    max_staleness_ns:        u64,
    history_capacity:        u32,
}

/// v2 per-source read outcome. Mirrors the canister enum by SHAPE, transcribed
/// by hand — importing it would make a wire change undetectable here.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum SourceReadStatus {
    Ok,
    CallFailed,
    Malformed,
    Stale,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum SnapshotStatus {
    Fresh,
    Stale,
    RefreshFailed,
    SourceCallFailed,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct SolvencySnapshot {
    supply_invariant_holds: bool,
    fixed_max_supply_e8s:   u128,
    sum_all_balances_e8s:   u128,
    pool_balance_e8s:       u128,
    // ── v2 (D-2): the pool attestation, the RED source ─────────────────────
    pool_attestation_source_status: SourceReadStatus,
    pool_delta_healthy:             bool,
    pool_public_delta_e8s:          i128,
    pool_attested_at_ns:            u64,
    // ── v2 (D-4): treasury stray funds, YELLOW only ────────────────────────
    treasury_read_status:           SourceReadStatus,
    treasury_stray_funds_e8s:       u128,
    // ── v3 (R-4): UNAVAILABLE, distinct from VIOLATED ──────────────────────
    supply_invariant_unavailable:   bool,
    refreshed_at_ns:        u64,
    max_staleness_ns:       u64,
    status:                 SnapshotStatus,
    healthy:                bool,
    schema_version:         u32,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct CertifiedSolvencySnapshot {
    snapshot:        SolvencySnapshot,
    canonical_bytes: ByteBuf,
    certificate:     Option<ByteBuf>,
    witness:         ByteBuf,
}

/// Mirror of the schema-2 monitor's `SolvencySnapshot` — no
/// `supply_invariant_unavailable`. Needed to read the PRE-v3 module across the
/// wire before the upgrade: the v3 mirror above declares that field as required
/// and cannot decode a v2 reply.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct SolvencySnapshotPreV3 {
    supply_invariant_holds: bool,
    fixed_max_supply_e8s:   u128,
    sum_all_balances_e8s:   u128,
    pool_balance_e8s:       u128,
    pool_attestation_source_status: SourceReadStatus,
    pool_delta_healthy:             bool,
    pool_public_delta_e8s:          i128,
    pool_attested_at_ns:            u64,
    treasury_read_status:           SourceReadStatus,
    treasury_stray_funds_e8s:       u128,
    refreshed_at_ns:        u64,
    max_staleness_ns:       u64,
    status:                 SnapshotStatus,
    healthy:                bool,
    schema_version:         u32,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct HealthStatus {
    healthy:         bool,
    status:          SnapshotStatus,
    snapshot_age_ns: u64,
    cycles_balance:  u128,
}

// Canonical-encoding constants — must mirror canisters/smoke-alarm-monitor
// (CERTIFIED_SNAPSHOT_ENCODING.md is the contract doc).
const DOMAIN_TAG: &[u8; 19] = b"stsh-smoke-alarm-v1";
const CANONICAL_LEN: usize = 131; // v2 (was 89)
const TREE_KEY: &[u8] = b"solvency_snapshot";

// ─────────────────────────────────────────────────────────────────────────────
// PocketIC helpers
// ─────────────────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn anon() -> Principal { Principal::anonymous() }

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected/failed: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: Candid decode failed: {}", label, e))
}

/// Give timers + the two sequential inter-canister awaits room to complete.
fn settle(pic: &PocketIc) {
    for _ in 0..8 {
        pic.tick();
    }
}

fn advance_and_settle(pic: &PocketIc, secs: u64) {
    pic.advance_time(Duration::from_secs(secs));
    settle(pic);
}

const REFRESH_INTERVAL_SECS: u64 = 60;

/// v2 (D-2): the monitor's init mirror for the pool's `PoolInitArgs`. Needed
/// because the attestation source must be a REAL canister — a bare principal
/// answers no call, which the monitor correctly reports as `CallFailed`.
#[derive(CandidType, Serialize, Deserialize)]
struct PoolInitArgs {
    token_canister:       Principal,
    nullifier_canister:   Principal,
    merkle_canister:      Principal,
    treasury_canister:    Principal,
    staking_canister:     Principal,
    controller:           Principal,
    initial_vk_hash:      [u8; 32],
    initial_proof_system: String,
    verifier_canister:    Option<Principal>,
}

fn pool_wasm() -> Vec<u8> { load_wasm(env!("POOL_WASM"), "shielded_pool") }


#[derive(CandidType, Serialize)]
struct FixedPoolAttestation {
    public_delta_e8s: i128,
    healthy: bool,
    attested_at_ns: u64,
    schema_version: u32,
}

#[derive(CandidType, Serialize)]
struct FixedCertifiedPoolAttestation {
    attestation: FixedPoolAttestation,
    canonical_bytes: ByteBuf,
    certificate: Option<ByteBuf>,
    witness: ByteBuf,
}

/// One fixed query responder, assembled from the documented core Wasm sections.
/// Code: i32.const 4; i32.const 0; i32.load align=2 offset=0; call
/// msg_reply_data_append; call msg_reply; end. Only section/data lengths use
/// unsigned LEB. The payload length itself lives as little-endian data.
fn fixed_attestation_responder_wasm(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() + 4 <= 65_536, "one memory page");
    fn leb(mut n: u32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 { byte |= 0x80; }
            out.push(byte);
            if n == 0 { return out; }
        }
    }
    fn name(value: &str) -> Vec<u8> {
        let mut out = leb(value.len() as u32);
        out.extend_from_slice(value.as_bytes());
        out
    }
    fn section(module: &mut Vec<u8>, id: u8, body: Vec<u8>) {
        module.push(id);
        module.extend(leb(body.len() as u32));
        module.extend(body);
    }

    let mut module = b"\0asm\x01\0\0\0".to_vec();
    section(&mut module, 1, vec![
        2, 0x60, 2, 0x7f, 0x7f, 0, 0x60, 0, 0,
    ]);

    let mut imports = vec![2];
    imports.extend(name("ic0"));
    imports.extend(name("msg_reply_data_append"));
    imports.extend([0, 0]);
    imports.extend(name("ic0"));
    imports.extend(name("msg_reply"));
    imports.extend([0, 1]);
    section(&mut module, 2, imports);
    section(&mut module, 3, vec![1, 1]);
    section(&mut module, 5, vec![1, 0, 1]);

    let mut exports = vec![2];
    exports.extend(name("memory"));
    exports.extend([2, 0]);
    exports.extend(name("canister_query get_solvency_attestation"));
    exports.extend([0, 2]);
    section(&mut module, 7, exports);

    let instructions = vec![
        0,       // zero local declarations
        0x41, 4, // i32.const 4: payload starts after its length word
        0x41, 0, // i32.const 0
        0x28, 2, 0, // i32.load align=2 offset=0
        0x10, 0, // call msg_reply_data_append
        0x10, 1, // call msg_reply
        0x0b,
    ];
    let mut code = vec![1];
    code.extend(leb(instructions.len() as u32));
    code.extend(instructions);
    section(&mut module, 10, code);

    let mut data_bytes = (payload.len() as u32).to_le_bytes().to_vec();
    data_bytes.extend_from_slice(payload);
    let mut data = vec![1, 0, 0x41, 0, 0x0b];
    data.extend(leb(data_bytes.len() as u32));
    data.extend(data_bytes);
    section(&mut module, 11, data);
    module
}


/// Install a real, zeroed (hence solvent) pool to serve attestations.
fn deploy_pool(pic: &PocketIc) -> Principal {
    let cid = create_canister(pic);
    pic.install_canister(
        cid,
        pool_wasm(),
        candid::encode_one(PoolInitArgs {
            token_canister:       p(0x21),
            nullifier_canister:   p(0x22),
            merkle_canister:      p(0x23),
            treasury_canister:    p(0x24),
            staking_canister:     p(0x25),
            controller:           p(0xC0),
            initial_vk_hash:      [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
            verifier_canister:    None,
        })
        .expect("encode pool init"),
        None,
    );
    cid
}

/// The treasury account weighed for stray funds. A plain principal is correct
/// here: it is read through the TOKEN's icrc1_balance_of, and the monitor never
/// calls the treasury canister itself.
fn treasury_principal() -> Principal { p(0x77) }

fn monitor_init(token: Principal, pool: Principal, attestation_source: Principal) -> MonitorInit {
    MonitorInit {
        token_canister:          token,
        pool_principal:          pool,
        treasury_principal:      treasury_principal(),
        pool_attestation_source: attestation_source,
        refresh_interval_ns:     REFRESH_INTERVAL_SECS * 1_000_000_000,
        max_staleness_ns:        5 * REFRESH_INTERVAL_SECS * 1_000_000_000,
        history_capacity:        3,
    }
}

fn deploy_monitor(pic: &PocketIc, init: &MonitorInit) -> Principal {
    deploy_monitor_from(pic, init, monitor_wasm())
}

/// `deploy_monitor` with the module named explicitly — test_sam_10 installs the
/// PRE-v3 module here and then upgrades it to the current one.
fn deploy_monitor_from(pic: &PocketIc, init: &MonitorInit, wasm: Vec<u8>) -> Principal {
    let monitor = create_canister(pic);
    pic.install_canister(
        monitor,
        wasm,
        candid::encode_one(init).expect("encode monitor init"),
        None,
    );
    monitor
}

/// Standard rig: token (all supply held by the pool principal) + monitor.
fn deploy_rig(pic: &PocketIc, wasm: Vec<u8>) -> (Principal, Principal, Principal) {
    let pool = p(0x50);
    let token = create_canister(pic);
    pic.install_canister(
        token,
        wasm,
        candid::encode_one(&all_to(pool)).expect("encode token init"),
        None,
    );
    let attestation_source = deploy_pool(pic);
    let monitor = deploy_monitor(pic, &monitor_init(token, pool, attestation_source));
    settle(pic);
    (token, pool, monitor)
}

fn get_snapshot(pic: &PocketIc, monitor: Principal) -> SolvencySnapshot {
    decode(
        "get_snapshot",
        pic.query_call(monitor, anon(), "get_snapshot", candid::encode_args(()).unwrap()),
    )
}

fn get_history(pic: &PocketIc, monitor: Principal) -> Vec<SolvencySnapshot> {
    decode(
        "get_history",
        pic.query_call(monitor, anon(), "get_history", candid::encode_args(()).unwrap()),
    )
}


/// Every field of a schema-2 record must survive the migration unchanged,
/// EXCEPT the two the migration is defined to change: `schema_version`
/// (re-stamped 2 -> 3, because the record is now encoded in the v3 layout) and
/// the newly added `supply_invariant_unavailable` (which must read `false` —
/// the schema-2 monitor never observed an arithmetic error).
///
/// SSA landed-diff round-2 RED-1: a length-only history assertion is vacuous.
/// A mapping that zeroed `refreshed_at_ns` on every historical record — real
/// data loss — kept the vector length and left the test GREEN. Everything the
/// migration is NOT allowed to touch is bound here, field by field, so any such
/// mutation fails on the field it corrupted.
fn assert_migrated_field_for_field(
    before: &SolvencySnapshotPreV3,
    after: &SolvencySnapshot,
    what: &str,
) {
    assert_eq!(after.supply_invariant_holds, before.supply_invariant_holds, "{what}: supply_invariant_holds");
    assert_eq!(after.fixed_max_supply_e8s, before.fixed_max_supply_e8s, "{what}: fixed_max_supply_e8s");
    assert_eq!(after.sum_all_balances_e8s, before.sum_all_balances_e8s, "{what}: sum_all_balances_e8s");
    assert_eq!(after.pool_balance_e8s, before.pool_balance_e8s, "{what}: pool_balance_e8s");
    assert_eq!(after.pool_attestation_source_status, before.pool_attestation_source_status, "{what}: pool_attestation_source_status");
    assert_eq!(after.pool_delta_healthy, before.pool_delta_healthy, "{what}: pool_delta_healthy");
    assert_eq!(after.pool_public_delta_e8s, before.pool_public_delta_e8s, "{what}: pool_public_delta_e8s");
    assert_eq!(after.pool_attested_at_ns, before.pool_attested_at_ns, "{what}: pool_attested_at_ns");
    assert_eq!(after.treasury_read_status, before.treasury_read_status, "{what}: treasury_read_status");
    assert_eq!(after.treasury_stray_funds_e8s, before.treasury_stray_funds_e8s, "{what}: treasury_stray_funds_e8s");
    assert_eq!(after.refreshed_at_ns, before.refreshed_at_ns, "{what}: refreshed_at_ns — the measurement's own timestamp");
    assert_eq!(after.max_staleness_ns, before.max_staleness_ns, "{what}: max_staleness_ns");
    assert_eq!(after.status, before.status, "{what}: status");
    assert_eq!(after.healthy, before.healthy, "{what}: healthy");
    // The two the migration IS defined to change.
    assert!(!after.supply_invariant_unavailable, "{what}: a migrated schema-2 record must not claim UNAVAILABLE");
    assert_eq!(before.schema_version, 2, "{what}: pre-upgrade record must really be schema 2");
    assert_eq!(after.schema_version, 3, "{what}: migrated record must be re-stamped v3");
}

/// The canonical leaf bytes as actually committed — the page parses THESE, not
/// the Candid display record, so this is the surface an encoding assertion has
/// to be made against.
fn certified_canonical_bytes(pic: &PocketIc, monitor: Principal) -> Vec<u8> {
    get_certified(pic, monitor).canonical_bytes.to_vec()
}

fn get_certified(pic: &PocketIc, monitor: Principal) -> CertifiedSolvencySnapshot {
    decode(
        "get_certified_snapshot",
        pic.query_call(monitor, anon(), "get_certified_snapshot", candid::encode_args(()).unwrap()),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Independent hash-tree verification (IC certification spec)
// ─────────────────────────────────────────────────────────────────────────────
//
// CBOR node encoding: [0]=Empty, [1,l,r]=Fork, [2,label,sub]=Labeled,
// [3,data]=Leaf, [4,hash]=Pruned. Digests use ic-hashtree-* domain separation.

use serde_cbor::Value;

fn unwrap_tag(v: &Value) -> &Value {
    match v {
        Value::Tag(_, inner) => unwrap_tag(inner),
        other => other,
    }
}

fn node_array(v: &Value) -> &Vec<Value> {
    match unwrap_tag(v) {
        Value::Array(a) => a,
        other => panic!("hash tree node must be a CBOR array, got {:?}", other),
    }
}

fn node_tag(arr: &[Value]) -> i128 {
    match unwrap_tag(&arr[0]) {
        Value::Integer(i) => *i,
        other => panic!("hash tree node tag must be an integer, got {:?}", other),
    }
}

fn node_bytes(v: &Value) -> Vec<u8> {
    match unwrap_tag(v) {
        Value::Bytes(b) => b.clone(),
        other => panic!("expected CBOR bytes, got {:?}", other),
    }
}

/// Per the IC spec, hash-tree domain separators are length-prefixed:
/// H = sha256(byte(len(sep)) || sep || content).
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
        3 => {
            domain_sep(&mut h, "ic-hashtree-leaf");
            h.update(node_bytes(&arr[1]));
        }
        4 => {
            let hash = node_bytes(&arr[1]);
            return hash.try_into().expect("pruned hash must be 32 bytes");
        }
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
        2 => {
            if node_bytes(&arr[1]) == path[0] {
                tree_lookup(&arr[2], &path[1..])
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract /canister/<id>/certified_data from a CBOR-encoded certificate.
fn certified_data_from_certificate(cert_bytes: &[u8], canister_id: Principal) -> Vec<u8> {
    let cert: Value = serde_cbor::from_slice(cert_bytes).expect("certificate CBOR decode");
    let map = match unwrap_tag(&cert) {
        Value::Map(m) => m,
        other => panic!("certificate must be a CBOR map, got {:?}", other),
    };
    let tree = map
        .get(&Value::Text("tree".to_string()))
        .expect("certificate has no tree field");
    tree_lookup(
        tree,
        &[b"canister", canister_id.as_slice(), b"certified_data"],
    )
    .expect("certificate tree has no certified_data for this canister")
}

/// Parse the canonical 89-byte leaf encoding back into field values.
struct ParsedCanonical {
    schema_version: u32,
    status: u8,
    supply_invariant_holds: bool,
    healthy: bool,
    pool_delta_healthy: bool,
    treasury_stray_present: bool,
    /// v3 bit 4.
    supply_invariant_unavailable: bool,
    fixed_max_supply_e8s: u128,
    sum_all_balances_e8s: u128,
    pool_balance_e8s: u128,
    refreshed_at_ns: u64,
    max_staleness_ns: u64,
    pool_attestation_source_status: u8,
    treasury_read_status: u8,
    pool_public_delta_e8s: i128,
    pool_attested_at_ns: u64,
    treasury_stray_funds_e8s: u128,
}

fn parse_canonical(bytes: &[u8]) -> ParsedCanonical {
    assert_eq!(bytes.len(), CANONICAL_LEN, "canonical length");
    assert_eq!(&bytes[0..19], DOMAIN_TAG, "domain tag");
    let u32be = |b: &[u8]| u32::from_be_bytes(b.try_into().unwrap());
    let u64be = |b: &[u8]| u64::from_be_bytes(b.try_into().unwrap());
    let u128be = |b: &[u8]| u128::from_be_bytes(b.try_into().unwrap());
    let i128be = |b: &[u8]| i128::from_be_bytes(b.try_into().unwrap());
    let flags = bytes[24];
    // v3 claimed bit 4 (supply_invariant_unavailable); 5..7 are still reserved
    // and MUST be zero. A v2 parser's `!0b1111` mask would now reject every leaf
    // that reports UNAVAILABLE, which is exactly why the page must be deployed
    // BEFORE the monitor cuts over — see MAINNET_DEPLOYMENT.md
    // "## Solvency surface: schema-3 transition (R-4)".
    assert_eq!(flags & !0b11111, 0, "reserved flag bits must be zero");
    ParsedCanonical {
        schema_version:         u32be(&bytes[19..23]),
        status:                 bytes[23],
        supply_invariant_holds: flags & 0b0001 != 0,
        healthy:                flags & 0b0010 != 0,
        pool_delta_healthy:     flags & 0b0100 != 0,
        treasury_stray_present: flags & 0b1000 != 0,
        supply_invariant_unavailable: flags & 0b10000 != 0,
        fixed_max_supply_e8s:   u128be(&bytes[25..41]),
        sum_all_balances_e8s:   u128be(&bytes[41..57]),
        pool_balance_e8s:       u128be(&bytes[57..73]),
        refreshed_at_ns:        u64be(&bytes[73..81]),
        max_staleness_ns:       u64be(&bytes[81..89]),
        pool_attestation_source_status: bytes[89],
        treasury_read_status:           bytes[90],
        pool_public_delta_e8s:          i128be(&bytes[91..107]),
        pool_attested_at_ns:            u64be(&bytes[107..115]),
        treasury_stray_funds_e8s:       u128be(&bytes[115..131]),
    }
}

fn status_code(s: SnapshotStatus) -> u8 {
    match s {
        SnapshotStatus::Fresh => 0,
        SnapshotStatus::Stale => 1,
        SnapshotStatus::RefreshFailed => 2,
        SnapshotStatus::SourceCallFailed => 3,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_sam_01_timer_refresh_produces_fresh_healthy_snapshot() {
    let pic = PocketIc::new();
    let (_token, _pool, monitor) = deploy_rig(&pic, token_wasm());

    let snap = get_snapshot(&pic, monitor);
    assert_eq!(snap.status, SnapshotStatus::Fresh, "first refresh should have landed");
    assert!(snap.healthy, "healthy rig must be green");
    assert!(snap.supply_invariant_holds);
    assert_eq!(snap.fixed_max_supply_e8s, TOTAL_SUPPLY);
    assert_eq!(snap.sum_all_balances_e8s, TOTAL_SUPPLY);
    assert_eq!(snap.pool_balance_e8s, TOTAL_SUPPLY, "all supply allocated to the pool principal");
    assert_eq!(snap.schema_version, 3, "v3 layout (R-4: bit 4 UNAVAILABLE)");
    // v2: the RED source read cleanly and the pool says its backing holds. Both
    // halves are asserted — an `Ok` read of an unhealthy pool, or a healthy bit
    // carried through a failed read, must not be able to render green.
    assert_eq!(snap.pool_attestation_source_status, SourceReadStatus::Ok);
    assert!(snap.pool_delta_healthy, "a zeroed pool is solvent");
    assert_eq!(snap.pool_public_delta_e8s, 0, "healthy states publish exactly zero");
    assert_eq!(
        snap.pool_attested_at_ns % 300_000_000_000,
        0,
        "the pool's stamp reaches the monitor already bucketed"
    );
    // v2: the treasury read succeeded and found nothing stray — YELLOW is clear.
    assert_eq!(snap.treasury_read_status, SourceReadStatus::Ok);
    assert_eq!(snap.treasury_stray_funds_e8s, 0);
    assert!(!get_history(&pic, monitor).is_empty(), "refresh results are recorded");

    // Interval firing: a later refresh advances the timestamp.
    let before = snap.refreshed_at_ns;
    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);
    let later = get_snapshot(&pic, monitor);
    assert!(later.refreshed_at_ns > before, "interval timer must keep refreshing");
    assert_eq!(later.status, SnapshotStatus::Fresh);

    // Derived health agrees while fresh.
    let health: HealthStatus = decode(
        "get_health_status",
        pic.query_call(monitor, anon(), "get_health_status", candid::encode_args(()).unwrap()),
    );
    assert!(health.healthy);
    assert_eq!(health.status, SnapshotStatus::Fresh);
}

#[test]
fn test_sam_02_certified_query_certificate_witness_canonical_contract() {
    let pic = PocketIc::new();
    let (_token, _pool, monitor) = deploy_rig(&pic, token_wasm());

    let certified = get_certified(&pic, monitor);
    assert!(certified.snapshot.healthy);

    // (1) A certificate must be present on the non-replicated query path.
    let cert = certified
        .certificate
        .as_ref()
        .expect("certified query must carry a certificate");
    assert!(!cert.is_empty());

    // (2) The witness must be a valid hash tree whose root equals the
    // certified_data the subnet signed for this canister.
    let witness: Value = serde_cbor::from_slice(&certified.witness).expect("witness CBOR decode");
    let witness_root = tree_digest(&witness);
    let certified_data = certified_data_from_certificate(cert, monitor);
    assert_eq!(
        witness_root.to_vec(),
        certified_data,
        "witness root must match the subnet-certified root"
    );

    // (3) The witness leaf under TREE_KEY must be exactly canonical_bytes.
    let leaf = tree_lookup(&witness, &[TREE_KEY]).expect("witness must reveal the snapshot leaf");
    assert_eq!(leaf, certified.canonical_bytes.to_vec());

    // (4) The canonical bytes must parse back to the exact snapshot struct —
    // this is the canister/frontend data contract.
    let parsed = parse_canonical(&certified.canonical_bytes);
    let s = &certified.snapshot;
    assert_eq!(parsed.schema_version, s.schema_version);
    assert_eq!(parsed.status, status_code(s.status));
    assert_eq!(parsed.supply_invariant_holds, s.supply_invariant_holds);
    assert_eq!(parsed.healthy, s.healthy);
    assert_eq!(parsed.fixed_max_supply_e8s, s.fixed_max_supply_e8s);
    assert_eq!(parsed.sum_all_balances_e8s, s.sum_all_balances_e8s);
    assert_eq!(parsed.pool_balance_e8s, s.pool_balance_e8s);
    assert_eq!(parsed.refreshed_at_ns, s.refreshed_at_ns);
    assert_eq!(parsed.max_staleness_ns, s.max_staleness_ns);
    assert_eq!(parsed.supply_invariant_unavailable, s.supply_invariant_unavailable);
}

#[test]
fn test_sam_03_fail_closed_on_token_stop_then_recover_and_history_bounded() {
    let pic = PocketIc::new();
    let (token, _pool, monitor) = deploy_rig(&pic, token_wasm());
    let green = get_snapshot(&pic, monitor);
    assert!(green.healthy);

    // Stop the token — the next refresh's source calls are rejected.
    pic.stop_canister(token, None).expect("stop token");
    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);

    let red = get_snapshot(&pic, monitor);
    assert_eq!(red.status, SnapshotStatus::SourceCallFailed);
    assert!(!red.healthy, "source failure must never show green");
    assert!(!red.supply_invariant_holds, "invariant is unproven on failure — fail closed");
    assert!(
        red.refreshed_at_ns > green.refreshed_at_ns,
        "failure must be a NEW snapshot, not a retained old one"
    );
    // Figures carry the last good values for continuity — status is authoritative.
    assert_eq!(red.pool_balance_e8s, green.pool_balance_e8s);

    // The failure is recorded in history too.
    let hist = get_history(&pic, monitor);
    assert!(hist.iter().any(|s| s.status == SnapshotStatus::SourceCallFailed));

    // Recovery: restart the token, next interval goes green again.
    pic.start_canister(token, None).expect("start token");
    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);
    let recovered = get_snapshot(&pic, monitor);
    assert_eq!(recovered.status, SnapshotStatus::Fresh);
    assert!(recovered.healthy);

    // Ring buffer stays bounded at history_capacity (3 in the rig).
    for _ in 0..4 {
        advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);
    }
    assert!(get_history(&pic, monitor).len() <= 3, "history must stay bounded");
}

#[test]
fn test_sam_04_supply_invariant_violation_turns_unhealthy() {
    let pic = PocketIc::new();
    // Test token wasm: exposes debug_credit_balance_for_test, which inflates a
    // balance WITHOUT minting — breaking TOTAL_SUPPLY == sum(balances).
    let (token, _pool, monitor) = deploy_rig(&pic, token_test_wasm());
    assert!(get_snapshot(&pic, monitor).healthy);

    let _: () = decode(
        "debug_credit_balance_for_test",
        pic.update_call(
            token,
            anon(),
            "debug_credit_balance_for_test",
            candid::encode_args((Account { owner: p(0x55), subaccount: None }, 1_000u128)).unwrap(),
        ),
    );

    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);
    let snap = get_snapshot(&pic, monitor);
    assert_eq!(snap.status, SnapshotStatus::Fresh, "the read itself succeeded");
    assert!(!snap.supply_invariant_holds, "token must report the violation");
    assert!(!snap.healthy, "invariant violation must show red");
}

#[test]
fn test_sam_05_upgrade_preserves_state_recertifies_and_restarts_timer() {
    let pic = PocketIc::new();
    let (_token, _pool, monitor) = deploy_rig(&pic, token_wasm());
    let before = get_snapshot(&pic, monitor);
    assert!(before.healthy);
    let hist_before = get_history(&pic, monitor).len();

    pic.upgrade_canister(monitor, monitor_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("monitor upgrade");

    // State survived.
    let after = get_snapshot(&pic, monitor);
    assert_eq!(after.refreshed_at_ns, before.refreshed_at_ns);
    assert_eq!(after.pool_balance_e8s, before.pool_balance_e8s);
    assert_eq!(get_history(&pic, monitor).len(), hist_before);
    let cfg: MonitorInit = decode(
        "get_config",
        pic.query_call(monitor, anon(), "get_config", candid::encode_args(()).unwrap()),
    );
    assert_eq!(cfg.history_capacity, 3);

    // Certified data was re-established (it is cleared by the upgrade).
    let certified = get_certified(&pic, monitor);
    let cert = certified.certificate.as_ref().expect("certificate after upgrade");
    let witness: Value = serde_cbor::from_slice(&certified.witness).unwrap();
    assert_eq!(
        tree_digest(&witness).to_vec(),
        certified_data_from_certificate(cert, monitor),
        "post-upgrade certified_data must match the rebuilt tree"
    );

    // Timers were restarted: a later interval still refreshes.
    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);
    assert!(
        get_snapshot(&pic, monitor).refreshed_at_ns > before.refreshed_at_ns,
        "refresh timer must survive the upgrade via post_upgrade re-arm"
    );
}

#[test]
fn test_sam_06_request_refresh_is_rate_limited() {
    let pic = PocketIc::new();
    let (_token, _pool, monitor) = deploy_rig(&pic, token_wasm());

    // The timer refreshed moments ago — a manual kick inside the 60s window
    // must be rejected (cycle-drain protection).
    let early: Result<(), String> = decode(
        "request_refresh (early)",
        pic.update_call(monitor, anon(), "request_refresh", candid::encode_args(()).unwrap()),
    );
    assert!(early.is_err(), "manual refresh within the rate window must be rejected");

    // Well past the window (and interval timers may also have run — the gap
    // check is against the LAST attempt, so jump far beyond it).
    pic.advance_time(Duration::from_secs(90));
    let ok: Result<(), String> = decode(
        "request_refresh (after window)",
        pic.update_call(monitor, anon(), "request_refresh", candid::encode_args(()).unwrap()),
    );
    assert!(ok.is_ok(), "manual refresh after the rate window must be accepted");
    settle(&pic);
    assert!(get_snapshot(&pic, monitor).healthy);
}

#[test]
fn test_sam_07_nonexistent_token_fails_closed_from_first_refresh() {
    let pic = PocketIc::new();
    // Monitor pointed at a canister id that does not exist — every refresh
    // fails; the placeholder must never be replaced by anything green.
    // v2: the attestation source is a nonexistent canister too, so BOTH the
    // token reads and the pool attestation fail — the point of this test is that
    // nothing green can ever appear, and that is now true on three sources.
    let monitor = deploy_monitor(&pic, &monitor_init(p(0x77), p(0x50), p(0x78)));
    settle(&pic);
    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);

    let snap = get_snapshot(&pic, monitor);
    assert_eq!(snap.status, SnapshotStatus::SourceCallFailed);
    assert!(!snap.healthy);
    assert_eq!(snap.pool_balance_e8s, 0, "no good figures ever existed — zeros carried");

    // Certified read still works and commits the red state.
    let certified = get_certified(&pic, monitor);
    let parsed = parse_canonical(&certified.canonical_bytes);
    assert!(!parsed.healthy);
    assert_eq!(parsed.status, 3, "SourceCallFailed in the canonical encoding");
}

// ─────────────────────────────────────────────────────────────────────────────
// R-4 (S-c / AC-6) — UNAVAILABLE is distinct from VIOLATED, MONITOR SIDE.
//
// The token reports `arithmetic_error = Some(_)` when the supply invariant
// could not be EVALUATED. Before this change the monitor read that field for
// `healthy` and then dropped it: the wire encoding carried
// `supply_invariant_holds = false` with no field saying WHY, so the page
// rendered "VIOLATED" — a claim about the ledger the monitor had no evidence
// for. v3 bit 4 carries the reason.
//
// The FALSIFIER for M6 is CASE A: an ordinary invariant violation
// (invariant_holds == false, arithmetic_error == None). Deriving bit 4 from
// `!supply_invariant_holds` instead of `arithmetic_error.is_some()` sets bit 4
// there too, and that assertion goes RED. A test that only checked the overflow
// case would pass under the mutation and prove nothing.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_sam_08_arithmetic_error_sets_unavailable_bit_violation_does_not() {
    let pic = PocketIc::new();
    let (token, _pool, monitor) = deploy_rig(&pic, token_test_wasm());
    assert!(get_snapshot(&pic, monitor).healthy, "rig starts healthy");

    // ── CASE A: an ordinary FIRST-LAW VIOLATION, no arithmetic error ────────
    // Credit a small amount without minting: sum(balances) + fee_reserve now
    // exceeds TOTAL_SUPPLY, but every checked add still succeeds.
    let _: () = decode(
        "debug_credit_balance_for_test",
        pic.update_call(
            token,
            anon(),
            "debug_credit_balance_for_test",
            candid::encode_args((Account { owner: p(0x55), subaccount: None }, 1_000u128)).unwrap(),
        ),
    );
    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);
    let violated = get_snapshot(&pic, monitor);
    assert_eq!(violated.status, SnapshotStatus::Fresh, "the read itself succeeded");
    assert!(!violated.supply_invariant_holds, "the invariant really is violated");
    assert!(!violated.healthy, "a violation is unhealthy");
    assert!(
        !violated.supply_invariant_unavailable,
        "M6 FALSIFIER: a computed violation is VIOLATED, not UNAVAILABLE — bit 4 \
         must be bound to arithmetic_error, never to !supply_invariant_holds"
    );
    let violated_bytes = certified_canonical_bytes(&pic, monitor);
    assert_eq!(violated_bytes[24] & 0b10000, 0, "bit 4 clear in the canonical leaf");
    assert_eq!(u32::from_be_bytes(violated_bytes[19..23].try_into().unwrap()), 3);

    // ── CASE B: a REAL arithmetic error ─────────────────────────────────────
    // R-1 RECONCILIATION (CTO countersign 2026-09-05, condition 2a). This case
    // used to credit `u128::MAX` through `debug_credit_balance_for_test`, whose
    // pre-R-1 hook saturated the stored balance so the O(N) balances FOLD inside
    // `evaluate_supply_invariant` overflowed. R-1 removed both halves of that
    // route: the debug hook now writes through the production funnel, whose
    // `SUM_BALANCES.checked_add` REFUSES the delta and TRAPS the update call
    // (that write-time refusal is R-1's first law, and is covered by
    // arith_hardening T2 — it is not this test's property); and the public path
    // no longer folds at all, so a fold overflow is not reachable by any input.
    //
    // THE PROPERTY THIS CASE ASSERTS IS UNCHANGED: when the token reports a REAL
    // `arithmetic_error`, the monitor sets bit 4 (UNAVAILABLE) and emits a
    // schema-3 leaf of unchanged length — the pair to CASE A's falsifier, which
    // is what makes "bit 4 tracks arithmetic_error, never !invariant_holds"
    // falsifiable in BOTH directions inside one test.
    //
    // Post-R-1 the ONLY remaining arithmetic-error site is the single public
    // `sum_balances.checked_add(fee_reserve)` — a QUERY-side add that reports
    // rather than traps. R-1's own declared seam drives exactly its three
    // operands, so this reaches the same reported state WITHOUT bypassing the
    // write funnel: the funnel governs WRITES, and this sets no balance row.
    // (CASE A above still goes through the funnel unchanged.)
    let _: () = decode(
        "set_supply_totals_for_test",
        pic.update_call(
            token,
            anon(),
            "set_supply_totals_for_test",
            candid::encode_args((u128::MAX, 0u128, 1u128)).unwrap(),
        ),
    );
    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);
    let unavailable = get_snapshot(&pic, monitor);
    assert_eq!(unavailable.status, SnapshotStatus::Fresh, "the READ succeeded; the MATH did not");
    assert!(!unavailable.supply_invariant_holds, "unproven is not proven");
    assert!(!unavailable.healthy, "fail closed — UNAVAILABLE is never healthy");
    assert!(
        unavailable.supply_invariant_unavailable,
        "AC-6: a real arithmetic_error must set the UNAVAILABLE bit"
    );

    let bytes = certified_canonical_bytes(&pic, monitor);
    let parsed = parse_canonical(&bytes);
    assert_eq!(parsed.schema_version, 3, "AC-7: the monitor emits schema 3");
    assert!(parsed.supply_invariant_unavailable, "bit 4 set in the canonical leaf");
    assert!(!parsed.healthy, "healthy semantics unchanged by the bump");
    assert!(!parsed.supply_invariant_holds);
    // No new field bytes; only the schema byte and one flag bit moved.
    assert_eq!(bytes.len(), CANONICAL_LEN);
}

// ─────────────────────────────────────────────────────────────────────────────
// R-4 AC-6c — the COMPOSED property, post-R-1.
//
// R-1 replaces the O(N) public-path fold with two maintained running totals, so
// after it lands the ONLY way the public invariant can become unavailable is the
// single remaining `sum_balances.checked_add(fee_reserve)` overflowing — a QUERY
// computation, so it reports rather than traps. This test drives exactly that,
// through R-1's own testing seam, and asserts the whole chain: token ->
// arithmetic_error -> monitor bit 4 -> schema 3 leaf.
//
// R-1 IS MERGED (master 2b0fff8; this branch is rebased onto it), so the gate's
// own `stsh_token_test.wasm` now exposes `set_supply_totals_for_test`. The
// former `R1_TOKEN_TEST_WASM` env gate and its early return are DELETED per the
// CTO countersign of 2026-09-05, condition 2b: this test now always executes,
// on the ordinary gate artifact, like every other test in this file.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_sam_09_ac6c_composed_arithmetic_error_renders_unavailable() {
    let pic = PocketIc::new();
    let (token, _pool, monitor) = deploy_rig(&pic, token_test_wasm());
    assert!(get_snapshot(&pic, monitor).healthy, "rig starts healthy");

    // ── Companion BASELINE: the add SUCCEEDS but does not equal TOTAL_SUPPLY.
    // Proves the fixture cannot silently degrade into an ordinary violation and
    // still be read as "unavailable" — and is the case M6c turns RED.
    let _: () = decode(
        "set_supply_totals_for_test",
        pic.update_call(
            token,
            anon(),
            "set_supply_totals_for_test",
            candid::encode_args((TOTAL_SUPPLY - 1, 0u128, 0u128)).unwrap(),
        ),
    );
    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);
    let baseline = get_snapshot(&pic, monitor);
    assert!(!baseline.supply_invariant_holds, "an ordinary first-law violation");
    assert!(!baseline.healthy);
    assert!(
        !baseline.supply_invariant_unavailable,
        "M6c FALSIFIER: arithmetic_error is None here, so bit 4 must be CLEAR — \
         VIOLATED, not UNAVAILABLE"
    );
    // ...and on the CANONICAL LEAF, which is what the page actually parses.
    // The Candid field above is display convenience: an encoder mutation that
    // derives bit 4 from `!supply_invariant_holds` leaves that field untouched
    // and is invisible to it. The bytes are the falsifying surface. (M6c found
    // exactly this gap in an earlier draft of this test.)
    let baseline_bytes = certified_canonical_bytes(&pic, monitor);
    assert_eq!(
        baseline_bytes[24] & 0b10000,
        0,
        "M6c FALSIFIER (leaf bytes): an ordinary violation must NOT set bit 4"
    );
    assert_eq!(
        u32::from_be_bytes(baseline_bytes[19..23].try_into().unwrap()),
        3,
        "still schema 3"
    );

    // ── The overflow: all three operands controlled, no trap anywhere.
    // sum_balances = u128::MAX, staking_locks = 0, fee_reserve = 1
    //   => sum_balances.checked_add(fee_reserve) == None
    //   => balances_plus_fee_overflow, arithmetic_error = Some(_)
    let _: () = decode(
        "set_supply_totals_for_test",
        pic.update_call(
            token,
            anon(),
            "set_supply_totals_for_test",
            candid::encode_args((u128::MAX, 0u128, 1u128)).unwrap(),
        ),
    );
    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);
    let snap = get_snapshot(&pic, monitor);
    assert_eq!(snap.status, SnapshotStatus::Fresh, "no trap: the query returned a report");
    assert!(!snap.supply_invariant_holds);
    assert!(!snap.healthy, "never green");
    assert!(snap.supply_invariant_unavailable, "AC-6c: bit 4 set end to end");

    let bytes = certified_canonical_bytes(&pic, monitor);
    let parsed = parse_canonical(&bytes);
    assert_eq!(parsed.schema_version, 3);
    assert!(parsed.supply_invariant_unavailable);
    // The page's rule over these bytes (verify.ts deriveDisplayState) is
    // asserted directly in website/solvency-status/src/verify.test.ts:
    // bit 4 set => light 'red', reason /could not be computed/, and NOT
    // /NOT proven to hold/. The three-artifact lockstep is what joins them.
}

/// test_sam_10 (SSA landed-diff round-1 RED-1) — REAL cross-Wasm schema-2 ->
/// schema-3 upgrade with a populated checkpoint.
///
/// WHY test_sam_05 cannot cover this: it installs `monitor_wasm()` and upgrades
/// to `monitor_wasm()` — the same module — so the bytes written by `pre_upgrade`
/// always carry exactly the fields `post_upgrade` expects. It is structurally
/// incapable of failing on a layout change. This test installs the module built
/// from 115526d (schema 2, no `supply_invariant_unavailable` anywhere in its
/// stable state), lets it take a real refresh so the checkpoint is POPULATED
/// rather than a fresh placeholder, and only then upgrades to the current
/// module. Before the explicit version arm in `post_upgrade` this rejected with
///     post_upgrade: state decode failed ...
///     Subtyping error: field supply_invariant_unavailable is not optional field
/// which is a mainnet cutover failure, not a test artifact.
#[test]
fn test_sam_10_pre_v3_monitor_upgrades_to_v3_preserving_state() {
    let pic = PocketIc::new();
    let pool = p(0x50);
    let token = create_canister(&pic);
    pic.install_canister(
        token,
        token_wasm(),
        candid::encode_one(&all_to(pool)).expect("encode token init"),
        None,
    );
    let attestation_source = deploy_pool(&pic);
    let init = monitor_init(token, pool, attestation_source);
    let monitor = deploy_monitor_from(&pic, &init, monitor_pre_v3_wasm());
    settle(&pic);

    // Populate the checkpoint with real measured state, plus more than one
    // history entry — a migration that dropped `history` would otherwise pass.
    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);
    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);

    let before: SolvencySnapshotPreV3 = decode(
        "get_snapshot",
        pic.query_call(monitor, anon(), "get_snapshot", candid::encode_args(()).unwrap()),
    );
    assert_eq!(before.schema_version, 2, "fixture must really be the schema-2 monitor");
    assert_eq!(before.status, SnapshotStatus::Fresh, "checkpoint must be populated, not a placeholder");
    assert!(before.healthy);
    assert!(before.pool_balance_e8s > 0, "a real measured figure must be present to survive");
    let hist_before: Vec<SolvencySnapshotPreV3> = decode(
        "get_history",
        pic.query_call(monitor, anon(), "get_history", candid::encode_args(()).unwrap()),
    );
    assert!(hist_before.len() > 1, "more than one history entry must be at risk");
    // The history entries must be DISTINGUISHABLE from one another, or an
    // order-scrambling or entry-duplicating mutation would be invisible to the
    // field-for-field comparison below. PocketIC time advances between the two
    // refreshes, so their timestamps differ; assert that rather than assume it.
    for (i, h) in hist_before.iter().enumerate() {
        assert!(h.refreshed_at_ns > 0, "history[{i}] must carry a real nonzero timestamp to be at risk");
    }
    for i in 1..hist_before.len() {
        assert_ne!(
            hist_before[i].refreshed_at_ns, hist_before[i - 1].refreshed_at_ns,
            "history[{}] and history[{}] must be distinguishable, or order is unbound", i - 1, i
        );
    }

    // THE CUTOVER.
    pic.upgrade_canister(monitor, monitor_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("schema-2 -> schema-3 monitor upgrade must decode the stored state");

    // 1. The snapshot survived, EVERY field.
    let after = get_snapshot(&pic, monitor);
    assert_migrated_field_for_field(&before, &after, "snapshot");

    // 2. THE WHOLE HISTORY survived: same length, same order, and every field
    //    of every entry unchanged apart from the two the migration defines.
    //    (SSA landed-diff round-2 RED-1: the previous length-only assertion let
    //    a mapping that zeroed every historical `refreshed_at_ns` pass GREEN.)
    let hist_after = get_history(&pic, monitor);
    assert_eq!(
        hist_after.len(), hist_before.len(),
        "history length must survive: {} entries before, {} after", hist_before.len(), hist_after.len()
    );
    for (i, (b, a)) in hist_before.iter().zip(hist_after.iter()).enumerate() {
        assert_migrated_field_for_field(b, a, &format!("history[{i}]"));
    }

    // 3. The PAGE-FACING BYTES are v3. This is the surface reserves.stsh.fi
    //    parses; a leaf still tagged 2 after the cutover would contradict the
    //    MAINNET_DEPLOYMENT.md transition table.
    assert_eq!(after.schema_version, 3, "migrated record must be re-stamped v3");
    let bytes = certified_canonical_bytes(&pic, monitor);
    assert_eq!(bytes.len(), 131, "canonical length is unchanged by the bump");
    let parsed = parse_canonical(&bytes);
    assert_eq!(parsed.schema_version, 3, "certified leaf must be v3 after the upgrade");
    assert!(!parsed.supply_invariant_unavailable, "bit 4 clear on a migrated leaf");
    assert_eq!(parsed.pool_balance_e8s, before.pool_balance_e8s, "figures re-certified intact");

    // 4. The migrated canister is still LIVE: timers re-armed and the next
    //    refresh writes a natively-v3 snapshot.
    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 5);
    let fresh = get_snapshot(&pic, monitor);
    assert!(fresh.refreshed_at_ns > before.refreshed_at_ns, "refresh timer survived the migration");
    assert_eq!(fresh.schema_version, 3);
}

// =============================================================================
// UMC-28 (lane R-11) — a REFUSED manual refresh still costs the canister
//
// `request_refresh` is documented as "rate-limited to protect the cycle
// reserve … the canister pays for the token reads, not the caller". The second
// half is inverted for the REFUSAL path: the endpoint is permissionless and
// unmetered, so a refused call still costs the canister a full message
// induction and decode, paid by the canister, not by the caller who made it.
//
// `test_sam_06` above proves the refusal HAPPENS. Nothing measured what it
// COSTS, which is the whole content of "protects the cycle reserve".
//
// This measures the refusal via the canister's own cycle-balance delta across a
// single refused call — the cross-canister-boundary observation, declared as
// such: `performance_counter` is not readable from outside the canister and the
// monitor exposes no measurement hook.
//
// IT ADDS NO GUARD. `request_refresh` stays unauthenticated; this pins the cost
// that unauthenticated refusal has today. If the pinned number is judged
// operationally unacceptable that is a FINDING for R-11's escalation NOTE, not
// a fix made here.
// =============================================================================

/// Refused-call ceiling for `request_refresh`, in cycles.
///
/// MEASURED, not guessed. Fresh sample over this test's own five refused calls
/// (lane R-11, 2026-09-07): 6_314_352 / 6_306_125 / 6_308_078 / 6_308_062 /
/// 6_308_078 cycles. max = 6_314_352, spread = 8_227, so max + 3x spread =
/// 6_339_033. Rounded UP to 7_000_000 — about 11% over the computed pin —
/// deliberately, because a pin sitting 0.4% above a measurement taken on ONE
/// machine is an author-machine-only pin, and this test runs everywhere the
/// gate does. Raising it further without re-sampling is the regression it
/// exists to catch.
const UMC28_REFUSED_REFRESH_CEILING_CYCLES: u128 = 7_000_000;

/// Mutation lever (AC-3): a fixed, test-owned multiplier applied INSIDE the
/// measurement. 10x exceeds any max+3x-spread pin by construction.
const UMC28_COST_MULTIPLIER: u128 = 1;

#[test]
fn umc28_refused_manual_refresh_cost_is_ceilinged() {
    let pic = PocketIc::new();
    let (_token, _pool, monitor) = deploy_rig(&pic, token_wasm());

    // The timer refreshed moments ago, so every call in this window is REFUSED
    // by the rate limiter — which is exactly the path being priced.
    let mut samples: Vec<u128> = Vec::new();
    for i in 0..5 {
        let before = pic.cycle_balance(monitor);
        let refused: Result<(), String> = decode(
            "request_refresh (refused)",
            pic.update_call(monitor, anon(), "request_refresh", candid::encode_args(()).unwrap()),
        );
        assert!(
            refused.is_err(),
            "sample {i}: the call must be REFUSED — a cost measured on an ACCEPTED refresh \
             prices the wrong path entirely"
        );
        let after = pic.cycle_balance(monitor);
        samples.push(before.saturating_sub(after) as u128 * UMC28_COST_MULTIPLIER);
    }

    let worst = *samples.iter().max().expect("five samples");
    println!("UMC-28 refused request_refresh cost, cycles per call: {samples:?} (worst {worst})");
    assert!(
        worst > 0,
        "fixture guard: a refused call that cost the canister NOTHING would make the ceiling \
         below vacuous — and would contradict the finding this test records"
    );
    assert!(
        worst <= UMC28_REFUSED_REFRESH_CEILING_CYCLES,
        "a REFUSED, unauthenticated `request_refresh` cost the monitor {worst} cycles, over \
         the pinned ceiling {UMC28_REFUSED_REFRESH_CEILING_CYCLES}. The rate limiter caps how \
         often a refresh is ACCEPTED; it does not cap what refusal costs, and this endpoint \
         is permissionless. samples: {samples:?}"
    );
}


#[test]
fn test_sam_11_l09_pending_refresh_upgrade_discards_old_traffic_and_timer_recovers() {
    use pocket_ic::PocketIcBuilder;

    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_application_subnet()
        .build();
    let subnets = pic.topology().get_app_subnets();
    assert_eq!(subnets.len(), 2);
    let controller = p(0x91);

    let pool = pic.create_canister_on_subnet(Some(controller), None, subnets[1]);
    pic.add_cycles(pool, 2_000_000_000_000u128);
    let token = pic.create_canister_on_subnet(Some(controller), None, subnets[1]);
    pic.add_cycles(token, 2_000_000_000_000u128);
    let monitor = pic.create_canister_on_subnet(Some(controller), None, subnets[0]);
    pic.add_cycles(monitor, 2_000_000_000_000u128);
    assert_ne!(pic.get_subnet(monitor), pic.get_subnet(token));

    pic.install_canister(
        pool,
        pool_wasm(),
        candid::encode_one(PoolInitArgs {
            token_canister: token,
            nullifier_canister: p(0x22),
            merkle_canister: p(0x23),
            treasury_canister: p(0x24),
            staking_canister: p(0x25),
            controller,
            initial_vk_hash: [0; 32],
            initial_proof_system: "groth16-bn254".into(),
            verifier_canister: None,
        }).unwrap(),
        Some(controller),
    );
    pic.install_canister(
        token,
        token_wasm(),
        candid::encode_one(&all_to(pool)).unwrap(),
        Some(controller),
    );
    let interval_ns = 30 * 24 * 60 * 60 * 1_000_000_000u64;
    let init = MonitorInit {
        token_canister: token,
        pool_principal: pool,
        treasury_principal: treasury_principal(),
        pool_attestation_source: pool,
        refresh_interval_ns: interval_ns,
        max_staleness_ns: interval_ns,
        history_capacity: 8,
    };
    pic.install_canister(
        monitor,
        monitor_wasm(),
        candid::encode_one(&init).unwrap(),
        Some(controller),
    );
    settle(&pic);
    let baseline = get_snapshot(&pic, monitor);
    assert_eq!(baseline.status, SnapshotStatus::Fresh);
    let baseline_history = get_history(&pic, monitor);
    let baseline_leaf = certified_canonical_bytes(&pic, monitor);

    // Pay the install-code throttle and manual cooldown before parking A.
    pic.advance_time(Duration::from_secs(7 * 24 * 60 * 60));
    settle(&pic);
    let settled_snapshot = get_snapshot(&pic, monitor);
    let settled_history = get_history(&pic, monitor);
    let settled_leaf = certified_canonical_bytes(&pic, monitor);

    let a = pic.submit_call(
        monitor,
        anon(),
        "request_refresh",
        candid::encode_args(()).unwrap(),
    ).expect("submit A");
    pic.tick();
    assert!(pic.ingress_status(a.clone()).is_none(),
        "A must be pending after its admitted pre-await segment");

    let b = pic.submit_call(
        monitor,
        anon(),
        "request_refresh",
        candid::encode_args(()).unwrap(),
    ).expect("submit B");
    pic.tick();
    let b_result: Result<(), String> = decode("B cooldown", pic.await_call(b));
    assert!(matches!(b_result, Err(ref e) if e.contains("rate-limited")));
    assert!(pic.ingress_status(a.clone()).is_none(),
        "A must still be pending at the upgrade stop point");
    assert_eq!(get_snapshot(&pic, monitor).refreshed_at_ns, settled_snapshot.refreshed_at_ns);
    assert_eq!(get_history(&pic, monitor).len(), settled_history.len());
    assert_eq!(certified_canonical_bytes(&pic, monitor), settled_leaf);

    pic.upgrade_canister(
        monitor,
        monitor_wasm(),
        candid::encode_args(()).unwrap(),
        Some(controller),
    ).expect("upgrade while A is pending");
    let _ = pic.await_call(a);

    // Old cross-subnet traffic may settle, but its destroyed continuation may
    // neither append nor overwrite the restored and recertified state.
    settle(&pic);
    assert_eq!(get_snapshot(&pic, monitor).refreshed_at_ns, settled_snapshot.refreshed_at_ns);
    assert_eq!(get_history(&pic, monitor).len(), settled_history.len());
    assert_eq!(certified_canonical_bytes(&pic, monitor), settled_leaf);

    pic.advance_time(Duration::from_secs(30 * 24 * 60 * 60));
    settle(&pic);
    let recovered = get_snapshot(&pic, monitor);
    assert_eq!(recovered.status, SnapshotStatus::Fresh);
    assert!(recovered.refreshed_at_ns > settled_snapshot.refreshed_at_ns);
    assert_eq!(get_history(&pic, monitor).len(), settled_history.len() + 1);

    // The initial snapshots are referenced to make explicit that staging did
    // not begin from the install placeholder.
    assert!(!baseline_history.is_empty());
    assert_ne!(baseline_leaf, Vec::<u8>::new());
}


#[test]
fn test_sam_12_l09_overlong_refresh_uses_start_time_fails_closed_then_recovers() {
    use pocket_ic::PocketIcBuilder;

    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_application_subnet()
        .build();
    let subnets = pic.topology().get_app_subnets();
    let controller = p(0x92);
    let pool = pic.create_canister_on_subnet(Some(controller), None, subnets[1]);
    let token = pic.create_canister_on_subnet(Some(controller), None, subnets[1]);
    let monitor = pic.create_canister_on_subnet(Some(controller), None, subnets[0]);
    for cid in [pool, token, monitor] {
        pic.add_cycles(cid, 2_000_000_000_000u128);
    }
    pic.install_canister(
        pool,
        pool_wasm(),
        candid::encode_one(PoolInitArgs {
            token_canister: token,
            nullifier_canister: p(0x22),
            merkle_canister: p(0x23),
            treasury_canister: p(0x24),
            staking_canister: p(0x25),
            controller,
            initial_vk_hash: [0; 32],
            initial_proof_system: "groth16-bn254".into(),
            verifier_canister: None,
        }).unwrap(),
        Some(controller),
    );
    pic.install_canister(
        token,
        token_wasm(),
        candid::encode_one(&all_to(pool)).unwrap(),
        Some(controller),
    );
    let bound_ns = 90_000_000_000u64;
    pic.install_canister(
        monitor,
        monitor_wasm(),
        candid::encode_one(MonitorInit {
            token_canister: token,
            pool_principal: pool,
            treasury_principal: treasury_principal(),
            pool_attestation_source: pool,
            refresh_interval_ns: bound_ns,
            max_staleness_ns: bound_ns,
            history_capacity: 8,
        }).unwrap(),
        Some(controller),
    );
    settle(&pic);
    let baseline = get_snapshot(&pic, monitor);
    let baseline_history_len = get_history(&pic, monitor).len();

    pic.advance_time(Duration::from_secs(61));
    let start_lower = pic.get_time().as_nanos_since_unix_epoch() as u64;
    let a = pic.submit_call(
        monitor,
        anon(),
        "request_refresh",
        candid::encode_args(()).unwrap(),
    ).expect("submit overlong A");
    pic.tick();
    let start_upper = pic.get_time().as_nanos_since_unix_epoch() as u64;
    assert!(pic.ingress_status(a.clone()).is_none(), "A must be pending before delay");

    // The interval timer fires during this delay, but A is younger than the
    // five-minute owner expiry and therefore keeps ownership.
    pic.advance_time(Duration::from_secs(91));
    let completed: Result<(), String> = decode("overlong A", pic.await_call(a));
    completed.expect("the ingress completes; its snapshot must fail closed");
    let failed = get_snapshot(&pic, monitor);
    assert_eq!(failed.status, SnapshotStatus::RefreshFailed);
    assert!(!failed.healthy);
    assert!(failed.refreshed_at_ns >= start_lower && failed.refreshed_at_ns <= start_upper,
        "refreshed_at_ns must be the admitted sample start, not completion");
    assert!(failed.refreshed_at_ns < pic.get_time().as_nanos_since_unix_epoch() as u64);
    assert_eq!(get_history(&pic, monitor).len(), baseline_history_len + 1);
    assert_eq!(failed.fixed_max_supply_e8s, baseline.fixed_max_supply_e8s,
        "failed refresh carries prior figures");

    pic.advance_time(Duration::from_secs(90));
    settle(&pic);
    let recovered = get_snapshot(&pic, monitor);
    assert_eq!(recovered.status, SnapshotStatus::Fresh);
    assert!(recovered.healthy);
    assert!(recovered.refreshed_at_ns > failed.refreshed_at_ns);
}


#[test]
fn test_sam_13_l09_malformed_attestation_is_certified_unhealthy_then_recovers() {
    let pic = PocketIc::new();
    let (_token, _pool_account, monitor) = deploy_rig(&pic, token_wasm());
    let source_cfg: MonitorInit = decode(
        "get_config",
        pic.query_call(monitor, anon(), "get_config", candid::encode_args(()).unwrap()),
    );
    let pool_source = source_cfg.pool_attestation_source;
    let before = get_snapshot(&pic, monitor);
    assert_eq!(before.pool_attestation_source_status, SourceReadStatus::Ok);
    assert!(before.healthy);

    // Pay the install-code throttle before replacing only the source module.
    // Keep the real source funded while the artificial seven-day test clock
    // jump drives timer rounds.
    pic.add_cycles(pool_source, 100_000_000_000_000u128);
    pic.advance_time(Duration::from_secs(7 * 24 * 60 * 60));
    settle(&pic);
    let stable_before_malformed = get_snapshot(&pic, monitor);
    let leaf_before_malformed = certified_canonical_bytes(&pic, monitor);

    let malformed = FixedCertifiedPoolAttestation {
        attestation: FixedPoolAttestation {
            public_delta_e8s: 0,
            healthy: true,
            attested_at_ns: pic.get_time().as_nanos_since_unix_epoch() as u64,
            schema_version: 2,
        },
        canonical_bytes: ByteBuf::from(vec![]),
        certificate: None,
        witness: ByteBuf::from(vec![]),
    };
    let payload = candid::encode_one(malformed).expect("encode fixed malformed reply");
    pic.upgrade_canister(
        pool_source,
        fixed_attestation_responder_wasm(&payload),
        candid::encode_args(()).unwrap(),
        None,
    ).expect("temporarily replace pool with fixed malformed responder");

    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 1);
    let rejected = get_snapshot(&pic, monitor);
    assert_eq!(
        rejected.pool_attestation_source_status,
        SourceReadStatus::Malformed,
        "a successfully decoded unsupported schema is Malformed, not CallFailed",
    );
    assert_eq!(rejected.status, SnapshotStatus::Fresh);
    assert!(!rejected.healthy);
    assert!(rejected.refreshed_at_ns > stable_before_malformed.refreshed_at_ns);
    let malformed_history = get_history(&pic, monitor);
    assert_eq!(
        malformed_history.last().unwrap().pool_attestation_source_status,
        SourceReadStatus::Malformed,
    );
    let certified = get_certified(&pic, monitor);
    let cert = certified.certificate.as_ref().expect("certified malformed snapshot");
    let witness: Value =
        serde_cbor::from_slice(&certified.witness).expect("malformed witness CBOR decode");
    assert_eq!(
        tree_digest(&witness).to_vec(),
        certified_data_from_certificate(cert, monitor),
        "malformed snapshot witness root must be subnet-certified",
    );
    let malformed_leaf =
        tree_lookup(&witness, &[TREE_KEY]).expect("witness reveals malformed snapshot leaf");
    assert_eq!(malformed_leaf, certified.canonical_bytes.to_vec());
    assert_ne!(malformed_leaf, leaf_before_malformed);
    let parsed = parse_canonical(&malformed_leaf);
    assert_eq!(parsed.pool_attestation_source_status, 2);
    assert!(!parsed.healthy);

    // The responder upgrade invoked the real pool's pre_upgrade first. Restore
    // that module and require its stable checkpoint to decode and answer again.
    pic.upgrade_canister(
        pool_source,
        pool_wasm(),
        candid::encode_args(()).unwrap(),
        None,
    ).expect("restore real pool over its preserved checkpoint");
    advance_and_settle(&pic, REFRESH_INTERVAL_SECS + 1);
    let recovered = get_snapshot(&pic, monitor);
    assert_eq!(recovered.pool_attestation_source_status, SourceReadStatus::Ok);
    assert_eq!(recovered.status, SnapshotStatus::Fresh);
    assert!(recovered.healthy);
    assert!(recovered.refreshed_at_ns > rejected.refreshed_at_ns);
    assert_eq!(
        get_history(&pic, monitor).last().unwrap().pool_attestation_source_status,
        SourceReadStatus::Ok,
    );

}
