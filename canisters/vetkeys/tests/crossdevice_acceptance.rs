// =============================================================================
// vetKeys cross-device acceptance tests (BRIEF_VETKEYS_CROSSDEVICE §5 DoD)
// =============================================================================
//
// Proves, against a real PocketIC instance with real vetKD:
//   1. Determinism / cross-device: a FRESH session (new transport key), same II
//      principal, re-derives the IDENTICAL vetKey, re-derives the identical
//      note secrets, and reconstructs the note set from the merkle-tree's
//      public `get_payloads` alone — the cross-device acceptance test.
//      Recovery is the same flow on a fresh session (asserted by the same test).
//   2. Isolation: user B derives a DIFFERENT key and cannot decrypt user A's
//      payloads; anonymous callers are rejected. (A caller cannot even ASK for
//      another user's key — the endpoint takes no owner parameter.)
//   3. IBE ciphertext size: a standard 104-byte note payload encrypts to well
//      under the merkle-tree's MAX_ENCRYPTED_PAYLOAD_BYTES = 1024 cap.
//
// RUN REQUIREMENTS (see canisters/vetkeys/Cargo.toml header):
//   - this crate's Wasm built first (wasm32-unknown-unknown --release)
//   - the WORKSPACE merkle_tree.wasm built (../../target/wasm32.../release/)
//   - POCKET_IC_BIN pointing at a pocket-ic server with vetKD support
//
// DERIVATION SPEC (must byte-match wallet/src/crypto/notes.ts — the shared
// test vector below pins the HKDF layer across both implementations):
//   master_note_secret = vetkey.derive_symmetric_key("stsh-notes-master-v1", 32)
//   per-note (index i, u64 LE):
//     HKDF-SHA256(ikm = master, salt = "stsh-note-v1",
//                 info = "stsh.note." || LE64(i), out = 96 bytes)
//       -> spend_key = out[0..32], rho = out[32..64], rseed = out[64..96]
// =============================================================================

use candid::{CandidType, Deserialize, Principal};
use hkdf::Hkdf;
use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, IbeCiphertext, IbeIdentity, IbeSeed, TransportSecretKey, VetKey};
use pocket_ic::{PocketIc, PocketIcBuilder};
use sha2::Sha256;

// ── Pinned constants (must match canisters/vetkeys/src/lib.rs + wallet) ───────
const KEY_NAME: &[u8] = b"notes";
const MASTER_DOMAIN_SEP: &str = "stsh-notes-master-v1";
const NOTE_HKDF_SALT: &[u8] = b"stsh-note-v1";
/// merkle-tree MAX_ENCRYPTED_PAYLOAD_BYTES (canisters/merkle-tree/src/lib.rs:164)
const MAX_ENCRYPTED_PAYLOAD_BYTES: usize = 1024;

// ── Wasm loading ───────────────────────────────────────────────────────────────
fn vetkeys_wasm() -> Vec<u8> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/wasm32-unknown-unknown/release/stsh_vetkeys.wasm"
    );
    std::fs::read(p).unwrap_or_else(|e| {
        panic!(
            "stsh_vetkeys.wasm not found ({e}) — build first:\n  cargo build \
             --manifest-path canisters/vetkeys/Cargo.toml --target wasm32-unknown-unknown --release"
        )
    })
}

fn merkle_wasm() -> Vec<u8> {
    // Workspace target dir — two levels up from this crate.
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/wasm32-unknown-unknown/release/merkle_tree.wasm"
    );
    std::fs::read(p).unwrap_or_else(|e| {
        panic!(
            "merkle_tree.wasm not found ({e}) — build the workspace canisters first \
             (cargo build --target wasm32-unknown-unknown --release -p merkle_tree)"
        )
    })
}

// ── Derivation helpers (the spec above; mirrored in wallet notes.ts) ──────────

/// Mirror of ic_vetkeys::key_manager::key_id_to_vetkd_input — the vetKD
/// derivation input and therefore the IBE identity for a user:
/// `len(principal) || principal || key_name`.
fn vetkd_input(principal: Principal, key_name: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(principal.as_slice().len() + 1 + key_name.len());
    input.push(principal.as_slice().len() as u8);
    input.extend(principal.as_slice());
    input.extend(key_name);
    input
}

fn master_note_secret(vetkey: &VetKey) -> Vec<u8> {
    vetkey.derive_symmetric_key(MASTER_DOMAIN_SEP, 32)
}

#[derive(Debug, PartialEq, Eq)]
struct NoteSecrets {
    spend_key: [u8; 32],
    rho: [u8; 32],
    rseed: [u8; 32],
}

fn derive_note_secrets(master: &[u8], index: u64) -> NoteSecrets {
    let hk = Hkdf::<Sha256>::new(Some(NOTE_HKDF_SALT), master);
    let mut info = b"stsh.note.".to_vec();
    info.extend(index.to_le_bytes());
    let mut okm = [0u8; 96];
    hk.expand(&info, &mut okm).expect("96 bytes is a valid HKDF-SHA256 length");
    // Reduce each chunk mod Fr so the secrets are canonical field elements —
    // raw HKDF output is a uniform 256-bit value, usually >= the (~254-bit) Fr
    // modulus. Mirrors the wallet's reduceLeToField and the circuit's
    // input-signal reduction (byte-identical: stsh_poseidon_wasm::reduce_le_field
    // == Fr::from_le_bytes_mod_order round-trip == wallet `% Fr`).
    let red = |s: &[u8]| stsh_poseidon_wasm::reduce_le_field(&s.try_into().unwrap());
    NoteSecrets {
        spend_key: red(&okm[0..32]),
        rho: red(&okm[32..64]),
        rseed: red(&okm[64..96]),
    }
}

/// Note payload layout — MUST match wallet notes.ts noteToBytes:
/// value (8B BE) || rho (32) || rseed (32) || recipientPk (32) = 104 bytes.
fn note_to_bytes(value: u64, rho: &[u8; 32], rseed: &[u8; 32], recipient_pk: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(104);
    buf.extend(value.to_be_bytes());
    buf.extend(rho);
    buf.extend(rseed);
    buf.extend(recipient_pk);
    buf
}

// ── L0-B note v2 (L3a) — nonce-keyed derivation + 0x02/121-byte payload ───────
//
// v2 keys the HKDF on a fresh 16-byte CSPRNG NONCE stored IN the payload
// (v1 keyed on a sequential index). MUST byte-match wallet notes.ts
// `deriveNoteSecretsV2` / `noteToBytesV2` — the pinned vector below and
// wallet/tests/notes_v2_l3a.test.ts pin the identical constants; update BOTH
// or neither.

/// HKDF salt for v2 per-note derivation — wallet NOTE_HKDF_SALT_V2.
const NOTE_HKDF_SALT_V2: &[u8] = b"stsh-note-v2";
/// HKDF info prefix for v2 — wallet NOTE_HKDF_INFO_PREFIX_V2.
const NOTE_HKDF_INFO_PREFIX_V2: &[u8] = b"stsh.note.v2";
/// v2 payload version byte + exact length (wallet NOTE_PAYLOAD_*_V2).
const NOTE_PAYLOAD_VERSION_V2: u8 = 0x02;
const NOTE_PAYLOAD_BYTES_V2: usize = 1 + 16 + 8 + 32 + 32 + 32; // 121

/// v2 per-note derivation: HKDF-SHA256(ikm = master, salt = "stsh-note-v2",
/// info = "stsh.note.v2" || nonce, out = 96) with each 32-byte chunk reduced
/// mod Fr — mirror of wallet `deriveNoteSecretsV2`.
fn derive_note_secrets_v2(master: &[u8], nonce: &[u8; 16]) -> NoteSecrets {
    let hk = Hkdf::<Sha256>::new(Some(NOTE_HKDF_SALT_V2), master);
    let mut info = NOTE_HKDF_INFO_PREFIX_V2.to_vec();
    info.extend(nonce);
    let mut okm = [0u8; 96];
    hk.expand(&info, &mut okm).expect("96 bytes is a valid HKDF-SHA256 length");
    let red = |s: &[u8]| stsh_poseidon_wasm::reduce_le_field(&s.try_into().unwrap());
    NoteSecrets {
        spend_key: red(&okm[0..32]),
        rho: red(&okm[32..64]),
        rseed: red(&okm[64..96]),
    }
}

/// v2 payload layout — MUST match wallet notes.ts noteToBytesV2:
/// version 0x02 || nonce (16) || value (8B BE) || rho (32) || rseed (32)
/// || recipientPk (32) = exactly 121 bytes.
fn note_to_bytes_v2(
    nonce: &[u8; 16],
    value: u64,
    rho: &[u8; 32],
    rseed: &[u8; 32],
    recipient_pk: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(NOTE_PAYLOAD_BYTES_V2);
    buf.push(NOTE_PAYLOAD_VERSION_V2);
    buf.extend(nonce);
    buf.extend(value.to_be_bytes());
    buf.extend(rho);
    buf.extend(rseed);
    buf.extend(recipient_pk);
    buf
}

// ── PocketIC setup ─────────────────────────────────────────────────────────────


// ── W-VETKEYS (D-1): the endpoint's typed reply/refusal, mirrored ────────────
//
// `get_encrypted_vetkey` moved from `variant { Ok : blob; Err : text }` to the
// typed channel the brief pins (V1 §4, V4 §H′). These declarations mirror
// `vetkeys.did` INDEPENDENTLY of the canister crate's own types: the test
// harness decodes what a real client would decode, so a silent field or
// variant reordering shows up here as a decode failure rather than being
// inherited from the code under test.
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq)]
struct EncryptedVetKeyReply {
    encrypted_key: Vec<u8>,
    remaining: u8,
}

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq)]
enum VetkeysError {
    AnonymousCaller,
    // Layer 1 (§B/§C/§E). Order MUST match the canister's declaration — candid
    // variants are matched by hashed field name, so a mismatch is a decode
    // error rather than a silent misread, but keeping the order aligned keeps
    // the two declarations reviewable side by side.
    RateLimited(String),
    DerivationQuotaExceeded { retry_after_ns: u64 },
    AdmissionLapsed,
    InvalidTransportKey(String),
    NotAuthorized(String),
    InvalidRequest(String),
    BootstrapNotAuthorized { reason: String },
    ApprovalRejected(String),
    RegistrationRateExceeded { retry_after_ns: u64 },
    RevocationRateExceeded { retry_after_ns: u64 },
    DeviceLimitReached { active: u32 },
    UnknownDevice,
    DeviceRevoked,
    PrincipalNotEligible(String),
    EligibilityCheckUnavailable(String),
    // C-26 remedy (fix brief V3 §7.2) — mirrored independently of the canister
    // crate, like every variant above. `candid::Nat` mirrors the DID `nat`
    // (the canister's u128), decoded as what a real client would decode.
    CycleFloorReached { liquid_cycles: candid::Nat, required_cycles: candid::Nat },
    GlobalDerivationBudgetExceeded { retry_after_ns: u64 },
    // V5 §6 — held-balance-age. Mirrored independently, like every variant
    // above: if the canister renamed or reshaped it, this decodes as an error
    // rather than silently agreeing with the code under test.
    EligibilityAgeNotMet { retry_after_ns: u64 },
    // LAUNCH-HARDEN-04 O-3 — the per-principal hourly derive cap. Mirrored
    // independently, like every variant above.
    PrincipalHourlyDerivationCapExceeded { retry_after_ns: u64 },
}

type VetKeyResult = Result<EncryptedVetKeyReply, VetkeysError>;

// ── C-26 observability (A1 fix brief V5 §3, §6.7) ────────────────────────────
//
// Mirrored INDEPENDENTLY of the canister crate, for the reason stated above the
// error channel: the harness must decode what a real client decodes. A field
// added, removed or retyped canister-side without the DID and this mirror
// moving together shows up here as a decode failure.

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq)]
enum CycleFloorView {
    Live { admits: bool },
    FloorOnly { meets_pinned_floor: bool, reason: String },
    Unavailable(String),
}

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq)]
struct DeriveBudgetStats {
    window_ns: u64,
    budget: u32,
    consumed: u32,
    retry_after_ns: u64,
    tagged_consumed: u32,
    distinct_principals: u32,
    max_by_one_principal: u32,
    first_derive_dispatches: u32,
    refusals_budget_total: u64,
    verification_key_management_calls_total: u64,
    stats_epoch_ns: u64,
    floor: CycleFloorView,
    sightings_recorded_total: u64,
    age_refusals_total: u64,
    sightings_pending: u32,
}

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
struct SignedApproval {
    issuer_device_id: String,
    nonce: Vec<u8>,
    expiry_ns: u64,
    signature: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
enum DeviceApproval {
    Bootstrap,
    Device(SignedApproval),
}

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
struct DeviceView {
    device_id: String,
    enc_pubkey_spki: Vec<u8>,
    sign_pubkey_spki: Vec<u8>,
    active: bool,
    added_at_ns: u64,
    revoked_at_ns: Option<u64>,
    approved_by_device: Option<String>,
}

/// Render the typed reply back to the `Result<Vec<u8>, String>` shape the
/// pre-existing A-2 arms assert on, PRESERVING their message substrings. The
/// arms below are unchanged: this exists so the move to a typed channel does
/// not quietly weaken or restate what lane A-2 already proved.
fn flatten(r: VetKeyResult) -> Result<Vec<u8>, String> {
    match r {
        Ok(reply) => Ok(reply.encrypted_key),
        Err(VetkeysError::AnonymousCaller) => Err(
            "anonymous callers cannot derive a vetKey — authenticate with Internet Identity"
                .to_string(),
        ),
        Err(VetkeysError::RateLimited(message)) => Err(message),
        Err(VetkeysError::DerivationQuotaExceeded { retry_after_ns }) => Err(format!(
            "derivation quota exceeded (§H′); retry_after_ns={retry_after_ns}"
        )),
        Err(VetkeysError::AdmissionLapsed) => Err("admission lapsed (§H′)".to_string()),
        Err(VetkeysError::InvalidTransportKey(message)) => Err(message),
        Err(VetkeysError::NotAuthorized(message)) => Err(message),
        Err(other) => Err(format!("{other:?}")),
    }
}

struct Harness {
    pic: PocketIc,
    vetkeys_id: Principal,
    merkle_id: Principal,
    /// The principal the merkle canister accepts append_commitment from.
    pool: Principal,
    /// §D: the mock token canister answering `icrc1_balance_of`.
    token_id: Principal,
}

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

/// A minimal ICRC-1 token canister that answers `icrc1_balance_of` with ONE
/// fixed balance.
///
/// Hand-written WAT rather than the real token Wasm, deliberately: the §D
/// coupling under test is "one outbound read-only balance query", and a stub
/// that answers a candid `nat` exercises exactly that without dragging the
/// token's install arguments, ledger state and fee model into a vetKeys test.
/// The reply is a literal candid encoding — `DIDL` header, one `nat` (0x7d),
/// LEB128 value — so the bytes on the wire are pinned by this function rather
/// than by another canister's behaviour.
fn candid_nat_reply(balance_e8s: u128) -> Vec<u8> {
    let mut reply = Vec::new();
    reply.extend_from_slice(b"DIDL");
    reply.push(0x00);
    reply.push(0x01);
    reply.push(0x7d); // nat
    let mut n = balance_e8s;
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        reply.push(byte);
        if n == 0 {
            break;
        }
    }
    reply
}

fn mock_token_wasm(balance_e8s: u128) -> Vec<u8> {
    let reply = candid_nat_reply(balance_e8s);
    let escaped: String = reply.iter().map(|b| format!("\\{b:02x}")).collect();
    wat::parse_str(format!(
        r#"(module
             (import "ic0" "msg_reply_data_append" (func $append (param i32 i32)))
             (import "ic0" "msg_reply" (func $reply))
             (memory 1)
             (data (i32.const 0) "{escaped}")
             (func (export "canister_update icrc1_balance_of")
               (call $append (i32.const 0) (i32.const {len}))
               (call $reply))
             (func (export "canister_init")))"#,
        escaped = escaped,
        len = reply.len()
    ))
    .expect("valid WAT")
}

/// A token canister whose balance reply takes TWO EXTRA ROUNDS to come back.
///
/// WHY THIS EXISTS. The §H′.5 probe needs a call PARKED in the eligibility
/// await while OTHER calls are admitted — that interleaving is the whole of
/// RED-6. With an instant-reply token it is unreachable from a test: PocketIC
/// delivers a pending response before it executes newly-submitted ingress, so
/// the parked call always resumes first and simply spends the slot it still
/// holds. Adding real latency to the reply is what makes the ordering the brief
/// describes actually occur, rather than being asserted about.
///
/// The latency is a SELF-CALL: `icrc1_balance_of` calls this same canister's
/// `hop` method and replies from the callback (a callback runs in the original
/// call's context, so replying there replies to the vetkeys canister). Two
/// extra rounds, no second canister id to plumb in, no timers.
fn slow_token_wasm(balance_e8s: u128) -> Vec<u8> {
    let reply = candid_nat_reply(balance_e8s);
    let escaped: String = reply.iter().map(|b| format!("\\{b:02x}")).collect();
    wat::parse_str(format!(
        r#"(module
             (import "ic0" "msg_reply_data_append" (func $append (param i32 i32)))
             (import "ic0" "msg_reply" (func $reply))
             (import "ic0" "canister_self_copy" (func $self_copy (param i32 i32 i32)))
             (import "ic0" "canister_self_size" (func $self_size (result i32)))
             (import "ic0" "call_new"
               (func $call_new (param i32 i32 i32 i32 i32 i32 i32 i32)))
             (import "ic0" "call_perform" (func $call_perform (result i32)))
             (memory 1)
             (table 2 funcref)
             (elem (i32.const 0) $on_reply $on_reject)
             (data (i32.const 0) "{escaped}")
             (data (i32.const 100) "hop")
             (func (export "canister_update icrc1_balance_of")
               (call $self_copy (i32.const 200) (i32.const 0) (call $self_size))
               (call $call_new
                 (i32.const 200) (call $self_size)
                 (i32.const 100) (i32.const 3)
                 (i32.const 0) (i32.const 0)
                 (i32.const 1) (i32.const 0))
               (drop (call $call_perform)))
             (func (export "canister_update hop")
               (call $append (i32.const 0) (i32.const {len}))
               (call $reply))
             (func $on_reply (param i32)
               (call $append (i32.const 0) (i32.const {len}))
               (call $reply))
             (func $on_reject (param i32)
               (call $append (i32.const 0) (i32.const {len}))
               (call $reply))
             (func (export "canister_init")))"#,
        escaped = escaped,
        len = reply.len()
    ))
    .expect("valid WAT")
}

/// A token canister that TRAPS on every balance query — the "we could not ask"
/// case, which must surface as the retryable `EligibilityCheckUnavailable` and
/// never as a verdict about the principal.
fn trapping_token_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (memory 1)
             (func (export "canister_update icrc1_balance_of") unreachable)
             (func (export "canister_init")))"#,
    )
    .expect("valid WAT")
}

/// Comfortably above the pinned §D floor (0.1 STSH = 10_000_000 e8s).
const RICH_BALANCE_E8S: u128 = 5_000_000_000;
/// Comfortably below it — and deliberately NOT zero, so the arm proves the
/// FLOOR is what refuses, not merely "has no tokens at all".
const POOR_BALANCE_E8S: u128 = 9_999_999;

fn install_mock_token(pic: &PocketIc, wasm: Vec<u8>) -> Principal {
    let id = pic.create_canister();
    pic.add_cycles(id, 2_000_000_000_000);
    pic.install_canister(id, wasm, candid::encode_args(()).unwrap(), None);
    id
}

fn setup() -> Harness {
    // The II subnet hosts the vetKD master test keys in PocketIC (same pattern
    // as the threshold-ECDSA test keys); nonmainnet features enable them.
    let pic = PocketIcBuilder::new()
        .with_ii_subnet()
        .with_application_subnet()
        .with_nonmainnet_features(true)
        .build();

    // §D: a funded mock token, configured through the trailing init argument.
    // Every existing arm derives as a first-ever derive, so without an eligible
    // balance the whole suite would fail closed — which is itself the point of
    // the fail-closed design.
    let token_id = install_mock_token(&pic, mock_token_wasm(RICH_BALANCE_E8S));

    let vetkeys_id = pic.create_canister();
    pic.add_cycles(vetkeys_id, 1_000_000_000_000_000); // vetkd_derive_key ≈ 26B/call
    pic.install_canister(
        vetkeys_id,
        vetkeys_wasm(),
        candid::encode_args(("test_key_1".to_string(), Some(token_id))).unwrap(),
        None,
    );

    let pool = p(0x05);
    let merkle_id = pic.create_canister();
    pic.add_cycles(merkle_id, 2_000_000_000_000);
    pic.install_canister(
        merkle_id,
        merkle_wasm(),
        candid::encode_one(pool).unwrap(),
        None,
    );

    Harness { pic, vetkeys_id, merkle_id, pool, token_id }
}

fn decode<T>(label: &str, res: Result<Vec<u8>, pocket_ic::RejectResponse>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
{
    let bytes = res.unwrap_or_else(|e| panic!("{label}: call rejected: {e:?}"));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{label}: decode failed: {e}"))
}

impl Harness {
    fn verification_key(&self) -> DerivedPublicKey {
        // R6-1 (lane A-2): this endpoint now REJECTS the anonymous principal
        // (it previously had no caller check at all), so the harness calls it
        // as an authenticated principal — the same thing the wallet does, where
        // `fetchUserVetKey` runs over the authenticated session agent. The
        // anonymous refusal itself is asserted by E6.
        let bytes: Vec<u8> = decode(
            "get_vetkey_verification_key",
            self.pic.update_call(
                self.vetkeys_id,
                p(0xA1),
                "get_vetkey_verification_key",
                candid::encode_args(()).unwrap(),
            ),
        );
        DerivedPublicKey::deserialize(&bytes).expect("valid canister-scoped vetKD public key")
    }

    /// One "device session": fresh transport key -> encrypted vetKey -> decrypt+verify.
    fn fetch_vetkey(&self, user: Principal, dpk: &DerivedPublicKey, seed: [u8; 32]) -> VetKey {
        let tsk = TransportSecretKey::from_seed(seed.to_vec()).expect("32-byte seed");
        // Same one-shot age-in as `try_get_encrypted_vetkey_typed` (V5 §6): a
        // first-ever derive records a sighting and is refused until T. Routed
        // through the typed helper so this path cannot drift from that one.
        let result: Result<Vec<u8>, String> =
            flatten(self.try_get_encrypted_vetkey_typed(user, tsk.public_key()));
        let ek_bytes = result.expect("authenticated caller must obtain its own vetKey");
        let ek = EncryptedVetKey::deserialize(&ek_bytes).expect("valid encrypted vetKey");
        ek.decrypt_and_verify(&tsk, dpk, &vetkd_input(user, KEY_NAME))
            .expect("decrypt-and-verify against the canister verification key")
    }

    fn append_payload(&self, commitment: [u8; 32], payload: Vec<u8>) -> u64 {
        let result: Result<u64, String> = decode(
            "append_commitment",
            self.pic.update_call(
                self.merkle_id,
                self.pool,
                "append_commitment",
                candid::encode_args((commitment.to_vec(), payload)).unwrap(),
            ),
        );
        result.expect("append_commitment as the pool principal must succeed")
    }

    fn get_payloads(&self, from: u64, limit: u64) -> Vec<(u64, Vec<u8>)> {
        decode(
            "get_payloads",
            self.pic.query_call(
                self.merkle_id,
                Principal::anonymous(), // DEF-073: intentionally public
                "get_payloads",
                candid::encode_args((from, limit)).unwrap(),
            ),
        )
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

/// DoD: cross-device acceptance + recovery + ciphertext size, in one flow.
#[test]
fn test_cross_device_note_reconstruction() {
    let h = setup();
    let user_a = p(0xA1);
    let dpk = h.verification_key();

    // ── Device 1: derive vetKey, derive note secrets, shield a note ──────────
    let vetkey_d1 = h.fetch_vetkey(user_a, &dpk, [0x11; 32]);
    let master_d1 = master_note_secret(&vetkey_d1);
    let secrets = derive_note_secrets(&master_d1, 0);

    let note_value: u64 = 100_000_000_000; // 1,000 STSH — DENOMINATIONS[0] (A6.6)
    let recipient_pk = secrets.spend_key; // placeholder pk binding (M3 defines pk derivation)
    let note_bytes = note_to_bytes(note_value, &secrets.rho, &secrets.rseed, &recipient_pk);
    assert_eq!(note_bytes.len(), 104, "note payload layout is 104 bytes");

    // IBE-encrypt to user A's OWN identity (self-shield) — identity is the
    // vetKD input bytes, and the public key needs NO canister call.
    let identity = IbeIdentity::from_bytes(&vetkd_input(user_a, KEY_NAME));
    let payload = IbeCiphertext::encrypt(&dpk, &identity, &note_bytes, &IbeSeed::random(&mut rand::thread_rng())).serialize();

    // DoD: ciphertext must fit the merkle-tree payload cap.
    assert!(
        payload.len() <= MAX_ENCRYPTED_PAYLOAD_BYTES,
        "IBE ciphertext {} bytes exceeds MAX_ENCRYPTED_PAYLOAD_BYTES {}",
        payload.len(),
        MAX_ENCRYPTED_PAYLOAD_BYTES
    );

    // A decoy payload from user B, to prove the scan filters by decryptability.
    let user_b = p(0xB2);
    let identity_b = IbeIdentity::from_bytes(&vetkd_input(user_b, KEY_NAME));
    let decoy = IbeCiphertext::encrypt(&dpk, &identity_b, b"not user A's note", &IbeSeed::random(&mut rand::thread_rng())).serialize();

    // Commitment bytes must be canonical BN254 Fr (LE high byte < 0x30) or the
    // merkle canister's DEF-041 canonicality check rejects the append.
    h.append_payload([0x1C; 32], payload);
    h.append_payload([0x2C; 32], decoy);

    // ── Device 2: FRESH session (new transport key), same II principal ───────
    let vetkey_d2 = h.fetch_vetkey(user_a, &dpk, [0x22; 32]);
    assert_eq!(
        vetkey_d2.signature_bytes(),
        vetkey_d1.signature_bytes(),
        "same principal must re-derive the IDENTICAL vetKey on any device"
    );
    let master_d2 = master_note_secret(&vetkey_d2);
    assert_eq!(master_d2, master_d1, "master note secret is deterministic");

    // Rebuild the note set from public on-chain data ALONE (get_payloads scan).
    let pages = h.get_payloads(0, 100);
    assert_eq!(pages.len(), 2, "both payloads visible to the public scan");

    let mut recovered: Vec<Vec<u8>> = Vec::new();
    for (_idx, bytes) in &pages {
        if let Ok(ct) = IbeCiphertext::deserialize(bytes) {
            if let Ok(pt) = ct.decrypt(&vetkey_d2) {
                recovered.push(pt);
            }
        }
    }
    assert_eq!(recovered.len(), 1, "exactly user A's payload trial-decrypts");
    assert_eq!(recovered[0], note_bytes, "recovered note bytes are identical");

    // The recovered note's secrets re-derive from the vetKey (index 0) —
    // proving the wallet can rebuild spendable state, not just read bytes.
    let secrets_d2 = derive_note_secrets(&master_d2, 0);
    assert_eq!(secrets_d2.rho, secrets.rho, "rho re-derived identically");
    assert_eq!(secrets_d2.rseed, secrets.rseed, "rseed re-derived identically");
    assert_eq!(secrets_d2.spend_key, secrets.spend_key, "spend_key re-derived identically");
    // Recovery (§5) == this same flow on a fresh session: covered by construction.
}

/// DoD: user A cannot obtain user B's key; keys are disjoint; anonymous rejected.
#[test]
fn test_key_isolation_and_anonymous_rejection() {
    let h = setup();
    let dpk = h.verification_key();
    let user_a = p(0xA1);
    let user_b = p(0xB2);

    let vetkey_a = h.fetch_vetkey(user_a, &dpk, [0x33; 32]);
    let vetkey_b = h.fetch_vetkey(user_b, &dpk, [0x44; 32]);
    assert_ne!(
        vetkey_a.signature_bytes(),
        vetkey_b.signature_bytes(),
        "different principals must derive different vetKeys"
    );

    // B cannot decrypt a payload IBE-encrypted to A. (B also cannot REQUEST A's
    // key: the endpoint derives from the caller's own principal — there is no
    // owner parameter to abuse.)
    let identity_a = IbeIdentity::from_bytes(&vetkd_input(user_a, KEY_NAME));
    let ct = IbeCiphertext::encrypt(&dpk, &identity_a, b"user A's secret note", &IbeSeed::random(&mut rand::thread_rng()));
    assert!(
        ct.decrypt(&vetkey_b).is_err(),
        "user B's vetKey must NOT decrypt user A's payload"
    );
    assert_eq!(
        ct.decrypt(&vetkey_a).expect("A decrypts own payload"),
        b"user A's secret note".to_vec()
    );

    // Anonymous callers are rejected before any derivation.
    let tsk = TransportSecretKey::from_seed(vec![0x55; 32]).unwrap();
    let result: Result<Vec<u8>, String> = flatten(decode(
        "get_encrypted_vetkey (anonymous)",
        h.pic.update_call(
            h.vetkeys_id,
            Principal::anonymous(),
            "get_encrypted_vetkey",
            candid::encode_one(tsk.public_key()).unwrap(),
        ),
    ));
    assert!(result.is_err(), "anonymous caller must be rejected");
    assert!(
        result.unwrap_err().contains("anonymous"),
        "rejection names the anonymous-caller rule"
    );
}

/// Pinned cross-language test vector for the HKDF note-secret layer. The wallet
/// (wallet/tests/notes.test.ts) asserts the SAME hex from the SAME inputs, so
/// the TS and Rust derivations cannot drift apart silently.
#[test]
fn test_note_secret_derivation_vector() {
    let master = [0xABu8; 32];
    let s0 = derive_note_secrets(&master, 0);
    let s1 = derive_note_secrets(&master, 1);

    // Deterministic + unique per index.
    assert_ne!(s0.spend_key, s1.spend_key);
    assert_ne!(s0.rho, s1.rho);
    assert_ne!(s0.rseed, s1.rseed);
    let s0_again = derive_note_secrets(&master, 0);
    assert_eq!(s0.spend_key, s0_again.spend_key);

    // Pinned vector (hex of spend_key||rho||rseed for master=0xAB*32, index 0).
    // wallet/tests/notes.test.ts pins the identical value — update BOTH or neither.
    let concat: Vec<u8> = [s0.spend_key.as_slice(), s0.rho.as_slice(), s0.rseed.as_slice()].concat();
    let hex: String = concat.iter().map(|b| format!("{b:02x}")).collect();
    // Pinned 2026-07-13 (Fr-REDUCED secrets — wallet-build Commit 2). Was the
    // raw-HKDF `0c231b76…` before; secrets are now reduced mod Fr so they are
    // valid field elements. wallet/tests/vetkeys_notes.test.ts pins the
    // identical constant — update BOTH or neither. (Backslash-newline in a Rust
    // string literal strips the newline + leading whitespace.)
    let expected = "08231bb6b902c6203c6733f569bc35bf18dc928423f0e6da68abc021b3d8ff08\
                    d91537a74f69ad54a080cbfd060187aea86ae45f9062f40eaa48355aa1bcc02e\
                    7a37a79134207c585c511938bff1d81256d1482774065478b4ba9ad105893919";
    assert_eq!(hex, expected);
}

/// Pinned cross-language test vector for the L0-B note-v2 layer (L3a re-review
/// gate): the nonce-keyed HKDF derivation AND the exact 0x02/121-byte payload.
/// wallet/tests/notes_v2_l3a.test.ts asserts the IDENTICAL constants from the
/// SAME inputs (master = 0x11*32, nonce = 0xA5*16, value = 100_000_000,
/// recipient_pk = 0x22*32) — update BOTH or neither.
#[test]
fn test_note_v2_derivation_and_payload_vector() {
    let master = [0x11u8; 32];
    let nonce = [0xA5u8; 16];
    let s = derive_note_secrets_v2(&master, &nonce);

    // Deterministic in (master, nonce); a different nonce diverges.
    let s_again = derive_note_secrets_v2(&master, &nonce);
    assert_eq!(s.spend_key, s_again.spend_key);
    let other = derive_note_secrets_v2(&master, &[0xA6u8; 16]);
    assert_ne!(s.spend_key, other.spend_key);

    let to_hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
    // Pinned 2026-07-19 from the wallet implementation (Fr-REDUCED secrets).
    assert_eq!(
        to_hex(&s.spend_key),
        "621c9edfc0757e794110575baf4d094ae6f773d2082e5b06eb9521863be9900c"
    );
    assert_eq!(
        to_hex(&s.rho),
        "b94fb3a09411db2391f2bbe30aec656dbacf2e9db8b28711a4bed1a1f53d0006"
    );
    assert_eq!(
        to_hex(&s.rseed),
        "1f6f8894356d53b34cd2f0bb803b57990781599cef9c33c52ade8bfab3b02d19"
    );

    // Exact 121-byte payload for value = 1 STSH (100_000_000 e8s) and a fixed
    // recipient_pk — byte-identical to wallet `noteToBytesV2`.
    let payload = note_to_bytes_v2(&nonce, 100_000_000, &s.rho, &s.rseed, &[0x22u8; 32]);
    assert_eq!(payload.len(), NOTE_PAYLOAD_BYTES_V2);
    assert_eq!(
        to_hex(&payload),
        "02a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a50000000005f5e100\
         b94fb3a09411db2391f2bbe30aec656dbacf2e9db8b28711a4bed1a1f53d0006\
         1f6f8894356d53b34cd2f0bb803b57990781599cef9c33c52ade8bfab3b02d19\
         2222222222222222222222222222222222222222222222222222222222222222"
    );
}

/// Rust reference for the wallet's commitment / nullifier / merkle-leaf
/// equality checkpoints (wallet-build Commit 2). Computes the FULL chain from
/// the SAME pinned input (master = 0x01*32, index 0) through the SAME
/// circom-anchored Poseidon the wallet's WASM uses (stsh-poseidon-wasm — proven
/// == circomlibjs and == stsh_field_utils::merkle_leaf in Commit 1). The wallet
/// tests (commitment.test.ts / nullifier.test.ts) pin the identical hex, so the
/// TS and Rust derivations cannot drift. This is the authoritative path — not a
/// second hand-derivation.
#[test]
fn test_commitment_nullifier_leaf_reference_vector() {
    use stsh_poseidon_wasm::{poseidon2_core, poseidon3_core, poseidon4_core, poseidon6_core};

    const OHSPU_FR: &str =
        "4523128485832663883733241601901871400518358776001584537534818377974931259392";
    const VALUE: u64 = 100_000_000_000; // 1,000 STSH (DENOMINATIONS[0], A6.6 five-tier ladder)
    let le = |n: u64| {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&n.to_le_bytes());
        b
    };
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    // ohspu principal → Fr, LE bytes (via the reduce helper on the decimal).
    let pool = stsh_poseidon_wasm::reduce_le_field(&dec_to_le32(OHSPU_FR));

    let secrets = derive_note_secrets(&[0x01u8; 32], 0);

    // Chain (source-verified spend.circom):
    let domain_hash = poseidon4_core(&pool, &le(0), &le(3), &le(1)).unwrap();
    let recipient_pk = poseidon2_core(&secrets.spend_key, &le(1 /*PK_DOMAIN*/)).unwrap();
    let commitment = poseidon6_core(
        &domain_hash,
        &le(VALUE),
        &recipient_pk,
        &secrets.rho,
        &secrets.rseed,
        &le(3 /*COMMITMENT_DOMAIN*/),
    )
    .unwrap();
    let nullifier =
        poseidon4_core(&domain_hash, &secrets.spend_key, &commitment, &le(2 /*NULLIFIER_DOMAIN*/))
            .unwrap();
    let leaf = poseidon3_core(&le(VALUE), &commitment, &le(4 /*MERKLE_LEAF_DOMAIN*/)).unwrap();

    // Independent cross-check: the leaf equals the pool's own implementation.
    let expected_leaf = stsh_field_utils::merkle_leaf(VALUE as u128, &commitment);
    assert_eq!(leaf, expected_leaf, "leaf must equal stsh_field_utils::merkle_leaf");

    // Pinned 2026-07-13; RE-DERIVED at lane A6.6 (DOMAIN_CIRCUIT_VERSION 2 -> 3).
    // Also pinned byte-identically in the wallet vitest.
    assert_eq!(hex(&domain_hash), "f86a7fd6a66d358ddbe7d8fa7b303f5da7e63d41b7ee207c6a31359c6220c125");
    assert_eq!(hex(&recipient_pk), "57d5c538e0154b3538ff4cf4d9523a74772da7998031f529723d1feababc4b27");
    assert_eq!(hex(&commitment), "dac25340d371120136a0b6d2d77523f584dffb930dced7564c6bb6d3683e0711");
    assert_eq!(hex(&nullifier), "8e3f63d306c5c7c04220d4a65cc5647b43dd4cb012f886444ef25cde09261014");
    assert_eq!(hex(&leaf), "b7f1b8f69c5cf8df50376c2c1c8d20f49db37d7b091d7c3bb255ab9075de4c21");
}

/// Parse a decimal string into a 32-byte LE field element via ark Fr.
fn dec_to_le32(dec: &str) -> [u8; 32] {
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use core::str::FromStr;
    let fr = Fr::from_str(dec).expect("valid decimal Fr");
    let le = fr.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
    out
}

// ── H-2 (A4): freeze the derivation input + context as behavioral fixtures ────────

/// H-2 (A4): pin the EXACT vetKD derivation input and context bytes the canister relies
/// on, using the LIBRARY function `ic_vetkeys::key_manager::key_id_to_vetkd_input` (NOT the
/// local `vetkd_input` mirror), so the derivation namespace is frozen as a behavioral
/// fixture — not a duplicated-constant compare. `wallet/tests/vetkeys.test.ts` pins the
/// identical principal + expected vector via the wallet's `vetkdInput` (update BOTH or
/// neither). These are three one-way doors (context, application key name, input encoding).
#[test]
fn test_h2_a4_vetkd_input_and_context_fixed_vector() {
    use ic_vetkeys::key_manager::key_id_to_vetkd_input;

    // One fixed principal (raw 10-byte id) — byte-identical to the wallet fixture.
    let principal = Principal::from_slice(&[
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x02,
    ]);
    // The library builds len(principal) || principal || key_name. KEY_NAME = b"notes".
    let input = key_id_to_vetkd_input(principal, KEY_NAME);
    let expected_input: [u8; 16] = [
        0x0a, // len = 10
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x02, // principal
        0x6e, 0x6f, 0x74, 0x65, 0x73, // "notes"
    ];
    assert_eq!(
        input, expected_input,
        "vetKD derivation input for the pinned principal is frozen (len || principal || notes)"
    );

    // Exact context bytes = UTF-8 of "stsh.wallet.notes.v1", pinned as an explicit vector
    // (a regression guard on the exact namespace bytes, not `DOMAIN_SEPARATOR.as_bytes()`).
    let expected_context: [u8; 20] = [
        0x73, 0x74, 0x73, 0x68, 0x2e, 0x77, 0x61, 0x6c, 0x6c, 0x65, // "stsh.walle"
        0x74, 0x2e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x2e, 0x76, 0x31, // "t.notes.v1"
    ];
    assert_eq!(
        "stsh.wallet.notes.v1".as_bytes(),
        &expected_context,
        "vetKD context (domain separator) bytes are frozen"
    );

    // Application key name frozen (the `notes` one-way door).
    assert_eq!(KEY_NAME, b"notes", "application key name is frozen");
}

// ── H-2 (A2): upgrade preservation + fresh-cell-trap on the PRODUCTION Wasm ───────
//
// The cross-cutting campaign gate: a #[post_upgrade] change must be proven by a REAL
// upgrade_canister to the production Wasm that asserts the persisted config is correctly
// reconstructed. vetkeys ships ONE Wasm (no test-feature split), so vetkeys_wasm() IS the
// production release Wasm.

/// A minimal, valid canister that exports `canister_init` (no-op) and writes NOTHING to
/// stable memory. Upgrading FROM this TO the production vetkeys Wasm is a GENUINE cross-Wasm
/// upgrade with an EMPTY predecessor — NOT a reinstall (which wipes state) masquerading as an
/// upgrade. It leaves the KeyManager config StableCell (mem 0) uninitialized, so the
/// production post_upgrade's `KeyManager::init` stores the sentinel default and
/// `validate_retained_config` traps (A1). This is how A2 case-3 exercises the REAL
/// post_upgrade on a fresh cell, per the SSA final-pass ruling (unit tests do not satisfy
/// the gate).
fn empty_predecessor_wasm() -> Vec<u8> {
    wat::parse_str(r#"(module (memory 1) (func (export "canister_init")))"#)
        .expect("valid WAT for the empty predecessor canister")
}

fn build_pic() -> PocketIc {
    // The II subnet hosts the vetKD master test keys; nonmainnet features enable them.
    PocketIcBuilder::new()
        .with_ii_subnet()
        .with_application_subnet()
        .with_nonmainnet_features(true)
        .build()
}

fn get_config(pic: &PocketIc, id: Principal) -> (String, String) {
    // get_config returns a candid MULTI-VALUE `(text, text)` (two return values), so it must
    // be decoded with decode_args — NOT the single-value decode_one the harness `decode`
    // helper uses (which fails with "wire_type: text, expect_type: record").
    let bytes = pic
        .query_call(
            id,
            Principal::anonymous(),
            "get_config",
            candid::encode_args(()).unwrap(),
        )
        .expect("get_config query must not be rejected");
    candid::decode_args(&bytes).expect("get_config decodes as (text, text)")
}

/// A2 (1–2, RELEASE BLOCKERS): a legitimately installed vetKD key (`"test_key_1"` or the
/// production `"key_1"`) survives a REAL upgrade to the production Wasm byte-for-byte. No
/// derive call is needed — only that post_upgrade preserves (does not trap on) a legit key.
fn assert_config_preserved_across_upgrade(key_name: &str) {
    let pic = build_pic();
    let id = pic.create_canister();
    pic.add_cycles(id, 1_000_000_000_000_000);
    pic.install_canister(
        id,
        vetkeys_wasm(),
        candid::encode_one(key_name.to_string()).unwrap(),
        None,
    );

    let before = get_config(&pic, id);
    assert_eq!(
        before,
        ("stsh.wallet.notes.v1".to_string(), key_name.to_string()),
        "installed config must be (domain, {key_name})"
    );

    // A REAL upgrade to the production Wasm (vetkeys ships one artifact).
    pic.upgrade_canister(id, vetkeys_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("upgrade must SUCCEED — a legitimately installed key is preserved, not trapped");

    let after = get_config(&pic, id);
    assert_eq!(
        after, before,
        "the (domain, key_name) config tuple must be byte-for-byte unchanged across the upgrade"
    );
}

#[test]
fn test_h2_a2_preservation_test_key_1() {
    assert_config_preserved_across_upgrade("test_key_1");
}

#[test]
fn test_h2_a2_preservation_key_1() {
    assert_config_preserved_across_upgrade("key_1");
}

/// A2 (case-3): a REAL upgrade from an EMPTY predecessor (fresh config cell) to the
/// production Wasm must TRAP in post_upgrade — the fail-closed sentinel is detected rather
/// than silently creating a new cryptographic namespace. Also confirms the `\0`-prefixed
/// sentinel round-trips the config StableCell's Candid encoding (if it did not, the fresh
/// write/read would fail before the sentinel could even be detected).
#[test]
fn test_h2_a2_case3_fresh_cell_upgrade_traps() {
    let pic = build_pic();
    let id = pic.create_canister();
    pic.add_cycles(id, 1_000_000_000_000_000);
    pic.install_canister(
        id,
        empty_predecessor_wasm(),
        candid::encode_args(()).unwrap(),
        None,
    );

    let upgrade = pic.upgrade_canister(id, vetkeys_wasm(), candid::encode_args(()).unwrap(), None);
    assert!(
        upgrade.is_err(),
        "post_upgrade MUST trap on a fresh config cell (surviving sentinel) — an Ok here would \
         mean a silent re-key of every user"
    );
    let reason = format!("{:?}", upgrade.unwrap_err());
    assert!(
        reason.contains("ABSENT") || reason.contains("sentinel"),
        "the trap reason must name the absent-config / sentinel cause; got: {reason}"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// R6-1 (lane A-2) — metering acceptance, E6..E10
// ═════════════════════════════════════════════════════════════════════════════
//
// E1..E5 are unit tests over the PURE `meter_admit` (canisters/vetkeys/src/lib.rs).
// The limbs below genuinely need the canister boundary and cannot be proven by
// a unit test: the two anonymous rejects, the charge-before-await ordering, the
// no-refund-on-failure guarantee (which requires observing what the PRODUCTION
// ENDPOINT does after a failure), and the balance query's Candid shape.

/// The metering constants, mirrored from src/lib.rs. Deliberately duplicated
/// rather than imported: this crate is `crate-type = ["cdylib"]`, so the tests
/// drive it over PocketIC and cannot link its `pub const`s. E5 pins the
/// production values; a drift between the two shows up as an E8/E9 failure.
const MAX_DERIVATIONS_PER_WINDOW: u32 = 5;

/// LAUNCH-HARDEN-04 O-3 — the per-principal hourly derive DISPATCH cap
/// (`pins::PER_PRINCIPAL_HOURLY_DERIVE_CAP`), mirrored as a literal for the
/// same reason as the pins above: reading it from the code under test could
/// not RED when it moves. Owner-ratified 2026-09-24
/// (RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24, sha256 249f551b…ec417).
///
/// It sits BELOW the A-2 meter's 5/h, so a single principal can no longer see
/// five SUCCESSFUL derives inside one hour: calls 3..=5 are metered (the meter
/// charges every call) and then refused at the dispatch fence with
/// `PrincipalHourlyDerivationCapExceeded`, and call 6 is refused by the meter.
/// The pre-existing arms below that drove five successes per principal per hour
/// are adapted to that shape; what each proved about the meter/§H′ still holds.
const PER_PRINCIPAL_HOURLY_DERIVE_CAP: u32 = 2;

/// The tightest funding that installs `stsh_vetkeys.wasm`, MEASURED (PocketIC
/// reports the exact deficit in its install rejection). Re-measured for the
/// LAUNCH-HARDEN-04 Wasm: the prior figure (301_691_759_530) + 200M margin fell
/// short by 26_966_000 cycles, so the new minimum is 301_918_725_530. Install
/// cost scales with module size; the 200M jitter margin is kept on top.
const MEASURED_MIN_INSTALL_CYCLES: u128 = 301_918_725_530;

/// A syntactically valid 48-byte BLS12-381 G1 transport public key encoding is
/// required; this one is deliberately malformed so the endpoint fails the
/// transport-key validation — which since R-5 (L04-01) happens BEFORE the
/// METER/`with_admission` charge, not after it.
const INVALID_TRANSPORT_KEY: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];

/// T = 2 minutes (V5 §6.1; value per 559b411e…, superseding 6b60d432…), as
/// this suite's OWN literal. Reading the canister's pin here would move the
/// expectation with the constant.
const ELIGIBILITY_MIN_AGE_NS: u64 = 120_000_000_000;

impl Harness {
    /// Raw `get_encrypted_vetkey` — returns the endpoint's own Result so a
    /// refusal can be inspected rather than unwrapped.
    fn try_get_encrypted_vetkey(&self, user: Principal, tpk: Vec<u8>) -> Result<Vec<u8>, String> {
        flatten(self.try_get_encrypted_vetkey_typed(user, tpk))
    }

    /// The TYPED refusal, for the §H′ arms: which mechanism refused is the
    /// whole question there, and a rendered string cannot answer it.
    ///
    /// **AGES IN AUTOMATICALLY (V5 §6).** A principal's FIRST derive now records
    /// a sighting and is refused until the balance has been held for T. This
    /// helper does exactly what the wallet does: on `EligibilityAgeNotMet` it
    /// waits precisely the `retry_after_ns` the canister named, then retries
    /// ONCE. That keeps every pre-existing arm exercising the REAL shipped
    /// admission path — sighting write included — instead of a bypass.
    ///
    /// EXACTLY ONE retry, and only on that variant: any other refusal is
    /// returned untouched, and a second age refusal is returned rather than
    /// waited out again. An arm that wants to SEE the gate calls
    /// `try_get_encrypted_vetkey_raw` instead.
    fn try_get_encrypted_vetkey_typed(&self, user: Principal, tpk: Vec<u8>) -> VetKeyResult {
        match self.try_get_encrypted_vetkey_raw(user, tpk.clone()) {
            Err(VetkeysError::EligibilityAgeNotMet { retry_after_ns }) => {
                self.pic.advance_time(std::time::Duration::from_nanos(retry_after_ns));
                self.pic.tick();
                self.try_get_encrypted_vetkey_raw(user, tpk)
            }
            other => other,
        }
    }

    /// The endpoint with NO age-in retry — what the §6 arms use, because the
    /// refusal is the thing under test there.
    fn try_get_encrypted_vetkey_raw(&self, user: Principal, tpk: Vec<u8>) -> VetKeyResult {
        decode(
            "get_encrypted_vetkey",
            self.pic.update_call(
                self.vetkeys_id,
                user,
                "get_encrypted_vetkey",
                candid::encode_one(tpk).unwrap(),
            ),
        )
    }

    /// Record a sighting for every principal, then advance the clock ONCE.
    ///
    /// For arms that derive MANY principals. The per-call helper above would
    /// advance T for each of them in turn, and an arm measuring a rolling
    /// window would find the window had rolled underneath it — the wait would
    /// become the thing being measured. Sightings are valid for seven days, so
    /// recording them all first and waiting once is both faithful and inert.
    fn age_in_all(&self, users: &[Principal]) {
        for (i, u) in users.iter().enumerate() {
            match self.try_get_encrypted_vetkey_raw(*u, Harness::valid_transport_key(i as u8)) {
                Err(VetkeysError::EligibilityAgeNotMet { .. }) => {}
                // Already established, or already sighted — both fine. Anything
                // else means the fixture is not in the state the arm assumes.
                Ok(_) => {}
                Err(e) => panic!("age_in_all: principal {i} refused unexpectedly: {e:?}"),
            }
        }
        self.pic.advance_time(std::time::Duration::from_nanos(ELIGIBILITY_MIN_AGE_NS));
        self.pic.tick();
    }

    fn valid_transport_key(seed: u8) -> Vec<u8> {
        TransportSecretKey::from_seed(vec![seed; 32]).expect("32-byte seed").public_key()
    }
}

/// E6 — the anonymous principal is rejected by `get_vetkey_verification_key`.
/// Before R6-1 this endpoint had NO caller check at all.
#[test]
fn e6_anonymous_rejected_by_verification_key() {
    let h = setup();
    let res = h.pic.update_call(
        h.vetkeys_id,
        Principal::anonymous(),
        "get_vetkey_verification_key",
        candid::encode_args(()).unwrap(),
    );
    let err = res.expect_err("anonymous must be refused");
    let text = format!("{err:?}");
    assert!(
        text.contains("anonymous"),
        "the refusal must name the anonymous-caller rule, got: {text}"
    );
    // Non-vacuity: an AUTHENTICATED caller still succeeds.
    let ok = h.pic.update_call(
        h.vetkeys_id,
        p(0xA1),
        "get_vetkey_verification_key",
        candid::encode_args(()).unwrap(),
    );
    assert!(ok.is_ok(), "an authenticated caller must still obtain the verification key");
}

/// E7 — non-regression: anonymous is still rejected by `get_encrypted_vetkey`,
/// and rejected BEFORE any budget is touched.
#[test]
fn e7_anonymous_still_rejected_by_get_encrypted_vetkey() {
    let h = setup();
    let err = h
        .try_get_encrypted_vetkey(Principal::anonymous(), Harness::valid_transport_key(0x55))
        .expect_err("anonymous caller must be rejected");
    assert!(err.contains("anonymous"), "rejection names the anonymous-caller rule, got: {err}");
    assert!(
        !err.contains("rate limit"),
        "anonymous must be refused by the anon check, not by the meter: {err}"
    );
}

/// E8 — CHARGE BEFORE AWAIT. The load-bearing concurrency proof.
///
/// `MAX + 25` ingress messages from ONE principal are SUBMITTED BEFORE any
/// tick, so they are all in flight across the endpoint's `.await` together. If
/// the counter were incremented only after the derivation resolved, every one
/// of them would observe budget available and every one would be forwarded to
/// `vetkd_derive_key`.
///
/// THE OBSERVABLE, and why the volume matters. At this depth the broken
/// ordering is not merely wasteful — it overruns the subnet's vetKD request
/// queue, `vetkd_derive_key` rejects with "request queue ... is full", and
/// ic-vetkeys TRAPS on the rejected call. So the mutation is visible as
/// TRAPPED CALLS, not just as an inflated admit count.
///
/// MEASURED, and recorded because it is the difference between evidence and
/// decoration:
/// ```text
///   over = MAX + 3   correct → admitted 5, refused 3, trapped 0
///                    charge-after-await → admitted 5, refused 3, trapped 0  ← DOES NOT BITE
///   over = MAX + 25  correct → admitted 5, refused 25, trapped 0
///                    charge-after-await → calls TRAP (vetKD queue full)     ← BITES
/// ```
/// At depth 3 the messages do not actually overlap the await under PocketIC, so
/// the shallower form passes on a BROKEN implementation — exactly the failure
/// the brief warned about. Do not reduce this depth, and do not downgrade this
/// to a loop of `update_call`: a sequential test passes on the broken build.
#[test]
fn e8_concurrent_in_flight_calls_cannot_exceed_the_budget() {
    let h = setup();
    let user = p(0xA1);
    let over = MAX_DERIVATIONS_PER_WINDOW + 25;
    // V5 §6: record this principal's sighting and let it age in BEFORE the arm
    // begins, then reset the meter — an age-refused attempt is still a call, and
    // the A-2 meter charges every call. Doing it here keeps the age gate out of
    // the boundary this arm actually measures.
    h.age_in_all(&[user]);
    h.skip_the_meter_window();

    // Submit them all FIRST — nothing executes until the tick.
    let mut ids = Vec::new();
    for i in 0..over {
        ids.push(
            h.pic
                .submit_call(
                    h.vetkeys_id,
                    user,
                    "get_encrypted_vetkey",
                    candid::encode_one(Harness::valid_transport_key(0x60 + i as u8)).unwrap(),
                )
                .expect("submit"),
        );
    }

    let mut admitted = 0u32;
    let mut rate_limited = 0u32;
    // LAUNCH-HARDEN-04 O-3: of the meter's five admitted calls, only
    // PER_PRINCIPAL_HOURLY_DERIVE_CAP may DISPATCH; the rest are refused at the
    // fence with the per-principal variant — concurrently, with no trap.
    let mut capped = 0u32;
    let mut trapped: Vec<String> = Vec::new();
    for id in ids {
        match h.pic.await_call(id) {
            Err(reject) => trapped.push(format!("{reject:?}")),
            Ok(raw) => {
                let res: VetKeyResult = candid::decode_one(&raw).unwrap();
                match res {
                    Ok(_) => admitted += 1,
                    Err(VetkeysError::PrincipalHourlyDerivationCapExceeded { .. }) => capped += 1,
                    Err(other) => {
                        let e = flatten(Err(other)).unwrap_err();
                        assert!(
                            e.contains("rate limit"),
                            "the only other expected refusal is the meter: {e}"
                        );
                        rate_limited += 1;
                    }
                }
            }
        }
    }

    // The primary observable: nothing trapped. A trap here means more requests
    // reached `vetkd_derive_key` than the budget permits — i.e. the meter did
    // not gate BEFORE the await.
    assert!(
        trapped.is_empty(),
        "{} of {over} concurrent calls TRAPPED — the budget was not charged before the \
         await, so excess requests reached vetKD and overran its queue. First: {}",
        trapped.len(),
        trapped.first().map(String::as_str).unwrap_or("")
    );
    assert_eq!(
        admitted, PER_PRINCIPAL_HOURLY_DERIVE_CAP,
        "at most the per-principal hourly cap may DISPATCH across concurrent in-flight calls \
         (admitted={admitted}, capped={capped}, rate_limited={rate_limited})"
    );
    assert_eq!(
        admitted + capped,
        MAX_DERIVATIONS_PER_WINDOW,
        "exactly the meter's window budget passes the meter (admitted + fence-capped)"
    );
    assert_eq!(rate_limited, over - MAX_DERIVATIONS_PER_WINDOW, "the rest must be refused by the meter");
}

/// E9 — NO REFUND ON FAILURE, proven against the PRODUCTION ENDPOINT.
///
/// `MAX` calls that fail on §D FIRST-DERIVE ELIGIBILITY (a below-floor
/// balance, `PrincipalNotEligible`) each fail *after* the meter charge — the
/// eligibility check runs at STEP 3b, strictly after `preflight` (R-5,
/// L04-01: the transport-key check moved BEFORE `preflight`, so it no longer
/// serves as a post-charge failure vehicle; `PrincipalNotEligible` still
/// does) — so they exhaust the budget. A subsequent call from the SAME
/// principal, even with a valid transport key, must then be refused by the
/// meter. A unit test over `meter_admit` could not observe this: a refund
/// written on the endpoint's failure branch would leave it green.
///
/// NON-VACUITY: the untouched-principal check is taken BEFORE any upgrade,
/// and asserts the VARIANT, not success. An upgrade clears the heap-only
/// METER (r3_1 step 3), so taking this observation after an upgrade would
/// destroy the exact evidence a global-accounting bug leaves behind (a shared
/// budget exhausted by `user`'s five calls). `PrincipalNotEligible` on the
/// untouched principal proves it got PAST the meter on its own budget; a
/// global-accounting bug would instead yield `RateLimited` here.
#[test]
fn e9_failed_calls_are_not_refunded() {
    // Every principal is below the §D floor by construction.
    let h = setup_with_token(Some(mock_token_wasm(POOR_BALANCE_E8S)));
    let user = p(0xA9);

    for i in 0..MAX_DERIVATIONS_PER_WINDOW {
        match h.try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(i as u8)) {
            Err(VetkeysError::PrincipalNotEligible(_)) => {}
            other => panic!(
                "call {} must fail on §D eligibility (i.e. AFTER the meter charge), got: {other:?}",
                i + 1
            ),
        }
    }

    // The budget is now spent by failures alone. A VALID call from the SAME
    // principal must be refused BY THE METER, not by eligibility — proving
    // the meter, not §D, is what gates here now.
    let err = h
        .try_get_encrypted_vetkey(user, Harness::valid_transport_key(0x77))
        .expect_err("the budget was consumed by the failed calls — no refund");
    assert!(
        err.contains("rate limit"),
        "failed calls must consume budget; a later call must hit the meter, got: {err}"
    );

    // NON-VACUITY, taken BEFORE any upgrade (see the doc comment above): a
    // DIFFERENT, untouched principal still has its own budget, so the
    // exhaustion above is per-caller accounting and not a global break.
    // Reached §D (not the meter) => got PAST the meter on ITS OWN allowance.
    match h.try_get_encrypted_vetkey_typed(p(0xB9), Harness::valid_transport_key(0x78)) {
        Err(VetkeysError::PrincipalNotEligible(_)) => {}
        other => panic!(
            "an untouched principal must still be admitted PAST the meter (failing on its own \
             §D eligibility, not on a shared/exhausted budget), got: {other:?}"
        ),
    }

    // Trailing liveness leg (kept from the original arm, demoted): once
    // reconfigured to a rich token, the untouched principal can actually
    // derive. This is NOT the non-vacuity proof (the match above is) — it is
    // an additional check that the eligibility path still leads somewhere real.
    let rich = install_mock_token(&h.pic, mock_token_wasm(RICH_BALANCE_E8S));
    h.upgrade_with(Some(rich));
    assert!(
        h.try_get_encrypted_vetkey(p(0xB9), Harness::valid_transport_key(0x78)).is_ok(),
        "an untouched, now-eligible principal must still derive after reconfiguration"
    );
}

/// R-5 (L04-01) AC-1 — invalid-transport-key traffic never engages the METER
/// or §H′ admission.
///
/// THE FALSIFIER for the reorder. `admission.rs` is untouched by this lane and
/// the crate has no `testing` feature to hang a state-reading probe off, so
/// the meter's own no-refund behaviour is the only black-box-observable proxy
/// for "zero writes happened" — and it is a faithful one: under base's order
/// (or any intermediate order) each malformed call reaches `meter_admit`, so
/// the SIXTH one inside a single window would be refused by the meter.
///
/// The assertion is specifically on the SIXTH call's variant. Asserting only
/// that the first five refuse on the transport key would pass under the base
/// order too, since the meter only bites on the sixth.
#[test]
fn invalid_transport_key_never_consumes_meter_or_admission() {
    let h = setup();
    let user = p(0xC3);

    for i in 0..(MAX_DERIVATIONS_PER_WINDOW + 1) {
        match h.try_get_encrypted_vetkey_raw(user, INVALID_TRANSPORT_KEY.to_vec()) {
            Err(VetkeysError::InvalidTransportKey(_)) => {}
            Err(VetkeysError::RateLimited(m)) => panic!(
                "call {} was refused BY THE METER ({m}) — a malformed transport key reached \
                 `meter_admit`, so the check no longer precedes METER/with_admission",
                i + 1
            ),
            other => panic!("call {}: expected InvalidTransportKey, got {other:?}", i + 1),
        }
    }
}

/// R-5 (L04-01) AC-2 — the public error shape is unchanged by the relocation.
///
/// Deliberately NOT a falsifier of the ordering property (AC-1 is): this arm
/// exists only to pin the exact typed error and message text across the move.
#[test]
fn invalid_transport_key_error_text_unchanged() {
    let h = setup();
    match h.try_get_encrypted_vetkey_raw(p(0xC4), INVALID_TRANSPORT_KEY.to_vec()) {
        Err(VetkeysError::InvalidTransportKey(msg)) => assert_eq!(
            msg,
            "invalid transport public key encoding (expected a 48-byte BLS12-381 G1 point)",
            "the relocation must not change the public error text"
        ),
        other => panic!("expected InvalidTransportKey, got {other:?}"),
    }
}

/// E9b — the POST-`.await` derivation-failure path: ATTEMPTED, NOT INDUCIBLE.
///
/// The brief requires an attempt to induce a deterministic post-await vetKD
/// failure, and — if it cannot be induced — that the inability be DEMONSTRATED
/// with evidence rather than asserted. This test is that demonstration, and it
/// is written so it FAILS if the path ever becomes inducible.
///
/// What was tried: cycle starvation, the only lever available from inside the
/// fence. Fund the canister so the derivation cannot be paid for while the
/// charge has already been taken. Measured, across four funding levels:
///
/// ```text
///   298_200_000_000  → install itself fails ("out of cycles", needs ~301.2B)
///   301_200_000_000  → installs; ALL derivations SUCCEED
///   305_000_000_000  → installs; ALL derivations SUCCEED
///   400_000_000_000  → installs; ALL derivations SUCCEED
///   1_000_000_000_000 → installs; ALL derivations SUCCEED
/// ```
///
/// There is no funding level that installs the canister and then starves the
/// derivation: under PocketIC's nonmainnet `test_key_1`, `vetkd_derive_key` is
/// effectively free, so the ~26B production cost that makes starvation
/// plausible on mainnet does not exist here. The only regime where the call
/// fails is one where the canister cannot be installed at all — which is not a
/// post-charge failure.
///
/// What covers the path instead: `MeterState` exposes NO decrement, refund,
/// release or remove-single-entry API (src/lib.rs §"THE metering table"), so a
/// refund on ANY branch — including this one — cannot be written without adding
/// a method, which is visible in diff review. That is a structural guarantee,
/// not a behavioural proof, and this package does not claim otherwise.
///
/// See NOTE_A-2_await_failure_uninducible.md.
#[test]
fn e9b_post_await_failure_not_inducible_by_cycle_starvation() {
    let pic = PocketIcBuilder::new()
        .with_ii_subnet()
        .with_application_subnet()
        .with_nonmainnet_features(true)
        .build();
    // §D: this instance builds its own canister, so it needs its own configured
    // token — an unconfigured canister fails first derives CLOSED, which would
    // silently replace this arm's premise (post-await failure) with an
    // eligibility refusal that never reaches the await at all.
    let token_id = install_mock_token(&pic, mock_token_wasm(RICH_BALANCE_E8S));

    let vetkeys_id = pic.create_canister();
    // The tightest funding that still installs. MEASURED, and re-measured
    // whenever the Wasm changes size: install cost scales with module size, so
    // the W-VETKEYS modules moved this figure (PocketIC reports the exact
    // deficit in its rejection, which is how it was re-derived). A too-low
    // value fails the INSTALL, not the assertion — the starvation premise is
    // unaffected either way.
    // Measured minimum (MEASURED_MIN_INSTALL_CYCLES, re-measured for the
    // LAUNCH-HARDEN-04 Wasm) plus a
    // 200M-cycle jitter margin: the exact install cost proved to move a few
    // tens of millions between isolated and full-gate runs of the SAME Wasm,
    // and a too-low value fails the INSTALL, not the assertion. 200M is noise
    // against the ~26B a single derive costs, so the starvation premise —
    // installed, but with nothing to spare at derive scale — is unchanged.
    // C-26 remedy: the cycle floor now refuses derives when the liquid balance
    // is below `live_cost + 500e9` — the remedy for the very starvation this
    // arm probes. THIS arm's funding therefore adds the floor plus generous
    // derive-burn headroom on top of the tight install figure; the
    // floor-refusal regime itself is proven by its own arms (g2_*, below).
    // The claim here stays what it was: ABOVE the floor, no funding level
    // starves the post-await derive under PocketIC's free test key.
    pic.add_cycles(vetkeys_id, MEASURED_MIN_INSTALL_CYCLES + 200_000_000 + 1_400_000_000_000);
    pic.install_canister(
        vetkeys_id,
        vetkeys_wasm(),
        candid::encode_args(("test_key_1".to_string(), Some(token_id))).unwrap(),
        None,
    );

    let user = p(0xC1);

    // V5 §6: the first call records a sighting and is age-refused. Wait exactly
    // T, then clear the meter — the refused attempt was still a call, and the
    // A-2 meter charges every call, so without this the loop below would start
    // with four of its five slots rather than five.
    let first: VetKeyResult = decode(
        "get_encrypted_vetkey",
        pic.update_call(
            vetkeys_id,
            user,
            "get_encrypted_vetkey",
            candid::encode_one(TransportSecretKey::from_seed(vec![0x8F; 32]).unwrap().public_key())
                .unwrap(),
        ),
    );
    assert!(
        matches!(first, Err(VetkeysError::EligibilityAgeNotMet { .. })),
        "a first-ever derive must be age-refused, even on a starved canister; got {first:?}"
    );
    pic.advance_time(std::time::Duration::from_nanos(ELIGIBILITY_MIN_AGE_NS));
    pic.advance_time(PAST_THE_METER_HOUR);
    pic.tick();

    // LAUNCH-HARDEN-04 O-3: a single principal can DISPATCH at most
    // PER_PRINCIPAL_HOURLY_DERIVE_CAP derives per rolling hour, so calls beyond
    // it inside the meter hour are refused at the fence (metered, not
    // dispatched). The starvation claim is about the DISPATCHED ones.
    let mut succeeded = 0u32;
    for i in 0..MAX_DERIVATIONS_PER_WINDOW {
        if i >= PER_PRINCIPAL_HOURLY_DERIVE_CAP {
            let r: VetKeyResult = decode(
                "get_encrypted_vetkey",
                pic.update_call(
                    vetkeys_id,
                    user,
                    "get_encrypted_vetkey",
                    candid::encode_one(
                        TransportSecretKey::from_seed(vec![0x90 + i as u8; 32]).unwrap().public_key(),
                    )
                    .unwrap(),
                ),
            );
            assert!(
                matches!(r, Err(VetkeysError::PrincipalHourlyDerivationCapExceeded { .. })),
                "call {i} past the per-principal cap must be refused at the fence; got {r:?}"
            );
            continue;
        }
        let bytes = pic
            .update_call(
                vetkeys_id,
                user,
                "get_encrypted_vetkey",
                candid::encode_one(
                    TransportSecretKey::from_seed(vec![0x90 + i as u8; 32]).unwrap().public_key(),
                )
                .unwrap(),
            )
            .expect("a starved-but-installed canister still executes the call");
        let res: Result<Vec<u8>, String> = flatten(candid::decode_one(&bytes).unwrap());
        match res {
            Ok(_) => succeeded += 1,
            Err(e) => panic!(
                "POST-AWAIT FAILURE IS NOW INDUCIBLE ({e}). E9b's premise has changed: \
                 replace this observation test with a causal charge/no-refund proof \
                 across the failure, and update NOTE_A-2_await_failure_uninducible.md."
            ),
        }
    }
    assert_eq!(
        succeeded, PER_PRINCIPAL_HOURLY_DERIVE_CAP,
        "at minimal funding every DISPATCHED derivation still succeeds — the starvation lever \
         does not reach the post-await path under PocketIC's test key"
    );

    // Non-vacuity: those successes WERE charged, so the meter is live on this
    // instance and the absence of failures above is about vetKD cost, not about
    // the metering being inert.
    let after = pic
        .update_call(
            vetkeys_id,
            user,
            "get_encrypted_vetkey",
            candid::encode_one(
                TransportSecretKey::from_seed(vec![0x9F; 32]).unwrap().public_key(),
            )
            .unwrap(),
        )
        .expect("call executes");
    let res: Result<Vec<u8>, String> = flatten(candid::decode_one(&after).unwrap());
    let err = res.expect_err("the window budget was spent by the successful derivations");
    assert!(err.contains("rate limit"), "the meter must be live on this instance: {err}");
}

/// E10 — the cycle-balance query lane A-6 will consume: it returns a plausible
/// balance and its Candid type matches `vetkeys.did` (`nat` ← Rust `u128`).
#[test]
fn e10_cycle_balance_query_shape_and_value() {
    let h = setup();
    let balance: u128 = decode(
        "cycle_balance",
        h.pic.query_call(
            h.vetkeys_id,
            Principal::anonymous(), // not sensitive; the monitor may be unauthenticated
            "cycle_balance",
            candid::encode_args(()).unwrap(),
        ),
    );
    // setup() funds the canister with 1e15 cycles; it must report a live,
    // plausible balance, not zero and not the funded amount exactly.
    assert!(balance > 0, "the balance query must report a real balance");
    assert!(
        balance <= 1_000_000_000_000_000,
        "balance {balance} exceeds what setup() funded"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// F-1 (lane A-2, relocated by CTO_RULING_A-3_f1_relocation) — cross-device
// reconstruction on the NOTE v2 path
// ═════════════════════════════════════════════════════════════════════════════
//
// TEST-ONLY: no production behaviour changes for this sub-item.
//
// WHY v2 IS NOT A TRIVIAL RE-RUN OF v1. v1 keys derivation on an INDEX (0),
// which device 2 knows a priori. v2 keys it on a FRESH 16-byte nonce carried
// INSIDE the payload, so device 2 cannot know it in advance — it must read the
// nonce out of the decrypted payload and re-derive from that.
//
// THE ANTI-TAUTOLOGY REQUIREMENT. A test that reuses device 1's `nonce`
// variable when re-deriving on device 2 proves nothing: it just re-runs the KDF
// against an input it was handed. This file removes that possibility BY
// CONSTRUCTION — the recovery assertions run through `reconstruct_note_v2`,
// whose only inputs are the master secret and the recovered plaintext. Device
// 1's nonce is not a parameter and is not in scope at the assertion site, so
// the tautological form is not expressible.

/// What a fresh device can rebuild from a recovered payload and nothing else.
#[derive(Debug, PartialEq, Eq)]
struct ReconstructedNote {
    secrets: NoteSecrets,
    value: u64,
    recipient_pk: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
enum ReconstructError {
    WrongVersion(u8),
    WrongLength(usize),
}

/// Production-shaped v2 recovery: **master secret + recovered plaintext only**.
///
/// This is the shape the wallet must actually implement to recover on a fresh
/// device — it has nothing but the master secret and the public payload bytes.
/// Testing through it tests the real reconstruction contract.
///
/// NOTE THE ABSENT PARAMETER: there is no `nonce` argument. The nonce is parsed
/// out of the plaintext at bytes 1..17, exactly as a fresh device must do.
fn reconstruct_note_v2(
    master: &[u8],
    recovered_plaintext: &[u8],
) -> Result<ReconstructedNote, ReconstructError> {
    // The parse is a GUARD, not a cast.
    if recovered_plaintext.len() != NOTE_PAYLOAD_BYTES_V2 {
        return Err(ReconstructError::WrongLength(recovered_plaintext.len()));
    }
    if recovered_plaintext[0] != NOTE_PAYLOAD_VERSION_V2 {
        return Err(ReconstructError::WrongVersion(recovered_plaintext[0]));
    }
    // version(1) || nonce(16) || value(8 BE) || rho(32) || rseed(32) || pk(32)
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&recovered_plaintext[1..17]);
    let mut value_bytes = [0u8; 8];
    value_bytes.copy_from_slice(&recovered_plaintext[17..25]);
    let mut recipient_pk = [0u8; 32];
    recipient_pk.copy_from_slice(&recovered_plaintext[89..121]);

    Ok(ReconstructedNote {
        secrets: derive_note_secrets_v2(master, &nonce),
        value: u64::from_be_bytes(value_bytes),
        recipient_pk,
    })
}

/// F-1 — cross-device reconstruction on the v2 (nonce-keyed) note path.
///
/// The v1 test above is deliberately left untouched: v1 payloads remain a
/// supported read path.
#[test]
fn test_cross_device_note_reconstruction_v2() {
    let h = setup();
    let user_a = p(0xA1);
    let dpk = h.verification_key();

    // ── Device 1 ────────────────────────────────────────────────────────────
    let vetkey_d1 = h.fetch_vetkey(user_a, &dpk, [0x11; 32]);
    let master_d1 = master_note_secret(&vetkey_d1);

    // TWO DISTINCT fresh nonces — not a reused constant.
    let nonce_1: [u8; 16] = [
        0x3A, 0x71, 0xC4, 0x0E, 0x95, 0x22, 0xDF, 0x68,
        0x11, 0xB3, 0x4C, 0xA7, 0x5E, 0x09, 0xFD, 0x82,
    ];
    let nonce_2: [u8; 16] = [
        0xE1, 0x08, 0x6B, 0xB9, 0x47, 0xD3, 0x2C, 0x50,
        0x9A, 0x7F, 0x15, 0xCE, 0x63, 0xAA, 0x38, 0x04,
    ];
    assert_ne!(nonce_1, nonce_2, "the two notes must use distinct nonces");

    let values: [u64; 2] = [100_000_000, 1_000_000_000]; // 1 STSH and 10 STSH
    let mut built: Vec<(NoteSecrets, u64, [u8; 32], Vec<u8>)> = Vec::new();
    for (nonce, value) in [(&nonce_1, values[0]), (&nonce_2, values[1])] {
        let secrets = derive_note_secrets_v2(&master_d1, nonce);
        let recipient_pk = secrets.spend_key;
        let bytes = note_to_bytes_v2(nonce, value, &secrets.rho, &secrets.rseed, &recipient_pk);
        assert_eq!(bytes.len(), NOTE_PAYLOAD_BYTES_V2, "v2 payload is exactly 121 bytes");
        assert_eq!(bytes[0], NOTE_PAYLOAD_VERSION_V2, "v2 payload version byte is 0x02");
        built.push((secrets, value, recipient_pk, bytes));
    }

    // ── IBE-encrypt each to A's own identity; RE-PROVE the ciphertext cap ────
    // The v2 plaintext is 121 bytes vs v1's 104, so this is not inherited.
    let identity_a = IbeIdentity::from_bytes(&vetkd_input(user_a, KEY_NAME));
    let mut payloads = Vec::new();
    for (_, _, _, bytes) in &built {
        let ct = IbeCiphertext::encrypt(
            &dpk,
            &identity_a,
            bytes,
            &IbeSeed::random(&mut rand::thread_rng()),
        )
        .serialize();
        assert!(
            ct.len() <= MAX_ENCRYPTED_PAYLOAD_BYTES,
            "v2 IBE ciphertext {} bytes exceeds MAX_ENCRYPTED_PAYLOAD_BYTES {}",
            ct.len(),
            MAX_ENCRYPTED_PAYLOAD_BYTES
        );
        payloads.push(ct);
    }

    // A user-B decoy, to prove the scan filters by decryptability.
    let user_b = p(0xB2);
    let identity_b = IbeIdentity::from_bytes(&vetkd_input(user_b, KEY_NAME));
    let decoy = IbeCiphertext::encrypt(
        &dpk,
        &identity_b,
        b"not user A's v2 note",
        &IbeSeed::random(&mut rand::thread_rng()),
    )
    .serialize();

    // Commitment bytes must be canonical BN254 Fr (LE high byte < 0x30) or the
    // merkle canister's DEF-041 canonicality check rejects the append.
    h.append_payload([0x1C; 32], payloads[0].clone());
    h.append_payload([0x2C; 32], payloads[1].clone());
    h.append_payload([0x0C; 32], decoy);

    // ── Device 2: FRESH transport key, same principal ───────────────────────
    let vetkey_d2 = h.fetch_vetkey(user_a, &dpk, [0x22; 32]);
    assert_eq!(
        vetkey_d2.signature_bytes(),
        vetkey_d1.signature_bytes(),
        "same principal must re-derive the IDENTICAL vetKey on any device"
    );
    let master_d2 = master_note_secret(&vetkey_d2);
    assert_eq!(master_d2, master_d1, "master note secret is deterministic");

    // Rebuild from public on-chain data ALONE, with device 2's vetKey only.
    let pages = h.get_payloads(0, 100);
    assert_eq!(pages.len(), 3, "both A-payloads and the decoy are publicly visible");
    let mut recovered: Vec<Vec<u8>> = Vec::new();
    for (_idx, bytes) in &pages {
        if let Ok(ct) = IbeCiphertext::deserialize(bytes) {
            if let Ok(pt) = ct.decrypt(&vetkey_d2) {
                recovered.push(pt);
            }
        }
    }
    assert_eq!(recovered.len(), 2, "exactly user A's two payloads trial-decrypt");

    // ── Reconstruct through the NONCE-FREE helper ───────────────────────────
    // From here on, device 1's nonces are NOT used. Notes are matched to
    // expectations by their reconstructed content, never by a carried index.
    let reconstructed: Vec<ReconstructedNote> = recovered
        .iter()
        .map(|pt| reconstruct_note_v2(&master_d2, pt).expect("a recovered v2 payload must parse"))
        .collect();

    for (expected_secrets, expected_value, expected_pk, _) in &built {
        let found = reconstructed
            .iter()
            .find(|r| &r.secrets == expected_secrets)
            .unwrap_or_else(|| {
                panic!(
                    "no reconstructed note matched the expected secrets for value {expected_value} \
                     — the nonce was not recovered from the payload"
                )
            });
        assert_eq!(found.value, *expected_value, "value reconstructed");
        assert_eq!(&found.recipient_pk, expected_pk, "recipient pk reconstructed");
        assert_eq!(found.secrets.rho, expected_secrets.rho, "rho re-derived identically");
        assert_eq!(found.secrets.rseed, expected_secrets.rseed, "rseed re-derived identically");
        assert_eq!(
            found.secrets.spend_key, expected_secrets.spend_key,
            "spend_key re-derived identically"
        );
    }

    // Nonce-keying genuinely separates the notes — the master secret alone does
    // not carry everything.
    assert_ne!(
        reconstructed[0].secrets, reconstructed[1].secrets,
        "two notes under distinct nonces must reconstruct to DISTINCT secrets"
    );

    // ── The parse is a guard, not a cast ────────────────────────────────────
    let good = &recovered[0];
    let mut wrong_version = good.clone();
    wrong_version[0] = 0x01;
    assert_eq!(
        reconstruct_note_v2(&master_d2, &wrong_version),
        Err(ReconstructError::WrongVersion(0x01)),
        "a non-v2 version byte must be REJECTED, not reinterpreted"
    );
    let mut wrong_length = good.clone();
    wrong_length.push(0x00);
    assert_eq!(
        reconstruct_note_v2(&master_d2, &wrong_length),
        Err(ReconstructError::WrongLength(NOTE_PAYLOAD_BYTES_V2 + 1)),
        "a wrong-length payload must be REJECTED"
    );
    assert_eq!(
        reconstruct_note_v2(&master_d2, &good[..NOTE_PAYLOAD_BYTES_V2 - 1]),
        Err(ReconstructError::WrongLength(NOTE_PAYLOAD_BYTES_V2 - 1)),
        "a truncated payload must be REJECTED"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// R3-1 (sweep fold, test-only) — the METER's upgrade reset is EVIDENCE, not a
// source comment.
//
// `METER` (canisters/vetkeys/src/lib.rs) is heap-only as a deliberate decision,
// and its reason 3 states that an upgrade clears the budget — acceptable because
// upgrades are controller-only and not attacker-reachable. Until this fold, no
// test in the tree combined an upgrade with the meter: every `upgrade_canister`
// here concerned the KeyManager config StableCell, and the metering acceptance
// tests never upgraded.
//
// This is the native-vs-cross-Wasm rule INVERTED. The claim is that state is
// LOST, and a native test can never establish that, because `thread_local`s
// survive in-process. Only a real cross-Wasm upgrade settles it. The regression
// this locks: were METER later moved to stable memory (registry-lint pressure
// makes that a plausible future edit), the comment would silently become false
// and — before this test — nothing would fail, while the unbounded-stable-growth
// surface the same comment warns about quietly opened.
//
// Step 4 is the half that matters as much as step 3: it proves the meter is
// still LIVE after the upgrade, so an upgrade that DISABLED metering (an
// accurate comment turned into a silent removal of the R6-1 rate limit) fails
// here too. Both halves need the canister boundary.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn r3_1_meter_is_cleared_by_a_real_upgrade_and_still_live_after() {
    // R-5 (L04-01): the vehicle for "a call that fails AFTER the meter charge"
    // is now the §D first-derive-eligibility failure, not an invalid transport
    // key — the transport check moved ahead of METER/with_admission, so a
    // malformed key no longer charges anything. POOR balance => every
    // principal is ineligible by construction.
    let h = setup_with_token(Some(mock_token_wasm(POOR_BALANCE_E8S)));
    let user = p(0xE3);

    // 1. Exhaust this caller's window (failed §D-eligibility calls charge — see E9).
    for i in 0..MAX_DERIVATIONS_PER_WINDOW {
        let _ = h.try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(i as u8));
        let _ = i;
    }
    let err = h
        .try_get_encrypted_vetkey(user, Harness::valid_transport_key(0xE4))
        .expect_err("pre-state: the window budget must be spent before the upgrade");
    assert!(
        err.contains("rate limit"),
        "pre-state must be a metered refusal, else the upgrade proves nothing: {err}"
    );

    // 2. A REAL cross-Wasm upgrade (vetkeys ships one artifact).
    h.pic
        .upgrade_canister(
            h.vetkeys_id,
            vetkeys_wasm(),
            candid::encode_args(()).unwrap(),
            None,
        )
        .expect("upgrade must succeed");

    // 3. THE CLAIM: the heap-only meter is cleared, so the same caller is
    //    admitted again (still ineligible, so this must fail on §D, NOT on the
    //    meter — proving the METER specifically was cleared).
    match h.try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(0xE5)) {
        Err(VetkeysError::PrincipalNotEligible(_)) => {}
        other => panic!(
            "post-upgrade: a heap-only METER is cleared, so this caller is admitted past it \
             again (still failing on §D eligibility, unaffected by the upgrade), got: {other:?}"
        ),
    }

    // 4. NON-VACUITY: the meter is still live after the upgrade — re-exhaust and
    //    the refusal must come back. Without this, an upgrade that disabled
    //    metering entirely would pass step 3.
    for _ in 1..MAX_DERIVATIONS_PER_WINDOW {
        let _ = h.try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(0xE6));
    }
    let err = h
        .try_get_encrypted_vetkey(user, Harness::valid_transport_key(0xE7))
        .expect_err("the post-upgrade window must be spendable to exhaustion");
    assert!(
        err.contains("rate limit"),
        "the meter must still be LIVE after the upgrade, not disabled by it: {err}"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// W-VETKEYS §H′ — ADMISSION AT THE CANISTER BOUNDARY
// ═════════════════════════════════════════════════════════════════════════════
//
// THE TRAP THESE ARMS EXIST TO AVOID (CTO adjudication 7cd63a14…, item A, and
// the SSA checkpoint): two rate limits now guard this endpoint and they share
// the number 5. The A-2 meter is 5 per principal per HOUR; §H′ is 5 per
// principal per rolling 24 HOURS. An arm that drives six calls in one minute
// is refused by the METER and proves nothing whatever about §H′.
//
// So every §H′ arm below advances PocketIC time past the meter hour between
// derives, and asserts on the TYPED variant received — the variant is what
// names the mechanism. The ordering arm does the converse deliberately.

/// One meter hour plus a margin: enough for the A-2 window to roll over, far
/// inside the §H′ 24 h window (five of these is ~5 h).
/// The shipped §H′ quota, mirrored here rather than imported: the canister
/// crate is a cdylib and its constants are not linkable from an integration
/// test, and a test that read the value from the code under test could not RED
/// when that value moves. `pins::tests` holds the mutation arm.
const DERIVE_QUOTA: u32 = 5;

const PAST_THE_METER_HOUR: std::time::Duration = std::time::Duration::from_secs(3_601);

impl Harness {
    /// Advance past the A-2 meter's window so the NEXT call is judged by §H′.
    fn skip_the_meter_window(&self) {
        self.pic.advance_time(PAST_THE_METER_HOUR);
        self.pic.tick();
    }

    /// A derive that is guaranteed to be judged by §H′, not by the meter.
    fn derive_past_the_meter(&self, user: Principal, seed: u8) -> VetKeyResult {
        self.skip_the_meter_window();
        self.try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(seed))
    }
}

/// H′-1 — THE ORDERING ARM (adjudication item A, verbatim requirement): the
/// sixth call inside ONE meter hour is refused by the METER, with the meter's
/// own typed variant — NOT by §H′.
///
/// What this arm can and cannot show, stated rather than implied: it proves the
/// meter is the mechanism that refuses. It CANNOT observe the absence of a §H′
/// write, because a stray `PreDispatch` reservation lives at most 5 min while
/// the meter refuses the same principal for a full hour — the evidence window
/// is strictly inside the blackout. That half is proved exactly, on the state's
/// own bytes, by `admission::tests::meter_refusal_leaves_admission_state_byte_identical`,
/// which REDs when the two limbs are swapped.
#[test]
fn hprime1_sixth_call_in_one_hour_is_refused_by_the_meter_not_the_quota() {
    let h = setup();
    let user = p(0xD1);
    // V5 §6: age the principal in FIRST, then reset the meter. The age-refused
    // attempt is still a CALL, and the A-2 meter charges every call uniformly —
    // so without this the principal would enter the loop having already spent
    // one of its five, and the arm would measure the wrong boundary.
    h.age_in_all(&[user]);
    h.skip_the_meter_window();
    // LAUNCH-HARDEN-04 O-3: the first PER_PRINCIPAL_HOURLY_DERIVE_CAP calls
    // dispatch; the rest of the meter's five are metered and then refused at the
    // fence by the per-principal cap. The SIXTH is still the meter's.
    for i in 0..MAX_DERIVATIONS_PER_WINDOW {
        let r = h.try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(0x10 + i as u8));
        if i < PER_PRINCIPAL_HOURLY_DERIVE_CAP {
            r.unwrap_or_else(|e| panic!("call {i} within the hour must succeed, got {e:?}"));
        } else {
            assert!(
                matches!(r, Err(VetkeysError::PrincipalHourlyDerivationCapExceeded { .. })),
                "call {i} is past the per-principal hourly cap; got {r:?}"
            );
        }
    }
    let sixth = h
        .try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(0x1F))
        .expect_err("the sixth call inside one hour must be refused");
    assert!(
        matches!(sixth, VetkeysError::RateLimited(_)),
        "inside one hour the METER must be the mechanism that refuses; got {sixth:?}"
    );
    assert!(
        !matches!(sixth, VetkeysError::DerivationQuotaExceeded { .. }),
        "a §H′ refusal here would mean the ordering is inverted"
    );
}

/// H′-2 — the §H′ quota bites once the meter is out of the way, and reports
/// itself with its OWN variant.
///
/// Five derives, each in its own meter hour (~5 h total, well inside the §H′
/// 24 h window), then a sixth: the meter has capacity, §H′ does not.
#[test]
fn hprime2_the_quota_refuses_past_the_meter_window_with_its_own_variant() {
    let h = setup();
    let user = p(0xD2);
    for i in 0..DERIVE_QUOTA {
        h.derive_past_the_meter(user, 0x20 + i as u8)
            .unwrap_or_else(|e| panic!("derive {i} must be admitted by §H′, got {e:?}"));
    }
    match h.derive_past_the_meter(user, 0x2F) {
        Err(VetkeysError::DerivationQuotaExceeded { retry_after_ns }) => {
            // The sixth derive is refused because five sit in the rolling 24 h
            // window; the wait is at most one full window and strictly positive.
            assert!(retry_after_ns > 0, "§H′ must say when a slot frees");
            assert!(
                retry_after_ns <= 24 * 60 * 60 * 1_000_000_000,
                "a wait longer than the window itself is not derivable from five \
                 in-window derives; got {retry_after_ns}"
            );
        }
        other => panic!("expected the §H′ quota to refuse the sixth derive, got {other:?}"),
    }
}

/// H′-3 — `remaining` is the §H′ allowance and counts down across the window,
/// unaffected by the meter's own (hourly) accounting.
///
/// The expected sequence is regenerated from the loop index here, never read
/// back from the canister.
#[test]
fn hprime3_remaining_counts_down_the_quota_not_the_meter() {
    let h = setup();
    let user = p(0xD3);
    for i in 0..DERIVE_QUOTA {
        let reply = h
            .derive_past_the_meter(user, 0x30 + i as u8)
            .unwrap_or_else(|e| panic!("derive {i} refused: {e:?}"));
        assert_eq!(
            reply.remaining as u32,
            DERIVE_QUOTA - i - 1,
            "remaining must report the §H′ allowance left after derive {i}"
        );
        assert!(!reply.encrypted_key.is_empty(), "a successful derive returns a key");
    }
}

/// H′-4 — §H′ state is STABLE and survives a REAL upgrade, and the arm is
/// built so that only the stable half can satisfy it.
///
/// The A-2 meter is deliberately EPHEMERAL (heap), so an upgrade clears it. If
/// §H′ were heap-resident too, the post-upgrade call would be ADMITTED. It must
/// instead be refused with the §H′ variant: the quota outlives the upgrade, the
/// meter does not, and the typed variant tells the two apart. This is the
/// native-vs-cross-Wasm blind spot arm — a heap-only quota passes every
/// in-process test and fails exactly here.
#[test]
fn hprime4_the_quota_survives_a_real_upgrade_while_the_meter_resets() {
    let h = setup();
    let user = p(0xD4);
    for i in 0..DERIVE_QUOTA {
        h.derive_past_the_meter(user, 0x40 + i as u8)
            .unwrap_or_else(|e| panic!("derive {i} refused: {e:?}"));
    }

    h.pic
        .upgrade_canister(h.vetkeys_id, vetkeys_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("a genuine upgrade of an initialised canister must succeed");

    // Past the meter hour, so the (now-empty) meter cannot be what refuses.
    match h.derive_past_the_meter(user, 0x4F) {
        Err(VetkeysError::DerivationQuotaExceeded { retry_after_ns }) => {
            assert!(retry_after_ns > 0);
        }
        Ok(_) => panic!(
            "the §H′ quota did not survive the upgrade — a post-upgrade admission means the \
             window is heap-resident, which is a free allowance per upgrade"
        ),
        other => panic!("expected the §H′ quota to refuse after the upgrade, got {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// W-VETKEYS LAYER 1 — §B bootstrap tickets, §C transcripts, §E limits
// ═════════════════════════════════════════════════════════════════════════════
//
// These arms run against the REAL Wasm on PocketIC, and they SIGN with the
// same P-256 primitives a browser's WebCrypto would. The canister's own
// `transcript` module is deliberately NOT imported: the test re-implements the
// canonical encoding from the brief's field list, so a silent change to the
// encoder shows up here as a verification failure instead of being inherited
// from the code under test. (`transcript::tests` holds the frozen vectors; this
// is the independent second implementation those vectors pin.)

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey};
use p256::pkcs8::EncodePublicKey as _;

const PROTOCOL: &[u8] = b"stsh.vetkeys.device-approval";
const ACTION_REGISTER: &[u8] = b"register_device";
const ACTION_REVOKE: &[u8] = b"revoke_device";

fn var(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_le_bytes());
    out.extend_from_slice(field);
}

#[allow(clippy::too_many_arguments)]
fn approval_transcript(
    canister: Principal,
    owner: Principal,
    issuer: &str,
    new_device: &str,
    enc_hash: [u8; 32],
    sign_hash: [u8; 32],
    wrapped_hash: [u8; 32],
    nonce: [u8; 16],
    expiry_ns: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    var(&mut out, PROTOCOL);
    out.extend_from_slice(&1u16.to_le_bytes());
    var(&mut out, canister.as_slice());
    var(&mut out, ACTION_REGISTER);
    var(&mut out, owner.as_slice());
    var(&mut out, issuer.as_bytes());
    var(&mut out, new_device.as_bytes());
    out.extend_from_slice(&enc_hash);
    out.extend_from_slice(&sign_hash);
    out.extend_from_slice(&wrapped_hash);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&expiry_ns.to_le_bytes());
    out
}

fn revoke_transcript(
    canister: Principal,
    owner: Principal,
    issuer: &str,
    target: &str,
    nonce: [u8; 16],
    expiry_ns: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    var(&mut out, PROTOCOL);
    out.extend_from_slice(&1u16.to_le_bytes());
    var(&mut out, canister.as_slice());
    var(&mut out, ACTION_REVOKE);
    var(&mut out, owner.as_slice());
    var(&mut out, issuer.as_bytes());
    var(&mut out, target.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&expiry_ns.to_le_bytes());
    out
}

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b);
    h.finalize().into()
}

/// A test device: a P-256 signing key plus a stand-in RSA-OAEP encryption SPKI
/// (opaque to the canister, which never parses it).
struct TestDevice {
    id: String,
    signing: SigningKey,
    sign_spki: Vec<u8>,
    enc_spki: Vec<u8>,
}

impl TestDevice {
    fn new(id: &str, seed: u8) -> Self {
        let signing = SigningKey::from_slice(&[seed; 32]).expect("valid P-256 scalar");
        let sign_spki = signing
            .verifying_key()
            .to_public_key_der()
            .expect("SPKI")
            .as_bytes()
            .to_vec();
        TestDevice {
            id: id.to_string(),
            signing,
            sign_spki,
            // Stand-in for an RSA-OAEP-3072 SPKI: the canister stores it opaque.
            enc_spki: vec![seed; 422],
        }
    }

    /// LOW-S NORMALIZED, as a correct wallet must: P-256 signers (RustCrypto's
    /// and WebCrypto's alike) do NOT emit low-S by convention, and the canister
    /// REFUSES high-S rather than normalizing it. Without this step roughly half
    /// of all honest approvals would be rejected.
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let raw: P256Signature = self.signing.sign(msg);
        raw.normalize_s().unwrap_or(raw).to_bytes().to_vec()
    }
}

/// The wrapped envelope a device would receive. Opaque bytes; 384 is the real
/// RSA-OAEP-3072 ciphertext length.
fn envelope(seed: u8) -> Vec<u8> {
    vec![seed; 384]
}

impl Harness {
    fn register(
        &self,
        user: Principal,
        dev: &TestDevice,
        wrapped: Vec<u8>,
        approval: DeviceApproval,
    ) -> Result<(), VetkeysError> {
        decode(
            "register_device",
            self.pic.update_call(
                self.vetkeys_id,
                user,
                "register_device",
                candid::encode_args((
                    dev.id.clone(),
                    dev.enc_spki.clone(),
                    dev.sign_spki.clone(),
                    wrapped,
                    approval,
                ))
                .unwrap(),
            ),
        )
    }

    fn revoke(
        &self,
        user: Principal,
        target: &str,
        approval: SignedApproval,
    ) -> Result<(), VetkeysError> {
        decode(
            "revoke_device",
            self.pic.update_call(
                self.vetkeys_id,
                user,
                "revoke_device",
                candid::encode_args((target.to_string(), approval)).unwrap(),
            ),
        )
    }

    fn wrapped_secret(&self, user: Principal, device_id: &str) -> Result<Vec<u8>, VetkeysError> {
        decode(
            "get_wrapped_secret",
            self.pic.query_call(
                self.vetkeys_id,
                user,
                "get_wrapped_secret",
                candid::encode_one(device_id.to_string()).unwrap(),
            ),
        )
    }

    fn devices(&self, user: Principal) -> Vec<DeviceView> {
        decode(
            "list_devices",
            self.pic.query_call(
                self.vetkeys_id,
                user,
                "list_devices",
                candid::encode_args(()).unwrap(),
            ),
        )
    }

    fn cycles(&self) -> u128 {
        decode(
            "cycle_balance",
            self.pic.query_call(
                self.vetkeys_id,
                Principal::anonymous(),
                "cycle_balance",
                candid::encode_args(()).unwrap(),
            ),
        )
    }

    /// §3 — the observability query, called ANONYMOUSLY on purpose: the surface
    /// has no caller check (the fleet monitor is unauthenticated), and calling
    /// it as an authenticated principal would leave that untested.
    fn derive_budget_stats(&self) -> DeriveBudgetStats {
        decode(
            "derive_budget_stats",
            self.pic.query_call(
                self.vetkeys_id,
                Principal::anonymous(),
                "derive_budget_stats",
                candid::encode_args(()).unwrap(),
            ),
        )
    }

    /// Run the full Layer-2 ceremony and register `dev` as the first device.
    fn bootstrap(&self, user: Principal, dev: &TestDevice, wrapped: Vec<u8>) {
        self.derive_past_the_meter(user, 0xB0)
            .expect("the bootstrap ceremony's derive must succeed");
        self.register(user, dev, wrapped, DeviceApproval::Bootstrap)
            .expect("a fresh ticket must authorize the first device");
    }

    /// A signed approval for `new_device`, issued by `issuer`.
    #[allow(clippy::too_many_arguments)]
    fn approval_from(
        &self,
        issuer: &TestDevice,
        owner: Principal,
        new_device: &TestDevice,
        wrapped: &[u8],
        nonce: [u8; 16],
        expiry_ns: u64,
    ) -> SignedApproval {
        let msg = approval_transcript(
            self.vetkeys_id,
            owner,
            &issuer.id,
            &new_device.id,
            sha256(&new_device.enc_spki),
            sha256(&new_device.sign_spki),
            sha256(wrapped),
            nonce,
            expiry_ns,
        );
        SignedApproval {
            issuer_device_id: issuer.id.clone(),
            nonce: nonce.to_vec(),
            expiry_ns,
            signature: issuer.sign(&msg),
        }
    }

    fn revocation_from(
        &self,
        issuer: &TestDevice,
        owner: Principal,
        target: &str,
        nonce: [u8; 16],
        expiry_ns: u64,
    ) -> SignedApproval {
        let msg = revoke_transcript(self.vetkeys_id, owner, &issuer.id, target, nonce, expiry_ns);
        SignedApproval {
            issuer_device_id: issuer.id.clone(),
            nonce: nonce.to_vec(),
            expiry_ns,
            signature: issuer.sign(&msg),
        }
    }

    fn now_ns(&self) -> u64 {
        self.pic
            .get_time()
            .as_nanos_since_unix_epoch()
    }
}

/// A far-future expiry, for arms where expiry is not the subject.
fn live_expiry(h: &Harness) -> u64 {
    h.now_ns() + 60 * 60 * 1_000_000_000
}

// ── §B — the bootstrap ticket ────────────────────────────────────────────────

/// B-1 — the happy path, and the property the whole lane exists for: a
/// registered device's Layer-1 operations perform ZERO vetKD derives.
///
/// Counted on an INDEPENDENT side channel — the canister's own cycle balance,
/// which a derive burns ~26B of — not on canister state and not by reading the
/// source. A Layer-1 fetch must not move it by anything of that magnitude.
#[test]
fn b1_bootstrap_registers_and_layer1_costs_no_derive() {
    let h = setup();
    let user = p(0xE1);
    let dev = TestDevice::new("device-1", 0x11);
    let env = envelope(0xAA);
    h.bootstrap(user, &dev, env.clone());

    assert_eq!(h.wrapped_secret(user, &dev.id), Ok(env), "the device fetches its own envelope");
    let listed = h.devices(user);
    assert_eq!(listed.len(), 1);
    assert!(listed[0].active);
    assert_eq!(listed[0].approved_by_device, None, "the first device rode a bootstrap ticket");

    // ZERO-DERIVE CHECK. One full Layer-1 cycle: list, fetch, list again.
    let before = h.cycles();
    for _ in 0..3 {
        let _ = h.devices(user);
        h.wrapped_secret(user, &dev.id).expect("Layer-1 read");
    }
    let spent = before.saturating_sub(h.cycles());
    // A single production derive is ~26B cycles. Query traffic is orders of
    // magnitude below that; anything approaching it means a derive happened.
    assert!(
        spent < 1_000_000_000,
        "a Layer-1 session must perform ZERO vetKD derives; {spent} cycles were spent, which is \
         derive-scale"
    );
}

/// B-2 — a `Bootstrap` registration with NO ticket is refused. This is the
/// direct attack RED-2 named: registering a first device without performing
/// the ceremony at all.
#[test]
fn b2_bootstrap_without_a_ticket_is_refused() {
    let h = setup();
    let user = p(0xE2);
    let dev = TestDevice::new("device-1", 0x12);
    match h.register(user, &dev, envelope(0xAB), DeviceApproval::Bootstrap) {
        Err(VetkeysError::BootstrapNotAuthorized { reason }) => {
            assert!(reason.contains("no bootstrap ticket"), "{reason}");
        }
        other => panic!("expected BootstrapNotAuthorized, got {other:?}"),
    }
    assert!(h.devices(user).is_empty(), "no device state may exist after the refusal");
}

/// B-3 — one ticket authorizes exactly ONE registration.
#[test]
fn b3_a_ticket_cannot_be_consumed_twice() {
    let h = setup();
    let user = p(0xE3);
    let first = TestDevice::new("device-1", 0x13);
    h.bootstrap(user, &first, envelope(0xAC));

    let second = TestDevice::new("device-2", 0x14);
    match h.register(user, &second, envelope(0xAD), DeviceApproval::Bootstrap) {
        Err(VetkeysError::BootstrapNotAuthorized { reason }) => {
            assert!(reason.contains("already been consumed"), "{reason}");
        }
        other => panic!("expected a consumed-ticket refusal, got {other:?}"),
    }
    assert_eq!(h.devices(user).len(), 1, "the second device must not exist");
}

/// B-4 — the ticket expires. Ten minutes after minting it authorizes nothing.
#[test]
fn b4_an_expired_ticket_authorizes_nothing() {
    let h = setup();
    let user = p(0xE4);
    h.derive_past_the_meter(user, 0xB4).expect("ceremony derive");
    // Past the pinned 10-minute lifetime.
    h.pic.advance_time(std::time::Duration::from_secs(601));
    h.pic.tick();

    let dev = TestDevice::new("device-1", 0x15);
    match h.register(user, &dev, envelope(0xAE), DeviceApproval::Bootstrap) {
        Err(VetkeysError::BootstrapNotAuthorized { reason }) => {
            assert!(reason.contains("expired"), "{reason}");
        }
        other => panic!("expected an expired-ticket refusal, got {other:?}"),
    }
}

/// B-5 — a ticket minted for P is unusable by Q. Tickets are keyed by
/// principal, and the consumer is the CALLER.
#[test]
fn b5_a_ticket_is_bound_to_its_principal() {
    let h = setup();
    let (owner, stranger) = (p(0xE5), p(0xE6));
    h.derive_past_the_meter(owner, 0xB5).expect("owner's ceremony");

    let dev = TestDevice::new("device-1", 0x16);
    match h.register(stranger, &dev, envelope(0xAF), DeviceApproval::Bootstrap) {
        Err(VetkeysError::BootstrapNotAuthorized { .. }) => {}
        other => panic!("another principal's ticket must not authorize this caller: {other:?}"),
    }
    assert!(h.devices(stranger).is_empty());
}

/// B-6 — the ticket and its CONSUMED flag survive a REAL upgrade: a replay
/// after the upgrade is still refused. A heap-resident ticket would either
/// vanish (breaking the interrupted-ceremony path) or come back UNUSED, which
/// is a free extra registration per upgrade.
#[test]
fn b6_ticket_state_including_used_survives_a_real_upgrade() {
    let h = setup();
    let user = p(0xE7);
    let first = TestDevice::new("device-1", 0x17);
    h.bootstrap(user, &first, envelope(0xB0));

    h.pic
        .upgrade_canister(h.vetkeys_id, vetkeys_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("a genuine upgrade must succeed");

    assert_eq!(h.devices(user).len(), 1, "the device registry survived the upgrade");
    let second = TestDevice::new("device-2", 0x18);
    match h.register(user, &second, envelope(0xB1), DeviceApproval::Bootstrap) {
        Err(VetkeysError::BootstrapNotAuthorized { reason }) => {
            assert!(
                reason.contains("already been consumed"),
                "the USED flag must survive the upgrade, not just the row: {reason}"
            );
        }
        other => panic!("expected a post-upgrade replay refusal, got {other:?}"),
    }
}

// ── §C — device-signed approvals ─────────────────────────────────────────────

/// C-1 — the happy path: an ACTIVE device approves a new one, zero derives.
#[test]
fn c1_an_active_device_approves_a_new_device() {
    let h = setup();
    let user = p(0xF1);
    let first = TestDevice::new("device-1", 0x21);
    h.bootstrap(user, &first, envelope(0xC0));

    let second = TestDevice::new("device-2", 0x22);
    let env2 = envelope(0xC1);
    let before = h.cycles();
    let approval = h.approval_from(&first, user, &second, &env2, [0x01; 16], live_expiry(&h));
    h.register(user, &second, env2.clone(), DeviceApproval::Device(approval))
        .expect("a genuine approval must be accepted");
    assert!(
        before.saturating_sub(h.cycles()) < 1_000_000_000,
        "adding a device by approval must perform ZERO derives"
    );

    assert_eq!(h.wrapped_secret(user, &second.id), Ok(env2));
    let listed = h.devices(user);
    assert_eq!(listed.len(), 2);
    let added = listed.iter().find(|d| d.device_id == second.id).unwrap();
    assert_eq!(added.approved_by_device.as_deref(), Some(first.id.as_str()));
}

/// C-2 — PUBKEY SUBSTITUTION. A signature over device X's keys presented with
/// device Y's keys is refused: both hashes are inside the signed bytes.
#[test]
fn c2_pubkey_substitution_is_refused() {
    let h = setup();
    let user = p(0xF2);
    let first = TestDevice::new("device-1", 0x23);
    h.bootstrap(user, &first, envelope(0xC2));

    let honest = TestDevice::new("device-2", 0x24);
    let attacker = TestDevice {
        id: honest.id.clone(),
        ..TestDevice::new("device-2", 0x25)
    };
    let env = envelope(0xC3);
    // Signed for the HONEST device's keys…
    let approval = h.approval_from(&first, user, &honest, &env, [0x02; 16], live_expiry(&h));
    // …presented with the ATTACKER's keys under the same device id.
    match h.register(user, &attacker, env, DeviceApproval::Device(approval)) {
        Err(VetkeysError::ApprovalRejected(reason)) => assert!(reason.contains("does not verify")),
        other => panic!("a substituted public key must be refused, got {other:?}"),
    }
    assert_eq!(h.devices(user).len(), 1);
}

/// C-3 — ENVELOPE SUBSTITUTION (SSA's RED-3). A valid approval paired with a
/// DIFFERENT wrapped envelope is refused, because `wrapped_secret_hash` is
/// inside the signed bytes. Without that field this test passes an attacker's
/// envelope through under a genuine signature.
#[test]
fn c3_envelope_substitution_is_refused() {
    let h = setup();
    let user = p(0xF3);
    let first = TestDevice::new("device-1", 0x26);
    h.bootstrap(user, &first, envelope(0xC4));

    let second = TestDevice::new("device-2", 0x27);
    let honest_env = envelope(0xC5);
    let approval = h.approval_from(&first, user, &second, &honest_env, [0x03; 16], live_expiry(&h));
    match h.register(user, &second, envelope(0xC6), DeviceApproval::Device(approval)) {
        Err(VetkeysError::ApprovalRejected(reason)) => assert!(reason.contains("does not verify")),
        other => panic!("a substituted envelope must be refused, got {other:?}"),
    }
    assert!(h.wrapped_secret(user, &second.id).is_err(), "nothing was written");
}

/// C-4 — CROSS-ACTION. A revoke transcript's signature presented as a
/// registration approval (and vice versa) is refused: the action tag is inside
/// the signed stream.
#[test]
fn c4_cross_action_transcripts_are_refused() {
    let h = setup();
    let user = p(0xF4);
    let first = TestDevice::new("device-1", 0x28);
    h.bootstrap(user, &first, envelope(0xC7));

    let second = TestDevice::new("device-2", 0x29);
    let env = envelope(0xC8);
    let expiry = live_expiry(&h);

    // A REVOKE signature, presented to register_device.
    let revoke_sig = h.revocation_from(&first, user, &second.id, [0x04; 16], expiry);
    match h.register(user, &second, env.clone(), DeviceApproval::Device(revoke_sig)) {
        Err(VetkeysError::ApprovalRejected(reason)) => assert!(reason.contains("does not verify")),
        other => panic!("a revoke transcript must not authorize a registration: {other:?}"),
    }

    // And the converse: a REGISTER signature presented to revoke_device.
    let register_sig = h.approval_from(&first, user, &second, &env, [0x05; 16], expiry);
    match h.revoke(user, &first.id, register_sig) {
        Err(VetkeysError::ApprovalRejected(reason)) => assert!(reason.contains("does not verify")),
        other => panic!("a registration transcript must not authorize a revocation: {other:?}"),
    }
    assert!(h.devices(user)[0].active, "nothing was revoked");
}

/// C-5 — CROSS-PRINCIPAL. An approval signed for owner A cannot register a
/// device for owner B, even by B's own call: the owner principal is signed.
#[test]
fn c5_cross_principal_approvals_are_refused() {
    let h = setup();
    let (a, b) = (p(0xF5), p(0xF6));
    let a_dev = TestDevice::new("device-1", 0x2A);
    h.bootstrap(a, &a_dev, envelope(0xC9));
    let b_dev = TestDevice::new("device-1", 0x2B);
    h.bootstrap(b, &b_dev, envelope(0xCA));

    let new_dev = TestDevice::new("device-2", 0x2C);
    let env = envelope(0xCB);
    // Signed by A's device, FOR A, then submitted by B (whose device id
    // happens to match, so only the signed principal separates them).
    let approval = h.approval_from(&a_dev, a, &new_dev, &env, [0x06; 16], live_expiry(&h));
    match h.register(b, &new_dev, env, DeviceApproval::Device(approval)) {
        Err(VetkeysError::ApprovalRejected(reason)) => assert!(reason.contains("does not verify")),
        other => panic!("a cross-principal approval must be refused, got {other:?}"),
    }
    assert_eq!(h.devices(b).len(), 1);
}

/// C-6 — CROSS-CANISTER. A transcript signed for a DIFFERENT canister id is
/// refused. This is what stops a transcript captured on one deployment
/// (testnet, a fork, a second instance) from being replayed here.
#[test]
fn c6_cross_canister_transcripts_are_refused() {
    let h = setup();
    let user = p(0xF7);
    let first = TestDevice::new("device-1", 0x2D);
    h.bootstrap(user, &first, envelope(0xCC));

    let second = TestDevice::new("device-2", 0x2E);
    let env = envelope(0xCD);
    let expiry = live_expiry(&h);
    // Everything genuine except the canister id inside the signed bytes.
    let other_canister = Principal::from_slice(&[0x09; 10]);
    assert_ne!(other_canister, h.vetkeys_id);
    let msg = approval_transcript(
        other_canister,
        user,
        &first.id,
        &second.id,
        sha256(&second.enc_spki),
        sha256(&second.sign_spki),
        sha256(&env),
        [0x07; 16],
        expiry,
    );
    let approval = SignedApproval {
        issuer_device_id: first.id.clone(),
        nonce: [0x07; 16].to_vec(),
        expiry_ns: expiry,
        signature: first.sign(&msg),
    };
    match h.register(user, &second, env, DeviceApproval::Device(approval)) {
        Err(VetkeysError::ApprovalRejected(reason)) => assert!(reason.contains("does not verify")),
        other => panic!("a transcript signed for another canister must be refused: {other:?}"),
    }
}

/// C-7 — NONCE REPLAY, and its post-upgrade half in the same arm: a nonce
/// burned before an upgrade is still burned after one. The consumed-nonce set
/// is stable for exactly this reason — a heap set would hand every upgrade a
/// window in which every captured approval replays.
#[test]
fn c7_nonce_replay_is_refused_before_and_after_a_real_upgrade() {
    let h = setup();
    let user = p(0xF8);
    let first = TestDevice::new("device-1", 0x2F);
    h.bootstrap(user, &first, envelope(0xCE));

    let second = TestDevice::new("device-2", 0x30);
    let env2 = envelope(0xCF);
    let nonce = [0x08; 16];
    let expiry = live_expiry(&h);
    let approval = h.approval_from(&first, user, &second, &env2, nonce, expiry);
    h.register(user, &second, env2.clone(), DeviceApproval::Device(approval.clone()))
        .expect("first use is genuine");

    // Same nonce, same signature, a third device id would need a new signature —
    // so the honest replay of the SAME approval is what an attacker actually
    // has. It must fail on the duplicate device id OR the nonce; force the
    // nonce path by re-signing for a fresh device id with the SAME nonce.
    let third = TestDevice::new("device-3", 0x31);
    let env3 = envelope(0xD0);
    let replay = h.approval_from(&first, user, &third, &env3, nonce, expiry);
    match h.register(user, &third, env3.clone(), DeviceApproval::Device(replay.clone())) {
        Err(VetkeysError::ApprovalRejected(reason)) => {
            assert!(reason.contains("already been used"), "{reason}")
        }
        other => panic!("a replayed nonce must be refused, got {other:?}"),
    }

    h.pic
        .upgrade_canister(h.vetkeys_id, vetkeys_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("upgrade");

    match h.register(user, &third, env3, DeviceApproval::Device(replay)) {
        Err(VetkeysError::ApprovalRejected(reason)) => {
            assert!(reason.contains("already been used"), "post-upgrade: {reason}")
        }
        other => panic!("a nonce burned before the upgrade must stay burned: {other:?}"),
    }
}

/// C-8 — expiry is enforced at the boundary: an already-passed expiry is
/// refused, a live one is accepted.
///
/// The ±1 ns half-open boundary itself is proved in
/// `registry::tests::the_approval_expiry_boundary_is_half_open`, NOT here, and
/// that is a limitation of the harness rather than a choice: PocketIC's clock
/// advances between the client building a call and the canister executing it,
/// so an expiry of `now + 1` constructed out here is ALREADY past by the time
/// the endpoint reads the time. An arm that pretended otherwise would be
/// measuring round scheduling, not the comparison.
#[test]
fn c8_the_approval_expiry_boundary_is_exact() {
    let h = setup();
    let user = p(0xF9);
    let first = TestDevice::new("device-1", 0x32);
    h.bootstrap(user, &first, envelope(0xD1));

    // An expiry exactly at the current canister time: already dead.
    let now = h.now_ns();
    let second = TestDevice::new("device-2", 0x33);
    let env = envelope(0xD2);
    let dead = h.approval_from(&first, user, &second, &env, [0x09; 16], now);
    match h.register(user, &second, env.clone(), DeviceApproval::Device(dead)) {
        Err(VetkeysError::ApprovalRejected(reason)) => assert!(reason.contains("expired")),
        other => panic!("an approval expiring AT now must be refused, got {other:?}"),
    }

    // A genuinely future expiry: accepted.
    let live = h.approval_from(&first, user, &second, &env, [0x0A; 16], live_expiry(&h));
    h.register(user, &second, env, DeviceApproval::Device(live))
        .expect("an approval that has not expired must be accepted");
}

/// C-9 — a REVOKED device cannot approve anything. Without this, revocation
/// would only close read paths and a revoked device could re-admit itself.
#[test]
fn c9_a_revoked_device_cannot_approve() {
    let h = setup();
    let user = p(0xFA);
    let first = TestDevice::new("device-1", 0x34);
    h.bootstrap(user, &first, envelope(0xD3));
    let second = TestDevice::new("device-2", 0x35);
    let env2 = envelope(0xD4);
    let approval = h.approval_from(&first, user, &second, &env2, [0x0B; 16], live_expiry(&h));
    h.register(user, &second, env2, DeviceApproval::Device(approval)).expect("second device");

    // The second device revokes the first.
    let rev = h.revocation_from(&second, user, &first.id, [0x0C; 16], live_expiry(&h));
    h.revoke(user, &first.id, rev).expect("an active device may revoke another");

    // The revoked device now tries to approve a third.
    let third = TestDevice::new("device-3", 0x36);
    let env3 = envelope(0xD5);
    let approval = h.approval_from(&first, user, &third, &env3, [0x0D; 16], live_expiry(&h));
    match h.register(user, &third, env3, DeviceApproval::Device(approval)) {
        Err(VetkeysError::ApprovalRejected(reason)) => assert!(reason.contains("revoked")),
        other => panic!("a revoked device must not approve, got {other:?}"),
    }
}

/// C-10 — HIGH-S at the canister boundary. The same genuine approval, signed
/// without the wallet's low-S normalization, is REFUSED — and the normalized
/// form of that same signature is accepted, so the refusal is the policy and
/// not a broken fixture.
#[test]
fn c10_a_high_s_signature_is_refused_at_the_boundary() {
    let h = setup();
    let user = p(0xFB);
    let first = TestDevice::new("device-1", 0x37);
    h.bootstrap(user, &first, envelope(0xD6));

    let second = TestDevice::new("device-2", 0x38);
    let env = envelope(0xD7);
    let expiry = live_expiry(&h);
    let nonce = [0x0E; 16];
    let msg = approval_transcript(
        h.vetkeys_id,
        user,
        &first.id,
        &second.id,
        sha256(&second.enc_spki),
        sha256(&second.sign_spki),
        sha256(&env),
        nonce,
        expiry,
    );
    let raw: P256Signature = first.signing.sign(&msg);
    let low = raw.normalize_s().unwrap_or(raw);
    let (r, s) = low.split_scalars();
    let high = P256Signature::from_scalars(r, -s).expect("valid malleated signature");
    assert!(high.normalize_s().is_some(), "the fixture must genuinely be high-S");

    let approval = SignedApproval {
        issuer_device_id: first.id.clone(),
        nonce: nonce.to_vec(),
        expiry_ns: expiry,
        signature: high.to_bytes().to_vec(),
    };
    match h.register(user, &second, env.clone(), DeviceApproval::Device(approval)) {
        Err(VetkeysError::ApprovalRejected(reason)) => assert!(reason.contains("high-S"), "{reason}"),
        other => panic!("a high-S signature must be refused, got {other:?}"),
    }

    // Non-vacuity: normalized, the SAME signature is accepted.
    let accepted = SignedApproval {
        issuer_device_id: first.id.clone(),
        nonce: nonce.to_vec(),
        expiry_ns: expiry,
        signature: low.to_bytes().to_vec(),
    };
    h.register(user, &second, env, DeviceApproval::Device(accepted))
        .expect("the low-S form of the same signature must verify");
}

/// C-11 — revocation is an honest FORWARD cutoff: the envelope is deleted and
/// the read path closes, while the record is retained as evidence.
#[test]
fn c11_revocation_deletes_the_envelope_and_retains_the_record() {
    let h = setup();
    let user = p(0xFC);
    let first = TestDevice::new("device-1", 0x39);
    h.bootstrap(user, &first, envelope(0xD8));
    let second = TestDevice::new("device-2", 0x3A);
    let env2 = envelope(0xD9);
    let approval = h.approval_from(&first, user, &second, &env2, [0x0F; 16], live_expiry(&h));
    h.register(user, &second, env2, DeviceApproval::Device(approval)).expect("second device");

    let rev = h.revocation_from(&second, user, &first.id, [0x10; 16], live_expiry(&h));
    h.revoke(user, &first.id, rev).expect("revoke");

    assert_eq!(
        h.wrapped_secret(user, &first.id),
        Err(VetkeysError::DeviceRevoked),
        "a revoked device gets neither the blob nor a working read path"
    );
    let listed = h.devices(user);
    let revoked = listed.iter().find(|d| d.device_id == first.id).expect("record retained");
    assert!(!revoked.active);
    assert!(revoked.revoked_at_ns.is_some(), "the revocation is timestamped evidence");
    // The surviving device is untouched.
    assert!(h.wrapped_secret(user, &second.id).is_ok());
}

/// C-12 — one principal can never see or read another's devices. Owner-only is
/// by construction (the range is keyed on the caller), and this is the arm that
/// says so at the boundary.
#[test]
fn c12_devices_are_owner_only() {
    let h = setup();
    let (a, b) = (p(0xFD), p(0xFE));
    let a_dev = TestDevice::new("device-a", 0x3B);
    h.bootstrap(a, &a_dev, envelope(0xDA));

    assert!(h.devices(b).is_empty(), "B sees none of A's devices");
    assert_eq!(
        h.wrapped_secret(b, &a_dev.id),
        Err(VetkeysError::UnknownDevice),
        "B cannot read A's envelope"
    );
}

// ── §E — the caller-writable-surface limits ──────────────────────────────────

/// E-1 — `register_device` is rate limited to 5 per rolling 24 h, counted
/// whether the call succeeds or fails. Driven entirely through FAILING calls,
/// which is the case that matters: if failures were free the failure path would
/// be an unmetered write loop.
#[test]
fn e1_registration_is_rate_limited_including_failures() {
    let h = setup();
    let user = p(0xC7);
    let dev = TestDevice::new("device-1", 0x3C);
    for i in 0..5 {
        match h.register(user, &dev, envelope(0xDB), DeviceApproval::Bootstrap) {
            Err(VetkeysError::BootstrapNotAuthorized { .. }) => {}
            other => panic!("attempt {i} should fail on the ticket, not the rate: {other:?}"),
        }
    }
    match h.register(user, &dev, envelope(0xDB), DeviceApproval::Bootstrap) {
        Err(VetkeysError::RegistrationRateExceeded { retry_after_ns }) => {
            assert!(retry_after_ns > 0, "the refusal must say when the window frees");
        }
        other => panic!("the sixth attempt in 24 h must be rate-refused, got {other:?}"),
    }
}

/// E-2 — the ACTIVE device cap. Ten devices register; the eleventh is refused,
/// and the refusal names the count.
#[test]
fn e2_the_active_device_cap_is_ten() {
    let h = setup();
    let user = p(0xC8);
    let first = TestDevice::new("device-1", 0x40);
    h.bootstrap(user, &first, envelope(0xDC));

    // Devices 2..=10 by approval. Each registration costs one §E rate unit, so
    // the window is advanced between them — the cap, not the rate limit, must
    // be what refuses at the end.
    for i in 2..=10u8 {
        let dev = TestDevice::new(&format!("device-{i}"), 0x40 + i);
        let env = envelope(0xE0 + i);
        let approval = h.approval_from(&first, user, &dev, &env, [i; 16], live_expiry(&h));
        h.register(user, &dev, env, DeviceApproval::Device(approval))
            .unwrap_or_else(|e| panic!("device {i} must register: {e:?}"));
        h.pic.advance_time(std::time::Duration::from_secs(24 * 60 * 60 + 1));
        h.pic.tick();
    }
    assert_eq!(h.devices(user).len(), 10);

    let eleventh = TestDevice::new("device-11", 0x60);
    let env = envelope(0xEF);
    let approval = h.approval_from(&first, user, &eleventh, &env, [0xFF; 16], live_expiry(&h));
    match h.register(user, &eleventh, env, DeviceApproval::Device(approval)) {
        Err(VetkeysError::DeviceLimitReached { active }) => {
            // Regenerated at point of use: ten.
            assert_eq!(active, 10);
        }
        other => panic!("the eleventh ACTIVE device must be refused, got {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// §D — FIRST-DERIVE ELIGIBILITY, its configuration, and the §H′.5 causal probe
// ═════════════════════════════════════════════════════════════════════════════

/// Build a harness whose vetkeys canister is configured with `token`:
/// `None` installs it UNCONFIGURED, which must fail first derives closed.
fn setup_with_token(token_wasm: Option<Vec<u8>>) -> Harness {
    let pic = PocketIcBuilder::new()
        .with_ii_subnet()
        .with_application_subnet()
        .with_nonmainnet_features(true)
        .build();
    let token_id = token_wasm.map(|w| install_mock_token(&pic, w));

    let vetkeys_id = pic.create_canister();
    pic.add_cycles(vetkeys_id, 1_000_000_000_000_000);
    pic.install_canister(
        vetkeys_id,
        vetkeys_wasm(),
        candid::encode_args(("test_key_1".to_string(), token_id)).unwrap(),
        None,
    );

    let pool = p(0x05);
    let merkle_id = pic.create_canister();
    pic.add_cycles(merkle_id, 2_000_000_000_000);
    pic.install_canister(merkle_id, merkle_wasm(), candid::encode_one(pool).unwrap(), None);

    Harness {
        pic,
        vetkeys_id,
        merkle_id,
        pool,
        token_id: token_id.unwrap_or_else(Principal::management_canister),
    }
}

impl Harness {
    fn configured_token(&self) -> Option<Principal> {
        decode(
            "get_token_canister",
            self.pic.query_call(
                self.vetkeys_id,
                Principal::anonymous(),
                "get_token_canister",
                candid::encode_args(()).unwrap(),
            ),
        )
    }

    /// Upgrade the vetkeys canister with the §D argument: `Some(p)` writes the
    /// cell, `None` PRESERVES it.
    fn upgrade_with(&self, token: Option<Principal>) {
        self.pic
            .upgrade_canister(
                self.vetkeys_id,
                vetkeys_wasm(),
                candid::encode_one(token).unwrap(),
                None,
            )
            .expect("a genuine upgrade of an initialised canister must succeed");
    }
}

/// D-1 — UNCONFIGURED fails CLOSED, retryably, and with no side effects.
///
/// Four things must all hold, and each is checked separately because each is a
/// different way the fail-closed claim could be false: the typed variant is the
/// INDETERMINATE one (never `PrincipalNotEligible` — an outage is not a verdict
/// about a user), no management derive was dispatched, no bootstrap ticket was
/// minted, and no `established_principal` bit was set.
#[test]
fn d1_unconfigured_eligibility_fails_closed_with_no_side_effects() {
    let h = setup_with_token(None);
    let user = p(0xA1);
    assert_eq!(h.configured_token(), None, "this instance is deliberately unconfigured");

    let before = h.cycles();
    match h.derive_past_the_meter(user, 0x01) {
        Err(VetkeysError::EligibilityCheckUnavailable(reason)) => {
            assert!(reason.contains("not configured"), "{reason}");
        }
        other => panic!("an unconfigured canister must fail CLOSED and retryable, got {other:?}"),
    }

    // ZERO MANAGEMENT DISPATCH: a derive is ~26B cycles; the refusal happens
    // before the dispatch fence, so nothing of that magnitude may be spent.
    let spent = before.saturating_sub(h.cycles());
    assert!(spent < 1_000_000_000, "{spent} cycles spent — that is derive-scale");

    // NO TICKET: a Bootstrap registration must still find nothing to consume.
    let dev = TestDevice::new("device-1", 0x71);
    match h.register(user, &dev, envelope(0x01), DeviceApproval::Bootstrap) {
        Err(VetkeysError::BootstrapNotAuthorized { reason }) => {
            assert!(reason.contains("no bootstrap ticket"), "{reason}");
        }
        other => panic!("a failed ceremony must mint no ticket, got {other:?}"),
    }

    // NO ESTABLISHED BIT: point the canister at a TRAPPING token. An
    // established principal would SKIP the query and succeed; this one must
    // still be refused, which is only true if the bit was never written.
    let trapping = install_mock_token(&h.pic, trapping_token_wasm());
    h.upgrade_with(Some(trapping));
    match h.derive_past_the_meter(user, 0x02) {
        Err(VetkeysError::EligibilityCheckUnavailable(_)) => {}
        Ok(_) => panic!(
            "the derive SKIPPED the eligibility query — an established_principal bit was set by \
             a ceremony that never completed"
        ),
        other => panic!("expected the indeterminate refusal, got {other:?}"),
    }
}

/// D-2 — an AUTHORITATIVE below-floor answer is `PrincipalNotEligible`, and it
/// RELEASES §H′ capacity (no management cycles were spent, so no slot is owed).
///
/// The release half is proved by exhausting nothing: five refusals, then five
/// SUCCESSFUL derives in the same 24 h window. If refusals had consumed
/// capacity, fewer than five would be admitted.
#[test]
fn d2_below_the_floor_is_a_verdict_and_releases_capacity() {
    let h = setup_with_token(Some(mock_token_wasm(POOR_BALANCE_E8S)));
    let user = p(0xA2);

    for i in 0..5 {
        match h.derive_past_the_meter(user, 0x10 + i) {
            Err(VetkeysError::PrincipalNotEligible(reason)) => {
                assert!(reason.contains("at least"), "{reason}");
            }
            other => panic!("attempt {i}: expected a below-floor verdict, got {other:?}"),
        }
    }

    // Now fund the principal by pointing the canister at a rich token. Five
    // derives must ALL be admitted: the refusals above released their slots.
    let rich = install_mock_token(&h.pic, mock_token_wasm(RICH_BALANCE_E8S));
    h.upgrade_with(Some(rich));
    for i in 0..5 {
        h.derive_past_the_meter(user, 0x20 + i)
            .unwrap_or_else(|e| panic!("derive {i} must be admitted — ineligible attempts must \
                                        not consume §H′ capacity: {e:?}"));
    }
    match h.derive_past_the_meter(user, 0x2F) {
        Err(VetkeysError::DerivationQuotaExceeded { .. }) => {}
        other => panic!("the sixth SUCCESSFUL derive must be quota-refused, got {other:?}"),
    }
}

/// D-3 — the `established_principal` bit does exactly one thing: it lets a
/// LATER recovery skip the balance query. Proved by making the query
/// impossible after the first ceremony.
///
/// Both halves are needed and both are here: the established principal
/// recovers through a trapping token, and a FRESH principal on the same
/// canister is refused by that same trapping token. Without the second half
/// this arm would also pass if eligibility had simply been switched off.
#[test]
fn d3_an_established_principal_skips_the_query_and_a_fresh_one_does_not() {
    let h = setup_with_token(Some(mock_token_wasm(RICH_BALANCE_E8S)));
    let established = p(0xA3);
    let fresh = p(0xA4);

    h.derive_past_the_meter(established, 0x30)
        .expect("the first ceremony is eligible and must succeed");

    let trapping = install_mock_token(&h.pic, trapping_token_wasm());
    h.upgrade_with(Some(trapping));

    h.derive_past_the_meter(established, 0x31)
        .expect("an established principal RECOVERS without asking the token canister again");

    match h.derive_past_the_meter(fresh, 0x32) {
        Err(VetkeysError::EligibilityCheckUnavailable(_)) => {}
        other => panic!(
            "a principal with no established bit must still be gated by the query, got {other:?}"
        ),
    }
}

/// D-4 — the configuration matrix, compared on the STORED PRINCIPAL.
///
/// Behavioural equivalence is not enough here (SSA checkpoint §1): a cell
/// rewritten to a different canister that answers alike would pass a
/// behaviour-only check. So every arm reads back the stored principal.
#[test]
fn d4_install_and_upgrade_configuration_matrix() {
    // Fresh install with None → absent.
    let unconfigured = setup_with_token(None);
    assert_eq!(unconfigured.configured_token(), None, "install None → absent");

    // Upgrade None over ABSENT → still absent (preserve, not "default to
    // something").
    unconfigured.upgrade_with(None);
    assert_eq!(unconfigured.configured_token(), None, "upgrade None over absent → absent");

    // Upgrade Some over ABSENT → set. This is the path that exists so
    // configuring a live canister never requires a reinstall.
    let first = install_mock_token(&unconfigured.pic, mock_token_wasm(RICH_BALANCE_E8S));
    unconfigured.upgrade_with(Some(first));
    assert_eq!(unconfigured.configured_token(), Some(first), "upgrade Some over absent → set");

    // Upgrade None over SET → PRESERVED, byte for byte.
    unconfigured.upgrade_with(None);
    assert_eq!(
        unconfigured.configured_token(),
        Some(first),
        "upgrade None must PRESERVE the stored principal — a routine upgrade may never \
         silently unconfigure the canister"
    );

    // Upgrade Some over SET → replaced with the NEW principal (and it is a
    // genuinely different one, or this arm would prove nothing).
    let second = install_mock_token(&unconfigured.pic, mock_token_wasm(RICH_BALANCE_E8S));
    assert_ne!(first, second);
    unconfigured.upgrade_with(Some(second));
    assert_eq!(unconfigured.configured_token(), Some(second), "upgrade Some over set → replaced");

    // And a fresh install with Some → set (the ordinary path).
    let configured = setup_with_token(Some(mock_token_wasm(RICH_BALANCE_E8S)));
    assert_eq!(configured.configured_token(), Some(configured.token_id), "install Some → set");

    // The namespace guards are independent of all of this: get_config is
    // unmoved across every upgrade above.
    // `get_config` returns TWO values, not a tuple-typed one, so it decodes
    // with `decode_args`.
    let raw = unconfigured
        .pic
        .query_call(
            unconfigured.vetkeys_id,
            Principal::anonymous(),
            "get_config",
            candid::encode_args(()).unwrap(),
        )
        .expect("get_config");
    let (domain, key_name): (String, String) = candid::decode_args(&raw).expect("get_config args");
    assert_eq!(domain, "stsh.wallet.notes.v1");
    assert_eq!(key_name, "test_key_1");
}

/// §H′.5 — THE TWO-WAVE PROBE (brief V4).
///
/// WHAT IS PROVED HERE: across a first wave of same-principal calls, a clock
/// advance past both the A-2 meter hour and the §H′ stale TTL, a SECOND wave
/// admitted afterwards, and the release of everything, the number of
/// `vetkd_derive_key` calls the canister actually DISPATCHED never exceeds the
/// rolling-24 h quota of 5 — counted on a side channel the admission machine
/// does not write.
///
/// HOW THE COUNT IS INDEPENDENT. The dispatch count comes from the canister's
/// CYCLE BALANCE — a derive costs ~26B cycles — divided by a per-derive cost
/// MEASURED in this test rather than assumed. It is not the endpoint's return
/// values and not any state `admission` writes, so a bug that both over-admits
/// and misreports would still be caught.
///
/// WHAT THIS HARNESS CANNOT STAGE, STATED PLAINLY. The brief's probe also asks
/// for replies held ACROSS the TTL boundary — i.e. a call parked in the
/// eligibility await while later calls are admitted at a LATER clock value.
/// PocketIC 9's `tick()` drains to quiescence (measured: after one `tick()`
/// following `submit_call`, ~68B cycles were already spent, so the call had
/// completed end to end), and `advance_time` cannot move the clock in the
/// middle of a drain. A call therefore always completes at the clock value at
/// which it was admitted, and "resume after another call pruned my reservation"
/// is not reachable from outside the canister here. That interleaving is proved
/// instead at the unit level, on the same function the endpoint calls, by
/// `admission::tests::a_pruned_predispatch_frees_capacity_but_kills_its_own_call`
/// and `a_reservation_can_be_dispatched_only_once`. This limitation is reported
/// in the builder close report rather than papered over — an arm asserting an
/// unreachable interleaving would pass vacuously and read as evidence.
#[test]
fn hprime5_two_wave_probe_never_exceeds_the_quota() {
    // The SLOW token (two extra rounds before its reply) keeps wave 1's calls
    // outstanding while wave 2's ingress is delivered, which is as much of the
    // interleaving as this harness admits.
    let h = setup_with_token(Some(slow_token_wasm(RICH_BALANCE_E8S)));
    let user = p(0xA5);

    // ── Calibration: what does ONE dispatched derive actually cost here? ─────
    let calibration_user = p(0xA6);
    let before_one = h.cycles();
    h.derive_past_the_meter(calibration_user, 0x40).expect("calibration derive");
    let cost_per_derive = before_one.saturating_sub(h.cycles());
    assert!(
        cost_per_derive > 1_000_000_000,
        "a dispatched derive must be visibly expensive for this counter to work; measured \
         {cost_per_derive} cycles"
    );

    // ── Wave 1 ───────────────────────────────────────────────────────────────
    // V5 §6: record this principal's sighting and let it age in BEFORE the arm
    // begins, then reset the meter — an age-refused attempt is still a call, and
    // the A-2 meter charges every call. Doing it here keeps the age gate out of
    // the boundary this arm actually measures.
    h.age_in_all(&[user]);
    h.skip_the_meter_window();
    let baseline = h.cycles();
    let mut wave1 = Vec::new();
    for i in 0..5u8 {
        wave1.push(
            h.pic
                .submit_call(
                    h.vetkeys_id,
                    user,
                    "get_encrypted_vetkey",
                    candid::encode_one(Harness::valid_transport_key(0x50 + i)).unwrap(),
                )
                .expect("submitted"),
        );
    }
    let wave1_outcomes: Vec<VetKeyResult> = wave1
        .into_iter()
        .map(|id| decode::<VetKeyResult>("wave 1", h.pic.await_call(id)))
        .collect();

    // ── Past the meter hour AND the stale TTL, then wave 2 ───────────────────
    //
    // ONE HOUR AND ONE SECOND, not five minutes: the advance must clear the A-2
    // METER window as well as the §H′ TTL, or wave 2 is refused by the METER
    // and this probe measures lane A-2 instead of §H′. (It did, before this was
    // corrected — the wave-2 refusals came back as "rate limit: at most 5
    // vetKey derivations". The typed-variant assertion below is what makes that
    // visible instead of silently passing.)
    h.pic.advance_time(std::time::Duration::from_secs(60 * 60 + 1));

    let mut wave2 = Vec::new();
    for i in 0..5u8 {
        wave2.push(
            h.pic
                .submit_call(
                    h.vetkeys_id,
                    user,
                    "get_encrypted_vetkey",
                    candid::encode_one(Harness::valid_transport_key(0x60 + i)).unwrap(),
                )
                .expect("submitted"),
        );
    }
    let wave2_outcomes: Vec<VetKeyResult> = wave2
        .into_iter()
        .map(|id| decode::<VetKeyResult>("wave 2", h.pic.await_call(id)))
        .collect();

    // LAUNCH-HARDEN-04 O-3: with the per-principal hourly DISPATCH cap at 2,
    // two waves dispatch 2 + 2 = 4 — below the rolling-24 h quota of 5, so the
    // quota would not be the refusing control. A THIRD wave, one more meter hour later, is what makes §H′ the binding
    // control again (non-vacuity below requires a DerivationQuotaExceeded).
    h.pic.advance_time(std::time::Duration::from_secs(60 * 60 + 1));
    let mut wave3 = Vec::new();
    for i in 0..5u8 {
        wave3.push(
            h.pic
                .submit_call(
                    h.vetkeys_id,
                    user,
                    "get_encrypted_vetkey",
                    candid::encode_one(Harness::valid_transport_key(0x70 + i)).unwrap(),
                )
                .expect("submitted"),
        );
    }
    let wave3_outcomes: Vec<VetKeyResult> = wave3
        .into_iter()
        .map(|id| decode::<VetKeyResult>("wave 3", h.pic.await_call(id)))
        .collect();

    let outcomes: Vec<&VetKeyResult> = wave1_outcomes
        .iter()
        .chain(wave2_outcomes.iter())
        .chain(wave3_outcomes.iter())
        .collect();

    // ── THE BOUND, on the independent counter ────────────────────────────────
    let spent = baseline.saturating_sub(h.cycles());
    let dispatches = spent / cost_per_derive;
    assert!(
        dispatches <= 5,
        "ACROSS BOTH WAVES the canister dispatched ~{dispatches} vetkd_derive_key calls \
         ({spent} cycles at ~{cost_per_derive} each) — the rolling-24 h quota is 5"
    );

    let succeeded = outcomes.iter().filter(|o| o.is_ok()).count();
    assert!(succeeded >= 1, "no call succeeded — this probe proved nothing: {outcomes:?}");
    assert!(succeeded <= 5, "more than the quota SUCCEEDED: {succeeded}");

    // NON-VACUITY: the quota must actually have bitten. Fifteen calls went in
    // inside one 24 h window; at most five may come out.
    let refused = outcomes.iter().filter(|o| o.is_err()).count();
    assert!(
        refused >= 10,
        "fifteen same-principal calls in one 24 h window produced only {refused} refusals — \
         the window is not binding across the wave boundaries"
    );
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Err(VetkeysError::DerivationQuotaExceeded { .. }))),
        "the §H′ quota itself must refuse at least one call across the three waves: {outcomes:?}"
    );

    // THE MECHANISM MUST BE §H′ (or, since LAUNCH-HARDEN-04 O-3, the per-
    // principal hourly fence cap), NOT THE METER. A `RateLimited` refusal would
    // mean the advance did not clear the meter and this probe is measuring the
    // wrong control.
    for outcome in &outcomes {
        if let Err(e) = outcome {
            assert!(
                matches!(
                    e,
                    VetkeysError::AdmissionLapsed
                        | VetkeysError::DerivationQuotaExceeded { .. }
                        | VetkeysError::PrincipalHourlyDerivationCapExceeded { .. }
                ),
                "refusals in this probe must come from §H′ or the per-principal cap, not the \
                 meter; got {e:?}"
            );
        }
    }
}

/// §H′.5 — the RESERVATION-STILL-HELD half, which this harness CAN stage: a
/// call whose eligibility reply comes back while its reservation is still
/// present dispatches exactly ONCE, and the slots it consumed stay consumed.
///
/// Paired with the unit-level prune arms, this covers both sides of the
/// dispatch fence: present ⇒ dispatch once; absent ⇒ lapse without dispatch.
#[test]
fn hprime5_a_held_reservation_dispatches_exactly_once() {
    let h = setup_with_token(Some(slow_token_wasm(RICH_BALANCE_E8S)));
    let user = p(0xA7);

    let before_one = h.cycles();
    h.derive_past_the_meter(p(0xA8), 0x6F).expect("calibration derive");
    let cost_per_derive = before_one.saturating_sub(h.cycles());
    assert!(cost_per_derive > 1_000_000_000, "measured {cost_per_derive} cycles per derive");

    h.skip_the_meter_window();
    let baseline = h.cycles();
    let reply = h
        .try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(0x70))
        .expect("a call whose reservation is intact must complete");
    assert_eq!(
        reply.remaining, 4,
        "one slot of five was taken by this call, and `remaining` reports the §H′ window"
    );

    // Exactly one dispatch — not zero (it really derived) and not two (the
    // resumption path cannot dispatch a second time on one reservation).
    let spent = baseline.saturating_sub(h.cycles());
    assert!(
        spent >= cost_per_derive / 2 && spent < cost_per_derive * 2,
        "{spent} cycles at ~{cost_per_derive} per derive is not exactly one dispatch"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// D-1b v3 §2 — replace_envelope (the opt-in passcode toggle, canister side)
// ═════════════════════════════════════════════════════════════════════════════

fn replace_transcript(
    canister: Principal,
    owner: Principal,
    device_id: &str,
    old_hash: [u8; 32],
    new_hash: [u8; 32],
    nonce: [u8; 16],
    expiry_ns: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    var(&mut out, PROTOCOL);
    out.extend_from_slice(&1u16.to_le_bytes());
    var(&mut out, canister.as_slice());
    var(&mut out, b"replace_envelope");
    var(&mut out, owner.as_slice());
    var(&mut out, device_id.as_bytes());
    out.extend_from_slice(&old_hash);
    out.extend_from_slice(&new_hash);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&expiry_ns.to_le_bytes());
    out
}

impl Harness {
    fn replace(
        &self,
        user: Principal,
        device_id: &str,
        new_envelope: Vec<u8>,
        approval: SignedApproval,
    ) -> Result<(), VetkeysError> {
        decode(
            "replace_envelope",
            self.pic.update_call(
                self.vetkeys_id,
                user,
                "replace_envelope",
                candid::encode_args((device_id.to_string(), new_envelope, approval)).unwrap(),
            ),
        )
    }

    /// A self-signed replacement, built the way the wallet builds it.
    fn replacement_from(
        &self,
        device: &TestDevice,
        owner: Principal,
        old_envelope: &[u8],
        new_envelope: &[u8],
        nonce: [u8; 16],
        expiry_ns: u64,
    ) -> SignedApproval {
        let msg = replace_transcript(
            self.vetkeys_id,
            owner,
            &device.id,
            sha256(old_envelope),
            sha256(new_envelope),
            nonce,
            expiry_ns,
        );
        SignedApproval {
            issuer_device_id: device.id.clone(),
            nonce: nonce.to_vec(),
            expiry_ns,
            signature: device.sign(&msg),
        }
    }
}

/// R-1 — the toggle works, and the OLD envelope is gone canister-side. This is
/// the arm the ruling demands to prove the toggle is real: after enabling a
/// passcode, a fetch returns ONLY the new (passcode-mode) envelope. A
/// wallet-local wrapper that left the stored blob bare would fail here.
#[test]
fn r1_replace_envelope_swaps_the_stored_blob() {
    let h = setup();
    let user = p(0x91);
    let dev = TestDevice::new("device-1", 0x81);
    let ii_only = envelope(0x11);
    h.bootstrap(user, &dev, ii_only.clone());
    assert_eq!(h.wrapped_secret(user, &dev.id), Ok(ii_only.clone()));

    let passcode_mode = envelope(0x22);
    assert_ne!(passcode_mode, ii_only);
    let approval =
        h.replacement_from(&dev, user, &ii_only, &passcode_mode, [0x01; 16], live_expiry(&h));
    h.replace(user, &dev.id, passcode_mode.clone(), approval).expect("self-service replacement");

    assert_eq!(
        h.wrapped_secret(user, &dev.id),
        Ok(passcode_mode),
        "the stored envelope must BE the new one — not the old one with something beside it"
    );
    // The device record itself is untouched: this replaces an envelope, not an
    // identity.
    let listed = h.devices(user);
    assert_eq!(listed.len(), 1);
    assert!(listed[0].active);
}

/// R-2 — ROLLBACK. Re-installing a captured OLD envelope is refused, because
/// the transcript the canister rebuilds uses what is stored NOW as
/// `old_envelope_hash`, and the attacker's signature commits to the superseded
/// one. Includes the honest converse: an attacker who kept the old BYTES still
/// has them — this refuses the canister-side rollback, nothing more.
#[test]
fn r2_a_captured_old_envelope_cannot_be_reinstalled() {
    let h = setup();
    let user = p(0x92);
    let dev = TestDevice::new("device-1", 0x82);
    let first = envelope(0x33);
    h.bootstrap(user, &dev, first.clone());

    let second = envelope(0x44);
    let forward = h.replacement_from(&dev, user, &first, &second, [0x02; 16], live_expiry(&h));
    h.replace(user, &dev.id, second.clone(), forward).expect("forward replacement");

    // Now try to put `first` back with a freshly signed, otherwise-valid
    // transcript that claims the CURRENT envelope is `first`.
    let rollback = h.replacement_from(&dev, user, &first, &first, [0x03; 16], live_expiry(&h));
    match h.replace(user, &dev.id, first.clone(), rollback) {
        Err(VetkeysError::ApprovalRejected(reason)) => {
            assert!(reason.contains("does not verify"), "{reason}");
        }
        other => panic!("a rollback to a superseded envelope must be refused, got {other:?}"),
    }
    assert_eq!(h.wrapped_secret(user, &dev.id), Ok(second), "the current envelope stands");
}

/// R-3 — REPLAY, before and after a REAL upgrade. The exact same signed
/// replacement cannot be applied twice: its nonce is burned, and the burn is
/// stable state.
#[test]
fn r3_a_replacement_cannot_be_replayed_before_or_after_an_upgrade() {
    let h = setup();
    let user = p(0x93);
    let dev = TestDevice::new("device-1", 0x83);
    let first = envelope(0x55);
    h.bootstrap(user, &dev, first.clone());

    let second = envelope(0x66);
    let nonce = [0x04; 16];
    let expiry = live_expiry(&h);
    let approval = h.replacement_from(&dev, user, &first, &second, nonce, expiry);
    h.replace(user, &dev.id, second.clone(), approval.clone()).expect("first application");

    // Immediate replay: the nonce is burned AND the old hash is stale — either
    // alone is fatal, which is the point of having both.
    assert!(
        h.replace(user, &dev.id, second.clone(), approval.clone()).is_err(),
        "a replayed replacement must be refused"
    );

    h.pic
        .upgrade_canister(h.vetkeys_id, vetkeys_wasm(), candid::encode_one(None::<Principal>).unwrap(), None)
        .expect("upgrade");

    assert!(
        h.replace(user, &dev.id, second.clone(), approval).is_err(),
        "a nonce burned before the upgrade must stay burned"
    );
    assert_eq!(h.wrapped_secret(user, &dev.id), Ok(second), "state survived intact");
}

/// R-4 — a device may replace ONLY ITS OWN envelope. Device B holding a valid
/// signature of its own cannot rewrite device A's blob.
#[test]
fn r4_a_device_cannot_replace_another_devices_envelope() {
    let h = setup();
    let user = p(0x94);
    let first = TestDevice::new("device-1", 0x84);
    let env1 = envelope(0x77);
    h.bootstrap(user, &first, env1.clone());

    let second = TestDevice::new("device-2", 0x85);
    let env2 = envelope(0x88);
    let approval = h.approval_from(&first, user, &second, &env2, [0x05; 16], live_expiry(&h));
    h.register(user, &second, env2, DeviceApproval::Device(approval)).expect("second device");

    // Device 2 signs a replacement naming device 1 as the subject.
    let attack = h.replacement_from(&second, user, &env1, &envelope(0x99), [0x06; 16], live_expiry(&h));
    let attack = SignedApproval { issuer_device_id: second.id.clone(), ..attack };
    match h.replace(user, &first.id, envelope(0x99), attack) {
        Err(VetkeysError::ApprovalRejected(reason)) => {
            assert!(reason.contains("its OWN envelope"), "{reason}");
        }
        other => panic!("cross-device replacement must be refused, got {other:?}"),
    }
    assert_eq!(h.wrapped_secret(user, &first.id), Ok(env1), "device 1's envelope is untouched");
}

/// R-5 — a REVOKED device cannot replace its envelope. Revocation deletes the
/// blob, so there is nothing to replace, and the device is refused before that
/// even matters.
#[test]
fn r5_a_revoked_device_cannot_replace_its_envelope() {
    let h = setup();
    let user = p(0x95);
    let first = TestDevice::new("device-1", 0x86);
    let env1 = envelope(0xAA);
    h.bootstrap(user, &first, env1.clone());
    let second = TestDevice::new("device-2", 0x87);
    let env2 = envelope(0xBB);
    let approval = h.approval_from(&first, user, &second, &env2, [0x07; 16], live_expiry(&h));
    h.register(user, &second, env2, DeviceApproval::Device(approval)).expect("second device");

    let rev = h.revocation_from(&second, user, &first.id, [0x08; 16], live_expiry(&h));
    h.revoke(user, &first.id, rev).expect("revoke device 1");

    let attempt = h.replacement_from(&first, user, &env1, &envelope(0xCC), [0x09; 16], live_expiry(&h));
    match h.replace(user, &first.id, envelope(0xCC), attempt) {
        Err(VetkeysError::ApprovalRejected(reason)) => assert!(reason.contains("revoked")),
        other => panic!("a revoked device must not replace anything, got {other:?}"),
    }
}

/// R-6 — the replacement rate limit is 5 per rolling 24 h AND is its own
/// counter: exhausting it must not consume the registration allowance.
#[test]
fn r6_replacement_is_rate_limited_on_its_own_counter() {
    let h = setup();
    let user = p(0x96);
    let dev = TestDevice::new("device-1", 0x88);
    let mut current = envelope(0xD0);
    h.bootstrap(user, &dev, current.clone());

    for i in 0..5u8 {
        let next = envelope(0xD1 + i);
        let approval =
            h.replacement_from(&dev, user, &current, &next, [0x10 + i; 16], live_expiry(&h));
        h.replace(user, &dev.id, next.clone(), approval)
            .unwrap_or_else(|e| panic!("replacement {i} must be admitted: {e:?}"));
        current = next;
    }
    let next = envelope(0xDF);
    let approval = h.replacement_from(&dev, user, &current, &next, [0x1F; 16], live_expiry(&h));
    match h.replace(user, &dev.id, next, approval) {
        Err(VetkeysError::RegistrationRateExceeded { retry_after_ns }) => {
            assert!(retry_after_ns > 0);
        }
        other => panic!("the sixth replacement in 24 h must be rate-refused, got {other:?}"),
    }

    // The REGISTRATION allowance is untouched — separate counters.
    let second = TestDevice::new("device-2", 0x89);
    let env2 = envelope(0xEE);
    let approval = h.approval_from(&dev, user, &second, &env2, [0x20; 16], live_expiry(&h));
    h.register(user, &second, env2, DeviceApproval::Device(approval))
        .expect("exhausting replacements must not consume the registration allowance");
}

// ═════════════════════════════════════════════════════════════════════════════
// D-1b v4 §2 — the compromise remedy, proved CAUSALLY
// ═════════════════════════════════════════════════════════════════════════════
//
// These two arms exist because a plausible-sounding remedy was ruled OUT and a
// different one ruled IN, and the difference is only visible in the crypto.
// They run against REAL vetKD, and every expected identity is CONSTRUCTED here
// from the principal and the pinned key name — never read back from the code
// under test.

/// V4-1 — THE WITHDRAWN REMEDY FAILS. A captured vetKey still decrypts a
/// payload the victim sends to THEMSELVES.
///
/// This is why "spend to yourself under fresh note randomness" was withdrawn
/// (SSA RED-5): the new payload is addressed to the SAME IBE identity, and the
/// captured key opens it exactly as it opened the old one. Fresh randomness
/// inside the note changes nothing about who the outer envelope is for.
#[test]
fn v4_1_a_captured_vetkey_still_reads_a_same_principal_self_spend() {
    let h = setup();
    let victim = p(0xC1);
    let dpk = h.verification_key();

    // The attacker's copy, taken before any revocation.
    let captured = h.fetch_vetkey(victim, &dpk, [0xC1; 32]);

    // The victim now "migrates" by spending to themselves — a FRESH payload,
    // fresh randomness, same identity. Identity built here from the principal.
    let self_identity = IbeIdentity::from_bytes(&vetkd_input(victim, KEY_NAME));
    let fresh_payload = IbeCiphertext::encrypt(
        &dpk,
        &self_identity,
        b"post-migration note, same principal",
        &IbeSeed::random(&mut rand::thread_rng()),
    )
    .serialize();

    let opened = IbeCiphertext::deserialize(&fresh_payload)
        .expect("valid ciphertext")
        .decrypt(&captured);
    assert_eq!(
        opened.expect("the captured key opens it").as_slice(),
        b"post-migration note, same principal",
        "a same-principal self-spend is NOT a remedy: the captured vetKey reads the new \
         payload too. Any UX calling this a fix is wrong (D-1b v4 §1)."
    );
}

/// V4-2 — THE RULED REMEDY WORKS. The same captured vetKey CANNOT read a
/// payload addressed to a FRESH principal.
///
/// This is the whole content of the correction: migration must change the IBE
/// IDENTITY, not the note randomness.
#[test]
fn v4_2_a_captured_vetkey_cannot_read_a_new_principal_payload() {
    let h = setup();
    let victim = p(0xC2);
    let fresh_identity_principal = p(0xC3);
    assert_ne!(victim, fresh_identity_principal);
    let dpk = h.verification_key();

    let captured = h.fetch_vetkey(victim, &dpk, [0xC2; 32]);

    // Value migrated to the NEW identity: the recipient is the new principal.
    let new_identity = IbeIdentity::from_bytes(&vetkd_input(fresh_identity_principal, KEY_NAME));
    let migrated = IbeCiphertext::encrypt(
        &dpk,
        &new_identity,
        b"migrated note, new principal",
        &IbeSeed::random(&mut rand::thread_rng()),
    )
    .serialize();

    assert!(
        IbeCiphertext::deserialize(&migrated)
            .expect("valid ciphertext")
            .decrypt(&captured)
            .is_err(),
        "the captured vetKey must NOT open a payload addressed to the fresh principal — this \
         is the property the whole migration ceremony rests on"
    );

    // NON-VACUITY: the new identity's OWN key does open it, so the failure
    // above is about the identity and not about a malformed fixture.
    let new_key = h.fetch_vetkey(fresh_identity_principal, &dpk, [0xC3; 32]);
    assert_eq!(
        IbeCiphertext::deserialize(&migrated)
            .expect("valid ciphertext")
            .decrypt(&new_key)
            .expect("the new identity opens its own payload")
            .as_slice(),
        b"migrated note, new principal"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// review-round RED-2 — `revoke_device` has its OWN metered window (VK-M2)
// ═════════════════════════════════════════════════════════════════════════════

/// A revocation approval whose signature is garbage: same transcript, one
/// byte of the signature flipped. Refused by P-256 verification — AFTER the
/// meter has charged, which is the property M2-1 asserts.
fn corrupted_revocation(h: &Harness, issuer: &TestDevice, owner: Principal, target: &str,
                        nonce: [u8; 16]) -> SignedApproval {
    let mut a = h.revocation_from(issuer, owner, target, nonce, live_expiry(h));
    a.signature[10] ^= 0xFF;
    a
}

/// M2-1 — five revoke attempts per rolling 24 h, charged on FAILURE too, and
/// the meter bites BEFORE signature verification: the sixth attempt is refused
/// with the distinct typed variant even though its approval is VALID, and the
/// target device is untouched. Then both OTHER windows are shown untouched:
/// after six revoke calls, registration and replacement still admit — with a
/// shared counter either would be over budget.
#[test]
fn m2_1_revocation_is_rate_limited_including_failures_and_meter_first() {
    let h = setup();
    let user = p(0x9A);
    let first = TestDevice::new("device-1", 0x8A);
    h.bootstrap(user, &first, envelope(0xA0));
    let second = TestDevice::new("device-2", 0x8B);
    let env2 = envelope(0xA1);
    let approval = h.approval_from(&first, user, &second, &env2, [0x30; 16], live_expiry(&h));
    h.register(user, &second, env2.clone(), DeviceApproval::Device(approval))
        .expect("second device");

    // Five invalid-signature attempts: each refused on the signature, each
    // CHARGED (if failures were free, the failure path would be an unmetered
    // P-256 loop — the exact RED-2 vector).
    for i in 0..5u8 {
        let bad = corrupted_revocation(&h, &first, user, &second.id, [0x31 + i; 16]);
        match h.revoke(user, &second.id, bad) {
            Err(VetkeysError::ApprovalRejected(_)) => {}
            other => panic!("attempt {i} must fail on the signature, not the rate: {other:?}"),
        }
    }

    // Sixth call carries a VALID revocation — refused by the METER, which
    // proves the charge happens before verification ever runs.
    let valid = h.revocation_from(&first, user, &second.id, [0x3F; 16], live_expiry(&h));
    match h.revoke(user, &second.id, valid) {
        Err(VetkeysError::RevocationRateExceeded { retry_after_ns }) => {
            assert!(retry_after_ns > 0, "the refusal must say when the window frees");
            assert!(
                retry_after_ns <= 24 * 60 * 60 * 1_000_000_000,
                "retry_after must be within the 24 h window, got {retry_after_ns}"
            );
        }
        other => panic!("the sixth revoke in 24 h must be rate-refused, got {other:?}"),
    }
    // The refused revocation left no trace: device-2 is still active.
    let dev2 = h.devices(user).into_iter().find(|d| d.device_id == second.id).unwrap();
    assert!(dev2.active, "a rate-refused revocation must not revoke");

    // ISOLATION (three-way, this direction): six revoke calls have consumed
    // NOTHING from the registration window (2/5 used) or the replacement
    // window (0/5 used) — a shared counter would refuse both of these.
    let third = TestDevice::new("device-3", 0x8C);
    let env3 = envelope(0xA2);
    let approval = h.approval_from(&first, user, &third, &env3, [0x40; 16], live_expiry(&h));
    h.register(user, &third, env3, DeviceApproval::Device(approval))
        .expect("exhausting revocation must not consume the registration allowance");
    let new_env = envelope(0xA3);
    let approval =
        h.replacement_from(&first, user, &envelope(0xA0), &new_env, [0x41; 16], live_expiry(&h));
    h.replace(user, &first.id, new_env, approval)
        .expect("exhausting revocation must not consume the replacement allowance");
}

/// M2-2 — the OTHER direction of isolation: registration exhausted AND
/// replacement exhausted, and a revocation is still admitted. All three
/// windows are independent.
#[test]
fn m2_2_exhausted_registration_and_replacement_do_not_consume_revocation() {
    let h = setup();
    let user = p(0x9B);
    let first = TestDevice::new("device-1", 0x8D);
    h.bootstrap(user, &first, envelope(0xB0));
    let second = TestDevice::new("device-2", 0x8E);
    let env2 = envelope(0xB1);
    let approval = h.approval_from(&first, user, &second, &env2, [0x50; 16], live_expiry(&h));
    h.register(user, &second, env2, DeviceApproval::Device(approval)).expect("second device");

    // Exhaust registration: 2 used; 3 more failing attempts spend the window.
    let ghost = TestDevice::new("ghost", 0x8F);
    for i in 0..3u8 {
        match h.register(user, &ghost, envelope(0xB2), DeviceApproval::Bootstrap) {
            Err(VetkeysError::BootstrapNotAuthorized { .. }) => {}
            other => panic!("filler registration {i} should fail on the ticket: {other:?}"),
        }
    }
    match h.register(user, &ghost, envelope(0xB2), DeviceApproval::Bootstrap) {
        Err(VetkeysError::RegistrationRateExceeded { .. }) => {}
        other => panic!("registration must now be exhausted, got {other:?}"),
    }

    // Exhaust replacement: five self-replacements on device-1.
    let mut current = envelope(0xB0);
    for i in 0..5u8 {
        let next = envelope(0xB3 + i);
        let approval =
            h.replacement_from(&first, user, &current, &next, [0x60 + i; 16], live_expiry(&h));
        h.replace(user, &first.id, next.clone(), approval)
            .unwrap_or_else(|e| panic!("replacement {i} must be admitted: {e:?}"));
        current = next;
    }
    let next = envelope(0xBF);
    let approval =
        h.replacement_from(&first, user, &current, &next, [0x6F; 16], live_expiry(&h));
    match h.replace(user, &first.id, next, approval) {
        Err(VetkeysError::RegistrationRateExceeded { .. }) => {}
        other => panic!("replacement must now be exhausted, got {other:?}"),
    }

    // Revocation still has its FULL budget: a valid revoke is admitted.
    let rev = h.revocation_from(&first, user, &second.id, [0x70; 16], live_expiry(&h));
    h.revoke(user, &second.id, rev)
        .expect("exhausted registration/replacement windows must not consume revocation");
}

/// M2-3 — the revocation window is STABLE: spent before a REAL upgrade means
/// spent after it; and past the 24 h boundary the window slides open again
/// (coarse PocketIC slide — the ±1 ns boundary is unit-proved in
/// `registry::tests::the_revocation_window_admits_exactly_the_quota_with_exact_wait`,
/// where the clock can be pinned).
#[test]
fn m2_3_revocation_window_survives_a_real_upgrade_and_slides() {
    let h = setup();
    let user = p(0x9C);
    let first = TestDevice::new("device-1", 0x90);
    h.bootstrap(user, &first, envelope(0xC0));
    let second = TestDevice::new("device-2", 0x91);
    let env2 = envelope(0xC1);
    let approval = h.approval_from(&first, user, &second, &env2, [0x71; 16], live_expiry(&h));
    h.register(user, &second, env2, DeviceApproval::Device(approval)).expect("second device");

    for i in 0..5u8 {
        let bad = corrupted_revocation(&h, &first, user, &second.id, [0x72 + i; 16]);
        assert!(
            matches!(h.revoke(user, &second.id, bad), Err(VetkeysError::ApprovalRejected(_))),
            "filler attempt {i}"
        );
    }
    let valid = h.revocation_from(&first, user, &second.id, [0x7F; 16], live_expiry(&h));
    match h.revoke(user, &second.id, valid) {
        Err(VetkeysError::RevocationRateExceeded { .. }) => {}
        other => panic!("pre-upgrade: the window must be spent, got {other:?}"),
    }

    // A REAL upgrade to the production Wasm (vetkeys ships one artifact).
    h.pic
        .upgrade_canister(h.vetkeys_id, vetkeys_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("upgrade");

    // Spent before means spent after — an upgrade-cleared window would be a
    // free allowance.
    let valid = h.revocation_from(&first, user, &second.id, [0x80; 16], live_expiry(&h));
    match h.revoke(user, &second.id, valid) {
        Err(VetkeysError::RevocationRateExceeded { .. }) => {}
        other => panic!("post-upgrade: the window must STILL be spent, got {other:?}"),
    }

    // Past the 24 h window the meter admits again — and the admitted call
    // actually revokes, so the meter is live, not wedged.
    h.pic.advance_time(std::time::Duration::from_secs(24 * 60 * 60 + 1));
    h.pic.tick();
    let valid = h.revocation_from(&first, user, &second.id, [0x81; 16], live_expiry(&h));
    h.revoke(user, &second.id, valid).expect("the window must slide open past 24 h");
    let dev2 = h.devices(user).into_iter().find(|d| d.device_id == second.id).unwrap();
    assert!(!dev2.active, "the admitted revocation must actually revoke");
}

// ═════════════════════════════════════════════════════════════════════════════
// review-round RED-1 — bounded consumed-nonce reclamation (VK-L1), endpoint side
// ═════════════════════════════════════════════════════════════════════════════
//
// The mechanism arms (both-or-neither, exact `< now` boundary, exactly-K
// drain, mutation-RED at K) are unit tests over the thread-local stable
// structures in src/lib.rs and src/registry.rs, where the clock and the map
// cardinalities can be pinned. What only PocketIC can prove is HERE: the
// primary/index pair survives a REAL upgrade, and reclamation runs cleanly on
// the upgraded canister — every prune re-checks the bijection and TRAPS on a
// mismatch, so "the consuming call succeeds after the upgrade" is the
// bijection evidence, not an assumption.

/// L1-1 — bijection survives a real upgrade: a nonce consumed BEFORE the
/// upgrade still refuses replay after it; an approval that EXPIRED before the
/// upgrade is reclaimed by a post-upgrade consume without trapping; and the
/// replay refusal of a live nonce still stands after that prune has run.
#[test]
fn l1_1_nonce_bijection_survives_a_real_upgrade_and_prunes_after_it() {
    let h = setup();
    let user = p(0x9D);
    let first = TestDevice::new("device-1", 0x92);
    h.bootstrap(user, &first, envelope(0xE0));

    // A SHORT-lived approval, consumed while live: this row expires before
    // the upgrade and is the post-upgrade prune's target.
    let second = TestDevice::new("device-2", 0x93);
    let env2 = envelope(0xE1);
    let short_expiry = h.now_ns() + 60 * 1_000_000_000;
    let approval = h.approval_from(&first, user, &second, &env2, [0x90; 16], short_expiry);
    h.register(user, &second, env2, DeviceApproval::Device(approval))
        .expect("short-expiry approval is live at consume time");

    // A LONG-lived approval, consumed: its nonce must refuse replay across
    // the upgrade (the live-rows-survive half).
    let third = TestDevice::new("device-3", 0x94);
    let env3 = envelope(0xE2);
    let long_expiry = h.now_ns() + 7 * 24 * 60 * 60 * 1_000_000_000;
    let live_nonce = [0x91; 16];
    let approval = h.approval_from(&first, user, &third, &env3, live_nonce, long_expiry);
    h.register(user, &third, env3, DeviceApproval::Device(approval)).expect("third device");

    // The short-lived row expires…
    h.pic.advance_time(std::time::Duration::from_secs(3600));
    h.pic.tick();

    // …then a REAL upgrade to the production Wasm carries both maps across.
    h.pic
        .upgrade_canister(h.vetkeys_id, vetkeys_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("upgrade");

    // A post-upgrade consume: its admission prunes the expired row from BOTH
    // structures. A primary/index mismatch — a row lost or duplicated by the
    // upgrade — TRAPS here and fails this register.
    let fourth = TestDevice::new("device-4", 0x95);
    let env4 = envelope(0xE3);
    let approval =
        h.approval_from(&first, user, &fourth, &env4, [0x92; 16], live_expiry(&h));
    h.register(user, &fourth, env4, DeviceApproval::Device(approval))
        .expect("post-upgrade consume must prune the expired backlog without trapping");

    // The LIVE nonce consumed before the upgrade still refuses replay — its
    // row survived both the upgrade and the prune.
    let fifth = TestDevice::new("device-5", 0x96);
    let env5 = envelope(0xE4);
    let replay = h.approval_from(&first, user, &fifth, &env5, live_nonce, long_expiry);
    match h.register(user, &fifth, env5, DeviceApproval::Device(replay)) {
        Err(VetkeysError::ApprovalRejected(reason)) => {
            assert!(reason.contains("already been used"), "{reason}")
        }
        other => panic!("a live nonce must stay burned across upgrade + prune: {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// C-26 REMEDY (A1 fix brief V3) — cycle floor + fleet-wide global derive budget
// ═════════════════════════════════════════════════════════════════════════════
//
// The PocketIC cycle regime, binding on the floor arms (brief §6.4): under
// PocketIC's nonmainnet `test_key_1`, `vetkd_derive_key` is effectively free,
// so the floor arms are driven by the PINNED FLOOR being large relative to
// post-install liquid balance — never by real derive spend, and never by
// depletion across successive derives. The RED-5 causal (depletion) arm is
// therefore NATIVE (`fence::tests`), not PocketIC; the arms here prove
// ORDERING and dispatch/global-state effects.

/// The shipped pins, mirrored as literals for the same reason `DERIVE_QUOTA`
/// is above: the canister crate is a cdylib, and reading the value from the
/// code under test could not RED when it moves. `pins::tests` holds the
/// mutation arms.
/// LAUNCH ON-RAMP RE-PIN 2026-09-01: 100 → 20 (ratification addd59af…).
/// LAUNCH-HARDEN-04 O-3 RE-PIN 2026-09-24: 20 → 100
/// (RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24, sha256 249f551b…ec417).
const GLOBAL_DERIVE_BUDGET: usize = 100;
const CYCLE_FLOOR: u128 = 500_000_000_000;

/// How many distinct principals it takes to reach the fleet ceiling at the
/// per-principal hourly DISPATCH cap of 2 (LAUNCH-HARDEN-04 O-3; before it, the
/// meter/§H′ allowance of 5 was the per-principal bound): 100 / 2 = 50.
const FILL_PRINCIPALS: usize = GLOBAL_DERIVE_BUDGET / PER_PRINCIPAL_HOURLY_DERIVE_CAP as usize;

fn fill_principal(i: usize) -> Principal {
    let mut b = [0u8; 29];
    b[0] = 0xF1;
    b[1..9].copy_from_slice(&(i as u64).to_le_bytes());
    Principal::from_slice(&b)
}

/// G1 — brief arms (16), (17), (18), (22), (23) and the budget self-heal
/// (§8's closure of (6) at the endpoint), in one instance so the capacity
/// accounting is EXACT: pre-dispatch failures must consume zero fleet
/// capacity, or the fill below could not reach exactly the ceiling; an actual
/// dispatch must consume exactly one, or the 101st would not be the first
/// refusal.
///
/// One deviation from §6.3(17)'s letter, disclosed: the global window has no
/// read surface (§7.2 permits NO DID delta beyond the two variants), so
/// "byte-for-byte unchanged" is proven as EXACT-COUNT capacity accounting —
/// the §2.4 acceptance criteria are themselves stated in counts (zero / zero /
/// zero / exactly one). The lapsed-parked-call leg is proven natively
/// (`fence::tests` arm 11 and `admission::tests`): the two-wave probe above
/// documents that PocketIC cannot park a call across a TTL prune from outside.
#[test]
fn g1_global_budget_charges_only_actual_dispatches_and_survives_upgrade() {
    // Start POOR: every principal is below the §D floor, so first derives fail
    // pre-dispatch as PrincipalNotEligible.
    let h = setup_with_token(Some(mock_token_wasm(POOR_BALANCE_E8S)));

    // (17a) ineligible principals consume ZERO fleet capacity.
    for i in 0..3u8 {
        match h.try_get_encrypted_vetkey_typed(p(0xE0 + i), Harness::valid_transport_key(i)) {
            Err(VetkeysError::PrincipalNotEligible(_)) => {}
            other => panic!("expected PrincipalNotEligible, got {other:?}"),
        }
    }
    // (17b) malformed transport keys consume ZERO fleet capacity.
    for i in 0..3u8 {
        match h.try_get_encrypted_vetkey_typed(p(0xE8 + i), INVALID_TRANSPORT_KEY.to_vec()) {
            Err(VetkeysError::InvalidTransportKey(_)) => {}
            other => panic!("expected InvalidTransportKey, got {other:?}"),
        }
    }

    // Reconfigure to a RICH token through the §D upgrade path (Some writes).
    let rich = install_mock_token(&h.pic, mock_token_wasm(RICH_BALANCE_E8S));
    h.upgrade_with(Some(rich));

    // V5 §6: age ALL of them in first — the fill principals and the 21st that
    // must later hit the FLEET wall — then reset the meter.
    //
    // BATCHED, DELIBERATELY. Waiting T per principal in turn would advance the
    // clock by 20 × 2 min = 40 min, and this arm measures a ROLLING HOUR: the
    // window would roll underneath the fill and the budget could never fill.
    // Sightings are valid for seven days, so recording them all and waiting
    // once is faithful and leaves the measured window intact. Age refusals
    // consume no fleet capacity and release §H′, so the fill still starts from
    // an empty window and full allowances.
    let mut to_age: Vec<Principal> = (0..FILL_PRINCIPALS).map(fill_principal).collect();
    to_age.push(p(0xFA));
    h.age_in_all(&to_age);
    h.skip_the_meter_window();

    // (18) + the fill: 50 principals × 2 concurrent derives (the per-principal
    // hourly cap, LAUNCH-HARDEN-04 O-3), submitted as one batch per principal —
    // 100 dispatches, all inside one rolling hour. If any earlier failure had
    // consumed capacity, this could not reach 100.
    for i in 0..FILL_PRINCIPALS {
        let user = fill_principal(i);
        let calls: Vec<_> = (0..PER_PRINCIPAL_HOURLY_DERIVE_CAP as u8)
            .map(|j| {
                h.pic
                    .submit_call(
                        h.vetkeys_id,
                        user,
                        "get_encrypted_vetkey",
                        candid::encode_one(Harness::valid_transport_key(
                            (i as u8).wrapping_mul(7).wrapping_add(j),
                        ))
                        .unwrap(),
                    )
                    .expect("submitted")
            })
            .collect();
        for (j, id) in calls.into_iter().enumerate() {
            let res: VetKeyResult = decode("fill derive", h.pic.await_call(id));
            res.unwrap_or_else(|e| {
                panic!("fill derive {j} of principal {i} refused ({e:?}) — a pre-dispatch \
                        failure or an earlier dispatch consumed capacity it must not have")
            });
        }
    }

    // (22) THE ARM PER-PRINCIPAL METERING STRUCTURALLY CANNOT PASS: a 21st,
    // never-seen principal — full meter allowance, empty §H′ window — is
    // refused with the FLEET variant.
    let fresh = p(0xFA);
    match h.try_get_encrypted_vetkey_typed(fresh, Harness::valid_transport_key(0xFA)) {
        Err(VetkeysError::GlobalDerivationBudgetExceeded { retry_after_ns }) => {
            assert!(retry_after_ns > 0, "a full fleet window must say when a slot frees");
            assert!(
                retry_after_ns <= 3_600_000_000_000,
                "no slot can be further away than one full window; got {retry_after_ns}"
            );
        }
        other => panic!("the 101st dispatch attempt must hit the FLEET budget, got {other:?}"),
    }

    // (23) REAL UPGRADE DURABILITY: the window is stable, not heap — after an
    // upgrade the same fresh principal is STILL refused. (`None` preserves the
    // token cell; the heap meter resets, which must not matter here.)
    h.upgrade_with(None);
    match h.try_get_encrypted_vetkey_typed(fresh, Harness::valid_transport_key(0xFB)) {
        Err(VetkeysError::GlobalDerivationBudgetExceeded { .. }) => {}
        other => panic!("an upgrade must not clear the fleet window; got {other:?}"),
    }

    // Self-heal: one window later the budget rolls and the fresh principal
    // derives with no operator action.
    h.pic.advance_time(std::time::Duration::from_secs(3_601));
    h.pic.tick();
    let reply = h
        .try_get_encrypted_vetkey_typed(fresh, Harness::valid_transport_key(0xFC))
        .expect("the rolled window must admit the fresh principal");
    assert!(!reply.encrypted_key.is_empty());
}

/// G2 — brief arms (19), (20), (21), (24): the floor fires end-to-end at the
/// tight measured install funding, refuses BEFORE any management dispatch,
/// leaves every Layer-1 endpoint serving, consumes neither the caller's meter
/// nor §H′ allowance, and self-heals on `add_cycles`.
#[test]
fn g2_cycle_floor_refuses_before_charge_keeps_layer1_alive_and_self_heals() {
    let pic = PocketIcBuilder::new()
        .with_ii_subnet()
        .with_application_subnet()
        .with_nonmainnet_features(true)
        .build();
    let token_id = install_mock_token(&pic, mock_token_wasm(RICH_BALANCE_E8S));
    let vetkeys_id = pic.create_canister();
    // (19) §7.6: the tight measured funding — installs, but leaves liquid
    // balance far below the 500e9 floor.
    pic.add_cycles(vetkeys_id, MEASURED_MIN_INSTALL_CYCLES + 200_000_000);
    pic.install_canister(
        vetkeys_id,
        vetkeys_wasm(),
        candid::encode_args(("test_key_1".to_string(), Some(token_id))).unwrap(),
        None,
    );
    let h = Harness {
        pic,
        vetkeys_id,
        merkle_id: Principal::management_canister(), // unused in this arm
        pool: p(0x05),
        token_id,
    };

    let user = p(0xC7);

    // (19) + (24): SIX consecutive attempts — one more than the meter's hourly
    // allowance — must ALL refuse with the floor variant. If the refusal
    // charged the meter, the sixth would come back RateLimited instead; the
    // floor pre-check refuses about the CANISTER before any caller allowance
    // is touched. And the refusal must not dispatch: six refusals may not
    // burn even a visible fraction of one ~26B-cycle derive.
    let balance_before = h.cycles();
    for i in 0..6u8 {
        match h.try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(0x20 + i)) {
            Err(VetkeysError::CycleFloorReached { liquid_cycles, required_cycles }) => {
                let floor = candid::Nat::from(CYCLE_FLOOR);
                assert!(required_cycles >= floor, "required must include the full floor");
                assert!(liquid_cycles < required_cycles, "refusal implies liquid < required");
            }
            other => panic!("attempt {i}: expected CycleFloorReached, got {other:?}"),
        }
    }
    let spent_on_refusals = balance_before.saturating_sub(h.cycles());
    assert!(
        spent_on_refusals < 1_000_000_000,
        "six floor refusals burned {spent_on_refusals} cycles — a management dispatch \
         (~26B) would be visible here; the refusal must precede the charge"
    );

    // (21) DEGRADATION, NOT FREEZE — at (19)'s funding every Layer-1 endpoint
    // and the free verification key keep SERVING (answering, not trapping):
    // the only degradation bought is that new users cannot onboard, because
    // a Bootstrap registration needs a ticket only a completed derive mints.
    let vk: Vec<u8> = decode(
        "get_vetkey_verification_key",
        h.pic.update_call(
            h.vetkeys_id,
            user,
            "get_vetkey_verification_key",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert!(!vk.is_empty(), "the zero-cycle verification key must still be served");
    assert!(h.devices(user).is_empty(), "list_devices must answer below the floor");
    match h.wrapped_secret(user, "device-1") {
        Err(VetkeysError::UnknownDevice) => {}
        other => panic!("get_wrapped_secret must answer below the floor, got {other:?}"),
    }
    let dev = TestDevice::new("device-1", 0x77);
    match h.register(user, &dev, envelope(0x77), DeviceApproval::Bootstrap) {
        Err(VetkeysError::BootstrapNotAuthorized { .. }) => {} // no ticket yet — the stated trade
        other => panic!("register_device must answer below the floor, got {other:?}"),
    }
    match h.revoke(
        user,
        "device-1",
        SignedApproval {
            issuer_device_id: "device-1".to_string(),
            nonce: vec![0x11; 16],
            expiry_ns: u64::MAX,
            signature: vec![0x22; 64],
        },
    ) {
        Err(
            VetkeysError::ApprovalRejected(_)
            | VetkeysError::UnknownDevice
            | VetkeysError::RevocationRateExceeded { .. },
        ) => {}
        other => panic!("revoke_device must answer below the floor, got {other:?}"),
    }

    // (20) SELF-HEAL: fund above the floor (floor + price/burn headroom) and
    // the SAME principal derives — and `remaining == 4` proves the six floor
    // refusals consumed none of its §H′ allowance (the (24) other half).
    h.pic.add_cycles(h.vetkeys_id, 1_400_000_000_000);
    let reply = h
        .try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(0x2F))
        .expect("above the floor the same principal must derive");
    assert_eq!(
        reply.remaining, 4,
        "the floor refusals must not have consumed any of the caller's §H′ allowance"
    );

    // And the ticket that derive minted now authorizes the Bootstrap
    // registration the floor was blocking — onboarding resumes, no operator
    // action beyond the cycle top-up.
    h.register(user, &dev, envelope(0x77), DeviceApproval::Bootstrap)
        .expect("post-heal, the minted ticket must authorize the first device");
}

// ═════════════════════════════════════════════════════════════════════════════
// Brief V4 §9.1 — THE GENUINE PREDECESSOR: an over-capacity window migrates
// ═════════════════════════════════════════════════════════════════════════════

/// The predecessor binary, built from the annotated tag `vetkeys/pre-repin-v1`
/// (67dbc409) and authenticated by SHA-256 in `run_gate.sh` on EVERY run.
///
/// A current-source rebuild cannot substitute for it: this crate now admits
/// only 20 dispatches per window, so it physically cannot write the
/// over-capacity cell the arm below exists to read, and the >= 21 guard in that
/// arm fails first if anyone tries.
fn pre_repin_wasm() -> Vec<u8> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/wasm32-unknown-unknown/release/vetkeys_pre_repin_67dbc40_test.wasm"
    );
    std::fs::read(p).unwrap_or_else(|e| {
        panic!(
            "vetkeys_pre_repin_67dbc40_test.wasm not found ({e}) — this arm needs the GENUINE \
             predecessor, built from the tag, not from current source:\n  \
             git worktree add --detach /tmp/stsh-vetkeys-pre-repin vetkeys/pre-repin-v1 && \
             (cd /tmp/stsh-vetkeys-pre-repin && \
             CARGO_TARGET_DIR=/tmp/stsh-vetkeys-pre-repin/target cargo build --manifest-path \
             canisters/vetkeys/Cargo.toml --target wasm32-unknown-unknown --release --locked) && \
             cp /tmp/stsh-vetkeys-pre-repin/target/wasm32-unknown-unknown/release/\
stsh_vetkeys.wasm canisters/vetkeys/target/wasm32-unknown-unknown/release/\
vetkeys_pre_repin_67dbc40_test.wasm\n  expected sha256: \
             8ce934e8176160f01ca4b5df0e8b19b971d0cf4f3f90fa4c35be91f77e503f14"
        )
    })
}

/// §9.1(f)/(g) — THE MIGRATION UNDER TEST, against a real predecessor.
///
/// WHAT WOULD HAPPEN WITHOUT THE §3 SPLIT: the predecessor's stable window can
/// hold up to 100 timestamps. The candidate lowers admission to 20. If the byte
/// bound and the decode assertion were still derived from the budget — as they
/// were at 67dbc409 — decoding that cell would trap INSIDE `post_upgrade`, with
/// no way back, on the very upgrade that tightens the ceiling.
///
/// THE >= 21 BEHAVIOURAL GUARD (§9.1(f)) is the second, independent mechanism.
/// Every one of the 25 dispatches below must be ADMITTED by the installed
/// binary. A current-source build refuses the 21st by construction, so planting
/// one here fails this arm even if the gate's hash check were bypassed.
///
/// RETENTION IS PROVED BY BEHAVIOUR, not by a read surface (there is none, and
/// §8 forbids a DID delta): the two batches are separated in time, so
/// newest-20 retention and oldest-20 retention imply materially different
/// `retry_after_ns` values, and the assertion below distinguishes them.
#[test]
fn pic_genuine_predecessor_over_capacity_window_migrates() {
    let pic = PocketIcBuilder::new()
        .with_ii_subnet()
        .with_application_subnet()
        .with_nonmainnet_features(true)
        .build();
    let token_id = install_mock_token(&pic, mock_token_wasm(RICH_BALANCE_E8S));
    let vetkeys_id = pic.create_canister();
    pic.add_cycles(vetkeys_id, 1_000_000_000_000_000);
    // INSTALL THE PREDECESSOR — the binary whose budget is 100.
    pic.install_canister(
        vetkeys_id,
        pre_repin_wasm(),
        candid::encode_args(("test_key_1".to_string(), Some(token_id))).unwrap(),
        None,
    );
    let merkle_id = pic.create_canister();
    pic.add_cycles(merkle_id, 2_000_000_000_000);
    let pool = p(0x05);
    pic.install_canister(merkle_id, merkle_wasm(), candid::encode_one(pool).unwrap(), None);
    let h = Harness { pic, vetkeys_id, merkle_id, pool, token_id };

    // ── Batch A: 5 dispatches, early in the window ───────────────────────────
    for j in 0..5u8 {
        h.try_get_encrypted_vetkey_typed(p(0xD0), Harness::valid_transport_key(j))
            .unwrap_or_else(|e| panic!("batch A dispatch {j} refused by the predecessor: {e:?}"));
    }

    // THE FENCE PROBE, established here on purpose (V5 §6).
    //
    // The §6 age gate sits BEFORE the dispatch fence, so a never-seen principal
    // now hits the age refusal and never reaches the fleet budget — it would
    // stop probing the thing this arm exists to measure. Waiting T for it
    // instead would advance the clock by T and move the very batch
    // timings the retention direction is read from.
    //
    // So the probe earns its ESTABLISHED bit here, with ONE derive on the
    // predecessor. An established principal skips §D entirely (arm 31 —
    // recovery is byte-for-byte untouched), so after the upgrade it reaches the
    // fence with no clock movement at all. It also leaves 4 of its 5 §H′
    // derives, so §H′ cannot be what refuses it later.
    //
    // 26 stored dispatches rather than 25: still comfortably over the
    // candidate's budget of 20, which is the only property the migration needs,
    // and the retained newest-20 is still exactly batch B.
    let probe = p(0xDF);
    h.try_get_encrypted_vetkey_typed(probe, Harness::valid_transport_key(0x30))
        .expect("the probe's establishing derive must succeed on the predecessor");

    // ── 50 minutes later, batch B: 20 more dispatches ────────────────────────
    //
    // The gap is what makes retention DIRECTION observable: batch A expires 10
    // minutes after this point, batch B a full hour after it.
    h.pic.advance_time(std::time::Duration::from_secs(50 * 60));
    h.pic.tick();
    for i in 0..4u8 {
        for j in 0..5u8 {
            h.try_get_encrypted_vetkey_typed(
                p(0xD1 + i),
                Harness::valid_transport_key(0x40 + i * 5 + j),
            )
            .unwrap_or_else(|e| {
                panic!(
                    "batch B dispatch {j} of principal {i} refused ({e:?}).\n\
                     THE >= 21 GUARD (brief V4 §9.1(f)): the installed binary refused a \
                     dispatch past 20, which the GENUINE predecessor (budget 100) never does. \
                     A current-source build was almost certainly planted as the predecessor \
                     artifact — rebuild it from tag vetkeys/pre-repin-v1."
                )
            });
        }
    }
    // 26 dispatches stored, all inside one rolling hour: comfortably past the
    // candidate's budget of 20, which is the state the migration must survive.

    // ── THE UPGRADE ──────────────────────────────────────────────────────────
    //
    // On master's decode this traps and `upgrade_canister` returns Err.
    h.pic
        .upgrade_canister(
            h.vetkeys_id,
            vetkeys_wasm(),
            candid::encode_one(None::<Principal>).unwrap(),
            None,
        )
        .expect(
            "the upgrade TRAPPED — an over-capacity fleet window failed to decode under the \
             new budget. This is exactly the §3 defect: byte bound and decode assertion must \
             derive from GLOBAL_DERIVE_WINDOW_MAX_ENTRIES, not from GLOBAL_DERIVE_BUDGET.",
        );

    // ── Retention at B = 100 (LAUNCH-HARDEN-04 O-3) ──────────────────────────
    //
    // The Owner-ratified budget (RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24)
    // is 100 = GLOBAL_DERIVE_WINDOW_MAX_ENTRIES, so the decoder's newest-`budget`
    // truncation can no longer fire on any stored cell: the 26-entry predecessor
    // window must decode INTACT. What this arm still proves is the §3 defect's
    // closure — the upgrade from the GENUINE predecessor's over-20 window does
    // not trap (the `expect` above) — plus that every carried entry still counts
    // against fleet capacity and none is invented an owner. (The newest-N
    // truncation direction stays proven natively by
    // `state::tests::truncation_keeps_capacity_consumed_for_longer_not_shorter`,
    // which re-arms automatically if the budget is ever lowered below storage.)
    let migrated = h.derive_budget_stats();
    assert_eq!(migrated.budget, 100);
    assert_eq!(
        migrated.consumed, 26,
        "all 26 carried dispatches must survive the upgrade and still count — none dropped"
    );
    assert_eq!(
        migrated.tagged_consumed, 0,
        "a V1 carry is counted but NEVER attributed to a principal"
    );
    assert_eq!(migrated.retry_after_ns, 0, "26 of 100: the fleet is not full");

    // The fence is LIVE on the migrated window: the established probe (its own
    // predecessor dispatch is untagged, so it does not count against its
    // per-principal cap) is admitted and adds exactly one tagged dispatch.
    // RAW, not the age-in helper: `probe` is established, so it must reach the
    // fence with no retry and no clock movement.
    h.try_get_encrypted_vetkey_raw(probe, Harness::valid_transport_key(0xDF))
        .expect("26 of 100 consumed: the migrated fleet window must admit the probe");
    let after_probe = h.derive_budget_stats();
    assert_eq!(after_probe.consumed, 27);
    assert_eq!(after_probe.tagged_consumed, 1);

    // ── And the migrated state is LIVE, not merely decodable ─────────────────
    //
    // One window after batch B, the whole retained set expires and the probe
    // derives with no operator action. RAW again: an established principal must
    // still need no age-in on the recovery path.
    h.pic.advance_time(std::time::Duration::from_secs(3_601));
    h.pic.tick();
    let reply = h
        .try_get_encrypted_vetkey_raw(probe, Harness::valid_transport_key(0xE0))
        .expect("the rolled window must admit the probe after migration");
    assert!(!reply.encrypted_key.is_empty());
}

// ═════════════════════════════════════════════════════════════════════════════
// COMMIT-1 FREEZE PROBES (A1 fix brief V5 §7.3)
// ═════════════════════════════════════════════════════════════════════════════

/// **Arm 20 — the TARGET-PLATFORM probe (SSA RED-2, obligation 1).**
///
/// V5 requires the commit-1 probe to call the target platform and assert WHICH
/// variant comes back. It asserts `Live` EXACTLY and panics on anything else —
/// an exhaustive match that accepted every branch would prove representability
/// and nothing about this platform, and a mutation forcing `FloorOnly` could
/// stay green under it. `floor_view_from`'s unit arms carry the other two
/// branches and demonstrate what such a mutation produces; this arm is the half
/// that refuses it.
///
/// **THE VERDICT IS ESTABLISHED CAUSALLY, NOT ASSUMED.** `f1b` below runs the
/// identical query against a canister funded FAR BELOW the floor and requires
/// `Live { admits: false }`. The pair is the control: the same platform, the
/// same code path, opposite fixtures, opposite verdicts. Either arm alone could
/// pass on a constant.
///
/// `cycle_balance` is deliberately NOT used as the cross-check: it is the GROSS
/// balance, while this view reports the LIQUID position net of the freezing
/// reserve, so it cannot establish the floor predicate (SSA RED-1).
#[test]
fn f1_the_platform_returns_a_live_floor_reading_on_a_funded_canister() {
    let h = setup();
    let stats = h.derive_budget_stats();

    // The pins, regenerated here as literals rather than read from the reply.
    assert_eq!(stats.window_ns, 60 * 60 * 1_000_000_000, "the rolling window is one hour");
    assert_eq!(
        stats.budget, 100,
        "the Owner-ratified budget (RATIFICATION_HARDEN04_DERIVE_NUMBERS_2026-09-24)"
    );

    // setup() funds 1e15 cycles — four orders of magnitude above the 500e9
    // floor and the ~26e9 derive price together, so on this platform the
    // reading must be Live AND admitting.
    assert_eq!(
        stats.floor,
        CycleFloorView::Live { admits: true },
        "this platform prices vetKD, so the reading must be LIVE — and a canister funded to \
         1e15 must admit. Any other variant here is a platform change or a regression, and \
         either way it must fail rather than be absorbed by an exhaustive match."
    );

    // The epoch is live: `#[init]` set it, so it is not the default zero.
    assert!(stats.stats_epoch_ns > 0, "the counter epoch must be set at install");
}

/// **Arm 20's causal control (SSA RED-2) — the same query, a starved canister,
/// the opposite verdict.**
///
/// Funding is the G2 measurement: enough to install, far below the 500e9 floor.
/// `admits` must flip. Without this arm, `f1`'s `admits: true` could be
/// satisfied by a hardcoded `true`, and the probe would assert nothing about
/// the predicate it claims to report.
#[test]
fn f1b_a_starved_canister_reports_a_live_but_refusing_floor_reading() {
    let pic = PocketIcBuilder::new()
        .with_ii_subnet()
        .with_application_subnet()
        .with_nonmainnet_features(true)
        .build();
    let token_id = install_mock_token(&pic, mock_token_wasm(RICH_BALANCE_E8S));
    let vetkeys_id = pic.create_canister();
    // The G2 §7.6 tight measured funding: installs, but leaves the LIQUID
    // balance far below the floor.
    pic.add_cycles(vetkeys_id, MEASURED_MIN_INSTALL_CYCLES + 200_000_000);
    pic.install_canister(
        vetkeys_id,
        vetkeys_wasm(),
        candid::encode_args(("test_key_1".to_string(), Some(token_id))).unwrap(),
        None,
    );
    let merkle_id = pic.create_canister();
    pic.add_cycles(merkle_id, 2_000_000_000_000);
    let pool = p(0x05);
    pic.install_canister(merkle_id, merkle_wasm(), candid::encode_one(pool).unwrap(), None);
    let h = Harness { pic, vetkeys_id, merkle_id, pool, token_id };

    assert_eq!(
        h.derive_budget_stats().floor,
        CycleFloorView::Live { admits: false },
        "the price is still readable, so the reading stays LIVE — but a canister below the \
         floor must report that it does not admit"
    );

    // AND the query still answers rather than trapping. A monitor surface that
    // dies exactly when the canister is in trouble reports nothing at the only
    // moment it matters.
    let again = h.derive_budget_stats();
    assert_eq!(again.consumed, 0, "no dispatch was charged by a refused floor");
    assert!(again.stats_epoch_ns > 0);
}

/// The freeze's shape, end to end through a REAL client decode.
///
/// Every field of `DeriveBudgetStats` is exercised as a decoded value on a
/// freshly installed canister, so a field the DID and the canister disagree
/// about fails here rather than at first operational use. The counters that
/// §6 will drive are asserted at their INSTALL values — this commit deliberately
/// lands the shape ahead of the behaviour that moves them.
#[test]
fn f2_the_stats_surface_decodes_completely_on_a_fresh_canister() {
    let h = setup();
    let stats = h.derive_budget_stats();

    assert_eq!(stats.consumed, 0, "a fresh canister has dispatched nothing");
    assert_eq!(stats.tagged_consumed, 0);
    assert_eq!(stats.distinct_principals, 0);
    assert_eq!(stats.max_by_one_principal, 0);
    assert_eq!(stats.first_derive_dispatches, 0);
    assert_eq!(stats.retry_after_ns, 0, "an empty window admits, so the retry hint is zero");
    assert_eq!(stats.refusals_budget_total, 0);
    // §6.7 rows: the structures exist and read empty; the counters that fill
    // them are wired by the §6 admission commit.
    assert_eq!(stats.sightings_pending, 0, "MemoryId 15 is live and empty");
    assert_eq!(stats.sightings_recorded_total, 0);
    assert_eq!(stats.age_refusals_total, 0);

    // The query is genuinely READ-ONLY: calling it repeatedly cannot move the
    // window, the counters, or the epoch. A query that pruned the stored cell
    // would be a free way to move fleet capacity.
    let again = h.derive_budget_stats();
    assert_eq!(stats.consumed, again.consumed);
    assert_eq!(stats.stats_epoch_ns, again.stats_epoch_ns);
    assert_eq!(stats.refusals_budget_total, again.refusals_budget_total);
    assert_eq!(stats.sightings_pending, again.sightings_pending);
}

/// The V2 tagged window ATTRIBUTES a real dispatch, and survives a real
/// upgrade with its attribution intact.
///
/// This is the MemoryId-14 half of the freeze proved behaviourally rather than
/// by round-tripping bytes in a unit test: a first-ever derive by a known
/// principal must show up as one tagged, first-derive dispatch by one distinct
/// principal — and an upgrade must not turn it back into an anonymous count.
#[test]
fn f3_the_v2_window_attributes_a_real_dispatch_and_survives_upgrade() {
    let h = setup();
    let user = p(0x41);

    let before = h.derive_budget_stats();
    assert_eq!(before.tagged_consumed, 0);

    h.derive_past_the_meter(user, 0xE1).expect("a funded first derive must succeed");

    let after = h.derive_budget_stats();
    assert_eq!(after.consumed, 1, "exactly one dispatch was charged");
    assert_eq!(after.tagged_consumed, 1, "and it carries attribution — the V2 layout");
    assert_eq!(after.distinct_principals, 1);
    assert_eq!(after.max_by_one_principal, 1);
    assert_eq!(
        after.first_derive_dispatches, 1,
        "a principal with no ESTABLISHED bit is a FIRST derive, and the tag must say so"
    );

    // A REAL upgrade. The window is stable, so both the charge AND its
    // attribution must come back — an upgrade that dropped the tag would
    // silently degrade every attributed field to the untagged carry.
    h.pic.upgrade_canister(
        h.vetkeys_id,
        vetkeys_wasm(),
        candid::encode_args((None::<Principal>,)).unwrap(),
        None,
    )
    .expect("upgrade");

    let post = h.derive_budget_stats();
    assert_eq!(post.consumed, 1, "the stable window survives the upgrade");
    assert_eq!(post.tagged_consumed, 1, "and so does its attribution");
    assert_eq!(post.distinct_principals, 1);
    assert_eq!(post.first_derive_dispatches, 1);
    // The ephemeral counters are heap, so the upgrade DOES reset them — and the
    // epoch is what makes that visible rather than silent.
    assert!(
        post.stats_epoch_ns > before.stats_epoch_ns,
        "an upgrade must start a NEW counter epoch, or a consumer would read the reset as a \
         rate falling to zero"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// §6 — HELD-BALANCE-AGE ADMISSION (A1 fix brief V5 §8.2, arms 30–35)
// ═════════════════════════════════════════════════════════════════════════════
//
// These are the CROSS-WASM half. The state-machine properties — the K-bounded
// prune, the cap arms, both-or-neither, retention at the shipped value — are
// driven natively in `sightings::tests` over the SAME stable structures, which
// is the crate's established technique for the MemoryId-13 pair and the only
// way a 10,000-row table is reachable at a sensible cost. What native cannot
// prove is durability across a genuine upgrade and behaviour through the real
// endpoint, and that is exactly what is here.

/// **Arm 30 — the gate, end to end.**
///
/// A first-ever derive is refused with the typed variant and DISPATCHES
/// NOTHING; after T the same principal derives; the row is then gone from BOTH
/// structures and `ESTABLISHED` is set.
#[test]
fn s30_the_age_gate_refuses_a_first_derive_then_admits_at_t_and_clears_the_row() {
    let h = setup();
    let user = p(0x51);

    assert_eq!(h.derive_budget_stats().sightings_pending, 0, "no rows before the first call");

    // (1) The first attempt records a sighting and REFUSES with exactly T.
    let refusal = h.try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x51));
    match refusal {
        Err(VetkeysError::EligibilityAgeNotMet { retry_after_ns }) => {
            assert_eq!(
                retry_after_ns, ELIGIBILITY_MIN_AGE_NS,
                "a first sighting must quote the FULL wait — this is not a resumed countdown"
            );
        }
        other => panic!("a first-ever derive must be age-refused; got {other:?}"),
    }
    let after_first = h.derive_budget_stats();
    assert_eq!(after_first.sightings_pending, 1, "the sighting was recorded");
    assert_eq!(after_first.sightings_recorded_total, 1);
    assert_eq!(after_first.age_refusals_total, 1);

    // (2) NOTHING WAS DISPATCHED. The refusal happens before the fence, so it
    // cannot have consumed fleet capacity — checked on the fleet counter
    // itself, not inferred from the reply.
    assert_eq!(after_first.consumed, 0, "an age refusal must dispatch nothing");
    assert_eq!(after_first.first_derive_dispatches, 0);

    // (3) PART of the way there still refuses — and the row is NOT rewritten
    // by the attempt, so the wait continues from the original sighting rather
    // than resetting on every poll.
    //
    // HALF of T, not one ns short, and the reason is a harness limit stated
    // plainly: PocketIC advances its clock in rounds, and every ingress message
    // moves it, so a single-nanosecond boundary is not expressible here. The
    // EXACT boundary — `T-1` refuses, `T` admits, and a call at
    // `now + retry_after_ns` is admitted while one ns earlier is not — is
    // proved in `sightings::tests::age_boundary_triple_refuses_below_t_and_admits_at_and_above`
    // and `…::retry_after_is_exact_from_both_sides`, which are pure and can
    // express it. This arm proves the END-TO-END shape; it does not restate a
    // precision it cannot observe.
    h.pic.advance_time(std::time::Duration::from_nanos(ELIGIBILITY_MIN_AGE_NS / 2));
    h.pic.tick();
    match h.try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x52)) {
        Err(VetkeysError::EligibilityAgeNotMet { retry_after_ns }) => {
            assert!(
                retry_after_ns < ELIGIBILITY_MIN_AGE_NS,
                "the quoted wait must COUNT DOWN from the original sighting ({retry_after_ns}                  vs the full {ELIGIBILITY_MIN_AGE_NS}) — a repeat attempt that restarted the                  clock would quote the full T again"
            );
        }
        other => panic!("half way to T must still refuse; got {other:?}"),
    }
    assert_eq!(
        h.derive_budget_stats().sightings_recorded_total,
        1,
        "a repeat attempt on a valid row begins no new age-in period"
    );

    // (4) At T it derives.
    h.pic.advance_time(std::time::Duration::from_nanos(ELIGIBILITY_MIN_AGE_NS / 2));
    h.pic.tick();
    let reply = h
        .try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x53))
        .expect("at T the same principal must derive");
    assert!(!reply.encrypted_key.is_empty());

    // (5) The row is GONE from the primary, and the dispatch was attributed as
    // a FIRST derive.
    let after = h.derive_budget_stats();
    assert_eq!(after.sightings_pending, 0, "a finalized derive deletes the row");
    assert_eq!(after.consumed, 1);
    assert_eq!(after.first_derive_dispatches, 1);

    // (6) AND from the INDEX. Proved through the shipped path rather than by a
    // query that does not exist: `clear_on_success` traps on an orphaned index
    // row, and it runs again on this second (now established) derive. A
    // surviving index row would abort this call.
    h.skip_the_meter_window();
    h.try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x54))
        .expect("an established principal re-derives — and would TRAP here on an index orphan");
    assert_eq!(h.derive_budget_stats().sightings_pending, 0);
}

/// **Arm 31 — RECOVERY IS BYTE-FOR-BYTE UNTOUCHED.**
///
/// An established principal performs NO sighting write, NO age test and NO
/// balance query. The last one is proved CAUSALLY: after establishing, the
/// canister is reconfigured to a token that reports a balance BELOW the floor.
/// If any balance query still ran on this path, the derive would come back
/// `PrincipalNotEligible`. It does not.
#[test]
fn s31_an_established_principal_derives_with_no_row_no_age_test_and_no_balance_query() {
    let h = setup();
    let user = p(0x61);

    h.age_in_all(&[user]);
    h.try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x61))
        .expect("the establishing derive");
    assert_eq!(h.derive_budget_stats().sightings_pending, 0, "no row survives a success");

    // Repoint §D at a POOR token — below the 0.1 STSH floor.
    let poor = install_mock_token(&h.pic, mock_token_wasm(1));
    h.upgrade_with(Some(poor));
    h.skip_the_meter_window();

    // NO age-in helper, NO retry: an established principal must be admitted on
    // the first call, immediately.
    let reply = h
        .try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x62))
        .expect(
            "recovery must not consult the balance or the age gate — a refusal here means the \
             §6 test escaped the `!established` branch, which is the property that killed \
             option C",
        );
    assert!(!reply.encrypted_key.is_empty());
    assert_eq!(
        h.derive_budget_stats().sightings_pending,
        0,
        "and recovery must not WRITE a sighting either"
    );

    // NON-VACUITY: the poor token really would refuse a principal that has to
    // ask. A never-seen principal on the same canister is turned away.
    match h.try_get_encrypted_vetkey_raw(p(0x63), Harness::valid_transport_key(0x63)) {
        Err(VetkeysError::PrincipalNotEligible(_)) => {}
        other => panic!("the poor token must refuse a NON-established principal; got {other:?}"),
    }
}

/// **Arm 33 — an age refusal RELEASES §H′ and costs the caller no allowance.**
///
/// `remaining` is reported from §H′ only, so a successful derive after several
/// age refusals must still report a full window minus exactly one.
#[test]
fn s33_age_refusals_do_not_consume_the_callers_24h_allowance() {
    let h = setup();
    let user = p(0x71);

    // Three age refusals, spread so the A-2 meter (5/hour) is not what stops
    // us — the meter is a different control and would confuse the reading.
    for i in 0..3u8 {
        assert!(matches!(
            h.try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x70 + i)),
            Err(VetkeysError::EligibilityAgeNotMet { .. })
        ));
    }
    assert_eq!(h.derive_budget_stats().age_refusals_total, 3);
    // Only the FIRST began an age-in period; the other two found a valid row.
    assert_eq!(
        h.derive_budget_stats().sightings_recorded_total,
        1,
        "a repeat refusal on an existing valid row begins nothing and must not be counted"
    );

    h.pic.advance_time(std::time::Duration::from_nanos(ELIGIBILITY_MIN_AGE_NS));
    h.skip_the_meter_window();
    let reply = h
        .try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x7F))
        .expect("after T the derive succeeds");

    // 5 per rolling 24 h; exactly ONE has been charged — the successful derive.
    assert_eq!(
        reply.remaining,
        (DERIVE_QUOTA - 1) as u8,
        "three age refusals must have released their §H′ reservations; a `remaining` below \
         this means a refused call kept its slot"
    );
}

/// **Arm 34 — DURABILITY: a waiting user's clock is not restarted by an
/// upgrade.**
///
/// The rows are stable, so the sighting recorded before the upgrade must still
/// be the one being aged after it. If either map were heap, the post-upgrade
/// call would be a fresh first sighting and would refuse again — which is the
/// failure this arm exists to catch, and it is exactly the failure a native
/// test cannot see.
#[test]
fn s34_sighting_rows_survive_a_real_upgrade_without_restarting_the_clock() {
    let h = setup();
    let user = p(0x81);

    assert!(matches!(
        h.try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x81)),
        Err(VetkeysError::EligibilityAgeNotMet { .. })
    ));
    assert_eq!(h.derive_budget_stats().sightings_pending, 1);

    // A REAL upgrade, mid-wait.
    h.pic.advance_time(std::time::Duration::from_nanos(ELIGIBILITY_MIN_AGE_NS / 2));
    h.pic.tick();
    h.upgrade_with(None);
    assert_eq!(
        h.derive_budget_stats().sightings_pending,
        1,
        "the row must survive the upgrade — losing it restarts an honest user's clock"
    );

    // The REMAINING half of the wait, measured from the ORIGINAL sighting. If
    // the upgrade had restarted the clock this would still be short.
    h.pic.advance_time(std::time::Duration::from_nanos(ELIGIBILITY_MIN_AGE_NS / 2));
    h.skip_the_meter_window();
    let reply = h
        .try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x82))
        .expect(
            "the wait must resume across the upgrade, not restart — a refusal here means the \
             sighting was heap-backed",
        );
    assert!(!reply.encrypted_key.is_empty());
    assert_eq!(h.derive_budget_stats().sightings_pending, 0);
}

/// **Arm 35 — THE HONESTY ARM. Expected to PASS, and it must not be "fixed".**
///
/// The gate is NOT a float-multiplication defence. Under two-point sampling
/// with a hard-coded ZERO ledger fee, one 0.1 STSH float can satisfy any number
/// of principals: it visits each at *t* (n free transfers, n sightings) and
/// again at *t + T* (n more free transfers), and all of them derive. This arm
/// runs that shape for five principals and asserts they ALL succeed.
///
/// WHAT THE FIXTURE DOES AND DOES NOT MODEL, stated rather than implied: the
/// mock ledger answers at-or-above-floor for every principal, which is the
/// OBSERVABLE this canister has — it makes exactly one `icrc1_balance_of` per
/// principal and can never see the transfers between them. That is the whole
/// point: two-point sampling proves the balance was at the floor at two
/// instants, NEVER that it was held continuously, and no fixture can make this
/// canister see a difference the protocol does not give it.
///
/// So what the gate delivers is pre-funding visibility, cold-start burst
/// damping and re-tooling latency — not a capital requirement. The 100/h budget
/// remains the wall. **A change that made this arm fail would be a change that
/// claims a defence the design does not have.**
#[test]
fn s35_one_float_satisfies_five_principals_the_gate_is_not_a_capital_requirement() {
    let h = setup();
    let cohort: Vec<Principal> = (0..5u8).map(|i| p(0x90 + i)).collect();

    // t: every principal is sighted. Five refusals, five rows.
    for (i, u) in cohort.iter().enumerate() {
        assert!(
            matches!(
                h.try_get_encrypted_vetkey_raw(*u, Harness::valid_transport_key(0x90 + i as u8)),
                Err(VetkeysError::EligibilityAgeNotMet { .. })
            ),
            "principal {i} must be sighted and refused at t"
        );
    }
    let at_t = h.derive_budget_stats();
    assert_eq!(at_t.sightings_pending, 5);
    assert_eq!(at_t.sightings_recorded_total, 5, "the FUNDING WAVE is visible T ahead");

    // t + T: all five derive. One float, five keys.
    h.pic.advance_time(std::time::Duration::from_nanos(ELIGIBILITY_MIN_AGE_NS));
    h.skip_the_meter_window();
    for (i, u) in cohort.iter().enumerate() {
        h.try_get_encrypted_vetkey_raw(*u, Harness::valid_transport_key(0xA0 + i as u8))
            .unwrap_or_else(|e| {
                panic!(
                    "principal {i} was refused ({e:?}). ARM 35 IS EXPECTED TO PASS: it states \
                     the ruled TRUE claim that the age gate is not a float-multiplication \
                     defence. If this now fails, the change did not strengthen the gate — it \
                     made the documentation false. Do not 'fix' this arm."
                )
            });
    }

    let after = h.derive_budget_stats();
    assert_eq!(after.sightings_pending, 0, "all five rows cleared by their derives");
    assert_eq!(after.first_derive_dispatches, 5, "five FIRST derives, from one float");
    assert_eq!(after.distinct_principals, 5);
}

// ═════════════════════════════════════════════════════════════════════════════
// §3 OBSERVABILITY — the V3 arms, re-driven at B = 100 (LAUNCH-HARDEN-04 O-3)
// ═════════════════════════════════════════════════════════════════════════════

/// **Arms 9–11 — the attribution fields are CAUSAL, checked against a driving
/// plan that is never read back from the reply.**
///
/// The plan is written here: fifty principals, two derives each (the
/// per-principal hourly cap, LAUNCH-HARDEN-04 O-3), filling the fleet to
/// exactly 100. Every expectation below is computed from THAT plan — `50`
/// distinct, `2` max, `100` tagged — and not from the numbers the canister
/// returns. An arm that derived its expectations from the reply would agree
/// with any implementation, including a broken one.
#[test]
fn s9_the_stats_attribute_a_driven_plan_and_saturate_at_one_hundred_via_fifty_by_two() {
    let h = setup();
    // THE PLAN, stated first and in full.
    const PRINCIPALS: usize = 50;
    const DERIVES_EACH: usize = 2;
    let cohort: Vec<Principal> = (0..PRINCIPALS).map(|i| {
        let mut b = [0u8; 29];
        b[0] = 0xB0;
        b[1] = i as u8;
        Principal::from_slice(&b)
    }).collect();

    h.age_in_all(&cohort);
    h.skip_the_meter_window();

    for (i, u) in cohort.iter().enumerate() {
        for j in 0..DERIVES_EACH {
            h.try_get_encrypted_vetkey_raw(*u, Harness::valid_transport_key((i * 8 + j) as u8))
                .unwrap_or_else(|e| panic!("plan derive {j} of principal {i} refused: {e:?}"));
        }
    }

    let stats = h.derive_budget_stats();
    assert_eq!(stats.consumed, (PRINCIPALS * DERIVES_EACH) as u32, "100 dispatches, from the plan");
    assert_eq!(stats.tagged_consumed, stats.consumed, "every dispatch this release makes is tagged");
    assert_eq!(stats.distinct_principals, PRINCIPALS as u32);
    assert_eq!(stats.max_by_one_principal, DERIVES_EACH as u32);
    // Exactly one FIRST derive per principal — the rest are re-derives by an
    // already-established principal.
    assert_eq!(stats.first_derive_dispatches, PRINCIPALS as u32);

    // SATURATED: the budget is spent, and the retry hint is inside one window.
    assert_eq!(stats.budget, 100);
    assert!(stats.retry_after_ns > 0, "a full window must say when a slot frees");
    assert!(stats.retry_after_ns <= stats.window_ns);

    // ── Arm 12 — the FLEET refusal moves its counter, and ONLY its counter ──
    let before = stats.refusals_budget_total;
    let fresh = p(0xBF);
    h.age_in_all(&[fresh]);
    match h.try_get_encrypted_vetkey_raw(fresh, Harness::valid_transport_key(0xBF)) {
        Err(VetkeysError::GlobalDerivationBudgetExceeded { .. }) => {}
        other => panic!("a 101st dispatch must hit the FLEET budget; got {other:?}"),
    }
    let after = h.derive_budget_stats();
    assert_eq!(
        after.refusals_budget_total,
        before + 1,
        "the fleet-budget limb, and only it, moves this counter"
    );
    // AND THE REFUSAL WROTE NOTHING DURABLE to the window: capacity is unchanged.
    assert_eq!(after.consumed, stats.consumed, "a refusal must not consume fleet capacity");

    // ── Arm 13 — the query is OBSERVE-ONLY ─────────────────────────────────
    //
    // Repeated reads cannot move any field. A query that pruned the stored
    // window would be a free way to move the wall.
    let a = h.derive_budget_stats();
    let b = h.derive_budget_stats();
    assert_eq!(a, b, "reading the surface must not change it");

    // ── Arm 14 — the window SELF-CLEARS, with no operator action ───────────
    h.pic.advance_time(std::time::Duration::from_secs(3_601));
    h.pic.tick();
    let rolled = h.derive_budget_stats();
    assert_eq!(rolled.consumed, 0, "one window later the fleet capacity is free again");
    assert_eq!(rolled.tagged_consumed, 0);
    assert_eq!(rolled.distinct_principals, 0);
    assert_eq!(rolled.max_by_one_principal, 0);
    assert_eq!(rolled.retry_after_ns, 0, "an empty window admits");
}

/// **Arm 15 — a REAL upgrade: the stable window survives, the ephemeral
/// counters reset, and the epoch says which is which.**
///
/// The two halves are deliberately opposite, and the epoch is what makes the
/// reset legible rather than silent — a consumer differencing across it would
/// otherwise read the restart as a rate falling to zero.
#[test]
fn s10_an_upgrade_keeps_the_window_resets_the_counters_and_advances_the_epoch() {
    let h = setup();
    let user = p(0xC5);
    h.age_in_all(&[user]);
    h.try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0xC5))
        .expect("one real dispatch");

    let before = h.derive_budget_stats();
    assert_eq!(before.consumed, 1);
    assert!(before.age_refusals_total > 0, "the age-in produced a refusal to count");

    h.upgrade_with(None);
    let after = h.derive_budget_stats();

    // STABLE: an upgrade must not hand the fleet a free allowance.
    assert_eq!(after.consumed, 1, "the window is stable");
    assert_eq!(after.tagged_consumed, 1, "and keeps its attribution");
    // EPHEMERAL: heap counters genuinely reset — that is the A-2 meter
    // precedent, and it is why no refusal path may write stably.
    assert_eq!(after.refusals_budget_total, 0);
    assert_eq!(after.age_refusals_total, 0);
    assert_eq!(after.sightings_recorded_total, 0);
    // And the epoch moved, so the reset is observable rather than silent.
    assert!(after.stats_epoch_ns > before.stats_epoch_ns);
}

/// **The advisory pre-check is NOT counted.**
///
/// Refusals that never reach the fence — a below-floor principal and a
/// malformed transport key — must leave `refusals_budget_total` untouched.
/// Folding them in would make the refusal-spike rule fire on conditions it does
/// not describe, which is the whole reason that counter has one writer.
#[test]
fn s11_refusals_that_never_reach_the_fence_are_not_counted_as_budget_refusals() {
    let h = setup_with_token(Some(mock_token_wasm(1))); // below the floor
    let before = h.derive_budget_stats().refusals_budget_total;

    match h.try_get_encrypted_vetkey_raw(p(0xD5), Harness::valid_transport_key(0xD5)) {
        Err(VetkeysError::PrincipalNotEligible(_)) => {}
        other => panic!("expected PrincipalNotEligible, got {other:?}"),
    }
    match h.try_get_encrypted_vetkey_raw(p(0xD6), INVALID_TRANSPORT_KEY.to_vec()) {
        Err(VetkeysError::InvalidTransportKey(_)) => {}
        other => panic!("expected InvalidTransportKey, got {other:?}"),
    }

    let after = h.derive_budget_stats();
    assert_eq!(
        after.refusals_budget_total, before,
        "only the fleet-budget limb may move this counter"
    );
    assert_eq!(after.consumed, 0, "and neither refusal consumed fleet capacity");
    assert_eq!(
        after.sightings_pending, 0,
        "a below-floor principal writes NO sighting — it has no age to accumulate"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// C-3 — REFUSED-CALL CYCLE CEILING (remediation lane R-L, campaign §5 G-b)
// ─────────────────────────────────────────────────────────────────────────────
//
// `get_encrypted_vetkey`'s cycle-floor refusal is the exemplar UMC-01 names: an
// endpoint whose ACCEPTED path spends ~26B cycles on a management dispatch, and
// whose refusal is asserted (above, in g2) only to be "less than 1B for six".
// That is a bound on the class, not on the endpoint, and it lives in the test
// as a literal chosen by the test's own author.
//
// This asserts the same refusal against a ceiling held OUTSIDE the code, in
// scripts/gate_lints/refused_call_ceilings.toml, pinned by the R-L builder at
// `ceil_100k(max + 3 x spread)` and reviewed as data. The test reads that file; it never reads
// a constant from this crate (brief §4 invariant 2 — a ceiling taken from the
// artifact it checks proves nothing).
//
// vetkeys is WORKSPACE-EXCLUDED, so this test runs ONLY under run_gate.sh's
// separate `--manifest-path canisters/vetkeys/Cargo.toml` invocation. A green
// workspace run says nothing about it.

#[derive(Debug, serde::Deserialize)]
struct CeilingRegistryFile {
    row: Vec<CeilingRowFile>,
}

#[derive(Debug, serde::Deserialize, Clone)]
struct CeilingRowFile {
    id: String,
    ceiling_cycles: u64,
    measured_cycles: u64,
}

fn ceiling_row(id: &str) -> CeilingRowFile {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("scripts/gate_lints/refused_call_ceilings.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "REQUIRED REGISTRY MISSING: {} ({e}).\n  \
             The refused-call ceilings are DATA, reviewed as data; this test \
             deliberately has no fallback value.",
            path.display()
        )
    });
    let reg: CeilingRegistryFile =
        toml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    reg.row
        .into_iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no [[row]] with id = \"{id}\" in {}", path.display()))
}

/// R-5 (L04-02) AC-4 — `get_vetkey_verification_key` makes exactly ONE
/// management-canister call across N calls, and serves the same key each time.
///
/// The raw blob is compared, not the deserialized `DerivedPublicKey`, so the
/// arm pins the bytes the cache actually stores and serves.
#[test]
fn verification_key_cached_after_first_call() {
    let h = setup();
    let user = p(0xA1);

    let mut keys: Vec<Vec<u8>> = Vec::new();
    for _ in 0..5 {
        let bytes: Vec<u8> = decode(
            "get_vetkey_verification_key",
            h.pic.update_call(
                h.vetkeys_id,
                user,
                "get_vetkey_verification_key",
                candid::encode_args(()).unwrap(),
            ),
        );
        assert!(!bytes.is_empty(), "the verification key must never come back empty");
        keys.push(bytes);
    }
    assert!(
        keys.windows(2).all(|w| w[0] == w[1]),
        "every call must serve byte-identical key material"
    );
    // Still a real key, not a cached artefact of the harness.
    DerivedPublicKey::deserialize(&keys[0]).expect("valid canister-scoped vetKD public key");

    assert_eq!(
        h.derive_budget_stats().verification_key_management_calls_total,
        1,
        "exactly ONE management-canister round trip across five calls — the other four \
         must be served from the MemoryId 18 cache"
    );
}

/// R-5 (L04-02) AC-5 — `refresh_vetkey_verification_key_cache` is
/// controller-only against the REAL controller API, and actually re-fetches.
///
/// `setup()` installs with `sender: None`, so the anonymous principal is the
/// canister's controller; the arm then hands control to a named principal via
/// `PocketIc::set_controllers` and checks both directions.
///
/// A non-controller TRAPS, which surfaces as a REJECTED call at the PocketIC
/// boundary rather than a decodable `Err` — so this leg inspects the raw
/// `update_call` result and never goes through `decode`, which would panic and
/// abort the test instead of letting it assert.
#[test]
fn refresh_cache_is_controller_only_and_refetches() {
    let h = setup();
    let controller = p(0xC0);
    h.pic
        .set_controllers(h.vetkeys_id, None, vec![controller])
        .expect("the anonymous installer is the current controller");
    h.pic.tick();

    // Prime the cache: one management call.
    let _: Vec<u8> = decode(
        "get_vetkey_verification_key",
        h.pic.update_call(
            h.vetkeys_id,
            p(0xA1),
            "get_vetkey_verification_key",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert_eq!(h.derive_budget_stats().verification_key_management_calls_total, 1);

    // (i) a NON-controller must be refused.
    let refused = h.pic.update_call(
        h.vetkeys_id,
        p(0xBB),
        "refresh_vetkey_verification_key_cache",
        candid::encode_args(()).unwrap(),
    );
    assert!(
        refused.is_err(),
        "a non-controller must be refused by refresh_vetkey_verification_key_cache, got {refused:?}"
    );
    assert_eq!(
        h.derive_budget_stats().verification_key_management_calls_total, 1,
        "a refused refresh must not have made a management call"
    );

    // (ii) the CONTROLLER forces a real re-fetch.
    let refreshed: Vec<u8> = decode(
        "refresh_vetkey_verification_key_cache",
        h.pic.update_call(
            h.vetkeys_id,
            controller,
            "refresh_vetkey_verification_key_cache",
            candid::encode_args(()).unwrap(),
        ),
    );
    assert!(!refreshed.is_empty(), "the refresh must return real key material");
    assert_eq!(
        h.derive_budget_stats().verification_key_management_calls_total, 2,
        "the controller refresh must make a SECOND management call — the counter, not the \
         returned bytes, is what proves a re-fetch happened (the key never rotates here)"
    );
}

/// C-3b — the INVALID-TRANSPORT-KEY refusal on `get_encrypted_vetkey`.
///
/// A DISTINCT refusal branch from C-3's cycle-floor refusal on the same
/// endpoint, measured and pinned on its OWN five samples rather than reusing
/// or re-deriving C-3's row (CTO_RULING_RL_REFUSED_CEILING_PIN_2026-09-05).
///
/// Fixture is `setup()`'s RICH funding, deliberately NOT C-3's tight-floor
/// fixture: this branch must refuse on the transport key, and each sample
/// asserts `InvalidTransportKey` (not `CycleFloorReached`) to prove the floor
/// did not engage and the measurement is of the intended path.
///
/// `MAX_DERIVATIONS_PER_WINDOW` does not bound these five samples: since R-5
/// (L04-01) a malformed key never reaches `meter_admit`, so consecutive
/// garbage-key calls from one principal cannot become a `RateLimited` that
/// would corrupt the measurement.
#[test]
fn ceiling_c3b_vetkeys_invalid_transport_key_refusal() {
    let h = setup();
    let user = p(0xCB);

    let mut samples: Vec<u64> = Vec::new();
    for _ in 0..5u8 {
        let before = h.cycles();
        match h.try_get_encrypted_vetkey_raw(user, INVALID_TRANSPORT_KEY.to_vec()) {
            Err(VetkeysError::InvalidTransportKey(_)) => {}
            other => panic!(
                "this test measures the INVALID-TRANSPORT-KEY refusal; got {other:?}, so the \
                 measurement is of the wrong path"
            ),
        }
        samples.push(before.saturating_sub(h.cycles()) as u64);
    }

    let row = ceiling_row("C-3b-vetkeys-invalid-transport-key");
    let max = *samples.iter().max().expect("five samples");
    let min = *samples.iter().min().expect("five samples");
    assert!(
        max <= row.ceiling_cycles,
        "REFUSED-CALL CEILING EXCEEDED for `get_encrypted_vetkey` (invalid transport key).\n  \
         samples (cycles): {samples:?}\n  min {min}, max {max}\n  \
         ceiling {} = ceil_100k(max + 3 x spread), pinned from a max sample of {} in \
         scripts/gate_lints/refused_call_ceilings.toml\n  \
         This branch stops before METER/with_admission/preflight are entered; a refusal \
         that costs more than that is not a defence.",
        row.ceiling_cycles, row.measured_cycles
    );
    println!(
        "[ceiling] C-3b-vetkeys-invalid-transport-key: samples {samples:?} min {min} max {max} \
         <= ceiling {}",
        row.ceiling_cycles
    );
}

#[test]
fn ceiling_c3_vetkeys_derive_refusal() {
    let pic = PocketIcBuilder::new()
        .with_ii_subnet()
        .with_application_subnet()
        .with_nonmainnet_features(true)
        .build();
    let token_id = install_mock_token(&pic, mock_token_wasm(RICH_BALANCE_E8S));
    let vetkeys_id = pic.create_canister();
    // The same tight measured funding g2 uses: installs, but leaves the liquid
    // balance far below the derive floor, so every derive refuses.
    pic.add_cycles(vetkeys_id, MEASURED_MIN_INSTALL_CYCLES + 200_000_000);
    pic.install_canister(
        vetkeys_id,
        vetkeys_wasm(),
        candid::encode_args(("test_key_1".to_string(), Some(token_id))).unwrap(),
        None,
    );
    let h = Harness {
        pic,
        vetkeys_id,
        merkle_id: Principal::management_canister(),
        pool: p(0x05),
        token_id,
    };
    let user = p(0xC9);

    // Five samples, each one refused call. Cycle deltas are noisy; the pin is
    // `ceil_100k(max + 3 x spread)` -- derived from the measurement's own noise,
    // never a multiplier on a baseline that is mostly fixed per-message overhead
    // (CTO_RULING_RL_REFUSED_CEILING_PIN_2026-09-05). Spread goes in the packet.
    let mut samples: Vec<u64> = Vec::new();
    for i in 0..5u8 {
        let before = h.cycles();
        match h.try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(0x40 + i)) {
            Err(VetkeysError::CycleFloorReached { .. }) => {}
            other => panic!(
                "sample {i}: this test measures the REFUSED path; got {other:?}, so the \
                 floor did not engage and the measurement is of the wrong path"
            ),
        }
        samples.push(before.saturating_sub(h.cycles()) as u64);
    }

    let row = ceiling_row("C-3-vetkeys-get-encrypted-vetkey");
    let max = *samples.iter().max().expect("five samples");
    let min = *samples.iter().min().expect("five samples");
    assert!(
        max <= row.ceiling_cycles,
        "REFUSED-CALL CEILING EXCEEDED for `get_encrypted_vetkey`.\n  \
         samples (cycles): {samples:?}\n  min {min}, max {max}\n  \
         ceiling {} = ceil_100k(max + 3 x spread), pinned from a max sample of {} in \
         scripts/gate_lints/refused_call_ceilings.toml\n  \
         A floor refusal that costs this much is not a defence — it is a cheaper \
         attack than the ~26B-cycle derive it refuses.",
        row.ceiling_cycles, row.measured_cycles
    );
    println!(
        "[ceiling] C-3-vetkeys-get-encrypted-vetkey: samples {samples:?} max {max} <= ceiling {}",
        row.ceiling_cycles
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// L04-07 — a revocation to ZERO devices is not undone by simply re-bootstrapping
// ═════════════════════════════════════════════════════════════════════════════
//
// THE HOLE. Revocation RETAINS the `DeviceRecord` and only flips its status, so
// a principal that has revoked its way to zero ACTIVE devices looks, to a
// device COUNT, exactly like one that never enrolled. A bootstrap ticket is the
// capability to enrol a device with NO existing device's signature. Handing one
// out on an empty active-device count therefore makes revocation reversible by
// whoever holds the II — which is normally the party the revocation was
// defending against.
//
// THE GATE. `bootstrap_path_open` distinguishes the three cases on the RETAINED
// rows: never enrolled (open), at least one active device (open, unchanged),
// enrolled but zero active (open ONLY with an `authorize_re_bootstrap` policy
// row). It is consulted TWICE — at ticket mint and again at ticket consume —
// because a revocation to zero inside a live ticket's TTL is caught only by the
// second.
//
// The authorization must be signed by a device that is ACTIVE at signing time,
// so it has to be created BEFORE the last device is revoked. A principal that
// revokes its last device without one is deliberately stuck: there is nobody
// left who can vouch, and an escape hatch here would be the hole itself.

const ACTION_RE_BOOTSTRAP: &[u8] = b"authorize_re_bootstrap";

fn re_bootstrap_transcript(
    canister: Principal,
    owner: Principal,
    issuer: &str,
    nonce: [u8; 16],
    expiry_ns: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    var(&mut out, PROTOCOL);
    out.extend_from_slice(&1u16.to_le_bytes());
    var(&mut out, canister.as_slice());
    var(&mut out, ACTION_RE_BOOTSTRAP);
    var(&mut out, owner.as_slice());
    var(&mut out, issuer.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&expiry_ns.to_le_bytes());
    out
}

/// The Candid mirror of the production `re_bootstrap_policy()` return type.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
struct RebootstrapPolicyView {
    allow_re_bootstrap: bool,
    authorized_at_ns: u64,
}

impl Harness {
    fn re_bootstrap_approval_from(
        &self,
        issuer: &TestDevice,
        owner: Principal,
        nonce: [u8; 16],
        expiry_ns: u64,
    ) -> SignedApproval {
        let msg = re_bootstrap_transcript(self.vetkeys_id, owner, &issuer.id, nonce, expiry_ns);
        SignedApproval {
            issuer_device_id: issuer.id.clone(),
            nonce: nonce.to_vec(),
            expiry_ns,
            signature: issuer.sign(&msg),
        }
    }

    fn authorize_re_bootstrap(
        &self,
        caller: Principal,
        target: Principal,
        approval: SignedApproval,
    ) -> Result<(), VetkeysError> {
        decode(
            "authorize_re_bootstrap",
            self.pic.update_call(
                self.vetkeys_id,
                caller,
                "authorize_re_bootstrap",
                candid::encode_args((target, approval)).unwrap(),
            ),
        )
    }

    /// The PRODUCTION, caller-scoped query. There is no owner argument, so this
    /// reads the row of whoever `caller` is and no other.
    fn re_bootstrap_policy(&self, caller: Principal) -> Option<RebootstrapPolicyView> {
        decode(
            "re_bootstrap_policy",
            self.pic.query_call(
                self.vetkeys_id,
                caller,
                "re_bootstrap_policy",
                candid::encode_args(()).unwrap(),
            ),
        )
    }

    /// Enrol `dev`, then revoke it with its own signature — the shortest route
    /// to a principal that HAS enrolled and now has zero ACTIVE devices.
    fn revoke_to_zero(&self, user: Principal, dev: &TestDevice, nonce: [u8; 16]) {
        let sig = self.revocation_from(dev, user, &dev.id, nonce, live_expiry(self));
        self.revoke(user, &dev.id, sig)
            .expect("a device may revoke itself");
        assert!(
            self.devices(user).iter().all(|d| !d.active),
            "precondition: the principal must now have zero ACTIVE devices"
        );
    }
}

/// AC-5 — the mint-time gate: after a revocation to zero, with no policy row, a
/// second bootstrap registration is REFUSED.
///
/// The refusal surfaces as `BootstrapNotAuthorized` at `register_device`: the
/// derive itself still succeeds (the user's own key material is theirs), it is
/// the TICKET that is not minted.
#[test]
fn l04_07_second_bootstrap_ticket_refused_after_revocation() {
    let h = setup();
    let user = p(0x51);
    let first = TestDevice::new("device-1", 0x51);
    h.bootstrap(user, &first, envelope(0x51));
    h.revoke_to_zero(user, &first, [0x51; 16]);

    // A fresh, successful ceremony — which before this lane would have minted a
    // ticket and handed the II holder a brand-new device.
    h.derive_past_the_meter(user, 0x52)
        .expect("the derive itself still succeeds: the key is the user's own");

    let second = TestDevice::new("device-2", 0x52);
    match h.register(user, &second, envelope(0x52), DeviceApproval::Bootstrap) {
        Err(VetkeysError::BootstrapNotAuthorized { .. }) => {}
        other => panic!("a revoked-to-zero principal must not re-bootstrap, got {other:?}"),
    }
    assert!(
        h.devices(user).iter().all(|d| !d.active),
        "nothing was enrolled"
    );
}

/// AC-6 — the consume-time re-check is INDEPENDENTLY load-bearing.
///
/// Here the device is ACTIVE when the ticket is minted, so the mint-time gate
/// passes and a real, live ticket exists. The revocation to zero happens INSIDE
/// that ticket's lifetime. Only the re-check at consume time can refuse this,
/// and it must.
#[test]
fn l04_07_ticket_minted_before_the_revocation_is_refused_at_consume_time() {
    let h = setup();
    let user = p(0x53);
    let first = TestDevice::new("device-1", 0x53);
    h.bootstrap(user, &first, envelope(0x53));

    // Ticket minted while the device is still ACTIVE — the mint-time gate is
    // satisfied and cannot be what refuses below.
    h.derive_past_the_meter(user, 0x54)
        .expect("derive while still holding an active device");

    // …and only THEN the revocation to zero, inside the ticket's TTL.
    h.revoke_to_zero(user, &first, [0x53; 16]);

    let second = TestDevice::new("device-2", 0x54);
    match h.register(user, &second, envelope(0x54), DeviceApproval::Bootstrap) {
        Err(VetkeysError::BootstrapNotAuthorized { .. }) => {}
        other => panic!(
            "a ticket minted before the revocation must not survive it, got {other:?}"
        ),
    }
}

/// AC-7 — `authorize_re_bootstrap` accepts a PRE-REVOCATION device's signature,
/// and the two halves of the story are separate predicates.
///
/// (i) two devices, one revoked, the other (active, and it existed before the
///     revocation) signs the authorization → accepted, and the principal can
///     subsequently derive and register.
/// (ii) one device, revoked, zero remain, NO authorization → the bootstrap is
///     refused by the mint-time zero-devices gate.
#[test]
fn l04_07_pre_revocation_device_may_authorize_re_bootstrap() {
    let h = setup();

    // ── (i) ────────────────────────────────────────────────────────────────
    let user = p(0x55);
    let first = TestDevice::new("device-1", 0x55);
    h.bootstrap(user, &first, envelope(0x55));
    let second = TestDevice::new("device-2", 0x56);
    let env2 = envelope(0x56);
    let approval = h.approval_from(&first, user, &second, &env2, [0x55; 16], live_expiry(&h));
    h.register(user, &second, env2, DeviceApproval::Device(approval))
        .expect("a second device enrols by approval");

    // Device 1 is revoked; device 2 — active, and present before that
    // revocation — signs the re-bootstrap authorization.
    let rev = h.revocation_from(&second, user, &first.id, [0x56; 16], live_expiry(&h));
    h.revoke(user, &first.id, rev).expect("device 2 revokes device 1");

    // (i-b) — and the converse, which is what makes `check_issuer`'s STATUS
    // check a separate, independently load-bearing predicate from the
    // mint-time device count: the REVOKED device 1 cannot authorize, even
    // though its record is still there to be found. Asserted BEFORE the
    // positive arm so the positive arm cannot be what wrote the row.
    let by_revoked = h.re_bootstrap_approval_from(&first, user, [0x5C; 16], live_expiry(&h));
    match h.authorize_re_bootstrap(user, user, by_revoked) {
        Err(VetkeysError::ApprovalRejected(reason)) => {
            assert!(reason.contains("revoked"), "unexpected reason: {reason}")
        }
        other => panic!("a REVOKED device must not authorize a re-bootstrap, got {other:?}"),
    }
    assert_eq!(
        h.re_bootstrap_policy(user),
        None,
        "a refused authorization must write no policy row"
    );

    let auth = h.re_bootstrap_approval_from(&second, user, [0x57; 16], live_expiry(&h));
    h.authorize_re_bootstrap(user, user, auth)
        .expect("an ACTIVE, pre-revocation device may authorize a re-bootstrap");

    h.derive_past_the_meter(user, 0x57).expect("derive");
    let third = TestDevice::new("device-3", 0x57);
    h.register(user, &third, envelope(0x57), DeviceApproval::Bootstrap)
        .expect("an authorized principal may bootstrap again");

    // ── (ii) ───────────────────────────────────────────────────────────────
    let lone = p(0x58);
    let only = TestDevice::new("device-1", 0x58);
    h.bootstrap(lone, &only, envelope(0x58));
    h.revoke_to_zero(lone, &only, [0x58; 16]);
    h.derive_past_the_meter(lone, 0x59).expect("derive");
    let replacement = TestDevice::new("device-2", 0x59);
    match h.register(lone, &replacement, envelope(0x59), DeviceApproval::Bootstrap) {
        Err(VetkeysError::BootstrapNotAuthorized { .. }) => {}
        other => panic!(
            "with zero active devices and no authorization the bootstrap must be \
             refused, got {other:?}"
        ),
    }
}

/// AC-8 — the policy row read through the REAL, SHIPPED query.
///
/// Three facts, none of them a re-derivation of the gate's logic and none of
/// them a re-run of AC-5's sequence:
///   · absent row reads as `null` — the state every existing enrolment is in;
///   · after a successful `authorize_re_bootstrap` the SAME query returns
///     `allow_re_bootstrap = true` with the authorizing timestamp;
///   · a DIFFERENT principal's call still returns `null` — the query is
///     caller-scoped, and there is no argument by which it could not be.
#[test]
fn l04_07_re_bootstrap_policy_query_defaults_to_none_and_is_caller_scoped() {
    let h = setup();
    let user = p(0x5A);
    let bystander = p(0x5B);

    assert_eq!(
        h.re_bootstrap_policy(user),
        None,
        "a principal with no policy row must read as null, not as authorized"
    );

    let first = TestDevice::new("device-1", 0x5A);
    h.bootstrap(user, &first, envelope(0x5A));
    assert_eq!(
        h.re_bootstrap_policy(user),
        None,
        "merely enrolling a device must not create a policy row"
    );

    let before_ns = h.now_ns();
    let auth = h.re_bootstrap_approval_from(&first, user, [0x5A; 16], live_expiry(&h));
    h.authorize_re_bootstrap(user, user, auth)
        .expect("an active device authorizes its own principal");

    let view = h
        .re_bootstrap_policy(user)
        .expect("the row must now be readable through the production query");
    assert!(view.allow_re_bootstrap, "the row records an authorization");
    assert!(
        view.authorized_at_ns >= before_ns,
        "the recorded time must be the authorizing call's, not zero: {} < {}",
        view.authorized_at_ns,
        before_ns
    );

    assert_eq!(
        h.re_bootstrap_policy(bystander),
        None,
        "the query is caller-scoped — another principal's call reads its OWN row"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// B-5-REBOOTSTRAP-SIGNATURE — the signature verify in `authorize_re_bootstrap`
// ═════════════════════════════════════════════════════════════════════════════
//
// WHY THIS EXISTS (SSA landed-diff R-8 V1, RED-1; CTO ruling
// cto-ruling-r8-landed-diff-fix-wave-2026-09-06 item 1).
//
// The endpoint was CORRECT at fdbde43a and UNBOUND. Stripping its
// `verify::verify_transcript` call REDded nothing in the whole suite: AC-7's
// negative arm is refused by `check_issuer`'s STATUS check (the issuer is
// revoked), and AC-5/AC-6/AC-8 all sign VALIDLY. The only predicate any
// committed test placed on this endpoint was issuer presence/status — so a
// future edit could delete the verify and go green through the entire gate,
// re-opening the bootstrap path to any 64 well-formed bytes, which is the exact
// capability the lane exists to gate.
//
// The three negatives below are chosen so that each fails on a DIFFERENT
// predicate, and only one of them can be satisfied by `check_issuer`:
//
//   · FORGED    — an ACTIVE issuer, well-formed 64-byte signature, garbage
//                 content. `check_issuer` passes it (it checks LENGTH, not
//                 validity); only `verify_transcript` refuses.
//   · REPLAYED  — an ACTIVE issuer's REAL signature, over a genuine
//                 `RevokeV1` transcript with the same issuer, nonce and
//                 expiry. Cryptographically valid, and everything
//                 `check_issuer` reads is identical to a legitimate request;
//                 refused because the endpoint rebuilds a `ReBootstrapV1` and
//                 verifies against THAT. Stated precisely, because the
//                 difference is not the label alone: `RevokeV1` also carries a
//                 target-device field `ReBootstrapV1` does not, so this arm
//                 binds "the transcript the device actually signed", of which
//                 the action label is one part. A label CHANGE is separately
//                 caught by the POSITIVE arms — the test's
//                 `re_bootstrap_transcript` helper is an independent
//                 re-implementation, so re-pointing the production encode at
//                 `ACTION_REVOKE_DEVICE` REDs this test and three others
//                 (measured, V1a mutation M-D2b).
//   · REVOKED   — a valid signature from a device that is NOT active. Refused
//                 by `check_issuer`'s status check, which is the separate
//                 predicate; asserted here so the row covers both halves of
//                 the ruling's requirement in one place.
//
// And then the POSITIVE, which is what makes the negatives non-vacuous: the
// same call shape with a genuine `ReBootstrapV1` signature IS accepted and DOES
// write the row. Every arm asserts the row afterwards, so a refusal that
// nevertheless wrote state would fail too.

// BINDING: B-5-REBOOTSTRAP-SIGNATURE — `authorize_re_bootstrap` verifies the
// approval's SIGNATURE against the issuing device's stored signing key, over a
// transcript rebuilt with this endpoint's OWN action label. A forged signature,
// a valid signature replayed from a different action, and a signature from a
// non-active device are each REFUSED and write no policy row; only the genuine
// `ReBootstrapV1` signature is accepted.
#[test]
fn l04_07_forged_or_replayed_signature_cannot_authorize_re_bootstrap() {
    let h = setup();
    let user = p(0x60);
    let dev = TestDevice::new("device-1", 0x60);
    h.bootstrap(user, &dev, envelope(0x60));

    let second = TestDevice::new("device-2", 0x61);
    let env2 = envelope(0x61);
    let approval = h.approval_from(&dev, user, &second, &env2, [0x60; 16], live_expiry(&h));
    h.register(user, &second, env2, DeviceApproval::Device(approval))
        .expect("a second device enrols by approval");

    // ── (a) FORGED: an ACTIVE issuer, 64 well-formed bytes, garbage content ──
    //
    // This is the mutation's payload. `check_issuer` finds device-1 registered,
    // ACTIVE and the approval live, and accepts the signature's LENGTH. If the
    // verify is stripped, THIS is the call that succeeds.
    let forged = SignedApproval {
        issuer_device_id: dev.id.clone(),
        nonce: [0x61; 16].to_vec(),
        expiry_ns: live_expiry(&h),
        signature: vec![0x01u8; 64],
    };
    match h.authorize_re_bootstrap(user, user, forged) {
        Err(VetkeysError::ApprovalRejected(_)) => {}
        other => panic!(
            "a FORGED 64-byte signature must be refused by the transcript verify, got {other:?}"
        ),
    }
    assert_eq!(
        h.re_bootstrap_policy(user),
        None,
        "a forged authorization must write no policy row"
    );

    // ── (b) REPLAYED: a REAL signature over a genuine RevokeV1 transcript ────
    //
    // Same issuer, same nonce, same expiry — everything `check_issuer` reads is
    // identical to a legitimate request, and the signature verifies against a
    // transcript this device really did sign. Only the ACTION LABEL differs.
    let replay_nonce = [0x62; 16];
    let replay_expiry = live_expiry(&h);
    let revoke_msg = revoke_transcript(
        h.vetkeys_id, user, &dev.id, &second.id, replay_nonce, replay_expiry,
    );
    let replayed = SignedApproval {
        issuer_device_id: dev.id.clone(),
        nonce: replay_nonce.to_vec(),
        expiry_ns: replay_expiry,
        signature: dev.sign(&revoke_msg),
    };
    match h.authorize_re_bootstrap(user, user, replayed) {
        Err(VetkeysError::ApprovalRejected(_)) => {}
        other => panic!(
            "a valid signature over a DIFFERENT action's transcript must not replay as a \
             re-bootstrap authorization, got {other:?}"
        ),
    }
    assert_eq!(
        h.re_bootstrap_policy(user),
        None,
        "a replayed authorization must write no policy row"
    );

    // ── (c) REVOKED ISSUER: a perfectly valid signature, non-active device ───
    let rev = h.revocation_from(&second, user, &dev.id, [0x63; 16], live_expiry(&h));
    h.revoke(user, &dev.id, rev).expect("device 2 revokes device 1");
    let by_revoked = h.re_bootstrap_approval_from(&dev, user, [0x64; 16], live_expiry(&h));
    match h.authorize_re_bootstrap(user, user, by_revoked) {
        Err(VetkeysError::ApprovalRejected(reason)) => {
            assert!(reason.contains("revoked"), "unexpected reason: {reason}")
        }
        other => panic!("a NON-ACTIVE device must not authorize a re-bootstrap, got {other:?}"),
    }
    assert_eq!(
        h.re_bootstrap_policy(user),
        None,
        "an authorization from a revoked device must write no policy row"
    );

    // ── (d) THE POSITIVE — non-vacuity ──────────────────────────────────────
    //
    // Identical call shape, genuine `ReBootstrapV1` signature from the still
    // ACTIVE device 2. Accepted, and the row appears. Without this arm the
    // three refusals above could all be produced by an endpoint that refuses
    // everything.
    let genuine = h.re_bootstrap_approval_from(&second, user, [0x65; 16], live_expiry(&h));
    h.authorize_re_bootstrap(user, user, genuine)
        .expect("a genuine ReBootstrapV1 signature from an ACTIVE device is accepted");
    assert!(
        h.re_bootstrap_policy(user)
            .expect("the accepted authorization writes the row")
            .allow_re_bootstrap,
        "the accepted authorization records allow_re_bootstrap"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// AMBER-2 — the policy row is ONE-SHOT: spent by the registration it authorises
// ═════════════════════════════════════════════════════════════════════════════
//
// At fdbde43a the row was written and NEVER removed, so `allow_re_bootstrap`
// was permanent: a principal that legitimately recovered ONCE had the L04-07
// gate disabled forever, and every LATER revocation to zero was undoable by
// whoever held the II — the precise threat the gate exists to close. The code's
// own `ReBootstrapV1` doc already said the capability was "one future bootstrap
// registration"; the EFFECT disagreed. CTO ruling item 3 settled it as ONE-SHOT.
//
// The consumption point is `register_device`'s `Bootstrap` arm, alongside the
// ticket consume, so the row and the ticket are spent in the same message as
// the write they authorise.
#[test]
fn l04_07_re_bootstrap_policy_is_one_shot_and_a_second_revocation_is_stuck_again() {
    let h = setup();
    let user = p(0x66);

    let first = TestDevice::new("device-1", 0x66);
    h.bootstrap(user, &first, envelope(0x66));

    // Authorised BEFORE the revocation, by the device that is still active.
    let auth = h.re_bootstrap_approval_from(&first, user, [0x66; 16], live_expiry(&h));
    h.authorize_re_bootstrap(user, user, auth)
        .expect("an active device authorizes its own principal");
    assert!(
        h.re_bootstrap_policy(user).is_some(),
        "precondition: the row exists before the recovery"
    );

    h.revoke_to_zero(user, &first, [0x67; 16]);

    // ── THE RECOVERY the row exists for — it must still work ────────────────
    h.derive_past_the_meter(user, 0x67).expect("derive");
    let second = TestDevice::new("device-2", 0x67);
    h.register(user, &second, envelope(0x67), DeviceApproval::Bootstrap)
        .expect("the authorised principal may bootstrap again — ONCE");

    // ── THE ROW IS SPENT ────────────────────────────────────────────────────
    assert_eq!(
        h.re_bootstrap_policy(user),
        None,
        "the row must be CONSUMED by the registration it authorised, not left standing"
    );

    // ── AND THE GATE IS BACK — a SECOND revocation to zero is stuck again ───
    h.revoke_to_zero(user, &second, [0x68; 16]);
    h.derive_past_the_meter(user, 0x68).expect("derive");
    let third = TestDevice::new("device-3", 0x68);
    match h.register(user, &third, envelope(0x68), DeviceApproval::Bootstrap) {
        Err(VetkeysError::BootstrapNotAuthorized { .. }) => {}
        other => panic!(
            "a SECOND revocation to zero must be refused: one authorization buys ONE \
             bootstrap, not permanent immunity, got {other:?}"
        ),
    }
    assert!(
        h.devices(user).iter().all(|d| !d.active),
        "nothing was enrolled by the refused second recovery"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// AMBER-3 — the PRE-R-8 predecessor: the lock-out applies RETROACTIVELY
// ═════════════════════════════════════════════════════════════════════════════
//
// `post_upgrade` asserts "migration: NONE — MemoryId 17 is a fresh region, so
// on an upgrade from a pre-lane build it is simply empty." That is a claim
// about an EMPTY MAP, and it was ASSERTED, not demonstrated — every
// `upgrade_canister` in this file upgrades `vetkeys_wasm()` to itself.
//
// The interesting case is not the empty map, it is the BEHAVIOUR CHANGE to LIVE
// STATE. A principal that enrolled and revoked to zero under fc30d618 could
// bootstrap again the moment before this upgrade and cannot the moment after,
// with no policy row it could ever have created — the pre-lane build has no
// `authorize_re_bootstrap` endpoint at all. That is a one-way door applied
// retroactively, and the CTO ruled it the INTENDED behaviour (item 4), so it is
// pinned here rather than merely accepted.
//
// The second principal is the control: an ordinary enrolment must come through
// the upgrade with its devices intact, or "retroactive lock-out" would be
// indistinguishable from "the upgrade lost the device table."

/// The PRE-R-8 predecessor, built from `fc30d618` — the lane's own base commit,
/// which has neither the gate, the policy map, nor the endpoint. Authenticated
/// by SHA-256 in `run_gate.sh` on EVERY run, exactly as the pre-repin fixture
/// is: a recipe that only runs on absence never looks at bytes already present.
///
/// A current-source rebuild cannot substitute: it carries the gate, so the
/// revoked-to-zero principal below could not reach the pre-upgrade state this
/// arm needs. The `expect` on the PRE-upgrade bootstrap is that second,
/// independent behavioural guard — a substituted current-source Wasm refuses
/// it and fails this arm before any upgrade happens.
fn pre_r8_wasm() -> Vec<u8> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/wasm32-unknown-unknown/release/vetkeys_pre_r8_fc30d618_test.wasm"
    );
    std::fs::read(p).unwrap_or_else(|e| {
        panic!(
            "vetkeys_pre_r8_fc30d618_test.wasm not found ({e}) — this arm needs the GENUINE \
             pre-lane predecessor, built from fc30d618, not from current source:\n  \
             git worktree add --detach /tmp/stsh-vetkeys-pre-r8 fc30d618 && \
             (cd /tmp/stsh-vetkeys-pre-r8 && \
             CARGO_TARGET_DIR=/tmp/stsh-vetkeys-pre-r8/target cargo build --manifest-path \
             canisters/vetkeys/Cargo.toml --target wasm32-unknown-unknown --release --locked) && \
             cp /tmp/stsh-vetkeys-pre-r8/target/wasm32-unknown-unknown/release/\
stsh_vetkeys.wasm canisters/vetkeys/target/wasm32-unknown-unknown/release/\
vetkeys_pre_r8_fc30d618_test.wasm\n  expected sha256: \
             59a8a33c3215bb9b6c5ad6a870d9909e5b8a255eaa84db53a50452b3d3f3ee4c"
        )
    })
}

/// A harness whose vetkeys canister is the PRE-R-8 binary. Identical to
/// `setup()` in every other respect, including the init arguments — the lane
/// changed no init shape, which is itself part of what this arm demonstrates,
/// since a changed shape would make the upgrade below fail outright.
fn setup_pre_r8() -> Harness {
    let pic = PocketIcBuilder::new()
        .with_ii_subnet()
        .with_application_subnet()
        .with_nonmainnet_features(true)
        .build();
    let token_id = install_mock_token(&pic, mock_token_wasm(RICH_BALANCE_E8S));
    let vetkeys_id = pic.create_canister();
    pic.add_cycles(vetkeys_id, 1_000_000_000_000_000);
    pic.install_canister(
        vetkeys_id,
        pre_r8_wasm(),
        candid::encode_args(("test_key_1".to_string(), Some(token_id))).unwrap(),
        None,
    );
    let pool = p(0x05);
    let merkle_id = pic.create_canister();
    pic.add_cycles(merkle_id, 2_000_000_000_000);
    pic.install_canister(merkle_id, merkle_wasm(), candid::encode_one(pool).unwrap(), None);
    Harness { pic, vetkeys_id, merkle_id, pool, token_id }
}

#[test]
fn l04_07_pre_r8_revoked_to_zero_principal_is_locked_out_by_the_upgrade() {
    let h = setup_pre_r8();

    // ── The principal the lane's gate will retroactively lock out ───────────
    let stuck = p(0x69);
    let stuck_dev = TestDevice::new("device-1", 0x69);
    h.bootstrap(stuck, &stuck_dev, envelope(0x69));
    h.revoke_to_zero(stuck, &stuck_dev, [0x69; 16]);

    // PRE-UPGRADE, the hole is open — and this `expect` is what proves the
    // installed binary really is the predecessor. On current source the gate
    // refuses here and this arm fails before it can pass vacuously.
    h.derive_past_the_meter(stuck, 0x6A).expect("derive on the predecessor");
    let replacement = TestDevice::new("device-2", 0x6A);
    h.register(stuck, &replacement, envelope(0x6A), DeviceApproval::Bootstrap)
        .expect("PRE-R-8: a revoked-to-zero principal COULD simply re-bootstrap — the hole");
    // …and back to zero, so the post-upgrade state is the one under test.
    h.revoke_to_zero(stuck, &replacement, [0x6B; 16]);

    // ── The CONTROL: an ordinary enrolment that must survive intact ─────────
    let keeper = p(0x6C);
    let keeper_dev = TestDevice::new("device-1", 0x6C);
    h.bootstrap(keeper, &keeper_dev, envelope(0x6C));
    let keeper_before = h.devices(keeper);
    assert_eq!(keeper_before.len(), 1, "precondition: the control has one device");
    assert!(keeper_before[0].active, "precondition: the control's device is active");

    // ── THE UPGRADE ────────────────────────────────────────────────────────
    h.pic
        .upgrade_canister(h.vetkeys_id, vetkeys_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("the pre-R-8 predecessor upgrades to the candidate without trapping");

    // MemoryId 17 comes through EMPTY — demonstrated, not asserted, and through
    // the SHIPPED query rather than a raw region read.
    assert_eq!(
        h.re_bootstrap_policy(stuck),
        None,
        "a principal that could never have created a policy row must read as null"
    );
    assert_eq!(h.re_bootstrap_policy(keeper), None, "…and so must the control");

    // THE RETROACTIVE LOCK-OUT — the ruled, intended behaviour.
    h.derive_past_the_meter(stuck, 0x6D).expect("derive after the upgrade");
    let post = TestDevice::new("device-3", 0x6D);
    match h.register(stuck, &post, envelope(0x6D), DeviceApproval::Bootstrap) {
        Err(VetkeysError::BootstrapNotAuthorized { .. }) => {}
        other => panic!(
            "the gate must apply to enrolments that predate it: a principal already \
             revoked to zero under fc30d618 is stuck after the upgrade, got {other:?}"
        ),
    }

    // THE CONTROL still holds its device, and can still use it — so the
    // lock-out above is the gate, not a lost device table.
    let keeper_after = h.devices(keeper);
    assert_eq!(
        keeper_after.len(),
        1,
        "an enrolled principal keeps its devices across the upgrade"
    );
    assert!(
        keeper_after[0].active,
        "…and they are still ACTIVE — the upgrade revoked nothing"
    );
    let extra = TestDevice::new("device-2", 0x6E);
    let env_extra = envelope(0x6E);
    let ok = h.approval_from(&keeper_dev, keeper, &extra, &env_extra, [0x6E; 16], live_expiry(&h));
    h.register(keeper, &extra, env_extra, DeviceApproval::Device(ok))
        .expect("the surviving device can still approve a new one after the upgrade");
}

// ═════════════════════════════════════════════════════════════════════════════
// VETKEYS-AGE-2MIN — the live a7l2d predecessor, and the combined upgrade arm
// (A1 notes v3 PART C; CTO ruling RULING_VETKEYS_ENVELOPE_CAP_MECHANISM
// 2026-09-23 incl. its "builder blockers ruled" addendum).
// ═════════════════════════════════════════════════════════════════════════════

/// The GENUINE pre-change live module (a7l2d, T=900s, WRAPPED_SECRET_MAX_BYTES=512),
/// built from bd12694. UNLIKE `pre_repin_wasm()`/`pre_r8_wasm()` above, this loader
/// hash-checks the bytes ITSELF, in addition to `run_gate.sh`'s external check —
/// C-3 (SSA review, 2026-09-23): a recipe that only fires on absence never looks at
/// bytes already present, and a direct `cargo test -p vetkeys` invocation that
/// bypasses `run_gate.sh` entirely (or a stale copy under a different
/// CARGO_TARGET_DIR) must still be caught here, not silently accepted.
const PRE_AGE2MIN_SHA256: &str =
    "b51a8436ee45a68b0505593757a5092d7cd698f1dab5cacca2a13a20a9b9f444";

fn pre_age2min_wasm() -> Vec<u8> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/wasm32-unknown-unknown/release/vetkeys_live_a7l2d_b51a8436_test.wasm"
    );
    let bytes = std::fs::read(p).unwrap_or_else(|e| {
        panic!(
            "vetkeys_live_a7l2d_b51a8436_test.wasm not found ({e}) — this test needs the \
             GENUINE live a7l2d module, built from bd12694, not from current source:\n  \
             git worktree add --detach /tmp/stsh-vetkeys-age2min bd12694 && \
             (cd /tmp/stsh-vetkeys-age2min && \
             CARGO_TARGET_DIR=/tmp/stsh-vetkeys-age2min/target cargo build --manifest-path \
             canisters/vetkeys/Cargo.toml --target wasm32-unknown-unknown --release --locked) && \
             cp /tmp/stsh-vetkeys-age2min/target/wasm32-unknown-unknown/release/\
stsh_vetkeys.wasm canisters/vetkeys/target/wasm32-unknown-unknown/release/\
vetkeys_live_a7l2d_b51a8436_test.wasm\n  expected sha256: {PRE_AGE2MIN_SHA256}"
        )
    });
    let actual: String = sha256(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        actual, PRE_AGE2MIN_SHA256,
        "vetkeys_live_a7l2d_b51a8436_test.wasm has the WRONG hash (expected {PRE_AGE2MIN_SHA256}, \
         got {actual}) — this loader authenticates independently of run_gate.sh, per C-3: a stale \
         or substituted fixture (e.g. a current-source rebuild, which carries the age/cap changes \
         already and would make this test's OLD-module assertions vacuous) must fail HERE, not \
         only in the shell gate."
    );
    bytes
}

/// A parameterised envelope, for the C-5 overflow-witness rows — `envelope(seed)`
/// is fixed at 384 bytes and stays as-is for every existing call site.
fn envelope_of_len(seed: u8, len: usize) -> Vec<u8> {
    vec![seed; len]
}

/// AD-12's corrected ceiling literal (627, not a 555-627 range): the largest
/// envelope this protocol version admits. See AD-12 (A1 notes v2 §B.6) for
/// the full field-by-field derivation; cited again here at the call site per
/// the CTO addendum's "both literals cite each other" instruction — the wallet
/// side is `wallet/tests/envelope_length_age2min.test.ts` (1024 ceiling, 627
/// passcode worst case, 583 II-only worst case).
///
/// 627 = header(215) + body(412): canisterId 10B + owner 29B
/// (`PRINCIPAL_MAX_BYTES`, `state.rs:46`) + deviceId 64B (`MAX_DEVICE_ID_BYTES`,
/// `pins.rs:168`) + salt 16B (passcode mode) + RSA ciphertext 384B + GCM nonce
/// 12B + GCM tag 16B; see `wallet/src/crypto/envelope.ts` for the header field
/// list.
const ENVELOPE_CEILING_BYTES: usize = 627;

/// The NEW stored-size ceiling after AD-11's raise (`state.rs`
/// `WRAPPED_SECRET_MAX_BYTES: u32 = 1024`) — the C-5 boundary case. Deliberately
/// NOT derived from the envelope protocol arithmetic above (which tops out at
/// 627): this literal exists to prove the RAISED BOUND ITSELF admits its own
/// exact declared maximum, a check the 627-byte "realistic worst case" cannot
/// stand in for.
const ENVELOPE_NEW_BOUND_BYTES: usize = 1024;

/// One byte past the new bound — the negative control. Must be refused with
/// the EXACT stored-size typed variant, not any error (C-5).
const ENVELOPE_OVER_BOUND_BYTES: usize = 1025;

// ═════════════════════════════════════════════════════════════════════════════
// COMBINED O-4/AD-3/AC-6/C-5 — the age-2min AND envelope-cap upgrade, together,
// against the REAL pre-change module. Supersedes AD-3's original step 4/5 and
// discharges AC-6; C-5's overflow witness is the final extension.
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn combined_age2min_and_envelope_cap_upgrade_with_overflow_witness() {
    assert_ne!(
        pre_age2min_wasm(), vetkeys_wasm(),
        "the pre-change fixture must be BYTE-DIFFERENT from the current-source build — if these \
         ever match, the fixture has silently become a current-source rebuild and every OLD-module \
         assertion below is vacuous"
    );

    // ── Install the OLD module: T=900s, WRAPPED_SECRET_MAX_BYTES=512 ─────────
    let pic = PocketIcBuilder::new()
        .with_ii_subnet()
        .with_application_subnet()
        .with_nonmainnet_features(true)
        .build();
    let token_id = install_mock_token(&pic, mock_token_wasm(RICH_BALANCE_E8S));
    let vetkeys_id = pic.create_canister();
    pic.add_cycles(vetkeys_id, 1_000_000_000_000_000);
    pic.install_canister(
        vetkeys_id,
        pre_age2min_wasm(),
        candid::encode_args(("test_key_1".to_string(), Some(token_id))).unwrap(),
        None,
    );
    let merkle_id = pic.create_canister();
    pic.add_cycles(merkle_id, 2_000_000_000_000);
    let pool = p(0x05);
    pic.install_canister(merkle_id, merkle_wasm(), candid::encode_one(pool).unwrap(), None);
    let h = Harness { pic, vetkeys_id, merkle_id, pool, token_id };

    // ── ENV_OWNER_1: bootstrap ONE device, 384-byte envelope, under the OLD
    //    module. `h.bootstrap` internally runs `derive_past_the_meter` (skips
    //    the A-2 meter window) then `try_get_encrypted_vetkey_typed`'s automatic
    //    age-in retry (waits exactly the OLD 900s the canister names), so this
    //    single call establishes the principal, ages it in under T=900,
    //    performs the ONE pre-upgrade derive, AND registers the first device —
    //    all real, no test-only bypass. A POPULATED map goes into the upgrade.
    let env_owner_1 = p(0xC1);
    let env_dev_1 = TestDevice::new("env-owner-1-device-1", 0xC1);
    let env_envelope_384 = envelope(0xC1);
    h.bootstrap(env_owner_1, &env_dev_1, env_envelope_384.clone());
    assert_eq!(
        h.wrapped_secret(env_owner_1, &env_dev_1.id),
        Ok(env_envelope_384.clone()),
        "the pre-upgrade device must read its own 384-byte envelope back byte-exact \
         immediately after registration, under the OLD module"
    );

    // ── AGE_P1 / AGE_P2: the age-2min scope's two sighting principals, wholly
    //    separate from the envelope-cap principals above.
    let age_p1 = p(0xA1);
    let age_p2 = p(0xA2);
    match h.try_get_encrypted_vetkey_raw(age_p1, Harness::valid_transport_key(0xA1)) {
        Err(VetkeysError::EligibilityAgeNotMet { retry_after_ns }) => {
            // The OLD module's T, as its own literal — NOT this suite's
            // (now 120s) `ELIGIBILITY_MIN_AGE_NS`: the historical 900-second
            // refusal is what proves the predecessor is the real one (C-3).
            assert_eq!(
                retry_after_ns, 900_000_000_000,
                "a FIRST sighting under the OLD module must report the full OLD T (900s)"
            );
        }
        other => panic!("AGE_P1's first call must record a sighting and refuse, got {other:?}"),
    }
    let t0_ns = h.now_ns();
    h.pic.advance_time(std::time::Duration::from_secs(90));
    h.pic.tick();
    match h.try_get_encrypted_vetkey_raw(age_p2, Harness::valid_transport_key(0xA2)) {
        Err(VetkeysError::EligibilityAgeNotMet { .. }) => {}
        other => panic!("AGE_P2's first call must record a sighting and refuse, got {other:?}"),
    }
    let sighting_b_ns = h.now_ns();
    // PocketIC advances its clock by a few ns per executed round, so an exact
    // equality is not a property of the harness (live run: +1ns). Bounded
    // instead, per SSA C-3 ("bound the B timing tolerance using measured
    // PocketIC time"): the drift must stay under 1 ms.
    const TICK_TOLERANCE_NS: u64 = 1_000_000;
    assert!(
        sighting_b_ns >= t0_ns + 90_000_000_000 && sighting_b_ns - (t0_ns + 90_000_000_000) < TICK_TOLERANCE_NS,
        "AGE_P2's sighting must land at t0+90s (measured t0+{}ns)",
        sighting_b_ns - t0_ns
    );

    // Advance to t0+150s: AGE_P1 is 150s old, AGE_P2 is 60s old, at upgrade time.
    h.pic.advance_time(std::time::Duration::from_secs(60));
    h.pic.tick();
    let t_upgrade_ns = h.now_ns();
    assert!(
        t_upgrade_ns >= t0_ns + 150_000_000_000 && t_upgrade_ns - (t0_ns + 150_000_000_000) < TICK_TOLERANCE_NS,
        "the upgrade must land at t0+150s, within PocketIC round drift (measured t0+{}ns)",
        t_upgrade_ns - t0_ns
    );

    // ── PRE-upgrade snapshot — global state seeded NONZERO (ENV_OWNER_1's one
    //    derive above), sightings_pending == 2 (AGE_P1 + AGE_P2, both live) ────
    let pre = h.derive_budget_stats();
    assert_eq!(pre.sightings_pending, 2, "both AGE_P1 and AGE_P2 sightings must be pending");
    assert_eq!(pre.consumed, 1, "ENV_OWNER_1's bootstrap derive is the only dispatch so far");
    assert_eq!(pre.tagged_consumed, 1);
    assert_eq!(pre.distinct_principals, 1);
    assert_eq!(pre.max_by_one_principal, 1);
    assert_eq!(pre.first_derive_dispatches, 1, "ENV_OWNER_1's derive was a first-derive");
    let pre_stats_epoch = pre.stats_epoch_ns;
    // C-3 (SSA landed-diff F-1): the EXACT token/config, read-only, against the
    // known install arguments — not merely "some working configuration".
    let installed_config = ("stsh.wallet.notes.v1".to_string(), "test_key_1".to_string());
    let pre_token = h.configured_token();
    let pre_config = get_config(&h.pic, h.vetkeys_id);
    assert_eq!(pre_token, Some(token_id), "the OLD module holds the installed token canister");
    assert_eq!(pre_config, installed_config, "the OLD module holds the installed (domain, key) tuple");

    // ── THE UPGRADE — empty arg bytes, exactly what the Vault sends (F-13) ───
    let new_wasm = vetkeys_wasm();
    assert_ne!(new_wasm, pre_age2min_wasm(), "sanity: new module bytes differ from the fixture");
    h.pic
        .upgrade_canister(h.vetkeys_id, new_wasm, vec![], None)
        .expect("the age-2min + envelope-cap upgrade must succeed on a populated, real predecessor");

    // ── POST-upgrade snapshot — IMMEDIATELY after, before ANY mutating call ──
    let post_token = h.configured_token();
    let post_config = get_config(&h.pic, h.vetkeys_id);
    assert_eq!(
        post_token,
        Some(token_id),
        "the retained token cell survives an empty-arg upgrade (post_upgrade(None) preserves it)"
    );
    assert_eq!(post_token, pre_token, "token unchanged across the upgrade");
    assert_eq!(post_config, installed_config, "the (domain, key) tuple survives the upgrade exactly");
    assert_eq!(post_config, pre_config, "config unchanged across the upgrade");
    let post = h.derive_budget_stats();
    assert_eq!(post.sightings_pending, 2, "the stable sightings map survives the upgrade untouched");
    assert_eq!(post.consumed, pre.consumed, "the stable GLOBAL_DERIVE_BUDGET_WINDOW survives");
    assert_eq!(post.tagged_consumed, pre.tagged_consumed);
    assert_eq!(post.distinct_principals, pre.distinct_principals);
    assert_eq!(post.max_by_one_principal, pre.max_by_one_principal);
    assert_eq!(post.first_derive_dispatches, pre.first_derive_dispatches);
    assert_ne!(
        post.stats_epoch_ns, pre_stats_epoch,
        "the HEAP stats epoch must advance across a real upgrade (F-12) — the heap meter/STATS \
         counters themselves are NOT asserted to survive or reset here (C-3)"
    );

    // ── Envelope-cap scope: the ENV_OWNER_1 row survives the upgrade byte-exact,
    //    on the SAME MemoryId::new(4) map (ruled Option A, in-place raise) ────
    assert_eq!(
        h.wrapped_secret(env_owner_1, &env_dev_1.id),
        Ok(env_envelope_384.clone()),
        "the PRE-upgrade 384-byte envelope must read back byte-exact AFTER the upgrade"
    );
    let env_devices = h.devices(env_owner_1);
    assert_eq!(env_devices.len(), 1, "no device was lost or duplicated across the upgrade");

    // ── Age-2min scope: AGE_P1 admitted, AGE_P2 refused, at the NEW T=120s ───
    let age_p1_reply = h
        .try_get_encrypted_vetkey_raw(age_p1, Harness::valid_transport_key(0xA1))
        .expect("AGE_P1 (150s old) must be ADMITTED under the new 120s rule");
    assert!(!age_p1_reply.encrypted_key.is_empty());

    let after_a = h.derive_budget_stats();
    assert_eq!(
        after_a.sightings_pending, 1,
        "AGE_P1's successful derive must CONSUME its sighting — sightings_pending drops 2 → 1 (C-3)"
    );
    assert_eq!(after_a.consumed, pre.consumed + 1, "AGE_P1's derive is a new global dispatch");
    assert_eq!(after_a.tagged_consumed, pre.tagged_consumed + 1);
    assert_eq!(after_a.distinct_principals, pre.distinct_principals + 1, "AGE_P1 is a new principal");
    assert_eq!(after_a.max_by_one_principal, 1, "each of the two principals has exactly one derive so far");
    assert_eq!(
        after_a.first_derive_dispatches, pre.first_derive_dispatches + 1,
        "AGE_P1's derive is ALSO a first-derive attribution — increments alongside consumed"
    );

    let age_p2_age_ns = t_upgrade_ns - sighting_b_ns; // ≈ 60s (± round drift), measured above
    let age_p2_retry = match h.try_get_encrypted_vetkey_raw(age_p2, Harness::valid_transport_key(0xA2)) {
        Err(VetkeysError::EligibilityAgeNotMet { retry_after_ns }) => retry_after_ns,
        other => panic!("AGE_P2 (~60s old) must still be refused under the new 120s rule, got {other:?}"),
    };
    let expected_upper = 120_000_000_000u64.saturating_sub(age_p2_age_ns);
    assert!(
        age_p2_retry > 0 && age_p2_retry <= expected_upper,
        "AGE_P2's wait must be a positive, bounded relation to the MEASURED elapsed time \
         ({age_p2_age_ns}ns), not an assumed-exact 60s; got retry_after_ns={age_p2_retry}, \
         expected in (0, {expected_upper}]"
    );

    let after_b = h.derive_budget_stats();
    assert_eq!(after_b.sightings_pending, 1, "B's REFUSAL must not touch the sightings map — still 1");
    assert_eq!(after_b.consumed, after_a.consumed, "B's refusal writes nothing to the global window");
    assert_eq!(after_b.tagged_consumed, after_a.tagged_consumed);
    assert_eq!(after_b.distinct_principals, after_a.distinct_principals);
    assert_eq!(after_b.first_derive_dispatches, after_a.first_derive_dispatches);

    // ── C-3's remaining-quota requirement: ENV_OWNER_1's OWN §H′ allowance.
    //    ENV_OWNER_1 is ALREADY ESTABLISHED (active device), so this derive
    //    skips §D entirely and goes straight to the dispatch fence.
    let env_owner_1_second = h
        .try_get_encrypted_vetkey_raw(env_owner_1, Harness::valid_transport_key(0xC2))
        .expect("an established principal's second derive must be admitted with no age wait");
    assert_eq!(
        env_owner_1_second.remaining, 3,
        "quota is 5; ENV_OWNER_1 consumed exactly 1 pre-upgrade (the bootstrap derive) and this \
         is derive #2, so remaining must be 5 - 2 = 3"
    );

    // ═══════════════════════════════════════════════════════════════════════
    // C-5 — THE OVERFLOW WITNESS. The OLD module created MemoryId 4's map
    // under the OLD 512-byte bound; its V2 page size is retained across the
    // in-place raise. This section forces the node past that page so the test
    // proves growth through overflow pages, not merely admission.
    //
    // ARITHMETIC (the overflow witness, recorded here per C-5):
    //   DeviceKey is fixed 95 bytes (PRINCIPAL_KEY_BYTES=30 + DEVICE_ID_KEY_BYTES=65).
    //   Node::max_size under the OLD bound = 7 + 11*(4+95+512+4) + 12*8 = 6868,
    //   so the retained V2 page is floor(3 * 6868 / 4) = 5151 bytes (SSA
    //   review §1, from the crate's own v1::size_v1 formula).
    //   This test populates 8 total rows in the SAME MemoryId(4) map:
    //     ENV_OWNER_1: device 1 =  384B (already stored, pre-upgrade)
    //                  device 2 =  627B (ENVELOPE_CEILING_BYTES)
    //                  device 3 = 1024B (ENVELOPE_NEW_BOUND_BYTES)
    //                  device 4 =  627B
    //                  device 5 =  627B
    //     ENV_OWNER_2: device 1 =  627B (fresh bootstrap, post-upgrade)
    //                  device 2 =  627B
    //                  device 3 =  627B
    //   Raw value bytes: 384 + 1024 + 6*627 = 5170 bytes — the VALUES ALONE
    //   already exceed the 5151-byte page; with the 8 × 95-byte keys and
    //   length prefixes the leaf payload is ≈ 5978 bytes. 8 entries stays under
    //   the node's 11-entry capacity, so this is a page-SIZE overflow forced by
    //   VALUE BYTES, not an entry-COUNT split.
    //
    // QUOTA ACCOUNTING (§E charges BEFORE validation, lib.rs register_device:
    //   "every call past the anonymous check costs one unit whatever its
    //   outcome" — so a refused registration still spends a unit):
    //   REGISTRATION_QUOTA = 5 per owner per 24h. ENV_OWNER_1: pre-upgrade
    //   Bootstrap (1) + devices 2-5 (4) = 5, AT the cap; the 6th attempt is the
    //   refused accounting check. ENV_OWNER_2: bootstrap + devices 2-3 (3) +
    //   the 1025-byte negative control (4) — under its cap. (Builder-blocker
    //   ruling 2026-09-23: the negative control lives on ENV_OWNER_2, not
    //   ENV_OWNER_1, because it spends a unit.) MAX_ACTIVE_DEVICES = 10: neither
    //   owner is near it.
    // ═══════════════════════════════════════════════════════════════════════

    // ENV_OWNER_1, device 2: the AD-12/AC-6 ceiling case (627B), via a ZERO-
    // DERIVE Device-approval signed by device 1.
    let env_dev_2 = TestDevice::new("env-owner-1-device-2", 0xC2);
    let envelope_627_a = envelope_of_len(0xD1, ENVELOPE_CEILING_BYTES);
    let expiry = live_expiry(&h);
    let approval_2 = h.approval_from(&env_dev_1, env_owner_1, &env_dev_2, &envelope_627_a, [0x02u8; 16], expiry);
    h.register(env_owner_1, &env_dev_2, envelope_627_a.clone(), DeviceApproval::Device(approval_2))
        .expect("a 627-byte envelope (the true protocol ceiling, AD-12) must be admitted under \
                 the new 1024-byte bound");
    assert_eq!(h.wrapped_secret(env_owner_1, &env_dev_2.id), Ok(envelope_627_a.clone()));

    // ENV_OWNER_1, device 3: the C-5 boundary case (exactly 1024B).
    let env_dev_3 = TestDevice::new("env-owner-1-device-3", 0xC3);
    let envelope_1024 = envelope_of_len(0xD2, ENVELOPE_NEW_BOUND_BYTES);
    let approval_3 = h.approval_from(&env_dev_1, env_owner_1, &env_dev_3, &envelope_1024, [0x03u8; 16], expiry);
    h.register(env_owner_1, &env_dev_3, envelope_1024.clone(), DeviceApproval::Device(approval_3))
        .expect("an EXACTLY 1024-byte envelope must be admitted — the raised bound's own declared \
                 maximum");
    assert_eq!(h.wrapped_secret(env_owner_1, &env_dev_3.id), Ok(envelope_1024.clone()));

    // ENV_OWNER_1, devices 4 and 5: two more 627B rows (registration quota 5/5).
    let env_dev_4 = TestDevice::new("env-owner-1-device-4", 0xC5);
    let envelope_627_b = envelope_of_len(0xD4, ENVELOPE_CEILING_BYTES);
    let approval_4 = h.approval_from(&env_dev_1, env_owner_1, &env_dev_4, &envelope_627_b, [0x05u8; 16], expiry);
    h.register(env_owner_1, &env_dev_4, envelope_627_b.clone(), DeviceApproval::Device(approval_4))
        .expect("4th registration for ENV_OWNER_1 today — within the 5/day quota");
    assert_eq!(h.wrapped_secret(env_owner_1, &env_dev_4.id), Ok(envelope_627_b.clone()));

    let env_dev_5 = TestDevice::new("env-owner-1-device-5", 0xC6);
    let envelope_627_c = envelope_of_len(0xD5, ENVELOPE_CEILING_BYTES);
    let approval_5 = h.approval_from(&env_dev_1, env_owner_1, &env_dev_5, &envelope_627_c, [0x06u8; 16], expiry);
    h.register(env_owner_1, &env_dev_5, envelope_627_c.clone(), DeviceApproval::Device(approval_5))
        .expect("5th and LAST registration for ENV_OWNER_1 today — exactly at the 5/day cap");
    assert_eq!(h.wrapped_secret(env_owner_1, &env_dev_5.id), Ok(envelope_627_c.clone()));

    // A 6th registration for ENV_OWNER_1 TODAY must now be refused by the rate
    // limit — confirms the quota accounting above was exact, not merely "under".
    let env_dev_6_attempt = TestDevice::new("env-owner-1-device-6-attempt", 0xC7);
    let envelope_627_extra = envelope_of_len(0xD6, ENVELOPE_CEILING_BYTES);
    let approval_6 = h.approval_from(
        &env_dev_1, env_owner_1, &env_dev_6_attempt, &envelope_627_extra, [0x07u8; 16], expiry,
    );
    match h.register(env_owner_1, &env_dev_6_attempt, envelope_627_extra, DeviceApproval::Device(approval_6)) {
        Err(VetkeysError::RegistrationRateExceeded { .. }) => {}
        other => panic!(
            "ENV_OWNER_1's 6th registration today must be refused by REGISTRATION_QUOTA=5 — this \
             is the accounting check that the 5-row plan above is exact, got {other:?}"
        ),
    }

    // ── ENV_OWNER_2: a FRESH principal, established post-upgrade under the NEW
    //    120s rule, contributing the remaining 3 overflow-witness rows. ───────
    let env_owner_2 = p(0xC8);
    let env_owner_2_dev_1 = TestDevice::new("env-owner-2-device-1", 0xD1);
    let envelope_627_d = envelope_of_len(0xE1, ENVELOPE_CEILING_BYTES);
    h.bootstrap(env_owner_2, &env_owner_2_dev_1, envelope_627_d.clone());
    assert_eq!(h.wrapped_secret(env_owner_2, &env_owner_2_dev_1.id), Ok(envelope_627_d.clone()));

    // `h.bootstrap` advanced the clock past the meter hour plus T, so the
    // expiry computed above is dead — re-derive it (builder-blocker ruling
    // 2026-09-23, mechanical fix).
    let expiry = live_expiry(&h);

    let env_owner_2_dev_2 = TestDevice::new("env-owner-2-device-2", 0xD2);
    let envelope_627_e = envelope_of_len(0xE2, ENVELOPE_CEILING_BYTES);
    let approval_7 = h.approval_from(
        &env_owner_2_dev_1, env_owner_2, &env_owner_2_dev_2, &envelope_627_e, [0x08u8; 16], expiry,
    );
    h.register(env_owner_2, &env_owner_2_dev_2, envelope_627_e.clone(), DeviceApproval::Device(approval_7))
        .expect("2nd registration for ENV_OWNER_2 — well within its own 5/day quota");
    assert_eq!(h.wrapped_secret(env_owner_2, &env_owner_2_dev_2.id), Ok(envelope_627_e.clone()));

    let env_owner_2_dev_3 = TestDevice::new("env-owner-2-device-3", 0xD3);
    let envelope_627_f = envelope_of_len(0xE3, ENVELOPE_CEILING_BYTES);
    let approval_8 = h.approval_from(
        &env_owner_2_dev_1, env_owner_2, &env_owner_2_dev_3, &envelope_627_f, [0x09u8; 16], expiry,
    );
    h.register(env_owner_2, &env_owner_2_dev_3, envelope_627_f.clone(), DeviceApproval::Device(approval_8))
        .expect("3rd registration for ENV_OWNER_2 — the 8th and final overflow-witness row");
    assert_eq!(h.wrapped_secret(env_owner_2, &env_owner_2_dev_3.id), Ok(envelope_627_f.clone()));

    // Negative control: 1025 bytes, refused with the EXACT stored-size typed
    // variant (C-5: "not any error/trap"). ENV_OWNER_2's 4th registration unit.
    let env_owner_2_dev_over = TestDevice::new("env-owner-2-device-over", 0xD4);
    let envelope_over = envelope_of_len(0xE4, ENVELOPE_OVER_BOUND_BYTES);
    let approval_over = h.approval_from(
        &env_owner_2_dev_1, env_owner_2, &env_owner_2_dev_over, &envelope_over, [0x0Au8; 16], expiry,
    );
    match h.register(env_owner_2, &env_owner_2_dev_over, envelope_over, DeviceApproval::Device(approval_over)) {
        Err(VetkeysError::InvalidRequest(msg)) => {
            assert_eq!(
                msg, "the wrapped envelope exceeds the maximum stored size",
                "must be the EXACT stored-size refusal string from register_device, not merely \
                 an error of some kind"
            );
        }
        other => panic!("a 1025-byte envelope must be refused by the STORED-SIZE variant, got {other:?}"),
    }
    assert_eq!(h.devices(env_owner_2).len(), 3, "the refused 1025-byte row stored nothing");

    // ── THE READBACK PASS — all 8 rows, via FRESH endpoint calls, AFTER every
    //    insertion — proves the later insertions (which forced the overflow
    //    growth) did not corrupt any EARLIER row, including the pre-upgrade one.
    assert_eq!(h.wrapped_secret(env_owner_1, &env_dev_1.id), Ok(env_envelope_384), "row 1 (384B, pre-upgrade)");
    assert_eq!(h.wrapped_secret(env_owner_1, &env_dev_2.id), Ok(envelope_627_a), "row 2 (627B)");
    assert_eq!(h.wrapped_secret(env_owner_1, &env_dev_3.id), Ok(envelope_1024), "row 3 (1024B)");
    assert_eq!(h.wrapped_secret(env_owner_1, &env_dev_4.id), Ok(envelope_627_b), "row 4 (627B)");
    assert_eq!(h.wrapped_secret(env_owner_1, &env_dev_5.id), Ok(envelope_627_c), "row 5 (627B)");
    assert_eq!(h.wrapped_secret(env_owner_2, &env_owner_2_dev_1.id), Ok(envelope_627_d), "row 6 (627B)");
    assert_eq!(h.wrapped_secret(env_owner_2, &env_owner_2_dev_2.id), Ok(envelope_627_e), "row 7 (627B)");
    assert_eq!(h.wrapped_secret(env_owner_2, &env_owner_2_dev_3.id), Ok(envelope_627_f), "row 8 (627B) — the overflow witness is complete");

    // ── Closing derive accounting — the registration burst performs ZERO
    //    vetKD derives; only ENV_OWNER_2's `h.bootstrap` derived. That bootstrap
    //    first advanced the clock past the meter hour (3601s), so the rolling
    //    one-hour global window has dropped every earlier dispatch: exactly ONE
    //    entry (ENV_OWNER_2's) remains. LITERAL FROM THE LIVE RUN (v3 §C.3 note;
    //    builder-blocker ruling 2026-09-23) — v3's `after_b.consumed + 1`
    //    omitted ENV_OWNER_1's remaining-check derive and the window roll.
    let final_stats = h.derive_budget_stats();
    assert_eq!(
        final_stats.consumed, 1,
        "only ENV_OWNER_2's bootstrap derive remains inside the rolling hour"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// LAUNCH-HARDEN-04 — O-1(b) `has_active_device` (MemoryId 20), O-3 per-principal
// hourly derive cap, O-8 "require device approval" flag (MemoryId 19)
// ═════════════════════════════════════════════════════════════════════════════
//
// Mirrors declared INDEPENDENTLY of the canister crate, like every mirror in
// this file: a renamed variant or field decodes as an error here rather than
// agreeing with the code under test.

#[derive(CandidType, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceCheckRefusal {
    CallerNotConfigured,
    CallerNotAuthorized,
}

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
struct DeviceApprovalPolicyView {
    require_device_approval: bool,
    set_at_ns: u64,
    pending_clear_effective_at_ns: Option<u64>,
}

const ACTION_SET_DEVICE_APPROVAL_POLICY: &[u8] = b"set_device_approval_policy";

/// Independent re-implementation of `SetDeviceApprovalPolicyV1::encode` from
/// the brief's field list (the canister's `transcript` module is not imported).
fn set_policy_transcript(
    canister: Principal,
    owner: Principal,
    issuer: &str,
    require: bool,
    nonce: [u8; 16],
    expiry_ns: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    var(&mut out, PROTOCOL);
    out.extend_from_slice(&1u16.to_le_bytes());
    var(&mut out, canister.as_slice());
    var(&mut out, ACTION_SET_DEVICE_APPROVAL_POLICY);
    var(&mut out, owner.as_slice());
    var(&mut out, issuer.as_bytes());
    out.push(require as u8);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&expiry_ns.to_le_bytes());
    out
}

/// The DEVICE_APPROVAL_REQUIRED reason's stable prefix (lib.rs).
const DEVICE_APPROVAL_REQUIRED_PREFIX: &str =
    "this principal requires an existing device to approve new devices";

impl Harness {
    fn device_check_caller(&self) -> Option<Principal> {
        decode(
            "get_device_check_caller",
            self.pic.query_call(
                self.vetkeys_id,
                Principal::anonymous(),
                "get_device_check_caller",
                candid::encode_args(()).unwrap(),
            ),
        )
    }

    fn has_active_device_as(
        &self,
        caller: Principal,
        principal: Principal,
    ) -> Result<bool, DeviceCheckRefusal> {
        decode(
            "has_active_device",
            self.pic.query_call(
                self.vetkeys_id,
                caller,
                "has_active_device",
                candid::encode_one(principal).unwrap(),
            ),
        )
    }

    fn policy_approval_from(
        &self,
        issuer: &TestDevice,
        owner: Principal,
        require: bool,
        nonce: [u8; 16],
        expiry_ns: u64,
    ) -> SignedApproval {
        let msg = set_policy_transcript(self.vetkeys_id, owner, &issuer.id, require, nonce, expiry_ns);
        SignedApproval {
            issuer_device_id: issuer.id.clone(),
            nonce: nonce.to_vec(),
            expiry_ns,
            signature: issuer.sign(&msg),
        }
    }

    fn set_policy(
        &self,
        user: Principal,
        require: bool,
        approval: SignedApproval,
    ) -> Result<(), VetkeysError> {
        decode(
            "set_device_approval_policy",
            self.pic.update_call(
                self.vetkeys_id,
                user,
                "set_device_approval_policy",
                candid::encode_args((require, approval)).unwrap(),
            ),
        )
    }

    fn request_policy_clear(&self, user: Principal) -> Result<u64, VetkeysError> {
        decode(
            "request_device_approval_policy_clear",
            self.pic.update_call(
                self.vetkeys_id,
                user,
                "request_device_approval_policy_clear",
                candid::encode_args(()).unwrap(),
            ),
        )
    }

    fn policy(&self, user: Principal) -> Option<DeviceApprovalPolicyView> {
        decode(
            "device_approval_policy",
            self.pic.query_call(
                self.vetkeys_id,
                user,
                "device_approval_policy",
                candid::encode_args(()).unwrap(),
            ),
        )
    }

    /// Move the clock to exactly `target_ns` (must be in the future).
    fn advance_to(&self, target_ns: u64) {
        let now = self.now_ns();
        assert!(target_ns > now, "advance_to: target {target_ns} is not after now {now}");
        self.pic.advance_time(std::time::Duration::from_nanos(target_ns - now));
        self.pic.tick();
    }
}

fn bootstrap_refusal_reason(r: Result<(), VetkeysError>) -> String {
    match r {
        Err(VetkeysError::BootstrapNotAuthorized { reason }) => reason,
        other => panic!("expected BootstrapNotAuthorized, got {other:?}"),
    }
}

/// Mainnet principals of the Vault Upgrade packet (canister_ids.json).
const MAINNET_POOL: &str = "cxrfg-qaaaa-aaaar-qchfa-cai";

// ── O-1(b) ───────────────────────────────────────────────────────────────────

/// LAUNCH-HARDEN-04 O-1(b) PocketIC arm (C-1(6)): MemoryId 20 absent → refuse;
/// configured via the TYPED upgrade arg (the production packet shape); wrong
/// caller refused; revoked → Ok(false); routine upgrade preserves; anonymous
/// arg traps and preserves; a fresh 3-arg install configures.
#[test]
fn harden04_o1b_has_active_device_is_answered_only_to_the_configured_pool() {
    let h = setup();
    let user = p(0x71);
    let other = p(0x72);
    let d1 = TestDevice::new("device-1", 0x71);
    h.bootstrap(user, &d1, envelope(0x71));

    // (i) setup() installs ("test_key_1", Some(token)) — no third arg — so
    // MemoryId 20 is ABSENT and every caller is refused, never answered.
    assert_eq!(h.device_check_caller(), None);
    assert_eq!(
        h.has_active_device_as(h.pool, user),
        Err(DeviceCheckRefusal::CallerNotConfigured),
        "an unconfigured canister must REFUSE, never answer Ok(false)/Ok(true)"
    );

    // (ii) the production packet arg shape: (null, opt pool).
    h.pic
        .upgrade_canister(
            h.vetkeys_id,
            vetkeys_wasm(),
            candid::encode_args((None::<Principal>, Some(h.pool))).unwrap(),
            None,
        )
        .expect("the typed (null, opt principal) upgrade must succeed");
    assert_eq!(h.device_check_caller(), Some(h.pool));
    assert_eq!(h.configured_token(), Some(h.token_id), "the None first arg PRESERVED the token");
    assert_eq!(h.has_active_device_as(h.pool, user), Ok(true));

    // (iii) any other caller learns nothing.
    assert_eq!(
        h.has_active_device_as(other, user),
        Err(DeviceCheckRefusal::CallerNotAuthorized)
    );
    assert_eq!(
        h.has_active_device_as(Principal::anonymous(), user),
        Err(DeviceCheckRefusal::CallerNotAuthorized)
    );
    assert_eq!(h.has_active_device_as(h.pool, other), Ok(false), "a never-enrolled principal");

    // (iv) revoke D1 → zero ACTIVE devices → Ok(false).
    h.revoke_to_zero(user, &d1, [0x71; 16]);
    assert_eq!(h.has_active_device_as(h.pool, user), Ok(false));

    // (v) a routine no-arg upgrade PRESERVES the cell.
    h.pic
        .upgrade_canister(h.vetkeys_id, vetkeys_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("routine upgrade");
    assert_eq!(h.device_check_caller(), Some(h.pool), "None/absent preserves");
    // (v-b) and the pre-existing one-opt shape preserves it too.
    h.upgrade_with(None);
    assert_eq!(h.device_check_caller(), Some(h.pool));

    // (vi) anonymous / self are refused by TRAPPING the upgrade: nothing is
    // written, and the old module still serves.
    for bad in [Principal::anonymous(), h.vetkeys_id] {
        let r = h.pic.upgrade_canister(
            h.vetkeys_id,
            vetkeys_wasm(),
            candid::encode_args((None::<Principal>, Some(bad))).unwrap(),
            None,
        );
        assert!(r.is_err(), "device_check_caller = {bad} must trap the upgrade");
        assert_eq!(h.device_check_caller(), Some(h.pool), "stored caller unchanged");
        assert_eq!(h.has_active_device_as(h.pool, user), Ok(false), "the old module still serves");
    }

    // (vii) a fresh 3-arg install configures the cell directly.
    let fresh = h.pic.create_canister();
    h.pic.add_cycles(fresh, 1_000_000_000_000_000);
    h.pic.install_canister(
        fresh,
        vetkeys_wasm(),
        candid::encode_args(("test_key_1".to_string(), Some(h.token_id), Some(h.pool))).unwrap(),
        None,
    );
    let got: Option<Principal> = decode(
        "get_device_check_caller",
        h.pic.query_call(fresh, Principal::anonymous(), "get_device_check_caller", candid::encode_args(()).unwrap()),
    );
    assert_eq!(got, Some(h.pool));
    // An anonymous init arg traps `#[init]` (driven through a REINSTALL, which
    // runs `#[init]` and returns the result instead of panicking).
    let bad = h.pic.create_canister();
    h.pic.add_cycles(bad, 1_000_000_000_000_000);
    h.pic.install_canister(
        bad,
        vetkeys_wasm(),
        candid::encode_args(("test_key_1".to_string(), Some(h.token_id))).unwrap(),
        None,
    );
    let r = h.pic.reinstall_canister(
        bad,
        vetkeys_wasm(),
        candid::encode_args(("test_key_1".to_string(), Some(h.token_id), Some(Principal::anonymous())))
            .unwrap(),
        None,
    );
    assert!(r.is_err(), "an anonymous device_check_caller must trap the install");
}

/// LAUNCH-HARDEN-04 §R — the EXACT vetkeys Vault-Upgrade arg bytes of the
/// packet, recomputed from these mirrors AND applied byte-for-byte on a real
/// upgrade: the stored caller reads back as the mainnet pool.
#[test]
fn harden04_packet_vetkeys_upgrade_arg_bytes_are_exact_and_apply() {
    let pool = Principal::from_text(MAINNET_POOL).unwrap();
    let bytes = candid::encode_args((None::<Principal>, Some(pool))).unwrap();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "4449444c016e680200000001010a00000000023011ca0101");
    let digest: String = sha256(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(digest, "d7641821f27452d3223de8780c958aa544c543700eb27bd52b55010ca11c749d");

    let h = setup();
    h.pic
        .upgrade_canister(h.vetkeys_id, vetkeys_wasm(), bytes, None)
        .expect("the packet's exact arg bytes must upgrade cleanly");
    assert_eq!(h.device_check_caller(), Some(pool));
    assert_eq!(h.configured_token(), Some(h.token_id), "the null first element preserves the token");
}

// ── O-3 ──────────────────────────────────────────────────────────────────────

/// LAUNCH-HARDEN-04 O-3 PocketIC arm: one principal's THIRD derive inside one
/// hour is refused with the per-principal variant; an hour later a derive
/// succeeds, and its `remaining` proves the refused call consumed no §H′ quota.
#[test]
fn harden04_o3_third_derive_in_an_hour_hits_the_per_principal_cap() {
    let h = setup();
    let user = p(0x73);
    h.age_in_all(&[user]);
    h.skip_the_meter_window();

    let r1 = h
        .try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x01))
        .expect("derive 1");
    assert_eq!(r1.remaining, 4);
    let r2 = h
        .try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x02))
        .expect("derive 2");
    assert_eq!(r2.remaining, 3);
    match h.try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x03)) {
        Err(VetkeysError::PrincipalHourlyDerivationCapExceeded { retry_after_ns }) => {
            assert!(retry_after_ns > 0 && retry_after_ns <= 3_600_000_000_000, "{retry_after_ns}");
        }
        other => panic!("the third derive inside one hour must hit the per-principal cap; got {other:?}"),
    }
    // Another principal is unaffected (the cap is per-principal, not fleet).
    let other = p(0x74);
    h.age_in_all(&[other]);
    // (age_in_all advanced T; the first user's entries are still in-window.)
    h.try_get_encrypted_vetkey_raw(other, Harness::valid_transport_key(0x04))
        .expect("another principal is not affected by this one's cap");

    // One hour later: admitted, and the refused call did not consume §H′.
    h.skip_the_meter_window();
    let r4 = h
        .try_get_encrypted_vetkey_raw(user, Harness::valid_transport_key(0x05))
        .expect("the rolled hour must admit the principal again");
    assert_eq!(
        r4.remaining, 2,
        "3 dispatches committed in 24 h → remaining 2; the fence-refused call consumed nothing"
    );
}

// ── O-8 ──────────────────────────────────────────────────────────────────────

/// (a) + (b): set immediately; the next derive mints no ticket; a Bootstrap is
/// refused with the flag's OWN reason; an existing device can still approve.
#[test]
fn harden04_o8_a_b_flag_blocks_bootstrap_but_not_device_approval() {
    let h = setup();
    let user = p(0x81);
    let d1 = TestDevice::new("device-1", 0x81);
    h.bootstrap(user, &d1, envelope(0x81));
    assert_eq!(h.policy(user), None, "flag off by default");

    let sig = h.policy_approval_from(&d1, user, true, [0x81; 16], live_expiry(&h));
    h.set_policy(user, true, sig).expect("an ACTIVE device may set the flag");
    let pol = h.policy(user).expect("the flag is set");
    assert!(pol.require_device_approval);
    assert_eq!(pol.pending_clear_effective_at_ns, None);

    // A derive still returns the key, but mints no ticket.
    h.derive_past_the_meter(user, 0x82).expect("the derive itself succeeds");
    let d2 = TestDevice::new("device-2", 0x82);
    let reason =
        bootstrap_refusal_reason(h.register(user, &d2, envelope(0x82), DeviceApproval::Bootstrap));
    assert!(reason.starts_with(DEVICE_APPROVAL_REQUIRED_PREFIX), "{reason}");

    // (b) the flag does NOT block an existing device's approval.
    let env = envelope(0x83);
    let appr = h.approval_from(&d1, user, &d2, &env, [0x83; 16], live_expiry(&h));
    h.register(user, &d2, env, DeviceApproval::Device(appr))
        .expect("an ACTIVE device may still approve a new device");
    assert_eq!(h.devices(user).iter().filter(|d| d.active).count(), 2);

    // Mint-time half: clear (device-signed, immediate) WITHOUT a new derive —
    // the derive above minted no ticket, so Bootstrap still fails on the ticket.
    let clr = h.policy_approval_from(&d1, user, false, [0x84; 16], live_expiry(&h));
    h.set_policy(user, false, clr).expect("device-signed clear");
    let d3 = TestDevice::new("device-3", 0x85);
    let reason =
        bootstrap_refusal_reason(h.register(user, &d3, envelope(0x85), DeviceApproval::Bootstrap));
    assert!(
        !reason.starts_with(DEVICE_APPROVAL_REQUIRED_PREFIX),
        "the flag is clear, so the refusal must be the TICKET's (none was minted): {reason}"
    );
}

/// (c): the flag cannot be set from zero devices.
#[test]
fn harden04_o8_c_zero_device_principal_cannot_set_the_flag() {
    let h = setup();
    let user = p(0x86);
    let ghost = TestDevice::new("device-1", 0x86);
    let sig = h.policy_approval_from(&ghost, user, true, [0x86; 16], live_expiry(&h));
    match h.set_policy(user, true, sig) {
        Err(VetkeysError::ApprovalRejected(_)) => {}
        other => panic!("a zero-device principal must be refused, got {other:?}"),
    }
    assert_eq!(h.policy(user), None);
}

/// (d): a device-signed clear is IMMEDIATE (CTO Addendum 2 V-3b): at the same
/// instant the row is gone and a live ticket enrols.
#[test]
fn harden04_o8_d_device_signed_clear_is_immediate() {
    let h = setup();
    let user = p(0x87);
    let d1 = TestDevice::new("device-1", 0x87);
    h.bootstrap(user, &d1, envelope(0x87));
    // Mint a live ticket while the flag is off.
    h.derive_past_the_meter(user, 0x88).expect("derive mints a ticket");
    let set = h.policy_approval_from(&d1, user, true, [0x87; 16], live_expiry(&h));
    h.set_policy(user, true, set).expect("set");
    let d2 = TestDevice::new("device-2", 0x88);
    let reason =
        bootstrap_refusal_reason(h.register(user, &d2, envelope(0x88), DeviceApproval::Bootstrap));
    assert!(reason.starts_with(DEVICE_APPROVAL_REQUIRED_PREFIX), "consume-time gate: {reason}");

    // No time advance between the clear and the checks.
    let clr = h.policy_approval_from(&d1, user, false, [0x88; 16], live_expiry(&h));
    h.set_policy(user, false, clr).expect("device-signed clear");
    assert_eq!(h.policy(user), None, "the row is DELETED immediately");
    h.register(user, &d2, envelope(0x88), DeviceApproval::Bootstrap)
        .expect("with the flag cleared, the still-live ticket enrols at the same instant");

    // Idempotent: a second clear with no row is Ok, and burns its nonce.
    let clr2 = h.policy_approval_from(&d1, user, false, [0x89; 16], live_expiry(&h));
    h.set_policy(user, false, clr2.clone()).expect("idempotent clear");
    match h.set_policy(user, false, clr2) {
        Err(VetkeysError::ApprovalRejected(r)) => assert!(r.contains("already been used"), "{r}"),
        other => panic!("the idempotent clear must still consume its nonce: {other:?}"),
    }
}

/// (e): the II-only request returns t, never resets or extends, and the flag
/// lapses at t (the ns-exact boundary is the native truth table; PocketIC rounds
/// move the clock, so the refusal is probed just before t and the open path at t).
#[test]
fn harden04_o8_e_ii_only_clear_takes_effect_after_24h() {
    let h = setup();
    let user = p(0x8A);
    let d1 = TestDevice::new("device-1", 0x8A);
    h.bootstrap(user, &d1, envelope(0x8A));
    // No row → typed refusal.
    match h.request_policy_clear(user) {
        Err(VetkeysError::InvalidRequest(r)) => assert!(r.contains("no device-approval policy"), "{r}"),
        other => panic!("no row must refuse: {other:?}"),
    }
    let set = h.policy_approval_from(&d1, user, true, [0x8A; 16], live_expiry(&h));
    h.set_policy(user, true, set).expect("set");

    let before = h.now_ns();
    let t = h.request_policy_clear(user).expect("II-only request");
    let day: u64 = 24 * 60 * 60 * 1_000_000_000;
    assert!(t >= before + day && t <= h.now_ns() + day, "t = request time + 24 h");
    h.pic.advance_time(std::time::Duration::from_secs(60));
    assert_eq!(h.request_policy_clear(user), Ok(t), "a second request returns the SAME t");
    assert_eq!(h.policy(user).unwrap().pending_clear_effective_at_ns, Some(t));

    // Shortly before t: still refused (derive mints nothing, consume refuses).
    h.advance_to(t - 5_000_000_000);
    h.try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(0x8B))
        .expect("derive works throughout");
    let d2 = TestDevice::new("device-2", 0x8B);
    let reason =
        bootstrap_refusal_reason(h.register(user, &d2, envelope(0x8B), DeviceApproval::Bootstrap));
    assert!(reason.starts_with(DEVICE_APPROVAL_REQUIRED_PREFIX), "{reason}");

    // At/after t: the flag has lapsed — derive mints a ticket, Bootstrap enrols.
    h.advance_to(t);
    h.try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(0x8C))
        .expect("derive at t");
    h.register(user, &d2, envelope(0x8B), DeviceApproval::Bootstrap)
        .expect("the matured II-only clear re-opens Bootstrap");
}

/// (f): a held device CANCELS a pending II-only clear by re-setting `true`.
#[test]
fn harden04_o8_f_device_reset_cancels_a_pending_clear() {
    let h = setup();
    let user = p(0x8D);
    let d1 = TestDevice::new("device-1", 0x8D);
    h.bootstrap(user, &d1, envelope(0x8D));
    let set = h.policy_approval_from(&d1, user, true, [0x8D; 16], live_expiry(&h));
    h.set_policy(user, true, set).expect("set");
    let t = h.request_policy_clear(user).expect("II-only request");
    let reset = h.policy_approval_from(&d1, user, true, [0x8E; 16], live_expiry(&h));
    h.set_policy(user, true, reset).expect("device re-set cancels");
    assert_eq!(h.policy(user).unwrap().pending_clear_effective_at_ns, None);

    h.advance_to(t + 60_000_000_000);
    h.try_get_encrypted_vetkey_typed(user, Harness::valid_transport_key(0x8E)).expect("derive");
    let d2 = TestDevice::new("device-2", 0x8E);
    let reason =
        bootstrap_refusal_reason(h.register(user, &d2, envelope(0x8E), DeviceApproval::Bootstrap));
    assert!(reason.starts_with(DEVICE_APPROVAL_REQUIRED_PREFIX), "cancelled clear: {reason}");
}

/// (g): revoked-to-zero with the flag set behaves EXACTLY like L04-07 — the
/// flag is ignored in the zero-active branch and the refusal names L04-07.
#[test]
fn harden04_o8_g_revoked_to_zero_is_the_l04_07_rule_not_the_flag() {
    let h = setup();
    let user = p(0x8F);
    let d1 = TestDevice::new("device-1", 0x8F);
    h.bootstrap(user, &d1, envelope(0x8F));
    let set = h.policy_approval_from(&d1, user, true, [0x8F; 16], live_expiry(&h));
    h.set_policy(user, true, set).expect("set");
    h.revoke_to_zero(user, &d1, [0x90; 16]);
    h.derive_past_the_meter(user, 0x90).expect("derive");
    let d2 = TestDevice::new("device-2", 0x90);
    let reason =
        bootstrap_refusal_reason(h.register(user, &d2, envelope(0x90), DeviceApproval::Bootstrap));
    assert!(reason.contains("every device of this principal has been revoked"), "{reason}");
    assert!(!reason.starts_with(DEVICE_APPROVAL_REQUIRED_PREFIX), "{reason}");
}

/// (h): a captured `set_device_approval_policy` signature cannot be replayed.
#[test]
fn harden04_o8_h_policy_signature_replay_is_refused() {
    let h = setup();
    let user = p(0x91);
    let d1 = TestDevice::new("device-1", 0x91);
    h.bootstrap(user, &d1, envelope(0x91));
    let sig = h.policy_approval_from(&d1, user, true, [0x91; 16], live_expiry(&h));
    h.set_policy(user, true, sig.clone()).expect("first use");
    match h.set_policy(user, true, sig.clone()) {
        Err(VetkeysError::ApprovalRejected(r)) => assert!(r.contains("already been used"), "{r}"),
        other => panic!("replay must be refused: {other:?}"),
    }
    // And a `true` signature cannot be replayed as `false` (the flag byte is signed).
    let sig2 = h.policy_approval_from(&d1, user, true, [0x92; 16], live_expiry(&h));
    match h.set_policy(user, false, sig2) {
        Err(VetkeysError::ApprovalRejected(_)) => {}
        other => panic!("a set signature must not verify as a clear: {other:?}"),
    }
    assert!(h.policy(user).unwrap().require_device_approval);
}

/// The LIVE a7l2d module at the time of LAUNCH-HARDEN-04 (144fb314, installed
/// by Vault #27; byte-identical to a build of master 6709af8). Hash-checked here
/// independently of any shell gate (the C-3 loader discipline).
const LIVE_144FB314_SHA256: &str =
    "144fb314026c51a04beec8a686c2cd0e78ab79ef6682154bc7ee5ab4caff0ba7";

fn live_144fb314_wasm() -> Vec<u8> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/wasm32-unknown-unknown/release/vetkeys_live_a7l2d_144fb314_test.wasm"
    );
    let bytes = std::fs::read(p).unwrap_or_else(|e| {
        panic!(
            "vetkeys_live_a7l2d_144fb314_test.wasm not found ({e}) — this test needs the GENUINE \
             live a7l2d module (144fb314), built from master 6709af8:\n  \
             git worktree add --detach /tmp/stsh-vetkeys-144fb314 6709af8 && \
             (cd /tmp/stsh-vetkeys-144fb314 && CARGO_TARGET_DIR=/tmp/stsh-vetkeys-144fb314/target \
             cargo build --manifest-path canisters/vetkeys/Cargo.toml --target \
             wasm32-unknown-unknown --release --locked) && cp \
             /tmp/stsh-vetkeys-144fb314/target/wasm32-unknown-unknown/release/stsh_vetkeys.wasm \
             canisters/vetkeys/target/wasm32-unknown-unknown/release/\
vetkeys_live_a7l2d_144fb314_test.wasm\n  expected sha256: {LIVE_144FB314_SHA256}"
        )
    });
    let actual: String = sha256(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(actual, LIVE_144FB314_SHA256, "vetkeys_live_a7l2d_144fb314_test.wasm has the WRONG hash");
    bytes
}

/// (i): an upgrade from the LIVE 144fb314 module — MemoryId 19 empty, MemoryId
/// 20 absent — preserves every enrolled device, and the new surfaces work.
#[test]
fn harden04_o8_i_upgrade_from_the_live_144fb314_module() {
    let live = live_144fb314_wasm();
    assert_ne!(live, vetkeys_wasm(), "the fixture must differ from the current-source build");

    let pic = PocketIcBuilder::new()
        .with_ii_subnet()
        .with_application_subnet()
        .with_nonmainnet_features(true)
        .build();
    let token_id = install_mock_token(&pic, mock_token_wasm(RICH_BALANCE_E8S));
    let vetkeys_id = pic.create_canister();
    pic.add_cycles(vetkeys_id, 1_000_000_000_000_000);
    pic.install_canister(
        vetkeys_id,
        live,
        candid::encode_args(("test_key_1".to_string(), Some(token_id))).unwrap(),
        None,
    );
    let merkle_id = pic.create_canister();
    pic.add_cycles(merkle_id, 2_000_000_000_000);
    let pool = p(0x05);
    pic.install_canister(merkle_id, merkle_wasm(), candid::encode_one(pool).unwrap(), None);
    let h = Harness { pic, vetkeys_id, merkle_id, pool, token_id };

    let user = p(0x93);
    let d1 = TestDevice::new("device-1", 0x93);
    h.bootstrap(user, &d1, envelope(0x93));

    // Routine (no-arg) upgrade onto this lane's module.
    h.pic
        .upgrade_canister(h.vetkeys_id, vetkeys_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("upgrade from the live module");
    assert_eq!(h.policy(user), None, "MemoryId 19 starts empty: flag off for every principal");
    assert_eq!(h.device_check_caller(), None, "MemoryId 20 starts absent");
    assert_eq!(h.has_active_device_as(h.pool, user), Err(DeviceCheckRefusal::CallerNotConfigured));
    assert_eq!(h.wrapped_secret(user, &d1.id), Ok(envelope(0x93)), "the enrolled device survives");
    assert_eq!(h.configured_token(), Some(token_id));

    // Then the packet-shaped configuring upgrade, and the new surfaces work.
    h.pic
        .upgrade_canister(
            h.vetkeys_id,
            vetkeys_wasm(),
            candid::encode_args((None::<Principal>, Some(h.pool))).unwrap(),
            None,
        )
        .expect("configuring upgrade");
    assert_eq!(h.has_active_device_as(h.pool, user), Ok(true));
    let set = h.policy_approval_from(&d1, user, true, [0x93; 16], live_expiry(&h));
    h.set_policy(user, true, set).expect("the flag works on the upgraded canister");
    assert!(h.policy(user).unwrap().require_device_approval);
}
