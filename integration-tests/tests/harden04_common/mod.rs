// =============================================================================
// LAUNCH-HARDEN-04 — shared PocketIC harness for the pool arms
// (harden04_spend_admission_tests, harden04_vk_revalidation_tests).
//
// A `mod.rs` under a directory is NOT an integration-test target of its own;
// each suite pulls it in with `mod harden04_common;`.
//
// Deposit/anchor setup is copied from `full_path_private_spend_benchmark.rs`:
// the real Groth16 fixture (circuits/proof.json + public.json) spends
// IN_COMMITMENT, seeded by one `shield_deposit`. The fixture carries ONE
// nullifier, so one VALID spend per instance; junk spends use fresh nullifiers.
// =============================================================================
#![allow(dead_code)]

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {pkg} Wasm at {path}: {e}"))
}
pub fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }
pub fn pool_wasm() -> Vec<u8> { load_wasm(env!("POOL_WASM"), "shielded_pool") }
pub fn pool_test_wasm() -> Vec<u8> { load_wasm(env!("POOL_TEST_WASM"), "shielded_pool_test") }
pub fn nullifier_wasm() -> Vec<u8> { load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry") }
pub fn merkle_wasm() -> Vec<u8> { load_wasm(env!("MERKLE_WASM"), "merkle_tree") }
pub fn verifier_wasm() -> Vec<u8> { load_wasm(env!("VERIFIER_WASM"), "stsh_verifier") }
pub fn stub_verifier_wasm() -> Vec<u8> { load_wasm(env!("STUB_VERIFIER_WASM"), "stsh_stub_verifier") }

/// The LIVE cxrfg pool module before this lane — the pre-LAUNCH-HARDEN-04
/// `[wasm.shielded_pool]` pin (5fa7176e…, byte-identical to the staged A-7
/// artifact ~/a7-kit/shielded_pool.wasm). Hash-checked here, for the
/// pre-change CONTRAST arms (T9, VK in-place swap).
pub const LIVE_POOL_SHA256: &str =
    "5fa7176e15548db1740fa184842db279b10f5621e1d9400a641caccc82910dc5";

pub fn live_pool_wasm() -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let path = std::path::Path::new(env!("POOL_WASM"))
        .with_file_name("shielded_pool_live_cxrfg_5fa7176e.wasm");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{} not found ({e}) — the pre-change contrast arms need the GENUINE live cxrfg \
             pool module (5fa7176e — the pre-LAUNCH-HARDEN-04 [wasm.shielded_pool] pin, \
             byte-identical to the staged A-7 artifact). Place it with:\n  \
             cp ~/a7-kit/shielded_pool.wasm {}\n  expected sha256: {LIVE_POOL_SHA256}",
            path.display(),
            path.display()
        )
    });
    let got: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(got, LIVE_POOL_SHA256, "live pool fixture has the WRONG hash");
    bytes
}

pub const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
pub const DEPOSIT_AMOUNT: u128 = 1_000 * 100_000_000;
pub const IN_COMMITMENT: [u8; 32] = [
    0xd2, 0x6f, 0x9b, 0xb7, 0x36, 0x0a, 0xed, 0x7f,
    0x09, 0x18, 0xe7, 0x27, 0x12, 0x3c, 0x86, 0x90,
    0xe2, 0x71, 0xb0, 0x5b, 0x6c, 0xb4, 0x52, 0xfc,
    0x6f, 0x05, 0x3a, 0xd4, 0xa1, 0x18, 0xdc, 0x0b,
];

pub const USER: u8 = 0xB0;
pub const CONTROLLER: u8 = 0x06;
pub const GOVERNANCE: u8 = 0x02;

pub fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy { ImmediatelyLiquid, LockedUntil(u64), Vested, GovernanceLocked }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy { cliff_end_ns: u64, vesting_end_ns: u64 }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct AllocationCategory {
    category_id: String,
    category_name: String,
    amount: u128,
    recipient: Principal,
    subaccount: Option<[u8; 32]>,
    lock_policy: LockPolicy,
    vesting_policy: Option<VestingPolicy>,
    created_at_genesis: bool,
    genesis_timestamp_ns: u64,
}
#[derive(CandidType, Deserialize)]
struct TokenInitArgs { allocations: Vec<AllocationCategory>, treasury: Principal, staking_canister: Principal }

#[derive(CandidType, Deserialize)]
pub struct PoolInitArgs {
    pub token_canister: Principal,
    pub nullifier_canister: Principal,
    pub merkle_canister: Principal,
    pub treasury_canister: Principal,
    pub staking_canister: Principal,
    pub controller: Principal,
    pub initial_vk_hash: [u8; 32],
    pub initial_proof_system: String,
    pub verifier_canister: Option<Principal>,
}

/// Mirror of the pool's `PoolUpgradeArg` (LAUNCH-HARDEN-04 O-1(b)).
#[derive(CandidType, Deserialize)]
pub struct PoolUpgradeArg { pub vetkeys_canister: Option<Principal> }

/// Mirror of vetkeys/pool `DeviceCheckRefusal`.
#[derive(CandidType, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCheckRefusal { CallerNotConfigured, CallerNotAuthorized }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ProofEnvelope {
    pub circuit_version: u32,
    pub proof_system_id: String,
    pub verifying_key_hash: [u8; 32],
    pub root_reference: [u8; 32],
    pub pool_version: u32,
    pub proof_bytes: Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ShieldDepositArgs { note_commitment: [u8; 32], encrypted_payload: Vec<u8>, public_amount: u128 }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct PrivateSpendArgs {
    pub spend_id: u64,
    pub envelope: ProofEnvelope,
    pub nullifiers: Vec<[u8; 32]>,
    pub output_commitments: Vec<[u8; 32]>,
    pub encrypted_outputs: Vec<Vec<u8>>,
    pub fee: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SpendStatus {
    Requested,
    OutputsStaged,
    Finalized,
    FailedBeforeStateChange { reason: String },
    FailedAfterOutputsStaged { reason: String },
    VerificationPending,
    NullifierReserved,
    PayoutPending { reason: String },
    PayoutSubmitting,
    PayoutUnknown { reason: String },
    NullifierInsertUnknown { reason: String },
    NullifierFinalizedOutputsPending,
    ActiveAppendInFlight,
    ActiveAppendUnknown { reason: String },
    ActiveAppendRejected { reason: String },
    ActiveRootPending,
    RootAccepted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct PendingSpend {
    pub spend_id: u64,
    pub status: SpendStatus,
}

/// FULL mirror of the pool DID's `PoolError` (every variant, so any refusal decodes).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PoolError {
    InvalidDenomination,
    InvalidProof,
    NullifierAlreadySpent,
    NullifierReserved,
    AnchorNotFound,
    EscrowUnderfunded { required: Nat, available: Nat },
    InsufficientEscrowCoverage { requested: Nat, available: Nat },
    CircuitVersionMismatch { expected: u32, got: u32 },
    VerifyingKeyMismatch,
    PoolVersionMismatch,
    ProofSystemMismatch,
    TransferFailed(String),
    AmountBelowLedgerFee { amount: Nat, fee: Nat },
    BelowMinimumDeposit { public_amount: Nat, minimum: Nat },
    InsufficientOperationsReserve { needed: Nat, available: Nat },
    InvariantViolationDuplicateNullifier,
    Paused,
    RecoveryInProgress(String),
    SolvencyCheckFailed,
    DuplicateWithdrawalId,
    NotInitialised,
    CommitmentAppendFailed(String),
    DepositCommitmentPending,
    SumMismatch { inputs: Nat, outputs: Nat },
    SumOverflow,
    MalformedSpendArgs,
    DuplicateOutputCommitment,
    InvalidOutputCommitment,
    DuplicateSpendId,
    DeploymentConfigMismatch,
    SpendFeeNotSupported,
    VerifierUnavailable(String),
    ProofRejected(String),
    InvalidVerifierKeyHashLength { len: u64 },
    VerifierKeyHashMismatch,
    VerifierKeyHashChangedDuringAttestation,
    VerifierConfigInProgress,
    PrivateSpendFeeMismatch { expected: Nat, got: Nat },
    InsufficientPrivateLiability { required: Nat, available: Nat },
    WithdrawalBelowMinimum { withdraw_gross_amount: Nat, minimum_withdrawal_gross: Nat },
    GrossAmountBelowFees { withdraw_gross_amount: Nat, total_fee: Nat },
    RecipientBelowMinimum { recipient_net_amount: Nat, minimum_recipient_amount: Nat },
    IdempotencyKeyConflict,
    EncryptedPayloadTooLarge { len: u64, max: u64 },
    EncryptedOutputTooLarge { index: u32, len: u64, max: u64 },
    InvalidProofLength { len: u64, expected: u64 },
    DepositTransferNotConfirmed,
    DepositAppendInProgress,
    DepositAppendUnknown,
    DepositAlreadyCompleted,
    PayoutNotPending,
    PayoutOutcomeUnknown,
    PayoutOutcomePrivate,
    PayoutExecutorBusy,
    PayoutMemoKeyNotReady,
    PayoutLegacyHold,
    PayoutStateInvalid,
    SpendNotFound,
    WrongSpendStatus,
    DisbursementNotFound,
    DisbursementNotReconcilable,
    DisbursementProposalIdRetired,
    PartialNullifierInsert { present: u32, absent: u32, total: u32 },
    OutputAppendUnknown,
    OutputAppendRejected(String),
    AmbiguousMerkleState,
    StagedOutputsMissing,
    InvalidCommitment,
    DepositNotFound,
    DepositNotReconcilable,
    AnonymousCaller,
    WithdrawalNotFound,
    WrongWithdrawalStatus,
    Unauthorized,
    WithdrawalPayoutObligation,
    SecurityEpochChanged,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct Account { owner: Principal, subaccount: Option<[u8; 32]> }
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ApproveArgs {
    from_subaccount: Option<[u8; 32]>,
    spender: Account,
    amount: Nat,
    expected_allowance: Option<Nat>,
    expires_at: Option<u64>,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

pub fn decode<T: CandidType + for<'de> serde::Deserialize<'de>>(
    label: &str,
    r: Result<Vec<u8>, pocket_ic::RejectResponse>,
) -> T {
    let bytes = r.unwrap_or_else(|e| panic!("{label}: call rejected: {e:?}"));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{label}: decode failed: {e}"))
}

fn circuits_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("circuits")
}

/// The real-proof fixture as a `PrivateSpendArgs` template (verifying-key hash
/// = the compiled VK's sha256).
pub fn fixture() -> PrivateSpendArgs {
    let public_json = std::fs::read_to_string(circuits_dir().join("public.json"))
        .expect("circuits/public.json is TRACKED — restore it");
    let proof_json = std::fs::read_to_string(circuits_dir().join("proof.json"))
        .expect("circuits/proof.json is TRACKED — restore it");
    let signals = stsh_verifier::public_json_to_signals(&public_json).unwrap();
    let proof_bytes = stsh_verifier::proof_json_to_bytes(&proof_json).unwrap();
    PrivateSpendArgs {
        spend_id: 0,
        envelope: ProofEnvelope {
            circuit_version: 0,
            proof_system_id: "groth16-bn254".to_string(),
            verifying_key_hash: stsh_verifier::compiled_vk_sha256(),
            root_reference: signals[0],
            pool_version: 1,
            proof_bytes,
        },
        nullifiers: vec![signals[1]],
        output_commitments: vec![signals[2], signals[3]],
        encrypted_outputs: vec![vec![0xAA], vec![0xBB]],
        fee: 0,
    }
}

/// BN254 base-field modulus q, little-endian.
const FQ_LE: [u8; 32] = {
    // 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
    let be: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
    ];
    let mut le = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        le[i] = be[31 - i];
        i += 1;
    }
    le
};

/// `q − y` over 32-byte little-endian integers (y < q, y ≠ 0).
fn neg_fq_le(y: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in 0..32 {
        let d = FQ_LE[i] as i16 - y[i] as i16 - borrow;
        if d < 0 {
            out[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[i] = d as u8;
            borrow = 0;
        }
    }
    assert_eq!(borrow, 0, "y must be < q");
    out
}

/// A JUNK spend: the fixture proof with G1 point A negated (y → q − y — still on
/// the curve, so it fails the PAIRING, not a parse), under a fresh canonical
/// nullifier derived from `seed`.
pub fn junk(spend_id: u64, seed: u64) -> PrivateSpendArgs {
    let mut a = fixture();
    let y = a.envelope.proof_bytes[32..64].to_vec();
    a.envelope.proof_bytes[32..64].copy_from_slice(&neg_fq_le(&y));
    let mut nf = [0u8; 32];
    nf[0..8].copy_from_slice(&seed.to_le_bytes());
    nf[8] = 0x5A;
    // nf[31] = 0 keeps it far below r (canonical Fr).
    a.nullifiers = vec![nf];
    a.spend_id = spend_id;
    a
}

/// A spend under a fresh canonical nullifier with the fixture's (real) proof
/// bytes — ACCEPTED by the stub verifier, REJECTED by the real one.
pub fn fresh_nullifier(spend_id: u64, seed: u64) -> PrivateSpendArgs {
    let mut a = fixture();
    let mut nf = [0u8; 32];
    nf[0..8].copy_from_slice(&seed.to_le_bytes());
    nf[8] = 0x6B;
    a.nullifiers = vec![nf];
    a.spend_id = spend_id;
    a
}

pub fn valid(spend_id: u64) -> PrivateSpendArgs {
    let mut a = fixture();
    a.spend_id = spend_id;
    a
}

pub struct Inst {
    pub pic: PocketIc,
    pub token: Principal,
    pub nullifier: Principal,
    pub pool: Principal,
    pub merkle: Principal,
    pub verifier: Principal,
}

pub enum VerifierKind {
    /// The real Groth16 verifier, attested by `set_verifier_canister`.
    Real,
    /// The stub (accepts every proof), reporting `vk` from `vk_hash()`; wired
    /// through InitArgs (init path, NO attestation) with the pool pinned at `pin`.
    StubViaInit { vk: [u8; 32], pin: [u8; 32] },
    /// The stub at `vk == pin`, attested by `set_verifier_canister`.
    StubAttested { pin: [u8; 32] },
}

/// Five canisters; pool from `pool_wasm_bytes`; one seeded deposit so the
/// fixture's anchor is accepted.
pub fn setup(pool_wasm_bytes: Vec<u8>, kind: VerifierKind) -> Inst {
    let pic = PocketIc::new();
    let mk = |pic: &PocketIc| {
        let c = pic.create_canister();
        pic.add_cycles(c, 20_000_000_000_000u128);
        c
    };
    let token = mk(&pic);
    let nullifier = mk(&pic);
    let pool = mk(&pic);
    let merkle = mk(&pic);
    let verifier = mk(&pic);
    pic.install_canister(nullifier, nullifier_wasm(), candid::encode_one(pool).unwrap(), None);
    pic.install_canister(merkle, merkle_wasm(), candid::encode_one(pool).unwrap(), None);
    let (pin, via_init) = match &kind {
        VerifierKind::Real => {
            pic.install_canister(verifier, verifier_wasm(), candid::encode_one(pool).unwrap(), None);
            (stsh_verifier::compiled_vk_sha256(), false)
        }
        VerifierKind::StubViaInit { vk, pin } => {
            pic.install_canister(verifier, stub_verifier_wasm(), candid::encode_one(Some(*vk)).unwrap(), None);
            (*pin, true)
        }
        VerifierKind::StubAttested { pin } => {
            pic.install_canister(verifier, stub_verifier_wasm(), candid::encode_one(Some(*pin)).unwrap(), None);
            (*pin, false)
        }
    };
    let tinit = TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".into(),
            category_name: "All tokens".into(),
            amount: TOTAL_SUPPLY,
            recipient: p(USER),
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01),
        staking_canister: p(GOVERNANCE),
    };
    pic.install_canister(token, token_wasm(), candid::encode_one(tinit).unwrap(), None);
    let pinit = PoolInitArgs {
        token_canister: token,
        nullifier_canister: nullifier,
        merkle_canister: merkle,
        treasury_canister: p(0x04),
        staking_canister: p(GOVERNANCE),
        controller: p(CONTROLLER),
        initial_vk_hash: pin,
        initial_proof_system: "groth16-bn254".to_string(),
        verifier_canister: if via_init { Some(verifier) } else { None },
    };
    pic.install_canister(pool, pool_wasm_bytes, candid::encode_one(pinit).unwrap(), None);
    if !via_init {
        pic.update_call(
            pool,
            p(CONTROLLER),
            "set_verifier_canister",
            candid::encode_args((verifier, pin.to_vec())).unwrap(),
        )
        .expect("set_verifier_canister call");
    }
    let inst = Inst { pic, token, nullifier, pool, merkle, verifier };
    inst.seed_deposit();
    inst.pic.tick();
    inst
}

impl Inst {
    fn seed_deposit(&self) {
        let user = p(USER);
        let r: Result<Nat, candid::Reserved> = decode(
            "icrc2_approve",
            self.pic.update_call(
                self.token,
                user,
                "icrc2_approve",
                candid::encode_one(ApproveArgs {
                    from_subaccount: None,
                    spender: Account { owner: self.pool, subaccount: None },
                    amount: Nat::from(DEPOSIT_AMOUNT),
                    expected_allowance: None,
                    expires_at: Some(self.now() + 3_600_000_000_000),
                    fee: None,
                    memo: None,
                    created_at_time: None,
                })
                .unwrap(),
            ),
        );
        assert!(r.is_ok(), "approve");
        let d: Result<Nat, PoolError> = decode(
            "shield_deposit",
            self.pic.update_call(
                self.pool,
                user,
                "shield_deposit",
                candid::encode_one(ShieldDepositArgs {
                    note_commitment: IN_COMMITMENT,
                    encrypted_payload: vec![],
                    public_amount: DEPOSIT_AMOUNT,
                })
                .unwrap(),
            ),
        );
        d.expect("seed shield_deposit");
    }

    pub fn now(&self) -> u64 {
        self.pic.get_time().as_nanos_since_unix_epoch()
    }

    pub fn spend(&self, caller: Principal, args: PrivateSpendArgs) -> Result<(), PoolError> {
        decode(
            "private_spend",
            self.pic.update_call(self.pool, caller, "private_spend", candid::encode_one(args).unwrap()),
        )
    }

    pub fn submit(&self, caller: Principal, args: PrivateSpendArgs) -> pocket_ic::common::rest::RawMessageId {
        self.pic
            .submit_call(self.pool, caller, "private_spend", candid::encode_one(args).unwrap())
            .expect("submit")
    }

    pub fn await_spend(&self, id: pocket_ic::common::rest::RawMessageId) -> Result<(), PoolError> {
        decode("private_spend (await)", self.pic.await_call(id))
    }

    pub fn status(&self, caller: Principal, spend_id: u64) -> Option<PendingSpend> {
        decode(
            "get_spend_status",
            self.pic.query_call(self.pool, caller, "get_spend_status", candid::encode_one(spend_id).unwrap()),
        )
    }

    pub fn vetkeys_ref(&self) -> Option<Principal> {
        decode(
            "get_vetkeys_canister",
            self.pic.query_call(self.pool, Principal::anonymous(), "get_vetkeys_canister", candid::encode_args(()).unwrap()),
        )
    }

    pub fn upgrade_pool(&self, wasm: Vec<u8>, arg: Vec<u8>) -> Result<(), pocket_ic::RejectResponse> {
        self.pic.upgrade_canister(self.pool, wasm, arg, None)
    }

    /// Point the pool's vetkeys reference (MemoryId 28) at `v` through the
    /// production raw upgrade arg, on the PRODUCTION pool Wasm.
    pub fn set_vetkeys_ref(&self, v: Principal) {
        self.upgrade_pool(
            pool_wasm(),
            candid::encode_args((Some(PoolUpgradeArg { vetkeys_canister: Some(v) }),)).unwrap(),
        )
        .expect("configuring upgrade");
        self.pic.tick();
        self.pic.tick();
    }

    /// Install a vetkeys STAND-IN answering every `has_active_device` with
    /// `reply`, and point the pool at it. Returns the stand-in's principal.
    pub fn install_device_stand_in(&self, reply: Result<bool, DeviceCheckRefusal>) -> Principal {
        let c = self.pic.create_canister();
        self.pic.add_cycles(c, 2_000_000_000_000u128);
        self.pic.install_canister(c, device_stand_in_wasm(&reply), vec![], None);
        self.set_vetkeys_ref(c);
        c
    }

    /// Change the stand-in's answer (reinstall at the same principal).
    pub fn set_device_reply(&self, stand_in: Principal, reply: Result<bool, DeviceCheckRefusal>) {
        self.pic
            .reinstall_canister(stand_in, device_stand_in_wasm(&reply), vec![], None)
            .expect("reinstall the device stand-in");
    }

    pub fn verifier_cycles(&self) -> u128 {
        self.pic.cycle_balance(self.verifier)
    }
}

/// Parse `SPEND_ADMISSION;code=<CODE>;retry_after_ns=<u64>` out of a refusal.
pub fn admission(r: &Result<(), PoolError>) -> Option<(String, u64)> {
    match r {
        Err(PoolError::VerifierUnavailable(s)) if s.starts_with("SPEND_ADMISSION;") => {
            let code = s.split(";code=").nth(1)?.split(';').next()?.to_string();
            let retry = s.split(";retry_after_ns=").nth(1)?.parse().ok()?;
            Some((code, retry))
        }
        _ => None,
    }
}

// ── The vetkeys STAND-IN (hand-assembled Wasm) ──────────────────────────────
//
// A minimal canister exporting `canister_query has_active_device` that replies
// with the Candid encoding of ONE fixed `Result<bool, DeviceCheckRefusal>` —
// the same four byte strings the cross-crate wire drift-lock pins. It lets the
// PRODUCTION pool Wasm exercise its exact production call (method name, Candid
// reply decode) with no test-only surface in the pool itself. Hand-assembled
// because the integration-tests crate carries no `wat` dependency (a
// Cargo.toml edit this lane may not make).

fn leb(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
}

fn section(id: u8, body: Vec<u8>, out: &mut Vec<u8>) {
    out.push(id);
    leb(body.len(), out);
    out.extend(body);
}

fn name(s: &str, out: &mut Vec<u8>) {
    leb(s.len(), out);
    out.extend_from_slice(s.as_bytes());
}

pub fn device_stand_in_wasm(reply: &Result<bool, DeviceCheckRefusal>) -> Vec<u8> {
    let data = candid::encode_one(reply).unwrap();
    assert!(data.len() < 64, "a one-byte signed LEB i32.const");
    let mut w = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    // types: 0 = (i32, i32) -> (), 1 = () -> ()
    section(1, vec![0x02, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x60, 0x00, 0x00], &mut w);
    // imports
    let mut imp = vec![0x02];
    name("ic0", &mut imp);
    name("msg_reply_data_append", &mut imp);
    imp.extend([0x00, 0x00]);
    name("ic0", &mut imp);
    name("msg_reply", &mut imp);
    imp.extend([0x00, 0x01]);
    section(2, imp, &mut w);
    // one function of type 1
    section(3, vec![0x01, 0x01], &mut w);
    // one memory, min 1 page
    section(5, vec![0x01, 0x00, 0x01], &mut w);
    // export the query (function index 2 — after the two imports)
    let mut exp = vec![0x01];
    name("canister_query has_active_device", &mut exp);
    exp.extend([0x00, 0x02]);
    section(7, exp, &mut w);
    // code: i32.const 0; i32.const len; call 0; call 1; end
    let body = vec![0x00, 0x41, 0x00, 0x41, data.len() as u8, 0x10, 0x00, 0x10, 0x01, 0x0b];
    let mut code = vec![0x01];
    leb(body.len(), &mut code);
    code.extend(body);
    section(10, code, &mut w);
    // data: active segment at offset 0
    let mut dat = vec![0x01, 0x00, 0x41, 0x00, 0x0b];
    leb(data.len(), &mut dat);
    dat.extend(data);
    section(11, dat, &mut w);
    w
}
