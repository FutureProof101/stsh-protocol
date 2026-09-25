// =============================================================================
// STSH — WD-FAILCLOSED-TEST: the four withdraw entrypoints are fail-closed
// (Owner ruling D-3, STSH_HARDEN_CLOSEOUT_CHARTER_V1_ADDENDUM_1_2026-09-18)
// =============================================================================
//
// CLAIM UNDER TEST (charter §2 severity correction, SSA, 2026-09-18):
//
//   At e1f4c72 all FOUR public withdraw entrypoints on `shielded_pool` are
//   UNCONDITIONALLY fail-closed via `reject_unbound_withdrawal_proof()`
//   (canisters/shielded-pool/src/lib.rs:8926), which is
//   `Err(PoolError::InvalidProof)` and nothing else. The guard sits BEFORE any
//   `.await` and BEFORE any durable write, so FQ1-F1 / FQ1-F2 / FQ1-C3 are
//   UNREACHABLE at launch and activate only with the Phase-5 proof-bound
//   withdraw lane (anti-drift law #1, "Decision 7: removed only in Phase 5").
//
// The four entrypoints, at e1f4c72:
//
//   fn decl   guard call   entrypoint
//   8456      8472         withdraw(WithdrawArgs)                    -> Result<Nat, PoolError>
//   8648      8653         resume_blocked_withdrawal(u64)            -> Result<Nat, PoolError>
//   8737      8741         reconcile_withdrawal_registry_insert(u64) -> Result<Nat, PoolError>
//   8809      8810         reconcile_withdrawal_ledger_transfer(u64) -> Result<Nat, PoolError>
//
//   Lines are at master 0209eb5; the charter addendum's 7471/7652/7740/7809 were the
//   GUARD-CALL lines at e1f4c72, before HARDEN-03-SETTLEMENT (dc622d5/6828c2d) shifted
//   the pool source by ~1001 lines. These line numbers are DOCUMENTARY ONLY: the
//   drift-lock binds to the fn NAME via the AST, so it is line-independent and a shift
//   like this one cannot produce a false red (it did not — the locks stayed green
//   across the rebase). The cites are refreshed anyway so a reader is not sent to the
//   wrong place.
//
// TWO INDEPENDENT LEGS, because either alone is weak:
//
//   LEG 1 — BEHAVIOURAL (PocketIC, PRODUCTION `shielded_pool.wasm`, NOT the
//           `_test` build). Each entrypoint is called with a well-formed
//           envelope / argument on a freshly installed, unpaused pool, and must
//           return `InvalidProof`. Two negative controls make the assertion
//           mean "before any state write":
//
//             (a) ORDERING PROBE — the three id-taking entrypoints are called
//                 with an id that does NOT exist. Were the guard placed after
//                 the record read they would return `WithdrawalNotFound`;
//                 observing `InvalidProof` proves the guard precedes even the
//                 read, hence every write.
//             (b) STOPPED-DOWNSTREAM PROBE — the nullifier, merkle and token
//                 canisters are STOPPED. A stopped callee rejects every
//                 inter-canister call, so any outbound call on these paths
//                 would surface as a transport error, never as `InvalidProof`.
//                 Observing `InvalidProof` is positive proof no call was made,
//                 hence no `.await` was reached.
//
//           Then: `get_withdrawal_status(id)` is `None` (no PendingWithdrawal
//           record was created) and the 6-bucket accounting snapshot is
//           byte-identical to the pre-call snapshot.
//
//   LEG 2 — DRIFT-LOCK (AST over canisters/shielded-pool/src/lib.rs, parsed
//           with `syn` — a substring oracle is satisfiable by a comment). It
//           asserts, for each of the four fns, that `reject_unbound_withdrawal_proof()?;`
//           appears as a TOP-LEVEL statement of the fn body with NO `.await`
//           before it; and that `reject_unbound_withdrawal_proof`'s own body is
//           EXACTLY `Err(PoolError::InvalidProof)`. Deleting the guard from any
//           entrypoint, or weakening it to a conditional, fails a test.
//
// PREREQUISITES (two-phase build — ARCHITECTURE.md Law #7; use ./run_gate.sh):
//   target/wasm32-unknown-unknown/release/{shielded_pool,stsh_token,
//   nullifier_registry,merkle_tree}.wasm   (PRODUCTION builds)
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//   cargo test --locked -p integration-tests --test wd_failclosed_gate_tests -- --test-threads=1
// =============================================================================

use candid::{CandidType, Nat, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use syn::{Expr, Item, ItemFn, Stmt};

// ── Wasm loading ────────────────────────────────────────────────────────────

fn load_wasm(path: &str, pkg: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {} Wasm at {}: {}", pkg, path, e))
}
/// PRODUCTION pool Wasm — deliberately NOT `POOL_TEST_WASM`. The claim is about
/// what ships, so the test-only feature build would not discharge it.
fn pool_wasm() -> Vec<u8> {
    load_wasm(env!("POOL_WASM"), "shielded_pool")
}
fn token_wasm() -> Vec<u8> {
    load_wasm(env!("TOKEN_WASM"), "stsh_token")
}
fn nullifier_wasm() -> Vec<u8> {
    load_wasm(env!("NULLIFIER_WASM"), "nullifier_registry")
}
fn merkle_wasm() -> Vec<u8> {
    load_wasm(env!("MERKLE_WASM"), "merkle_tree")
}

const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;
const DENOM: u128 = 1_000 * 100_000_000; // DENOMINATIONS[0]

// ── Token init mirrors ──────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
enum LockPolicy {
    ImmediatelyLiquid,
    LockedUntil(u64),
    Vested,
    GovernanceLocked,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct VestingPolicy {
    cliff_end_ns: u64,
    vesting_end_ns: u64,
}

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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct TokenInitArgs {
    allocations: Vec<AllocationCategory>,
    treasury: Principal,
    staking_canister: Principal,
}

fn all_to(recipient: Principal, staking: Principal) -> TokenInitArgs {
    TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All".to_string(),
            amount: TOTAL_SUPPLY,
            recipient,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(0x01),
        staking_canister: staking,
    }
}

// ── Pool mirrors ────────────────────────────────────────────────────────────

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PoolInitArgs {
    token_canister: Principal,
    nullifier_canister: Principal,
    merkle_canister: Principal,
    treasury_canister: Principal,
    staking_canister: Principal,
    controller: Principal,
    initial_vk_hash: [u8; 32],
    initial_proof_system: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct ProofEnvelope {
    circuit_version: u32,
    proof_system_id: String,
    verifying_key_hash: [u8; 32],
    root_reference: [u8; 32],
    pool_version: u32,
    proof_bytes: Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct WithdrawArgs {
    withdrawal_id: u64,
    envelope: ProofEnvelope,
    nullifier: [u8; 32],
    destination: Principal,
    destination_subaccount: Option<[u8; 32]>,
    gross_withdraw_amount: u128,
}

/// Minimal decode mirror for `get_withdrawal_status` — Candid record subtyping
/// lets the reader drop fields it does not need. Its ONLY job is to distinguish
/// `None` (no record) from `Some(_)` (a durable record exists).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
struct PendingWithdrawalProbe {
    withdrawal_id: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct AccountingState {
    private_liability: u128,
    escrow_backing: u128,
    operations_reserve: u128,
    insurance_reserve: u128,
    governance_rewards_reserve: u128,
    pending_fee_reimbursements: u128,
}

// Full mirror of the pool's PoolError. A Candid variant decode FAILS on any
// arriving variant the mirror does not declare — so this must stay complete, and
// a decode failure here is itself a signal that the error surface drifted.
#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum PoolError {
    PayoutOutcomePrivate,
    PayoutExecutorBusy,
    PayoutMemoKeyNotReady,
    PayoutLegacyHold,
    PayoutStateInvalid,
    InvalidDenomination,
    InvalidProof,
    NullifierAlreadySpent,
    NullifierReserved,
    AnchorNotFound,
    EscrowUnderfunded { required: u128, available: u128 },
    InsufficientEscrowCoverage { requested: u128, available: u128 },
    CircuitVersionMismatch { expected: u32, got: u32 },
    VerifyingKeyMismatch,
    PoolVersionMismatch,
    ProofSystemMismatch,
    TransferFailed(String),
    AmountBelowLedgerFee { amount: u128, fee: u128 },
    BelowMinimumDeposit { public_amount: u128, minimum: u128 },
    InsufficientOperationsReserve { needed: u128, available: u128 },
    InvariantViolationDuplicateNullifier,
    Paused,
    RecoveryInProgress(String),
    SolvencyCheckFailed,
    DuplicateWithdrawalId,
    NotInitialised,
    CommitmentAppendFailed(String),
    DepositCommitmentPending,
    SumMismatch { inputs: u128, outputs: u128 },
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
    PrivateSpendFeeMismatch { expected: u128, got: u128 },
    InsufficientPrivateLiability { required: u128, available: u128 },
    WithdrawalBelowMinimum {
        withdraw_gross_amount: u128,
        minimum_withdrawal_gross: u128,
    },
    GrossAmountBelowFees {
        withdraw_gross_amount: u128,
        total_fee: u128,
    },
    RecipientBelowMinimum {
        recipient_net_amount: u128,
        minimum_recipient_amount: u128,
    },
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

// ── Harness ─────────────────────────────────────────────────────────────────

fn p(n: u8) -> Principal {
    let mut b = [0u8; 29];
    b[0] = n;
    Principal::from_slice(&b)
}

fn create_canister(pic: &PocketIc) -> Principal {
    let cid = pic.create_canister();
    pic.add_cycles(cid, 2_000_000_000_000u128);
    cid
}

fn install<T: CandidType>(pic: &PocketIc, cid: Principal, wasm: Vec<u8>, init: &T) {
    pic.install_canister(cid, wasm, candid::encode_one(init).expect("encode init"), None);
}

fn decode<T, E>(label: &str, result: Result<Vec<u8>, E>) -> T
where
    T: CandidType + for<'de> serde::Deserialize<'de>,
    E: std::fmt::Debug,
{
    let bytes = result.unwrap_or_else(|e| panic!("{}: call rejected: {:?}", label, e));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{}: decode failed: {}", label, e))
}

struct Stack {
    pool: Principal,
    token: Principal,
    null: Principal,
    merkle: Principal,
    controller: Principal,
    user: Principal,
}

fn deploy_stack(pic: &PocketIc) -> Stack {
    let controller = p(0xC0);
    let user = p(0xAA);
    let token = create_canister(pic);
    let null = create_canister(pic);
    let merkle = create_canister(pic);
    let pool = create_canister(pic);

    install(pic, null, nullifier_wasm(), &pool);
    install(pic, merkle, merkle_wasm(), &pool);
    install(pic, token, token_wasm(), &all_to(user, p(0x02)));
    install(
        pic,
        pool,
        pool_wasm(), // PRODUCTION
        &PoolInitArgs {
            token_canister: token,
            nullifier_canister: null,
            merkle_canister: merkle,
            treasury_canister: p(0x01),
            staking_canister: p(0x02),
            controller,
            initial_vk_hash: [0u8; 32],
            initial_proof_system: "groth16-bn254".to_string(),
        },
    );
    Stack { pool, token, null, merkle, controller, user }
}

/// A WELL-FORMED envelope: the pinned proof system, the pool's own VK hash and
/// pool version, and a 256-byte proof blob of the shape the Groth16 path
/// expects. Nothing here is malformed — the rejection must come from the
/// unconditional Phase-5 guard, not from an envelope validation.
fn well_formed_envelope() -> ProofEnvelope {
    ProofEnvelope {
        circuit_version: 1,
        proof_system_id: "groth16-bn254".to_string(),
        verifying_key_hash: [0u8; 32],
        root_reference: [0u8; 32],
        pool_version: 1,
        proof_bytes: vec![0u8; 256],
    }
}

fn accounting(pic: &PocketIc, s: &Stack) -> AccountingState {
    decode(
        "get_accounting_state",
        pic.query_call(
            s.pool,
            s.controller, // DEF-076: controller-only
            "get_accounting_state",
            candid::encode_args(()).unwrap(),
        ),
    )
}

fn withdrawal_status(
    pic: &PocketIc,
    s: &Stack,
    caller: Principal,
    id: u64,
) -> Option<PendingWithdrawalProbe> {
    decode(
        "get_withdrawal_status",
        pic.query_call(
            s.pool,
            caller,
            "get_withdrawal_status",
            candid::encode_one(id).unwrap(),
        ),
    )
}

// ── The four entrypoints under test ─────────────────────────────────────────

fn call_withdraw(pic: &PocketIc, s: &Stack, id: u64) -> Result<Nat, PoolError> {
    decode(
        "withdraw",
        pic.update_call(
            s.pool,
            s.user,
            "withdraw",
            candid::encode_one(WithdrawArgs {
                withdrawal_id: id,
                envelope: well_formed_envelope(),
                nullifier: [7u8; 32],
                destination: s.user,
                destination_subaccount: None,
                gross_withdraw_amount: DENOM,
            })
            .unwrap(),
        ),
    )
}

fn call_by_id(pic: &PocketIc, s: &Stack, method: &str, id: u64) -> Result<Nat, PoolError> {
    decode(
        method,
        pic.update_call(s.pool, s.user, method, candid::encode_one(id).unwrap()),
    )
}

/// The three id-taking entrypoints, by their EXACT exported names.
const ID_ENTRYPOINTS: [&str; 3] = [
    "resume_blocked_withdrawal",              // lib.rs:8648 (guard 8653)
    "reconcile_withdrawal_registry_insert",   // lib.rs:8737 (guard 8741)
    "reconcile_withdrawal_ledger_transfer",   // lib.rs:8809 (guard 8810)
];

// =============================================================================
// LEG 1 — BEHAVIOURAL, on the PRODUCTION pool Wasm
// =============================================================================

/// AC-1: `withdraw` returns InvalidProof, creates no PendingWithdrawal record,
/// and leaves the 6-bucket accounting snapshot byte-identical.
#[test]
fn test_wd_01_withdraw_is_fail_closed_before_any_write() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    let before = accounting(&pic, &s);
    assert!(
        withdrawal_status(&pic, &s, s.controller, 4242).is_none(),
        "precondition: no record 4242 may exist before the call"
    );

    let r = call_withdraw(&pic, &s, 4242);
    assert_eq!(
        r,
        Err(PoolError::InvalidProof),
        "withdraw (lib.rs:8456, guard at 8472) must be fail-closed via reject_unbound_withdrawal_proof \
         (lib.rs:8926) — Decision 7, removed only in Phase 5"
    );

    // No durable write: neither the submitter nor the controller can see a record.
    assert!(
        withdrawal_status(&pic, &s, s.user, 4242).is_none(),
        "submitter must see NO PendingWithdrawal record after a fail-closed withdraw"
    );
    assert!(
        withdrawal_status(&pic, &s, s.controller, 4242).is_none(),
        "controller must see NO PendingWithdrawal record after a fail-closed withdraw"
    );
    assert_eq!(
        accounting(&pic, &s),
        before,
        "the 6-bucket accounting snapshot must be unchanged by a fail-closed withdraw"
    );
}

/// AC-2 + ORDERING PROBE: each of the three id-taking entrypoints returns
/// InvalidProof for an id that does NOT exist. `WithdrawalNotFound` would prove
/// the guard sits AFTER the record read; `InvalidProof` proves it sits before
/// it — and therefore before every write on those paths.
#[test]
fn test_wd_02_id_entrypoints_reject_before_the_record_read() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    let before = accounting(&pic, &s);
    const MISSING_ID: u64 = 999_999;

    for method in ID_ENTRYPOINTS {
        assert!(
            withdrawal_status(&pic, &s, s.controller, MISSING_ID).is_none(),
            "precondition ({}): record {} must not exist",
            method,
            MISSING_ID
        );

        let r = call_by_id(&pic, &s, method, MISSING_ID);
        assert_eq!(
            r,
            Err(PoolError::InvalidProof),
            "{} must return InvalidProof, NOT WithdrawalNotFound — the guard must \
             precede the record read (and therefore every durable write)",
            method
        );

        assert!(
            withdrawal_status(&pic, &s, s.controller, MISSING_ID).is_none(),
            "{} must not have created a PendingWithdrawal record",
            method
        );
    }

    assert_eq!(
        accounting(&pic, &s),
        before,
        "the 6-bucket accounting snapshot must be unchanged by the three fail-closed \
         reconcile/resume calls"
    );
}

/// AC-3 + STOPPED-DOWNSTREAM PROBE: with the nullifier, merkle and token
/// canisters STOPPED, all four entrypoints still return InvalidProof. A stopped
/// callee rejects every inter-canister call, so `InvalidProof` is positive proof
/// that no outbound call was originated — i.e. the guard is reached before any
/// `.await`, hence before any state the awaits could commit.
#[test]
fn test_wd_03_all_four_reject_with_every_downstream_stopped() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    let before = accounting(&pic, &s);

    pic.stop_canister(s.null, None).expect("stop nullifier_registry");
    pic.stop_canister(s.merkle, None).expect("stop merkle_tree");
    pic.stop_canister(s.token, None).expect("stop stsh_token");

    assert_eq!(
        call_withdraw(&pic, &s, 5150),
        Err(PoolError::InvalidProof),
        "withdraw must return InvalidProof, never a transport/TransferFailed error — \
         a transport error would mean an inter-canister call was made first"
    );
    assert!(
        withdrawal_status(&pic, &s, s.controller, 5150).is_none(),
        "withdraw must not have created a record with downstream stopped"
    );

    for method in ID_ENTRYPOINTS {
        assert_eq!(
            call_by_id(&pic, &s, method, 5150),
            Err(PoolError::InvalidProof),
            "{} must return InvalidProof with every downstream canister stopped",
            method
        );
    }

    assert_eq!(
        accounting(&pic, &s),
        before,
        "the 6-bucket accounting snapshot must be unchanged with downstream stopped"
    );
}

/// AC-4: the guard is UNCONDITIONAL — repeated calls, distinct ids, and a
/// controller caller all get the same answer. There is no id, caller or
/// repetition that reaches a durable write.
#[test]
fn test_wd_04_guard_is_unconditional_across_ids_and_callers() {
    let pic = PocketIc::new();
    let s = deploy_stack(&pic);

    let before = accounting(&pic, &s);

    for id in [0u64, 1, 2, u64::MAX] {
        assert_eq!(
            call_withdraw(&pic, &s, id),
            Err(PoolError::InvalidProof),
            "withdraw must be fail-closed for withdrawal_id {}",
            id
        );
        // A second attempt on the same id must NOT become DuplicateWithdrawalId:
        // that would prove the first attempt wrote an idempotency record.
        assert_eq!(
            call_withdraw(&pic, &s, id),
            Err(PoolError::InvalidProof),
            "the SECOND withdraw on id {} must still be InvalidProof — \
             DuplicateWithdrawalId would prove the first call wrote a record",
            id
        );
        assert!(
            withdrawal_status(&pic, &s, s.controller, id).is_none(),
            "no record may exist for withdrawal_id {}",
            id
        );
    }

    // Controller caller, same result: the guard precedes the authority checks on
    // the id-taking paths too.
    for method in ID_ENTRYPOINTS {
        let r: Result<Nat, PoolError> = decode(
            method,
            pic.update_call(
                s.pool,
                s.controller,
                method,
                candid::encode_one(1u64).unwrap(),
            ),
        );
        assert_eq!(
            r,
            Err(PoolError::InvalidProof),
            "{} must be fail-closed for the controller too (the guard precedes \
             caller_is_submitter_or_controller)",
            method
        );
    }

    assert_eq!(accounting(&pic, &s), before, "accounting must be unchanged");
}

// =============================================================================
// LEG 2 — DRIFT-LOCK (AST, not substring)
// =============================================================================

const POOL_SRC: &str = "../canisters/shielded-pool/src/lib.rs";
const GUARD: &str = "reject_unbound_withdrawal_proof";

/// The four fn names the guard must appear in, and the line each sits at in the
/// e1f4c72 tree (documentary — the test binds to the NAME, not the line, so a
/// benign line shift does not produce a false red).
const GUARDED_FNS: [(&str, u32); 4] = [
    ("withdraw", 8472),
    ("resume_blocked_withdrawal", 8653),
    ("reconcile_withdrawal_registry_insert", 8741),
    ("reconcile_withdrawal_ledger_transfer", 8810),
];

fn pool_ast() -> Vec<ItemFn> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(POOL_SRC);
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read pool source at {}: {}", path.display(), e));
    let file = syn::parse_file(&src).expect("shielded-pool lib.rs must parse");
    file.items
        .into_iter()
        .filter_map(|i| match i {
            Item::Fn(f) => Some(f),
            _ => None,
        })
        .collect()
}

/// `true` iff the statement is EXACTLY `reject_unbound_withdrawal_proof()?;` —
/// a bare, argument-free, `?`-propagated call statement. A call nested inside an
/// `if`, a `match`, a closure or a boolean expression does NOT match, which is
/// what makes this a lock on unconditionality rather than on mere presence.
fn is_guard_stmt(stmt: &Stmt) -> bool {
    let Stmt::Expr(Expr::Try(t), Some(_semi)) = stmt else {
        return false;
    };
    let Expr::Call(call) = &*t.expr else {
        return false;
    };
    if !call.args.is_empty() {
        return false;
    }
    let Expr::Path(p) = &*call.func else {
        return false;
    };
    p.path.is_ident(GUARD)
}

/// `true` if the statement's token stream mentions `await` anywhere — used only
/// to prove nothing awaits BEFORE the guard.
fn stmt_has_await(stmt: &Stmt) -> bool {
    struct AwaitFinder(bool);
    impl<'ast> syn::visit::Visit<'ast> for AwaitFinder {
        fn visit_expr_await(&mut self, node: &'ast syn::ExprAwait) {
            self.0 = true;
            syn::visit::visit_expr_await(self, node);
        }
    }
    let mut f = AwaitFinder(false);
    syn::visit::Visit::visit_stmt(&mut f, stmt);
    f.0
}

/// DRIFT-LOCK 1: each of the four entrypoints calls the guard as a top-level,
/// unconditional statement, with no `.await` before it.
#[test]
fn test_wd_05_driftlock_all_four_entrypoints_call_the_guard_unconditionally() {
    let fns = pool_ast();

    for (name, documented_line) in GUARDED_FNS {
        let f = fns
            .iter()
            .find(|f| f.sig.ident == name)
            .unwrap_or_else(|| {
                panic!(
                    "withdraw entrypoint `{}` (guard documented at {}:{}) not found — if it was \
                     renamed or removed, this lock must be updated deliberately",
                    name, POOL_SRC, documented_line
                )
            });

        let idx = f
            .block
            .stmts
            .iter()
            .position(is_guard_stmt)
            .unwrap_or_else(|| {
                panic!(
                    "`{}()?;` is NOT a top-level unconditional statement of `{}` \
                     ({}:{}). The four withdraw entrypoints are fail-closed until the \
                     Phase-5 proof-bound withdraw lane (ARCHITECTURE.md anti-drift law #1, \
                     \"Decision 7: removed only in Phase 5\"). Removing or conditioning \
                     this guard re-opens FQ1-F1/F2/C3.",
                    GUARD, name, POOL_SRC, documented_line
                )
            });

        for (i, stmt) in f.block.stmts.iter().take(idx).enumerate() {
            assert!(
                !stmt_has_await(stmt),
                "`{}` awaits at top-level statement {} — BEFORE the `{}` guard at \
                 statement {}. The guard must precede every await (and therefore every \
                 durable write) on this path.",
                name,
                i,
                GUARD,
                idx
            );
        }

        // Exactly one guard call: a second one would be dead, and a differently
        // shaped one would not be caught by the position() above.
        let count = f.block.stmts.iter().filter(|s| is_guard_stmt(s)).count();
        assert_eq!(
            count, 1,
            "`{}` must call `{}` exactly once at top level, found {}",
            name, GUARD, count
        );
    }
}

/// DRIFT-LOCK 2: the guard's own body is EXACTLY `Err(PoolError::InvalidProof)`
/// — one statement, no branch, no argument. If it ever becomes conditional, the
/// four entrypoints stop being unconditionally fail-closed and this fails.
#[test]
fn test_wd_06_driftlock_guard_body_is_exactly_err_invalid_proof() {
    let fns = pool_ast();
    let f = fns
        .iter()
        .find(|f| f.sig.ident == GUARD)
        .unwrap_or_else(|| panic!("`fn {}` not found in {}", GUARD, POOL_SRC));

    assert!(
        f.sig.asyncness.is_none(),
        "`{}` must stay synchronous — an async guard could await before rejecting",
        GUARD
    );
    assert_eq!(
        f.block.stmts.len(),
        1,
        "`{}` must have exactly ONE statement (the unconditional Err), found {}",
        GUARD,
        f.block.stmts.len()
    );

    let Stmt::Expr(Expr::Call(call), None) = &f.block.stmts[0] else {
        panic!(
            "`{}` body must be the tail expression `Err(PoolError::InvalidProof)`",
            GUARD
        )
    };
    let Expr::Path(err_path) = &*call.func else {
        panic!("`{}` body must call `Err(..)`", GUARD)
    };
    assert!(
        err_path.path.is_ident("Err"),
        "`{}` body must be `Err(..)`, found a call to `{}`",
        GUARD,
        quote_path(&err_path.path)
    );
    assert_eq!(call.args.len(), 1, "`Err(..)` takes exactly one argument");

    let Expr::Path(arg_path) = &call.args[0] else {
        panic!("`{}` must return `Err(PoolError::InvalidProof)`", GUARD)
    };
    assert_eq!(
        quote_path(&arg_path.path),
        "PoolError::InvalidProof",
        "`{}` must return EXACTLY `Err(PoolError::InvalidProof)`",
        GUARD
    );
}

fn quote_path(p: &syn::Path) -> String {
    p.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}
