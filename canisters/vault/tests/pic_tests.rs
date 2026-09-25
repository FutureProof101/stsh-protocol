// =============================================================================
// L1 ACCEPTANCE TESTS — PocketIC suite (real replica, real management calls)
// =============================================================================
//
// PREREQUISITES (fail loudly if absent — house convention, never silently
// degrade):
//   cargo build --target wasm32-unknown-unknown --release -p vault
//   export POCKET_IC_BIN=$(dfx cache show)/pocket-ic
//
// The native `#[cfg(test)]` suite in src/lib.rs covers the state machine and
// crash boundaries via the ExecBackend seam; this suite proves the same
// contracts over real ingress against a real replica:
//   · concurrent quorum-reaching approvals admit exactly ONE execution
//   · C1 UpgraderUpgrade happy path against the real management canister
//   · crash → OutcomeUnknown → typed reconcile → Failed, never re-triggerable
//   · signer-gated query negatives (anonymous / removed / unknown) as `None`
//   · durable state survives a real canister upgrade (reservations included)

use candid::{CandidType, Deserialize, Principal};
use serde::Serialize;
use pocket_ic::PocketIc;
use sha2::{Digest, Sha256};
use stsh_custody_types::{
    ActionOutcome, ControllerInvariant, ControllerInvariantProof, InvariantFreshness,
    InvariantRefreshRefusal, ManagementAction,
    ManifestDisposition,
    ObservedCanisterStatus,
    ReconcileTerminalOutcome, ReconcileUpgraderUpgrade, ReconcileVaultUpgradeViaUpgrader,
    RecoveryAction, RecoveryError, StartObjectiveEvidence, TriggerUpgradeResult,
    UpgradeObjectiveEvidence,
    UpgraderInitArgs, UpgraderUpgrade, VaultError, VaultInitArgs, VaultUpgradeViaUpgrader,
};

// ── Vault-local mirror types (must match canisters/vault/vault.did) ──────────

#[derive(CandidType, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
struct VaultTargets {
    shielded_pool: Option<Principal>,
    treasury: Option<Principal>,
    vesting: Option<Principal>,
    nullifier_registry: Option<Principal>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
struct GovernedTarget {
    principal: Principal,
    disposition: ManifestDisposition,
    purpose: String,
}

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
enum CreationReceiptStatus {
    Bound,
    OrphanedPurposeConflict,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
struct CreationReceipt {
    proposal_id: u64,
    principal: Principal,
    purpose: String,
    disposition: ManifestDisposition,
    created_at_ns: u64,
    status: CreationReceiptStatus,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
struct VaultInit {
    quorum: VaultInitArgs,
    cutover_targets: Vec<GovernedTarget>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
enum VaultActionKind {
    Application(stsh_custody_types::ActionRequest),
    Management(ManagementAction),
    UpgraderUpgrade(UpgraderUpgrade),
    ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade),
    ReadModel(stsh_custody_types::ReadModelRequest),
    UpdateSignerSet {
        signers: Vec<Principal>,
        threshold: u32,
    },
    VaultUpgradeViaUpgrader(VaultUpgradeViaUpgrader),
    ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader),
    /// §S7 cell 3 — the retrofit's missing exit.
    ReconcileUpgraderStart(stsh_custody_types::ReconcileUpgraderStart),
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
enum ApprovalOutcome {
    Approved { approvals: u32, threshold: u32 },
    Executing,
    PriorResult {
        outcome: ActionOutcome,
        result: Option<String>,
    },
}

/// R1.7 — mirror of the typed management view. Replaces the former
/// `Management(String)`, which was the vault's `Debug` of the whole action.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
enum ManagementActionView {
    Upgrade {
        target: Principal,
        expected_wasm_hash: Vec<u8>,
        expected_arg_hash: Vec<u8>,
        wasm_bytes_len: u64,
        arg_bytes_len: u64,
        bytes_retained: bool,
    },
    Start {
        target: Principal,
    },
    Stop {
        target: Principal,
    },
    UpdateSettings {
        target: Principal,
        controllers: Vec<Principal>,
    },
    DepositCycles {
        target: Principal,
        cycles: u128,
    },
    CreateCanister {
        manifest_purpose: String,
        disposition: ManifestDisposition,
    },
    InstallCode {
        target: Principal,
        expected_wasm_hash: Vec<u8>,
        expected_arg_hash: Vec<u8>,
        wasm_bytes_len: u64,
        arg_bytes_len: u64,
        bytes_retained: bool,
    },
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
enum ActionView {
    Application(String),
    Management(ManagementActionView),
    UpgraderUpgrade {
        expected_wasm_hash: Vec<u8>,
        expected_arg_hash: Vec<u8>,
        bytes_retained: bool,
    },
    ReconcileUpgraderUpgrade {
        target_proposal_id: u64,
        objective_evidence: UpgradeObjectiveEvidence,
    },
    VaultUpgradeViaUpgrader {
        request_id: u64,
        expected_wasm_hash: Vec<u8>,
        expected_arg_hash: Vec<u8>,
        bytes_retained: bool,
    },
    ReconcileVaultUpgradeViaUpgrader {
        target_proposal_id: u64,
        objective_evidence: UpgradeObjectiveEvidence,
    },
    /// §S7 cell 3 — start evidence shown IN FULL, on the same R1.6 disclosure
    /// reasoning the two upgrade reconcile views carry.
    ReconcileUpgraderStart {
        target_proposal_id: u64,
        objective_evidence: StartObjectiveEvidence,
    },
    ReadModel(String),
    UpdateSignerSet {
        signers: Vec<Principal>,
        threshold: u32,
    },
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
struct ProposalView {
    proposal_id: u64,
    proposer: Principal,
    created_at_ns: u64,
    epoch: u64,
    outcome: ActionOutcome,
    result: Option<String>,
    snapshot_id: Option<u64>,
    action: ActionView,
    approvals: Vec<Principal>,
    /// R1.2 property 8 / R1.3 — the stored commitment a signer supplies to
    /// `approve`. This mirror must track vault.did by hand.
    commitment_hash: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
struct GovernanceSummary {
    threshold: u32,
    signer_count: u32,
    governance_epoch: u64,
}

// ── CONF-02: mirror drift lock ───────────────────────────────────────────────
//
// The types above are a HAND-MAINTAINED mirror of `vault.did`, needed because
// the vault crate is `crate-type = ["cdylib"]` and cannot be imported here.
// Until now nothing enforced the correspondence — unlike the DIDs themselves,
// which have had a structural lock since S2.1. The vault's own
// `did_types_match_the_real_rust_interface` pins vault.did to the Rust source;
// this pins the mirror to vault.did. Together they close the triangle, so an
// interface change cannot leave this file quietly decoding a stale shape.
//
// Why a silent mirror is dangerous rather than merely stale: Candid decoding
// is TOLERANT in exactly the wrong direction. A record field added in the
// vault is ignored by a mirror that lacks it, so an assertion here keeps
// passing while testing a surface that no longer exists — a green test
// asserting nothing. That is a worse failure than a decode error.
//
// A deliberate interface change repins the mirror in the SAME commit, which is
// the review event this lock exists to force — never a later refresh to make
// the gate go green.

const VAULT_DID: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/vault.did"));
const UPGRADER_DID: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../upgrader/upgrader.did"));

/// Assert that a mirror type is STRUCTURALLY EQUAL to the `vault.did` type of
/// the same name. Equality, not compatibility: a mirror that is merely a
/// subtype is the silent-divergence case above.
fn assert_mirror_matches_did<T: CandidType>(name: &str) {
    assert_mirror_matches_did_in::<T>(name, VAULT_DID)
}

/// CONF-02 extended to the UPGRADER surface (S5B W3).
///
/// The lock previously covered only `vault.did`, so a hand-maintained mirror of
/// an UPGRADER type — which W3's acceptance-13 test needs — would have had no
/// drift lock at all. That is precisely the CONF-02 defect ("pic_tests
/// hand-maintains a mirror with no drift lock"), so the fix is to widen the
/// lock rather than to leave the new mirror unguarded.
fn assert_mirror_matches_did_in<T: CandidType>(name: &str, did: &str) {
    use candid::types::internal::TypeContainer;
    use candid_parser::utils::CandidSource;

    let (mut env, _) = CandidSource::Text(did)
        .load()
        .expect("committed vault.did parses");
    let committed = env
        .find_type(name)
        .unwrap_or_else(|e| panic!("vault.did declares no type `{name}`: {e}"))
        .clone();

    let mut container = TypeContainer::new();
    let mirror = container.add::<T>();
    // Merge the mirror's own type environment into the .did's before
    // comparing: the two sides define the same NAMES independently, and
    // `merge_type` is what reconciles the two namespaces.
    let mirror = env.merge_type(container.env, mirror);

    let mut gamma = std::collections::HashSet::new();
    candid::types::subtype::equal(&mut gamma, &env, &mirror, &committed).unwrap_or_else(|e| {
        panic!(
            "pic_tests mirror `{name}` has DRIFTED from vault.did: {e}\n\n\
             Repin the mirror in the SAME change as the interface edit."
        )
    });
}

/// CONF-02 — EVERY hand-maintained mirror type is locked to `vault.did`.
///
/// The list must cover the whole mirror block, not a representative sample. A
/// partial lock is worse than none: it reports "mirrors locked" while the
/// unlisted types drift freely, which is exactly what happened on the first
/// cut of this test — it omitted `AuditKind`, whose mirror was ALREADY missing
/// `ProposalCancelled`/`ProposalExpired`, and passed anyway.
///
/// That omission is the same defect the vault's own DID lock exists to catch
/// (see `did_drift_tests`: `AuditKind` grew those two variants in Rust while
/// the committed Candid did not). Reproducing it one layer out is a reminder
/// that a lock's COVERAGE is as load-bearing as its strictness.
///
/// Types are listed explicitly rather than derived, because the risk this
/// guards is a NEW mirror type added without a lock — a reviewer comparing
/// this list against the mirror block can see an omission; no automation here
/// can. The count assertion below turns "I forgot one" into a failure rather
/// than a silent gap.
#[test]
fn conf02_mirror_types_match_the_committed_did() {
    assert_mirror_matches_did::<ProposalView>("ProposalView");
    assert_mirror_matches_did::<ActionView>("ActionView");
    assert_mirror_matches_did::<ManagementActionView>("ManagementActionView");
    assert_mirror_matches_did::<VaultActionKind>("VaultActionKind");
    assert_mirror_matches_did::<ApprovalOutcome>("ApprovalOutcome");
    assert_mirror_matches_did::<VaultTargets>("VaultTargets");
    assert_mirror_matches_did::<GovernedTarget>("GovernedTarget");
    assert_mirror_matches_did::<CreationReceipt>("CreationReceipt");
    assert_mirror_matches_did::<CreationReceiptStatus>("CreationReceiptStatus");
    assert_mirror_matches_did::<GovernanceSummary>("GovernanceSummary");
    // Added after the first cut of this lock shipped incomplete.
    assert_mirror_matches_did::<VaultInit>("VaultInit");
    assert_mirror_matches_did::<CreationReceiptPage>("CreationReceiptPage");
    assert_mirror_matches_did::<AuditKind>("AuditKind");
    assert_mirror_matches_did::<AuditEvent>("AuditEvent");
    // Upgrader-surface mirror (S5B W3 acceptance 13), locked against
    // upgrader.did rather than vault.did.
    assert_mirror_matches_did_in::<RotationProposalView>("RotationProposalView", UPGRADER_DID);

    // Coverage guard: the number of mirror declarations in this file must
    // equal the number of LOCK LINES ACTUALLY PRESENT above. Adding a mirror
    // without a lock line fails HERE, at the point the omission is made,
    // rather than silently years later.
    //
    // BOTH SIDES ARE COUNTED FROM THE SOURCE. The first cut compared
    // declarations against a hand-maintained `const LOCKED: usize = 14`, which
    // does not close the hole it claims to: adding a mirror, bumping the
    // constant, and forgetting the equality assertion still passed. A guard
    // whose expected value is edited by the same hand that makes the omission
    // guards nothing.
    //
    // Declarations match at LINE START and locks match on the TRIMMED line, so
    // neither pattern can count the prose or the string literals on these very
    // lines — the literals below are not at the start of their trimmed lines.
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pic_tests.rs"));
    let declared = src.matches("\n#[derive(CandidType, Deserialize").count();
    let locked = src
        .lines()
        // A LOCK SITE names its type as a string literal. The helper's own
        // delegation line (`assert_mirror_matches_did_in::<T>(name, VAULT_DID)`)
        // starts with the same prefix but carries no literal, and counting it
        // would inflate the lock count and mask a genuinely missing lock.
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("assert_mirror_matches_did") && t.contains('"')
        })
        .count();
    assert_eq!(
        declared, locked,
        "pic_tests declares {declared} mirror types but only {locked} carry an \
         equality assertion. Every hand-maintained mirror needs one — a partial \
         lock reports success while the unlisted types drift."
    );
}

// ── Harness ──────────────────────────────────────────────────────────────────

fn vault_wasm() -> Vec<u8> {
    let path = format!(
        "{}/../../target/wasm32-unknown-unknown/release/vault.wasm",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "vault.wasm not found at {path}: {e}\nBuild it first:\n  \
             cargo build --target wasm32-unknown-unknown --release -p vault"
        )
    })
}

fn p(b: u8) -> Principal {
    Principal::from_slice(&[b; 29])
}

// The exact manifest SetControllerAtCutover set (mirrors the vault's baked
// REQUIRED_CUTOVER constants; provenance: custody_manifest.toml).
const PYEOP: &str = "pyeop-7yaaa-aaaam-ajfja-cai";
const S3TYU: &str = "s3tyu-aaaaa-aaaab-qhdjq-cai";

fn manifest_cutover() -> Vec<GovernedTarget> {
    vec![
        GovernedTarget {
            principal: Principal::from_text(PYEOP).unwrap(),
            disposition: ManifestDisposition::SetControllerAtCutover,
            purpose: "solvency_status".to_string(),
        },
        GovernedTarget {
            principal: Principal::from_text(S3TYU).unwrap(),
            disposition: ManifestDisposition::SetControllerAtCutover,
            purpose: "wallet_frontend".to_string(),
        },
    ]
}

const S1: u8 = 1;
const S2: u8 = 2;
const S3: u8 = 3;

fn rig() -> (PocketIc, Principal) {
    rig_with_cutover(p(9), manifest_cutover())
}

/// Rig with a pre-created, Vault-controlled governed target declared as a
/// SetControllerAtCutover entry (the manifest's pyeop/s3tyu shape).
fn rig_with_governed_target() -> (PocketIc, Principal, Principal) {
    let pic = PocketIc::new();
    // Create the REAL manifest cutover principals so the exact-set init
    // accepts them AND they exist for governed management calls.
    let target = pic
        .create_canister_with_id(None, None, Principal::from_text(PYEOP).unwrap())
        .unwrap();
    pic.add_cycles(target, 1_000_000_000_000u128);
    let wallet = pic
        .create_canister_with_id(None, None, Principal::from_text(S3TYU).unwrap())
        .unwrap();
    pic.add_cycles(wallet, 1_000_000_000_000u128);
    let vault = pic.create_canister();
    pic.add_cycles(vault, 10_000_000_000_000u128);
    let init = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
            upgrader: p(9),
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(vault, vault_wasm(), candid::encode_one(&init).unwrap(), None);
    pic.set_controllers(target, None, vec![vault]).unwrap();
    pic.set_controllers(wallet, None, vec![vault]).unwrap();
    (pic, vault, target)
}

/// Rig whose durable Upgrader counterpart is a chosen principal — for C1
/// tests this must be the REAL dummy canister id, because the Vault executes
/// `UpgraderUpgrade` against its durable wiring, never a caller-supplied id.
/// Rig with a REAL dummy "Upgrader" canister on the same instance: created
/// first so its principal can be wired as the Vault's durable counterpart,
/// then its controller is moved to the Vault (born-under-vault ring shape).
fn rig_with_dummy_upgrader() -> (PocketIc, Principal, Principal) {
    let pic = PocketIc::new();
    let upgrader = pic.create_canister();
    pic.add_cycles(upgrader, 5_000_000_000_000u128);
    let dummy_init = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(11), p(12), p(13)],
            threshold: 2,
            upgrader: p(19),
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(
        upgrader,
        vault_wasm(),
        candid::encode_one(&dummy_init).unwrap(),
        None,
    );
    let vault = pic.create_canister();
    pic.add_cycles(vault, 10_000_000_000_000u128);
    let init = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
            upgrader,
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(vault, vault_wasm(), candid::encode_one(&init).unwrap(), None);
    pic.set_controllers(upgrader, None, vec![vault]).unwrap();
    (pic, vault, upgrader)
}

fn rig_with_cutover(upgrader: Principal, cutover_targets: Vec<GovernedTarget>) -> (PocketIc, Principal) {
    let pic = PocketIc::new();
    let vault = pic.create_canister();
    pic.add_cycles(vault, 10_000_000_000_000u128);
    let init = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
            upgrader,
        },
        cutover_targets,
    };
    pic.install_canister(vault, vault_wasm(), candid::encode_one(&init).unwrap(), None);
    (pic, vault)
}

fn predecessor_vault_wasm() -> Vec<u8> {
    let path = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
        .join("wasm32-unknown-unknown/release/vault_pre_hardening_d068_prod.wasm");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!("immutable d068 predecessor Vault missing at {}: {e}", path.display())
    });
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "e5fc99984703f95113942105f66dfe2e7c95fc07391daf9e85d5bcb4a5451f65",
        "d068 Vault fixture must match its literal production pin"
    );
    bytes
}

/// The IMMUTABLE pre-VR-1 production Vault (master db2cf90) — the module that
/// is live on cpdab today and that stranded proposal #10. Built under
/// `run_gate.sh`'s `env -i` re-exec at db2cf90 and copied to this name; see the
/// fixture recipe in `run_gate.sh`. Never committed to the repo.
fn pre_vr1_vault_wasm() -> Vec<u8> {
    let path = std::env::var_os("VAULT_PRE_VR1_TEST_WASM")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("CARGO_TARGET_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
                })
                .join("wasm32-unknown-unknown/release/vault_pre_vr1_d7d128b8_prod.wasm")
        });
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!("pre-VR-1 predecessor Vault missing at {}: {e}", path.display())
    });
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "d7d128b87f4d91de48f959e6f128771a02100cf1c93d8f4dbc0d0200bdae6578",
        "pre-VR-1 Vault fixture must match its literal production pin"
    );
    bytes
}

/// VR-1 — the exact mainnet path, end to end, through a real message boundary.
///
/// Reproduces proposal #10: under the LIVE (pre-VR-1) Vault, a governed
/// `InstallCode` whose management call is rejected lands in `OutcomeUnknown`
/// holding the single-flight lock on its target, with NO route out. Then it
/// upgrades the Vault to the VR-1 module and shows the stranded record is
/// untouched by `post_upgrade` (the §S7 sweep must not terminalize it) and
/// still locked — and that a quorum-approved `ReconcileUpgraderUpgrade` now
/// terminalizes it exactly once, releases the lock, and readmits a fresh
/// `InstallCode` on the same target.
#[test]
fn pic_vr1_stranded_management_install_reconciles_after_upgrade() {
    let pic = PocketIc::new();
    let vault = pic.create_canister();
    pic.add_cycles(vault, 20_000_000_000_000u128);
    let init = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
            upgrader: p(9),
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(
        vault,
        pre_vr1_vault_wasm(),
        candid::encode_one(&init).unwrap(),
        None,
    );

    // A governed born-under-vault target, created through the real receipt path.
    let (target_canister, _) = l02_create(&pic, vault, "merkle_tree");

    // Drive an InstallCode to OutcomeUnknown. The management canister rejects
    // deterministically: the module is not a valid Wasm. (On mainnet the reject
    // was "out of cycles"; the Vault maps EVERY call rejection to
    // OutcomeUnknown, so the stranding is the same record either way.)
    let bad_module = b"\x00not-a-wasm-module".to_vec();
    let install = |bytes: Vec<u8>| {
        VaultActionKind::Management(ManagementAction::InstallCode {
            target: target_canister,
            expected_wasm_hash: sha256(&bytes),
            expected_arg_hash: sha256(b""),
            wasm_bytes: bytes,
            arg_bytes: vec![],
        })
    };
    let stranded = propose(&pic, vault, p(S1), install(bad_module.clone()));
    approve(&pic, vault, p(S1), stranded).unwrap();
    approve(&pic, vault, p(S2), stranded).unwrap();
    assert_eq!(
        get_proposal(&pic, vault, p(S1), stranded).unwrap().outcome,
        ActionOutcome::OutcomeUnknown,
        "a rejected install_code strands the proposal"
    );

    // The lock is held: a second InstallCode on the same target is refused.
    let refused = pic
        .update_call(
            vault,
            p(S1),
            "propose",
            candid::encode_one(&install(b"\x00second".to_vec())).unwrap(),
        )
        .unwrap();
    assert_eq!(
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(refused)).unwrap(),
        Err(VaultError::IllegalSourceState),
        "the stranded intent holds single-flight on the target"
    );

    // Under the PRE-VR-1 module the reconcile route does not admit a
    // management target at all — this is the live defect.
    let evidence = |at: u64| UpgradeObjectiveEvidence {
        observed_upgrader_principal: target_canister,
        observed_module_hash: None,
        observed_controllers: vec![vault],
        observed_canister_status: ObservedCanisterStatus::Running,
        observed_at_ns: at,
    };
    let pre_fix = pic
        .update_call(
            vault,
            p(S1),
            "propose",
            candid::encode_one(&VaultActionKind::ReconcileUpgraderUpgrade(
                ReconcileUpgraderUpgrade {
                    proposal_id: stranded,
                    objective_evidence: evidence(
                        pic.get_time().as_nanos_since_unix_epoch(),
                    ),
                },
            ))
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(pre_fix)).unwrap(),
        Err(VaultError::IllegalSourceState),
        "pre-VR-1: no reconcile route admits a management target"
    );

    // Upgrade the Vault to the VR-1 module (the Owner's dfx upgrade of cpdab).
    let before = get_proposal(&pic, vault, p(S1), stranded).unwrap();
    pic.advance_time(std::time::Duration::from_secs(600));
    pic.tick();
    pic.upgrade_canister(vault, vault_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("supported pre-VR-1 -> VR-1 upgrade");

    // post_upgrade must NOT touch the stranded record, and the lock survives.
    let after = get_proposal(&pic, vault, p(S1), stranded).unwrap();
    assert_eq!(after.outcome, ActionOutcome::OutcomeUnknown, "S7 sweep must not terminalize it");
    assert_eq!(after.commitment_hash, before.commitment_hash);
    let still_refused = pic
        .update_call(
            vault,
            p(S1),
            "propose",
            candid::encode_one(&install(b"\x00third".to_vec())).unwrap(),
        )
        .unwrap();
    assert_eq!(
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(still_refused)).unwrap(),
        Err(VaultError::IllegalSourceState),
        "the lock survives the upgrade"
    );

    // Reconcile: module None, controllers [Vault], Running, fresh evidence.
    let rec = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
            proposal_id: stranded,
            objective_evidence: evidence(pic.get_time().as_nanos_since_unix_epoch()),
        }),
    );
    approve(&pic, vault, p(S1), rec).unwrap();
    approve(&pic, vault, p(S2), rec).unwrap();
    assert_eq!(
        get_proposal(&pic, vault, p(S1), rec).unwrap().outcome,
        ActionOutcome::Executed,
        "the reconcile itself executes"
    );
    assert_eq!(
        get_proposal(&pic, vault, p(S1), stranded).unwrap().outcome,
        ActionOutcome::Failed,
        "module hash None terminalizes the stranded install as Failed"
    );

    // The lock is gone: a fresh InstallCode on the same target is ADMITTED.
    let readmitted = propose(&pic, vault, p(S1), install(b"\x00fourth".to_vec()));
    assert_eq!(
        get_proposal(&pic, vault, p(S1), readmitted).unwrap().outcome,
        ActionOutcome::Pending,
        "a fresh InstallCode on the same target is admitted once the lock releases"
    );

    // Exactly once: the terminalized target is no longer a legal source.
    let twice = pic
        .update_call(
            vault,
            p(S1),
            "propose",
            candid::encode_one(&VaultActionKind::ReconcileUpgraderUpgrade(
                ReconcileUpgraderUpgrade {
                    proposal_id: stranded,
                    objective_evidence: evidence(
                        pic.get_time().as_nanos_since_unix_epoch(),
                    ),
                },
            ))
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(twice)).unwrap(),
        Err(VaultError::IllegalSourceState),
        "never re-triggerable"
    );
}

#[test]
fn pic_l02_populated_d068_pending_proposal_survives_upgrade_and_executes_once() {
    let pic = PocketIc::new();
    let vault = pic.create_canister();
    pic.add_cycles(vault, 10_000_000_000_000u128);
    let init = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
            upgrader: p(9),
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(
        vault,
        predecessor_vault_wasm(),
        candid::encode_one(&init).unwrap(),
        None,
    );
    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::UpdateSignerSet {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
        },
    );
    let before = get_proposal(&pic, vault, p(S1), id).unwrap();
    assert_eq!(before.outcome, ActionOutcome::Pending);
    // PocketIC enforces the management canister install-code rate limit too.
    // Move beyond that window so this witness reaches the compatibility check.
    pic.advance_time(std::time::Duration::from_secs(600));
    pic.tick();
    pic.upgrade_canister(vault, vault_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("supported d068 -> L02 upgrade");
    let after = get_proposal(&pic, vault, p(S1), id).unwrap();
    assert_eq!(after.commitment_hash, before.commitment_hash);
    assert_eq!(after.outcome, ActionOutcome::Pending);
    approve_with_hash(&pic, vault, p(S1), id, before.commitment_hash.clone()).unwrap();
    approve_with_hash(&pic, vault, p(S2), id, before.commitment_hash.clone()).unwrap();
    assert_eq!(get_proposal(&pic, vault, p(S1), id).unwrap().outcome, ActionOutcome::Executed);
    let replay = approve_with_hash(&pic, vault, p(S3), id, before.commitment_hash).unwrap();
    assert!(matches!(
        replay,
        ApprovalOutcome::PriorResult { outcome: ActionOutcome::Executed, .. }
    ));
}


#[test]
fn pic_l02_d068_pending_cross_family_commitments_survive_upgrade() {
    let pic = PocketIc::new();
    let vault = pic.create_canister();
    pic.add_cycles(vault, 20_000_000_000_000u128);
    let init = VaultInit {
        quorum: VaultInitArgs { signers: vec![p(S1), p(S2), p(S3)], threshold: 2, upgrader: p(9) },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(vault, predecessor_vault_wasm(), candid::encode_one(&init).unwrap(), None);
    let (pool, receipt_audit_id) = l02_create(&pic, vault, "shielded_pool");
    let pool_init = L02PoolInitArgs {
        token_canister: p(40), nullifier_canister: p(41), merkle_canister: p(42),
        treasury_canister: p(43), staking_canister: p(44), controller: vault,
        initial_vk_hash: [0; 32], initial_proof_system: "groth16-bn254".to_string(),
        verifier_canister: None,
    };
    pic.install_canister(pool, predecessor_pool_wasm(),
        candid::encode_one(pool_init).unwrap(), Some(vault));
    let snapshot_proposal = propose(&pic, vault, p(S1), VaultActionKind::ReadModel(
        stsh_custody_types::ReadModelRequest::PoolReadAccountingState(
            stsh_custody_types::PageRequest { cursor: None, limit: 1 })));
    approve(&pic, vault, p(S1), snapshot_proposal).unwrap();
    approve(&pic, vault, p(S2), snapshot_proposal).unwrap();
    let snapshot_id = get_proposal(&pic, vault, p(S1), snapshot_proposal).unwrap().snapshot_id.unwrap();
    let snapshot_before = get_snapshot(&pic, vault, p(S1), snapshot_id).unwrap();
    assert!(audit_events(&pic, vault, p(S1)).iter().any(|e| e.id == receipt_audit_id));
    let actions = vec![
        VaultActionKind::Application(stsh_custody_types::ActionRequest::PoolEmergencyPauseSpends),
        VaultActionKind::ReadModel(stsh_custody_types::ReadModelRequest::PoolReadAccountingState(stsh_custody_types::PageRequest { cursor: None, limit: 1 })),
        VaultActionKind::Management(ManagementAction::Start { target: Principal::from_text(PYEOP).unwrap() }),
        VaultActionKind::UpgraderUpgrade(UpgraderUpgrade { expected_wasm_hash: sha256(b"w"), expected_arg_hash: sha256(b""), wasm_bytes: b"w".to_vec(), arg_bytes: vec![] }),
        VaultActionKind::UpdateSignerSet { signers: vec![p(S1),p(S2),p(S3)], threshold: 2 },
        VaultActionKind::VaultUpgradeViaUpgrader(VaultUpgradeViaUpgrader { request_id: 0, expected_wasm_hash: sha256(b"w"), expected_arg_hash: sha256(b""), wasm_bytes: b"w".to_vec(), arg_bytes: vec![] }),
    ];
    let pending:Vec<_>=actions.into_iter().map(|a| { let id=propose(&pic,vault,p(S1),a); let v=get_proposal(&pic,vault,p(S1),id).unwrap(); (id,v.action,v.commitment_hash) }).collect();
    let partial_id = pending[0].0;
    let partial_hash = pending[0].2.clone();
    assert!(matches!(
        approve_with_hash(&pic, vault, p(S1), partial_id, partial_hash.clone()).unwrap(),
        ApprovalOutcome::Approved { approvals: 1, threshold: 2 }
    ));

    let unknown_action = VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
        expected_wasm_hash: sha256(b"unknown-wasm"),
        expected_arg_hash: sha256(b""),
        wasm_bytes: b"unknown-wasm".to_vec(),
        arg_bytes: vec![],
    });
    let unknown_id = propose(&pic, vault, p(S1), unknown_action);
    let unknown_hash = get_proposal(&pic, vault, p(S1), unknown_id).unwrap().commitment_hash;
    approve_with_hash(&pic, vault, p(S1), unknown_id, unknown_hash.clone()).unwrap();
    approve_with_hash(&pic, vault, p(S2), unknown_id, unknown_hash.clone()).unwrap();
    assert_eq!(get_proposal(&pic, vault, p(S1), unknown_id).unwrap().outcome, ActionOutcome::OutcomeUnknown);

    pic.advance_time(std::time::Duration::from_secs(600)); pic.tick();
    pic.upgrade_canister(vault,vault_wasm(),candid::encode_args(()).unwrap(),None).unwrap();
    assert_eq!(get_snapshot(&pic, vault, p(S1), snapshot_id).unwrap(), snapshot_before);
    assert!(audit_events(&pic, vault, p(S1)).iter().any(|e| e.id == receipt_audit_id));

    let partial_after = get_proposal(&pic, vault, p(S1), partial_id).unwrap();
    assert_eq!(partial_after.commitment_hash, partial_hash);
    assert_eq!(partial_after.approvals, vec![p(S1)]);
    let terminal = approve_with_hash(&pic, vault, p(S2), partial_id, partial_hash.clone()).unwrap();
    assert!(matches!(terminal, ApprovalOutcome::PriorResult { outcome: ActionOutcome::Executed, .. }));
    let terminal_replay = approve_with_hash(&pic, vault, p(S3), partial_id, partial_hash).unwrap();
    assert!(matches!(terminal_replay, ApprovalOutcome::PriorResult { outcome: ActionOutcome::Executed, .. }));

    let unknown_after = get_proposal(&pic, vault, p(S1), unknown_id).unwrap();
    assert_eq!(unknown_after.commitment_hash, unknown_hash);
    assert_eq!(unknown_after.outcome, ActionOutcome::OutcomeUnknown);
    let unknown_replay = approve_with_hash(&pic, vault, p(S3), unknown_id, unknown_hash).unwrap();
    assert!(matches!(unknown_replay, ApprovalOutcome::PriorResult { outcome: ActionOutcome::OutcomeUnknown, .. }));
    let blocked = pic.update_call(
        vault, p(S1), "propose",
        candid::encode_one(&VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
            expected_wasm_hash: sha256(b"second"),
            expected_arg_hash: sha256(b""),
            wasm_bytes: b"second".to_vec(),
            arg_bytes: vec![],
        })).unwrap(),
    ).unwrap();
    assert_eq!(
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(blocked)).unwrap(),
        Err(VaultError::IllegalSourceState),
        "the predecessor unknown-intent companion lock survives the upgrade"
    );

    for (id,action,hash) in pending.into_iter().skip(1) {
        let after=get_proposal(&pic,vault,p(S1),id).unwrap();
        assert_eq!(after.action,action);
        assert_eq!(after.commitment_hash,hash);
        assert_eq!(after.outcome,ActionOutcome::Pending);
        let approval=approve_with_hash(&pic,vault,p(S1),id,hash).unwrap();
        assert!(matches!(approval,ApprovalOutcome::Approved{approvals:1,threshold:2}));
        assert_eq!(get_proposal(&pic,vault,p(S1),id).unwrap().outcome,ActionOutcome::Pending);
    }
}

fn propose(pic: &PocketIc, vault: Principal, sender: Principal, action: VaultActionKind) -> u64 {
    let r = pic
        .update_call(
            vault,
            sender,
            "propose",
            candid::encode_one(&action).unwrap(),
        )
        .expect("propose call");
    candid::decode_one::<Result<u64, VaultError>>(static_bytes(r))
        .unwrap()
        .expect("propose accepted")
}

/// R1.5 — approve now REQUIRES the expected commitment hash. This mirrors what
/// a real signer does: read the proposal view, take `commitment_hash`, supply
/// it. Approving by id alone is exactly the CUST-SSA-001 shape.
fn approve(
    pic: &PocketIc,
    vault: Principal,
    sender: Principal,
    id: u64,
) -> Result<ApprovalOutcome, VaultError> {
    let hash = get_proposal(pic, vault, sender, id)
        .expect("signer may read the proposal to obtain its commitment")
        .commitment_hash;
    approve_with_hash(pic, vault, sender, id, hash)
}

/// Approve with an EXPLICIT hash, so tests can supply a deliberately wrong one.
fn approve_with_hash(
    pic: &PocketIc,
    vault: Principal,
    sender: Principal,
    id: u64,
    expected_action_hash: Vec<u8>,
) -> Result<ApprovalOutcome, VaultError> {
    let r = pic
        .update_call(
            vault,
            sender,
            "approve",
            candid::encode_args((id, expected_action_hash)).unwrap(),
        )
        .expect("approve call");
    candid::decode_one::<Result<ApprovalOutcome, VaultError>>(static_bytes(r)).unwrap()
}

fn get_proposal(pic: &PocketIc, vault: Principal, sender: Principal, id: u64) -> Option<ProposalView> {
    let r = pic
        .query_call(
            vault,
            sender,
            "get_proposal",
            candid::encode_one(&id).unwrap(),
        )
        .expect("query");
    candid::decode_one::<Option<ProposalView>>(&r).unwrap()
}

fn get_signers(pic: &PocketIc, vault: Principal, sender: Principal) -> Option<Vec<Principal>> {
    let r = pic
        .query_call(vault, sender, "get_signers", candid::encode_args(()).unwrap())
        .expect("query");
    candid::decode_one::<Option<Vec<Principal>>>(&r).unwrap()
}

fn summary(pic: &PocketIc, vault: Principal) -> GovernanceSummary {
    let r = pic
        .query_call(
            vault,
            Principal::anonymous(),
            "get_governance_summary",
            candid::encode_args(()).unwrap(),
        )
        .expect("query");
    candid::decode_one::<GovernanceSummary>(&r).unwrap()
}

/// VaultError embeds `&'static str`, so decoding it needs 'static input.
/// Test-only leak of the reply buffer.
fn static_bytes(b: Vec<u8>) -> &'static [u8] {
    Box::leak(b.into_boxed_slice())
}

fn sha256(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn pic_public_summary_and_gated_query_negatives() {
    let (pic, vault) = rig();
    let s = summary(&pic, vault);
    assert_eq!((s.threshold, s.signer_count, s.governance_epoch), (2, 3, 0));
    // Signer positive.
    assert_eq!(get_signers(&pic, vault, p(S1)).unwrap().len(), 3);
    // Anonymous / unknown → indistinguishable None.
    assert_eq!(get_signers(&pic, vault, Principal::anonymous()), None);
    assert_eq!(get_signers(&pic, vault, p(77)), None);
}

/// Concurrent quorum-reaching approvals admit exactly ONE execution — real
/// replica, two in-flight update calls submitted before either completes.
#[test]
fn pic_concurrent_quorum_admits_exactly_one_execution() {
    let (pic, vault, target) = rig_with_governed_target();
    // Governed target is controlled by the Vault; stop it so Start has an effect.
    pic.stop_canister(target, Some(vault)).unwrap();

    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::Start { target }),
    );
    // S1 approves (below quorum), then S2 and S3 approve CONCURRENTLY —
    // either could be the quorum-reaching approval.
    let a1 = approve(&pic, vault, p(S1), id).unwrap();
    assert!(matches!(a1, ApprovalOutcome::Approved { approvals: 1, .. }));
    // R1.5: raw submit_call, so the commitment must be supplied explicitly —
    // the helper is bypassed here deliberately to race the two approvals.
    let commitment = get_proposal(&pic, vault, p(S1), id).unwrap().commitment_hash;
    let m2 = pic
        .submit_call(
            vault,
            p(S2),
            "approve",
            candid::encode_args((id, commitment.clone())).unwrap(),
        )
        .unwrap();
    let m3 = pic
        .submit_call(
            vault,
            p(S3),
            "approve",
            candid::encode_args((id, commitment.clone())).unwrap(),
        )
        .unwrap();
    let b2 = pic.await_call(m2).unwrap();
    let b3 = pic.await_call(m3).unwrap();
    let r2 = candid::decode_one::<Result<ApprovalOutcome, VaultError>>(static_bytes(b2)).unwrap();
    let r3 = candid::decode_one::<Result<ApprovalOutcome, VaultError>>(static_bytes(b3)).unwrap();
    // Exactly one of the two drove an execution; the other got a replay of
    // the in-flight/terminal state — never a second execution.
    let finals = [r2, r3];
    assert!(finals.iter().all(|r| r.is_ok()));
    let view = get_proposal(&pic, vault, p(S1), id).unwrap();
    assert_eq!(view.outcome, ActionOutcome::Executed);
    // And the management call really happened exactly once: the target is
    // running with the Vault as its sole controller.
    let status = pic.canister_status(target, Some(vault)).unwrap();
    assert_eq!(
        status.settings.controllers,
        vec![vault],
        "vault remains sole controller"
    );
    // Replay is stable: approving again returns the prior terminal result.
    let replay = approve(&pic, vault, p(S3), id).unwrap();
    assert!(matches!(
        replay,
        ApprovalOutcome::PriorResult {
            outcome: ActionOutcome::Executed,
            ..
        }
    ));
}

/// C1 happy path over the REAL management canister: the Vault upgrades a
/// canister it controls, in upgrade mode, hash-bound; bytes cleared after
/// terminal evidence; module hash matches the approved hash afterwards.
#[test]
fn pic_upgrader_upgrade_happy_path() {
    let (pic, vault, upgrader) = rig_with_dummy_upgrader();
    let wasm = vault_wasm();
    let arg = candid::encode_args(()).unwrap(); // post_upgrade takes no args
    let uu = UpgraderUpgrade {
        expected_wasm_hash: sha256(&wasm),
        expected_arg_hash: sha256(&arg),
        wasm_bytes: wasm.clone(),
        arg_bytes: arg,
    };
    let id = propose(&pic, vault, p(S1), VaultActionKind::UpgraderUpgrade(uu));
    approve(&pic, vault, p(S1), id).unwrap();
    let out = approve(&pic, vault, p(S2), id).unwrap();
    assert!(
        matches!(
            out,
            ApprovalOutcome::PriorResult {
                outcome: ActionOutcome::Executed,
                ..
            }
        ),
        "quorum approval drives execution to Executed: {out:?}"
    );
    // The delivered module is exactly the approved hash.
    let status = pic.canister_status(upgrader, Some(vault)).unwrap();
    assert_eq!(
        status.module_hash.as_deref(),
        Some(sha256(&wasm).as_slice()),
        "delivered bytes == approved hash"
    );
    // Artifact bytes cleared after terminal evidence durable; hashes kept.
    let view = get_proposal(&pic, vault, p(S1), id).unwrap();
    match view.action {
        ActionView::UpgraderUpgrade { bytes_retained, .. } => assert!(!bytes_retained),
        _ => panic!("wrong action view"),
    }
}

/// Crash at install_code → OutcomeUnknown (bytes retained) → typed reconcile
/// to Failed on objective evidence → never re-triggerable. F-4 signer set
/// lands in the reconciliation audit event (asserted natively; here the
/// end-to-end legality chain is what is under test).
#[test]
fn pic_upgrader_upgrade_crash_then_reconcile_failed() {
    let (pic, vault, upgrader) = rig_with_dummy_upgrader();

    // A validly-hash-bound but NOT-loadable module: install_code rejects it,
    // which is the honest OutcomeUnknown path (never Failed, never retried).
    let bad_wasm = b"\0asm-not-a-real-module".to_vec();
    let arg = candid::encode_args(()).unwrap();
    let uu = UpgraderUpgrade {
        expected_wasm_hash: sha256(&bad_wasm),
        expected_arg_hash: sha256(&arg),
        wasm_bytes: bad_wasm.clone(),
        arg_bytes: arg,
    };
    let target = propose(&pic, vault, p(S1), VaultActionKind::UpgraderUpgrade(uu));
    approve(&pic, vault, p(S1), target).unwrap();
    let out = approve(&pic, vault, p(S2), target).unwrap();
    assert!(
        matches!(
            out,
            ApprovalOutcome::PriorResult {
                outcome: ActionOutcome::OutcomeUnknown,
                ..
            }
        ),
        "rejected install lands OutcomeUnknown: {out:?}"
    );
    // Never back to Pending; bytes retained pending terminal evidence.
    let view = get_proposal(&pic, vault, p(S1), target).unwrap();
    assert_eq!(view.outcome, ActionOutcome::OutcomeUnknown);
    match view.action {
        ActionView::UpgraderUpgrade { bytes_retained, .. } => assert!(bytes_retained),
        _ => panic!(),
    }

    // Typed reconciliation (freeze §3d): evidence shows the delivered module
    // is NOT the approved hash → terminal Failed.
    let status = pic.canister_status(upgrader, Some(vault)).unwrap();
    // L1-3: evidence must be fresh — observed_at within [intent, now].
    let observed_now = pic.get_time().as_nanos_since_unix_epoch();
    let observed_status = match format!("{:?}", status.status).as_str() {
        "Running" => ObservedCanisterStatus::Running,
        "Stopping" => ObservedCanisterStatus::Stopping,
        other => panic!("unexpected canister status: {other}"),
    };
    let rec_action = VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
        proposal_id: target,
        objective_evidence: UpgradeObjectiveEvidence {
            observed_upgrader_principal: upgrader, // durable counterpart from init
            observed_module_hash: status.module_hash.clone(),
            observed_controllers: status.settings.controllers.clone(),
            observed_canister_status: observed_status,
            observed_at_ns: observed_now,
        },
    });
    let rid = propose(&pic, vault, p(S1), rec_action);
    approve(&pic, vault, p(S1), rid).unwrap();
    let rout = approve(&pic, vault, p(S2), rid).unwrap();
    assert!(matches!(
        rout,
        ApprovalOutcome::PriorResult {
            outcome: ActionOutcome::Executed,
            ..
        }
    ));
    let view = get_proposal(&pic, vault, p(S1), target).unwrap();
    assert_eq!(view.outcome, ActionOutcome::Failed, "evidence → terminal Failed");
    // Never re-triggerable: a second reconcile proposal is rejected
    // (legal source state is OutcomeUnknown ONLY), and approve replays.
    let rec_again = VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
        proposal_id: target,
        objective_evidence: UpgradeObjectiveEvidence {
            observed_upgrader_principal: upgrader,
            observed_module_hash: status.module_hash,
            observed_controllers: status.settings.controllers,
            observed_canister_status: observed_status,
            observed_at_ns: observed_now,
        },
    });
    let raw = pic
        .update_call(
            vault,
            p(S1),
            "propose",
            candid::encode_one(&rec_again).unwrap(),
        )
        .unwrap();
    assert_eq!(
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw)).unwrap(),
        Err(VaultError::IllegalSourceState)
    );
}

/// Removed signer sees the same `None` as anonymous/unknown — over real
/// ingress, after a real epoch-advancing governance transition.
#[test]
fn pic_removed_signer_query_negative_and_stale_epoch_rejection() {
    let (pic, vault) = rig();
    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::UpdateSignerSet {
            signers: vec![p(S1), p(S2)],
            threshold: 2,
        },
    );
    approve(&pic, vault, p(S1), id).unwrap();
    let out = approve(&pic, vault, p(S2), id).unwrap();
    assert!(matches!(
        out,
        ApprovalOutcome::PriorResult {
            outcome: ActionOutcome::Executed,
            ..
        }
    ));
    assert_eq!(summary(&pic, vault).governance_epoch, 1);
    // Removed (stale-epoch) signer: indistinguishable None everywhere gated.
    assert_eq!(get_signers(&pic, vault, p(S3)), None);
    assert_eq!(get_proposal(&pic, vault, p(S3), id), None);
    // Stale-epoch approval: a proposal from epoch 0 cannot be approved now.
    // (Any new proposal is epoch 1; craft the stale case via a fresh propose
    // before a second transition.)
    let stale = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::UpdateSignerSet {
            signers: vec![p(S1), p(S2)],
            threshold: 2,
        },
    );
    let bump = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::UpdateSignerSet {
            signers: vec![p(S1), p(S2), p(4)],
            threshold: 2,
        },
    );
    approve(&pic, vault, p(S1), bump).unwrap();
    approve(&pic, vault, p(S2), bump).unwrap();
    assert_eq!(
        approve(&pic, vault, p(S2), stale),
        Err(VaultError::StaleEpoch {
            expected: 2,
            found: 1
        })
    );
}

/// Durable state — proposals, audit, reservations implicitly via replay —
/// survives a REAL canister upgrade. (post_upgrade revalidation fail-closed
/// is covered natively; here the byte-for-byte survival is the claim.)
#[test]
fn pic_state_survives_real_upgrade() {
    let (pic, vault, target) = rig_with_governed_target();
    pic.stop_canister(target, Some(vault)).unwrap();
    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::Start { target }),
    );
    approve(&pic, vault, p(S1), id).unwrap();
    approve(&pic, vault, p(S2), id).unwrap();
    // Upgrade the Vault to itself (post_upgrade revalidates the cell).
    pic.upgrade_canister(vault, vault_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("upgrade succeeds");
    let view = get_proposal(&pic, vault, p(S1), id).unwrap();
    assert_eq!(view.outcome, ActionOutcome::Executed);
    assert_eq!(view.approvals, vec![p(S1), p(S2)]);
    // Replay after upgrade: the permanent reservation still returns the
    // prior result — never a re-execution.
    let replay = approve(&pic, vault, p(S3), id).unwrap();
    assert!(matches!(
        replay,
        ApprovalOutcome::PriorResult {
            outcome: ActionOutcome::Executed,
            ..
        }
    ));
    assert_eq!(summary(&pic, vault).signer_count, 3);
}

// ── L1-1/L1-4 over real ingress: receipt → allowlist → governed management ──

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
struct CreationReceiptPage {
    items: Vec<CreationReceipt>,
    next_cursor: Option<u64>,
}

fn get_creation_receipts(
    pic: &PocketIc,
    vault: Principal,
    sender: Principal,
) -> Option<CreationReceiptPage> {
    let r = pic
        .query_call(
            vault,
            sender,
            "get_creation_receipts",
            candid::encode_args((None::<u64>, 128u32)).unwrap(),
        )
        .expect("query");
    candid::decode_one::<Option<CreationReceiptPage>>(&r).unwrap()
}

fn get_governed_targets(
    pic: &PocketIc,
    vault: Principal,
    sender: Principal,
) -> Option<(VaultTargets, Vec<GovernedTarget>)> {
    let r = pic
        .query_call(
            vault,
            sender,
            "get_governed_targets",
            candid::encode_args(()).unwrap(),
        )
        .expect("query");
    candid::decode_one::<Option<(VaultTargets, Vec<GovernedTarget>)>>(&r).unwrap()
}

#[test]
fn pic_creation_receipt_binds_governed_target_end_to_end() {
    let (pic, vault) = rig();
    // A governed CreateCanister over the REAL management canister.
    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::CreateCanister {
            manifest_purpose: "verifier".to_string(),
            disposition: ManifestDisposition::BornUnderVault,
        }),
    );
    approve(&pic, vault, p(S1), id).unwrap();
    let out = approve(&pic, vault, p(S2), id).unwrap();
    assert!(matches!(
        out,
        ApprovalOutcome::PriorResult {
            outcome: ActionOutcome::Executed,
            ..
        }
    ));
    // Typed receipt read-back: exact fields, signer-gated.
    let receipts = get_creation_receipts(&pic, vault, p(S1)).expect("signer reads receipts");
    assert_eq!(receipts.items.len(), 1);
    assert_eq!(receipts.next_cursor, None);
    let r = &receipts.items[0];
    assert_eq!(r.proposal_id, id);
    assert_eq!(r.purpose, "verifier");
    assert_eq!(r.disposition, ManifestDisposition::BornUnderVault);
    assert_eq!(r.status, CreationReceiptStatus::Bound);
    // Anonymous / unknown: indistinguishable None.
    assert_eq!(get_creation_receipts(&pic, vault, Principal::anonymous()), None);
    assert_eq!(get_creation_receipts(&pic, vault, p(77)), None);
    // The created principal is now governed — a real Start against it works,
    // while an unknown principal is rejected at propose.
    let (_, governed) = get_governed_targets(&pic, vault, p(S1)).expect("governed read-back");
    assert!(governed.iter().any(|t| t.principal == r.principal));
    let start = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::Start {
            target: r.principal,
        }),
    );
    approve(&pic, vault, p(S1), start).unwrap();
    approve(&pic, vault, p(S2), start).unwrap();
    assert_eq!(
        get_proposal(&pic, vault, p(S1), start).unwrap().outcome,
        ActionOutcome::Executed
    );
    let raw = pic
        .update_call(
            vault,
            p(S1),
            "propose",
            candid::encode_one(&VaultActionKind::Management(ManagementAction::Stop {
                target: p(88),
            }))
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw)).unwrap(),
        Err(VaultError::NotAuthorized),
        "unknown target fails closed over real ingress"
    );
}

// ── §3e CUST-L12-01: governed Vault upgrade THROUGH the Upgrader ─────────────
//
// Real two-canister ring: vault.wasm + upgrader.wasm built IN THE SAME
// integrated tree (post-integration the lanes share one workspace; run_gate.sh
// phase 2 builds both into this tree's target dir before tests run).
// Controllers are set to the real ring shape: vault→[upgrader],
// upgrader→[vault].

/// The `--features testing` Upgrader Wasm, carrying the index-corruption hook.
/// The PINNED PREDECESSOR Upgrader Wasm — the last build BEFORE MemoryId 10 and
/// the companion schema bump (commit `d12df2c`, `COMPANION_STATE_SCHEMA_VERSION
/// = 1`, no `NONTERMINAL_RECOVERY_PROPOSAL_INDEX`).
///
/// A GENUINE predecessor binary, built from a pinned commit by `run_gate.sh`,
/// not a synthetic V1 record planted by a test helper. SSA ruled option (a)
/// explicitly and refused an interim (b): the whole history of this item is
/// substitutes reading stronger than they are.
fn upgrader_pre_b1_wasm() -> Vec<u8> {
    let path = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
        .join("wasm32-unknown-unknown/release/upgrader_pre_b1_d12df2c_test.wasm");
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "upgrader_pre_b1_d12df2c_test.wasm not found at {}: {e}\nBuild it (run_gate.sh \
             prerequisite):\n  git worktree add --detach /tmp/stsh-upgrader-pre-b1 d12df2c \
             && (cd /tmp/stsh-upgrader-pre-b1 && cargo build --target wasm32-unknown-unknown \
             --release -p upgrader --features testing)",
            path.display()
        )
    })
}

fn upgrader_test_wasm() -> Vec<u8> {
    let path = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
        .join("wasm32-unknown-unknown/release/upgrader_test.wasm");
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "upgrader_test.wasm not found at {}: {e}\nBuild it (law #7 phase 1):\n  \
             cargo build --target wasm32-unknown-unknown --release -p upgrader --features testing \
             && cp target/wasm32-unknown-unknown/release/upgrader.wasm \
             target/wasm32-unknown-unknown/release/upgrader_test.wasm",
            path.display()
        )
    })
}

fn upgrader_wasm() -> Vec<u8> {
    // CARGO_TARGET_DIR-aware, falling back to the workspace target dir
    // (CARGO_MANIFEST_DIR = canisters/vault).
    let path = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
        })
        .join("wasm32-unknown-unknown/release/upgrader.wasm");
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "upgrader.wasm not found at {}: {e}\nBuild it in THIS tree:\n  \
             cargo build --target wasm32-unknown-unknown --release -p upgrader",
            path.display()
        )
    })
}

/// The closed ring: vault and upgrader deployed with each other as their
/// recorded counterpart, controllers set to the invariant shape.
/// `ring_rig`, but the Upgrader runs the `testing` Wasm so the index-corruption
/// hook is reachable.
fn ring_rig_upgrader_test_wasm() -> (PocketIc, Principal, Principal) {
    let pic = PocketIc::new();
    let upgrader = pic.create_canister();
    let vault = pic.create_canister();
    pic.add_cycles(upgrader, 10_000_000_000_000u128);
    pic.add_cycles(vault, 10_000_000_000_000u128);
    let uinit = UpgraderInitArgs {
        recovery_members: vec![p(11), p(12), p(13)],
        threshold: 2,
        vault,
    };
    pic.install_canister(upgrader, upgrader_test_wasm(), candid::encode_one(&uinit).unwrap(), None);
    let vinit = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
            upgrader,
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(vault, vault_wasm(), candid::encode_one(&vinit).unwrap(), None);
    pic.set_controllers(vault, None, vec![upgrader]).unwrap();
    pic.set_controllers(upgrader, None, vec![vault]).unwrap();
    (pic, vault, upgrader)
}

fn ring_rig() -> (PocketIc, Principal, Principal) {
    let pic = PocketIc::new();
    let upgrader = pic.create_canister();
    let vault = pic.create_canister();
    pic.add_cycles(upgrader, 10_000_000_000_000u128);
    pic.add_cycles(vault, 10_000_000_000_000u128);
    let uinit = UpgraderInitArgs {
        recovery_members: vec![p(11), p(12), p(13)],
        threshold: 2,
        vault,
    };
    pic.install_canister(upgrader, upgrader_wasm(), candid::encode_one(&uinit).unwrap(), None);
    let vinit = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
            upgrader,
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(vault, vault_wasm(), candid::encode_one(&vinit).unwrap(), None);
    pic.set_controllers(vault, None, vec![upgrader]).unwrap();
    pic.set_controllers(upgrader, None, vec![vault]).unwrap();
    (pic, vault, upgrader)
}

fn vault_upgrade_action(wasm: &[u8], arg: &[u8]) -> VaultActionKind {
    VaultActionKind::VaultUpgradeViaUpgrader(VaultUpgradeViaUpgrader {
        request_id: 0, // unbound at propose; the Vault binds the proposal id
        expected_wasm_hash: sha256(wasm),
        expected_arg_hash: sha256(arg),
        wasm_bytes: wasm.to_vec(),
        arg_bytes: arg.to_vec(),
    })
}

/// 2-of-3 upgrades the Vault THROUGH the Upgrader — real end-to-end upgrade
/// of the vault canister (same module re-installed in upgrade mode).
///
/// Note the platform semantics this test documents: the Vault upgrades
/// ITSELF mid-call, so the reply callback lands on the NEW module with a
/// fresh heap — the approve call cannot complete cleanly. That is exactly
/// why the durable-intent + reconciliation contract exists: the intent is
/// Executing/OutcomeUnknown, the module DID change, and the typed reconcile
/// settles it to Executed on objective evidence.
#[test]
fn pic_ring_vault_upgrade_via_upgrader_end_to_end() {
    let (pic, vault, upgrader) = ring_rig();
    let wasm = vault_wasm();
    let arg = candid::encode_args(()).unwrap();
    let id = propose(&pic, vault, p(S1), vault_upgrade_action(&wasm, &arg));
    let a1 = approve(&pic, vault, p(S1), id).unwrap();
    assert!(matches!(a1, ApprovalOutcome::Approved { approvals: 1, .. }));
    // The quorum approval triggers the self-upgrade; the reply callback
    // lands on the replaced module and cannot complete (reject expected).
    // Raw call: the reply callback lands on the REPLACED module and cannot
    // complete, so the helper's decode would be meaningless. The commitment is
    // read BEFORE the upgrade, while the module can still answer.
    let commitment = get_proposal(&pic, vault, p(S1), id).unwrap().commitment_hash;
    let _ = pic.update_call(
        vault,
        p(S2),
        "approve",
        candid::encode_args((id, commitment)).unwrap(),
    );
    // The upgrade really happened, observed via the Upgrader as controller.
    let status = pic.canister_status(vault, Some(upgrader)).unwrap();
    assert_eq!(
        status.module_hash.as_deref(),
        Some(sha256(&wasm).as_slice()),
        "the Vault was upgraded through the Upgrader"
    );
    // The durable intent is non-terminal and never returned to Pending.
    let view = get_proposal(&pic, vault, p(S1), id).unwrap();
    assert!(
        matches!(view.outcome, ActionOutcome::Executing | ActionOutcome::OutcomeUnknown),
        "intent survives the self-upgrade: {:?}",
        view.outcome
    );
    match view.action {
        ActionView::VaultUpgradeViaUpgrader { request_id, .. } => assert_eq!(request_id, id),
        other => panic!("wrong action view: {other:?}"),
    }
    // Typed reconciliation on objective evidence settles it: the approved
    // module hash IS running → Executed.
    let rid = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader {
            request_id: id,
            objective_evidence: UpgradeObjectiveEvidence {
                observed_upgrader_principal: vault,
                observed_module_hash: status.module_hash.clone(),
                observed_controllers: status.settings.controllers.clone(),
                observed_canister_status: ObservedCanisterStatus::Running,
                observed_at_ns: pic.get_time().as_nanos_since_unix_epoch(),
            },
        }),
    );
    approve(&pic, vault, p(S1), rid).unwrap();
    let rout = approve(&pic, vault, p(S2), rid).unwrap();
    assert!(matches!(
        rout,
        ApprovalOutcome::PriorResult {
            outcome: ActionOutcome::Executed,
            ..
        }
    ));
    let view = get_proposal(&pic, vault, p(S1), id).unwrap();
    assert_eq!(view.outcome, ActionOutcome::Executed, "reconciled to Executed");
    match view.action {
        ActionView::VaultUpgradeViaUpgrader { bytes_retained, .. } => assert!(!bytes_retained),
        _ => panic!(),
    }
    // The upgraded Vault still governs itself.
    assert_eq!(summary(&pic, vault).signer_count, 3);
}

/// One signer cannot trigger it; direct callers cannot spoof the Vault at
/// the Upgrader.
#[test]
fn pic_ring_one_signer_cannot_trigger_and_spoofing_rejected() {
    let (pic, vault, upgrader) = ring_rig();
    let wasm = vault_wasm();
    let arg = candid::encode_args(()).unwrap();
    let id = propose(&pic, vault, p(S1), vault_upgrade_action(&wasm, &arg));
    let a1 = approve(&pic, vault, p(S1), id).unwrap();
    assert!(
        matches!(a1, ApprovalOutcome::Approved { approvals: 1, threshold: 2 }),
        "one approval stays below quorum: {a1:?}"
    );
    assert_eq!(
        get_proposal(&pic, vault, p(S1), id).unwrap().outcome,
        ActionOutcome::Pending
    );
    // Direct caller at the Upgrader, NOT the Vault: rejected.
    let payload = candid::encode_args((
        99u64,
        sha256(&wasm),
        sha256(&arg),
        wasm.clone(),
        arg.clone(),
    ))
    .unwrap();
    for spoofer in [Principal::anonymous(), p(S1), p(77)] {
        let raw = pic
            .update_call(upgrader, spoofer, "trigger_vault_upgrade", payload.clone())
            .unwrap();
        let r = candid::decode_one::<Result<TriggerUpgradeResult, RecoveryError>>(&raw).unwrap();
        assert!(r.is_err(), "spoofer {spoofer} must be rejected");
    }
}

/// Crash at the Upgrader's install → OutcomeUnknown (no retry) → normal
/// Vault-originated reconciliation while the Vault is available.
#[test]
fn pic_ring_transport_unknown_then_normal_reconcile() {
    let (pic, vault, upgrader) = ring_rig();
    // Hash-bound but non-loadable module: the Upgrader's install_code
    // rejects — the honest OutcomeUnknown path, no retry.
    let bad = b"\0asm-not-a-real-module".to_vec();
    let arg = candid::encode_args(()).unwrap();
    let id = propose(&pic, vault, p(S1), vault_upgrade_action(&bad, &arg));
    approve(&pic, vault, p(S1), id).unwrap();
    let out = approve(&pic, vault, p(S2), id).unwrap();
    assert!(
        matches!(
            out,
            ApprovalOutcome::PriorResult {
                outcome: ActionOutcome::OutcomeUnknown,
                ..
            }
        ),
        "rejected install lands OutcomeUnknown: {out:?}"
    );
    // Normal reconciliation via the Upgrader's reconcile_vault_upgrade:
    // evidence shows the approved module did NOT land → terminal Failed.
    let status = pic.canister_status(vault, Some(upgrader)).unwrap();
    let rid = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader {
            request_id: id,
            objective_evidence: UpgradeObjectiveEvidence {
                observed_upgrader_principal: vault, // frozen field binds the Vault here
                observed_module_hash: status.module_hash.clone(),
                observed_controllers: status.settings.controllers.clone(),
                observed_canister_status: ObservedCanisterStatus::Running,
                observed_at_ns: pic.get_time().as_nanos_since_unix_epoch(),
            },
        }),
    );
    approve(&pic, vault, p(S1), rid).unwrap();
    let rout = approve(&pic, vault, p(S2), rid).unwrap();
    assert!(matches!(
        rout,
        ApprovalOutcome::PriorResult {
            outcome: ActionOutcome::Executed,
            ..
        }
    ));
    assert_eq!(
        get_proposal(&pic, vault, p(S1), id).unwrap().outcome,
        ActionOutcome::Failed,
        "evidence → terminal Failed on the upgrade intent"
    );
    // Never re-triggerable.
    let raw = pic
        .update_call(
            vault,
            p(S1),
            "propose",
            candid::encode_one(&VaultActionKind::ReconcileVaultUpgradeViaUpgrader(
                ReconcileVaultUpgradeViaUpgrader {
                    request_id: id,
                    objective_evidence: UpgradeObjectiveEvidence {
                        observed_upgrader_principal: vault,
                        observed_module_hash: status.module_hash,
                        observed_controllers: status.settings.controllers,
                        observed_canister_status: ObservedCanisterStatus::Running,
                        observed_at_ns: pic.get_time().as_nanos_since_unix_epoch(),
                    },
                },
            ))
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw)).unwrap(),
        Err(VaultError::IllegalSourceState)
    );
}

/// The direct §3d UpgraderUpgrade (upgrading the UPGRADER) still works
/// independently — distinct namespace, distinct lock.
#[test]
fn pic_ring_direct_upgrader_upgrade_still_works() {
    let (pic, vault, upgrader) = ring_rig();
    let wasm = upgrader_wasm();
    let arg = candid::encode_args(()).unwrap();
    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
            expected_wasm_hash: sha256(&wasm),
            expected_arg_hash: sha256(&arg),
            wasm_bytes: wasm.clone(),
            arg_bytes: arg,
        }),
    );
    approve(&pic, vault, p(S1), id).unwrap();
    let out = approve(&pic, vault, p(S2), id).unwrap();
    assert!(matches!(
        out,
        ApprovalOutcome::PriorResult {
            outcome: ActionOutcome::Executed,
            ..
        }
    ));
    let status = pic.canister_status(upgrader, Some(vault)).unwrap();
    assert_eq!(status.module_hash.as_deref(), Some(sha256(&wasm).as_slice()));
}

/// The recovery plane exists independently of the Vault's new normal path —
/// a recovery member can still propose directly at the Upgrader (2-of-3
/// fallback when the Vault is unavailable is L2's test domain; this proves
/// my side neither blocks nor bypasses it).
#[test]
fn pic_ring_recovery_plane_independent() {
    let (pic, _vault, upgrader) = ring_rig();
    let wasm = vault_wasm();
    let action = RecoveryAction::TriggerVaultUpgrade {
        expected_wasm_hash: sha256(&wasm),
        expected_arg_hash: sha256(&candid::encode_args(()).unwrap()),
        wasm_bytes: wasm,
        arg_bytes: candid::encode_args(()).unwrap(),
    };
    let raw = pic
        .update_call(
            upgrader,
            p(11),
            "propose_recovery",
            candid::encode_one(&action).unwrap(),
        )
        .unwrap();
    let r = candid::decode_one::<Result<u64, RecoveryError>>(&raw).unwrap();
    assert!(r.is_ok(), "recovery proposal accepted independently: {r:?}");
    // A non-member cannot use the recovery plane.
    let raw = pic
        .update_call(
            upgrader,
            p(77),
            "propose_recovery",
            candid::encode_one(&RecoveryAction::TriggerVaultUpgrade {
                expected_wasm_hash: sha256(b"x"),
                expected_arg_hash: sha256(b"y"),
                wasm_bytes: b"x".to_vec(),
                arg_bytes: b"y".to_vec(),
            })
            .unwrap(),
        )
        .unwrap();
    assert!(candid::decode_one::<Result<u64, RecoveryError>>(&raw)
        .unwrap()
        .is_err());
}

// ── CUST-L12-02: recovery plane vs normal-path attribution ──────────────────

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
enum AuditKind {
    ProposalCreated,
    ApprovalAdded,
    QuorumReached,
    Executed,
    Failed,
    OutcomeUnknown,
    GovernanceTransition,
    Reconciled,
    ReconcileConflict,
    SnapshotStored,
    CanisterCreated,
    // R3.7/R3.8 — a client missing these cannot decode an audit page that
    // contains one, so they are part of the wire contract. This mirror was
    // missing both until CONF-02's coverage was completed: any test decoding a
    // page containing a cancelled or expired proposal would have failed on the
    // wire, and none happened to.
    ProposalCancelled,
    ProposalExpired,
    /// §S7 §3c.3 / §7d.1 — same wire-contract reasoning: a client missing these
    /// cannot decode a page containing one.
    LateCallbackFenced,
    SettlementEvidenceConflict,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
struct AuditEvent {
    id: u64,
    at_ns: u64,
    epoch: u64,
    kind: AuditKind,
    proposal_id: Option<u64>,
    actor: Principal,
    approving_signers: Option<Vec<Principal>>,
    creation_receipt: Option<CreationReceipt>,
    /// §S7 §7d.1 — the frozen eight-field payload, present exactly on
    /// SettlementEvidenceConflict events.
    settlement_conflict: Option<stsh_custody_types::SettlementEvidenceConflict>,
    detail: String,
}

fn audit_events(pic: &PocketIc, vault: Principal, sender: Principal) -> Vec<AuditEvent> {
    let r = pic
        .query_call(
            vault,
            sender,
            "get_audit_events",
            candid::encode_args((None::<u64>, 128u32)).unwrap(),
        )
        .expect("query");
    candid::decode_one::<Option<Vec<AuditEvent>>>(&r)
        .unwrap()
        .expect("signer reads audit")
}

fn recover_vault(pic: &PocketIc, upgrader: Principal, wasm: &[u8], arg: &[u8]) {
    let action = RecoveryAction::TriggerVaultUpgrade {
        expected_wasm_hash: sha256(wasm),
        expected_arg_hash: sha256(arg),
        wasm_bytes: wasm.to_vec(),
        arg_bytes: arg.to_vec(),
    };
    let raw = pic
        .update_call(
            upgrader,
            p(11),
            "propose_recovery",
            candid::encode_one(&action).unwrap(),
        )
        .unwrap();
    let rid = candid::decode_one::<Result<u64, RecoveryError>>(&raw)
        .unwrap()
        .expect("recovery proposal");
    // R1.1 (V8 §3, CTO R-1a): proposing approves NOTHING, so BOTH members
    // approve explicitly. Previously the proposer's approval was seeded at
    // propose and only one further approval was needed — that implicit
    // approval was necessarily unbound, which is CUST-SSA-001.
    // R1.5: approve_recovery REQUIRES the expected commitment hash, read from
    // the signer-gated proposal view exactly as a real member would.
    for m in [p(11), p(12)] {
        let raw = pic
            .query_call(
                upgrader,
                m,
                "get_recovery_proposal",
                candid::encode_one(&rid).unwrap(),
            )
            .unwrap();
        let hash = candid::decode_one::<Option<stsh_custody_types::RecoveryProposal>>(&raw)
            .unwrap()
            .expect("member may read the proposal to obtain its commitment")
            .commitment_hash;
        let raw = pic
            .update_call(
                upgrader,
                m,
                "approve_recovery",
                candid::encode_args((rid, hash)).unwrap(),
            )
            .unwrap();
        candid::decode_one::<Result<(), RecoveryError>>(&raw)
            .unwrap()
            .expect("recovery approval");
    }
}

/// Drive the normal path to OutcomeUnknown WITHOUT an L2 intent: the
/// Upgrader is stopped when the trigger fires, so the call rejects and no
/// intent exists at L2.
fn normal_request_outcome_unknown_without_l2_intent(
    pic: &PocketIc,
    vault: Principal,
    upgrader: Principal,
    wasm: &[u8],
) -> u64 {
    pic.stop_canister(upgrader, Some(vault)).unwrap();
    let arg = candid::encode_args(()).unwrap();
    let id = propose(pic, vault, p(S1), vault_upgrade_action(wasm, &arg));
    approve(pic, vault, p(S1), id).unwrap();
    let out = approve(pic, vault, p(S2), id).unwrap();
    pic.start_canister(upgrader, Some(vault)).unwrap();
    assert!(
        matches!(
            out,
            ApprovalOutcome::PriorResult {
                outcome: ActionOutcome::OutcomeUnknown,
                ..
            }
        ),
        "trigger to a stopped Upgrader → OutcomeUnknown, no L2 intent: {out:?}"
    );
    id
}

fn reconcile_normal(
    pic: &PocketIc,
    vault: Principal,
    upgrader: Principal,
    target: u64,
    module_hash: Option<Vec<u8>>,
) -> ApprovalOutcome {
    let status = pic.canister_status(vault, Some(upgrader)).unwrap();
    let rid = propose(
        pic,
        vault,
        p(S1),
        VaultActionKind::ReconcileVaultUpgradeViaUpgrader(ReconcileVaultUpgradeViaUpgrader {
            request_id: target,
            objective_evidence: UpgradeObjectiveEvidence {
                observed_upgrader_principal: vault,
                observed_module_hash: module_hash,
                observed_controllers: status.settings.controllers.clone(),
                observed_canister_status: ObservedCanisterStatus::Running,
                observed_at_ns: pic.get_time().as_nanos_since_unix_epoch(),
            },
        }),
    );
    approve(pic, vault, p(S1), rid).unwrap();
    approve(pic, vault, p(S2), rid).unwrap()
}

/// Recovery plane installs the SAME wasm while the normal L2 request is
/// absent → the normal proposal must NOT receive attribution (CUST-L12-03:
/// terminal Failed-as-no-admission, NEVER Executed — and the wedge is gone).
#[test]
fn pic_ring_recovery_same_wasm_no_attribution() {
    let (pic, vault, upgrader) = ring_rig();
    let wasm = vault_wasm();
    let target = normal_request_outcome_unknown_without_l2_intent(&pic, vault, upgrader, &wasm);
    // Recovery plane installs the same bytes (2-of-3 recovery members).
    let arg = candid::encode_args(()).unwrap();
    recover_vault(&pic, upgrader, &wasm, &arg);
    let status = pic.canister_status(vault, Some(upgrader)).unwrap();
    assert_eq!(status.module_hash.as_deref(), Some(sha256(&wasm).as_slice()));
    // Evidence would say "Executed" (module matches!) — but L2 has no
    // normal intent for the request id: no admission → terminal Failed,
    // NEVER Executed.
    let rout = reconcile_normal(&pic, vault, upgrader, target, status.module_hash.clone());
    assert!(
        matches!(
            rout,
            ApprovalOutcome::PriorResult {
                outcome: ActionOutcome::Executed, // the reconcile proposal itself resolves…
                ..
            }
        ),
        "reconcile outcome: {rout:?}"
    );
    let view = get_proposal(&pic, vault, p(S1), target).unwrap();
    assert_eq!(
        view.outcome,
        ActionOutcome::Failed,
        "…terminalizing the upgrade intent as no-admission Failed — never Executed"
    );
    assert!(audit_events(&pic, vault, p(S1))
        .iter()
        .any(|e| e.kind == AuditKind::ReconcileConflict && e.proposal_id == Some(target)));
    // The wedge is gone: a FRESH normal Vault upgrade is accepted and
    // executes through the Upgrader.
    let fresh = propose(&pic, vault, p(S1), vault_upgrade_action(&wasm, &arg));
    approve(&pic, vault, p(S1), fresh).unwrap();
    let fresh_commitment = get_proposal(&pic, vault, p(S1), fresh).unwrap().commitment_hash;
    let _ = pic.update_call(
        vault,
        p(S2),
        "approve",
        candid::encode_args((fresh, fresh_commitment)).unwrap(),
    );
    let status2 = pic.canister_status(vault, Some(upgrader)).unwrap();
    assert_eq!(status2.module_hash.as_deref(), Some(sha256(&wasm).as_slice()));
    let fresh_view = get_proposal(&pic, vault, p(S1), fresh).unwrap();
    assert!(
        matches!(
            fresh_view.outcome,
            ActionOutcome::Executing | ActionOutcome::OutcomeUnknown | ActionOutcome::Executed
        ),
        "fresh normal upgrade proceeds (lock released): {:?}",
        fresh_view.outcome
    );
}

/// Recovery plane installs DIFFERENT wasm during an unresolved normal
/// request → no stranded L2 lock (recovery executes), no attribution
/// (terminal no-admission Failed, never Executed).
#[test]
fn pic_ring_recovery_different_wasm_no_false_terminalization() {
    let (pic, vault, upgrader) = ring_rig();
    let wasm = vault_wasm();
    let target = normal_request_outcome_unknown_without_l2_intent(&pic, vault, upgrader, &wasm);
    // A DIFFERENT but valid module: same code + a trailing custom section
    // (distinct hash, same functionality).
    let mut other = wasm.clone();
    other.extend_from_slice(&[0x00, 0x04, 0x02, b'h', b'i', 0x00]); // custom section "hi" + 1 payload byte
    let arg = candid::encode_args(()).unwrap();
    recover_vault(&pic, upgrader, &other, &arg);
    let status = pic.canister_status(vault, Some(upgrader)).unwrap();
    assert_eq!(
        status.module_hash.as_deref(),
        Some(sha256(&other).as_slice()),
        "recovery executed — no stranded lock from the unresolved normal request"
    );
    // L2 has no normal intent → no admission → terminal Failed, never
    // Executed, and the lock releases.
    let rout = reconcile_normal(&pic, vault, upgrader, target, status.module_hash.clone());
    assert!(matches!(
        rout,
        ApprovalOutcome::PriorResult {
            outcome: ActionOutcome::Executed,
            ..
        }
    ));
    assert_eq!(
        get_proposal(&pic, vault, p(S1), target).unwrap().outcome,
        ActionOutcome::Failed,
        "no admission → terminal Failed, never a false Executed"
    );
    // The vault still works (same code) — governance query fine.
    assert_eq!(summary(&pic, vault).signer_count, 3);
    // And the lock is released: a fresh normal proposal is accepted.
    assert!(propose(&pic, vault, p(S1), vault_upgrade_action(&wasm, &arg)) > 0);
}

// ── L3-INT-03: Vault→nullifier read-model wire compatibility ─────────────────
//
// The Vault's read-model dispatch special-cases NullifierReadSpentAt: the
// frozen nullifier endpoint `spent_at_for_controller_update(blob) -> opt
// nat64` predates the generic read-model contract, so the Vault sends the RAW
// nullifier bytes and wraps the typed Option<u64> reply. These tests exercise
const TOTAL_SUPPLY: u128 = 1_000_000_000 * 100_000_000;

#[derive(CandidType, Serialize)]
enum L02LockPolicy {
    ImmediatelyLiquid,
    LockedUntil(u64),
    Vested,
    GovernanceLocked,
}
#[derive(CandidType, Serialize)]
struct L02VestingPolicy {
    cliff_end_ns: u64,
    vesting_end_ns: u64,
}
#[derive(CandidType, Serialize)]
struct L02AllocationCategory {
    category_id: String,
    category_name: String,
    amount: u128,
    recipient: Principal,
    subaccount: Option<[u8; 32]>,
    lock_policy: L02LockPolicy,
    vesting_policy: Option<L02VestingPolicy>,
    created_at_genesis: bool,
    genesis_timestamp_ns: u64,
}
#[derive(CandidType, Serialize)]
struct L02TokenInitArgs {
    allocations: Vec<L02AllocationCategory>,
    treasury: Principal,
    staking_canister: Principal,
}
#[derive(CandidType, Serialize)]
struct L02PoolInitArgs {
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

fn predecessor_pool_wasm() -> Vec<u8> {
    let bytes = l02_wasm("shielded_pool_pre_hardening_d068_prod");
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "73f198e73de8255781e4fe423a33da841fb6ffb75acb6667b380ae44250607ea",
        "d068 shielded-pool fixture must match its literal production pin"
    );
    bytes
}

fn l02_wasm(name: &str) -> Vec<u8> {
    let path = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
        .join(format!("wasm32-unknown-unknown/release/{name}.wasm"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{name}.wasm missing at {}: {e}", path.display()))
}

fn l02_create(pic: &PocketIc, vault: Principal, purpose: &str) -> (Principal, u64) {
    let id = propose(
        pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::CreateCanister {
            manifest_purpose: purpose.to_string(),
            disposition: ManifestDisposition::BornUnderVault,
        }),
    );
    approve(pic, vault, p(S1), id).unwrap();
    approve(pic, vault, p(S2), id).unwrap();
    let event = audit_events(pic, vault, p(S1))
        .into_iter()
        .find(|event| {
            event.creation_receipt.as_ref().is_some_and(|receipt| {
                receipt.purpose == purpose && receipt.status == CreationReceiptStatus::Bound
            })
        })
        .expect("typed creation event discovered through bounded signer page");
    (event.creation_receipt.unwrap().principal, event.id)
}

#[test]
fn pic_l02_real_controller_topology_initializer_readiness_and_token_fold() {
    let (pic, vault) = rig();

    let (pool, _) = l02_create(&pic, vault, "shielded_pool");
    let pool_init = L02PoolInitArgs {
        token_canister: p(40),
        nullifier_canister: p(41),
        merkle_canister: p(42),
        treasury_canister: p(43),
        staking_canister: p(44),
        controller: vault,
        initial_vk_hash: [0; 32],
        initial_proof_system: "groth16-bn254".to_string(),
        verifier_canister: None,
    };
    pic.install_canister(
        pool,
        l02_wasm("shielded_pool"),
        candid::encode_one(pool_init).unwrap(),
        Some(vault),
    );

    let init_id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::Application(
            stsh_custody_types::ActionRequest::PoolInitializePayoutMemoKey,
        ),
    );
    approve(&pic, vault, p(S1), init_id).unwrap();
    approve(&pic, vault, p(S2), init_id).unwrap();
    assert_eq!(
        get_proposal(&pic, vault, p(S1), init_id).unwrap().outcome,
        ActionOutcome::Executed
    );

    let ready_id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::ReadModel(
            stsh_custody_types::ReadModelRequest::PoolReadPayoutMemoKeyReady,
        ),
    );
    approve(&pic, vault, p(S1), ready_id).unwrap();
    approve(&pic, vault, p(S2), ready_id).unwrap();
    let ready_view = get_proposal(&pic, vault, p(S1), ready_id).unwrap();
    assert_eq!(ready_view.outcome, ActionOutcome::Executed);
    let ready = get_snapshot(&pic, vault, p(S1), ready_view.snapshot_id.unwrap()).unwrap();
    assert_eq!(
        ready.response,
        stsh_custody_types::ReadModelResponse::PoolReadPayoutMemoKeyReady(Some(true))
    );
    let unauthorized = pic
        .update_call(
            pool,
            p(77),
            "payout_memo_key_ready_for_controller_update",
            candid::encode_args(()).unwrap(),
        )
        .expect("unauthorized readiness is indistinguishable None");
    assert_eq!(candid::decode_one::<Option<bool>>(&unauthorized).unwrap(), None);

    let (token, receipt_audit_id) = l02_create(&pic, vault, "stsh_token");
    let token_init = L02TokenInitArgs {
        allocations: vec![L02AllocationCategory {
            category_id: "all".to_string(),
            category_name: "All tokens".to_string(),
            amount: TOTAL_SUPPLY,
            recipient: p(60),
            subaccount: None,
            lock_policy: L02LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(61),
        staking_canister: p(62),
    };
    pic.install_canister(
        token,
        l02_wasm("stsh_token"),
        candid::encode_one(token_init).unwrap(),
        Some(vault),
    );
    let fold_id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::ReadModel(
            stsh_custody_types::ReadModelRequest::TokenReadSupplyReconciliation {
                receipt_audit_id,
            },
        ),
    );
    approve(&pic, vault, p(S1), fold_id).unwrap();
    approve(&pic, vault, p(S2), fold_id).unwrap();
    let fold_view = get_proposal(&pic, vault, p(S1), fold_id).unwrap();
    assert_eq!(fold_view.outcome, ActionOutcome::Executed);
    let fold = get_snapshot(&pic, vault, p(S1), fold_view.snapshot_id.unwrap()).unwrap();
    let stsh_custody_types::ReadModelResponse::TokenReadSupplyReconciliation(report) =
        fold.response
    else {
        panic!("typed token reconciliation snapshot required")
    };
    assert!(report.totals_consistent);
    assert!(report.folded_first_law_holds);
    assert_eq!(fold.source_canister, token);
}

// the REAL wire: vault.wasm + the real nullifier_registry.wasm over PocketIC.

fn nullifier_wasm() -> Vec<u8> {
    let path = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
        })
        .join("wasm32-unknown-unknown/release/nullifier_registry.wasm");
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "nullifier_registry.wasm not found at {}: {e}\nBuild it in THIS tree:\n  \
             cargo build --target wasm32-unknown-unknown --release -p nullifier_registry",
            path.display()
        )
    })
}

/// Create the nullifier canister THROUGH the Vault's governed CreateCanister
/// (receipt wires the nullifier_registry role), install the real registry
/// wasm on it, and insert one nullifier as the pool. Returns the nullifier
/// canister id.
fn rig_nullifier(pic: &PocketIc, vault: Principal) -> (Principal, [u8; 32]) {
    let id = propose(
        pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::CreateCanister {
            manifest_purpose: "nullifier_registry".to_string(),
            disposition: ManifestDisposition::BornUnderVault,
        }),
    );
    approve(pic, vault, p(S1), id).unwrap();
    let out = approve(pic, vault, p(S2), id).unwrap();
    assert!(
        matches!(
            out,
            ApprovalOutcome::PriorResult { outcome: ActionOutcome::Executed, .. }
        ),
        "governed creation must execute: {out:?}"
    );
    let receipts = get_creation_receipts(pic, vault, p(S1)).expect("signer reads receipts");
    let nullifier = receipts.items[0].principal;

    // The Vault is the created canister's controller (creator). Install the
    // real registry wasm with the pool ref set to a test pool principal.
    let pool = p(50);
    pic.install_canister(
        nullifier,
        nullifier_wasm(),
        candid::encode_one(&pool).unwrap(),
        Some(vault),
    );

    // Insert one nullifier as the pool (insert_nullifier is pool-gated).
    let nf = [7u8; 32];
    let r = pic
        .update_call(
            nullifier,
            pool,
            "insert_nullifier",
            candid::encode_one(&nf.to_vec()).unwrap(),
        )
        .expect("insert call");
    let r: Result<(), String> = candid::decode_one(&r).unwrap();
    assert!(r.is_ok(), "insert_nullifier failed: {r:?}");
    (nullifier, nf)
}

fn get_snapshot(
    pic: &PocketIc,
    vault: Principal,
    sender: Principal,
    snapshot_id: u64,
) -> Option<stsh_custody_types::ControllerReadSnapshot> {
    let r = pic
        .query_call(
            vault,
            sender,
            "get_controller_read_snapshot",
            candid::encode_one(&snapshot_id).unwrap(),
        )
        .expect("snapshot query");
    candid::decode_one(&r).unwrap()
}

/// Drive a NullifierReadSpentAt read-model proposal to a snapshot; returns
/// the snapshot id.
fn drive_nullifier_read(pic: &PocketIc, vault: Principal, nf: [u8; 32]) -> u64 {
    let id = propose(
        pic,
        vault,
        p(S1),
        VaultActionKind::ReadModel(stsh_custody_types::ReadModelRequest::NullifierReadSpentAt {
            nullifier: nf,
            page: stsh_custody_types::PageRequest { cursor: None, limit: 10 },
        }),
    );
    approve(pic, vault, p(S1), id).unwrap();
    approve(pic, vault, p(S2), id).unwrap();
    let view = get_proposal(pic, vault, p(S1), id).expect("proposal readable");
    assert_eq!(
        view.outcome,
        ActionOutcome::Executed,
        "read-model proposal must execute (wire-compatible): {view:?}"
    );
    view.snapshot_id.expect("a snapshot is recorded")
}

#[test]
fn pic_nullifier_read_model_wire_compatibility() {
    let (pic, vault) = rig();
    let (nullifier, nf) = rig_nullifier(&pic, vault);

    // ── SUCCESS: an inserted nullifier flows Some(spent_at) into a durable
    //    snapshot, over the REAL wire contract. ──
    let snap_id = drive_nullifier_read(&pic, vault, nf);
    let snap = get_snapshot(&pic, vault, p(S1), snap_id).expect("signer reads snapshot");
    assert_eq!(snap.source_canister, nullifier);
    assert_eq!(snap.snapshot_id, snap_id);
    assert_eq!(snap.governance_epoch, 0, "no governance transition happened");
    let stsh_custody_types::ReadModelResponse::NullifierReadSpentAt { items, next_cursor } =
        &snap.response
    else {
        panic!("snapshot response must be the nullifier page, got {:?}", snap.response)
    };
    assert!(next_cursor.is_none());
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].nullifier, nf);
    assert!(
        items[0].spent_at.is_some(),
        "inserted nullifier must report Some(spent_at) over the wire"
    );
    // Snapshot storage correctness: the bound request is recorded verbatim.
    let stsh_custody_types::ReadModelRequest::NullifierReadSpentAt {
        nullifier: nf_recorded,
        page,
    } = snap.request
    else {
        panic!("snapshot request must be the nullifier variant")
    };
    assert_eq!(nf_recorded, nf);
    assert_eq!(page.limit, 10);
    assert!(page.cursor.is_none());
    // Signer-gated: anonymous and unknown principals get indistinguishable None.
    assert_eq!(get_snapshot(&pic, vault, Principal::anonymous(), snap_id), None);
    assert_eq!(get_snapshot(&pic, vault, p(77), snap_id), None);

    // ── UNKNOWN nullifier → None over the wire, still Executed. ──
    let unknown = [9u8; 32];
    let snap_id2 = drive_nullifier_read(&pic, vault, unknown);
    let snap2 = get_snapshot(&pic, vault, p(S1), snap_id2).expect("snapshot");
    let stsh_custody_types::ReadModelResponse::NullifierReadSpentAt { items, .. } =
        &snap2.response
    else {
        panic!("wrong response variant")
    };
    assert_eq!(items[0].nullifier, unknown);
    assert_eq!(items[0].spent_at, None, "unknown nullifier must report None");

    // ── UNAUTHORIZED direct caller at the nullifier endpoint → rejected
    //    (assert_ic_controller traps: the caller is not a controller). ──
    let rejected = pic.update_call(
        nullifier,
        p(77),
        "spent_at_for_controller_update",
        candid::encode_one(&nf.to_vec()).unwrap(),
    );
    assert!(
        rejected.is_err(),
        "non-controller direct call must be rejected by the nullifier canister"
    );
    let rejected_anon = pic.update_call(
        nullifier,
        Principal::anonymous(),
        "spent_at_for_controller_update",
        candid::encode_one(&nf.to_vec()).unwrap(),
    );
    assert!(rejected_anon.is_err(), "anonymous direct call must be rejected");

    // ── MALFORMED request: limit 0 violates the frozen page bounds and is
    //    rejected at propose, never reaching the wire. ──
    let raw = pic
        .update_call(
            vault,
            p(S1),
            "propose",
            candid::encode_one(&VaultActionKind::ReadModel(
                stsh_custody_types::ReadModelRequest::NullifierReadSpentAt {
                    nullifier: nf,
                    page: stsh_custody_types::PageRequest { cursor: None, limit: 0 },
                },
            ))
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw)).unwrap(),
        Err(VaultError::ReadLimitExceeded { limit: 0, max: stsh_custody_types::MAX_READ_PAGE_LIMIT }),
        "limit 0 must be rejected at propose with the typed bound error"
    );
}

// ── amended R3 item 10: REAL Wasm-upgrade VALIDATION of the companions ──────
//
// SSA CUST-SSA-S5B-COMP-01: this header previously described "migration",
// "rebuild logic" and indexes "re-derived from durable state". That is the
// SUPERSEDED model. Nothing is migrated or re-derived across an upgrade: the
// companions are stable structures that survive it intact, and `post_upgrade`
// VALIDATES them and traps on disagreement.
//
// Calling `post_upgrade()` in-process proves the wiring but not the real
// boundary: the native test keeps the same process, the same stable-structure
// handles and the same heap. Only a real `upgrade_canister` replaces the Wasm
// instance, which is what makes the validation evidence real.
//
// Each assertion below is BEHAVIOURAL — the indexes are not readable over the
// wire, so what is proven is the property they exist to provide: the
// single-flight lock is still held after the upgrade, and still releases
// afterwards. A test that could only read the index would not prove the lock
// works; this does.

/// Vault MUTATING single-flight index (MemoryId 7) survives a real upgrade.
///
/// Both directions matter. A LOST entry would silently release a lock that is
/// genuinely held, admitting a second concurrent intent against the same
/// target — the exact concurrency the lock exists to forbid. A STALE entry
/// would wedge the target forever.
#[test]
fn pic_r3_mutating_single_flight_index_survives_real_upgrade() {
    let (pic, vault, upgrader) = rig_with_dummy_upgrader_test_wasm();

    // Open a durable mutating intent on the Upgrader: a hash-bound but
    // unloadable module lands OutcomeUnknown, which HOLDS the lock.
    let bad_wasm = b"\0asm-not-a-real-module".to_vec();
    let arg = candid::encode_args(()).unwrap();
    let uu = UpgraderUpgrade {
        expected_wasm_hash: sha256(&bad_wasm),
        expected_arg_hash: sha256(&arg),
        wasm_bytes: bad_wasm,
        arg_bytes: arg.clone(),
    };
    let held = propose(&pic, vault, p(S1), VaultActionKind::UpgraderUpgrade(uu));
    approve(&pic, vault, p(S1), held).unwrap();
    approve(&pic, vault, p(S2), held).unwrap();
    assert_eq!(
        get_proposal(&pic, vault, p(S1), held).unwrap().outcome,
        ActionOutcome::OutcomeUnknown,
        "the intent must be open for the lock to mean anything"
    );

    let second = |pic: &PocketIc| -> Result<u64, VaultError> {
        let other = b"\0asm-another-bad-module".to_vec();
        let uu2 = UpgraderUpgrade {
            expected_wasm_hash: sha256(&other),
            expected_arg_hash: sha256(&arg),
            wasm_bytes: other,
            arg_bytes: arg.clone(),
        };
        let raw = pic
            .update_call(
                vault,
                p(S1),
                "propose",
                candid::encode_one(&VaultActionKind::UpgraderUpgrade(uu2)).unwrap(),
            )
            .unwrap();
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw)).unwrap()
    };

    assert_eq!(
        second(&pic),
        Err(VaultError::IllegalSourceState),
        "pre-upgrade: the lock is held"
    );

    // S5B W2 — REVISED FROM THE REBUILD MODEL.
    //
    // This previously corrupted MemoryId 7 and asserted the upgrade REBUILT it
    // from PROPOSALS. Amended R3 item 10 (878d685e…) inverts that: (a) the
    // companion is authoritative, (c) `post_upgrade` may not scan permanent
    // history, and (d) inconsistency traps instead of being repaired. The old
    // assertion demanded exactly the silent reactivation (d) forbids.
    //
    // What replaces it is stronger evidence, not weaker: a corrupted companion
    // must make the REAL upgrade of the REAL production Wasm FAIL.

    // 1. INTACT: the upgrade succeeds and the lock survives untouched.
    pic.upgrade_canister(vault, vault_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("an intact companion must upgrade cleanly");
    assert_hook_absent(&pic, vault, p(S1), "corrupt_indexes_for_test");
    assert_eq!(
        second(&pic),
        Err(VaultError::IllegalSourceState),
        "post-upgrade: an intact companion must still hold the lock"
    );

    // 2. And the lock still RELEASES on terminalization, post-upgrade.
    let status = pic.canister_status(upgrader, Some(vault)).unwrap();
    let observed_status = match format!("{:?}", status.status).as_str() {
        "Running" => ObservedCanisterStatus::Running,
        "Stopping" => ObservedCanisterStatus::Stopping,
        other => panic!("unexpected canister status: {other}"),
    };
    let rec = VaultActionKind::ReconcileUpgraderUpgrade(ReconcileUpgraderUpgrade {
        proposal_id: held,
        objective_evidence: UpgradeObjectiveEvidence {
            observed_upgrader_principal: upgrader,
            observed_module_hash: status.module_hash.clone(),
            observed_controllers: status.settings.controllers.clone(),
            observed_canister_status: observed_status,
            observed_at_ns: pic.get_time().as_nanos_since_unix_epoch(),
        },
    });
    let rid = propose(&pic, vault, p(S1), rec);
    approve(&pic, vault, p(S1), rid).unwrap();
    approve(&pic, vault, p(S2), rid).unwrap();
    assert_eq!(
        get_proposal(&pic, vault, p(S1), held).unwrap().outcome,
        ActionOutcome::Failed
    );
    assert!(
        second(&pic).is_ok(),
        "post-upgrade the lock must still RELEASE on terminalization — a stale \
         index entry would wedge this target forever"
    );
}

/// S5B W2(d) — a CORRUPTED companion must make the REAL upgrade of the REAL
/// production Wasm FAIL.
///
/// This is the evidence that replaces the old rebuild assertions, and it is
/// stronger than what it replaces: the previous tests proved a corrupted index
/// was silently repaired, which under amended item 10(d) is the defect, not the
/// property. Kept as its own test rather than folded into the lock tests so a
/// failure names the cause precisely.
///
/// Uses a real message boundary and the deployable artifact, per the same
/// evidence standard W5(a) is held to — an in-process check would not prove the
/// canister actually refuses to resume.
#[test]
fn pic_w2_corrupted_companion_refuses_to_resume() {
    let (pic, vault, _upgrader) = rig_with_dummy_upgrader_test_wasm();

    // A real durable companion entry to corrupt. `inject_nonterminal_creation_
    // for_test` writes through `proposal_put` — the SAME choke point production
    // uses — so the entry and its commitment are produced by the real
    // primitive, not planted. A proposal driven to quorum here would
    // terminalize immediately and hold no companion entry at all, leaving
    // nothing to corrupt and making the assertion below vacuous (observed).
    let raw = pic
        .update_call(
            vault,
            p(S1),
            "inject_nonterminal_creation_for_test",
            candid::encode_one(&"verifier".to_string()).unwrap(),
        )
        .expect("injection hook");
    let _id = candid::decode_one::<u64>(static_bytes(raw)).expect("injected proposal id");

    // Control: intact companion upgrades cleanly. Without this the refusal
    // below would also pass against a post_upgrade that simply always trapped.
    pic.upgrade_canister(vault, vault_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("intact companion must upgrade cleanly");

    corrupt_indexes(&pic, vault);

    let refused =
        pic.upgrade_canister(vault, vault_wasm(), candid::encode_args(()).unwrap(), None);
    assert!(
        refused.is_err(),
        "W2(d): a corrupted companion MUST make post_upgrade trap. Succeeding here \
         means the canister resumed on companion state it could not validate — and \
         under the amended model there is no rebuild behind it to repair the damage."
    );
}

/// The `--features testing` Vault Wasm, carrying the injection endpoint that is
/// ABSENT from every production build.
/// `rig_with_dummy_upgrader`, but the Vault runs the `testing` Wasm so the
/// index-corruption hook is reachable.
fn rig_with_dummy_upgrader_test_wasm() -> (PocketIc, Principal, Principal) {
    let pic = PocketIc::new();
    let upgrader = pic.create_canister();
    pic.add_cycles(upgrader, 5_000_000_000_000u128);
    let dummy_init = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(11), p(12), p(13)],
            threshold: 2,
            upgrader: p(19),
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(upgrader, vault_wasm(), candid::encode_one(&dummy_init).unwrap(), None);
    let vault = pic.create_canister();
    pic.add_cycles(vault, 10_000_000_000_000u128);
    let init = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
            upgrader,
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(vault, vault_test_wasm(), candid::encode_one(&init).unwrap(), None);
    pic.set_controllers(upgrader, None, vec![vault]).unwrap();
    (pic, vault, upgrader)
}

fn vault_test_wasm() -> Vec<u8> {
    let path = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
        .join("wasm32-unknown-unknown/release/vault_test.wasm");
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "vault_test.wasm not found at {}: {e}\nBuild it (law #7 phase 1):\n  \
             cargo build --target wasm32-unknown-unknown --release -p vault --features testing \
             && cp target/wasm32-unknown-unknown/release/vault.wasm \
             target/wasm32-unknown-unknown/release/vault_test.wasm",
            path.display()
        )
    })
}

/// After upgrading to the PRODUCTION build the test-only hook must be GONE.
/// This is what proves the destination really was the deployable artifact and
/// not another testing build — without it the migration test could silently be
/// exercising the testing `post_upgrade` forever.
fn assert_hook_absent(pic: &PocketIc, canister: Principal, sender: Principal, method: &str) {
    let r = pic.update_call(canister, sender, method, candid::encode_args(()).unwrap());
    assert!(
        r.is_err(),
        "{method} is still callable after the upgrade — the destination was NOT the \
         production Wasm, so the production post_upgrade was never exercised"
    );
}

/// Drive the `testing`-only companion corruption so the upgrade that follows
/// has something to DETECT. (Not "to repair" — amended R3 item 10 ships no
/// repair surface; a drifted companion traps.) Without this the assertions
/// cannot fail: the companions are stable structures and survive a Wasm
/// replacement on their own.
fn corrupt_indexes(pic: &PocketIc, vault: Principal) {
    pic.update_call(vault, p(S1), "corrupt_indexes_for_test", candid::encode_args(()).unwrap())
        .expect("corruption hook");
}

/// Vault CREATION single-flight index (MemoryId 8) survives a real upgrade.
///
/// Keyed on the manifest purpose, so it is a genuinely different index from
/// MemoryId 7 and needs its own migration evidence.
///
/// WHY AN INJECTION WASM. An earlier version of this test let the real
/// `create_canister` settle and then RETURNED EARLY if the proposal had
/// terminalized. In a funded rig it always terminalizes, so that test never
/// reached the upgrade at all — it would have passed even if MemoryId 8 were
/// never validated. A vacuous test is worse than no test.
///
/// Production offers no nonterminal creation intent a test can hold open:
/// `create_canister` either succeeds (`Executed`) or is rejected
/// (`OutcomeUnknown`), and forcing a rejection by under-funding drains the
/// canister below its freezing threshold, so the ingress is rejected rather
/// than the state produced (measured: at 1.0T, 1.9T and 1.99T the approve call
/// fails with "out of cycles"). The `testing`-only injection writes through
/// `proposal_put`, the same choke point production uses, so the index entry is
/// produced by the real maintenance path and the upgrade validates genuine state.
///
/// The precondition is ASSERTED, never skipped.
#[test]
fn pic_r3_creation_single_flight_index_survives_real_upgrade() {
    let pic = PocketIc::new();
    let upgrader = pic.create_canister();
    // Both principals must exist before either init runs: the Upgrader's init
    // fail-closes on an anonymous counterpart.
    let vault = pic.create_canister();
    pic.add_cycles(upgrader, 5_000_000_000_000u128);
    pic.add_cycles(vault, 10_000_000_000_000u128);
    let uinit = UpgraderInitArgs {
        recovery_members: vec![p(11), p(12), p(13)],
        threshold: 2,
        vault,
    };
    pic.install_canister(upgrader, upgrader_wasm(), candid::encode_one(&uinit).unwrap(), None);
    let vinit = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
            upgrader,
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(vault, vault_test_wasm(), candid::encode_one(&vinit).unwrap(), None);

    // Plant a nonterminal creation intent through the production write path.
    let raw = pic
        .update_call(
            vault,
            p(S1),
            "inject_nonterminal_creation_for_test",
            candid::encode_one(&"treasury".to_string()).unwrap(),
        )
        .expect("injection call");
    let held = candid::decode_one::<u64>(static_bytes(raw)).unwrap();

    // PRECONDITION, ASSERTED — never skipped. Without an open creation intent
    // there is no lock to migrate and everything below would be vacuous.
    assert_eq!(
        get_proposal(&pic, vault, p(S1), held).unwrap().outcome,
        ActionOutcome::OutcomeUnknown,
        "the injected creation intent must be NONTERMINAL, or the migration \
         assertions below prove nothing"
    );

    let create = |purpose: &str| {
        VaultActionKind::Management(ManagementAction::CreateCanister {
            manifest_purpose: purpose.to_string(),
            disposition: ManifestDisposition::BornUnderVault,
        })
    };
    let same_purpose = |pic: &PocketIc| -> Result<u64, VaultError> {
        let raw = pic
            .update_call(
                vault,
                p(S1),
                "propose",
                candid::encode_one(&create("treasury")).unwrap(),
            )
            .unwrap();
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw)).unwrap()
    };
    assert_eq!(
        same_purpose(&pic),
        Err(VaultError::IllegalSourceState),
        "pre-upgrade: the purpose-scoped lock is held"
    );

    // S5B W2 — REVISED FROM THE REBUILD MODEL (see the mutating-index test and
    // `pic_w2_corrupted_companion_refuses_to_resume` for the full reasoning).
    // The companion is authoritative and is NOT re-derived; what must be proved
    // across a real upgrade is that it SURVIVES INTACT and keeps binding.
    pic.upgrade_canister(vault, vault_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("vault upgrade must succeed");
    assert_hook_absent(&pic, vault, p(S1), "corrupt_indexes_for_test");
    assert_hook_absent(&pic, vault, p(S1), "inject_nonterminal_creation_for_test");

    assert_eq!(
        same_purpose(&pic),
        Err(VaultError::IllegalSourceState),
        "post-upgrade: the creation lock MUST still bind — a MemoryId 8 entry \
         that went missing would admit a second concurrent creation for the same \
         manifest purpose, which is exactly what L1-5 forbids"
    );

    // A DIFFERENT purpose is unaffected: the lock is purpose-scoped, and the
    // companion must not collapse distinct purposes into one another.
    let raw = pic
        .update_call(
            vault,
            p(S1),
            "propose",
            candid::encode_one(&create("vesting")).unwrap(),
        )
        .unwrap();
    assert!(
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw))
            .unwrap()
            .is_ok(),
        "a different manifest purpose must remain proposable after the upgrade"
    );
}

/// Upgrader NONTERMINAL-INTENT index (MemoryId 5) survives a real upgrade.
///
/// This one is load-bearing for the recovery plane: if the entry were lost the
/// single-flight invariant would silently permit a second in-flight upgrade
/// intent, which is what makes objective reconciliation unsound (with two
/// intents open, mismatched-hash evidence can no longer prove which one
/// failed). `post_upgrade` also TRAPS if it VALIDATES more than one nonterminal
/// intent, so a successful upgrade is itself part of the evidence.
#[test]
fn pic_r3_upgrader_nonterminal_index_survives_real_upgrade() {
    let (pic, vault, upgrader) = ring_rig_upgrader_test_wasm();
    let m1 = p(11);

    let propose_trigger = |pic: &PocketIc, tag: u8| -> Result<u64, RecoveryError> {
        let wasm = vec![tag; 8];
        let arg = candid::encode_args(()).unwrap();
        let action = RecoveryAction::TriggerVaultUpgrade {
            expected_wasm_hash: sha256(&wasm),
            expected_arg_hash: sha256(&arg),
            wasm_bytes: wasm,
            arg_bytes: arg,
        };
        let raw = pic
            .update_call(
                upgrader,
                m1,
                "propose_recovery",
                candid::encode_one(&action).unwrap(),
            )
            .unwrap();
        candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw)).unwrap()
    };

    let first = propose_trigger(&pic, 0xA1).expect("first trigger proposal");
    assert!(first > 0);
    // A second nonterminal intent must be refused while the first is open.
    let blocked_before = propose_trigger(&pic, 0xA2);
    assert!(
        blocked_before.is_err(),
        "pre-upgrade: a second nonterminal intent must be refused, got {blocked_before:?}"
    );

    // S5B W2 — REVISED FROM THE REBUILD MODEL, clause (g) (both canisters).
    //
    // This previously corrupted MemoryId 5 and asserted `post_upgrade` rebuilt
    // it from `UPGRADE_INTENTS`. Amended item 10 removes that: (a) the pointer
    // is authoritative, (c) forbids the history pass, (d) requires the
    // inconsistency to trap. `rebuild_nonterminal_intent_index()` no longer
    // exists to be exercised.
    //
    // The corruption-and-probe dance is therefore gone too. It only made sense
    // while a rebuild existed to be given something to repair, and it had to work
    // around the single-flight guard by opening and withdrawing a second
    // intent — machinery that proves nothing under the amended model. Refusal
    // to resume on a corrupted companion is proved directly by
    // `pic_w2_corrupted_companion_refuses_to_resume`.
    //
    // What remains, and is the real migration property: the companion survives
    // a REAL upgrade of the REAL production Wasm INTACT and keeps binding.
    pic.upgrade_canister(
        upgrader,
        upgrader_wasm(),
        candid::encode_args(()).unwrap(),
        Some(vault),
    )
    .expect("upgrader upgrade must succeed — a trapping post_upgrade fails here");
    assert_hook_absent(&pic, upgrader, m1, "corrupt_indexes_for_test");

    let blocked_after = propose_trigger(&pic, 0xA3);
    assert!(
        blocked_after.is_err(),
        "post-upgrade: the nonterminal-intent lock MUST still be held — losing \
         it would permit two concurrent intents and make objective \
         reconciliation unsound, got {blocked_after:?}"
    );

    // Cancelling the holder releases the lock (S2.1 finding 1) — and that must
    // hold across the upgrade too, or the plane stays wedged forever.
    let raw = pic
        .update_call(
            upgrader,
            m1,
            "cancel_recovery_proposal",
            candid::encode_one(&first).unwrap(),
        )
        .unwrap();
    candid::decode_one::<Result<(), RecoveryError>>(static_bytes(raw))
        .unwrap()
        .expect("the proposer may cancel after an upgrade");
    assert!(
        propose_trigger(&pic, 0xA4).is_ok(),
        "post-upgrade the lock must still RELEASE on cancellation"
    );
}

/// S6 — REAL UPGRADE MIGRATION over BOTH expiry indexes (vault MemoryId 6,
/// upgrader MemoryId 6).
///
/// REPLACES `pic_r3_expiry_indexes_are_unreachable_until_lifetime_constants_land`,
/// which proved those indexes were unreachable BY CONSTRUCTION while C3/C4 were
/// unruled and therefore carried no migration test. That test named this exact
/// successor as an S6 OBLIGATION — "when the §10.5 lifetime constants land and
/// proposals start carrying expiries, a real `upgrade_canister` migration test
/// for BOTH expiry indexes becomes required and this test's premise expires
/// with it" — and wrote its assertions so they would fail the moment expiry
/// became reachable. They did. This is the follow-up it forced.
///
/// Run against the PRODUCTION Wasms deliberately: the property is that a real
/// release build carries these indexes across a real upgrade boundary, which a
/// testing build with injection hooks would not establish.
#[test]
fn pic_s6_expiry_indexes_survive_a_real_upgrade_on_both_planes() {
    let (pic, vault, upgrader) = ring_rig();
    let m1 = p(11);
    let bounds = stsh_custody_types::PROPOSAL_LIFETIME_BOUNDS.expect("C3/C4 ruled at S6");

    // ── Vault: a default-lifetime proposal now CARRIES an expiry ────────────
    let action = VaultActionKind::Management(ManagementAction::CreateCanister {
        manifest_purpose: "vesting".to_string(),
        disposition: ManifestDisposition::BornUnderVault,
    });
    let id = propose(&pic, vault, p(S1), action);

    // THE VAULT'S EXPIRY IS NOT OBSERVABLE OVER THE WIRE — `ProposalView` has
    // no `expires_at_ns` field, and adding one would be a DID change S6 is not
    // authorized to make. So the Vault half is proved BEHAVIOURALLY, by
    // bracketing the ruled expiry with two sweeps. That is the stronger
    // evidence anyway: it pins what the index actually does with the value,
    // not what a view reports about it.
    let sweep_vault = |pic: &PocketIc| -> Vec<u64> {
        let raw = pic
            .update_call(vault, p(S1), "sweep_expired_proposals", candid::encode_one(&1_000u32).unwrap())
            .unwrap();
        candid::decode_one::<Result<Vec<u64>, VaultError>>(static_bytes(raw))
            .unwrap()
            .expect("signer may sweep")
    };
    // Not due before the upgrade. Without this the post-upgrade reap would
    // prove nothing: an index that reaped unconditionally would also pass.
    assert!(sweep_vault(&pic).is_empty(), "not due yet");

    // Sent as the UPGRADER, which is the Vault's controller in the ring — and
    // the production path: the Vault is upgraded by its counterpart, never by
    // an anonymous caller. `None` here is the anonymous principal and is
    // refused with CanisterInvalidController.
    pic.upgrade_canister(vault, vault_wasm(), candid::encode_args(()).unwrap(), Some(upgrader))
        .expect("vault upgrade");

    // Just SHORT of the ruled maximum: still not due. This is what pins the
    // surviving value rather than merely the surviving index — a migration
    // that defaulted every expiry to zero, or re-derived it from the upgrade
    // time, would reap here.
    //
    // THE MARGIN IS ONE HOUR, NOT ONE NANOSECOND, and the reason is the
    // harness rather than the mechanism: PocketIC advances its clock by a
    // small amount on every round, so several update calls and an upgrade sit
    // between the proposal and this sweep. A 1 ns bracket is below the
    // harness's own time resolution and reaps spuriously. One hour out of a
    // thirty-day lifetime is still tight enough to catch the failures this
    // brackets for — an expiry defaulted to zero, or re-derived from the
    // upgrade time, is off by ~30 days, not by an hour.
    const MARGIN: u64 = 3_600 * stsh_custody_types::NANOS_PER_SEC;
    pic.advance_time(std::time::Duration::from_nanos(bounds.max_ns - MARGIN));
    assert!(
        sweep_vault(&pic).is_empty(),
        "the expiry must survive the upgrade UNCHANGED — reaping this early \
         means the value was defaulted or re-derived"
    );

    // Past it: the index survived and still reaps.
    pic.advance_time(std::time::Duration::from_nanos(2 * MARGIN));
    assert_eq!(
        sweep_vault(&pic),
        vec![id],
        "the Vault expiry index must survive the upgrade and still reap"
    );

    // ── Upgrader: the same property on the recovery plane ───────────────────
    let wasm = vec![0xB1u8; 8];
    let arg = candid::encode_args(()).unwrap();
    let rec_action = RecoveryAction::TriggerVaultUpgrade {
        expected_wasm_hash: sha256(&wasm),
        expected_arg_hash: sha256(&arg),
        wasm_bytes: wasm,
        arg_bytes: arg,
    };
    let raw = pic
        .update_call(
            upgrader,
            m1,
            "propose_recovery",
            candid::encode_one(&rec_action).unwrap(),
        )
        .unwrap();
    let rid = candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
        .unwrap()
        .expect("default lifetime accepted");

    let rec_expiry = |pic: &PocketIc| -> Option<u64> {
        let raw = pic
            .query_call(upgrader, m1, "get_recovery_proposal", candid::encode_one(&rid).unwrap())
            .unwrap();
        candid::decode_one::<Option<stsh_custody_types::RecoveryProposal>>(static_bytes(raw))
            .unwrap()
            .expect("member may read")
            .expires_at_ns
    };
    let rec_before = rec_expiry(&pic).expect("S6: a recovery proposal must carry an expiry");

    let sweep_rec = |pic: &PocketIc| -> Vec<u64> {
        let raw = pic
            .update_call(
                upgrader,
                m1,
                "sweep_expired_recovery_proposals",
                candid::encode_one(&1_000u32).unwrap(),
            )
            .unwrap();
        candid::decode_one::<Result<Vec<u64>, RecoveryError>>(static_bytes(raw))
            .unwrap()
            .expect("member may sweep")
    };

    // Symmetrically, the Upgrader's controller is the Vault.
    pic.upgrade_canister(upgrader, upgrader_wasm(), candid::encode_args(()).unwrap(), Some(vault))
        .expect("upgrader upgrade");

    // The VALUE is proved directly on this plane — `RecoveryProposal` does
    // expose `expires_at_ns` over the wire, unlike the Vault's `ProposalView`.
    assert_eq!(
        rec_expiry(&pic),
        Some(rec_before),
        "the recovery expiry must survive the upgrade UNCHANGED"
    );

    // This proposal was created AFTER the Vault half advanced the clock, so it
    // carries its own fresh thirty days and is nowhere near due yet. Not due
    // before the advance — the non-vacuity half, without which an index that
    // reaped unconditionally would also pass.
    assert!(sweep_rec(&pic).is_empty(), "not due yet");
    pic.advance_time(std::time::Duration::from_nanos(bounds.max_ns + MARGIN));
    assert_eq!(
        sweep_rec(&pic),
        vec![rid],
        "the Upgrader expiry index must survive the upgrade and still reap"
    );
}

/// S11-1 (P1-A) — THE COMMITTED DEADLINE BINDS ACROSS A REAL WASM UPGRADE, ON
/// BOTH PLANES.
///
/// The native `s11_*` tests prove the admission check rejects. They cannot
/// prove it survives an upgrade: in-process thread-locals outlive `init` and
/// `post_upgrade` in the same address space, so a deadline held only in the heap
/// passes every native durability assertion. Only a real `upgrade_canister`
/// through a deployed Wasm establishes the property, which is why this test
/// exists alongside them.
///
/// THE SHAPE IS THE ONE THE PACKET NAMES: a proposal that expired BEFORE the
/// upgrade must not be able to collect an approval AFTER it. The failure this
/// brackets against is a migration that defaults or re-derives `expires_at_ns`
/// — which would silently un-expire every in-flight proposal at exactly the
/// moment an upgrade lands, i.e. the moment an attacker who can trigger one
/// would choose.
///
/// Run against the PRODUCTION Wasms, like its S6 predecessor above: a testing
/// build with injection hooks would not establish that a real release carries
/// the property.
#[test]
fn pic_s11_expired_proposal_cannot_collect_approval_across_a_real_upgrade() {
    let (pic, vault, upgrader) = ring_rig();
    let m1 = p(11);
    let bounds = stsh_custody_types::PROPOSAL_LIFETIME_BOUNDS.expect("C3/C4 ruled at S6");
    // Same rationale as the S6 test above: PocketIC advances its own clock a
    // little every round, so the brackets are an hour wide rather than a
    // nanosecond. An hour out of thirty days still catches a defaulted or
    // re-derived expiry, which is off by ~30 days.
    const MARGIN: u64 = 3_600 * stsh_custody_types::NANOS_PER_SEC;

    // ── Vault plane ─────────────────────────────────────────────────────────
    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::CreateCanister {
            manifest_purpose: "vesting".to_string(),
            disposition: ManifestDisposition::BornUnderVault,
        }),
    );

    // NON-VACUITY, and it must come first: before the deadline this exact call
    // SUCCEEDS. Without it, a build where `approve` was broken outright — or
    // where the ring rejected S1 for an unrelated reason — would pass every
    // assertion below for the wrong reason.
    assert!(
        matches!(approve(&pic, vault, p(S1), id), Ok(ApprovalOutcome::Approved { .. })),
        "before the deadline the proposal is approvable"
    );

    // Past the committed deadline, but DO NOT SWEEP. The proposal stays
    // `Pending` and past-deadline — which is precisely the state the S11-1
    // ruling governs, because admission is now the thing that must refuse it
    // while the sweep has not yet reached it.
    pic.advance_time(std::time::Duration::from_nanos(bounds.max_ns + MARGIN));

    // NOW the upgrade — with the expired proposal still Pending and unswept.
    pic.upgrade_canister(vault, vault_wasm(), candid::encode_args(()).unwrap(), Some(upgrader))
        .expect("vault upgrade");

    // A DIFFERENT signer, so this is a first approval by this principal and the
    // refusal cannot be the duplicate-approval rejection wearing another name.
    match approve(&pic, vault, p(S2), id) {
        Err(VaultError::ProposalExpired { expires_at_ns, now_ns }) => {
            assert!(
                now_ns >= expires_at_ns,
                "the refusal must carry a time at or past the deadline it names"
            );
        }
        other => panic!(
            "an expired-pre-upgrade proposal must not collect an approval after \
             a real upgrade; got {other:?}"
        ),
    }

    // ZERO MUTATION across the wire: still Pending, still one approval. If the
    // refusal had terminalized (the V1 alternative the CTO ruling supersedes)
    // this would read Expired, and there would be a second capacity-release
    // path to keep consistent with the sweep.
    let view = get_proposal(&pic, vault, p(S1), id).expect("signer may read");
    assert_eq!(view.outcome, ActionOutcome::Pending, "admission never terminalizes");

    // And the sweep — the SOLE terminalizer — still reaps it after the upgrade.
    let raw = pic
        .update_call(vault, p(S1), "sweep_expired_proposals", candid::encode_one(&1_000u32).unwrap())
        .unwrap();
    let reaped = candid::decode_one::<Result<Vec<u64>, VaultError>>(static_bytes(raw))
        .unwrap()
        .expect("signer may sweep");
    assert!(reaped.contains(&id), "the sweep still reaps it post-upgrade: {reaped:?}");

    // ── Recovery plane — the same property, independently ───────────────────
    let wasm = vec![0xB2u8; 8];
    let arg = candid::encode_args(()).unwrap();
    let rec_action = RecoveryAction::TriggerVaultUpgrade {
        expected_wasm_hash: sha256(&wasm),
        expected_arg_hash: sha256(&arg),
        wasm_bytes: wasm,
        arg_bytes: arg,
    };
    let raw = pic
        .update_call(upgrader, m1, "propose_recovery", candid::encode_one(&rec_action).unwrap())
        .unwrap();
    let rid = candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
        .unwrap()
        .expect("default lifetime accepted");

    let rec_proposal = |pic: &PocketIc| -> stsh_custody_types::RecoveryProposal {
        let raw = pic
            .query_call(upgrader, m1, "get_recovery_proposal", candid::encode_one(&rid).unwrap())
            .unwrap();
        candid::decode_one::<Option<stsh_custody_types::RecoveryProposal>>(static_bytes(raw))
            .unwrap()
            .expect("member may read")
    };
    // The success arm is decoded as `Reserved` deliberately: `ApproveOutcome`
    // lives in the Upgrader crate and is NOT mirrored in this file, and adding a
    // mirror would put it under CONF-02's structural-equality lock — a large
    // drift surface bought for one assertion. Nothing here needs the success
    // VALUE, only whether the call succeeded and, when it failed, the typed
    // error. That is exactly what `Reserved` on the Ok arm gives.
    let approve_rec = |pic: &PocketIc, who: Principal| -> Result<candid::Reserved, RecoveryError> {
        let hash = rec_proposal(pic).commitment_hash;
        let raw = pic
            .update_call(
                upgrader,
                who,
                "approve_recovery",
                candid::encode_args((rid, hash)).unwrap(),
            )
            .unwrap();
        candid::decode_one::<Result<candid::Reserved, RecoveryError>>(static_bytes(raw)).unwrap()
    };

    let rec_expiry = rec_proposal(&pic)
        .expires_at_ns
        .expect("S6: a recovery proposal carries an expiry");

    // Non-vacuity first, exactly as on the Vault plane.
    assert!(
        approve_rec(&pic, m1).is_ok(),
        "before the deadline the recovery proposal is approvable"
    );

    pic.advance_time(std::time::Duration::from_nanos(bounds.max_ns + MARGIN));
    pic.upgrade_canister(upgrader, upgrader_wasm(), candid::encode_args(()).unwrap(), Some(vault))
        .expect("upgrader upgrade");

    // The committed deadline itself survived the upgrade UNCHANGED — asserted
    // directly here because `RecoveryProposal` exposes it over the wire, unlike
    // the Vault's `ProposalView`. This is what makes the refusal below evidence
    // about enforcement rather than about a mangled value.
    assert_eq!(
        rec_proposal(&pic).expires_at_ns,
        Some(rec_expiry),
        "the recovery deadline must survive the upgrade unchanged"
    );

    // p(12) is a second member: a first approval by this principal, and the one
    // that would have REACHED QUORUM (threshold 2) and triggered a real Vault
    // upgrade off a proposal whose deadline had already passed.
    match approve_rec(&pic, p(12)) {
        Err(RecoveryError::ProposalExpired { expires_at_ns, now_ns }) => {
            assert_eq!(expires_at_ns, rec_expiry);
            assert!(now_ns >= expires_at_ns);
        }
        other => panic!(
            "an expired-pre-upgrade recovery proposal must not reach quorum after \
             a real upgrade; got {other:?}"
        ),
    }
    assert_eq!(
        rec_proposal(&pic).outcome,
        ActionOutcome::Pending,
        "admission never terminalizes on the recovery plane either"
    );
}

// ── S5B W5(a) — governance rollback evidence, through a message boundary ─────
//
// AMENDMENT_V8_S4_GOVERNANCE_ATOMICITY_V2 (0fe84841…) §2 requires trap/rollback
// evidence at BOTH internal boundaries of the governance-execution path, and
// pins the evidence standard: "an in-process Rust panic does not prove
// canister-state rollback and is not acceptable evidence." So these tests run
// against a REAL deployed Wasm under PocketIC, arm the trap over ingress, and
// assert rollback by re-reading durable state through queries — never by
// inspecting in-process memory.
//
// The §4 ratification's whole claim is that the same-message path cannot leave
// an externally-committed partial state. These are the tests that make that
// claim falsifiable: if the epoch write were independently committable, the
// epoch would survive the trap and boundary (i) would fail.

/// Vault alone on the TESTING build — the arming hook exists only there.
fn rig_test_wasm() -> (PocketIc, Principal) {
    let pic = PocketIc::new();
    let vault = pic.create_canister();
    pic.add_cycles(vault, 10_000_000_000_000u128);
    let init = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
            upgrader: p(19),
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(
        vault,
        vault_test_wasm(),
        candid::encode_one(&init).unwrap(),
        None,
    );
    (pic, vault)
}

fn arm_gov_trap(pic: &PocketIc, vault: Principal, point: &str) {
    pic.update_call(
        vault,
        p(S1),
        "arm_governance_trap_for_test",
        candid::encode_one(point).unwrap(),
    )
    .expect("arming hook is callable on the testing build");
}

/// Drive a signer-set update to the quorum boundary with the trap armed, and
/// assert NOTHING committed: epoch unmoved, proposal not terminal, and no
/// governance audit event.
fn assert_governance_rollback_at(point: &str) {
    let (pic, vault) = rig_test_wasm();

    let epoch_before = summary(&pic, vault).governance_epoch;
    let audit_before = audit_events(&pic, vault, p(S1)).len();

    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::UpdateSignerSet {
            signers: vec![p(S1), p(S2)],
            threshold: 2,
        },
    );
    approve(&pic, vault, p(S1), id).unwrap();

    arm_gov_trap(&pic, vault, point);

    // The quorum-reaching approve executes the transition synchronously, so the
    // trap fires inside THIS message. A trapped message is a rejected call.
    let hash = get_proposal(&pic, vault, p(S2), id)
        .expect("proposal readable")
        .commitment_hash;
    let r = pic.update_call(
        vault,
        p(S2),
        "approve",
        candid::encode_args((id, hash)).unwrap(),
    );
    assert!(
        r.is_err(),
        "W5(a) {point}: the armed trap did not reject the message — no rollback was \
         exercised, so this test proves nothing"
    );

    // ROLLBACK ASSERTIONS, all re-read over ingress from durable state.
    assert_eq!(
        summary(&pic, vault).governance_epoch,
        epoch_before,
        "W5(a) {point}: the epoch survived the trap. The governance cell write is \
         independently committable, which is exactly what the §4 ratification denies — \
         and there is no repair machinery behind it."
    );

    let view = get_proposal(&pic, vault, p(S1), id).expect("proposal still readable");
    assert!(
        !matches!(
            view.outcome,
            ActionOutcome::Executed | ActionOutcome::Failed
        ),
        "W5(a) {point}: the proposal finalized despite the trap — outcome {:?}",
        view.outcome
    );

    let audit_after = audit_events(&pic, vault, p(S1));
    assert!(
        !audit_after
            .iter()
            .any(|e| matches!(e.kind, AuditKind::GovernanceTransition)),
        "W5(a) {point}: a GovernanceTransition audit event committed despite the trap"
    );
    assert_eq!(
        audit_after.len(),
        audit_before + 2,
        "W5(a) {point}: audit length moved by something other than the two pre-trap \
         entries (ProposalCreated + ApprovalAdded) — a write escaped the rollback"
    );

    // The signer set itself must be untouched: S3 is still a signer.
    assert!(
        get_signers(&pic, vault, p(S3)).is_some(),
        "W5(a) {point}: S3 lost signer status, so the membership mutation committed \
         while its proposal never finalized"
    );
}

/// Boundary (i) — trap AFTER `gov_store`, BEFORE the governance audit append.
/// This is the load-bearing one: the epoch has been written to the cell in this
/// message, and must not survive.
#[test]
fn pic_w5a_rollback_after_gov_store_before_audit() {
    assert_governance_rollback_at("after_gov_store_before_audit");
}

/// Boundary (ii) — trap AFTER the governance audit append, BEFORE `finalize`.
#[test]
fn pic_w5a_rollback_after_audit_before_finalize() {
    assert_governance_rollback_at("after_audit_before_finalize");
}

/// NON-VACUITY. Without the trap armed, the identical sequence must SUCCEED and
/// advance the epoch. Without this, both tests above would still pass if the
/// governance path were broken outright and every quorum-reaching approve
/// trapped for unrelated reasons.
#[test]
fn pic_w5a_unarmed_control_commits_normally() {
    let (pic, vault) = rig_test_wasm();
    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::UpdateSignerSet {
            signers: vec![p(S1), p(S2)],
            threshold: 2,
        },
    );
    approve(&pic, vault, p(S1), id).unwrap();
    approve(&pic, vault, p(S2), id).expect("unarmed quorum approve succeeds");
    assert_eq!(
        summary(&pic, vault).governance_epoch,
        1,
        "control: the epoch must advance when no trap is armed"
    );
    assert!(
        audit_events(&pic, vault, p(S1))
            .iter()
            .any(|e| matches!(e.kind, AuditKind::GovernanceTransition)),
        "control: the GovernanceTransition event must be present when nothing traps"
    );
}

/// S5B W1.3 — COMMITTED-ID SEMANTICS through a REAL message boundary.
///
/// The brief requires: "trap mid-transaction (message boundary) and prove the
/// candidate was never committed and a clean retry succeeds with the same id."
///
/// This cannot be shown in-process. A Rust panic unwinds without exercising IC
/// transactional semantics, so it proves nothing about whether the counter
/// committed — the same standard the §4 amendment pins for W5(a).
///
/// The trap point reused here is W5(a)'s governance boundary: it fires AFTER
/// `gov_store` and inside the same message as the audit append, and every audit
/// append allocates an audit id. So arming it produces exactly the shape under
/// test — an id allocated, its record written, and the message then trapped.
#[test]
fn pic_w1_trapped_transaction_commits_no_id_and_retry_reuses_it() {
    let (pic, vault) = rig_test_wasm();

    let audit_len = |pic: &PocketIc| -> usize { audit_events(pic, vault, p(S1)).len() };
    // RF-5 — the audit IDs themselves, not merely how many there are. The
    // first cut of this test asserted only length and a successful retry,
    // which is strictly weaker than the "reuses it" its own name claims: a
    // retry that was handed a DIFFERENT id would have passed every assertion.
    let audit_ids = |pic: &PocketIc| -> Vec<u64> {
        audit_events(pic, vault, p(S1)).into_iter().map(|e| e.id).collect()
    };
    let before = audit_len(&pic);

    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::UpdateSignerSet {
            signers: vec![p(S1), p(S2)],
            threshold: 2,
        },
    );
    approve(&pic, vault, p(S1), id).unwrap();
    let after_first_approve = audit_len(&pic);
    let ids_before_trap = audit_ids(&pic);

    // Arm the boundary that sits between the governance cell write and the
    // audit append, then drive the quorum-reaching approve.
    arm_gov_trap(&pic, vault, "after_gov_store_before_audit");
    let hash = get_proposal(&pic, vault, p(S2), id)
        .expect("proposal readable")
        .commitment_hash;
    let trapped = pic.update_call(
        vault,
        p(S2),
        "approve",
        candid::encode_args((id, hash)).unwrap(),
    );
    assert!(trapped.is_err(), "the armed trap must reject the message");

    // NOTHING COMMITTED. The audit log is exactly where it was before the
    // trapped message: no id was consumed, no record written.
    assert_eq!(
        audit_len(&pic),
        after_first_approve,
        "W1.3 VIOLATED: a trapped transaction left durable audit state behind. \
         Counter and entry must commit or roll back TOGETHER (W1.2)."
    );
    assert_eq!(
        audit_ids(&pic),
        ids_before_trap,
        "W1.3: the trapped message must leave the audit ID sequence untouched — \
         equal LENGTH alone would also hold if an entry had been replaced"
    );

    // Disarm before retrying. The arm was committed in an EARLIER message, so
    // the trapped message's rollback did not clear it — which is the correct
    // behaviour of a switch that deliberately does not self-disarm.
    arm_gov_trap(&pic, vault, "none");

    // CLEAN RETRY SUCCEEDS, and reuses the candidate the trapped attempt was
    // handed. That is correct under committed-ID semantics, not a reuse
    // violation: the trapped candidate was never allocated, because it never
    // committed.
    let hash = get_proposal(&pic, vault, p(S2), id)
        .expect("proposal still readable")
        .commitment_hash;
    pic.update_call(
        vault,
        p(S2),
        "approve",
        candid::encode_args((id, hash)).unwrap(),
    )
    .expect("the retry must succeed — the trap left no durable trace to block it");

    assert!(
        audit_len(&pic) > after_first_approve,
        "the successful retry must append its audit events"
    );
    // RF-5 — THE ASSERTION THIS TEST'S NAME ALWAYS CLAIMED AND NEVER MADE.
    // The retry must receive the EXACT id the trapped attempt was handed. That
    // is the substance of committed-ID semantics (W1.3): the trapped candidate
    // was never allocated, so it is still the next id — not merely "some id,
    // and the log got longer".
    let ids_after_retry = audit_ids(&pic);
    let expected_next = ids_before_trap.last().copied().expect("prior audit events exist") + 1;
    assert_eq!(
        ids_after_retry.get(ids_before_trap.len()).copied(),
        Some(expected_next),
        "W1.3 VIOLATED: the retry did not reuse the trapped attempt's audit id. \
         Expected the next id to still be {expected_next} — a trapped transaction \
         commits neither counter nor entry, so its candidate must come back \
         unchanged. Full sequence after retry: {ids_after_retry:?}"
    );
    assert_eq!(
        &ids_after_retry[..ids_before_trap.len()],
        &ids_before_trap[..],
        "W1.3: the pre-trap audit ids must be unchanged by the retry — the retry \
         appends, it does not renumber"
    );
    assert_eq!(
        summary(&pic, vault).governance_epoch,
        1,
        "and the transition must actually have committed this time"
    );
    let _ = before;
}

/// SSA RF-5 — the RECOVERY plane's committed-ID evidence, through a REAL
/// Wasm/PocketIC message boundary.
///
/// RF-5 records two gaps. The Vault's test asserted length and a successful
/// retry but never that the retry received the SAME id (fixed in
/// `pic_w1_trapped_transaction_commits_no_id_and_retry_reuses_it`), and there
/// was NO recovery-plane equivalent at all. This is that equivalent.
///
/// The boundary sits between the proposal insertion and `commit_proposal_id`,
/// so the trap catches the one window where the record is durable and the
/// counter is not. What must hold (W1.2/W1.3): both roll back together, and
/// the uncommitted candidate is handed to the next attempt UNCHANGED — because
/// it was never allocated.
#[test]
fn pic_rf5_recovery_plane_trapped_propose_commits_no_id_and_retry_reuses_it() {
    let (pic, _vault, upgrader) = ring_rig_upgrader_test_wasm();
    let m1 = p(11);

    let rotate = |pic: &PocketIc, tag: u8| -> Result<u64, RecoveryError> {
        let raw = pic
            .update_call(
                upgrader,
                m1,
                "propose_membership_rotation",
                candid::encode_args((vec![p(12), p(13), p(tag)], None::<u64>)).unwrap(),
            )
            .unwrap();
        candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw)).unwrap()
    };
    let proposal_exists = |pic: &PocketIc, id: u64| -> bool {
        let r = pic
            .query_call(upgrader, m1, "get_rotation_proposal", candid::encode_one(&id).unwrap())
            .expect("rotation proposal query");
        candid::decode_one::<Option<RotationProposalView>>(static_bytes(r))
            .expect("decodes")
            .is_some()
    };
    let audit_raw = |pic: &PocketIc| -> Vec<u8> {
        pic.query_call(
            upgrader,
            m1,
            "get_upgrader_audit_events",
            candid::encode_args((None::<u64>, 128u32)).unwrap(),
        )
        .expect("audit query")
    };
    let arm = |pic: &PocketIc, point: &str| {
        pic.update_call(
            upgrader,
            m1,
            "arm_rotation_trap_for_test",
            candid::encode_one(&point.to_string()).unwrap(),
        )
        .expect("arming hook is callable on the testing build");
    };

    // One committed proposal, so the counter is demonstrably in motion rather
    // than sitting at its initial value.
    let first = rotate(&pic, 20).expect("first proposal commits");
    let audit_before = audit_raw(&pic);
    // GUARD: a real gated read, not the None this query returns to a
    // non-member — otherwise the equality below compares two refusals.
    assert_ne!(
        audit_before,
        pic.query_call(
            upgrader,
            p(99),
            "get_upgrader_audit_events",
            candid::encode_args((None::<u64>, 128u32)).unwrap(),
        )
        .expect("audit query"),
        "fixture guard: the audit baseline must be a real gated read"
    );

    // TRAP between the insertion and the counter commit.
    arm(&pic, "after_insert_before_counter");
    let trapped = pic.update_call(
        upgrader,
        m1,
        "propose_membership_rotation",
        candid::encode_args((vec![p(12), p(13), p(21)], None::<u64>)).unwrap(),
    );
    assert!(
        trapped.is_err(),
        "RF-5 fixture guard: the propose boundary must fire, or this test proves nothing"
    );

    // NOTHING COMMITTED — neither the record nor the counter nor the audit.
    assert!(
        !proposal_exists(&pic, first + 1),
        "W1.2 VIOLATED on the recovery plane: a trapped propose left its proposal \
         record behind. Insertion and counter increment must commit or roll back \
         TOGETHER."
    );
    assert_eq!(
        audit_raw(&pic),
        audit_before,
        "W1.3 VIOLATED on the recovery plane: a trapped propose left durable audit \
         state behind"
    );

    // CLEAN RETRY REUSES THE EXACT CANDIDATE. This is the assertion RF-5 says
    // was missing everywhere: not "a proposal succeeded", but that it received
    // the SAME id the trapped attempt was handed. The trapped candidate was
    // never allocated, so it is still next.
    arm(&pic, "none");
    let retried = rotate(&pic, 22).expect("the retry must succeed — the trap left no trace");
    assert_eq!(
        retried,
        first + 1,
        "W1.3 VIOLATED on the recovery plane: the retry did not reuse the trapped \
         attempt's proposal id. A trapped transaction commits neither counter nor \
         entry, so its candidate must come back unchanged — burning it would also \
         mean the counter moved without an insertion."
    );
    assert!(
        proposal_exists(&pic, retried),
        "control: the retried proposal must actually be durable"
    );
    assert_ne!(
        audit_raw(&pic),
        audit_before,
        "control: a committed propose must move the audit log — without this the \
         rollback assertion above compares two inert responses"
    );
}

/// W3 ACCEPTANCE 13 — ONE MESSAGE terminalizes the COMPLETE stale set at C12
/// occupancy, and is idempotent.
///
/// The rollback half of acceptance 13 is covered by
/// `pic_rf2_trap_after_first_terminalization_rolls_back_completed_work`. This is
/// the other half, and the one the brief specifies "at C12 occupancy
/// (parameter-injected)": that a single call snapshots the bounded index once
/// and terminalizes EVERY stale proposal — not a batch, not a page, not a
/// cursor-driven prefix — while committing the membership rotation in that same
/// message.
///
/// WHY COMPLETENESS AT OCCUPANCY IS THE PROPERTY. A partial sweep is the
/// dangerous outcome precisely because it SUCCEEDS: rotation reports success,
/// membership moves, and an unterminalized remainder is left behind holding
/// slots against C12 forever. Testing with one or two stale records cannot
/// distinguish "terminalizes all" from "terminalizes the first few" — so the
/// stale set here is filled to the injected cap.
#[test]
fn pic_w3_acceptance13_one_message_terminalizes_complete_stale_set_at_occupancy() {
    let (pic, _vault, upgrader) = ring_rig_upgrader_test_wasm();
    let (m1, m2, m3) = (p(11), p(12), p(13));

    // Occupancy: 8 stale proposals plus the rotation that sweeps them.
    const STALE: usize = 8;
    pic.update_call(
        upgrader,
        m1,
        "set_nonterminal_caps_for_test",
        candid::encode_one(&Some(stsh_custody_types::NonterminalCaps {
            global: (STALE + 1) as u32,
            per_signer: (STALE + 1) as u32,
        }))
        .unwrap(),
    )
    .expect("caps injection hook is callable on the testing build");

    let propose_rotation = |pic: &PocketIc, sender: Principal, tag: u8| -> u64 {
        let raw = pic
            .update_call(
                upgrader,
                sender,
                "propose_membership_rotation",
                candid::encode_args((vec![m2, m3, p(tag)], None::<u64>)).unwrap(),
            )
            .unwrap();
        candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
            .unwrap()
            .expect("proposal commits")
    };
    let outcome_of = |pic: &PocketIc, reader: Principal, id: u64| -> ActionOutcome {
        let r = pic
            .query_call(upgrader, reader, "get_rotation_proposal", candid::encode_one(&id).unwrap())
            .expect("rotation proposal query");
        candid::decode_one::<Option<RotationProposalView>>(static_bytes(r))
            .expect("decodes")
            .expect("proposal exists")
            .outcome
    };
    // READER IS A PARAMETER, deliberately — the same trap the older ring tests
    // document: this rotation's roster is [m2, m3, ...], so a SUCCESSFUL sweep
    // REMOVES m1, and every gated query then returns an indistinguishable None
    // to it. Reading as m1 after the rotation fails for a reason that has
    // nothing to do with the property under test. (It also incidentally proves
    // the rotation really took effect.)
    let commit_of = |pic: &PocketIc, reader: Principal, id: u64| -> Vec<u8> {
        let r = pic
            .query_call(upgrader, reader, "get_rotation_proposal", candid::encode_one(&id).unwrap())
            .expect("rotation proposal query");
        candid::decode_one::<Option<RotationProposalView>>(static_bytes(r))
            .expect("decodes")
            .expect("proposal exists")
            .commitment_hash
    };

    // Fill the stale set to occupancy.
    let stale: Vec<u64> = (0..STALE).map(|i| propose_rotation(&pic, m1, 30 + i as u8)).collect();
    for id in &stale {
        assert_eq!(
            outcome_of(&pic, m1, *id),
            ActionOutcome::Pending,
            "fixture guard: every stale record must start Pending"
        );
    }

    // The sweeping rotation, driven to the quorum boundary.
    let rot = propose_rotation(&pic, m1, 40);
    pic.update_call(upgrader, m1, "approve_recovery", candid::encode_args((rot, commit_of(&pic, m1, rot))).unwrap())
        .expect("first approval");

    // ── THE SINGLE MESSAGE ──────────────────────────────────────────────────
    pic.update_call(upgrader, m2, "approve_recovery", candid::encode_args((rot, commit_of(&pic, m1, rot))).unwrap())
        .expect("the quorum-reaching message commits the rotation");

    // COMPLETENESS: every stale record, not a prefix.
    let survivors: Vec<u64> = stale
        .iter()
        .copied()
        .filter(|id| outcome_of(&pic, m2, *id) == ActionOutcome::Pending)
        .collect();
    assert!(
        survivors.is_empty(),
        "W3 acceptance 13 VIOLATED: {} of {STALE} stale proposals survived the rotation \
         ({survivors:?}). A partial sweep is the dangerous outcome BECAUSE it succeeds — \
         membership moves, the call reports success, and the remainder holds C12 slots \
         forever with no path to release them.",
        survivors.len()
    );
    assert_eq!(
        outcome_of(&pic, m2, rot),
        ActionOutcome::Executed,
        "and the rotation itself must be Executed in that same message"
    );

    // IDEMPOTENCE, asserted as the PROPERTY rather than as a return value.
    //
    // Decoding the outcome would need a hand-maintained mirror of the
    // Upgrader's ApproveOutcome, which CONF-02's lock would then require to be
    // structurally equal — a large drift surface for one assertion. The
    // substance of "never reprocessing" is that a replay writes NOTHING: no
    // second terminalization, no second rotation, no audit growth. Raw audit
    // bytes are the SSA-approved way to assert that, and they are stricter than
    // inspecting a return code, which a reprocessing implementation could
    // return while still having written.
    let audit_raw = |pic: &PocketIc| -> Vec<u8> {
        pic.query_call(
            upgrader,
            m2,
            "get_upgrader_audit_events",
            candid::encode_args((None::<u64>, 128u32)).unwrap(),
        )
        .expect("audit query")
    };
    let audit_after_sweep = audit_raw(&pic);
    let _ = pic.update_call(
        upgrader,
        m3,
        "approve_recovery",
        candid::encode_args((rot, commit_of(&pic, m2, rot))).unwrap(),
    );
    assert_eq!(
        audit_raw(&pic),
        audit_after_sweep,
        "W3 acceptance 13: re-invoking a completed rotation WROTE to the audit log. It \
         must be a no-op or a clean error — never a second sweep over already-terminal \
         records."
    );
    for id in &stale {
        assert_ne!(
            outcome_of(&pic, m2, *id),
            ActionOutcome::Pending,
            "terminal records must never be reprocessed back toward Pending"
        );
    }
}

/// SSA RF-7 — B3 regression evidence through a REAL `post_upgrade` message
/// boundary, VAULT plane.
///
/// WHAT EXISTED AND WHAT DID NOT. `rf7_companion_sentinel_created_at_install_
/// and_absence_rejected` covers fresh-install creation and absent-record
/// rejection IN-PROCESS, on the UPGRADER only. SSA asked for the same property
/// "preferably exercising `post_upgrade` through a real message boundary and
/// covering inline validation as well", on BOTH planes. Neither the PocketIC
/// half nor the Vault half existed.
///
/// THE DEFECT (B3). An absent companion record must be REJECTED, not read as an
/// empty default. The first cut accepted absence whenever the active indexes
/// happened to be empty — so a pre-companion deployment upgraded into this build
/// would pass `post_upgrade` and run with no companion authority at all.
#[test]
fn pic_rf7_vault_absent_companion_rejected_across_real_upgrade_and_inline() {
    let (pic, vault) = rig_test_wasm();

    // Real state, so absence is the ONLY thing under test.
    let _ = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::UpdateSignerSet { signers: vec![p(S1), p(S2)], threshold: 2 },
    );

    // INSTALL-CODE RATE LIMIT — why this wait exists, since deleting it will
    // look harmless and will not fail immediately.
    //
    // The IC rate-limits `install_code` against a canister that consumed too
    // much instruction budget in its RECENT install_code messages, and rejects
    // with the TRANSIENT `CanisterInstallCodeRateLimited` rather than any
    // failure of the property under test. The Vault's testing Wasm is ~1.4 MB
    // and this test installs and then immediately upgrades it, which sits
    // directly on that boundary: measured during S5A, adding 11,622 bytes of
    // test-only surface (+0.83%) flipped this test from green to a hard,
    // repeatable failure with no assertion involved.
    //
    // So the limit is cleared by advancing time rather than by keeping the
    // testing Wasm small — a size budget nobody can see is not a constraint
    // anyone can honour, and every future test-only hook would silently spend
    // it. Advancing PocketIC's clock is exactly the remedy the platform's own
    // error text prescribes ("retry the installation at a later time").
    pic.advance_time(std::time::Duration::from_secs(600));
    pic.tick();

    // Control: an upgrade with the record PRESENT must succeed. Without this,
    // the assertion below would also hold against a canister that simply cannot
    // be upgraded at all.
    pic.upgrade_canister(vault, vault_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("control: a healthy canister upgrades cleanly");

    pic.update_call(
        vault,
        p(S1),
        "clear_companion_state_for_test",
        candid::encode_args(()).unwrap(),
    )
    .expect("clearing hook is callable on the testing build");

    // (a) INLINE VALIDATION — before any upgrade. The absent record must be
    // rejected on the ordinary path too, not only at post_upgrade.
    let inline = pic.update_call(
        vault,
        p(S1),
        "propose",
        candid::encode_one(&VaultActionKind::UpdateSignerSet {
            signers: vec![p(S2), p(S3)],
            threshold: 2,
        })
        .unwrap(),
    );
    assert!(
        inline.is_err(),
        "RF-7 / B3: an ABSENT companion record was accepted by INLINE validation. \
         Reading absence as an empty default means a pre-companion deployment runs \
         with no companion authority — every allocation and every single-flight \
         decision then rests on state nothing is guarding."
    );

    // (b) REAL post_upgrade BOUNDARY — the half that in-process evidence cannot
    // reach: a Wasm instance replacement with post_upgrade running fresh.
    let upgraded =
        pic.upgrade_canister(vault, vault_test_wasm(), candid::encode_args(()).unwrap(), None);
    assert!(
        upgraded.is_err(),
        "RF-7 / B3: an ABSENT companion record was accepted across a REAL upgrade. \
         This is exactly the pre-companion-deployment case — the upgrade must FAIL \
         CLOSED, because there is no repair surface behind it."
    );
}

/// SSA RF-7 — the same property on the RECOVERY plane, through a real boundary.
///
/// The existing in-process test covers this plane's fresh-install creation and
/// absent-record rejection. This is the real-message-boundary half.
#[test]
fn pic_rf7_upgrader_absent_companion_rejected_across_real_upgrade_and_inline() {
    let (pic, vault, upgrader) = ring_rig_upgrader_test_wasm();
    let m1 = p(11);

    let rotate = |pic: &PocketIc, tag: u8| {
        pic.update_call(
            upgrader,
            m1,
            "propose_membership_rotation",
            candid::encode_args((vec![p(12), p(13), p(tag)], None::<u64>)).unwrap(),
        )
    };
    rotate(&pic, 20).expect("call").len();

    // The upgrade is issued AS THE VAULT, because the ring rig sets the
    // Upgrader's controller to the Vault — the real closed-ring shape
    // (`Upgrader.controllers == [Vault]`, brief invariant 1). Upgrading as
    // anyone else is rejected by the platform before post_upgrade ever runs,
    // which would make this test pass for a reason unrelated to B3.
    let upgrade_as_vault = |pic: &PocketIc| {
        pic.upgrade_canister(
            upgrader,
            upgrader_test_wasm(),
            candid::encode_args(()).unwrap(),
            Some(vault),
        )
    };

    // Control: healthy canister upgrades cleanly.
    upgrade_as_vault(&pic).expect("control: a healthy canister upgrades cleanly");

    pic.update_call(
        upgrader,
        m1,
        "clear_companion_state_for_test",
        candid::encode_args(()).unwrap(),
    )
    .expect("clearing hook is callable on the testing build");

    // (a) INLINE validation on the ordinary admission path.
    assert!(
        rotate(&pic, 21).is_err(),
        "RF-7 / B3 (recovery plane): an ABSENT companion record was accepted by INLINE \
         validation"
    );

    // (b) REAL post_upgrade boundary.
    let upgraded = upgrade_as_vault(&pic);
    assert!(
        upgraded.is_err(),
        "RF-7 / B3 (recovery plane): an ABSENT companion record was accepted across a \
         REAL upgrade — post_upgrade must fail closed on the pre-companion-deployment \
         case"
    );
}

/// SSA RF-3 — DETERMINISTIC INSTRUCTION-AT-DEPTH evidence for W6.
///
/// WHAT WAS REFUSED AND WHY THIS IS DIFFERENT. The builder built no wall-clock
/// harness for W6 on the grounds that a time threshold at test scale cannot
/// distinguish O(1) from O(n) — that reasoning stands. SSA's ask was
/// INSTRUCTION-at-depth evidence, which is a different thing:
/// `instruction_counter` under PocketIC is exact and deterministic, so the same
/// operation measured at two history depths yields a real comparison with no
/// noise budget to hide behind.
///
/// THE PROPERTY. Every ID allocation runs W1.6 inline companion validation
/// first. That validation walks the BOUNDED companions and must never touch
/// permanent history — so its instruction cost must not grow as terminal
/// history grows. If it ever did, the allocation path would degrade toward the
/// instruction ceiling as the canister aged, which is the exhaustion half of
/// CUST-SSA-003 arriving by a different road.
///
/// The history built here is TERMINAL (each proposal is cancelled), so the
/// active companions return to their prior size while the permanent record
/// grows. Measuring against Pending proposals instead would confound the two:
/// the companions would legitimately grow, and a rising count would prove
/// nothing about history-independence.
#[test]
fn pic_rf3_allocation_instruction_cost_is_independent_of_history_depth() {
    let (pic, vault) = rig_test_wasm();
    // C9 is live as of S6 and this harness seeds far past it from one signer.
    suspend_entry_rate_for_measurement(&pic, vault);
    raise_byte_quotas_for_measurement(&pic, vault);

    let measure = |pic: &PocketIc| -> u64 {
        let r = pic
            .update_call(
                vault,
                p(S1),
                "measure_allocation_instructions_for_test",
                candid::encode_args(()).unwrap(),
            )
            .expect("measurement hook is callable on the testing build");
        candid::decode_one::<u64>(static_bytes(r)).expect("instruction count decodes")
    };

    // SHALLOW baseline.
    let shallow = measure(&pic);
    assert!(
        shallow > 0,
        "fixture guard: the measurement must report real instructions consumed — a \
         zero reading would make every comparison below vacuous"
    );

    // Grow PERMANENT history with TERMINAL records: propose, then cancel, so
    // the active companions end where they started.
    for _ in 0..40 {
        let id = propose(
            &pic,
            vault,
            p(S1),
            VaultActionKind::UpdateSignerSet { signers: vec![p(S1), p(S2)], threshold: 2 },
        );
        pic.update_call(vault, p(S1), "cancel_proposal", candid::encode_one(&id).unwrap())
            .expect("call")
            .len();
    }

    let deep = measure(&pic);

    // THE THRESHOLD IS MEASURED, NOT GUESSED. A first cut allowed `deep <=
    // shallow * 2` and a planted history scan on the allocation path SURVIVED
    // it — the scan is cheap relative to the sha256-and-decode cost of
    // companion validation, so a 2x band swallowed it whole. Measured on this
    // toolchain, 40 additional TERMINAL records:
    //
    //   clean:   shallow 459_759 -> deep 426_655   (delta  -33_104, flat)
    //   mutated: shallow 468_667 -> deep 786_697   (delta +318_030, +68%)
    //
    // The clean path does not grow at all — it drifts slightly DOWN — so a 10%
    // band sits far above real variation and far below the defect. Widening
    // this bound without re-measuring would reintroduce exactly the vacuum the
    // first cut had.
    assert!(
        deep * 10 <= shallow * 11,
        "W6 / RF-3 VIOLATED: allocation instruction cost grew with PERMANENT history \
         depth by more than 10%. shallow={shallow} deep={deep} after 40 additional \
         TERMINAL records. \
         Inline companion validation must walk only the bounded companions — a cost \
         that tracks history means something on the allocation path is decoding \
         permanent records, and the path degrades toward the instruction ceiling as \
         the canister ages."
    );
}

/// SSA B1 option (a), RULED — a GENUINE predecessor binary must FAIL CLOSED
/// when upgraded into the MemoryId 10 build.
///
/// WHAT THIS REPLACES. The B1 blocker was closed in-process: a test constructs a
/// V1-shaped companion record and asserts `companion_check` traps. That proves
/// the sentinel compares versions. It does NOT prove that a real predecessor
/// canister — with real durable state written by real predecessor code — is
/// refused when upgraded into this build. SSA ruled option (a) and explicitly
/// refused an interim synthetic substitute.
///
/// THE DEFECT THIS GUARDS. MemoryId 10 changed the companion registry and the
/// commitment domain. The new index starts EMPTY, and an empty index
/// contributes nothing to the XOR accumulator or the byte/entry accounting — so
/// the predecessor's commitment STILL VERIFIES. `companion_recompute` walks only
/// the companion indexes, never history, so it cannot notice that live
/// nonterminal proposals are missing from the new index. Without the schema
/// bump this upgrade would SUCCEED and C12 would silently undercount every
/// proposal admitted before it.
///
/// The predecessor is built from pinned commit `d12df2c` by `run_gate.sh`, with
/// its sha256 verified there — so this test cannot silently start running
/// against a rebuilt-from-current binary, which would make it vacuous.
#[test]
fn pic_b1a_genuine_predecessor_upgrade_fails_closed() {
    let pic = PocketIc::new();
    let upgrader = pic.create_canister();
    pic.add_cycles(upgrader, 10_000_000_000_000u128);
    let m1 = p(11);
    let uinit = UpgraderInitArgs {
        recovery_members: vec![p(11), p(12), p(13)],
        threshold: 2,
        vault: p(0xF0),
    };

    // Install the GENUINE PREDECESSOR and let it write real durable state
    // through its own code paths — companion record at schema V1, with a live
    // nonterminal proposal that the new build's MemoryId 10 knows nothing about.
    pic.install_canister(
        upgrader,
        upgrader_pre_b1_wasm(),
        candid::encode_one(&uinit).unwrap(),
        None,
    );
    let raw = pic
        .update_call(
            upgrader,
            m1,
            "propose_membership_rotation",
            candid::encode_args((vec![p(12), p(13), p(20)], None::<u64>)).unwrap(),
        )
        .expect("the predecessor accepts a rotation proposal");
    let live = candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
        .unwrap()
        .expect("predecessor proposal commits");

    // FIXTURE GUARD: the predecessor must really be the predecessor. If the
    // pinned Wasm were silently rebuilt from current source, it would carry
    // MemoryId 10 and schema V2, the upgrade below would succeed, and this test
    // would assert nothing. A predecessor build has no `arm_companion_trap_for_test`
    // (that hook lands with RF-1, after d12df2c), so its absence identifies the
    // binary behaviourally rather than on trust.
    assert!(
        pic.update_call(
            upgrader,
            m1,
            "arm_companion_trap_for_test",
            candid::encode_one(&"none".to_string()).unwrap(),
        )
        .is_err(),
        "fixture guard: the installed Wasm answers a hook that only exists AFTER the \
         pinned predecessor commit — it is not the predecessor, and this test would \
         prove nothing"
    );

    // ── THE UPGRADE MUST FAIL CLOSED ────────────────────────────────────────
    let upgraded = pic.upgrade_canister(
        upgrader,
        upgrader_test_wasm(),
        candid::encode_args(()).unwrap(),
        None,
    );
    assert!(
        upgraded.is_err(),
        "SSA B1 BLOCKER 1, through a REAL upgrade: a genuine predecessor canister was \
         ACCEPTED by the MemoryId 10 build. Its empty new index contributes nothing to \
         the accumulator or the accounting, so the old commitment still verifies, and \
         companion_recompute never reads history — so the live nonterminal proposal \
         would vanish from C12's authority and the cap would undercount every proposal \
         admitted before the upgrade. The schema sentinel exists to make this \
         impossible."
    );

    // The predecessor canister is untouched by the refused upgrade: still
    // running its own code, still serving its own state. Fail-CLOSED, not
    // fail-broken.
    let r = pic
        .query_call(
            upgrader,
            m1,
            "get_rotation_proposal",
            candid::encode_one(&live).unwrap(),
        )
        .expect("the predecessor still answers after the refused upgrade");
    assert!(
        candid::decode_one::<Option<RotationProposalView>>(static_bytes(r))
            .expect("decodes")
            .is_some(),
        "the refused upgrade must leave the predecessor's durable state intact — \
         fail-closed means the upgrade does not land, not that the canister dies"
    );
}

/// SSA RF-6 / W4 acceptance 17 — the C9 entry-rate ledger across a REAL Wasm
/// upgrade.
///
/// WHAT WAS MISSING. `w4_ledger_is_durable_and_rolls_windows_across_upgrade`
/// calls `post_upgrade()` IN-PROCESS. That re-runs a function; it does not
/// replace a Wasm instance, does not discard the heap, and cannot distinguish
/// durable stable state from a `thread_local` that happens to persist inside
/// one test binary. RF-6 requires crossing a real upgrade.
///
/// WHY THE PROPERTY MATTERS. The party able to trigger an upgrade IS the
/// governed path. If an upgrade cleared the ledger, the bound would be evadable
/// by exactly the actor it exists to bound — so "durable" here is a security
/// property, not a storage preference.
///
/// PARAMETERS ARE RE-INJECTED AFTER THE UPGRADE, deliberately and stated so
/// this is not mistaken for a gap: the candidate C9 values live in a
/// `thread_local` (heap) precisely so no candidate value is ever durable — that
/// is brief §3's requirement. Configuration is therefore EXPECTED to be gone
/// after an upgrade. The subject under test is the LEDGER, which lives in
/// stable memory and must NOT be gone. Re-injecting restores the gate so the
/// ledger's surviving contents become observable again; if the ledger had been
/// cleared, the post-upgrade proposal below would SUCCEED.
#[test]
fn pic_rf6_entry_rate_ledger_survives_a_real_wasm_upgrade() {
    let (pic, vault) = rig_test_wasm();

    let inject = |pic: &PocketIc, params: Option<stsh_custody_types::EntryRateParams>| {
        pic.update_call(
            vault,
            p(S1),
            "set_entry_rate_params_for_test",
            candid::encode_one(&params).unwrap(),
        )
        .expect("injection hook is callable on the testing build");
    };
    let try_propose = |pic: &PocketIc, sender: Principal, signers: Vec<Principal>| {
        pic.update_call(
            vault,
            sender,
            "propose",
            candid::encode_one(&VaultActionKind::UpdateSignerSet { signers, threshold: 2 })
                .unwrap(),
        )
        .map(|r| candid::decode_one::<Result<u64, VaultError>>(static_bytes(r)).unwrap())
    };

    // A window long enough that it cannot roll during the test by accident,
    // and a budget of exactly one entry.
    let window_ns = 3_600_000_000_000u64; // 1 hour
    let params = stsh_custody_types::EntryRateParams {
        window_ns,
        global_per_window: 1,
        per_signer_per_window: 1,
    };
    inject(&pic, Some(params));

    // Consume the single entry, then confirm the gate actually binds. Without
    // this the post-upgrade refusal below could not be attributed to the
    // surviving ledger.
    try_propose(&pic, p(S1), vec![p(S1), p(S2)])
        .expect("call")
        .expect("the first entry fits the budget");
    assert!(
        try_propose(&pic, p(S2), vec![p(S1), p(S3)]).expect("call").is_err(),
        "fixture guard: the C9 gate must bind BEFORE the upgrade, or the post-upgrade \
         assertion proves nothing"
    );

    // ── THE REAL UPGRADE ────────────────────────────────────────────────────
    // A genuine Wasm instance replacement: the heap is discarded, post_upgrade
    // runs in a fresh instance, and only stable memory crosses.
    pic.upgrade_canister(vault, vault_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("upgrade succeeds");

    // Configuration is gone (heap) — restore it. The LEDGER must not be.
    inject(&pic, Some(params));
    assert!(
        try_propose(&pic, p(S2), vec![p(S1), p(S3)]).expect("call").is_err(),
        "W4 acceptance 17 VIOLATED across a REAL upgrade: the entry-rate ledger did \
         not survive. The party who can trigger an upgrade is the governed path \
         itself, so a ledger cleared by upgrade is no bound at all — anyone able to \
         upgrade could reset the limit at will."
    );

    // ── THE WINDOW ROLLS CORRECTLY ACROSS THE UPGRADE BOUNDARY ──────────────
    // Not merely "the ledger is non-empty": its stored window_start must still
    // be honoured, so advancing past it frees budget exactly once.
    pic.advance_time(std::time::Duration::from_nanos(window_ns + 1));
    pic.tick();
    try_propose(&pic, p(S2), vec![p(S1), p(S3)])
        .expect("call")
        .expect("W4 acceptance 17: the window must ROLL after the upgrade — a ledger \
                 that survives but never rolls would brick entry permanently");
    assert!(
        try_propose(&pic, p(S3), vec![p(S2), p(S3)]).expect("call").is_err(),
        "and the fresh window must bind again immediately — one entry per window, \
         not an unbounded post-roll allowance"
    );
}

/// S11-3 — THE SAME PROPERTY ON THE UPGRADER (MemoryId 9), across a REAL Wasm
/// upgrade. The recovery plane's twin of
/// `pic_rf6_entry_rate_ledger_survives_a_real_wasm_upgrade` above.
///
/// WHAT WAS MISSING. The Vault's C9 ledger had committed real-upgrade evidence;
/// the Upgrader's did not. Closing only one plane leaves the other's durability
/// claim resting on the Vault's evidence, which says nothing about it — the
/// same reasoning that forced MemoryId 10 and the R3.8/R3.11 sweep to be built
/// on both planes rather than one. The Upgrader's C9 suspension landed at S6
/// precisely so both planes enforce identically; that symmetry is worth nothing
/// unmeasured on this side.
///
/// WHY IT MATTERS, in the same terms as the Vault's: the party able to trigger
/// an upgrade IS the governed path. A ledger cleared by upgrade is no bound at
/// all against exactly the actor it exists to bound. Durability here is a
/// security property, not a storage preference.
///
/// PARAMETERS ARE RE-INJECTED AFTER THE UPGRADE, deliberately and for the same
/// stated reason as the Vault twin: the candidate C9 values live in a heap
/// `thread_local` so that no candidate value is ever durable (brief §3), so
/// configuration is EXPECTED to be gone after an upgrade. The subject under
/// test is the LEDGER in stable memory. Re-injecting makes its surviving
/// contents observable again — had the ledger cleared, the post-upgrade
/// proposal below would SUCCEED.
#[test]
fn pic_s11_3_upgrader_entry_rate_ledger_survives_a_real_wasm_upgrade() {
    let (pic, vault, upgrader) = ring_rig_upgrader_test_wasm();
    let m1 = p(11);
    let m2 = p(12);

    let inject = |pic: &PocketIc, params: Option<stsh_custody_types::EntryRateParams>| {
        pic.update_call(
            upgrader,
            m1,
            "set_entry_rate_params_for_test",
            candid::encode_one(&params).unwrap(),
        )
        .expect("injection hook is callable on the testing build");
    };
    // Reconcile actions, not triggers: single flight admits at most ONE
    // nonterminal upgrade intent globally, so a second trigger proposal is
    // refused for a reason having nothing to do with C9 — and the refusal this
    // test attributes to the entry-rate gate would be the wrong one.
    let try_propose = |pic: &PocketIc, sender: Principal, tag: u8| {
        let action = RecoveryAction::ReconcileVaultUpgrade {
            proposal_id: tag as u64,
            objective_evidence: UpgradeObjectiveEvidence {
                observed_upgrader_principal: vault,
                observed_module_hash: Some(sha256(&[tag; 8])),
                observed_controllers: vec![upgrader],
                observed_canister_status: ObservedCanisterStatus::Running,
                observed_at_ns: 1_000,
            },
        };
        pic.update_call(upgrader, sender, "propose_recovery", candid::encode_one(&action).unwrap())
            .map(|r| candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(r)).unwrap())
    };

    // A window long enough that it cannot roll during the test by accident, and
    // a budget of exactly one entry — the Vault twin's shape, so the two sets of
    // evidence are taken under the same regime rather than being compared
    // across differently-configured runs.
    let window_ns = 3_600_000_000_000u64; // 1 hour
    let params = stsh_custody_types::EntryRateParams {
        window_ns,
        global_per_window: 1,
        per_signer_per_window: 1,
    };
    inject(&pic, Some(params));

    // Consume the single entry, then confirm the gate actually binds. Without
    // this fixture guard the post-upgrade refusal could not be attributed to
    // the surviving ledger.
    try_propose(&pic, m1, 1)
        .expect("call")
        .expect("the first entry fits the budget");
    assert!(
        try_propose(&pic, m2, 2).expect("call").is_err(),
        "fixture guard: the Upgrader's C9 gate must bind BEFORE the upgrade, or \
         the post-upgrade assertion proves nothing"
    );

    // ── THE REAL UPGRADE ────────────────────────────────────────────────────
    // A genuine Wasm instance replacement: the heap is discarded, post_upgrade
    // runs in a fresh instance, and only stable memory crosses. The Upgrader's
    // controller is the Vault, which is the production path.
    pic.upgrade_canister(upgrader, upgrader_test_wasm(), candid::encode_args(()).unwrap(), Some(vault))
        .expect("upgrader upgrade succeeds");

    // Configuration is gone (heap) — restore it. The LEDGER must not be.
    inject(&pic, Some(params));
    assert!(
        try_propose(&pic, m2, 3).expect("call").is_err(),
        "S11-3 VIOLATED across a REAL upgrade: the UPGRADER's entry-rate ledger \
         (MemoryId 9) did not survive. The party who can trigger an upgrade is \
         the governed path itself, so a ledger cleared by upgrade is no bound at \
         all on this plane either."
    );

    // ── THE WINDOW ROLLS CORRECTLY ACROSS THE UPGRADE BOUNDARY ──────────────
    // Not merely "the ledger is non-empty": its stored window_start must still
    // be honoured, so advancing past it frees budget exactly once. A ledger that
    // survived but never rolled would brick recovery entry permanently — a
    // different defect, and one this plane can least afford.
    pic.advance_time(std::time::Duration::from_nanos(window_ns + 1));
    pic.tick();
    try_propose(&pic, m2, 4)
        .expect("call")
        .expect("S11-3: the window must ROLL after the upgrade on this plane too");
    assert!(
        try_propose(&pic, p(13), 5).expect("call").is_err(),
        "and the fresh window must bind again immediately — one entry per window, \
         not an unbounded post-roll allowance"
    );
}

/// SSA RF-6 — a TRAPPED message cannot reset the ledger either.
///
/// Acceptance 17 names three reset routes: upgrade, trap, and any callable
/// path. The upgrade route is covered above. This covers the trap route, which
/// is the subtler one: a trapped message rolls back, so an attacker cannot use
/// a deliberate trap to discard consumed budget.
#[test]
fn pic_rf6_a_trapped_message_cannot_reset_the_entry_rate_ledger() {
    let (pic, vault) = rig_test_wasm();

    let inject = |pic: &PocketIc, params: Option<stsh_custody_types::EntryRateParams>| {
        pic.update_call(
            vault,
            p(S1),
            "set_entry_rate_params_for_test",
            candid::encode_one(&params).unwrap(),
        )
        .expect("injection hook is callable on the testing build");
    };
    let try_propose = |pic: &PocketIc, sender: Principal| {
        pic.update_call(
            vault,
            sender,
            "propose",
            candid::encode_one(&VaultActionKind::UpdateSignerSet {
                signers: vec![p(S1), p(S2)],
                threshold: 2,
            })
            .unwrap(),
        )
        .map(|r| candid::decode_one::<Result<u64, VaultError>>(static_bytes(r)).unwrap())
    };

    inject(
        &pic,
        Some(stsh_custody_types::EntryRateParams {
            window_ns: 3_600_000_000_000,
            global_per_window: 2,
            per_signer_per_window: 2,
        }),
    );
    try_propose(&pic, p(S1)).expect("call").expect("entry 1 of 2");

    // A message that consumes budget and THEN traps: the charge and the trap
    // are in the same message, so the charge must roll back with it.
    pic.update_call(
        vault,
        p(S1),
        "arm_companion_trap_for_test",
        candid::encode_one("after_index_before_accounting").unwrap(),
    )
    .expect("arming hook");
    assert!(
        try_propose(&pic, p(S2)).is_err(),
        "fixture guard: the armed trap must reject this message"
    );
    pic.update_call(
        vault,
        p(S1),
        "arm_companion_trap_for_test",
        candid::encode_one("none").unwrap(),
    )
    .expect("disarm");

    // The trapped message consumed NOTHING, so exactly one entry of budget
    // remains — not two (which would mean the successful entry was rolled back
    // too) and not zero (which would mean the trapped one was charged).
    try_propose(&pic, p(S2)).expect("call").expect("entry 2 of 2 — the budget is intact");
    assert!(
        try_propose(&pic, p(S3)).expect("call").is_err(),
        "W4 acceptance 17: the budget must now be exhausted. If a trapped message had \
         reset or failed to preserve the ledger, this call would succeed — that is the \
         'not resettable by trap' half of the requirement."
    );
}

/// SSA RF-1 / W2 acceptance 11 — COMPANION-WRITE trap-and-ROLLBACK, VAULT
/// plane, through a real Wasm/PocketIC message boundary.
///
/// WHAT WAS MISSING. Corruption DETECTION had evidence on both planes
/// (`companion_check` traps on a forged or omitted entry). ROLLBACK had none:
/// nothing proved that a trap DURING a companion write discards the index
/// mutations along with the accounting.
///
/// WHY IT MATTERS MORE THAN DETECTION. If the indexes survived a trap while
/// their accounting did not, the canister is not merely wrong — it is BRICKED.
/// The very next `companion_validate` traps, on every path that reaches it, and
/// W2 ships NO runtime repair surface by ruling; recovery would be a governed
/// hash-bound Wasm upgrade. So the rollback property is what stands between a
/// trapped message and a dead canister.
///
/// The strongest available assertion is therefore not "state looks unchanged"
/// but "the canister is STILL USABLE": a subsequent legitimate proposal must
/// succeed, which it can only do if `companion_validate` still passes.
#[test]
fn pic_rf1_vault_companion_write_trap_rolls_back_and_leaves_canister_usable() {
    let (pic, vault) = rig_test_wasm();

    let arm_companion = |pic: &PocketIc, point: &str| {
        pic.update_call(
            vault,
            p(S1),
            "arm_companion_trap_for_test",
            candid::encode_one(point).unwrap(),
        )
        .expect("arming hook is callable on the testing build");
    };
    let audit_len = |pic: &PocketIc| -> usize { audit_events(pic, vault, p(S1)).len() };
    let audit_ids = |pic: &PocketIc| -> Vec<u64> {
        audit_events(pic, vault, p(S1)).into_iter().map(|e| e.id).collect()
    };

    // One committed proposal so the companions are non-empty — a rollback over
    // empty companions would be a much weaker claim.
    let first = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::UpdateSignerSet { signers: vec![p(S1), p(S2)], threshold: 2 },
    );
    let ids_before = audit_ids(&pic);
    let audit_before = audit_len(&pic);

    // TRAP inside the companion write: indexes mutated, accounting not stored.
    arm_companion(&pic, "after_index_before_accounting");
    let trapped = pic.update_call(
        vault,
        p(S2),
        "propose",
        candid::encode_one(&VaultActionKind::UpdateSignerSet {
            signers: vec![p(S1), p(S3)],
            threshold: 2,
        })
        .unwrap(),
    );
    assert!(
        trapped.is_err(),
        "RF-1 fixture guard: the companion-write boundary must fire, or this test \
         proves nothing about rollback"
    );

    // ── Rollback ────────────────────────────────────────────────────────────
    assert_eq!(
        audit_ids(&pic),
        ids_before,
        "RF-1: the trapped companion write left durable audit state behind — the \
         index writes, the accounting and the audit append must commit or roll back \
         together"
    );
    assert_eq!(audit_len(&pic), audit_before, "RF-1: audit length moved");

    // THE LOAD-BEARING ASSERTION: the canister is still usable. If the index
    // writes had survived without their accounting, companion_validate would
    // now trap on every path that reaches it and this call could not succeed —
    // a state with no repair surface behind it.
    arm_companion(&pic, "none");
    let after = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::UpdateSignerSet { signers: vec![p(S2), p(S3)], threshold: 2 },
    );
    assert_eq!(
        after,
        first + 1,
        "RF-1: the post-trap proposal must receive the id the trapped attempt was \
         handed — the counter lives INSIDE the companion commitment (W1.6), so a \
         moved counter here would mean the companion write partially survived"
    );
    assert!(
        audit_len(&pic) > audit_before,
        "control: the recovery proposal really does append audit events, so the \
         equality assertions above were not comparing inert responses"
    );
}

/// SSA RF-1 / W2 acceptance 11 — the same property on the RECOVERY plane.
///
/// Both planes are required. Closing only the Vault would leave the Upgrader's
/// rollback claim resting on evidence from a different canister with a
/// different companion set — the same reasoning that put the recovery plane in
/// R3.8/R3.11, MemoryId 9 and MemoryId 10.
#[test]
fn pic_rf1_upgrader_companion_write_trap_rolls_back_and_leaves_canister_usable() {
    let (pic, _vault, upgrader) = ring_rig_upgrader_test_wasm();
    let m1 = p(11);

    let rotate = |pic: &PocketIc, tag: u8| -> Result<u64, RecoveryError> {
        let raw = pic
            .update_call(
                upgrader,
                m1,
                "propose_membership_rotation",
                candid::encode_args((vec![p(12), p(13), p(tag)], None::<u64>)).unwrap(),
            )
            .unwrap();
        candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw)).unwrap()
    };
    let audit_raw = |pic: &PocketIc| -> Vec<u8> {
        pic.query_call(
            upgrader,
            m1,
            "get_upgrader_audit_events",
            candid::encode_args((None::<u64>, 128u32)).unwrap(),
        )
        .expect("audit query")
    };
    let arm_companion = |pic: &PocketIc, point: &str| {
        pic.update_call(
            upgrader,
            m1,
            "arm_companion_trap_for_test",
            candid::encode_one(&point.to_string()).unwrap(),
        )
        .expect("arming hook is callable on the testing build");
    };

    let first = rotate(&pic, 20).expect("baseline rotation commits");
    let audit_before = audit_raw(&pic);
    assert_ne!(
        audit_before,
        pic.query_call(
            upgrader,
            p(99),
            "get_upgrader_audit_events",
            candid::encode_args((None::<u64>, 128u32)).unwrap(),
        )
        .expect("audit query"),
        "fixture guard: the audit baseline must be a real gated read, not a None refusal"
    );

    arm_companion(&pic, "after_index_before_accounting");
    let trapped = pic.update_call(
        upgrader,
        m1,
        "propose_membership_rotation",
        candid::encode_args((vec![p(12), p(13), p(21)], None::<u64>)).unwrap(),
    );
    assert!(
        trapped.is_err(),
        "RF-1 fixture guard: the recovery plane's companion-write boundary must fire"
    );

    assert_eq!(
        audit_raw(&pic),
        audit_before,
        "RF-1: the trapped companion write left durable audit state on the recovery \
         plane"
    );

    // Still usable, and the counter did not move — the counter is inside the
    // companion commitment on this plane too.
    arm_companion(&pic, "none");
    let after = rotate(&pic, 22).expect(
        "RF-1: the canister must remain usable after the trap. A surviving index \
         write without its accounting would make companion_validate trap here, with \
         no repair surface behind it.",
    );
    assert_eq!(
        after,
        first + 1,
        "RF-1: the post-trap proposal must receive the trapped attempt's id"
    );
    assert_ne!(
        audit_raw(&pic),
        audit_before,
        "control: a committed rotation really does append audit events"
    );
}

/// SSA RF-5 re-review — the RECOVERY-ACTION leg.
///
/// The rotation leg above proves exact proposal-ID reuse, but the two admission
/// paths have SEPARATE insert/commit sequences, so evidence on one says nothing
/// about the other — the builder's own packet said so and then shipped only the
/// rotation test. SSA returned it.
///
/// This leg matters more than the rotation one, because `TriggerVaultUpgrade`
/// writes strictly more before reaching the boundary: the durable INTENT
/// carrying the artifact BYTES, a `VaultUpgradeIntentRecorded` audit append,
/// and only then the proposal. A rotation-only test cannot prove any of that
/// rolls back — a rotation proposal has no intent and no artifact store at all.
#[test]
fn pic_rf5_recovery_action_trapped_propose_rolls_back_intent_and_reuses_id() {
    let (pic, _vault, upgrader) = ring_rig_upgrader_test_wasm();
    let m1 = p(11);

    let trigger = |pic: &PocketIc, tag: u8| -> Result<u64, RecoveryError> {
        let wasm = vec![tag; 8];
        let arg = candid::encode_args(()).unwrap();
        let action = RecoveryAction::TriggerVaultUpgrade {
            expected_wasm_hash: sha256(&wasm),
            expected_arg_hash: sha256(&arg),
            wasm_bytes: wasm,
            arg_bytes: arg,
        };
        let raw = pic
            .update_call(upgrader, m1, "propose_recovery", candid::encode_one(&action).unwrap())
            .unwrap();
        candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw)).unwrap()
    };
    let status_raw = |pic: &PocketIc, id: u64| -> Vec<u8> {
        pic.query_call(upgrader, m1, "get_upgrade_status", candid::encode_one(&id).unwrap())
            .expect("upgrade status query")
    };
    let proposal_absent = |pic: &PocketIc, id: u64| -> bool {
        let r = pic
            .query_call(upgrader, m1, "get_recovery_proposal", candid::encode_one(&id).unwrap())
            .expect("proposal query");
        candid::decode_one::<Option<stsh_custody_types::RecoveryProposal>>(static_bytes(r))
            .expect("decodes")
            .is_none()
    };
    let audit_raw = |pic: &PocketIc| -> Vec<u8> {
        pic.query_call(
            upgrader,
            m1,
            "get_upgrader_audit_events",
            candid::encode_args((None::<u64>, 128u32)).unwrap(),
        )
        .expect("audit query")
    };
    let arm = |pic: &PocketIc, point: &str| {
        pic.update_call(
            upgrader,
            m1,
            "arm_rotation_trap_for_test",
            candid::encode_one(&point.to_string()).unwrap(),
        )
        .expect("arming hook is callable on the testing build");
    };

    // A committed ROTATION first, purely to put the counter in motion. It must
    // be a rotation rather than a trigger: single-flight (L2-5) refuses a
    // second trigger while any nonterminal intent exists, and a committed
    // trigger would hold one — so a trigger baseline would make the trapped
    // attempt below fail for the wrong reason and prove nothing.
    let first = {
        let raw = pic
            .update_call(
                upgrader,
                m1,
                "propose_membership_rotation",
                candid::encode_args((vec![p(12), p(13), p(20)], None::<u64>)).unwrap(),
            )
            .unwrap();
        candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
            .unwrap()
            .expect("baseline rotation commits")
    };
    let candidate = first + 1;

    let audit_before = audit_raw(&pic);
    // The absence sentinel: what this gated query returns for an id that has
    // never existed. Comparing against it is how "absent" is asserted without
    // a hand-maintained mirror (raw-byte method, SSA-approved).
    let absent_sentinel = status_raw(&pic, 424_242);
    assert_ne!(
        audit_before,
        pic.query_call(
            upgrader,
            p(99),
            "get_upgrader_audit_events",
            candid::encode_args((None::<u64>, 128u32)).unwrap(),
        )
        .expect("audit query"),
        "fixture guard: the audit baseline must be a real gated read, not a None refusal"
    );

    // TRAP the recovery-action propose between insertion and counter commit.
    arm(&pic, "after_insert_before_counter");
    let wasm = vec![0xE1u8; 8];
    let arg = candid::encode_args(()).unwrap();
    let action = RecoveryAction::TriggerVaultUpgrade {
        expected_wasm_hash: sha256(&wasm),
        expected_arg_hash: sha256(&arg),
        wasm_bytes: wasm,
        arg_bytes: arg,
    };
    let trapped =
        pic.update_call(upgrader, m1, "propose_recovery", candid::encode_one(&action).unwrap());
    assert!(
        trapped.is_err(),
        "RF-5 fixture guard: the propose boundary must fire on the RECOVERY-ACTION \
         path, or this leg proves nothing"
    );

    // ── Everything written before the trap must be gone ─────────────────────
    assert!(
        proposal_absent(&pic, candidate),
        "RF-5: a trapped recovery-action propose left its PROPOSAL behind"
    );
    assert_eq!(
        status_raw(&pic, candidate),
        absent_sentinel,
        "RF-5: the linked INTENT and its artifact store survived the trap. The \
         trigger path writes the intent WITH the artifact bytes before the \
         boundary, so this is the write a rotation-only test could never cover."
    );
    assert_eq!(
        audit_raw(&pic),
        audit_before,
        "RF-5: the VaultUpgradeIntentRecorded audit append survived the trap — every \
         mutation in the message rolls back together or the atomicity claim is false"
    );

    // ── The counter is unchanged: the retry receives the EXACT candidate ────
    arm(&pic, "none");
    let retried = trigger(&pic, 0xE2).expect("the retry must succeed — the trap left no trace");
    assert_eq!(
        retried,
        candidate,
        "RF-5: the recovery-action retry did not reuse the trapped attempt's id. The \
         counter must not have moved — a trapped transaction commits neither counter \
         nor entry, so its candidate comes back unchanged (W1.2/W1.3)."
    );

    // Controls: the committed retry really does write all three surfaces, so
    // none of the equality assertions above compared inert responses.
    assert!(!proposal_absent(&pic, retried), "control: the retried proposal is durable");
    assert_ne!(
        status_raw(&pic, retried),
        absent_sentinel,
        "control: a committed trigger really does create its linked intent"
    );
    assert_ne!(
        audit_raw(&pic),
        audit_before,
        "control: a committed trigger really does append audit events"
    );
}

/// Wire mirror of the Upgrader's `RotationProposalView`. Hand-maintained here
/// like the other views in this file; the DID drift lock is what keeps the
/// upgrader's real type honest.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
struct RotationProposalView {
    proposal_id: u64,
    epoch: u64,
    new_members: Vec<Principal>,
    proposer: Principal,
    approvals: Vec<Principal>,
    threshold: u32,
    created_at_ns: u64,
    outcome: ActionOutcome,
    expires_at_ns: Option<u64>,
    commitment_hash: Vec<u8>,
}

/// S5B W3 acceptance 13 — TRAP MID-TERMINALIZATION ROLLS BACK THE WHOLE
/// ROTATION, through a REAL Wasm/PocketIC message boundary.
///
/// CTO ruled this a GATE CONDITION (2026-08-08): it may not be argued closed on
/// in-process evidence. The reason is measured, not theoretical — outside a
/// canister there is no transaction, `catch_unwind` leaves every mutation in
/// place, and the membership write PRECEDES the terminalization loop, so an
/// in-process assertion observes an already-rotated membership and proves
/// nothing.
///
/// The ordering is safe only because the path is one await-free message. This
/// test is what turns that from an argument into evidence.
#[test]
fn pic_w3_trap_mid_terminalization_rolls_back_whole_rotation() {
    let (pic, _vault, upgrader) = ring_rig_upgrader_test_wasm();
    let (m1, m2, m3) = (p(11), p(12), p(13));

    let call = |pic: &PocketIc, sender: Principal, method: &str, arg: Vec<u8>| {
        pic.update_call(upgrader, sender, method, arg)
    };

    let propose_trigger = |pic: &PocketIc, tag: u8| -> Result<u64, RecoveryError> {
        let wasm = vec![tag; 8];
        let arg = candid::encode_args(()).unwrap();
        let action = RecoveryAction::TriggerVaultUpgrade {
            expected_wasm_hash: sha256(&wasm),
            expected_arg_hash: sha256(&arg),
            wasm_bytes: wasm,
            arg_bytes: arg,
        };
        let raw = call(pic, m1, "propose_recovery", candid::encode_one(&action).unwrap()).unwrap();
        candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw)).unwrap()
    };

    // Reader is a PARAMETER, deliberately: a successful rotation removes m1
    // from the roster, and the membership query is member-gated — so reading as
    // m1 afterwards returns an indistinguishable `None` (correct behaviour, and
    // a nice incidental proof that the rotation really took effect). Post-
    // rotation assertions must therefore read as a SURVIVING member.
    let members = |pic: &PocketIc, reader: Principal| -> Vec<Principal> {
        let r = pic
            .query_call(upgrader, reader, "get_recovery_membership", candid::encode_args(()).unwrap())
            .expect("membership query");
        candid::decode_one::<Option<Vec<Principal>>>(static_bytes(r))
            .expect("membership decodes")
            .expect("membership readable by a member")
    };

    // Reader parameterised for the same reason as `members`.
    let outcome_of = |pic: &PocketIc, reader: Principal, id: u64| -> ActionOutcome {
        let r = pic
            .query_call(upgrader, reader, "get_recovery_proposal", candid::encode_one(&id).unwrap())
            .expect("proposal query");
        candid::decode_one::<Option<stsh_custody_types::RecoveryProposal>>(static_bytes(r))
            .expect("proposal decodes")
            .expect("proposal exists")
            .outcome
    };

    // A stale Pending proposal for the rotation to terminalize.
    let stale = propose_trigger(&pic, 0xC1).expect("stale pending proposal");
    let members_before = members(&pic, m1);

    // Propose the rotation and take it to the quorum boundary.
    let raw = call(
        &pic,
        m1,
        "propose_membership_rotation",
        candid::encode_args((vec![m2, m3, p(14)], None::<u64>)).unwrap(),
    )
    .unwrap();
    let rot = candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
        .unwrap()
        .expect("rotation proposed");
    // R1.5 — approve carries the commitment hash, exactly as a real member
    // does: read the proposal, take its `commitment_hash`, supply it.
    // A ROTATION proposal is a different stored variant, so it is served by
    // `get_rotation_proposal`, not `get_recovery_proposal` (which returns None
    // for it).
    let commit_of = |pic: &PocketIc, id: u64| -> Vec<u8> {
        let r = pic
            .query_call(upgrader, m1, "get_rotation_proposal", candid::encode_one(&id).unwrap())
            .expect("rotation proposal query");
        candid::decode_one::<Option<RotationProposalView>>(static_bytes(r))
            .expect("rotation proposal decodes")
            .expect("rotation proposal exists")
            .commitment_hash
    };
    call(
        &pic,
        m1,
        "approve_recovery",
        candid::encode_args((rot, commit_of(&pic, rot))).unwrap(),
    )
    .expect("first approval");

    // Arm the mid-terminalization boundary; the trap fires INSIDE the
    // quorum-reaching message.
    call(
        &pic,
        m1,
        "arm_rotation_trap_for_test",
        candid::encode_one(&"mid_terminalization".to_string()).unwrap(),
    )
    .expect("arming hook is callable on the testing build");

    let trapped = call(
        &pic,
        m2,
        "approve_recovery",
        candid::encode_args((rot, commit_of(&pic, rot))).unwrap(),
    );
    assert!(
        trapped.is_err(),
        "the armed trap must reject the quorum-reaching message"
    );

    // ROLLBACK, re-read over ingress from durable state.
    assert_eq!(
        members(&pic, m1),
        members_before,
        "W3 acceptance 13 VIOLATED: membership rotated despite the trap. A rotated \
         membership alongside a partially-terminalized stale set is exactly the \
         split-brain state one-message atomicity exists to prevent — and there is \
         no repair machinery behind it."
    );
    assert_eq!(
        outcome_of(&pic, m1, stale),
        ActionOutcome::Pending,
        "W3 acceptance 13 VIOLATED: a stale proposal was terminalized by a rotation \
         that trapped"
    );

    // NON-VACUITY: disarm and re-drive — the same rotation must now commit.
    // Without this the assertions above would pass against a rotation that
    // simply always failed.
    call(
        &pic,
        m1,
        "arm_rotation_trap_for_test",
        candid::encode_one(&"none".to_string()).unwrap(),
    )
    .expect("disarm");
    call(
        &pic,
        m2,
        "approve_recovery",
        candid::encode_args((rot, commit_of(&pic, rot))).unwrap(),
    )
    .expect("the retry must commit the rotation");
    assert_eq!(
        members(&pic, m2),
        vec![m2, m3, p(14)],
        "control: with no trap armed the rotation must actually rotate membership"
    );
    assert_ne!(
        outcome_of(&pic, m2, stale),
        ActionOutcome::Pending,
        "control: and terminalize the stale set"
    );
}

/// SSA RF-2 — GENUINELY mid-terminalization rollback, through a real
/// Wasm/PocketIC message boundary.
///
/// WHAT THE PRIOR TEST DID NOT PROVE. `pic_w3_trap_mid_terminalization_rolls_
/// back_whole_rotation` arms the loop-HEAD boundary with a SINGLE stale
/// record, so the trap fires before any stale record has changed. That
/// establishes "trap before work", which cannot distinguish a rollback from a
/// loop that never started. SSA is right that this is a real gap, and the
/// builder agrees.
///
/// WHAT THIS PROVES INSTEAD. TWO stale records, and the trap fires at the END
/// of the first iteration — after the first stale proposal, its linked intent
/// and its audit event are all durably written inside the message. The
/// rollback therefore has completed work to discard, and every mutation made
/// before the trap is asserted reverted:
///   - membership NOT rotated (the epoch-visible effect),
///   - the FIRST stale proposal back to Pending — the one that HAD been
///     terminalized when the trap fired,
///   - its linked intent back to Pending WITH its artifact bytes still held —
///     terminalization had nulled them,
///   - the audit log back to its pre-rotation length,
///   - the SECOND stale proposal untouched, which is what proves the loop was
///     genuinely mid-flight rather than complete.
///
/// The two stale records are deliberately of DIFFERENT variants: single-flight
/// (L2-5) permits only one nonterminal trigger intent, so a second trigger
/// cannot exist. A trigger plus an extra rotation proposal gives a stale set
/// that exercises BOTH arms of the terminalization match, and the trigger's
/// lower id makes it the one terminalized before the trap.
#[test]
fn pic_rf2_trap_after_first_terminalization_rolls_back_completed_work() {
    let (pic, _vault, upgrader) = ring_rig_upgrader_test_wasm();
    let (m1, m2, m3) = (p(11), p(12), p(13));

    let call = |pic: &PocketIc, sender: Principal, method: &str, arg: Vec<u8>| {
        pic.update_call(upgrader, sender, method, arg)
    };

    let members = |pic: &PocketIc, reader: Principal| -> Vec<Principal> {
        let r = pic
            .query_call(upgrader, reader, "get_recovery_membership", candid::encode_args(()).unwrap())
            .expect("membership query");
        candid::decode_one::<Option<Vec<Principal>>>(static_bytes(r))
            .expect("membership decodes")
            .expect("membership readable by a member")
    };
    let outcome_of = |pic: &PocketIc, reader: Principal, id: u64| -> ActionOutcome {
        let r = pic
            .query_call(upgrader, reader, "get_recovery_proposal", candid::encode_one(&id).unwrap())
            .expect("proposal query");
        candid::decode_one::<Option<stsh_custody_types::RecoveryProposal>>(static_bytes(r))
            .expect("proposal decodes")
            .expect("proposal exists")
            .outcome
    };
    let rotation_outcome_of = |pic: &PocketIc, reader: Principal, id: u64| -> ActionOutcome {
        let r = pic
            .query_call(upgrader, reader, "get_rotation_proposal", candid::encode_one(&id).unwrap())
            .expect("rotation proposal query");
        candid::decode_one::<Option<RotationProposalView>>(static_bytes(r))
            .expect("rotation proposal decodes")
            .expect("rotation proposal exists")
            .outcome
    };
    // The linked intent and the audit log are compared as RAW CANDID RESPONSE
    // BYTES rather than decoded.
    //
    // WHY, stated because "the test did not decode it" normally deserves
    // suspicion: decoding either surface here would require hand-maintained
    // mirrors of `UpgradeStatusView` and of `AuditEventsPage` — and the latter
    // drags in `UpgraderAuditEvent` and its ~16-variant kind enum with five
    // dependent types. CONF-02's lock demands STRUCTURAL EQUALITY, so a
    // deliberately-partial mirror is precisely what it forbids, and a full one
    // would add a large drift surface for a single length assertion.
    //
    // Byte equality of the same deterministic query is also STRICTLY STRONGER
    // than the length comparison RF-2 asks for: it catches a rolled-back-count
    // with changed content, which a length check cannot see. Non-vacuity is
    // covered below — the same bytes are asserted to CHANGE once the rotation
    // is allowed to commit, so this cannot pass by querying something inert.
    let raw_query = |pic: &PocketIc, reader: Principal, method: &str, arg: Vec<u8>| -> Vec<u8> {
        pic.query_call(upgrader, reader, method, arg)
            .unwrap_or_else(|e| panic!("{method} query failed: {e:?}"))
    };
    let intent_bytes = |pic: &PocketIc, reader: Principal, id: u64| -> Vec<u8> {
        raw_query(pic, reader, "get_upgrade_status", candid::encode_one(&id).unwrap())
    };
    let audit_bytes = |pic: &PocketIc, reader: Principal| -> Vec<u8> {
        raw_query(
            pic,
            reader,
            "get_upgrader_audit_events",
            // 128 = MAX_READ_PAGE_LIMIT. A larger limit is REJECTED by the
            // query (`limit > MAX_READ_PAGE_LIMIT` returns None), and the
            // first cut of this test passed 256 — so both sides of the
            // rollback comparison were an identical `None` and the assertion
            // was vacuous. Caught by the non-vacuity control at the end of
            // this test, not by reading the diff.
            candid::encode_args((None::<u64>, 128u32)).unwrap(),
        )
    };

    // STALE RECORD 1 — a trigger proposal. Lowest id, so the terminalization
    // loop reaches it FIRST and it is the record completed before the trap.
    let wasm = vec![0xD1u8; 8];
    let arg = candid::encode_args(()).unwrap();
    let action = RecoveryAction::TriggerVaultUpgrade {
        expected_wasm_hash: sha256(&wasm),
        expected_arg_hash: sha256(&arg),
        wasm_bytes: wasm,
        arg_bytes: arg,
    };
    let raw = call(&pic, m1, "propose_recovery", candid::encode_one(&action).unwrap()).unwrap();
    let stale_trigger = candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
        .unwrap()
        .expect("stale trigger proposal");

    // STALE RECORD 2 — an extra rotation proposal, left Pending. A second
    // TRIGGER is impossible here (single-flight), and using two records of
    // different variants also exercises both arms of the match.
    let raw = call(
        &pic,
        m1,
        "propose_membership_rotation",
        candid::encode_args((vec![m1, m2, p(15)], None::<u64>)).unwrap(),
    )
    .unwrap();
    let stale_rotation = candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
        .unwrap()
        .expect("stale rotation proposal");

    // The rotation that will DRIVE the terminalization.
    let raw = call(
        &pic,
        m1,
        "propose_membership_rotation",
        candid::encode_args((vec![m2, m3, p(14)], None::<u64>)).unwrap(),
    )
    .unwrap();
    let rot = candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
        .unwrap()
        .expect("rotation proposed");

    let commit_of = |pic: &PocketIc, id: u64| -> Vec<u8> {
        let r = pic
            .query_call(upgrader, m1, "get_rotation_proposal", candid::encode_one(&id).unwrap())
            .expect("rotation proposal query");
        candid::decode_one::<Option<RotationProposalView>>(static_bytes(r))
            .expect("rotation proposal decodes")
            .expect("rotation proposal exists")
            .commitment_hash
    };
    call(
        &pic,
        m1,
        "approve_recovery",
        candid::encode_args((rot, commit_of(&pic, rot))).unwrap(),
    )
    .expect("first approval");

    // Baselines captured at the quorum boundary — the state the rollback must
    // restore EXACTLY.
    let members_before = members(&pic, m1);
    let audit_before = audit_bytes(&pic, m1);
    let intent_before = intent_bytes(&pic, m1, stale_trigger);
    // GUARD: both baselines must be REAL DATA, not the `None` this gated query
    // returns for an unauthorized caller or an out-of-range limit. Without
    // this, a query that silently refused would make every equality assertion
    // below compare two identical refusals and pass while proving nothing —
    // which is exactly what the first cut of this test did.
    let outsider = p(99);
    assert_ne!(
        audit_before,
        audit_bytes(&pic, outsider),
        "fixture guard: the audit baseline must be a real gated read, not the None \
         returned to a non-member or for an out-of-range page limit"
    );
    assert_ne!(
        intent_before,
        intent_bytes(&pic, outsider, stale_trigger),
        "fixture guard: the intent baseline must be a real gated read, not None"
    );
    assert_eq!(
        outcome_of(&pic, m1, stale_trigger),
        ActionOutcome::Pending,
        "fixture guard: the stale trigger starts Pending"
    );

    // Arm the AFTER-FIRST boundary and drive to quorum.
    call(
        &pic,
        m1,
        "arm_rotation_trap_for_test",
        candid::encode_one(&"after_first_terminalization".to_string()).unwrap(),
    )
    .expect("arming hook is callable on the testing build");
    let trapped = call(
        &pic,
        m2,
        "approve_recovery",
        candid::encode_args((rot, commit_of(&pic, rot))).unwrap(),
    );
    let reject = format!("{trapped:?}");
    assert!(
        trapped.is_err(),
        "RF-2 fixture guard: the after-first boundary must fire. If it does not, the \
         loop completed and this test proves nothing about mid-work rollback."
    );
    // THE LOAD-BEARING ASSERTION. Rollback erases the completed work, so after
    // the fact this boundary and the loop-head one are indistinguishable by
    // state alone — every assertion below would pass just as well against a
    // trap that fired before any record changed, which is precisely RF-2's
    // complaint about the existing test. The canister therefore reports how
    // many stale records it had ALREADY terminalized when it trapped, and that
    // count is checked here, over ingress, from its own execution.
    assert!(
        reject.contains("after 1 terminalized"),
        "RF-2: the trap must fire with at least one stale record ALREADY \
         terminalized in this message — otherwise this is the loop-head boundary \
         again, proving 'trap before work' rather than mid-work rollback. \
         Reject message was: {reject}"
    );

    // ── ROLLBACK, re-read over ingress from durable state ───────────────────
    assert_eq!(
        members(&pic, m1),
        members_before,
        "RF-2: membership rotated despite a trap taken AFTER real terminalization work. \
         A rotated membership beside a partially-terminalized stale set is the \
         split-brain state one-message atomicity exists to prevent — and there is no \
         repair machinery behind it."
    );
    assert_eq!(
        outcome_of(&pic, m1, stale_trigger),
        ActionOutcome::Pending,
        "RF-2: the FIRST stale proposal — the one that HAD been terminalized when the \
         trap fired — was not rolled back. This is the assertion the prior test could \
         not make, because its trap fired before any record changed."
    );
    assert_eq!(
        intent_bytes(&pic, m1, stale_trigger),
        intent_before,
        "RF-2: the linked INTENT was not rolled back. Terminalization set it Failed and \
         nulled its artifact bytes; the whole status view must revert byte-for-byte, so \
         a partial revert (outcome restored, bytes still nulled) cannot pass here."
    );
    assert_eq!(
        audit_bytes(&pic, m1),
        audit_before,
        "RF-2: audit events written before the trap survived. Every mutation in the \
         message rolls back together or the atomicity claim is false."
    );
    assert_eq!(
        rotation_outcome_of(&pic, m1, stale_rotation),
        ActionOutcome::Pending,
        "RF-2: the SECOND stale proposal must be untouched — that is what proves the \
         loop trapped MID-flight rather than after completing"
    );

    // NON-VACUITY: disarm and re-drive. Without this every assertion above
    // would pass against a rotation that simply always failed — and it also
    // proves the stale set really was reachable and really does terminalize.
    call(
        &pic,
        m1,
        "arm_rotation_trap_for_test",
        candid::encode_one(&"none".to_string()).unwrap(),
    )
    .expect("disarm");
    call(
        &pic,
        m2,
        "approve_recovery",
        candid::encode_args((rot, commit_of(&pic, rot))).unwrap(),
    )
    .expect("the retry must commit the rotation");
    assert_eq!(
        members(&pic, m2),
        vec![m2, m3, p(14)],
        "control: with no trap armed the rotation must actually rotate membership"
    );
    assert_ne!(
        outcome_of(&pic, m2, stale_trigger),
        ActionOutcome::Pending,
        "control: the first stale record really does terminalize"
    );
    assert_ne!(
        rotation_outcome_of(&pic, m2, stale_rotation),
        ActionOutcome::Pending,
        "control: and so does the second — both were genuinely in the stale set"
    );
    // NON-VACUITY for the two byte comparisons: they must be capable of
    // MOVING. Without this, both equality assertions above would also hold
    // against a query that returned a constant.
    assert_ne!(
        audit_bytes(&pic, m2),
        audit_before,
        "control: the audit query must actually move when the rotation commits — \
         otherwise the rollback assertion above compares two inert responses"
    );
    assert_ne!(
        intent_bytes(&pic, m2, stale_trigger),
        intent_before,
        "control: the intent status must actually move when terminalization commits"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// S5A — I_msg PROBE (CTO ruling T0010Z, leg (i))
// ═════════════════════════════════════════════════════════════════════════════

/// Measure the effective per-message instruction ceiling by binary search.
///
/// WHY THIS IS A TEST AND NOT A CONSTANT. Every budget in
/// `A1_M1_MEASUREMENT_SPEC_V2` — sweep `0.25 × I_msg`, rotation `0.20 × I_msg`,
/// commitment validation `0.05 × I_msg` — is a fraction of `I_msg`, and `I_msg`
/// is pinned nowhere in this repository or in the S5A office lineage. Writing
/// the number down from recall would make every derived figure rest on an
/// unverified premise, which is the exact failure mode ("agreement is not
/// confirmation") that the ~27 → 46.2 MB/yr lesson was drawn from.
///
/// WHAT IT ESTABLISHES, PRECISELY. This is PocketIC's ceiling on this machine —
/// the limit under which every M1 figure in the packet was actually taken. It
/// is NOT the mainnet application-subnet limit, which production safety depends
/// on and which cannot be measured from here; that is leg (ii), pinned by
/// documented authority at the constants-table step. If the two differ, the
/// budgets adjudicate against the mainnet value with the discrepancy recorded.
/// Reported as a MEASURED figure, never as a ruled one.
#[test]
fn s5a_measure_effective_per_message_instruction_ceiling() {
    let (pic, vault) = rig_test_wasm();

    // Does a burn to `target` survive, or is the message killed for exceeding
    // its instruction limit? Any reject is treated as "did not survive"; the
    // search only needs the boundary, and the reject text is printed so a
    // ceiling found for some OTHER reason cannot masquerade as this one.
    // Every refusal is checked to be an INSTRUCTION-LIMIT refusal. A ceiling
    // found for any other reason — cycles exhaustion, a trap, a decode failure
    // — would otherwise be reported as `I_msg` with full confidence, and the
    // binary search would converge on it just as cleanly.
    let survives = |target: u64| -> bool {
        match pic.update_call(
            vault,
            p(S1),
            "burn_instructions_for_test",
            candid::encode_one(target).unwrap(),
        ) {
            Ok(_) => true,
            Err(e) => {
                println!(
                    "  target {target:>15} → REJECT {:?}: {}",
                    e.reject_code, e.reject_message
                );
                assert!(
                    e.reject_message.contains("instructions"),
                    "the burn was refused for a reason OTHER than the instruction \
                     limit, so the boundary being measured is not I_msg: {}",
                    e.reject_message
                );
                false
            }
        }
    };

    // A small burn MUST succeed, or the search would "converge" on a ceiling
    // produced by a broken endpoint — an unarmed hook, a gating failure, a
    // decode error — rather than by the instruction limit. Without this the
    // whole measurement could return a confident number for the wrong reason.
    assert!(
        survives(1_000_000),
        "control: a 1M-instruction burn must succeed. If it does not, the probe \
         is failing for a reason unrelated to the instruction ceiling and every \
         figure below would be meaningless."
    );

    // Bracket: climb by doubling until a target is refused. Bounded so a
    // never-refusing endpoint fails loudly rather than looping forever.
    let mut lo: u64 = 1_000_000;
    let mut hi: u64 = 0;
    let mut probe: u64 = 2_000_000;
    for _ in 0..40 {
        if survives(probe) {
            lo = probe;
            probe = probe.saturating_mul(2);
        } else {
            hi = probe;
            break;
        }
    }
    assert!(
        hi > 0,
        "no target was refused up to {lo} instructions — the burner is not \
         actually consuming instructions (optimised away?), so no ceiling exists \
         to find"
    );

    // Narrow. 64 halvings is far more than u64 needs; the loop exits on
    // convergence.
    for _ in 0..64 {
        if hi - lo <= 1_000_000 {
            break;
        }
        let mid = lo + (hi - lo) / 2;
        if survives(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }

    println!("\n=== S5A — EFFECTIVE PER-MESSAGE INSTRUCTION CEILING (leg (i)) ===");
    println!("| bound | instructions |");
    println!("|---|---|");
    println!("| highest surviving burn | {lo} |");
    println!("| lowest refused burn    | {hi} |");
    println!(
        "\nI_msg (PocketIC, this machine) is bracketed in [{lo}, {hi}] — \
         resolution {} instructions.",
        hi - lo
    );
    println!(
        "MEASURED, not ruled. This is the ceiling the M1 figures were taken \
         under (leg (i)). The MAINNET application-subnet limit is leg (ii), \
         pinned by documented authority at the constants-table step; budgets \
         adjudicate against that value.\n"
    );

    // The bracket must be real: a degenerate one would print a confident
    // interval that means nothing.
    assert!(lo > 0 && hi > lo, "the ceiling must be bracketed by a real interval");
}

// ═════════════════════════════════════════════════════════════════════════════
// S5A — M1 GATE A: SWEEP COST (spec §A) — VAULT PLANE
// ═════════════════════════════════════════════════════════════════════════════

/// Seed `n` DUE, artifact-bearing proposals through the REAL propose path.
///
/// Driven rather than hand-planted: a synthetic seeder that wrote records
/// directly would measure a shape the system never actually produces, and would
/// keep passing if `propose` stopped populating the expiry index at all.
fn seed_due_proposals(
    pic: &PocketIc,
    vault: Principal,
    n: u32,
    artifact_bytes: usize,
    lifetime_ns: u64,
) {
    for i in 0..n {
        // Artifact-bearing worst shape (§A): expiry CLEARS these bytes, so the
        // record is rewritten at reap and the payload is part of the per-record
        // cost rather than incidental to it. Each payload differs by a byte so
        // no two records can be deduplicated or share storage.
        let wasm = vec![(i % 251) as u8; artifact_bytes];
        let arg = vec![0u8; 8];
        let u = UpgraderUpgrade {
            expected_wasm_hash: sha256(&wasm),
            expected_arg_hash: sha256(&arg),
            wasm_bytes: wasm,
            arg_bytes: arg,
        };
        let r = pic
            .update_call(
                vault,
                p(S1),
                "propose",
                candid::encode_args((
                    VaultActionKind::UpgraderUpgrade(u),
                    Some(lifetime_ns),
                ))
                .unwrap(),
            )
            .expect("propose call");
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(r))
            .unwrap()
            .expect("seeded proposal accepted");
    }
}

/// Take C9 OUT OF FORCE for a measurement, deliberately and visibly.
///
/// S6 ruled C9 at 26 entry events per signer per rolling 24 h. Every S5A
/// measurement harness seeds from ONE signer — `p(S1)` — and needs far more
/// than 26 admissions to reach the occupancies its budgets are stated at, so
/// with C9 live the seeding loop is refused partway through and the harness
/// reports a truncated table rather than a failure.
///
/// C9 IS NOT UNDER MEASUREMENT HERE. These harnesses measure sweep cost,
/// validation cost and admission cost at a given occupancy; the rate at which
/// that occupancy was reached does not enter any of those figures. Setting the
/// gate inactive for the duration is therefore measuring the intended quantity,
/// not evading a bound — and it is done through the SAME test-only ingress hook
/// whose absence from every release Wasm the feature-isolation suite asserts.
///
/// The alternative — advancing PocketIC time one 24 h window per seeded record
/// — was rejected: at the occupancies §C requires it would put hundreds of
/// simulated days between the first and last record, which changes nothing
/// about the cost being measured while making every table slower to produce and
/// harder to reason about.
///
/// C9's own enforcement is proved separately and at full strength by
/// `pic_rf6_entry_rate_ledger_survives_a_real_wasm_upgrade` and the S6
/// obligation tests.
///
/// IT INJECTS A PERMISSIVE VALUE RATHER THAN `None`, AND THAT IS NOT A STYLE
/// CHOICE. The accessor is
///
/// ```ignore
/// if let Some(p) = INJECTED { return Some(p) }
/// stsh_custody_types::ENTRY_RATE_PARAMS
/// ```
///
/// so injecting `None` does not disable the gate — it falls THROUGH to the
/// ruled constant. The injector can override a bound; it cannot express the
/// absence of one. That was harmless while the production constant was `None`
/// (both paths agreed) and became load-bearing the moment S6 ruled C9: an
/// injection of `None` now silently leaves 240/26 in force. Anything here that
/// means "no rate bound" must therefore say so as a value.
fn suspend_entry_rate_for_measurement(pic: &PocketIc, vault: Principal) {
    pic.update_call(
        vault,
        p(S1),
        "set_entry_rate_params_for_test",
        candid::encode_one(&Some(stsh_custody_types::EntryRateParams {
            window_ns: u64::MAX,
            global_per_window: u32::MAX,
            per_signer_per_window: u32::MAX,
        }))
        .unwrap(),
    )
    .expect("entry-rate injection is callable on the testing build");
}

/// Raise C5/C7 out of the way for a measurement that must reach an occupancy
/// admission cannot produce.
///
/// V15 §4 obligation 6 states the §C inequalities AT OCCUPANCY 320.
///
/// AN EARLIER REVISION CLAIMED THAT OCCUPANCY WAS UNREACHABLE — that C5 x a
/// 9-signer roster tops out at 288 and the remaining 32 slots were "ruled
/// margin". THAT ARGUMENT IS WITHDRAWN. It assumed the roster bounds the
/// nonterminal population, and it does not: a proposal stays nonterminal across
/// a signer-set rotation, so slots held by rotated-out signers persist and the
/// population accumulates past the roster size. The same mechanism makes C8
/// legally reachable, proved directly by
/// `s6c_c8_is_reachable_by_legal_rotation_and_enforced_at_equality`. C7's
/// margin was never adjudicated and is treated as UNPROVEN, not safe.
///
/// So raising the cap here is a HARNESS CONVENIENCE, not a necessity: the
/// occupancy is reachable legally, but only through a long rotation sequence
/// that would measure the rotation path rather than the admission cost this
/// harness exists to measure. Stated honestly rather than justified by a
/// reachability claim that does not hold.
///
/// The global cap is left at its ruled 320 — that is the number under test.
/// Only the per-signer distribution constraint is lifted, so what is being
/// measured is still "the system holding 320 nonterminal proposals".
/// Raise C6/C8 out of the way for a measurement that must reach a byte
/// occupancy legal admission cannot produce.
///
/// The allocation sweep measures AT the C8 ceiling of 20,971,520 logical bytes.
///
/// C8 IS LEGALLY REACHABLE — via rotation, since retained bytes attribute to
/// historical proposers and accumulate past 9 x C6. The earlier "ruled margin"
/// claim here is WITHDRAWN (see the count-cap helper above). Raising the
/// per-signer limb is therefore a harness convenience that avoids driving a
/// multi-rotation sequence inside an allocation measurement; it is not a
/// statement that the ceiling cannot be reached. The GLOBAL limb is left at its
/// ruled C8 — that is the number the sweep measures against.
fn raise_byte_quotas_for_measurement(pic: &PocketIc, vault: Principal) {
    pic.update_call(
        vault,
        p(S1),
        "set_byte_quotas_for_test",
        candid::encode_one(&Some((u64::MAX, stsh_custody_types::GLOBAL_LOGICAL_BYTE_QUOTA)))
            .unwrap(),
    )
    .expect("byte-quota injection is callable on the testing build");
}

fn raise_per_signer_cap_for_measurement(pic: &PocketIc, vault: Principal) {
    pic.update_call(
        vault,
        p(S1),
        "set_nonterminal_caps_for_test",
        candid::encode_one(&Some(stsh_custody_types::NonterminalCaps {
            global: 320,
            per_signer: u32::MAX,
        }))
        .unwrap(),
    )
    .expect("caps injection is callable on the testing build");
}

fn inject_bounds(pic: &PocketIc, vault: Principal, min_ns: u64, max_ns: u64) {
    pic.update_call(
        vault,
        p(S1),
        "set_lifetime_params_for_test",
        candid::encode_args((
            Some(stsh_custody_types::ProposalLifetimeBounds { min_ns, max_ns }),
            Option::<u32>::None,
        ))
        .unwrap(),
    )
    .expect("bounds injection is callable on the testing build");
}

fn measure_sweep(pic: &PocketIc, vault: Principal, limit: u32) -> (u64, u32) {
    let r = pic
        .update_call(
            vault,
            p(S1),
            "measure_sweep_instructions_for_test",
            candid::encode_args((u64::MAX, limit)).unwrap(),
        )
        .expect("sweep measurement call");
    candid::decode_args::<(u64, u32)>(static_bytes(r)).unwrap()
}

/// M1 gate A — `c_fixed_worst` and `c_record_worst`, Vault plane.
///
/// Reported as MEASURED figures only. C11 is
/// `floor((0.25 × I_msg − c_fixed_worst) / c_record_worst)`; deriving it is the
/// constants table's step under R-4 Route 2, not the builder's, so this test
/// prints the inputs and rules nothing.
///
/// FIXTURE vs RULED THRESHOLD, stated explicitly per the S5A discipline: the
/// lifetime bounds and artifact size below are FIXTURE values chosen to make
/// the path measurable. They are not proposed constants, and agreement between
/// this fixture and any candidate C11 would not constitute confirmation of it.
#[test]
fn s5a_m1_gate_a_measure_sweep_cost_vault_plane() {
    let (pic, vault) = rig_test_wasm();
    suspend_entry_rate_for_measurement(&pic, vault);
    raise_byte_quotas_for_measurement(&pic, vault);
    inject_bounds(&pic, vault, 1_000, 1_000_000_000);

    const ARTIFACT: usize = 64 * 1024;
    let occupancies: [u32; 5] = [0, 2, 4, 8, 16];

    println!("\n=== S5A/M1 GATE A — SWEEP COST, VAULT PLANE ===");
    println!("(artifact-bearing proposals, {ARTIFACT} B payload each)");
    println!("| due records | instructions | reaped | marginal/record |");
    println!("|---|---|---|---|");

    let mut baseline = 0u64;
    let mut points: Vec<(u32, u64)> = Vec::new();
    for (idx, n) in occupancies.iter().copied().enumerate() {
        seed_due_proposals(&pic, vault, n, ARTIFACT, 1_000);
        let (instr, reaped) = measure_sweep(&pic, vault, 1_000);
        assert_eq!(
            reaped, n,
            "the sweep reaped {reaped} of {n} seeded due records — a fixture that \
             under-delivers would silently deflate every per-record figure below"
        );
        if idx == 0 {
            baseline = instr;
        }
        let marginal = if n > 0 {
            format!("{}", (instr.saturating_sub(baseline)) / n as u64)
        } else {
            "— (this row IS c_fixed_worst)".to_string()
        };
        println!("| {n} | {instr} | {reaped} | {marginal} |");
        points.push((n, instr));
    }

    let c_fixed = baseline;
    let (max_n, max_instr) = *points.last().unwrap();
    let c_record = (max_instr.saturating_sub(c_fixed)) / max_n as u64;

    println!("\n**c_fixed_worst = {c_fixed} instructions** (empty-index sweep call)");
    println!("**c_record_worst = {c_record} instructions/record** (slope to n={max_n})");
    println!(
        "\nLINEARITY CHECK — if the marginal column above is not flat, C11's \
         formula shape (a single c_record_worst) does not hold and that is a \
         finding for the table, not something to average away."
    );
    println!(
        "FIXTURE, NOT THRESHOLD: bounds and the {ARTIFACT} B artifact are fixture \
         values chosen to make the path measurable. They are not proposed \
         constants; agreement with any candidate C11 is not confirmation of it.\n"
    );

    // Non-vacuity: a sweep that costs nothing per record would mean the fixture
    // never populated the index, which is the failure this whole measurement is
    // most exposed to.
    assert!(
        c_record > 0,
        "measured a per-record cost of ZERO — the fixture is not producing due \
         records and every figure here would be a measurement of nothing"
    );
    assert!(c_fixed > 0, "an empty sweep must still cost something");
}

/// M1 gate A, second axis — per-record sweep cost against ARTIFACT SIZE.
///
/// WHY THIS EXISTS AND WHY IT IS NOT OPTIONAL. Spec §A asks for
/// `c_record_worst` at "worst shape (artifact-bearing)", as a SINGLE symbol.
/// The occupancy run above shows the per-record cost is dominated by the
/// artifact payload — expiry clears the bytes, so the whole record is rewritten
/// at reap. That makes `c_record_worst` a function of payload size rather than
/// a constant, and the worst admitted payload is far larger than any
/// convenient fixture.
///
/// Measuring one artifact size and calling it `c_record_worst` would therefore
/// understate the true worst case by whatever ratio the largest admitted
/// payload bears to the fixture — silently, and in the generous direction, on a
/// constant that bounds a DoS surface. So the dependence is measured directly
/// and reported as a curve. Which point on it is "worst" is the table's call.
#[test]
fn s5a_m1_gate_a_sweep_cost_vs_artifact_size_vault_plane() {
    let (pic, vault) = rig_test_wasm();
    // S6 corrective: C6/C8 are enforced now, and this harness admits MANY large
    // artifacts to one signer. Cumulative retention would hit C6 partway
    // through and the probe would report the point where the QUOTA bound,
    // not the point the measurement is looking for — a silent measurement
    // artifact, which is exactly how P_max appeared to "move" to 1 MiB.
    raise_byte_quotas_for_measurement(&pic, vault);
    inject_bounds(&pic, vault, 1_000, 1_000_000_000);

    // Spread across three orders of magnitude, ending near the largest payload
    // the §8 encoded-message invariant admits (~1.9 MB bound, so 1.5 MB leaves
    // room for the rest of the envelope).
    // The top point is the PROVED P_max, not a convenient large fixture.
    // c_record_worst is required AT P_max: extrapolating from 1,500 KiB was the
    // defect SSA returned (Blocker 2), and it understated the figure.
    let sizes: [usize; 5] = [1_024, 16 * 1024, 64 * 1024, 512 * 1024, P_MAX_VAULT];
    const N: u32 = 2;

    println!("\n=== S5A/M1 GATE A — SWEEP PER-RECORD COST vs ARTIFACT SIZE (VAULT) ===");
    println!("| artifact bytes | instructions (n={N}) | per record | instr/byte |");
    println!("|---|---|---|---|");

    let mut rows: Vec<(usize, u64)> = Vec::new();
    for size in sizes {
        seed_due_proposals(&pic, vault, N, size, 1_000);
        let (instr, reaped) = measure_sweep(&pic, vault, 1_000);
        assert_eq!(reaped, N, "fixture must deliver {N} due records at {size} B");
        let per = instr / N as u64;
        println!(
            "| {size} | {instr} | {per} | {} |",
            per / size.max(1) as u64
        );
        rows.push((size, per));
    }

    let (small_size, small_cost) = rows[0];
    let (big_size, big_cost) = *rows.last().unwrap();
    println!(
        "\n**Per-record cost is NOT a constant**: {small_cost} instructions at \
         {small_size} B vs {big_cost} at {big_size} B — a factor of {:.1}× across \
         a {:.0}× payload range.",
        big_cost as f64 / small_cost.max(1) as f64,
        big_size as f64 / small_size as f64
    );
    println!(
        "CONSEQUENCE FOR C11, stated as a measurement and not a ruling: \
         `c_record_worst` in §A's formula is a FUNCTION OF PAYLOAD SIZE, so a \
         single C11 is only safe if it is derived against the LARGEST ADMITTED \
         artifact. Deriving it from a small-artifact fixture overstates the \
         admissible batch, in the generous direction, on a bound whose purpose \
         is to stop the sweep becoming the DoS it exists to prevent."
    );
    println!(
        "TOP POINT IS PROVED P_max ({P_MAX_VAULT} B, bracketed with an adjacent \
         observed refusal) — c_record_worst is therefore MEASURED at the maximum, \
         not extrapolated toward it. The smaller sizes remain fixture points that \
         expose the payload dependence.\n"
    );

    assert!(
        big_cost > small_cost,
        "per-record cost must rise with payload — if it does not, the artifact \
         bytes are not being rewritten at reap and the worst-shape premise of \
         §A is wrong"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// S5A — M1 GATE B: ROTATION ENVELOPE + W3 ONE-MESSAGE CURVE (spec §B)
// ═════════════════════════════════════════════════════════════════════════════

/// The W3 one-message rotation instruction curve, at candidate occupancies.
///
/// THE ENVELOPE EVIDENCE THAT DECIDES WHETHER A RULED C12 FITS (brief V3
/// acceptance 14, spec §B). W3's rotation is NOT a resumable sweep: the
/// complete stale set is terminalized and the membership change committed in
/// ONE message, with no cursor and no continuation, because a partially-rotated
/// membership beside a partially-terminalized stale set is the split-brain
/// state the atomicity exists to prevent. So the whole cost must fit inside a
/// single message's budget, and the question C12 answers is how many stale
/// records that permits.
///
/// The code comment at the terminalization loop says exactly this — "whether
/// the ruled C12 fits this envelope is M1's finding, not an assumption made
/// here. If it does not, that returns to CTO as a constants problem (lower
/// C12) — never as a licence to batch." This is that finding.
///
/// MEASURED ONLY. §B's gate is
///   rotation_fixed + max(N × c_stale_unlinked,
///                        c_stale_linked + (N−1) × c_stale_unlinked) ≤ 0.20 × I_msg
/// with N = C12 − 1. Evaluating it is the constants table's step; this test
/// supplies rotation_fixed and the per-record slope and rules nothing.
#[test]
fn s5a_m1_gate_b_w3_rotation_instruction_curve() {
    let (m1, m2, m3) = (p(11), p(12), p(13));

    // Caps are raised to admit the fixture. The CAP VALUE here is a FIXTURE,
    // not a candidate C12 — this curve is the evidence C12 is chosen FROM, so
    // reading a candidate back out of it would be circular.
    const MAX_STALE: u32 = 24;

    println!("\n=== S5A/M1 GATE B — W3 ONE-MESSAGE ROTATION CURVE ===");
    println!("(instructions consumed by the QUORUM-REACHING message alone)");
    println!("| stale records terminalized | instructions | marginal/record |");
    println!("|---|---|---|");

    // Each occupancy needs a FRESH canister: a rotation changes membership, so
    // the same rig cannot be driven twice with the same signers.
    let mut rows: Vec<(u32, u64)> = Vec::new();
    let mut baseline = 0u64;
    for (idx, n) in [0u32, 1, 2, 4, 8, 16, 24].into_iter().enumerate() {
        let (pic, _v, upgrader) = ring_rig_upgrader_test_wasm();
        pic.update_call(
            upgrader,
            m1,
            "set_nonterminal_caps_for_test",
            candid::encode_one(&Some(stsh_custody_types::NonterminalCaps {
                global: MAX_STALE + 4,
                per_signer: MAX_STALE + 4,
            }))
            .unwrap(),
        )
        .expect("caps injection");

        let propose_rotation = |sender: Principal, tag: u8| -> u64 {
            let raw = pic
                .update_call(
                    upgrader,
                    sender,
                    "propose_membership_rotation",
                    candid::encode_args((vec![m2, m3, p(tag)], None::<u64>)).unwrap(),
                )
                .unwrap();
            candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
                .unwrap()
                .expect("proposal commits")
        };
        let commit_of = |reader: Principal, id: u64| -> Vec<u8> {
            let r = pic
                .query_call(
                    upgrader,
                    reader,
                    "get_rotation_proposal",
                    candid::encode_one(&id).unwrap(),
                )
                .expect("rotation proposal query");
            candid::decode_one::<Option<RotationProposalView>>(static_bytes(r))
                .expect("decodes")
                .expect("proposal exists")
                .commitment_hash
        };

        // Stale set: rotation proposals, which carry NO linked intent. Per
        // spec §B.1 these are the `c_stale_unlinked` shape, and they are the
        // only shape a multi-record fixture can use — single-flight permits at
        // most ONE nonterminal intent globally, so at most one stale record in
        // any rotation can be a linked trigger proposal.
        for i in 0..n {
            propose_rotation(m1, 30 + i as u8);
        }

        let rot = propose_rotation(m1, 60);
        pic.update_call(
            upgrader,
            m1,
            "approve_recovery",
            candid::encode_args((rot, commit_of(m1, rot))).unwrap(),
        )
        .expect("first approval");

        // ── THE QUORUM-REACHING MESSAGE ─────────────────────────────────────
        pic.update_call(
            upgrader,
            m2,
            "approve_recovery",
            candid::encode_args((rot, commit_of(m1, rot))).unwrap(),
        )
        .expect("the quorum-reaching message commits the rotation");

        // Read as m2: this rotation's roster is [m2, m3, …], so m1 has been
        // rotated OUT and every gated surface returns an indistinguishable
        // fail-closed value to it.
        //
        // DEFINED INSIDE THE LOOP, and that is the point. Each occupancy needs
        // its own canister, so the readback must be bound to THIS iteration's
        // `pic`/`upgrader`. An earlier cut defined it in the outer scope, where
        // it silently queried the outer rig — a canister that never had a
        // rotation approved — and returned 0 for every occupancy. The curve
        // looked perfectly well-formed and was entirely fictional; the
        // per-record non-vacuity assertion below is what caught it.
        let last_instructions = |reader: Principal| -> u64 {
            let r = pic
                .query_call(
                    upgrader,
                    reader,
                    "last_approve_instructions_for_test",
                    candid::encode_args(()).unwrap(),
                )
                .expect("instruction readback query");
            candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
        };
        let instr = last_instructions(m2);
        if idx == 0 {
            baseline = instr;
        }
        let marginal = if n > 0 {
            format!("{}", instr.saturating_sub(baseline) / n as u64)
        } else {
            "— (this row IS rotation_fixed)".to_string()
        };
        println!("| {n} | {instr} | {marginal} |");
        rows.push((n, instr));
    }

    let rotation_fixed = baseline;
    let (max_n, max_instr) = *rows.last().unwrap();
    let c_stale_unlinked = max_instr.saturating_sub(rotation_fixed) / max_n as u64;

    println!("\n**rotation_fixed = {rotation_fixed} instructions**");
    println!("**c_stale_unlinked = {c_stale_unlinked} instructions/record** (slope to n={max_n})");
    println!(
        "\n§B GATE (evaluated by the TABLE, not here), with N = C12 − 1:\n\
         \x20 rotation_fixed + max(N × c_stale_unlinked,\n\
         \x20                      c_stale_linked + (N−1) × c_stale_unlinked)  ≤  0.20 × I_msg"
    );
    println!(
        "AT MOST ONE stale record can be a LINKED trigger proposal — single-flight \
         permits one nonterminal intent globally (spec §B.1). c_stale_linked is \
         therefore measured separately and is never multiplied by N."
    );
    println!(
        "FIXTURE, NOT THRESHOLD: the injected caps admit the fixture and are NOT a \
         candidate C12. This curve is the evidence C12 is chosen FROM; agreement \
         between it and any candidate is not confirmation of that candidate.\n"
    );

    assert!(
        c_stale_unlinked > 0,
        "measured a per-stale-record cost of ZERO — the fixture terminalized \
         nothing and the whole curve would be a measurement of an empty stale set"
    );
    assert!(
        max_instr > rotation_fixed,
        "the quorum-reaching message must cost more with a stale set than without"
    );
    // Non-vacuity for the readback itself: a query wired to a constant would
    // produce a perfectly plausible flat curve.
    assert!(
        rows.iter().map(|(_, i)| *i).collect::<std::collections::BTreeSet<_>>().len() > 1,
        "every occupancy reported the SAME instruction count — the readback query \
         is not observing the message it claims to measure"
    );
}

/// M1 gate B — `c_stale_linked`: the ONE permitted linked trigger proposal.
///
/// Spec §B.1's correction, measured. Single-flight permits at most ONE
/// nonterminal upgrade intent across BOTH origin namespaces, so at most one
/// stale record in any rotation can carry a linked intent. That is why §B gates
/// against `max(N × c_stale_unlinked, c_stale_linked + (N−1) × c_stale_unlinked)`
/// rather than against `N × c_stale_linked` — the latter would constrain C12
/// against a state the system cannot enter.
///
/// The linked branch does strictly more work than the unlinked one: it reads
/// the intent, asserts it is Pending, terminalizes it, CLEARS its artifact
/// bytes, and emits `StaleIntentTerminalized` instead of
/// `StaleProposalTerminalized` (`core.rs:3061` vs `:3097`). This measures that
/// difference on the real path.
#[test]
fn s5a_m1_gate_b_measure_c_stale_linked() {
    let (m1, m2, m3) = (p(11), p(12), p(13));
    // The single linked record carries PROVED P_max. At 64 KiB the envelope was
    // understated (SSA Blocker 2): the linked branch CLEARS artifact bytes, so
    // its cost scales with the payload, and the one record §B.1 permits is
    // exactly the one that can be at maximum.
    const ARTIFACT: usize = P_MAX_RECOVERY;

    println!("\n=== S5A/M1 GATE B — c_stale_linked (the ONE permitted linked record) ===");
    println!("| fixture | instructions |");
    println!("|---|---|");

    // Two rigs differing ONLY in whether the single stale record carries a
    // linked intent. Any difference is therefore the linked branch's cost and
    // nothing else.
    let run = |linked: bool| -> u64 {
        let (pic, _v, upgrader) = ring_rig_upgrader_test_wasm();
        pic.update_call(
            upgrader,
            m1,
            "set_nonterminal_caps_for_test",
            candid::encode_one(&Some(stsh_custody_types::NonterminalCaps {
                global: 8,
                per_signer: 8,
            }))
            .unwrap(),
        )
        .expect("caps injection");

        if linked {
            // A Pending TriggerVaultUpgrade proposal writes its durable intent
            // at propose time — the linked pair the rotation must terminalize
            // together.
            let wasm = vec![7u8; ARTIFACT];
            let arg = vec![0u8; 8];
            let raw = pic
                .update_call(
                    upgrader,
                    m1,
                    "propose_recovery",
                    candid::encode_args((
                        RecoveryAction::TriggerVaultUpgrade {
                            expected_wasm_hash: sha256(&wasm),
                            expected_arg_hash: sha256(&arg),
                            wasm_bytes: wasm,
                            arg_bytes: arg,
                        },
                        None::<u64>,
                    ))
                    .unwrap(),
                )
                .expect("propose_recovery call");
            candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
                .unwrap()
                .expect("trigger proposal admitted");
        }

        let propose_rotation = |sender: Principal, tag: u8| -> u64 {
            let raw = pic
                .update_call(
                    upgrader,
                    sender,
                    "propose_membership_rotation",
                    candid::encode_args((vec![m2, m3, p(tag)], None::<u64>)).unwrap(),
                )
                .unwrap();
            candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
                .unwrap()
                .expect("rotation proposal commits")
        };
        let commit_of = |reader: Principal, id: u64| -> Vec<u8> {
            let r = pic
                .query_call(
                    upgrader,
                    reader,
                    "get_rotation_proposal",
                    candid::encode_one(&id).unwrap(),
                )
                .expect("rotation proposal query");
            candid::decode_one::<Option<RotationProposalView>>(static_bytes(r))
                .expect("decodes")
                .expect("proposal exists")
                .commitment_hash
        };

        let rot = propose_rotation(m1, 60);
        pic.update_call(
            upgrader,
            m1,
            "approve_recovery",
            candid::encode_args((rot, commit_of(m1, rot))).unwrap(),
        )
        .expect("first approval");
        pic.update_call(
            upgrader,
            m2,
            "approve_recovery",
            candid::encode_args((rot, commit_of(m1, rot))).unwrap(),
        )
        .expect("quorum-reaching message");

        let r = pic
            .query_call(
                upgrader,
                m2,
                "last_approve_instructions_for_test",
                candid::encode_args(()).unwrap(),
            )
            .expect("instruction readback");
        candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
    };

    let bare = run(false);
    let with_linked = run(true);
    println!("| rotation, no stale records | {bare} |");
    println!("| rotation + 1 LINKED trigger proposal ({ARTIFACT} B artifact) | {with_linked} |");

    let c_stale_linked = with_linked.saturating_sub(bare);
    println!("\n**c_stale_linked = {c_stale_linked} instructions** (one linked record)");
    println!(
        "Enters §B's gate ADDITIVELY EXACTLY ONCE and is never multiplied by N — \
         single-flight permits one nonterminal intent globally (spec §B.1), so a \
         rotation facing N linked records is a state the system cannot enter."
    );
    println!(
        "MEASURED AT PROVED P_max ({ARTIFACT} B, bracketed with an adjacent observed \
         refusal). The linked branch CLEARS artifact bytes, so this figure scales \
         with payload; at 64 KiB it measured 9_980_760, understating the envelope \
         ~15x. That understatement is what SSA Blocker 2 returned."
    );

    // ── §B ENVELOPE RE-ASSERTED AGAINST THE RULED 0.10 FRACTION ─────────────
    //
    // 0.10 x I_msg = 4.0e9 SUPERSEDES the M1 spec V2's 0.20. Both the fraction
    // and c_stale_linked moved, in opposite directions, so the verdict is
    // recomputed from measured terms rather than rescaled from the old one.
    //
    // c_stale_unlinked is measured by the companion curve test
    // (s5a_m1_gate_b_w3_rotation_instruction_curve), which establishes it as
    // flat within ~6% over a 24x range; the slope is re-derived here from a
    // two-point run so this verdict carries no quoted constant.
    let two_unlinked = {
        let (pic, _v, upgrader) = ring_rig_upgrader_test_wasm();
        pic.update_call(
            upgrader,
            m1,
            "set_nonterminal_caps_for_test",
            candid::encode_one(&Some(stsh_custody_types::NonterminalCaps { global: 8, per_signer: 8 }))
                .unwrap(),
        )
        .expect("caps injection");
        let propose_rotation = |sender: Principal, tag: u8| -> u64 {
            let raw = pic
                .update_call(
                    upgrader,
                    sender,
                    "propose_membership_rotation",
                    candid::encode_args((vec![m2, m3, p(tag)], None::<u64>)).unwrap(),
                )
                .unwrap();
            candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
                .unwrap()
                .expect("commits")
        };
        let commit_of = |reader: Principal, id: u64| -> Vec<u8> {
            let r = pic
                .query_call(upgrader, reader, "get_rotation_proposal", candid::encode_one(&id).unwrap())
                .expect("query");
            candid::decode_one::<Option<RotationProposalView>>(static_bytes(r))
                .expect("decodes")
                .expect("exists")
                .commitment_hash
        };
        for i in 0..2u8 {
            propose_rotation(m1, 30 + i);
        }
        let rot = propose_rotation(m1, 60);
        pic.update_call(upgrader, m1, "approve_recovery", candid::encode_args((rot, commit_of(m1, rot))).unwrap())
            .expect("first approval");
        pic.update_call(upgrader, m2, "approve_recovery", candid::encode_args((rot, commit_of(m1, rot))).unwrap())
            .expect("quorum-reaching message");
        let r = pic
            .query_call(upgrader, m2, "last_approve_instructions_for_test", candid::encode_args(()).unwrap())
            .expect("readback");
        candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
    };
    let c_stale_unlinked = two_unlinked.saturating_sub(bare) / 2;

    const C12: u64 = 320;
    const RULED_ROTATION_BUDGET: u64 = 4_000_000_000; // 0.10 x I_msg (40e9)
    let n = C12 - 1;
    let linked_branch = bare + c_stale_linked + (n - 1) * c_stale_unlinked;
    let unlinked_branch = bare + n * c_stale_unlinked;
    let envelope = linked_branch.max(unlinked_branch);

    println!("\n=== §B ENVELOPE at C12={C12}, RULED fraction 0.10 x I_msg = {RULED_ROTATION_BUDGET} ===");
    println!("| term | instructions |");
    println!("|---|---|");
    println!("| rotation_fixed | {bare} |");
    println!("| c_stale_unlinked (2-point slope) | {c_stale_unlinked} |");
    println!("| c_stale_linked @ P_max | {c_stale_linked} |");
    println!("| linked branch: fixed + linked + (N-1) x unlinked | {linked_branch} |");
    println!("| unlinked branch: fixed + N x unlinked | {unlinked_branch} |");
    println!("| **max (the gate)** | **{envelope}** |");
    println!(
        "\n**{:.1}% of the ruled 0.10 budget** — {}",
        envelope as f64 * 100.0 / RULED_ROTATION_BUDGET as f64,
        if envelope <= RULED_ROTATION_BUDGET { "WITHIN budget" } else { "EXCEEDS budget" }
    );
    println!(
        "Reported as arithmetic. Whether it PASSES is the table's adjudication at \
         V13, not the builder's — but the figure is now taken at P_max and against \
         the ruled fraction, which is what SSA Blocker 2 required.\n"
    );

    assert!(
        c_stale_linked > 0,
        "the linked branch must cost more than no stale record at all — a zero \
         difference would mean the trigger proposal was never in the stale set"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// S5A — M1 GATE C: INLINE COMMITMENT VALIDATION AT C12 OCCUPANCY (spec §C)
// ═════════════════════════════════════════════════════════════════════════════

/// `commitment_validation_worst` and `admission_path_total`, Vault-origin path.
///
/// Gate C is the measurement S5B EXISTED to unblock: before the inline
/// validation was built there was nothing here to measure. V11 §2 moved
/// commitment validation from a `post_upgrade`-only check to an inline
/// precondition on every absence-dependent operation, so this is hot-path cost
/// on the authorization path, and §C gives it its own budget (0.05 × I_msg)
/// separate from the admission total (0.20 × I_msg) precisely so a bounded
/// registry walk cannot become an authorization-path DoS hidden inside an
/// admission figure that passes overall.
///
/// "AT C12 OCCUPANCY" IS THE LOAD-BEARING HALF. A validation cost measured
/// against an empty registry would report comfortably inside budget while
/// saying nothing whatever about the state the budget exists to bound — so the
/// occupancy is driven up with real nonterminal proposals and read back from
/// the canister, not assumed.
#[test]
fn s5a_m1_gate_c_validation_and_admission_at_occupancy_vault_plane() {
    let (pic, vault) = rig_test_wasm();
    suspend_entry_rate_for_measurement(&pic, vault);
    raise_byte_quotas_for_measurement(&pic, vault);
    raise_per_signer_cap_for_measurement(&pic, vault);
    raise_byte_quotas_for_measurement(&pic, vault);

    let occupancy = |&()| -> u64 {
        let r = pic
            .update_call(
                vault,
                p(S1),
                "companion_occupancy_for_test",
                candid::encode_args(()).unwrap(),
            )
            .expect("occupancy readback");
        candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
    };
    let validation_cost = || -> u64 {
        let r = pic
            .update_call(
                vault,
                p(S1),
                "measure_companion_validation_for_test",
                candid::encode_args(()).unwrap(),
            )
            .expect("validation measurement");
        candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
    };
    let last_propose = || -> u64 {
        let r = pic
            .query_call(
                vault,
                p(S1),
                "last_propose_instructions_for_test",
                candid::encode_args(()).unwrap(),
            )
            .expect("propose instruction readback");
        candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
    };
    let propose_sized = |bytes: usize| {
        let wasm = vec![3u8; bytes];
        let arg = vec![0u8; 8];
        let raw = pic
            .update_call(
                vault,
                p(S1),
                "propose",
                candid::encode_args((
                    VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
                        expected_wasm_hash: sha256(&wasm),
                        expected_arg_hash: sha256(&arg),
                        wasm_bytes: wasm,
                        arg_bytes: arg,
                    }),
                    None::<u64>,
                ))
                .unwrap(),
            )
            .expect("propose call");
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw))
            .unwrap()
            .expect("proposal admitted");
    };

    println!("\n=== S5A/M1 GATE C — VALIDATION COST vs OCCUPANCY (VAULT ORIGIN) ===");
    println!("| nonterminal occupancy | validation instructions |");
    println!("|---|---|");

    // Occupancy is raised in steps by admitting real nonterminal proposals.
    // OCCUPANCY 320 — the ruled C7/C12 point. SSA Blocker 2: the source comment
    // below already said "at C12 occupancy" while the run stopped at 32, so the
    // figure described a TENTH of the state its budget exists to bound.
    // Artifacts here are small on purpose: this axis is OCCUPANCY, and the
    // admission measurement supplies the payload axis at proved P_max.
    let mut rows: Vec<(u64, u64)> = Vec::new();
    for step in [0usize, 32] {
        while (occupancy(&()) as usize) < step {
            propose_sized(1_024);
        }
        let occ = occupancy(&());
        let cost = validation_cost();
        println!("| {occ} | {cost} |");
        rows.push((occ, cost));
    }

    // ORDERING IS LOAD-BEARING AS OF S6 — the admission measurement comes
    // BEFORE the occupancy-320 row, and reaching 320 is what it does.
    //
    // This harness used to walk to 320 and THEN measure an admission on top.
    // With C7 ruled at 320 that admission is REFUSED — the cap is full — and
    // the measurement cannot be taken at all.
    //
    // Filling to 319 and measuring the 320th admission is not a workaround for
    // that refusal; it is the figure §C actually wants. The most expensive
    // admission the system can PERFORM is the one into the fullest state it can
    // legally hold. Measuring an admission into an already-full 320 would be
    // measuring a path policy forbids — the same "state the system cannot
    // enter" error the recovery gate-A fixture note rejects for C11, and it
    // would over-constrain the admission budget on a fiction.
    //
    // The admission therefore lands the canister exactly at occupancy 320, and
    // the validation row below is taken there. Both §C figures end up at the
    // ruled occupancy, and the admission one is legal.
    while (occupancy(&()) as usize) < 319 {
        propose_sized(1_024);
    }
    propose_sized(P_MAX_VAULT);
    let admission_total = last_propose();
    let occ_at_admission = occupancy(&());

    let cost = validation_cost();
    println!("| {occ_at_admission} | {cost} |");
    rows.push((occ_at_admission, cost));

    let (occ0, cost0) = rows[0];
    let (occ_n, cost_n) = *rows.last().unwrap();

    println!("\n**commitment_validation_worst = {cost_n} instructions** at occupancy {occ_n}");
    println!("(vs {cost0} at occupancy {occ0} — the walk IS bounded by occupancy)");
    println!(
        "**admission_path_total = {admission_total} instructions** — complete \
         admission path at P_max ({P_MAX_VAULT} B) AND occupancy {occ_at_admission}"
    );

    const RULED_VALIDATION_BUDGET: u64 = 2_000_000_000; // 0.05 x I_msg
    const RULED_ADMISSION_BUDGET: u64 = 8_000_000_000; // 0.20 x I_msg
    println!("\n=== §C INEQUALITIES, VAULT ORIGIN, at RULED fractions ===");
    println!("| inequality | measured | budget | % |");
    println!("|---|---|---|---|");
    println!(
        "| commitment_validation_worst <= 0.05 x I_msg | {cost_n} | {RULED_VALIDATION_BUDGET} | {:.3}% |",
        cost_n as f64 * 100.0 / RULED_VALIDATION_BUDGET as f64
    );
    println!(
        "| admission_path_total <= 0.20 x I_msg | {admission_total} | {RULED_ADMISSION_BUDGET} | {:.1}% |",
        admission_total as f64 * 100.0 / RULED_ADMISSION_BUDGET as f64
    );
    println!(
        "\nReported as arithmetic; the verdict is the table's at V13. Both figures \
         are now taken at the ruled occupancy AND the proved maximum payload.\n"
    );

    assert_eq!(occ_n, 320, "the validation figure must be taken AT occupancy 320");
    assert_eq!(
        occ_at_admission, 320,
        "the admission figure must be the one that fills the ruled cap — the \
         most expensive admission the system can legally perform"
    );
    assert!(cost_n > cost0, "validation cost must rise with occupancy");
    assert!(admission_total > 0, "the admission figure must be real");

}

// ═════════════════════════════════════════════════════════════════════════════
// S5A — M1 GATE A, RECOVERY PLANE (spec §A, "both canisters")
// ═════════════════════════════════════════════════════════════════════════════

/// The recovery plane's half of the C9 suspension — see
/// `suspend_entry_rate_for_measurement` for the full reasoning, including why
/// this injects a permissive VALUE rather than `None` (injecting `None` falls
/// through to the ruled constant; the injector can override a bound but cannot
/// express the absence of one).
///
/// Both planes suspend identically and deliberately. Suspending C9 on the Vault
/// while leaving it in force here would take the two sets of §A/§C figures under
/// different regimes and then compare them, which is precisely the
/// substitute-reading-stronger-than-it-is failure this campaign keeps catching.
fn suspend_recovery_entry_rate_for_measurement(
    pic: &PocketIc,
    upgrader: Principal,
    member: Principal,
) {
    pic.update_call(
        upgrader,
        member,
        "set_entry_rate_params_for_test",
        candid::encode_one(&Some(stsh_custody_types::EntryRateParams {
            window_ns: u64::MAX,
            global_per_window: u32::MAX,
            per_signer_per_window: u32::MAX,
        }))
        .unwrap(),
    )
    .expect("entry-rate injection is callable on the upgrader testing build");
}

/// `c_fixed_worst` / `c_record_worst` for the RECOVERY sweep.
///
/// §A requires both canisters. Closing that hold.
///
/// THE FIXTURE SHAPE IS FORCED, and the reason is §B.1's correction recurring
/// on a gate that does not state it. `RecoveryAction` has exactly two variants.
/// `TriggerVaultUpgrade` creates an upgrade intent, and single-flight permits at
/// most ONE nonterminal intent across both origin namespaces — so a multi-record
/// recovery sweep is necessarily built from `ReconcileVaultUpgrade` records plus
/// AT MOST ONE trigger. A multi-record fixture of trigger proposals would not
/// merely be unrealistic; it is a state the system cannot enter, and measuring
/// it would over-constrain C11 on a fiction. That is exactly the error V1 of the
/// measurement spec made at §B.1 for the rotation gate, and §A does not
/// currently correct for it on the sweep gate.
///
/// So the two costs are reported separately, the same two-cost shape §B.1
/// mandates for rotation. Referred to the table as a recommended §A amendment.
#[test]
fn s5a_m1_gate_a_measure_sweep_cost_recovery_plane() {
    let (pic, _vault, upgrader) = ring_rig_upgrader_test_wasm();
    let m1 = p(11);
    suspend_recovery_entry_rate_for_measurement(&pic, upgrader, m1);

    pic.update_call(
        upgrader,
        m1,
        "set_lifetime_params_for_test",
        candid::encode_args((
            Some(stsh_custody_types::ProposalLifetimeBounds {
                min_ns: 1_000,
                max_ns: 1_000_000_000,
            }),
            Option::<u32>::None,
        ))
        .unwrap(),
    )
    .expect("bounds injection is callable on the testing build");

    // A recovery proposal that creates NO intent — the only shape a
    // multi-record fixture can use (see the doc comment).
    let propose_reconcile = |tag: u64| {
        let raw = pic
            .update_call(
                upgrader,
                m1,
                "propose_recovery",
                candid::encode_args((
                    RecoveryAction::ReconcileVaultUpgrade {
                        proposal_id: tag,
                        objective_evidence: UpgradeObjectiveEvidence {
                            observed_upgrader_principal: upgrader,
                            observed_module_hash: Some(sha256(b"observed")),
                            observed_controllers: vec![upgrader],
                            observed_canister_status: ObservedCanisterStatus::Running,
                            observed_at_ns: 1_000,
                        },
                    },
                    Some(2_000u64),
                ))
                .unwrap(),
            )
            .expect("propose_recovery call");
        candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
            .unwrap()
            .expect("reconcile proposal admitted");
    };

    let measure = |limit: u32| -> (u64, u32) {
        let r = pic
            .update_call(
                upgrader,
                m1,
                "measure_sweep_instructions_for_test",
                candid::encode_args((u64::MAX, limit)).unwrap(),
            )
            .expect("sweep measurement call");
        candid::decode_args::<(u64, u32)>(static_bytes(r)).unwrap()
    };

    println!("\n=== S5A/M1 GATE A — SWEEP COST, RECOVERY PLANE ===");
    println!("(ReconcileVaultUpgrade records — the only multi-record shape reachable)");
    println!("| due records | instructions | reaped | marginal/record |");
    println!("|---|---|---|---|");

    let mut baseline = 0u64;
    let mut rows: Vec<(u32, u64)> = Vec::new();
    let mut next_tag = 1u64;
    for (idx, n) in [0u32, 2, 4, 8, 16].into_iter().enumerate() {
        for _ in 0..n {
            propose_reconcile(next_tag);
            next_tag += 1;
        }
        let (instr, reaped) = measure(1_000);
        assert_eq!(
            reaped, n,
            "the recovery sweep reaped {reaped} of {n} seeded due records — a \
             fixture that under-delivers would deflate every per-record figure"
        );
        if idx == 0 {
            baseline = instr;
        }
        let marginal = if n > 0 {
            format!("{}", instr.saturating_sub(baseline) / n as u64)
        } else {
            "— (this row IS c_fixed_worst)".to_string()
        };
        println!("| {n} | {instr} | {reaped} | {marginal} |");
        rows.push((n, instr));
    }

    let c_fixed = baseline;
    let (max_n, max_instr) = *rows.last().unwrap();
    let c_record = max_instr.saturating_sub(c_fixed) / max_n as u64;

    println!("\n**c_fixed_worst (recovery) = {c_fixed} instructions**");
    println!("**c_record_worst (recovery, unlinked shape) = {c_record} instructions/record**");
    println!(
        "\nAT MOST ONE due record can be an artifact-bearing TriggerVaultUpgrade \
         (single-flight, one nonterminal intent globally). §A asks for one \
         c_record_worst at 'worst shape (artifact-bearing)'; on this plane that \
         shape is capped at ONE record, so the two costs are reported separately \
         — the same correction §B.1 already makes for rotation."
    );
    println!(
        "FIXTURE, NOT THRESHOLD: bounds and occupancies are fixture points chosen \
         to make the path measurable, not proposed constants.\n"
    );

    assert!(
        c_record > 0,
        "measured a per-record cost of ZERO on the recovery plane — the fixture \
         produced no due records and every figure would be a measurement of nothing"
    );
    assert!(c_fixed > 0, "an empty recovery sweep must still cost something");
}

/// M1 gate C — RECOVERY-ORIGIN validation and admission (spec §C).
///
/// §C's budgets apply to BOTH origin paths INDEPENDENTLY. Measuring the Vault
/// and asserting the recovery plane is "similar" would be exactly the
/// substitute-reading-stronger-than-it-is failure this campaign keeps catching,
/// and the two planes do not share an implementation — different companion
/// layout, different indexes, different record shapes.
#[test]
fn s5a_m1_gate_c_validation_and_admission_recovery_origin() {
    let (pic, _vault, upgrader) = ring_rig_upgrader_test_wasm();
    let m1 = p(11);
    suspend_recovery_entry_rate_for_measurement(&pic, upgrader, m1);
    // C12 caps a member at 32; this walk needs 319 from one member. Global
    // stays at the ruled 320 — that is the number under test.
    pic.update_call(
        upgrader,
        m1,
        "set_nonterminal_caps_for_test",
        candid::encode_one(&Some(stsh_custody_types::NonterminalCaps {
            global: 320,
            per_signer: u32::MAX,
        }))
        .unwrap(),
    )
    .expect("caps injection is callable on the upgrader testing build");

    let validation_cost = || -> u64 {
        let r = pic
            .update_call(
                upgrader,
                m1,
                "measure_companion_validation_for_test",
                candid::encode_args(()).unwrap(),
            )
            .expect("validation measurement");
        candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
    };
    let last_propose = || -> u64 {
        let r = pic
            .query_call(
                upgrader,
                m1,
                "last_propose_instructions_for_test",
                candid::encode_args(()).unwrap(),
            )
            .expect("propose instruction readback");
        candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
    };
    // Non-intent shape, so occupancy can be DRIVEN past one: single-flight caps
    // nonterminal INTENTS at one globally, so a fixture built from trigger
    // proposals cannot reach occupancy at all.
    let propose_reconcile = |tag: u64| {
        let raw = pic
            .update_call(
                upgrader,
                m1,
                "propose_recovery",
                candid::encode_args((
                    RecoveryAction::ReconcileVaultUpgrade {
                        proposal_id: tag,
                        objective_evidence: UpgradeObjectiveEvidence {
                            observed_upgrader_principal: upgrader,
                            observed_module_hash: Some(sha256(b"observed")),
                            observed_controllers: vec![upgrader],
                            observed_canister_status: ObservedCanisterStatus::Running,
                            observed_at_ns: 1_000,
                        },
                    },
                    None::<u64>,
                ))
                .unwrap(),
            )
            .expect("propose_recovery call");
        candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
            .unwrap()
            .expect("reconcile proposal admitted");
    };

    println!("\n=== S5A/M1 GATE C — RECOVERY ORIGIN, AT OCCUPANCY ===");
    println!("| nonterminal occupancy | validation instructions |");
    println!("|---|---|");
    let empty = validation_cost();
    println!("| 0 | {empty} |");

    // DRIVEN occupancy, not empty (SSA Blocker 2: the prior figure was taken on
    // a fresh companion, which says nothing about the state §C's budget bounds).
    //
    // S6 — STOPS AT 319, AND THE P_MAX TRIGGER BELOW IS THE 320th. Two ruled
    // constants bind here that did not exist when this loop was written:
    // C12 caps a MEMBER at 32 nonterminal proposals (raised for the
    // measurement, see the Vault's counterpart for why occupancy 320 is a
    // ruled ceiling rather than a reachable state), and the GLOBAL 320 is left
    // in force because it is the number under test. Filling all 320 here would
    // leave the admission measurement below with no slot, and admitting into an
    // already-full cap is a path policy forbids — measuring it would
    // over-constrain the admission budget on a state the system cannot enter.
    for tag in 1..=319u64 {
        propose_reconcile(tag);
    }

    // ADMISSION at proved recovery P_max, ON THE LOADED CANISTER — not a fresh
    // canister per payload, which was the prior defect: it measured admission
    // into an empty companion every time.
    let wasm = vec![5u8; P_MAX_RECOVERY];
    let arg = vec![0u8; 8];
    let raw = pic
        .update_call(
            upgrader,
            m1,
            "propose_recovery",
            candid::encode_args((
                RecoveryAction::TriggerVaultUpgrade {
                    expected_wasm_hash: sha256(&wasm),
                    expected_arg_hash: sha256(&arg),
                    wasm_bytes: wasm,
                    arg_bytes: arg,
                },
                None::<u64>,
            ))
            .unwrap(),
        )
        .expect("propose_recovery at P_max");
    candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
        .unwrap()
        .expect("P_max trigger admitted on the loaded canister");
    let admission_total = last_propose();

    // The admission above filled the ruled cap; the validation figure §C wants
    // is taken HERE, at 320, on the state that admission produced.
    let loaded = validation_cost();
    println!("| 320 | {loaded} |");

    const RULED_VALIDATION_BUDGET: u64 = 2_000_000_000; // 0.05 x I_msg
    const RULED_ADMISSION_BUDGET: u64 = 8_000_000_000; // 0.20 x I_msg
    println!("\n=== §C INEQUALITIES, RECOVERY ORIGIN, at RULED fractions ===");
    println!("| inequality | measured | budget | % |");
    println!("|---|---|---|---|");
    println!(
        "| commitment_validation_worst <= 0.05 x I_msg (occupancy 320) | {loaded} | {RULED_VALIDATION_BUDGET} | {:.3}% |",
        loaded as f64 * 100.0 / RULED_VALIDATION_BUDGET as f64
    );
    println!(
        "| admission_path_total <= 0.20 x I_msg (P_max {P_MAX_RECOVERY} B, at occupancy) | {admission_total} | {RULED_ADMISSION_BUDGET} | {:.1}% |",
        admission_total as f64 * 100.0 / RULED_ADMISSION_BUDGET as f64
    );
    println!(
        "\n§C applies to both origin paths INDEPENDENTLY; these are the recovery \
         plane's own figures, measured at the ruled occupancy and its own proved \
         P_max. Verdict is the table's at V13.\n"
    );

    assert!(loaded > empty, "validation cost must rise with driven occupancy");
    assert!(admission_total > 0, "the admission figure must be real");

}

// ═════════════════════════════════════════════════════════════════════════════
// S5A CORRECTIVE — BLOCKER 1: BRACKET P_max ON BOTH PLANES
// ═════════════════════════════════════════════════════════════════════════════

/// PROVED P_max, both planes — the largest ADMITTED artifact, each with an
/// adjacent observed REFUSAL (`s5a_c1_bracket_p_max_*`, 1,024 B resolution).
///
/// THE VAULT IS THE BINDING PLANE. Its envelope overhead is ~4,104 B (the
/// artifact is wrapped in `VaultActionKind::UpgraderUpgrade` with its hashes)
/// against ~72 B on the recovery plane, so the Vault admits ~4,096 B LESS.
/// Reading the recovery figure across would err 4 KB in the unsafe direction on
/// the plane where admission is already the largest instruction consumer.
///
/// Both bracket tests ASSERT these constants against what they measure, so a
/// bound change cannot leave a stale number here — the figure and its evidence
/// cannot drift apart.
const P_MAX_VAULT: usize = 1_895_424;
const P_MAX_RECOVERY: usize = 1_899_520;

/// Bracket the admission boundary: largest ADMITTED, smallest REFUSED, adjacent.
///
/// WHY THE PRIOR FIGURE WAS NOT A MAXIMUM, stated plainly because the error is
/// instructive. The earlier tests tried a fixed list of sizes and reported the
/// LAST one that was admitted. Every size on that list was admitted, so no
/// refusal was ever observed — the figure was "the largest size I happened to
/// try", which is indistinguishable from a maximum when you only look at the
/// output. A maximum requires the refusal next to it.
///
/// Both planes are bracketed INDEPENDENTLY rather than one being read across.
/// They have different request shapes and different ceilings
/// (`VAULT_UPGRADE_VIA_UPGRADER_REQ_CEILING_BYTES` vs the recovery path's), so
/// assuming a shared boundary is the same substitution error §C's "both origin
/// paths independently" exists to forbid.
#[test]
fn s5a_c1_bracket_p_max_vault_plane() {
    let (pic, vault) = rig_test_wasm();
    // S6 corrective: C6/C8 are enforced now, and this harness admits MANY large
    // artifacts to one signer. Cumulative retention would hit C6 partway
    // through and the probe would report the point where the QUOTA bound,
    // not the point the measurement is looking for — a silent measurement
    // artifact, which is exactly how P_max appeared to "move" to 1 MiB.
    raise_byte_quotas_for_measurement(&pic, vault);

    let admits = |bytes: usize| -> bool {
        let wasm = vec![3u8; bytes];
        let arg = vec![0u8; 8];
        // PocketIC's client PANICS (rather than returning Err) when the ingress
        // message itself exceeds the platform limit, so the probe is caught.
        // That layer is a REFUSAL too — it is simply enforced by the platform
        // rather than by the canister — and conflating the two would misreport
        // WHICH bound establishes P_max.
        let args = candid::encode_args((
            VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
                expected_wasm_hash: sha256(&wasm),
                expected_arg_hash: sha256(&arg),
                wasm_bytes: wasm,
                arg_bytes: arg,
            }),
            None::<u64>,
        ))
        .unwrap();
        // The default panic hook would print a scary backtrace for a probe we
        // deliberately expect to fail, which in a measurement transcript reads
        // like a broken test rather than a recorded refusal.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pic.update_call(vault, p(S1), "propose", args)
        }));
        std::panic::set_hook(prev);
        let Ok(r) = caught else {
            println!("  {bytes:>9} B → REJECTED at INGRESS (platform message limit)");
            return false;
        };
        match r {
            Ok(raw) => match candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw)) {
                Ok(Ok(_)) => true,
                Ok(Err(e)) => {
                    println!("  {bytes:>9} B → REFUSED by the vault: {e:?}");
                    false
                }
                Err(e) => {
                    println!("  {bytes:>9} B → undecodable reply: {e}");
                    false
                }
            },
            Err(e) => {
                println!("  {bytes:>9} B → REJECTED at ingress: {:?}", e.reject_code);
                false
            }
        }
    };

    // Establish the bracket: a known-admitted floor and a refused ceiling.
    let mut lo = 512 * 1024usize;
    assert!(admits(lo), "control: a small artifact must be admitted");
    let mut hi = 0usize;
    let mut probe = 1_024 * 1024usize;
    for _ in 0..8 {
        if admits(probe) {
            lo = probe;
            probe = probe.saturating_mul(2);
        } else {
            hi = probe;
            break;
        }
    }
    assert!(
        hi > 0,
        "no size was refused up to {lo} B — the admission boundary was never \
         reached, so no maximum has been established (this is exactly the defect \
         in the superseded figure)"
    );

    // Narrow to adjacency. 1 KiB resolution is far below any plausible policy
    // step and keeps the run bounded.
    const RESOLUTION: usize = 1_024;
    while hi - lo > RESOLUTION {
        let mid = lo + (hi - lo) / 2;
        if admits(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }

    println!("\n=== S5A/C1 — P_max BRACKET, VAULT PLANE ===");
    println!("| bound | bytes |");
    println!("|---|---|");
    println!("| largest ADMITTED | **{lo}** |");
    println!("| smallest REFUSED | {hi} |");
    println!(
        "\n**P_max (vault) is bracketed in [{lo}, {hi})** — resolution {} B.",
        hi - lo
    );
    assert_eq!(
        lo, P_MAX_VAULT,
        "the proved Vault P_max has MOVED. Every figure measured at P_MAX_VAULT is \
         now taken at the wrong point — update the constant and RERUN gates A/B/C, \
         do not simply re-pin it."
    );
    println!(
        "Both bounds OBSERVED: the refusal is what makes the admitted figure a \
         MAXIMUM rather than the largest size that happened to be tried.\n"
    );

    assert!(lo > 0 && hi > lo, "the boundary must be a real interval");
}

/// The same bracket on the RECOVERY plane, measured independently.
#[test]
fn s5a_c1_bracket_p_max_recovery_plane() {
    let m1 = p(11);

    // Each attempt needs a fresh canister: a Pending TriggerVaultUpgrade holds
    // the single-flight lock, so a second admitted proposal would be refused
    // for a reason unrelated to size — which would look exactly like the
    // boundary and would silently halve the reported P_max.
    let admits = |bytes: usize| -> bool {
        let (pic, _v, upgrader) = ring_rig_upgrader_test_wasm();
        let wasm = vec![5u8; bytes];
        let arg = vec![0u8; 8];
        let args = candid::encode_args((
            RecoveryAction::TriggerVaultUpgrade {
                expected_wasm_hash: sha256(&wasm),
                expected_arg_hash: sha256(&arg),
                wasm_bytes: wasm,
                arg_bytes: arg,
            },
            None::<u64>,
        ))
        .unwrap();
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pic.update_call(upgrader, m1, "propose_recovery", args)
        }));
        std::panic::set_hook(prev);
        let Ok(r) = caught else {
            println!("  {bytes:>9} B → REJECTED at INGRESS (platform message limit)");
            return false;
        };
        match r {
            Ok(raw) => match candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw)) {
                Ok(Ok(_)) => true,
                Ok(Err(e)) => {
                    println!("  {bytes:>9} B → REFUSED by the upgrader: {e:?}");
                    false
                }
                Err(e) => {
                    println!("  {bytes:>9} B → undecodable reply: {e}");
                    false
                }
            },
            Err(e) => {
                println!("  {bytes:>9} B → REJECTED at ingress: {:?}", e.reject_code);
                false
            }
        }
    };
    let mut lo = 512 * 1024usize;
    assert!(admits(lo), "control: a small artifact must be admitted");
    let mut hi = 0usize;
    let mut probe = 1_024 * 1024usize;
    for _ in 0..8 {
        if admits(probe) {
            lo = probe;
            probe = probe.saturating_mul(2);
        } else {
            hi = probe;
            break;
        }
    }
    assert!(hi > 0, "no size refused up to {lo} B — boundary never reached");

    const RESOLUTION: usize = 1_024;
    while hi - lo > RESOLUTION {
        let mid = lo + (hi - lo) / 2;
        if admits(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }

    println!("\n=== S5A/C1 — P_max BRACKET, RECOVERY PLANE ===");
    println!("| bound | bytes |");
    println!("|---|---|");
    println!("| largest ADMITTED | **{lo}** |");
    println!("| smallest REFUSED | {hi} |");
    println!(
        "\n**P_max (recovery) is bracketed in [{lo}, {hi})** — resolution {} B. \
         Measured on this plane independently; V13 chooses the binding plane or \
         keeps both.\n",
        hi - lo
    );
    assert_eq!(
        lo, P_MAX_RECOVERY,
        "the proved recovery P_max has MOVED — see the Vault note; rerun, do not re-pin."
    );

    assert!(lo > 0 && hi > lo, "the boundary must be a real interval");
}

// ═════════════════════════════════════════════════════════════════════════════
// S5A CORRECTIVE — BLOCKER 3: ALLOCATION OVERHEAD FOR C6/C8
// ═════════════════════════════════════════════════════════════════════════════

/// Maximum allocated footprint over a SATURATING search of reachable mixtures.
///
/// SUPERSEDES two narrower searches. The first drove one greedy mixture. The
/// second swept every full-`P_max` count but forced every remaining record to
/// the MINIMUM size — so it explored boundary counts without saturating the byte
/// cap at those counts, leaving 1,697,280 logical bytes unused at its own
/// reported maximum. SSA's counterexample binds BOTH caps exactly:
///
///     10 x 1,895,432 + 309 x 1,032 + 1 x 1,698,312 = 20,971,520, occupancy 320
///
/// It has the same maximum count and strictly more retained payload, and could
/// therefore cross the next 8 MiB allocation bucket.
///
/// THE SEARCHED DOMAIN, stated precisely because the result is only a maximum
/// OVER IT: for every feasible count k of full-`P_max` artifacts, the remaining
/// count is filled and the residual byte budget distributed two ways —
/// CONCENTRATED into a single record, and DISTRIBUTED evenly across the
/// remainder. Allocation depends on B-tree shape and not merely on totals, so
/// the same saturated total is probed in two different shapes.
///
/// THIS IS NOT CLAIMED AS A GLOBAL MAXIMUM. The space of mixtures is far larger
/// than the searched domain, and no conservative allocator bound is available to
/// close the gap. The figure is reported as the maximum over the domain below.
///
/// ── RUN OBLIGATION (CTO ruling, corrective-2 V2 checkpoint) ────────────────
///
/// `#[ignore]` because the full sweep costs ~390s, which is disproportionate on
/// every gate run. It is NOT optional. It MUST run and pass at:
///   (a) every constants-gate submission;
///   (b) S6 close;
///   (c) the campaign holistic pass;
///   (d) ANY change to C6, C8, P_max, or a stable record shape.
///
/// Trigger (d) is the load-bearing one: the sweep re-runs when the thing it
/// measures can move, not on a calendar. The obligation is a checked item on the
/// S6 gate list, not a convention.
///
/// The gate is NOT blind in the meantime:
/// `s5a_c3_allocation_sentinel_saturated_max_mixture` runs permanently and pins
/// the known-maximal, byte-saturating state. An ignored sweep alone would be a
/// test nobody runs; an unskippable sentinel plus an ignored sweep is a
/// different risk profile.
///
/// Run explicitly:
///   cargo test -p vault --test pic_tests s5a_c3_max_allocated -- --ignored --nocapture
#[test]
#[ignore = "full 24-mixture sweep, ~390s — see RUN OBLIGATION above; sentinel runs in-gate"]
fn s5a_c3_max_allocated_footprint_saturating_search() {
    const C7_COUNT_CAP: u64 = 320;
    const C8_LOGICAL_CAP: u64 = 20_971_520;
    const PAGE: u64 = 64 * 1024;
    const ARG: u64 = 8;
    const MIN_WASM: u64 = 1_024;
    const MIN_COST: u64 = MIN_WASM + ARG; // 1_032, the canonical domain per record
    let p_max_cost: u64 = P_MAX_VAULT as u64 + ARG; // 1_895_432

    // Drive an explicit list of wasm sizes; returns (occupancy, logical, allocated).
    let drive = |sizes: &[u64]| -> (u64, u64, u64) {
        let (pic, vault) = rig_test_wasm();
        // C9 and C5 are live as of S6; this search drives to the C7 cap from
        // one signer. See the helpers for why occupancy 320 is a ruled ceiling
        // rather than a state admission can reach.
        suspend_entry_rate_for_measurement(&pic, vault);
        raise_byte_quotas_for_measurement(&pic, vault);
        raise_per_signer_cap_for_measurement(&pic, vault);
    raise_byte_quotas_for_measurement(&pic, vault);
        raise_byte_quotas_for_measurement(&pic, vault);
        let logical_total = || -> u64 {
            let r = pic
                .update_call(vault, p(S1), "c8_logical_total_for_test", candid::encode_args(()).unwrap())
                .expect("C8 logical total");
            candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
        };
        let occupancy = || -> u64 {
            let r = pic
                .update_call(vault, p(S1), "companion_occupancy_for_test", candid::encode_args(()).unwrap())
                .expect("occupancy");
            candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
        };
        let pages = || -> u64 {
            let r = pic
                .update_call(vault, p(S1), "stable_pages_for_test", candid::encode_args(()).unwrap())
                .expect("pages");
            candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
        };
        let base = pages();
        for &sz in sizes {
            let wasm = vec![3u8; sz as usize];
            let arg = vec![0u8; ARG as usize];
            let raw = pic
                .update_call(
                    vault,
                    p(S1),
                    "propose",
                    candid::encode_args((
                        VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
                            expected_wasm_hash: sha256(&wasm),
                            expected_arg_hash: sha256(&arg),
                            wasm_bytes: wasm,
                            arg_bytes: arg,
                        }),
                        None::<u64>,
                    ))
                    .unwrap(),
                )
                .expect("propose call");
            candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw))
                .unwrap()
                .expect("admitted");
        }
        let occ = occupancy();
        let logical = logical_total();
        let allocated = (pages() - base) * PAGE;
        assert!(logical <= C8_LOGICAL_CAP, "fixture breached the ruled C8 it measures under");
        assert!(occ <= C7_COUNT_CAP, "fixture breached the ruled count cap");
        (occ, logical, allocated)
    };

    println!("\n=== S5A/C2 — SATURATING SEARCH FOR MAX ALLOCATED FOOTPRINT ===");
    println!("RULED: C7 {C7_COUNT_CAP}, C8 {C8_LOGICAL_CAP} B. Canonical domain = wasm + arg.");
    println!("| k x P_max | residual shape | records | occupancy | logical B | ALLOCATED B |");
    println!("|---|---|---|---|---|---|");

    // (label, sizes, occ, logical, allocated)
    let mut rows: Vec<(String, u64, u64, u64)> = Vec::new();
    let mut counterexample_seen = false;

    for k in 0..=11u64 {
        let large_cost = k * p_max_cost;
        if large_cost > C8_LOGICAL_CAP {
            println!("| {k} | — | — | — | — | INFEASIBLE (artifacts alone breach C8) |");
            break;
        }
        // Fill the remaining COUNT with minimal records, shrinking if the byte
        // cap forbids the full remainder.
        let mut remaining = C7_COUNT_CAP.saturating_sub(k);
        while large_cost + remaining * MIN_COST > C8_LOGICAL_CAP {
            remaining -= 1;
        }
        let residual = C8_LOGICAL_CAP - large_cost - remaining * MIN_COST;

        for shape in ["concentrated", "distributed"] {
            if remaining == 0 && residual > 0 {
                continue;
            }
            let mut sizes: Vec<u64> = vec![P_MAX_VAULT as u64; k as usize];
            if shape == "concentrated" {
                // One record absorbs the whole residual, capped at P_max.
                let extra = residual.min(p_max_cost - MIN_COST);
                for i in 0..remaining {
                    sizes.push(if i == 0 { MIN_WASM + extra } else { MIN_WASM });
                }
            } else {
                // Residual spread evenly; the first records take the remainder
                // so the cap is saturated rather than approached.
                let per = residual / remaining.max(1);
                let rem = residual % remaining.max(1);
                for i in 0..remaining {
                    let mut sz = MIN_WASM + per.min(p_max_cost - MIN_COST);
                    if i < rem {
                        sz += 1;
                    }
                    sizes.push(sz);
                }
            }
            let (occ, logical, allocated) = drive(&sizes);
            let label = format!("{k} x P_max / {shape}");
            println!(
                "| {k} | {shape} | {} | {occ} | {logical} | {allocated} |",
                sizes.len()
            );
            // SSA's mandatory fixture: k=10 concentrated saturates C8 exactly at
            // occupancy 320.
            if k == 10 && shape == "concentrated" && logical == C8_LOGICAL_CAP && occ == C7_COUNT_CAP
            {
                counterexample_seen = true;
            }
            rows.push((label, occ, logical, allocated));
        }
    }

    let best = rows
        .iter()
        .max_by_key(|(_, _, _, allocated)| *allocated)
        .expect("at least one mixture");
    let max_alloc = best.3;
    let argmax: Vec<&(String, u64, u64, u64)> =
        rows.iter().filter(|(_, _, _, a)| *a == max_alloc).collect();

    println!("\n**MAXIMUM ALLOCATED FOOTPRINT OVER THE SEARCHED DOMAIN:**");
    println!("| measure | value |");
    println!("|---|---|");
    println!("| **ALLOCATED** | **{max_alloc} B ({:.2} MiB)** |", max_alloc as f64 / 1_048_576.0);
    println!("| attained by | {} of {} mixtures |", argmax.len(), rows.len());
    for (label, occ, logical, _) in &argmax {
        println!("| — {label} | occupancy {occ}, logical {logical} B |");
    }

    println!(
        "\nNOT CLAIMED AS A GLOBAL MAXIMUM. The searched domain is: every feasible \n\
         count of full-P_max artifacts, remaining count filled, residual budget \n\
         distributed CONCENTRATED and DISTRIBUTED. The space of admissible mixtures \n\
         is larger, and no conservative allocator bound is available to close the \n\
         gap — so this is the maximum OVER THAT DOMAIN and is reported as such."
    );
    println!(
        "\nSSA MANDATORY FIXTURE (10 x P_max + 309 minimal + 1 x 1,698,312, C8 \n\
         saturated exactly at occupancy 320): {}",
        if counterexample_seen { "PRESENT and measured" } else { "ABSENT — see assertion" }
    );

    assert!(
        counterexample_seen,
        "the mandatory counterexample must be DRIVEN: k=10 concentrated must \
         saturate C8 exactly ({C8_LOGICAL_CAP} B) at occupancy {C7_COUNT_CAP}. If \
         it is not reached, the search again fails to cover the state SSA used to \
         disprove the previous maximum."
    );
    assert!(max_alloc > 0, "allocation must be observable");
    assert!(rows.len() >= 4, "the search must cover multiple counts and both shapes");
}

/// M1 §A — `linked_at_recovery_Pmax`: the ONE artifact-bearing record a recovery
/// sweep can face, measured (SSA corrective-2 Blocker 3).
///
/// The §A two-cost structure was NARRATED on this plane and never measured: the
/// packet said "at most one due record can be an artifact-bearing
/// TriggerVaultUpgrade" and then reported only the unlinked cost. Single-flight
/// makes the claim true, but a cost that is never measured is not a figure —
/// and it is the LARGEST single term in the recovery sweep's envelope.
///
/// REQUIRED FIX 1: the recovery plane's figures use the RECOVERY bracket
/// (P_MAX_RECOVERY = 1,899,520), not the Vault's. The two brackets differ by
/// ~4 KB and each binds its own plane.
#[test]
fn s5a_c2_linked_at_recovery_pmax_sweep_cost() {
    let m1 = p(11);

    // Two runs differing ONLY in whether the swept set contains the single
    // permitted linked trigger record, so the delta is that record's reap cost
    // and nothing else.
    let run = |with_linked: bool, unlinked: u32| -> (u64, u32) {
        let (pic, _v, upgrader) = ring_rig_upgrader_test_wasm();
        pic.update_call(
            upgrader,
            m1,
            "set_lifetime_params_for_test",
            candid::encode_args((
                Some(stsh_custody_types::ProposalLifetimeBounds {
                    min_ns: 1_000,
                    max_ns: 1_000_000_000,
                }),
                Option::<u32>::None,
            ))
            .unwrap(),
        )
        .expect("bounds injection");

        if with_linked {
            let wasm = vec![5u8; P_MAX_RECOVERY];
            let arg = vec![0u8; 8];
            let raw = pic
                .update_call(
                    upgrader,
                    m1,
                    "propose_recovery",
                    candid::encode_args((
                        RecoveryAction::TriggerVaultUpgrade {
                            expected_wasm_hash: sha256(&wasm),
                            expected_arg_hash: sha256(&arg),
                            wasm_bytes: wasm,
                            arg_bytes: arg,
                        },
                        Some(2_000u64),
                    ))
                    .unwrap(),
                )
                .expect("propose trigger at recovery P_max");
            candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
                .unwrap()
                .expect("trigger admitted");
        }
        for tag in 1..=unlinked as u64 {
            let raw = pic
                .update_call(
                    upgrader,
                    m1,
                    "propose_recovery",
                    candid::encode_args((
                        RecoveryAction::ReconcileVaultUpgrade {
                            proposal_id: tag,
                            objective_evidence: UpgradeObjectiveEvidence {
                                observed_upgrader_principal: upgrader,
                                observed_module_hash: Some(sha256(b"observed")),
                                observed_controllers: vec![upgrader],
                                observed_canister_status: ObservedCanisterStatus::Running,
                                observed_at_ns: 1_000,
                            },
                        },
                        Some(2_000u64),
                    ))
                    .unwrap(),
                )
                .expect("propose reconcile");
            candid::decode_one::<Result<u64, RecoveryError>>(static_bytes(raw))
                .unwrap()
                .expect("reconcile admitted");
        }
        let r = pic
            .update_call(
                upgrader,
                m1,
                "measure_sweep_instructions_for_test",
                candid::encode_args((u64::MAX, 10_000u32)).unwrap(),
            )
            .expect("sweep measurement");
        candid::decode_args::<(u64, u32)>(static_bytes(r)).unwrap()
    };

    let (fixed, reaped0) = run(false, 0);
    assert_eq!(reaped0, 0, "the empty-sweep control must reap nothing");
    let (unlinked_2, reaped2) = run(false, 2);
    assert_eq!(reaped2, 2, "the unlinked fixture must deliver its records");
    let (with_linked, reaped_l) = run(true, 2);
    assert_eq!(
        reaped_l, 3,
        "the linked fixture must reap the trigger record TOO — if it reaps only \
         the unlinked ones the delta below is not the linked record's cost"
    );

    let unlinked = (unlinked_2.saturating_sub(fixed)) / 2;
    let linked_at_recovery_pmax = with_linked.saturating_sub(unlinked_2);

    println!("\n=== S5A/C2 — RECOVERY SWEEP, LINKED RECORD AT RECOVERY P_max ===");
    println!("| fixture | instructions | reaped |");
    println!("|---|---|---|");
    println!("| empty sweep (c_fixed_worst) | {fixed} | 0 |");
    println!("| 2 unlinked | {unlinked_2} | 2 |");
    println!("| 2 unlinked + 1 LINKED @ {P_MAX_RECOVERY} B | {with_linked} | 3 |");
    println!("\n**c_fixed_worst = {fixed}**");
    println!("**unlinked = {unlinked} / record**");
    println!("**linked_at_recovery_Pmax = {linked_at_recovery_pmax}**");

    // ── THE RULED GATE ──────────────────────────────────────────────────────
    const C11R: u64 = 2_048;
    const SWEEP_BUDGET: u64 = 10_000_000_000; // 0.25 x I_msg (40e9)
    let envelope = fixed + linked_at_recovery_pmax + (C11R - 1) * unlinked;
    println!(
        "\n=== RULED GATE: fixed + linked_at_recovery_Pmax + (C11r-1) x unlinked <= 0.25 x I_msg ==="
    );
    println!("| term | value |");
    println!("|---|---|");
    println!("| C11r | {C11R} |");
    println!("| fixed | {fixed} |");
    println!("| linked_at_recovery_Pmax | {linked_at_recovery_pmax} |");
    println!("| (C11r-1) x unlinked | {} |", (C11R - 1) * unlinked);
    println!("| **envelope** | **{envelope}** |");
    println!("| budget (0.25 x 40e9) | {SWEEP_BUDGET} |");
    println!(
        "| **result** | **{:.1}% — {}** |",
        envelope as f64 * 100.0 / SWEEP_BUDGET as f64,
        if envelope <= SWEEP_BUDGET { "WITHIN budget" } else { "EXCEEDS budget" }
    );
    if envelope > SWEEP_BUDGET {
        let headroom = SWEEP_BUDGET.saturating_sub(fixed + linked_at_recovery_pmax);
        println!(
            "\nCEILING REPORTED, per the dispatch: the largest C11r this envelope \
             admits is {} — C11r falls at V14, never batching or structure.",
            headroom / unlinked.max(1) + 1
        );
    }
    println!(
        "\nFIXTURE vs RULED: the linked record is at the PROVED recovery P_max \
         bracket (Required Fix 1 — recovery figures use the recovery bracket, not \
         the Vault's 1,895,424). C11r = {C11R} and the 0.25 fraction are RULED \
         inputs, not builder selections. Verdict is the table's at V14.\n"
    );

    assert!(
        linked_at_recovery_pmax > unlinked,
        "the linked branch must cost MORE than an unlinked record — it additionally \
         terminalizes the intent and clears its artifact bytes"
    );
}

/// Required Fix 2 — admission cost across BOTH observed tree shapes, gated on
/// the MAX.
///
/// WHY THIS EXISTS. Two runs of the "same" measurement disagreed by ~2.4%:
/// 1,017,644,142 with 320 small records in `PROPOSALS`, and 1,041,975,435 with
/// ~5 multi-megabyte records — the LARGER figure coming from the run with FEWER
/// records and a SMALLER payload. `StableBTreeMap` insertion cost depends on the
/// tree being inserted into, so accumulated record SHAPE is a cost axis that
/// none of §C's stated axes (payload, occupancy) captures.
///
/// A measurement that picks one shape is picking a number. Both observed shapes
/// are therefore driven here and the MAX is reported, so the figure a budget
/// gates on cannot depend on which fixture happened to run.
#[test]
fn s5a_c2_admission_across_both_tree_shapes_gate_on_max() {
    // Shape 1: MANY SMALL records — the count-heavy tree.
    let many_small = {
        let (pic, vault) = rig_test_wasm();
        // C9 is live as of S6; this harness seeds past it from one signer.
        suspend_entry_rate_for_measurement(&pic, vault);
        raise_byte_quotas_for_measurement(&pic, vault);
        raise_per_signer_cap_for_measurement(&pic, vault);
    raise_byte_quotas_for_measurement(&pic, vault);
        raise_byte_quotas_for_measurement(&pic, vault);
        let propose_sized = |bytes: usize| {
            let wasm = vec![3u8; bytes];
            let arg = vec![0u8; 8];
            let raw = pic
                .update_call(
                    vault,
                    p(S1),
                    "propose",
                    candid::encode_args((
                        VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
                            expected_wasm_hash: sha256(&wasm),
                            expected_arg_hash: sha256(&arg),
                            wasm_bytes: wasm,
                            arg_bytes: arg,
                        }),
                        None::<u64>,
                    ))
                    .unwrap(),
                )
                .expect("propose call");
            candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw))
                .unwrap()
                .expect("admitted");
        };
        // 319, NOT 320 — the P_max admission below is the 320th and fills the
        // ruled C7 cap. Seeding all 320 first would leave it no slot, and
        // admitting into a full cap is a path policy forbids: the measured
        // figure would over-constrain the admission budget on a state the
        // system cannot enter.
        for _ in 0..319 {
            propose_sized(1_024);
        }
        propose_sized(P_MAX_VAULT);
        let r = pic
            .query_call(
                vault,
                p(S1),
                "last_propose_instructions_for_test",
                candid::encode_args(()).unwrap(),
            )
            .expect("readback");
        candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
    };

    // Shape 2: FEW LARGE records — the byte-heavy tree that produced the higher
    // figure. Sizes kept inside the ruled C8 logical cap so the shape is
    // reachable.
    let few_large = {
        let (pic, vault) = rig_test_wasm();
        // C9 is live as of S6; this harness seeds past it from one signer.
        suspend_entry_rate_for_measurement(&pic, vault);
        raise_byte_quotas_for_measurement(&pic, vault);
        raise_per_signer_cap_for_measurement(&pic, vault);
    raise_byte_quotas_for_measurement(&pic, vault);
        raise_byte_quotas_for_measurement(&pic, vault);
        let propose_sized = |bytes: usize| {
            let wasm = vec![3u8; bytes];
            let arg = vec![0u8; 8];
            let raw = pic
                .update_call(
                    vault,
                    p(S1),
                    "propose",
                    candid::encode_args((
                        VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
                            expected_wasm_hash: sha256(&wasm),
                            expected_arg_hash: sha256(&arg),
                            wasm_bytes: wasm,
                            arg_bytes: arg,
                        }),
                        None::<u64>,
                    ))
                    .unwrap(),
                )
                .expect("propose call");
            candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw))
                .unwrap()
                .expect("admitted");
        };
        for bytes in [512 * 1024, 1_024 * 1024, 1_536 * 1024, 1_792 * 1024] {
            propose_sized(bytes);
        }
        propose_sized(P_MAX_VAULT);
        let r = pic
            .query_call(
                vault,
                p(S1),
                "last_propose_instructions_for_test",
                candid::encode_args(()).unwrap(),
            )
            .expect("readback");
        candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
    };

    const RULED_ADMISSION_BUDGET: u64 = 8_000_000_000; // 0.20 x I_msg
    let max = many_small.max(few_large);

    println!("\n=== S5A/C2 — ADMISSION AT P_max ACROSS BOTH TREE SHAPES ===");
    println!("| tree shape | admission_path_total | % of 0.20 budget |");
    println!("|---|---|---|");
    println!(
        "| MANY SMALL (319 x 1 KiB + P_max = cap, count-heavy) | {many_small} | {:.1}% |",
        many_small as f64 * 100.0 / RULED_ADMISSION_BUDGET as f64
    );
    println!(
        "| FEW LARGE (4 multi-MiB, byte-heavy) | {few_large} | {:.1}% |",
        few_large as f64 * 100.0 / RULED_ADMISSION_BUDGET as f64
    );
    println!(
        "| **MAX — the figure to gate on** | **{max}** | **{:.1}%** |",
        max as f64 * 100.0 / RULED_ADMISSION_BUDGET as f64
    );
    println!(
        "\nSpread between shapes: {} instructions ({:.2}%). Accumulated record \n\
         SHAPE is a cost axis §C does not name; gating on the max removes the \n\
         dependence on which fixture ran rather than explaining it away.\n\
         COST-AT-DEPTH WATCH: if this spread grows, the tree-shape dependence is \n\
         widening and the §C figure needs re-derivation, not a re-run.\n",
        many_small.abs_diff(few_large),
        many_small.abs_diff(few_large) as f64 * 100.0 / max as f64
    );

    assert!(many_small > 0 && few_large > 0, "both shapes must be measured");
}

/// IN-GATE SENTINEL — the known-maximal, byte-saturating mixture, permanently.
///
/// CTO ruling (corrective-2 V2 checkpoint): the full 24-mixture sweep is
/// `#[ignore]` with hard triggers, but ONE mixture stays in the gate forever so
/// allocation never goes unwatched. This is SSA's mandatory counterexample —
/// `k = 10` full `P_max` artifacts, residual CONCENTRATED, C8 saturated
/// EXACTLY, occupancy at the count cap — which the sweep found to be one of the
/// five mixtures attaining the maximum.
///
/// It asserts the allocated footprint does not EXCEED the figure S6 gates on.
/// A regression that pushed this state into the next 8 MiB bucket would fail
/// here on the next gate run rather than at the next constants submission.
///
/// One mixture, ~16s: cheap enough to pay on every run forever.
#[test]
fn s5a_c3_allocation_sentinel_saturated_max_mixture() {
    const C7_COUNT_CAP: u64 = 320;
    const C8_LOGICAL_CAP: u64 = 20_971_520;
    const PAGE: u64 = 64 * 1024;
    const ARG: u64 = 8;
    const MIN_WASM: u64 = 1_024;
    const MIN_COST: u64 = MIN_WASM + ARG;
    /// The maximum allocated footprint over the searched domain
    /// (`s5a_c3_max_allocated_footprint_saturating_search`). S6's
    /// allocated-footprint assertion gates on this figure, domain-stated.
    ///
    /// SUPERSEDED AT S6: 75,497,472 → 83,886,080 B (72.00 → 80.00 MiB), per
    /// `CTO_RULING_S6_ALLOCATION_AND_C10_2026-08-10.md` (sha256 b406336a…) §1,
    /// which supersedes V15 §3's allocation reference BY REFERENCE (V15 itself
    /// is not edited; all its other content stands). Carried to SSA at
    /// landed-diff as a NAMED superseding item vs SSA-accepted V15 §3.
    ///
    /// WHY IT MOVED, mechanism not inference — this is the attribution the
    /// ruling required before any number was allowed to change:
    /// `BUCKET_SIZE_IN_PAGES = 128` (ic-stable-structures 0.6.9) is 8 MiB
    /// exactly, and the delta is EXACTLY ONE BUCKET. `PROPOSAL_EXPIRY_INDEX` is
    /// `MemoryId(6)`, its own region, and it had allocated ZERO buckets pre-S6
    /// because the index was necessarily empty — no proposal could carry an
    /// expiry while C3/C4 were `None`. Installing C3/C4 makes every proposal
    /// carry one and the region claims its first bucket. The 75,497,472 figure
    /// was measured in a state S6 ends; it is not wrong, it is obsolete.
    ///
    /// STILL DOMAIN-SCOPED, never an allocator-global maximum: same searched
    /// domain as before (24 mixtures, both concentration shapes, SSA's
    /// mandatory C8-saturated fixture present and measured), re-run in full
    /// rather than adjusted by the delta.
    ///
    /// The "do not raise this constant to match" instruction below stands and
    /// is not weakened by this edit — it is why this value arrived through a
    /// ruling and a re-run sweep instead of through a builder's arithmetic.
    const MAX_ALLOCATED: u64 = 83_886_080;

    let p_max_cost: u64 = P_MAX_VAULT as u64 + ARG;
    let (pic, vault) = rig_test_wasm();
    // C9 is live as of S6; this harness seeds past it from one signer.
    suspend_entry_rate_for_measurement(&pic, vault);
    raise_byte_quotas_for_measurement(&pic, vault);
    raise_per_signer_cap_for_measurement(&pic, vault);
    raise_byte_quotas_for_measurement(&pic, vault);

    let read_u64 = |method: &str| -> u64 {
        let r = pic
            .update_call(vault, p(S1), method, candid::encode_args(()).unwrap())
            .expect("readback");
        candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
    };
    let propose_sized = |bytes: u64| {
        let wasm = vec![3u8; bytes as usize];
        let arg = vec![0u8; ARG as usize];
        let raw = pic
            .update_call(
                vault,
                p(S1),
                "propose",
                candid::encode_args((
                    VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
                        expected_wasm_hash: sha256(&wasm),
                        expected_arg_hash: sha256(&arg),
                        wasm_bytes: wasm,
                        arg_bytes: arg,
                    }),
                    None::<u64>,
                ))
                .unwrap(),
            )
            .expect("propose call");
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw))
            .unwrap()
            .expect("admitted");
    };

    let base_pages = read_u64("stable_pages_for_test");
    const K: u64 = 10;
    let remaining = C7_COUNT_CAP - K;
    let residual = C8_LOGICAL_CAP - K * p_max_cost - remaining * MIN_COST;
    for _ in 0..K {
        propose_sized(P_MAX_VAULT as u64);
    }
    for i in 0..remaining {
        propose_sized(if i == 0 { MIN_WASM + residual } else { MIN_WASM });
    }

    let occ = read_u64("companion_occupancy_for_test");
    let logical = read_u64("c8_logical_total_for_test");
    let allocated = (read_u64("stable_pages_for_test") - base_pages) * PAGE;

    println!("\n=== S5A — IN-GATE ALLOCATION SENTINEL (SSA mandatory mixture) ===");
    println!("| measure | value |");
    println!("|---|---|");
    println!("| mixture | {K} x P_max + {} minimal + 1 residual-absorbing |", remaining - 1);
    println!("| occupancy | {occ} (cap {C7_COUNT_CAP}) |");
    println!("| logical (canonical C8 domain) | {logical} B (cap {C8_LOGICAL_CAP}) |");
    println!("| ALLOCATED | {allocated} B ({:.2} MiB) |", allocated as f64 / 1_048_576.0);
    println!("| gate | <= {MAX_ALLOCATED} B |\n");

    // The fixture must actually be the state it claims to pin, or the assertion
    // below guards nothing.
    assert_eq!(
        logical, C8_LOGICAL_CAP,
        "sentinel must SATURATE C8 exactly — a mixture that leaves budget unused \
         is not the state this sentinel exists to pin"
    );
    assert_eq!(
        occ, C7_COUNT_CAP,
        "sentinel must sit AT the count cap as well — both caps bound simultaneously"
    );
    assert!(
        allocated <= MAX_ALLOCATED,
        "ALLOCATION REGRESSION: the byte-saturating maximal mixture now allocates \
         {allocated} B, above the {MAX_ALLOCATED} B the S6 footprint assertion \
         gates on. Re-run the full sweep \
         (`--ignored s5a_c3_max_allocated`) and re-derive — do not raise this \
         constant to match."
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// S6 CORRECTIVE 2, FINDING 1 — §C ADMISSION COST AT THE WORST **REACHABLE**
// SIGNER-ACCOUNTING CARDINALITY
// ═════════════════════════════════════════════════════════════════════════════
//
// WHY THE EXISTING §C FIGURE DOES NOT COVER THIS. That harness drives occupancy
// to 320 from ONE signer, so `retained_by_signer` holds a SINGLE entry. The C6
// limb scans that vector linearly on every admission, so a one-entry scan
// measures the cheapest possible case while reporting "at occupancy 320". The
// occupancy axis and the ACCOUNTING-CARDINALITY axis are different axes, and
// only the first was ever measured.
//
// THE BOUND, DERIVED — not chosen (dispatch: if it needs an unruled constant,
// stop and report; it does not):
//   * an entry exists only while a proposer holds > 0 retained bytes;
//   * retained bytes come only from concurrently-NONTERMINAL artifact-bearing
//     proposals;
//   * that population is capped by C7 = 320, a RULED V15 value;
//   => distinct proposers with a live entry <= 320.
//
// The cardinality is built LEGALLY, by real governed rotations, mirroring the
// C8 reachability construction rather than falling back to a hook: two anchor
// signers approve each rotation while seven slots cycle through fresh
// principals, each of whom makes one small artifact-bearing proposal. C9 is
// suspended as a measurement convenience (this axis is cost, not rate); no hook
// touches the accounting itself.
#[test]
fn s6c_gate_c_admission_cost_at_worst_signer_cardinality() {
    let (pic, vault) = rig_test_wasm();
    suspend_entry_rate_for_measurement(&pic, vault);

    let anchor_a = p(S1);
    let anchor_b = p(S2);
    let fresh = |i: u32| -> Principal {
        let mut b = [0u8; 29];
        b[0..4].copy_from_slice(&i.to_be_bytes());
        b[4] = 0xF0;
        Principal::from_slice(&b)
    };

    let propose_rotation = |roster: &Vec<Principal>| {
        let raw = pic
            .update_call(
                vault,
                anchor_a,
                "propose",
                candid::encode_one(&VaultActionKind::UpdateSignerSet {
                    signers: roster.clone(),
                    threshold: 2,
                })
                .unwrap(),
            )
            .expect("rotation propose");
        let id = candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw))
            .unwrap()
            .expect("rotation admitted");
        // Quorum-reaching approve EXECUTES inline over ingress, so the roster
        // changes here rather than at some later step. (Quorum alone marks
        // Executing — a test asserting rotation at quorum asserts nothing.)
        let commitment = get_proposal(&pic, vault, anchor_a, id)
            .expect("rotation readable")
            .commitment_hash;
        for who in [anchor_a, anchor_b] {
            approve_with_hash(&pic, vault, who, id, commitment.clone())
                .expect("rotation approve");
        }
    };

    let propose_small = |who: Principal| -> Result<u64, VaultError> {
        let wasm = vec![0x5Au8; 1_024];
        let arg = vec![0u8; 8];
        let raw = pic
            .update_call(
                vault,
                who,
                "propose",
                candid::encode_one(&VaultActionKind::UpgraderUpgrade(UpgraderUpgrade {
                    expected_wasm_hash: sha256(&wasm),
                    expected_arg_hash: sha256(&arg),
                    wasm_bytes: wasm,
                    arg_bytes: arg,
                }))
                .unwrap(),
            )
            .expect("propose call");
        candid::decode_one::<Result<u64, VaultError>>(static_bytes(raw)).unwrap()
    };

    // Build 319 distinct proposers holding retained bytes, seven per rotation.
    // 319 and not 320: the MEASURED admission is the 320th, so it must have a
    // slot — admitting into a full C7 is a path policy forbids, and measuring
    // it would report a cost the system can never pay.
    const TARGET: u32 = 319;
    let mut made = 0u32;
    let mut batch = 0u32;
    while made < TARGET {
        let take = 7.min(TARGET - made);
        let members: Vec<Principal> = (0..take).map(|k| fresh(made + k)).collect();
        let mut roster = vec![anchor_a, anchor_b];
        roster.extend(members.iter().copied());
        propose_rotation(&roster);
        for m in &members {
            propose_small(*m).expect("fresh signer admitted");
        }
        made += take;
        batch += 1;
    }
    println!("\n=== S6C §C — ADMISSION AT WORST SIGNER CARDINALITY ===");
    println!("built {made} distinct proposers over {batch} governed rotations");

    // The measured admission: a fresh signer, so the scan is at its widest and
    // the admission itself is legal (the 320th).
    let last = fresh(TARGET);
    propose_rotation(&vec![anchor_a, anchor_b, last]);
    propose_small(last).expect("the 320th admission is legal");

    let cost = {
        let r = pic
            .query_call(
                vault,
                anchor_a,
                "last_propose_instructions_for_test",
                candid::encode_args(()).unwrap(),
            )
            .expect("readback");
        candid::decode_one::<u64>(static_bytes(r)).expect("decodes")
    };

    const RULED_ADMISSION_BUDGET: u64 = 8_000_000_000; // 0.20 x I_msg
    println!("| quantity | value |");
    println!("|---|---|");
    println!("| signer-accounting cardinality | {} |", TARGET + 1);
    println!("| admission_path_total | {cost} |");
    println!(
        "| vs 0.20 x I_msg budget | {:.2}% |",
        cost as f64 * 100.0 / RULED_ADMISSION_BUDGET as f64
    );
    println!(
        "\nCARDINALITY, not occupancy: the existing §C figure was taken with ONE \n\
         accounting entry. This is the same admission path with the C6 scan at \n\
         its ruled maximum of C7 = 320 entries.\n"
    );

    assert!(cost > 0, "the admission figure must be real");
    assert!(
        cost <= RULED_ADMISSION_BUDGET,
        "§C VIOLATED at the worst reachable signer cardinality: admission cost \
         {cost} exceeds the ruled 0.20 x I_msg budget of {RULED_ADMISSION_BUDGET}. \
         This is a finding for the table, not something to smooth away."
    );
}

// =============================================================================
// §S7 START SETTLEMENT — ACCEPTANCE 17 and 18, ON THE REAL RING
//
// These two items are the ones V5 §10 requires to be **DEMONSTRATED, NOT
// ASSERTED** (CUST-SSA-004's own wording for item 17). They therefore run
// against genuinely stopped canisters in PocketIC on the real two-canister
// ring, not against a fake backend:
//
//   17. Cell 4 (Upgrader -> Vault) against a REAL stopped canister.
//   18. Cell 3 (Vault -> Upgrader) regression — the Vault still starts a
//       genuinely stopped Upgrader, UNDER THIS CONTRACT.
// =============================================================================

/// Drive a recovery-plane action to quorum on the Upgrader, exactly as a real
/// 2-of-3 recovery member would: propose, then BOTH members approve explicitly
/// with the commitment hash read from the signer-gated proposal view.
fn recovery_quorum(
    pic: &PocketIc,
    upgrader: Principal,
    action: RecoveryAction,
) -> (u64, Result<(), RecoveryError>) {
    let raw = pic
        .update_call(
            upgrader,
            p(11),
            "propose_recovery",
            candid::encode_one(&action).unwrap(),
        )
        .unwrap();
    let rid = candid::decode_one::<Result<u64, RecoveryError>>(&raw)
        .unwrap()
        .expect("recovery proposal");
    let mut last = Ok(());
    for m in [p(11), p(12)] {
        let raw = pic
            .query_call(
                upgrader,
                m,
                "get_recovery_proposal",
                candid::encode_one(&rid).unwrap(),
            )
            .unwrap();
        let hash = candid::decode_one::<Option<stsh_custody_types::RecoveryProposal>>(&raw)
            .unwrap()
            .expect("member may read the proposal")
            .commitment_hash;
        let raw = pic
            .update_call(
                upgrader,
                m,
                "approve_recovery",
                candid::encode_args((rid, hash)).unwrap(),
            )
            .unwrap();
        last = candid::decode_one::<Result<(), RecoveryError>>(&raw).unwrap();
    }
    (rid, last)
}

fn recovery_proposal(
    pic: &PocketIc,
    upgrader: Principal,
    rid: u64,
) -> stsh_custody_types::RecoveryProposal {
    let raw = pic
        .query_call(
            upgrader,
            p(11),
            "get_recovery_proposal",
            candid::encode_one(&rid).unwrap(),
        )
        .unwrap();
    candid::decode_one::<Option<stsh_custody_types::RecoveryProposal>>(&raw)
        .unwrap()
        .expect("proposal readable")
}

/// **ACCEPTANCE 17 — cell 4 against a REAL STOPPED CANISTER.**
///
/// The Vault is genuinely stopped. The recovery quorum proposes `StartVault`,
/// which carries NO target parameter — the target is read from the Upgrader's
/// durable membership. The start lands, and the settlement is then driven from
/// OBJECTIVE `canister_status` EVIDENCE read off the real subnet, not from the
/// call's reply.
///
/// This is the stopped-recovery path CUST-SSA-004 exists for: with the Vault
/// stopped, the ring's only route back is the Upgrader's recovery quorum.
#[test]
fn pic_s7_acceptance_17_cell4_starts_a_really_stopped_vault() {
    let (pic, vault, upgrader) = ring_rig();

    // GENUINELY stopped — by its real controller, the Upgrader.
    pic.stop_canister(vault, Some(upgrader)).unwrap();
    let status = pic.canister_status(vault, Some(upgrader)).unwrap();
    assert_eq!(
        format!("{:?}", status.status),
        "Stopped".to_string(),
        "the Vault must really be stopped before cell 4 runs"
    );

    // Cell 4: the recovery quorum starts it. No target parameter exists.
    let (rid, res) = recovery_quorum(&pic, upgrader, RecoveryAction::StartVault);
    assert!(res.is_ok(), "the recovery quorum's start must be admitted: {res:?}");

    // DEMONSTRATED: the Vault is actually running again.
    let status = pic.canister_status(vault, Some(upgrader)).unwrap();
    assert_eq!(
        format!("{:?}", status.status),
        "Running".to_string(),
        "acceptance 17: cell 4 must start a REAL stopped canister"
    );

    // The proposal carries its §2 start-intent, bound to the Vault principal
    // read from durable membership.
    let proposal = recovery_proposal(&pic, upgrader, rid);
    let start = proposal.start.expect("§2: a durable start-intent exists");
    assert_eq!(start.intent.target, vault, "§1: the target came from durable membership");

    // The reply was observed, so §3a's success edge terminalized it directly
    // and — deliberately — wrote NO SettlementRecord (no §4 evidence existed).
    assert_eq!(proposal.outcome, ActionOutcome::Executed);
    assert!(
        start.settlement.is_none(),
        "a callback-terminalized start holds no SettlementRecord"
    );
}

/// **ACCEPTANCE 17, the settlement half** — the same cell-4 mechanism driven to
/// a settlement from OBJECTIVE EVIDENCE, which is the path R-2 actually rules
/// on: a start whose reply did not objectively establish success sits in
/// `OutcomeUnknown` until `canister_status` evidence settles it.
///
/// The evidence here is read from the REAL subnet — observed target, observed
/// status and the observed controller set — not fabricated.
#[test]
fn pic_s7_acceptance_17_cell4_settles_from_real_canister_status_evidence() {
    let (pic, vault, upgrader) = ring_rig();
    pic.stop_canister(vault, Some(upgrader)).unwrap();

    let (rid, _) = recovery_quorum(&pic, upgrader, RecoveryAction::StartVault);
    let proposal = recovery_proposal(&pic, upgrader, rid);
    let intent_at = proposal.start.expect("start state").intent.intent_at_ns;

    // Read REAL objective evidence about the Vault, from its controller.
    let status = pic.canister_status(vault, Some(upgrader)).unwrap();
    assert_eq!(
        status.settings.controllers,
        vec![upgrader],
        "§4.3: evidence is only about the ring while the controllers hold"
    );

    // A cell-4 reconcile against the now-terminal proposal is a §7f step-2
    // ILLEGAL SOURCE — it was settled by the observed reply, not by evidence,
    // so it holds no SettlementRecord (acceptance 7). This demonstrates the
    // gate ladder on the real ring rather than only in unit tests.
    let evidence = stsh_custody_types::StartObjectiveEvidence {
        observed_target_principal: vault,
        observed_canister_status: ObservedCanisterStatus::Running,
        observed_controllers: status.settings.controllers.clone(),
        observed_at_ns: pic.get_time().as_nanos_since_unix_epoch().max(intent_at),
    };
    let (_, res) = recovery_quorum(
        &pic,
        upgrader,
        RecoveryAction::ReconcileVaultStart {
            proposal_id: rid,
            objective_evidence: evidence,
        },
    );
    assert_eq!(
        res,
        Err(RecoveryError::IllegalSourceState),
        "§7f step 2: a proposal terminalized by its callback holds no \
         SettlementRecord and is an illegal reconcile source"
    );
}

/// **ACCEPTANCE 18 — cell 3 regression.** The Vault still starts a GENUINELY
/// STOPPED Upgrader, under this contract.
///
/// The regression matters because S7 changed this path: the ring start now
/// writes a §2 durable start-intent before the call and claims the mutating
/// single-flight lock, neither of which it did before. The behaviour that must
/// NOT have regressed is the plain one — the Upgrader actually starts.
#[test]
fn pic_s7_acceptance_18_cell3_still_starts_a_really_stopped_upgrader() {
    let (pic, vault, upgrader) = ring_rig();

    pic.stop_canister(upgrader, Some(vault)).unwrap();
    let status = pic.canister_status(upgrader, Some(vault)).unwrap();
    assert_eq!(
        format!("{:?}", status.status),
        "Stopped".to_string(),
        "the Upgrader must really be stopped before cell 3 runs"
    );

    // Cell 3: the Vault quorum starts its ring counterpart.
    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::Start { target: upgrader }),
    );
    approve(&pic, vault, p(S1), id).unwrap();
    approve(&pic, vault, p(S2), id).unwrap();

    // DEMONSTRATED: the Upgrader is actually running again.
    let status = pic.canister_status(upgrader, Some(vault)).unwrap();
    assert_eq!(
        format!("{:?}", status.status),
        "Running".to_string(),
        "acceptance 18: cell 3 must still start a REAL stopped Upgrader"
    );

    // And it did so UNDER THIS CONTRACT: the §2 start-intent is durable on the
    // proposal, bound to the ring counterpart.
    let view = get_proposal(&pic, vault, p(S1), id).expect("proposal readable");
    assert_eq!(
        view.outcome,
        ActionOutcome::Executed,
        "§3a: the observed success edge terminalized it"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// §S7 CORRECTIVE r1 — P1-2 (typed wire carriage) and P1-4 (real upgrades)
//
// Authority: CTO_ADJUDICATION_S7_RETURN_AND_CORRECTIVE_DISPATCH_2026-08-11.md
// (sha256 62393a04ee9c5387c9260135cfc7cbee682625646db07b89e7f176a2e864c8ad).
// ═════════════════════════════════════════════════════════════════════════════

/// A ring whose counterpart principal is NOT a live canister.
///
/// This is how a cell-3 start reaches `OutcomeUnknown` through PRODUCTION CODE
/// on a real subnet: management `start_canister` against a principal that is
/// not a canister genuinely rejects, so E1 fires exactly as it would against a
/// deleted or not-yet-created counterpart. Nothing is planted and no seam is
/// used — the alternative would be fabricating `OutcomeUnknown` by hand, which
/// proves nothing about the path that produces it.
fn ring_rig_absent_counterpart() -> (PocketIc, Principal, Principal) {
    let pic = PocketIc::new();
    let vault = pic.create_canister();
    pic.add_cycles(vault, 10_000_000_000_000u128);
    // Never created, so never a canister.
    let absent = Principal::from_slice(&[0xAB; 29]);
    let vinit = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
            upgrader: absent,
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(vault, vault_wasm(), candid::encode_one(&vinit).unwrap(), None);
    (pic, vault, absent)
}

fn start_evidence_for(
    target: Principal,
    vault: Principal,
    status: ObservedCanisterStatus,
    at: u64,
) -> stsh_custody_types::StartObjectiveEvidence {
    stsh_custody_types::StartObjectiveEvidence {
        observed_target_principal: target,
        observed_canister_status: status,
        observed_controllers: vec![vault],
        observed_at_ns: at,
    }
}

/// Drive a cell-3 start to `OutcomeUnknown` through production E1.
fn cell3_start_to_outcome_unknown(pic: &PocketIc, vault: Principal, target: Principal) -> u64 {
    let id = propose(
        pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::Start { target }),
    );
    approve(pic, vault, p(S1), id).unwrap();
    approve(pic, vault, p(S2), id).unwrap();
    let view = get_proposal(pic, vault, p(S1), id).expect("proposal");
    assert_eq!(
        view.outcome,
        ActionOutcome::OutcomeUnknown,
        "E1: a rejected start_canister routes to OutcomeUnknown, never Failed"
    );
    id
}

/// Submit a cell-3 reconcile and return the PUBLIC result of the
/// quorum-reaching `approve` — i.e. the Candid boundary response.
fn cell3_reconcile_public(
    pic: &PocketIc,
    vault: Principal,
    target_id: u64,
    evidence: stsh_custody_types::StartObjectiveEvidence,
) -> Result<ApprovalOutcome, VaultError> {
    let rid = propose(
        pic,
        vault,
        p(S1),
        VaultActionKind::ReconcileUpgraderStart(stsh_custody_types::ReconcileUpgraderStart {
            proposal_id: target_id,
            objective_evidence: evidence,
        }),
    );
    approve(pic, vault, p(S1), rid).unwrap();
    approve(pic, vault, p(S2), rid)
}

/// **P1-2 — `AlreadySettled { outcome }` IS A TYPED VALUE ON THE PUBLIC WIRE,
/// in all three replay branches.**
///
/// V5 §7c requires every replay in both directions to return that typed error
/// and never a success-shaped response. The landed code stringified it into
/// `ProposalRecord.result` and replied `Ok(PriorResult { .. })`, which left the
/// advertised DID variant dead and made the two planes observably asymmetric —
/// the recovery plane returning a typed error where the Vault returned debug
/// text inside a success. This asserts the CANDID BOUNDARY, not an internal
/// disposition enum.
#[test]
fn pic_s7_p1_2_vault_replay_returns_typed_already_settled_on_the_wire() {
    let (pic, vault, absent) = ring_rig_absent_counterpart();
    let target_id = cell3_start_to_outcome_unknown(&pic, vault, absent);
    let now = pic.get_time().as_nanos_since_unix_epoch();

    // Settle it Executed from a valid Running observation.
    let settle = cell3_reconcile_public(
        &pic,
        vault,
        target_id,
        start_evidence_for(absent, vault, ObservedCanisterStatus::Running, now),
    );
    assert!(settle.is_ok(), "a genuine settlement is Ok, not an error: {settle:?}");
    assert_eq!(
        get_proposal(&pic, vault, p(S1), target_id).unwrap().outcome,
        ActionOutcome::Executed
    );

    // ── The three replay branches, each at the PUBLIC boundary ──────────────
    for (label, status) in [
        ("concordant", ObservedCanisterStatus::Running),
        ("inconclusive", ObservedCanisterStatus::Stopping),
        ("discordant", ObservedCanisterStatus::Stopped),
    ] {
        let now = pic.get_time().as_nanos_since_unix_epoch();
        let got = cell3_reconcile_public(
            &pic,
            vault,
            target_id,
            start_evidence_for(absent, vault, status, now),
        );
        assert_eq!(
            got,
            Err(VaultError::AlreadySettled {
                outcome: ReconcileTerminalOutcome::Executed
            }),
            "{label} replay must return the TYPED error on the wire, carrying the \
             settled outcome in its payload — never a success-shaped response"
        );
        // NO RE-OPEN, whatever the replay carried.
        assert_eq!(
            get_proposal(&pic, vault, p(S1), target_id).unwrap().outcome,
            ActionOutcome::Executed,
            "{label} replay must not re-open a settled proposal"
        );
    }

    // MUTATION 1:1 — the assertion is discriminating, not "any Err". A
    // genuinely different failure class must NOT satisfy it: reconciling an
    // unknown proposal id is a different gate and does not produce
    // AlreadySettled.
    let now = pic.get_time().as_nanos_since_unix_epoch();
    let other = cell3_reconcile_public(
        &pic,
        vault,
        9_999_999,
        start_evidence_for(absent, vault, ObservedCanisterStatus::Running, now),
    );
    assert_ne!(
        other,
        Err(VaultError::AlreadySettled {
            outcome: ReconcileTerminalOutcome::Executed
        }),
        "MUTATION GUARD: a different rejection class must not masquerade as \
         AlreadySettled, else the assertions above would pass on any error"
    );
}

/// **P1-4 (cell 3) — REAL CROSS-WASM UPGRADE: E2 through the actual
/// `post_upgrade`, then record survival.**
///
/// A start is held at the await boundary by the production-faithful seam (the
/// real `approve_inner` + the real `record_start_intent`, with the management
/// call simply not issued). The Wasm is then genuinely replaced, so E2 runs
/// inside the real `post_upgrade` against real stable memory — not by calling
/// the sweep function directly, which establishes only the sweep body and
/// nothing about stable decoding or post-upgrade wiring.
#[test]
fn pic_s7_p1_4_cell3_e2_runs_through_a_real_upgrade_and_settles() {
    let pic = PocketIc::new();
    let vault = pic.create_canister();
    pic.add_cycles(vault, 10_000_000_000_000u128);
    let absent = Principal::from_slice(&[0xAB; 29]);
    let vinit = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
            upgrader: absent,
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(vault, vault_test_wasm(), candid::encode_one(&vinit).unwrap(), None);

    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::Start { target: absent }),
    );
    approve(&pic, vault, p(S1), id).unwrap();
    // Quorum boundary reached WITHOUT issuing the call: the durable writes are
    // exactly production's pre-await set.
    let hash = get_proposal(&pic, vault, p(S1), id).unwrap().commitment_hash;
    let raw = pic
        .update_call(
            vault,
            p(S2),
            "approve_start_without_issuing_call_for_test",
            candid::encode_args((id, hash)).unwrap(),
        )
        .expect("seam call");
    candid::decode_one::<Result<(), VaultError>>(static_bytes(raw))
        .unwrap()
        .expect("seam admitted");

    let held = get_proposal(&pic, vault, p(S1), id).expect("proposal");
    assert_eq!(
        held.outcome,
        ActionOutcome::Executing,
        "the start is held at the await boundary, durably Executing"
    );

    // ── THE REAL UPGRADE ────────────────────────────────────────────────────
    pic.upgrade_canister(vault, vault_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("vault upgrade");

    let swept = get_proposal(&pic, vault, p(S1), id).expect("proposal survives the upgrade");
    assert_eq!(
        swept.outcome,
        ActionOutcome::OutcomeUnknown,
        "acceptance 2 / E2: the intent SURVIVES the upgrade and the proposal is \
         promoted to OutcomeUnknown by the REAL post_upgrade — not Executing"
    );

    // MUTATION 1:1 — E2 is what moved it. Before the upgrade it was Executing
    // (asserted above), and no other path runs between the two reads.
    assert_ne!(
        held.outcome, swept.outcome,
        "MUTATION GUARD: removing the E2 call from post_upgrade leaves Executing \
         and this assertion fails"
    );

    // Settlement then proceeds, as acceptance 2 requires.
    let now = pic.get_time().as_nanos_since_unix_epoch();
    let settle = cell3_reconcile_public(
        &pic,
        vault,
        id,
        start_evidence_for(absent, vault, ObservedCanisterStatus::Running, now),
    );
    assert!(settle.is_ok(), "settlement proceeds after E2: {settle:?}");
    assert_eq!(
        get_proposal(&pic, vault, p(S1), id).unwrap().outcome,
        ActionOutcome::Executed
    );

    // ── Acceptance 13(b): the SettlementRecord survives upgrade byte-unchanged
    //    and replay still classifies correctly afterwards ────────────────────
    let before = get_proposal(&pic, vault, p(S1), id).expect("settled proposal");
    pic.upgrade_canister(vault, vault_test_wasm(), candid::encode_args(()).unwrap(), None)
        .expect("second vault upgrade");
    let after = get_proposal(&pic, vault, p(S1), id).expect("settled proposal survives");
    assert_eq!(
        before, after,
        "§8a invariant 4: the record is carried across upgrade UNMODIFIED — \
         asserted as exact equality of the whole view, not field-by-field"
    );

    // And replay still classifies correctly against the SURVIVING record.
    let now = pic.get_time().as_nanos_since_unix_epoch();
    assert_eq!(
        cell3_reconcile_public(
            &pic,
            vault,
            id,
            start_evidence_for(absent, vault, ObservedCanisterStatus::Running, now),
        ),
        Err(VaultError::AlreadySettled {
            outcome: ReconcileTerminalOutcome::Executed
        }),
        "§8a invariant 6 / 13(b): classification reads the STORED semantic_key, \
         which survived the upgrade"
    );
}

// ── S8A / R6.0 — durable controller-invariant observation ───────────────────

/// The R6.0 harness's view of the PUBLIC no-human-controller proof.
fn controller_invariant(pic: &PocketIc, upgrader: Principal) -> ControllerInvariant {
    let r = pic
        .query_call(
            upgrader,
            Principal::anonymous(),
            "get_controller_invariant",
            candid::encode_args(()).unwrap(),
        )
        .expect("query");
    candid::decode_one::<ControllerInvariant>(&r).unwrap()
}

/// S11-2 — the AUTHORITATIVE proof endpoint. Anonymous, like its predecessor:
/// both are PUBLIC by freeze §5, and querying as an unprivileged caller is the
/// point — the no-human-controller property is meant to be verifiable by
/// anyone, not only by a member.
fn controller_invariant_proof(pic: &PocketIc, upgrader: Principal) -> ControllerInvariantProof {
    let r = pic
        .query_call(
            upgrader,
            Principal::anonymous(),
            "get_controller_invariant_proof",
            candid::encode_args(()).unwrap(),
        )
        .expect("query");
    candid::decode_one::<ControllerInvariantProof>(&r).unwrap()
}

fn upgrader_audit_len(pic: &PocketIc, upgrader: Principal) -> u64 {
    let r = pic
        .query_call(upgrader, p(11), "audit_len_for_test", candid::encode_args(()).unwrap())
        .expect("query");
    candid::decode_one::<u64>(&r).unwrap()
}

/// **S8A / R6.0 — REAL CROSS-WASM UPGRADE: the controller-invariant
/// observation survives byte-exact, twice, past the removed scan's cap.**
///
/// THE DEFECT. The observation was durable only as an audit event in
/// MemoryId 4, and the served value was a heap mirror that `post_upgrade`
/// rebuilt by scanning that trail backwards for at most `SCAN_CAP = 10_000`
/// events (`rebuild_invariant_mirror`, core.rs:806 at 41ff8f01 — the pre-S8A
/// base; the constant is cited from the code it is removed from, not invented).
/// Grow the tail past the cap and the observation went out of reach: the
/// rebuild produced `None` and this PUBLIC proof reverted to
/// `{false, false, 0}` — no evidence, for a ring that was intact and observed.
/// R6.0 gives the observation its own cell (MemoryId 11) and deletes the scan.
///
/// WHY THIS TEST EXISTS SEPARATELY FROM THE NATIVE ONES. The native suite
/// proves the mechanism in process. It cannot prove the property that matters
/// here, because in-process `post_upgrade` is a plain function call: no Wasm is
/// replaced, no stable memory is handed between module instances, and a value
/// that happened to survive in a thread-local would look identical to one that
/// survived durably. This runs a genuine `upgrade_canister` against the real
/// Wasm and asserts through the real `post_upgrade`.
///
/// BYTE-EXACT, NOT SHAPE-EXACT: all three fields are pinned to the values
/// recorded, and `vault_controllers_ok != upgrader_controllers_ok` deliberately
/// — a swap, a defaulted timestamp, or a fail-closed `{false,false,0}` are each
/// distinguishable from success rather than coincidentally equal to it.
///
/// TWICE (populate → upgrade → verify → upgrade → verify): the first upgrade
/// proves the cell survives a module replacement; the second proves the value
/// is not merely re-derivable once from state the first upgrade happened to
/// leave behind.
#[test]
fn pic_s8a_r6_0_controller_invariant_survives_real_upgrades_past_scan_cap() {
    /// The cap the REMOVED backwards scan used. Retained only as the threshold
    /// this regression must cross; it is not a live constant.
    const HISTORICAL_SCAN_CAP: u64 = 10_000;
    const OBSERVED_AT_NS: u64 = 777_000_000;

    let (pic, vault, upgrader) = ring_rig_upgrader_test_wasm();

    // Fail-closed before any observation — the baseline the defect wrongly
    // reverted TO, asserted here so a later `{false,false,0}` cannot be read as
    // "unchanged".
    let before_any = controller_invariant(&pic, upgrader);
    assert_eq!(
        before_any,
        ControllerInvariant {
            vault_controllers_ok: false,
            upgrader_controllers_ok: false,
            observed_at_ns: 0
        },
        "no observation yet must fail closed"
    );

    // Record one observation through the same core function the production
    // seam calls. Asymmetric on purpose.
    pic.update_call(
        upgrader,
        p(11),
        "record_controller_invariant_for_test",
        candid::encode_args((true, false, OBSERVED_AT_NS)).unwrap(),
    )
    .expect("record observation");

    let recorded = controller_invariant(&pic, upgrader);
    assert_eq!(
        recorded,
        ControllerInvariant {
            vault_controllers_ok: true,
            upgrader_controllers_ok: false,
            observed_at_ns: OBSERVED_AT_NS
        },
        "the observation must be served before any upgrade"
    );

    // Bury it: grow MemoryId 4 STRICTLY past the cap. Batched because 10,000+
    // appends do not fit one message's instruction budget, and the resulting
    // length is ASSERTED rather than assumed — a run that seeded short would
    // pass this regression below the very threshold it exists to cross.
    let len_at_observation = upgrader_audit_len(&pic, upgrader);
    const BATCH: u32 = 500;
    const BATCHES: u32 = 21; // 10,500 > 10,000
    for _ in 0..BATCHES {
        pic.update_call(
            upgrader,
            p(11),
            "seed_audit_events_for_test",
            candid::encode_one(BATCH).unwrap(),
        )
        .expect("seed audit events");
    }
    let buried_len = upgrader_audit_len(&pic, upgrader);
    assert!(
        buried_len > len_at_observation + HISTORICAL_SCAN_CAP,
        "the tail must be driven STRICTLY past the removed scan's cap: \
         {buried_len} events, observation at {len_at_observation}, cap \
         {HISTORICAL_SCAN_CAP}"
    );

    // ── THE REAL UPGRADE (1 of 2) ───────────────────────────────────────────
    pic.upgrade_canister(upgrader, upgrader_test_wasm(), candid::encode_args(()).unwrap(), Some(vault))
        .expect("first upgrader upgrade");

    let after_first = controller_invariant(&pic, upgrader);
    assert_eq!(
        after_first, recorded,
        "R6.0: the observation must survive a REAL upgrade byte-exact with the \
         audit tail past the cap. Pre-R6.0 this returned {{false,false,0}} — \
         the defect."
    );
    assert_ne!(
        after_first, before_any,
        "MUTATION GUARD: without the durable cell this collapses to the \
         fail-closed baseline, which is precisely how the defect presented"
    );

    // ── THE REAL UPGRADE (2 of 2) ───────────────────────────────────────────
    pic.upgrade_canister(upgrader, upgrader_test_wasm(), candid::encode_args(()).unwrap(), Some(vault))
        .expect("second upgrader upgrade");

    let after_second = controller_invariant(&pic, upgrader);
    assert_eq!(
        after_second, recorded,
        "R6.0: still byte-exact after a second real upgrade"
    );
    // The tail is still there and still irrelevant — survival is not a function
    // of its length in either direction.
    assert!(
        upgrader_audit_len(&pic, upgrader) >= buried_len,
        "the audit trail is append-only and must not have been pruned to make \
         this pass"
    );
}

/// S11-2 / CUST-SSA-006 — THE SERVED FRESHNESS CONTRACT SURVIVES A REAL
/// UPGRADE, AND FRESHNESS IS COMPUTED AGAINST THE CURRENT CLOCK.
///
/// Two properties, and the second is the one native tests cannot reach at all.
///
/// 1. DURABILITY: the observation behind the proof survives a real
///    `upgrade_canister`, so `current_proof_ok` does not silently collapse to
///    the fail-closed `NeverObserved` answer the moment a module is replaced.
///
/// 2. LIVENESS OF THE CLASSIFICATION: freshness is derived at QUERY TIME, not
///    stored. Proved by advancing PocketIC's real clock past the ruled 24 h
///    bound WITHOUT touching the canister — no upgrade, no call, nothing
///    written — and observing the SAME durable observation reclassify from
///    Fresh to Stale. A stored freshness flag would still read Fresh here,
///    which is exactly the failure mode that makes a stale proof look current.
///
/// Runs against the TESTING Upgrader Wasm because recording an observation
/// through the production seam needs two successful management `canister_status`
/// calls; the injected record is written by the SAME core function the
/// production seam calls, so the surviving record is production-shaped.
#[test]
fn pic_s11_2_freshness_contract_survives_upgrade_and_is_computed_at_query_time() {
    let (pic, vault, upgrader) = ring_rig_upgrader_test_wasm();
    let max_age = stsh_custody_types::INVARIANT_REFRESH_PARAMS
        .expect("S11-2 requires the R6 constants ruled")
        .max_age_ns;

    // ── Before any observation: NeverObserved, and NOT success-shaped ───────
    let never = controller_invariant_proof(&pic, upgrader);
    assert_eq!(never.freshness, InvariantFreshness::NeverObserved);
    assert_eq!(never.age_ns, None);
    assert!(!never.current_proof_ok, "absence of evidence is never a proof");
    assert_eq!(never.max_age_ns, max_age, "the ruled bound is served, not invented");

    // Record an INTACT observation stamped at the canister's current time, so
    // it is genuinely fresh rather than fresh by an arbitrary constant.
    let now_at_record = pic
        .get_time()
        .as_nanos_since_unix_epoch();
    pic.update_call(
        upgrader,
        p(11),
        "record_controller_invariant_for_test",
        candid::encode_args((true, true, now_at_record)).unwrap(),
    )
    .expect("record observation");

    let fresh = controller_invariant_proof(&pic, upgrader);
    assert_eq!(fresh.freshness, InvariantFreshness::Fresh);
    assert!(
        fresh.current_proof_ok,
        "a fresh, intact observation IS a current proof — without this the \
         assertions below would pass against a contract that is never true"
    );
    assert_eq!(fresh.observed_at_ns, now_at_record);

    // ── THE REAL UPGRADE ────────────────────────────────────────────────────
    pic.upgrade_canister(upgrader, upgrader_test_wasm(), candid::encode_args(()).unwrap(), Some(vault))
        .expect("upgrader upgrade");

    let after = controller_invariant_proof(&pic, upgrader);
    assert_eq!(
        after.observed_at_ns, now_at_record,
        "the observation behind the proof must survive the upgrade byte-exact"
    );
    assert!(after.vault_controllers_ok && after.upgrader_controllers_ok);
    assert_eq!(after.freshness, InvariantFreshness::Fresh);
    assert!(
        after.current_proof_ok,
        "S11-2: the served contract must still be a CURRENT PROOF after a real \
         upgrade. Collapsing to NeverObserved here would mean every module \
         replacement silently withdraws the ring's public proof."
    );

    // ── Freshness is computed at QUERY TIME ─────────────────────────────────
    // Advance past the ruled bound and touch NOTHING. Same durable record,
    // same canister, no message delivered — only the clock moved.
    pic.advance_time(std::time::Duration::from_nanos(max_age + 1));
    // `advance_time` sets the time the NEXT round will run at; a query observes
    // it only once a round has executed. `tick()` executes an EMPTY round — it
    // delivers no message to the Upgrader and writes nothing, so the durable
    // record below is still the one recorded before the upgrade. This is a
    // harness mechanic, not a step in the property being proved.
    pic.tick();
    let stale = controller_invariant_proof(&pic, upgrader);
    assert_eq!(
        stale.freshness,
        InvariantFreshness::Stale,
        "freshness must be derived from the CURRENT clock at query time — a \
         stored flag would still read Fresh here"
    );
    assert!(!stale.current_proof_ok, "a stale reading is never a current proof");
    // ORTHOGONALITY, across a real upgrade and a real clock advance: staleness
    // withdrew the warrant, it did not rewrite what the observation said.
    assert!(
        stale.vault_controllers_ok && stale.upgrader_controllers_ok,
        "the recorded truth booleans must survive staleness unmodified"
    );
    assert_eq!(stale.observed_at_ns, now_at_record);
    assert!(
        stale.age_ns.expect("an observed proof has an age") >= max_age,
        "the served age must reflect the advanced clock"
    );

    // The PREDECESSOR endpoint still serves its 3 fields unchanged — retained
    // for compatibility, and this is what makes it a deliberate successor
    // rather than a silent reshape.
    let legacy = controller_invariant(&pic, upgrader);
    assert_eq!(
        legacy,
        ControllerInvariant {
            vault_controllers_ok: true,
            upgrader_controllers_ok: true,
            observed_at_ns: now_at_record
        },
        "the predecessor endpoint keeps its exact prior meaning"
    );
}

// ── S8B / R6 Option B — permissionless refresh, real-upgrade durability ─────

/// **S8B criterion 3 — the rate limiter survives a REAL cross-Wasm upgrade, so
/// an upgrade cannot reset the window and grant a free burst.**
///
/// This is the criterion that CANNOT be proved natively. In process,
/// `post_upgrade` is a plain function call: no Wasm is replaced and no stable
/// memory is handed between module instances, so a limiter living in a
/// thread-local would pass the native test identically. The addendum's
/// condition 4 refuses a heap counter precisely because the party who can
/// trigger an upgrade is the governed path itself — which means the proof has
/// to cross a genuine `upgrade_canister`.
///
/// Also exercises the permissionless surface as intended: the refresh is called
/// by `Principal::anonymous()`, not a recovery member. The parameter-injection
/// hook is member-gated because it is TEST harness, but the endpoint under test
/// is reached by an arbitrary caller — otherwise this would be quietly testing
/// a gated endpoint.
#[test]
fn pic_s8b_refresh_rate_limiter_survives_a_real_upgrade() {
    // FIXTURE constants, recorded as such: the three R6 values are Route 2 and
    // unruled. Only the ordering matters here (max_age < min_interval).
    const MIN_INTERVAL_NS: u64 = 3_600_000_000_000;
    const MAX_AGE_NS: u64 = 600_000_000_000;
    const CYCLE_BUDGET: u64 = 1_000_000_000;

    let pinned = stsh_custody_types::INVARIANT_REFRESH_PARAMS
        .expect("A1 pin eee3f17a… — production constants are ruled");
    #[allow(non_snake_case)]
    let PINNED_MIN_INTERVAL_NS = pinned.min_interval_ns;

    let (pic, vault, upgrader) = ring_rig_upgrader_test_wasm();

    // Condition 1 still has deployed coverage AFTER the A1 pin, but it must now
    // be FORCED: the production constants are `Some` (eee3f17a…), so simply not
    // injecting would exercise the pinned path while claiming to test the inert
    // one. On a deployed canister `None` through this hook means "force
    // unruled", never "clear the injection".
    pic.update_call(
        upgrader,
        p(11),
        "set_invariant_refresh_params_for_test",
        candid::encode_one(Option::<stsh_custody_types::InvariantRefreshParams>::None).unwrap(),
    )
    .expect("force the unruled path");
    let raw = pic
        .update_call(
            upgrader,
            Principal::anonymous(),
            "refresh_controller_invariant_now",
            candid::encode_args(()).unwrap(),
        )
        .expect("permissionless call is reachable by an arbitrary caller");
    let inert = candid::decode_one::<Result<ControllerInvariant, InvariantRefreshRefusal>>(&raw)
        .unwrap();
    assert_eq!(
        inert,
        Err(InvariantRefreshRefusal::NotRuled),
        "condition 1: inert while the three R6 constants are unruled"
    );
    assert_eq!(
        refresh_ledger(&pic, upgrader),
        Some((None, None)),
        "an inert refusal must not have charged anything"
    );

    // Arm the candidates, then spend the window.
    pic.update_call(
        upgrader,
        p(11),
        "set_invariant_refresh_params_for_test",
        candid::encode_one(Some(stsh_custody_types::InvariantRefreshParams {
            min_interval_ns: MIN_INTERVAL_NS,
            cycle_budget: CYCLE_BUDGET,
            max_age_ns: MAX_AGE_NS,
        }))
        .unwrap(),
    )
    .expect("inject candidate R6 constants");

    let raw = pic
        .update_call(
            upgrader,
            Principal::anonymous(),
            "refresh_controller_invariant_now",
            candid::encode_args(()).unwrap(),
        )
        .expect("first refresh");
    assert!(
        candid::decode_one::<Result<ControllerInvariant, InvariantRefreshRefusal>>(&raw)
            .unwrap()
            .is_ok(),
        "first refresh is admitted"
    );
    let (spent_at, in_flight) = refresh_ledger(&pic, upgrader).expect("ledger readable");
    assert!(spent_at.is_some(), "the window is now spent");
    assert_eq!(in_flight, None, "the in-flight marker is released on return");

    // ── THE REAL UPGRADE ────────────────────────────────────────────────────
    pic.upgrade_canister(upgrader, upgrader_test_wasm(), candid::encode_args(()).unwrap(), Some(vault))
        .expect("upgrader upgrade");

    assert_eq!(
        refresh_ledger(&pic, upgrader),
        Some((spent_at, None)),
        "criterion 3: the spent window survives the upgrade byte-exact — a heap \
         counter would read None here and hand out a free burst"
    );

    // The injected candidates lived in HEAP and are cleared by the upgrade, so
    // what applies now is the PINNED production constants (eee3f17a…) — the
    // real post-pin behaviour. The durable half survived; the parameter half is
    // reloaded from the shipped constant. Both directions are safe, and the one
    // that matters is that NEITHER grants a free refresh.
    let raw = pic
        .update_call(
            upgrader,
            Principal::anonymous(),
            "refresh_controller_invariant_now",
            candid::encode_args(()).unwrap(),
        )
        .expect("second attempt inside the surviving window");
    // The pinned 6 h cadence, read from the shipped constant rather than
    // restated, so a re-pin moves this test with it.
    let _ = PINNED_MIN_INTERVAL_NS;
    match candid::decode_one::<Result<ControllerInvariant, InvariantRefreshRefusal>>(&raw).unwrap() {
        Err(InvariantRefreshRefusal::TooSoon { retry_after_ns }) => assert_eq!(
            retry_after_ns,
            spent_at.unwrap() + PINNED_MIN_INTERVAL_NS,
            "the retry time is computed from the SURVIVING charge under the PINNED \
             cadence, not from a window the upgrade reset"
        ),
        other => panic!(
            "criterion 3: an upgrade must not grant a burst — expected TooSoon \
             from the surviving window, got {other:?}"
        ),
    }
}

/// Ring rig with a chosen recovery roster, so cost can be measured at both the
/// 3-member and the ruled 9-member maximum (`MAX_RECOVERY_MEMBERS`).
fn ring_rig_with_roster(members: Vec<Principal>) -> (PocketIc, Principal, Principal) {
    let pic = PocketIc::new();
    let upgrader = pic.create_canister();
    let vault = pic.create_canister();
    pic.add_cycles(upgrader, 10_000_000_000_000u128);
    pic.add_cycles(vault, 10_000_000_000_000u128);
    let uinit = UpgraderInitArgs { recovery_members: members, threshold: 2, vault };
    pic.install_canister(upgrader, upgrader_test_wasm(), candid::encode_one(&uinit).unwrap(), None);
    let vinit = VaultInit {
        quorum: VaultInitArgs { signers: vec![p(S1), p(S2), p(S3)], threshold: 2, upgrader },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(vault, vault_wasm(), candid::encode_one(&vinit).unwrap(), None);
    pic.set_controllers(vault, None, vec![upgrader]).unwrap();
    pic.set_controllers(upgrader, None, vec![vault]).unwrap();
    (pic, vault, upgrader)
}

/// **S8B MEASUREMENT — cycle cost of one refresh, by BALANCE DELTA.**
///
/// Requested by the CTO before the packet files: the `cycle_budget` pin must
/// rest on a measured cost of the two management `canister_status` calls, under
/// the same no-invented-constants rule that produced the DID stop-and-report.
///
/// WHY BALANCE DELTA AND NOT `instruction_counter`. One refresh spans two
/// `await` boundaries, so it is three messages, and the instruction counter
/// resets per message — there is no single instruction figure for "one refresh"
/// to read. The canister's cycle balance, by contrast, is charged for all of it:
/// execution plus both inter-canister management calls.
///
/// DECOMPOSITION, stated so the figure is not over-read. Two calls are measured:
///   * a REFUSED call (`NotRuled`) — endpoint entered, no management call, no
///     write. This is the message-overhead baseline.
///   * an ACCEPTED call — the same plus the two `canister_status` calls, the
///     observation write and the audit append.
/// The difference is what the pin actually needs: the incremental cost of the
/// management-call half. Both absolute figures are reported too, because the
/// budget is spent per call, not per delta.
///
/// Measured at BOTH rosters and asserted roster-independent rather than assumed:
/// `canister_status` is a per-canister management call and carries no roster, so
/// the cost should not move — but "should" is not evidence, and the assertion is
/// what turns it into evidence.
/// UMC-03 (lane R-11) — refused-call ceiling for
/// `refresh_controller_invariant_now`, in cycles.
///
/// WHY IT EXISTS. `canisters/upgrader/src/tests.rs`'s S8B rate-limit tests
/// measure how many refreshes are ADMITTED per window. The doc comment on them
/// said the endpoint "cannot exceed the rate-limited ceiling", which reads as a
/// MEASURED: pic_s8b_measure_refresh_cycle_cost_by_balance_delta
/// SPEND bound and is not what those tests measure: `refresh_controller_
/// invariant_now` is permissionless, and a REFUSED call still costs the
/// upgrader a full message induction and decode, paid by the canister.
///
/// MEASURED, not guessed. Fresh sample over this test's own four refusals
/// (lane R-11, 2026-09-07): roster 3 = 6_444_414 / 6_459_462, roster 9 =
/// 6_444_549 / 6_459_462 cycles. max = 6_459_462, spread = 15_048, so
/// max + 3x spread = 6_504_606. Rounded UP to 7_000_000 (about 8% over the
/// computed pin) deliberately: a pin sitting 0.7% above one machine's sample is
/// an author-machine-only pin, and this test runs wherever the gate does.
///
/// This test adds NO guard. It prices the refusal that exists today; if the
/// figure is judged operationally unacceptable that is a finding for R-11's
/// escalation NOTE, not a fix made here.
const UMC03_REFUSED_REFRESH_CEILING_CYCLES: u128 = 7_000_000;

/// Mutation lever (AC-2): a fixed, test-owned 10x multiplier applied INSIDE the
/// measurement, exceeding any max+3x-spread pin by construction.
const UMC03_COST_MULTIPLIER: u128 = 1;

#[test]
fn pic_s8b_measure_refresh_cycle_cost_by_balance_delta() {
    const MIN_INTERVAL_NS: u64 = 3_600_000_000_000;
    const MAX_AGE_NS: u64 = 600_000_000_000;
    const CYCLE_BUDGET: u64 = 1_000_000_000;

    // Tolerance for the roster-independence claim. Not a ruled constant: it is
    // the width within which two runs of the same code are treated as equal
    // cost. Set from the observed noise floor of repeated identical calls, which
    // the test measures rather than assumes (see `noise` below).
    let mut rows: Vec<(usize, u128, u128, u128)> = Vec::new();
    let mut noise: Vec<u128> = Vec::new();

    for members in [
        vec![p(11), p(12), p(13)],
        vec![p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19)],
    ] {
        let n = members.len();
        let (pic, _vault, upgrader) = ring_rig_with_roster(members);

        // (1) Refusal baseline — endpoint entered, no management calls.
        //
        // FORCED unruled. Post-pin (eee3f17a…) the production constants are
        // `Some`, so an un-injected call would be ADMITTED and this "baseline"
        // would silently include the two management calls it exists to exclude
        // — inflating the baseline, deflating the management-call half, and
        // reporting a smaller cost than the truth. That is the direction that
        // matters for a budget pin, so it is forced rather than assumed.
        pic.update_call(
            upgrader,
            p(11),
            "set_invariant_refresh_params_for_test",
            candid::encode_one(Option::<stsh_custody_types::InvariantRefreshParams>::None)
                .unwrap(),
        )
        .expect("force unruled for the baseline");
        let before = pic.cycle_balance(upgrader);
        pic.update_call(
            upgrader,
            Principal::anonymous(),
            "refresh_controller_invariant_now",
            candid::encode_args(()).unwrap(),
        )
        .expect("refused call");
        let refused_cost = before - pic.cycle_balance(upgrader);
        // The baseline must genuinely be a refusal, or it is not a baseline.
        assert!(
            matches!(
                candid::decode_one::<Result<ControllerInvariant, InvariantRefreshRefusal>>(
                    &pic.query_call(
                        upgrader,
                        Principal::anonymous(),
                        "get_controller_invariant",
                        candid::encode_args(()).unwrap(),
                    )
                    .map(|r| candid::encode_one(
                        Ok::<ControllerInvariant, InvariantRefreshRefusal>(
                            candid::decode_one::<ControllerInvariant>(&r).unwrap()
                        )
                    )
                    .unwrap())
                    .unwrap()
                ),
                Ok(_)
            ),
            "sanity: the invariant query must still answer"
        );

        // Noise floor: a second identical refusal must cost the same, and the
        // spread is what any equality claim below has to tolerate.
        let before2 = pic.cycle_balance(upgrader);
        pic.update_call(
            upgrader,
            Principal::anonymous(),
            "refresh_controller_invariant_now",
            candid::encode_args(()).unwrap(),
        )
        .expect("refused call 2");
        let refused_cost2 = before2 - pic.cycle_balance(upgrader);
        noise.push(refused_cost.abs_diff(refused_cost2));
        println!("UMC-03 refused-call cost, roster {n}: {refused_cost} / {refused_cost2} cycles");

        // (2) Accepted call — both management status calls actually issued.
        pic.update_call(
            upgrader,
            p(11),
            "set_invariant_refresh_params_for_test",
            candid::encode_one(Some(stsh_custody_types::InvariantRefreshParams {
                min_interval_ns: MIN_INTERVAL_NS,
                cycle_budget: CYCLE_BUDGET,
                max_age_ns: MAX_AGE_NS,
            }))
            .unwrap(),
        )
        .expect("inject candidates");

        let before = pic.cycle_balance(upgrader);
        let raw = pic
            .update_call(
                upgrader,
                Principal::anonymous(),
                "refresh_controller_invariant_now",
                candid::encode_args(()).unwrap(),
            )
            .expect("accepted call");
        let accepted_cost = before - pic.cycle_balance(upgrader);
        let res =
            candid::decode_one::<Result<ControllerInvariant, InvariantRefreshRefusal>>(&raw).unwrap();
        assert!(res.is_ok(), "the measured call must be an ACCEPTED refresh, got {res:?}");
        // The observation must actually have been taken, or this measures a
        // no-op and understates the management half.
        assert!(
            res.unwrap().observed_at_ns > 0,
            "the accepted refresh must have recorded an observation — otherwise \
             the two status calls did not both succeed and this figure is not \
             the cost of a real refresh"
        );

        // UMC-03 (lane R-11): the REFUSAL cost is now ASSERTED, not just
        // reported. `canisters/upgrader/src/tests.rs`'s rate-limit tests measure
        // how many refreshes are ADMITTED; nothing measured what a REFUSED
        // permissionless call costs the canister, which is the other half of
        // "the endpoint cannot exceed the rate-limited ceiling"
        // (MEASURED: pic_s8b_measure_refresh_cycle_cost_by_balance_delta).
        for (i, cost) in [refused_cost, refused_cost2].into_iter().enumerate() {
            let cost = cost * UMC03_COST_MULTIPLIER;
            assert!(
                cost > 0,
                "roster {n}, refusal sample {i}: a refused call that cost NOTHING would make \
                 the ceiling below vacuous"
            );
            assert!(
                cost <= UMC03_REFUSED_REFRESH_CEILING_CYCLES,
                "roster {n}, refusal sample {i}: a REFUSED, anonymous \
                 `refresh_controller_invariant_now` cost the upgrader {cost} cycles, over the \
                 pinned ceiling {UMC03_REFUSED_REFRESH_CEILING_CYCLES}. The rate limiter caps \
                 how often a refresh is ADMITTED; it does not cap what refusal costs, and this \
                 endpoint is permissionless."
            );
        }

        rows.push((n, refused_cost, accepted_cost, accepted_cost - refused_cost));
    }

    let tol = noise.iter().copied().max().unwrap_or(0).max(1_000_000);
    println!("\n=== S8B MEASURED CYCLE COST (balance delta, PocketIC) ===");
    println!("| roster | refused call (baseline) | accepted call | management-call half |");
    println!("|---:|---:|---:|---:|");
    for (n, r, a, d) in &rows {
        println!("| {n} members | {r} | {a} | {d} |");
    }
    println!(
        "\nnoise floor across identical repeated calls: {:?} (tolerance used: {tol})",
        noise
    );
    println!(
        "RANGE for the cycle_budget pin — accepted call, across both rosters: \
         {}..{} cycles; management-call half: {}..{} cycles.\n",
        rows.iter().map(|r| r.2).min().unwrap(),
        rows.iter().map(|r| r.2).max().unwrap(),
        rows.iter().map(|r| r.3).min().unwrap(),
        rows.iter().map(|r| r.3).max().unwrap()
    );

    // ROSTER-INDEPENDENCE — asserted, not assumed.
    let (n3, _, acc3, mgmt3) = rows[0];
    let (n9, _, acc9, mgmt9) = rows[1];
    assert_eq!((n3, n9), (3, 9), "rosters measured must be 3 and 9");
    assert!(
        acc3.abs_diff(acc9) <= tol,
        "the accepted-refresh cost must be ROSTER-INDEPENDENT — `canister_status` \
         carries no roster. 3-member {acc3} vs 9-member {acc9} (tolerance {tol}). \
         If this ever fails, the cycle_budget pin needs a maxima-keyed bound \
         instead of a flat figure."
    );
    assert!(
        mgmt3.abs_diff(mgmt9) <= tol,
        "the management-call half must be roster-independent: {mgmt3} vs {mgmt9} \
         (tolerance {tol})"
    );
    assert!(
        rows.iter().all(|(_, r, a, _)| a > r),
        "an accepted refresh must cost MORE than a refusal — if not, the two \
         management calls were not issued and this harness is measuring nothing"
    );
}

fn refresh_ledger(
    pic: &PocketIc,
    upgrader: Principal,
) -> Option<(Option<u64>, Option<u64>)> {
    let r = pic
        .query_call(upgrader, p(11), "refresh_ledger_for_test", candid::encode_args(()).unwrap())
        .expect("query");
    candid::decode_one::<Option<(Option<u64>, Option<u64>)>>(&r).unwrap()
}

/// **P1-4 (cell 4) — REAL CROSS-WASM UPGRADE on the recovery plane.**
///
/// Same property, other direction: a start held at the await boundary by the
/// production-faithful seam, the Upgrader's Wasm genuinely replaced, E2
/// observed through the real `post_upgrade`, settlement proceeding, and then a
/// settled record surviving a further upgrade with replay still classifying.
#[test]
fn pic_s7_p1_4_cell4_e2_runs_through_a_real_upgrade_and_settles() {
    let (pic, vault, upgrader) = ring_rig_upgrader_test_wasm();

    // Propose StartVault and reach quorum WITHOUT issuing the call.
    let raw = pic
        .update_call(
            upgrader,
            p(11),
            "propose_recovery",
            candid::encode_one(&RecoveryAction::StartVault).unwrap(),
        )
        .unwrap();
    let rid = candid::decode_one::<Result<u64, RecoveryError>>(&raw)
        .unwrap()
        .expect("recovery proposal");
    for (i, m) in [p(11), p(12)].into_iter().enumerate() {
        let hash = recovery_proposal(&pic, upgrader, rid).commitment_hash;
        let method = if i == 0 {
            "approve_recovery"
        } else {
            "approve_start_without_issuing_call_for_test"
        };
        let raw = pic
            .update_call(upgrader, m, method, candid::encode_args((rid, hash)).unwrap())
            .unwrap();
        candid::decode_one::<Result<(), RecoveryError>>(&raw)
            .unwrap()
            .expect("approval");
    }

    let held = recovery_proposal(&pic, upgrader, rid);
    assert_eq!(
        held.outcome,
        ActionOutcome::Executing,
        "held at the await boundary, durably Executing"
    );
    assert!(held.start.is_some(), "§2: the start-intent is durable before the await");

    // ── THE REAL UPGRADE ────────────────────────────────────────────────────
    pic.upgrade_canister(
        upgrader,
        upgrader_test_wasm(),
        candid::encode_args(()).unwrap(),
        Some(vault),
    )
    .expect("upgrader upgrade");

    let swept = recovery_proposal(&pic, upgrader, rid);
    assert_eq!(
        swept.outcome,
        ActionOutcome::OutcomeUnknown,
        "E2 through the REAL post_upgrade promotes the held start"
    );
    assert_ne!(
        held.outcome, swept.outcome,
        "MUTATION GUARD: without the E2 call in post_upgrade this stays Executing"
    );
    assert_eq!(
        swept.start.as_ref().unwrap().intent,
        held.start.as_ref().unwrap().intent,
        "§2: the start-intent survives the upgrade unchanged — E2 takes no \
         evidence and rewrites no intent"
    );

    // Settlement proceeds from objective evidence.
    let now = pic.get_time().as_nanos_since_unix_epoch();
    let (_, res) = recovery_quorum(
        &pic,
        upgrader,
        RecoveryAction::ReconcileVaultStart {
            proposal_id: rid,
            objective_evidence: start_evidence_for(
                vault,
                upgrader,
                ObservedCanisterStatus::Running,
                now,
            ),
        },
    );
    assert!(res.is_ok(), "settlement proceeds after E2: {res:?}");
    let settled = recovery_proposal(&pic, upgrader, rid);
    assert_eq!(settled.outcome, ActionOutcome::Executed);
    let record = settled
        .start
        .as_ref()
        .unwrap()
        .settlement
        .as_ref()
        .expect("§8a record written on the terminal transition")
        .clone();

    // ── 13(b): record survives a further upgrade byte-unchanged ─────────────
    pic.upgrade_canister(
        upgrader,
        upgrader_test_wasm(),
        candid::encode_args(()).unwrap(),
        Some(vault),
    )
    .expect("second upgrader upgrade");
    let after = recovery_proposal(&pic, upgrader, rid);
    let record_after = after.start.as_ref().unwrap().settlement.as_ref().unwrap().clone();
    assert_eq!(
        record, record_after,
        "§8a invariant 4: outcome, semantic_key, evidence_commitment, \
         observed_at_ns and conflict_recorded all carried across UNCHANGED"
    );

    // And replay still classifies against the surviving stored key.
    let now = pic.get_time().as_nanos_since_unix_epoch();
    let (_, replay) = recovery_quorum(
        &pic,
        upgrader,
        RecoveryAction::ReconcileVaultStart {
            proposal_id: rid,
            objective_evidence: start_evidence_for(
                vault,
                upgrader,
                ObservedCanisterStatus::Running,
                now,
            ),
        },
    );
    assert_eq!(
        replay,
        Err(RecoveryError::AlreadySettled {
            outcome: ReconcileTerminalOutcome::Executed
        }),
        "§8a invariant 6 / 13(b): classification reads the STORED semantic_key \
         that survived the upgrade"
    );
}


// ═════════════════════════════════════════════════════════════════════════════
// §S9 — R5.2: TEST 9 AND EVERY ONE-SIDED STOP/FREEZE CASE, DEMONSTRATED
//
// Authority: CTO_RULING_S9_SCOPE_AND_DISPATCH_2026-08-12.md
// (sha256 01d7ca997b397ee8a190e06f9db8c828cd17b47c0bdd0edbd6bd975306aa9d76),
// discharging SSA release condition 9 and the demonstration half of 7.
//
// THE LAW UNDER TEST (CTO_TRIAGE_SSA_COMPREHENSIVE_REVIEW_2026-08-05.md item 2):
// "both-stopped is the ONLY unrecoverable state" is true only if each SINGLE
// stopped state is recoverable, in BOTH directions. These tests demonstrate
// that law against real stopped and real frozen canisters on a real subnet;
// none of it is asserted by prose.
//
// The five ruled cases and the test that carries each:
//   1. both-stopped, UNRECOVERABLE  → pic_s9_test9_both_stopped_is_unrecoverable
//   2. Vault stopped/Upgrader up    → pic_s9_case2_stopped_vault_recovers_...
//   3. Upgrader stopped/Vault up    → pic_s9_case3_stopped_upgrader_recovers_...
//   4. both-frozen, RECOVERABLE     → pic_s9_case4_both_frozen_recovers_...
//   5. one-sided freeze, each way   → pic_s9_case5a_… and pic_s9_case5b_…
// ═════════════════════════════════════════════════════════════════════════════

/// The closed ring with the VAULT on the `testing` Wasm, so the cell-3 start
/// seam (`approve_start_without_issuing_call_for_test`) is reachable while the
/// Upgrader stays on the production Wasm. Mirrors `ring_rig_upgrader_test_wasm`
/// in the other direction; the controller shape is identical to `ring_rig`.
fn ring_rig_vault_test_wasm() -> (PocketIc, Principal, Principal) {
    let pic = PocketIc::new();
    let upgrader = pic.create_canister();
    let vault = pic.create_canister();
    pic.add_cycles(upgrader, 10_000_000_000_000u128);
    pic.add_cycles(vault, 10_000_000_000_000u128);
    let uinit = UpgraderInitArgs {
        recovery_members: vec![p(11), p(12), p(13)],
        threshold: 2,
        vault,
    };
    pic.install_canister(upgrader, upgrader_wasm(), candid::encode_one(&uinit).unwrap(), None);
    let vinit = VaultInit {
        quorum: VaultInitArgs {
            signers: vec![p(S1), p(S2), p(S3)],
            threshold: 2,
            upgrader,
        },
        cutover_targets: manifest_cutover(),
    };
    pic.install_canister(vault, vault_test_wasm(), candid::encode_one(&vinit).unwrap(), None);
    pic.set_controllers(vault, None, vec![upgrader]).unwrap();
    pic.set_controllers(upgrader, None, vec![vault]).unwrap();
    (pic, vault, upgrader)
}

/// Read the REAL status string of a canister off the subnet, from its real
/// controller. Panics if the status cannot be read — a case where the read
/// itself fails is a different observation and must not be silently treated as
/// "not running" (that is the assertion-by-prose failure this lane forbids).
fn real_status(pic: &PocketIc, canister: Principal, controller: Principal) -> String {
    format!("{:?}", pic.canister_status(canister, Some(controller)).unwrap().status)
}

/// Assert an ingress update call is rejected because the canister cannot
/// execute it, and return the observed reject for the record.
fn assert_ingress_refused(
    pic: &PocketIc,
    canister: Principal,
    sender: Principal,
    method: &str,
    arg: Vec<u8>,
) -> String {
    let r = pic.update_call(canister, sender, method, arg);
    let err = r.err().unwrap_or_else(|| {
        panic!("{method} on {canister} was ADMITTED — the canister is not out of service")
    });
    format!("{err:?}")
}

/// **CASE 1 — TEST 9. BOTH-STOPPED IS UNRECOVERABLE, DEMONSTRATED.**
///
/// This is the launch-blocking artifact CUST-SSA-005 requires and the one the
/// V7 audit (§ "Threshold floor + liveness") calls correctly launch-blocking.
/// It is a test of the DESIGN WORKING: with both ring members genuinely
/// stopped, the ring has no route back, because every route that could start a
/// canister is itself a canister that must execute a message to issue it.
///
/// What is demonstrated, not asserted:
///   * both canisters are REALLY `Stopped` (read off the subnet);
///   * cell 3 — the Vault's governed `Start` — cannot even be PROPOSED, because
///     the ingress that would carry it is refused by a stopped Vault;
///   * cell 4 — the recovery quorum's `StartVault` — likewise cannot be
///     proposed against a stopped Upgrader;
///   * cycles are NOT the constraint: a permissionless top-up (the remedy that
///     DOES cure the frozen cases, 4 and 5) changes nothing here;
///   * both canisters are still `Stopped` afterwards.
///
/// MUTATION GUARD: cases 2 and 3 run the SAME two routes with exactly one side
/// stopped and both succeed. If a route existed that could start a canister
/// from outside the ring, case 2/3 would still pass and THIS test would fail.
#[test]
fn pic_s9_test9_both_stopped_is_unrecoverable() {
    let (pic, vault, upgrader) = ring_rig();

    // ── Both genuinely stopped, each by its real controller ──────────────────
    pic.stop_canister(vault, Some(upgrader)).unwrap();
    pic.stop_canister(upgrader, Some(vault)).unwrap();
    assert_eq!(real_status(&pic, vault, upgrader), "Stopped");
    assert_eq!(real_status(&pic, upgrader, vault), "Stopped");

    // ── Route 1 (cell 3): the Vault's governed Start. A stopped canister
    //    accepts no ingress, so the signer cannot even open the proposal. ─────
    let cell3 = assert_ingress_refused(
        &pic,
        vault,
        p(S1),
        "propose",
        candid::encode_one(&VaultActionKind::Management(ManagementAction::Start {
            target: upgrader,
        }))
        .unwrap(),
    );
    assert!(
        cell3.contains("CanisterStopped"),
        "cell 3 must be refused BECAUSE the Vault is stopped, not for some \
         other reason; observed: {cell3}"
    );

    // ── Route 2 (cell 4): the recovery quorum's StartVault, the route
    //    CUST-SSA-004 exists for. Refused for the mirror-image reason. ────────
    let cell4 = assert_ingress_refused(
        &pic,
        upgrader,
        p(11),
        "propose_recovery",
        candid::encode_one(&RecoveryAction::StartVault).unwrap(),
    );
    assert!(
        cell4.contains("CanisterStopped"),
        "cell 4 must be refused BECAUSE the Upgrader is stopped; observed: {cell4}"
    );

    // ── The freeze remedy does NOT apply: this is not a cycles condition ─────
    pic.add_cycles(vault, 100_000_000_000_000u128);
    pic.add_cycles(upgrader, 100_000_000_000_000u128);
    let after_topup = assert_ingress_refused(
        &pic,
        upgrader,
        p(11),
        "propose_recovery",
        candid::encode_one(&RecoveryAction::StartVault).unwrap(),
    );
    assert!(
        after_topup.contains("CanisterStopped"),
        "a permissionless top-up cures a FROZEN canister (cases 4/5), never a \
         STOPPED one; observed: {after_topup}"
    );

    // ── And nothing moved ────────────────────────────────────────────────────
    assert_eq!(real_status(&pic, vault, upgrader), "Stopped");
    assert_eq!(real_status(&pic, upgrader, vault), "Stopped");
}

/// Reach quorum on a `StartVault` WITHOUT issuing the management call — the
/// production-faithful reply-loss seam (`testing` Wasm only). Returns the
/// proposal id, durably `Executing`.
fn cell4_start_held_at_the_await(pic: &PocketIc, upgrader: Principal) -> u64 {
    let raw = pic
        .update_call(
            upgrader,
            p(11),
            "propose_recovery",
            candid::encode_one(&RecoveryAction::StartVault).unwrap(),
        )
        .expect("propose_recovery");
    let rid = candid::decode_one::<Result<u64, RecoveryError>>(&raw)
        .unwrap()
        .expect("recovery proposal");
    for (i, m) in [p(11), p(12)].into_iter().enumerate() {
        let hash = recovery_proposal(pic, upgrader, rid).commitment_hash;
        let method = if i == 0 {
            "approve_recovery"
        } else {
            "approve_start_without_issuing_call_for_test"
        };
        let raw = pic
            .update_call(upgrader, m, method, candid::encode_args((rid, hash)).unwrap())
            .expect("approval call");
        candid::decode_one::<Result<(), RecoveryError>>(&raw).unwrap().expect("approval");
    }
    assert_eq!(
        recovery_proposal(pic, upgrader, rid).outcome,
        ActionOutcome::Executing,
        "held at the await boundary, durably Executing"
    );
    rid
}

/// **CASE 2 — VAULT STOPPED / UPGRADER RUNNING: RECOVERABLE.**
///
/// The half of the law that CUST-SSA-004 exists to make true. The Vault is
/// GENUINELY stopped, so the only route back is the Upgrader's fixed-target,
/// recovery-quorum-gated cell-4 start. This test drives that route through
/// SETTLEMENT — every terminal here is reached from `canister_status` evidence
/// READ OFF THE REAL SUBNET, never from a reply and never from prose:
///
///   (a) a start whose reply is lost sits in `OutcomeUnknown` after E2, and
///       the REAL observation at that moment is `Stopped` — the Vault did not
///       start — which §5 maps to a terminal `Failed`. The mechanism does NOT
///       claim success it cannot see.
///   (b) the recovery quorum then really starts the Vault; the subnet shows
///       `Running`.
///   (c) a further reply-loss over the now-running Vault settles from REAL
///       `Running` evidence to terminal `Executed`.
#[test]
fn pic_s9_case2_stopped_vault_recovers_through_settlement() {
    let (pic, vault, upgrader) = ring_rig_upgrader_test_wasm();

    pic.stop_canister(vault, Some(upgrader)).unwrap();
    assert_eq!(
        real_status(&pic, vault, upgrader),
        "Stopped",
        "the Vault must REALLY be stopped before any recovery route runs"
    );
    // The Upgrader — the surviving side — is genuinely up.
    assert_eq!(real_status(&pic, upgrader, vault), "Running");

    // ── (a) reply loss over a still-stopped Vault settles to Failed ──────────
    let a = cell4_start_held_at_the_await(&pic, upgrader);
    pic.upgrade_canister(
        upgrader,
        upgrader_test_wasm(),
        candid::encode_args(()).unwrap(),
        Some(vault),
    )
    .expect("upgrader upgrade");
    assert_eq!(
        recovery_proposal(&pic, upgrader, a).outcome,
        ActionOutcome::OutcomeUnknown,
        "E2 through the REAL post_upgrade promotes the held start"
    );

    // The evidence is the REAL subnet reading, taken now.
    let observed = pic.canister_status(vault, Some(upgrader)).unwrap();
    assert_eq!(format!("{:?}", observed.status), "Stopped");
    assert_eq!(
        observed.settings.controllers,
        vec![upgrader],
        "§4.3: evidence is only about the ring while the controllers hold"
    );
    let now = pic.get_time().as_nanos_since_unix_epoch();
    let (_, res) = recovery_quorum(
        &pic,
        upgrader,
        RecoveryAction::ReconcileVaultStart {
            proposal_id: a,
            objective_evidence: start_evidence_for(
                vault,
                upgrader,
                ObservedCanisterStatus::Stopped,
                now,
            ),
        },
    );
    assert!(res.is_ok(), "a Stopped observation is legal start evidence: {res:?}");
    assert_eq!(
        recovery_proposal(&pic, upgrader, a).outcome,
        ActionOutcome::Failed,
        "§5: an observed Stopped target maps to a terminal Failed — the \
         mechanism does not claim a start it cannot see"
    );

    // ── (b) the recovery quorum really starts the Vault ──────────────────────
    let (b, res) = recovery_quorum(&pic, upgrader, RecoveryAction::StartVault);
    assert!(res.is_ok(), "the recovery quorum's start must be admitted: {res:?}");
    assert_eq!(
        real_status(&pic, vault, upgrader),
        "Running",
        "CASE 2 RECOVERED: cell 4 started a REAL stopped Vault"
    );
    assert_eq!(recovery_proposal(&pic, upgrader, b).outcome, ActionOutcome::Executed);

    // ── (c) reply loss over the recovered Vault settles to Executed ──────────
    let c = cell4_start_held_at_the_await(&pic, upgrader);
    pic.upgrade_canister(
        upgrader,
        upgrader_test_wasm(),
        candid::encode_args(()).unwrap(),
        Some(vault),
    )
    .expect("second upgrader upgrade");
    assert_eq!(
        recovery_proposal(&pic, upgrader, c).outcome,
        ActionOutcome::OutcomeUnknown
    );
    let observed = pic.canister_status(vault, Some(upgrader)).unwrap();
    assert_eq!(format!("{:?}", observed.status), "Running");
    let now = pic.get_time().as_nanos_since_unix_epoch();
    let (_, res) = recovery_quorum(
        &pic,
        upgrader,
        RecoveryAction::ReconcileVaultStart {
            proposal_id: c,
            objective_evidence: start_evidence_for(
                vault,
                upgrader,
                ObservedCanisterStatus::Running,
                now,
            ),
        },
    );
    assert!(res.is_ok(), "settlement from real Running evidence: {res:?}");
    let settled = recovery_proposal(&pic, upgrader, c);
    assert_eq!(
        settled.outcome,
        ActionOutcome::Executed,
        "§5: a REAL Running observation is what makes the terminal Executed"
    );
    assert!(
        settled.start.as_ref().unwrap().settlement.is_some(),
        "§8a: an evidence-driven terminal carries a SettlementRecord"
    );
}

/// Cell-3 mirror of `cell4_start_held_at_the_await`: reach quorum on a governed
/// `Start` WITHOUT issuing the management call (`testing` Wasm only).
fn cell3_start_held_at_the_await(pic: &PocketIc, vault: Principal, target: Principal) -> u64 {
    let id = propose(
        pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::Start { target }),
    );
    approve(pic, vault, p(S1), id).unwrap();
    let hash = get_proposal(pic, vault, p(S1), id).unwrap().commitment_hash;
    let raw = pic
        .update_call(
            vault,
            p(S2),
            "approve_start_without_issuing_call_for_test",
            candid::encode_args((id, hash)).unwrap(),
        )
        .expect("seam call");
    candid::decode_one::<Result<(), VaultError>>(static_bytes(raw))
        .unwrap()
        .expect("seam admitted");
    assert_eq!(
        get_proposal(pic, vault, p(S1), id).unwrap().outcome,
        ActionOutcome::Executing,
        "held at the await boundary, durably Executing"
    );
    id
}

/// **CASE 3 — UPGRADER STOPPED / VAULT RUNNING: RECOVERABLE.**
///
/// The other half of the law, on the governed Vault plane (cell 3), with the
/// SAME settlement discipline as case 2 — the symmetry item 2 of the CTO
/// triage requires. The Upgrader is GENUINELY stopped; the Vault's 2-of-3
/// quorum is the route back; every terminal is reached from a real
/// `canister_status` observation.
#[test]
fn pic_s9_case3_stopped_upgrader_recovers_through_settlement() {
    let (pic, vault, upgrader) = ring_rig_vault_test_wasm();

    pic.stop_canister(upgrader, Some(vault)).unwrap();
    assert_eq!(
        real_status(&pic, upgrader, vault),
        "Stopped",
        "the Upgrader must REALLY be stopped before any recovery route runs"
    );
    assert_eq!(real_status(&pic, vault, upgrader), "Running");

    // ── (a) reply loss over a still-stopped Upgrader settles to Failed ───────
    let a = cell3_start_held_at_the_await(&pic, vault, upgrader);
    pic.upgrade_canister(
        vault,
        vault_test_wasm(),
        candid::encode_args(()).unwrap(),
        Some(upgrader),
    )
    .expect("vault upgrade");
    assert_eq!(
        get_proposal(&pic, vault, p(S1), a).unwrap().outcome,
        ActionOutcome::OutcomeUnknown,
        "E2 through the REAL post_upgrade promotes the held start"
    );

    let observed = pic.canister_status(upgrader, Some(vault)).unwrap();
    assert_eq!(format!("{:?}", observed.status), "Stopped");
    assert_eq!(
        observed.settings.controllers,
        vec![vault],
        "§4.3: the ring invariant holds for the Upgrader as target"
    );
    let now = pic.get_time().as_nanos_since_unix_epoch();
    let settle = cell3_reconcile_public(
        &pic,
        vault,
        a,
        start_evidence_for(upgrader, vault, ObservedCanisterStatus::Stopped, now),
    );
    assert!(settle.is_ok(), "a Stopped observation is legal start evidence: {settle:?}");
    assert_eq!(
        get_proposal(&pic, vault, p(S1), a).unwrap().outcome,
        ActionOutcome::Failed,
        "§5: an observed Stopped target maps to a terminal Failed — identical \
         mapping to case 2, in the other direction (acceptance 15(a) symmetry)"
    );

    // ── (b) the Vault quorum really starts the Upgrader ──────────────────────
    let b = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::Start { target: upgrader }),
    );
    approve(&pic, vault, p(S1), b).unwrap();
    approve(&pic, vault, p(S2), b).unwrap();
    assert_eq!(
        real_status(&pic, upgrader, vault),
        "Running",
        "CASE 3 RECOVERED: cell 3 started a REAL stopped Upgrader"
    );
    assert_eq!(
        get_proposal(&pic, vault, p(S1), b).unwrap().outcome,
        ActionOutcome::Executed
    );

    // ── (c) reply loss over the recovered Upgrader settles to Executed ───────
    let c = cell3_start_held_at_the_await(&pic, vault, upgrader);
    pic.upgrade_canister(
        vault,
        vault_test_wasm(),
        candid::encode_args(()).unwrap(),
        Some(upgrader),
    )
    .expect("second vault upgrade");
    assert_eq!(
        get_proposal(&pic, vault, p(S1), c).unwrap().outcome,
        ActionOutcome::OutcomeUnknown
    );
    let observed = pic.canister_status(upgrader, Some(vault)).unwrap();
    assert_eq!(format!("{:?}", observed.status), "Running");
    let now = pic.get_time().as_nanos_since_unix_epoch();
    let settle = cell3_reconcile_public(
        &pic,
        vault,
        c,
        start_evidence_for(upgrader, vault, ObservedCanisterStatus::Running, now),
    );
    assert!(settle.is_ok(), "settlement from real Running evidence: {settle:?}");
    assert_eq!(
        get_proposal(&pic, vault, p(S1), c).unwrap().outcome,
        ActionOutcome::Executed,
        "§5: a REAL Running observation is what makes the terminal Executed"
    );
}

// ── Freeze (cases 4 and 5) ──────────────────────────────────────────────────
//
// A canister is FROZEN when its cycle balance is at or below the reserve its
// freezing threshold implies; it then executes nothing — no ingress, no query,
// and not even its controller's `canister_status`. The threshold below is not
// an invented constant: it is DERIVED, per canister, from that canister's own
// observed idle burn and its own observed balance, so the reserve provably
// exceeds the balance. The only remedy the platform offers is cycles, and
// depositing cycles requires NO controllership — that permissionlessness is
// precisely what makes the frozen cases recoverable where case 1 is not
// (CTO_AUDIT_CUSTODY_VAULT_V7_2026-08-02.md, §"Threshold floor + liveness").
//
// MODELLING NOTE, stated because this lane forbids silent downgrades: the
// permissionless top-up is performed with PocketIC's `add_cycles`, which takes
// NO sender and requires NO controllership — it models `deposit_cycles`'
// AUTHORITY property exactly. What it does not model is a second canister
// attaching cycles to the management call; that leg is a canary item, named in
// the packet, not asserted here.

/// Freeze `canister` by raising its freezing threshold above what its own
/// balance can reserve. Returns the balance observed at freeze time.
fn freeze_by_raising_the_threshold(
    pic: &PocketIc,
    canister: Principal,
    controller: Principal,
) -> u128 {
    use ic_management_canister_types::CanisterSettings;
    let st = pic.canister_status(canister, Some(controller)).expect("status before freeze");
    let balance: u128 = st.cycles.0.to_string().parse().unwrap();
    let idle_per_day: u128 = st.idle_cycles_burned_per_day.0.to_string().parse().unwrap();
    assert!(idle_per_day > 0, "a zero idle burn would make the threshold undefined");
    // reserve(threshold_s) = threshold_s * idle_per_day / 86_400. Solve for a
    // reserve of TWICE the current balance, so the canister is unambiguously
    // below its threshold with margin.
    let threshold_s = 2 * balance * 86_400 / idle_per_day;
    pic.update_canister_settings(
        canister,
        Some(controller),
        CanisterSettings {
            freezing_threshold: Some(candid::Nat::from(threshold_s)),
            ..Default::default()
        },
    )
    .expect("a controller may raise the freezing threshold");
    balance
}

/// Assert `canister` is really frozen: it refuses ingress with
/// `CanisterOutOfCycles`, and its controller cannot even read its status.
fn assert_really_frozen(pic: &PocketIc, canister: Principal, controller: Principal, sender: Principal, method: &str) {
    let err = assert_ingress_refused(pic, canister, sender, method, candid::encode_args(()).unwrap());
    assert!(
        err.contains("CanisterOutOfCycles"),
        "{canister} must refuse ingress BECAUSE it is frozen; observed: {err}"
    );
    assert!(
        pic.canister_status(canister, Some(controller)).is_err(),
        "a frozen canister cannot even serve its controller's status read"
    );
}

/// **CASE 4 — BOTH-FROZEN IS RECOVERABLE, DEMONSTRATED.**
///
/// The case that separates freeze from stop, and the reason the V7 audit
/// accepts a solo monitor owner. Both ring members are genuinely frozen: every
/// governed and every recovery route is dead, and — unlike case 1 — the ring
/// cannot rescue itself either, because the rescuer is frozen too. The remedy
/// takes no controllership at all, and after it the FULL ring works again,
/// demonstrated by really stopping the Upgrader and really starting it back
/// through cell 3.
#[test]
fn pic_s9_case4_both_frozen_recovers_by_permissionless_top_up() {
    let (pic, vault, upgrader) = ring_rig();

    freeze_by_raising_the_threshold(&pic, vault, upgrader);
    freeze_by_raising_the_threshold(&pic, upgrader, vault);

    // ── Both really frozen: neither plane accepts anything ───────────────────
    assert_really_frozen(&pic, vault, upgrader, p(S1), "get_governance_summary");
    assert_really_frozen(&pic, upgrader, vault, p(11), "get_controller_invariant");
    // Including the two routes case 1 tested: dead for a DIFFERENT reason.
    let cell3 = assert_ingress_refused(
        &pic,
        vault,
        p(S1),
        "propose",
        candid::encode_one(&VaultActionKind::Management(ManagementAction::Start {
            target: upgrader,
        }))
        .unwrap(),
    );
    assert!(cell3.contains("CanisterOutOfCycles"), "observed: {cell3}");
    let cell4 = assert_ingress_refused(
        &pic,
        upgrader,
        p(11),
        "propose_recovery",
        candid::encode_one(&RecoveryAction::StartVault).unwrap(),
    );
    assert!(cell4.contains("CanisterOutOfCycles"), "observed: {cell4}");

    // ── The remedy: cycles, from nobody in particular ────────────────────────
    pic.add_cycles(vault, 100_000_000_000_000_000_000u128);
    pic.add_cycles(upgrader, 100_000_000_000_000_000_000u128);

    // ── RECOVERED, and the whole ring works: stop the Upgrader for real, then
    //    start it back through the governed cell-3 route ─────────────────────
    assert_eq!(real_status(&pic, vault, upgrader), "Running");
    pic.stop_canister(upgrader, Some(vault)).unwrap();
    assert_eq!(real_status(&pic, upgrader, vault), "Stopped");
    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::Start { target: upgrader }),
    );
    approve(&pic, vault, p(S1), id).unwrap();
    approve(&pic, vault, p(S2), id).unwrap();
    assert_eq!(
        real_status(&pic, upgrader, vault),
        "Running",
        "CASE 4 RECOVERED: after a permissionless top-up the ring governs again"
    );
    assert_eq!(
        get_proposal(&pic, vault, p(S1), id).unwrap().outcome,
        ActionOutcome::Executed
    );
}

/// **CASE 5a — VAULT FROZEN / UPGRADER RUNNING: RECOVERABLE.**
///
/// One-sided freeze, Vault side. Two distinct facts are demonstrated:
///   * the surviving side's recovery route is NOT a freeze remedy — the
///     Upgrader's cell-4 start runs against a Vault that is `Running` and
///     frozen, and the Vault is STILL dead to every caller afterwards. Freeze
///     and stop are different failures with different cures, and the ring
///     does not pretend otherwise;
///   * the cure is the permissionless top-up, after which the Vault governs.
#[test]
fn pic_s9_case5a_frozen_vault_recovers_by_permissionless_top_up() {
    let (pic, vault, upgrader) = ring_rig();

    freeze_by_raising_the_threshold(&pic, vault, upgrader);
    assert_really_frozen(&pic, vault, upgrader, p(S1), "get_governance_summary");
    // The counterpart is untouched and fully live.
    assert_eq!(real_status(&pic, upgrader, vault), "Running");

    // The recovery plane still works — and cannot help.
    let (rid, res) = recovery_quorum(&pic, upgrader, RecoveryAction::StartVault);
    assert!(res.is_ok(), "the recovery plane is unaffected by the Vault's freeze: {res:?}");
    assert_eq!(
        recovery_proposal(&pic, upgrader, rid).outcome,
        ActionOutcome::Executed,
        "the start SUCCEEDS — and it is telling the truth: a frozen canister is \
         `Running`. `Executed` here means the target is running, NOT that it is \
         serviceable. Detecting the freeze is the external monitor's job \
         (CTO_AUDIT_CUSTODY_VAULT_V7_2026-08-02.md §\"Threshold floor + \
         liveness\"), not this route's."
    );
    let still = assert_ingress_refused(
        &pic,
        vault,
        p(S1),
        "get_governance_summary",
        candid::encode_args(()).unwrap(),
    );
    assert!(
        still.contains("CanisterOutOfCycles"),
        "the cell-4 start is not a freeze remedy; observed: {still}"
    );

    // ── The cure ─────────────────────────────────────────────────────────────
    pic.add_cycles(vault, 100_000_000_000_000_000_000u128);
    assert_eq!(real_status(&pic, vault, upgrader), "Running");
    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::Start { target: upgrader }),
    );
    approve(&pic, vault, p(S1), id).unwrap();
    approve(&pic, vault, p(S2), id).unwrap();
    assert_eq!(
        get_proposal(&pic, vault, p(S1), id).unwrap().outcome,
        ActionOutcome::Executed,
        "CASE 5a RECOVERED: the Vault governs again after a permissionless top-up"
    );
}

/// **CASE 5b — UPGRADER FROZEN / VAULT RUNNING: RECOVERABLE.**
///
/// The mirror image, and the direction that matters for the recovery plane:
/// while the Upgrader is frozen the ring has NO recovery quorum at all, and
/// the Vault's governed cell-3 start does not cure it either. The
/// permissionless top-up restores the recovery plane.
#[test]
fn pic_s9_case5b_frozen_upgrader_recovers_by_permissionless_top_up() {
    let (pic, vault, upgrader) = ring_rig();

    freeze_by_raising_the_threshold(&pic, upgrader, vault);
    assert_really_frozen(&pic, upgrader, vault, p(11), "get_controller_invariant");
    assert_eq!(real_status(&pic, vault, upgrader), "Running");

    // The governed plane still works — and cannot help.
    let id = propose(
        &pic,
        vault,
        p(S1),
        VaultActionKind::Management(ManagementAction::Start { target: upgrader }),
    );
    approve(&pic, vault, p(S1), id).unwrap();
    approve(&pic, vault, p(S2), id).unwrap();
    assert_eq!(
        get_proposal(&pic, vault, p(S1), id).unwrap().outcome,
        ActionOutcome::Executed,
        "symmetric with case 5a: the start succeeds against a frozen-but-Running \
         target, and says only that — not that the target can serve callers"
    );
    let still = assert_ingress_refused(
        &pic,
        upgrader,
        p(11),
        "get_controller_invariant",
        candid::encode_args(()).unwrap(),
    );
    assert!(
        still.contains("CanisterOutOfCycles"),
        "the cell-3 start is not a freeze remedy; observed: {still}"
    );

    // ── The cure ─────────────────────────────────────────────────────────────
    pic.add_cycles(upgrader, 100_000_000_000_000_000_000u128);
    assert_eq!(real_status(&pic, upgrader, vault), "Running");
    let (rid, res) = recovery_quorum(&pic, upgrader, RecoveryAction::StartVault);
    assert!(
        res.is_ok(),
        "CASE 5b RECOVERED: the recovery quorum functions again: {res:?}"
    );
    assert_eq!(
        recovery_proposal(&pic, upgrader, rid).outcome,
        ActionOutcome::Executed,
        "the recovery plane is not merely reachable again — it executes"
    );
}
