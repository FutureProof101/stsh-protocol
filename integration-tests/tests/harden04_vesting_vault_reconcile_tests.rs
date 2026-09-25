// =============================================================================
// LAUNCH-HARDEN-04 O-7 — vesting: the reconcile-claim authority becomes the
// Vault, via a typed upgrade-arg rebind carried by a Vault `Management` Upgrade.
// =============================================================================
//
// Real Wasms end to end: the custody ring (Vault 2-of-3 + Upgrader), the real
// token, and vesting CREATED, INSTALLED and UPGRADED by Vault proposals — the
// production shape of cfxs7 (IC controller = the Vault).
//
// The Vault's Candid types are MIRRORED LOCALLY (encode-side subsets, decode
// side via `candid::Reserved` where a full mirror is not needed): taking
// `stsh_custody_types` as a dev-dependency would be a Cargo.toml edit this lane
// may not make. Candid is structural, so a subset enum encodes exactly the
// variant the Vault decodes.
//
// T1 acceptance (pre-rebind refusal → hash-bound Vault Upgrade → readback →
//    post-rebind Vault reconcile succeeds → the old controller is refused);
// T2 no-arg upgrades preserve; T3 rejected-op atomicity; T4 anonymous marker
// listing; T5 upgrade from the LIVE pre-change module preserves all state.

use candid::{CandidType, Deserialize, Nat, Principal};
use pocket_ic::PocketIc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Duration;

fn load_wasm(path: &str, label: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {label} wasm at {path}: {e}"))
}
fn vault_wasm() -> Vec<u8> { load_wasm(env!("VAULT_WASM"), "vault") }
fn upgrader_wasm() -> Vec<u8> { load_wasm(env!("UPGRADER_WASM"), "upgrader") }
fn vesting_wasm() -> Vec<u8> { load_wasm(env!("VESTING_WASM"), "vesting") }
fn token_wasm() -> Vec<u8> { load_wasm(env!("TOKEN_WASM"), "stsh_token") }

/// The LIVE cfxs7 module at the time of LAUNCH-HARDEN-04 — the `[wasm.vesting]`
/// pin before this lane (760488eb…, the A-7 install). Hash-checked here.
const LIVE_VESTING_SHA256: &str =
    "760488eb60d9b23bd3b612b122fb183ea5f9c1525208709e580956cf1ee59b27";

fn live_vesting_wasm() -> Vec<u8> {
    let path = std::path::Path::new(env!("VESTING_WASM"))
        .with_file_name("vesting_live_cfxs7_760488eb.wasm");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{} not found ({e}) — T5 needs the GENUINE live cfxs7 vesting module \
             (760488eb — the pre-LAUNCH-HARDEN-04 [wasm.vesting] pin, byte-identical to the \
             staged A-7 artifact ~/a7-kit/vesting.wasm and to a clean gate build of master \
             6709af8). Place it with:\n  cp ~/a7-kit/vesting.wasm {}\n  expected sha256: \
             {LIVE_VESTING_SHA256}",
            path.display(),
            path.display()
        )
    });
    assert_eq!(hex(&Sha256::digest(&bytes)), LIVE_VESTING_SHA256, "live vesting fixture has the WRONG hash");
    bytes
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn sha(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

const STSH: u128 = 100_000_000;
const TOTAL_SUPPLY: u128 = 1_000_000_000 * STSH;
const S1: u8 = 1;
const S2: u8 = 2;
const S3: u8 = 3;

fn p(b: u8) -> Principal {
    Principal::from_slice(&[b; 29])
}

// ── Vault / Upgrader mirrors (vault.did, upgrader.did) ───────────────────────

#[derive(CandidType, Deserialize)]
struct VaultInitArgs { signers: Vec<Principal>, threshold: u32, upgrader: Principal }

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq)]
enum ManifestDisposition { BornUnderVault, SetControllerAtCutover, OutOfScope }

#[derive(CandidType, Deserialize)]
struct GovernedTarget { principal: Principal, disposition: ManifestDisposition, purpose: String }

#[derive(CandidType, Deserialize)]
struct VaultInit { quorum: VaultInitArgs, cutover_targets: Vec<GovernedTarget> }

#[derive(CandidType, Deserialize)]
struct UpgraderInitArgs { recovery_members: Vec<Principal>, threshold: u32, vault: Principal }

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
enum ClaimDecision { Executed, NotExecuted }

/// Encode-side SUBSET of the Vault's `ActionRequest`.
#[derive(CandidType)]
enum ActionRequest {
    VestingReconcileClaim(Principal, ClaimDecision),
}

/// Encode-side SUBSET of the Vault's `ManagementAction`.
#[derive(CandidType)]
enum ManagementAction {
    Upgrade {
        target: Principal,
        expected_wasm_hash: Vec<u8>,
        expected_arg_hash: Vec<u8>,
        wasm_bytes: Vec<u8>,
        arg_bytes: Vec<u8>,
    },
    CreateCanister { manifest_purpose: String, disposition: ManifestDisposition },
    InstallCode {
        target: Principal,
        expected_wasm_hash: Vec<u8>,
        expected_arg_hash: Vec<u8>,
        wasm_bytes: Vec<u8>,
        arg_bytes: Vec<u8>,
    },
}

/// Encode-side SUBSET of the Vault's `VaultActionKind`.
#[derive(CandidType)]
enum VaultActionKind {
    Application(ActionRequest),
    Management(ManagementAction),
}

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq)]
enum ActionOutcome { Pending, Executing, Executed, Failed, OutcomeUnknown, Cancelled, Expired }

/// Decode-side subset of `ProposalView` (record width subtyping ignores the rest).
#[derive(CandidType, Deserialize, Debug)]
struct ProposalView {
    proposal_id: u64,
    outcome: ActionOutcome,
    result: Option<String>,
    commitment_hash: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq)]
enum CreationReceiptStatus { Bound, OrphanedPurposeConflict }

#[derive(CandidType, Deserialize, Debug)]
struct CreationReceipt {
    proposal_id: u64,
    principal: Principal,
    purpose: String,
    disposition: ManifestDisposition,
    created_at_ns: u64,
    status: CreationReceiptStatus,
}

#[derive(CandidType, Deserialize, Debug)]
struct CreationReceiptPage { items: Vec<CreationReceipt>, next_cursor: Option<u64> }

// ── Token + vesting mirrors ─────────────────────────────────────────────────

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
struct NewSchedule { beneficiary: Principal, total_amount: u128, cliff_months: u32, linear_months: u32 }
#[derive(CandidType, Deserialize)]
struct VestingInitArgs { token_canister: Principal, controller: Principal, schedules: Vec<NewSchedule> }

/// Mirror of vesting's `VestingUpgradeArg` (LAUNCH-HARDEN-04 O-7).
#[derive(CandidType, Deserialize)]
struct VestingUpgradeArg { rebind_controller: Option<Principal> }

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
struct CanisterRefsReadback { token_canister: Principal, controller: Principal }

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
struct VestingSchedule {
    beneficiary: Principal,
    total_amount: u128,
    cliff_end_ns: u64,
    vesting_end_ns: u64,
    claimed: u128,
    start_ns: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
enum ClaimMarkerState { InFlight, Stuck }
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
struct OutstandingClaimMarker {
    beneficiary: Principal,
    state: ClaimMarkerState,
    pending_amount: Option<u128>,
    claim_seq: Option<u64>,
    created_at_time_ns: Option<u64>,
}
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
enum OutstandingClaimMarkerError { NotController, ControllerNotConfigured }

// ── Harness ──────────────────────────────────────────────────────────────────

struct Rig {
    pic: PocketIc,
    vault: Principal,
    token: Principal,
    vesting: Principal,
    /// The genesis reconcile controller stand-in (fshhc on mainnet).
    legacy: Principal,
    beneficiary: Principal,
}

fn decode<T: CandidType + for<'de> Deserialize<'de>>(label: &str, r: Result<Vec<u8>, pocket_ic::RejectResponse>) -> T {
    let bytes = r.unwrap_or_else(|e| panic!("{label}: rejected: {e:?}"));
    candid::decode_one(&bytes).unwrap_or_else(|e| panic!("{label}: decode failed: {e}"))
}

impl Rig {
    fn propose(&self, action: VaultActionKind) -> u64 {
        let bytes = self
            .pic
            .update_call(self.vault, p(S1), "propose", candid::encode_args((action, None::<u64>)).unwrap())
            .expect("propose call");
        let r: Result<u64, candid::Reserved> = candid::decode_one(&bytes).expect("decode propose");
        r.unwrap_or_else(|_| {
            panic!("propose refused: {}", candid::IDLArgs::from_bytes(&bytes).map(|a| a.to_string()).unwrap_or_default())
        })
    }
    fn proposal(&self, id: u64) -> ProposalView {
        let v: Option<ProposalView> = decode(
            "get_proposal",
            self.pic.query_call(self.vault, p(S1), "get_proposal", candid::encode_one(id).unwrap()),
        );
        v.expect("signer reads its proposal")
    }
    fn approve(&self, signer: u8, id: u64) {
        let hash = self.proposal(id).commitment_hash;
        let raw = self
            .pic
            .update_call(self.vault, p(signer), "approve", candid::encode_args((id, hash)).unwrap());
        // The reply may be any ApprovalOutcome / VaultError; the proposal view is
        // what the tests assert on.
        let _ = raw;
    }
    /// Propose, approve 2-of-3, return the settled view.
    fn run(&self, action: VaultActionKind) -> ProposalView {
        let id = self.propose(action);
        self.approve(S1, id);
        self.approve(S2, id);
        self.proposal(id)
    }
    fn readback(&self) -> CanisterRefsReadback {
        let r: Result<CanisterRefsReadback, String> = decode(
            "get_canister_refs_readback",
            self.pic.query_call(self.vesting, Principal::anonymous(), "get_canister_refs_readback", candid::encode_args(()).unwrap()),
        );
        r.expect("readback")
    }
    fn schedules_bytes(&self) -> Vec<u8> {
        self.pic
            .query_call(self.vesting, Principal::anonymous(), "list_schedules", candid::encode_args(()).unwrap())
            .expect("list_schedules")
    }
    fn schedule(&self) -> VestingSchedule {
        let s: Option<VestingSchedule> = decode(
            "get_schedule",
            self.pic.query_call(self.vesting, Principal::anonymous(), "get_schedule", candid::encode_one(self.beneficiary).unwrap()),
        );
        s.expect("schedule")
    }
    fn markers(&self, caller: Principal) -> Result<Vec<OutstandingClaimMarker>, OutstandingClaimMarkerError> {
        decode(
            "list_outstanding_claim_markers",
            self.pic.query_call(self.vesting, caller, "list_outstanding_claim_markers", candid::encode_args(()).unwrap()),
        )
    }
    fn claim(&self) -> Result<Nat, String> {
        decode("claim", self.pic.update_call(self.vesting, self.beneficiary, "claim", candid::encode_args(()).unwrap()))
    }
    /// Force a transport-unknown claim: stop the token, claim, start it again.
    fn make_stuck(&self) {
        self.pic.stop_canister(self.token, None).expect("stop token");
        let r = self.claim();
        assert!(r.as_ref().unwrap_err().contains("TransferOutcomeUnknown"), "got {r:?}");
        self.pic.start_canister(self.token, None).expect("start token");
    }
    fn upgrade_via_vault(&self, wasm: Vec<u8>, arg: Vec<u8>) -> ProposalView {
        self.run(VaultActionKind::Management(ManagementAction::Upgrade {
            target: self.vesting,
            expected_wasm_hash: sha(&wasm),
            expected_arg_hash: sha(&arg),
            wasm_bytes: wasm,
            arg_bytes: arg,
        }))
    }
    fn reconcile_via_vault(&self, decision: ClaimDecision) -> ProposalView {
        self.run(VaultActionKind::Application(ActionRequest::VestingReconcileClaim(self.beneficiary, decision)))
    }
}

/// The ring (Vault 2-of-3 + Upgrader), then vesting CREATED and INSTALLED by
/// Vault proposals with `controller = legacy` — the pre-rebind mainnet shape.
fn rig_with(vesting_install_wasm: Vec<u8>) -> Rig {
    let pic = PocketIc::new();
    let upgrader = pic.create_canister();
    let vault = pic.create_canister();
    pic.add_cycles(upgrader, 10_000_000_000_000u128);
    pic.add_cycles(vault, 100_000_000_000_000u128);
    pic.install_canister(
        upgrader,
        upgrader_wasm(),
        candid::encode_one(UpgraderInitArgs { recovery_members: vec![p(11), p(12), p(13)], threshold: 2, vault }).unwrap(),
        None,
    );
    let vinit = VaultInit {
        quorum: VaultInitArgs { signers: vec![p(S1), p(S2), p(S3)], threshold: 2, upgrader },
        // The Vault's baked manifest cutover set (vault.did / custody_manifest.toml).
        cutover_targets: vec![
            GovernedTarget {
                principal: Principal::from_text("pyeop-7yaaa-aaaam-ajfja-cai").unwrap(),
                disposition: ManifestDisposition::SetControllerAtCutover,
                purpose: "solvency_status".to_string(),
            },
            GovernedTarget {
                principal: Principal::from_text("s3tyu-aaaaa-aaaab-qhdjq-cai").unwrap(),
                disposition: ManifestDisposition::SetControllerAtCutover,
                purpose: "wallet_frontend".to_string(),
            },
        ],
    };
    pic.install_canister(vault, vault_wasm(), candid::encode_one(vinit).unwrap(), None);
    pic.set_controllers(vault, None, vec![upgrader]).unwrap();
    pic.set_controllers(upgrader, None, vec![vault]).unwrap();

    let mut rig = Rig {
        pic,
        vault,
        token: Principal::anonymous(),
        vesting: Principal::anonymous(),
        legacy: p(0x4C),
        beneficiary: p(0xB1),
    };

    // (b) CreateCanister{"vesting", BornUnderVault}.
    let created = rig.run(VaultActionKind::Management(ManagementAction::CreateCanister {
        manifest_purpose: "vesting".to_string(),
        disposition: ManifestDisposition::BornUnderVault,
    }));
    assert_eq!(created.outcome, ActionOutcome::Executed, "create: {:?}", created.result);
    let page: Option<CreationReceiptPage> = decode(
        "get_creation_receipts",
        rig.pic.query_call(vault, p(S1), "get_creation_receipts", candid::encode_args((None::<u64>, 128u32)).unwrap()),
    );
    let receipt = page
        .expect("signer reads receipts")
        .items
        .into_iter()
        .find(|r| r.purpose == "vesting" && r.status == CreationReceiptStatus::Bound)
        .expect("a Bound vesting receipt");
    rig.vesting = receipt.principal;
    rig.pic.add_cycles(rig.vesting, 5_000_000_000_000u128);

    // The real token, all supply to the vesting canister (test-owned).
    rig.token = rig.pic.create_canister();
    rig.pic.add_cycles(rig.token, 2_000_000_000_000u128);
    let tinit = TokenInitArgs {
        allocations: vec![AllocationCategory {
            category_id: "all".into(),
            category_name: "All tokens".into(),
            amount: TOTAL_SUPPLY,
            recipient: rig.vesting,
            subaccount: None,
            lock_policy: LockPolicy::ImmediatelyLiquid,
            vesting_policy: None,
            created_at_genesis: false,
            genesis_timestamp_ns: 0,
        }],
        treasury: p(0x91),
        staking_canister: p(0x92),
    };
    rig.pic.install_canister(rig.token, token_wasm(), candid::encode_one(tinit).unwrap(), None);

    // Hash-bound InstallCode of vesting via the Vault.
    let init = candid::encode_one(VestingInitArgs {
        token_canister: rig.token,
        controller: rig.legacy,
        schedules: vec![NewSchedule { beneficiary: rig.beneficiary, total_amount: 5 * STSH, cliff_months: 0, linear_months: 1 }],
    })
    .unwrap();
    let installed = rig.run(VaultActionKind::Management(ManagementAction::InstallCode {
        target: rig.vesting,
        expected_wasm_hash: sha(&vesting_install_wasm),
        expected_arg_hash: sha(&init),
        wasm_bytes: vesting_install_wasm,
        arg_bytes: init,
    }));
    assert_eq!(installed.outcome, ActionOutcome::Executed, "install: {:?}", installed.result);
    rig.pic.advance_time(Duration::from_secs(31 * 24 * 3600));
    rig.pic.tick();
    rig
}

fn rebind_arg(p: Principal) -> Vec<u8> {
    candid::encode_args((Some(VestingUpgradeArg { rebind_controller: Some(p) }),)).unwrap()
}

/// §R — the packet's vesting arg bytes, recomputed from these mirrors.
#[test]
fn harden04_packet_vesting_upgrade_arg_bytes_are_exact() {
    let vault = Principal::from_text("cpdab-saaaa-aaaar-qca2q-cai").unwrap();
    let bytes = rebind_arg(vault);
    assert_eq!(hex(&bytes), "4449444c036e016c01cbf98cb604026e6801000101010a00000000023010350101");
    assert_eq!(hex(&sha(&bytes)), "84bd8f408cb773bc63f20cfb46e3a1420a9cc577025efc19cf03a5b1ea394fac");
}

/// T1 (acceptance) + T4 (anonymous listing).
#[test]
fn t1_vault_rebind_makes_the_vault_the_reconcile_authority() {
    let r = rig_with(vesting_wasm());
    assert_eq!(r.readback(), CanisterRefsReadback { token_canister: r.token, controller: r.legacy });

    // (c) a stuck claim.
    r.make_stuck();
    let stuck_amount = r.schedule().claimed;
    assert_eq!(stuck_amount, 5 * STSH, "claimed pre-incremented while stuck");

    // T4: an ANONYMOUS listing returns the stuck marker.
    let rows = r.markers(Principal::anonymous()).expect("anonymous-readable");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].beneficiary, r.beneficiary);
    assert_eq!(rows[0].state, ClaimMarkerState::Stuck);
    assert_eq!(rows[0].pending_amount, Some(5 * STSH));

    // (d) PRE-rebind: the Vault is not the reconcile controller.
    let pre = r.reconcile_via_vault(ClaimDecision::NotExecuted);
    assert_eq!(pre.outcome, ActionOutcome::Failed, "{pre:?}");
    assert!(
        pre.result.as_deref().unwrap_or("").contains("Only the controller may reconcile claims"),
        "{pre:?}"
    );

    // (e) the hash-bound Vault Management Upgrade with the rebind arg.
    let schedules_before = r.schedules_bytes();
    let up = r.upgrade_via_vault(vesting_wasm(), rebind_arg(r.vault));
    assert_eq!(up.outcome, ActionOutcome::Executed, "{up:?}");

    // (f) readback: controller == vault, token unchanged, schedules identical.
    assert_eq!(r.readback(), CanisterRefsReadback { token_canister: r.token, controller: r.vault });
    assert_eq!(r.schedules_bytes(), schedules_before, "list_schedules byte-identical");

    // (g) POST-rebind: the Vault reconcile succeeds and reverts exactly the stuck amount.
    let post = r.reconcile_via_vault(ClaimDecision::NotExecuted);
    assert_eq!(post.outcome, ActionOutcome::Executed, "{post:?}");
    assert_eq!(r.schedule().claimed, 0, "claimed reverted by exactly the stuck amount");
    assert!(r.markers(Principal::anonymous()).unwrap().is_empty(), "marker cleared (tombstoned)");

    // (h) the legacy controller is refused directly.
    let direct: Result<(), String> = decode(
        "reconcile_claim",
        r.pic.update_call(r.vesting, r.legacy, "reconcile_claim", candid::encode_args((r.beneficiary, ClaimDecision::Executed)).unwrap()),
    );
    assert!(direct.unwrap_err().contains("Only the controller"), "legacy controller refused");

    // The beneficiary can claim again after the revert.
    r.claim().expect("re-claim after NotExecuted");
}

/// T2 — upgrades with `b""` and with `()` preserve the controller.
#[test]
fn t2_no_arg_upgrades_preserve_the_controller() {
    let r = rig_with(vesting_wasm());
    let up = r.upgrade_via_vault(vesting_wasm(), rebind_arg(r.vault));
    assert_eq!(up.outcome, ActionOutcome::Executed, "{up:?}");
    for arg in [Vec::new(), candid::encode_args(()).unwrap(), candid::encode_one(None::<VestingUpgradeArg>).unwrap()] {
        let v = r.upgrade_via_vault(vesting_wasm(), arg.clone());
        assert_eq!(v.outcome, ActionOutcome::Executed, "arg {}: {v:?}", hex(&arg));
        assert_eq!(r.readback().controller, r.vault, "arg {} must preserve", hex(&arg));
    }
}

/// T3 — rejected-op atomicity: a rebind to anonymous, a non-controller, the
/// token, or the canister itself FAILS the upgrade; readback and schedules are
/// unchanged and the old Wasm still serves.
#[test]
fn t3_rejected_rebind_traps_the_whole_upgrade() {
    // One fresh rig per case: a trapped Management Upgrade leaves the Vault
    // proposal un-Executed (the Vault does not treat an IC reject as success),
    // and the Vault then fences further management of that target until the
    // outcome is reconciled — the Vault's own discipline, not this lane's.
    for case in 0..4 {
        let r = rig_with(vesting_wasm());
        let before = r.readback();
        let sched = r.schedules_bytes();
        let (label, target) = match case {
            0 => ("anonymous", Principal::anonymous()),
            1 => ("non-controller", p(0x5E)),
            2 => ("the token", r.token),
            _ => ("itself", r.vesting),
        };
        let v = r.upgrade_via_vault(vesting_wasm(), rebind_arg(target));
        assert_ne!(v.outcome, ActionOutcome::Executed, "{label}: the upgrade must fail: {v:?}");
        assert_eq!(r.readback(), before, "{label}: readback unchanged");
        assert_eq!(r.schedules_bytes(), sched, "{label}: schedules unchanged");
        // The old module still serves an ordinary call.
        assert!(r.markers(Principal::anonymous()).is_ok(), "{label}: old module serves");
    }
}

/// T5 — an upgrade FROM the live pre-change module (760488eb) preserves all
/// state, and the rebind works on that path.
#[test]
fn t5_upgrade_from_the_live_module_preserves_state_and_rebinds() {
    let r = rig_with(live_vesting_wasm());
    r.make_stuck();
    let sched = r.schedules_bytes();
    // The live module still gates the listing: the controller reads it.
    let pre_rows: Result<Vec<OutstandingClaimMarker>, OutstandingClaimMarkerError> = r.markers(r.legacy);
    let pre_rows = pre_rows.expect("the legacy controller reads the pre-change listing");
    assert_eq!(pre_rows.len(), 1);

    let up = r.upgrade_via_vault(vesting_wasm(), rebind_arg(r.vault));
    assert_eq!(up.outcome, ActionOutcome::Executed, "{up:?}");
    assert_eq!(r.schedules_bytes(), sched, "schedules byte-identical across the cross-Wasm upgrade");
    assert_eq!(r.markers(Principal::anonymous()).unwrap(), pre_rows, "the stuck marker survives");
    assert_eq!(r.readback(), CanisterRefsReadback { token_canister: r.token, controller: r.vault });
    let post = r.reconcile_via_vault(ClaimDecision::Executed);
    assert_eq!(post.outcome, ActionOutcome::Executed, "{post:?}");
}
