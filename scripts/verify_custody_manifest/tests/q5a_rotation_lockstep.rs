// Q5-A — the rotation-aware init lockstep.
//
// WHY THIS FILE EXISTS. Three deploy-time checks compare the pins in
// `deployment/mainnet/vault_authorities.toml` to the IMMUTABLE install payloads
// (`vault_init.did`, `upgrader_init.did`). ROT-LEDGER-FILL rewrites those pins
// to the POST-rotation roster, so on a CORRECT rotated record all three would go
// RED. Q5-A repairs that without relaxing anything: post-rotation the init
// payloads are judged against `[rotation.bootstrap]` (the install-time
// snapshot), and the pins against the LAST EXECUTED row of the matching plane.
//
// FIXTURE DISCIPLINE (carried from tests/rotation_ledger.rs:3-19). Every
// negative starts from a baseline ASSERTED to pass, injects EXACTLY ONE change,
// asserts the change took effect, and asserts the IDENTITY of the surface that
// disagreed. Because Addendum 1 reuses the existing violation KINDS
// (`AuthorityBindingViolation` / `RecoveryRosterViolation`), identity here is
// the surface MARKER in the message, and every negative also asserts that the
// OTHER surface's marker is ABSENT — otherwise one failure could stand in as
// the witness for another. No expected value is read from the committed record.

use verify_custody_manifest as vcm;
use vcm::Violation;

// PRE-rotation set (II/dfx-shaped) and POST-rotation set (canister-rooted).
// Neither is read from the committed record, and neither contains the Vault or
// the Upgrader principal — a roster that names its own counterpart is a
// different, pre-existing defect and must not be the witness for these.
const P1: &str = "5jmfd-2u6rs-j5c3d-jhmmq-3ri63-iha4r-l5vwb-smaqn-bjodx-y4alu-qae";
const P2: &str = "lwiax-bc6fp-osh2p-jhbyc-tpxjl-ir24x-o5pde-gtzl2-4ht56-ikt6h-oqe";
const P3: &str = "4f6wg-dzscu-4ixsl-t57n5-tiilb-4tqcj-i6vzi-3qvqt-5y5fu-d6b6y-cae";
const B1: &str = "ib4mm-7l7xb-lc4bu-t25ya-t3ahs-5zvaz-kkfef-5ezep-pbngz-mexxv-sae";
const B2: &str = "m3y6b-2wc5k-7c5xs-52q73-wg5hs-lv5bw-zjusd-t7bgg-olw3q-7wkkl-6ae";
const B3: &str = "rdmx6-jaaaa-aaaaa-aaadq-cai";
// A fourth POST-shaped principal, for the one-principal-disagreement fixtures.
const B3B: &str = "mxzaz-hqaaa-aaaar-qaada-cai";
const VAULT: &str = "cpdab-saaaa-aaaar-qca2q-cai";
const UPG: &str = "cgal5-eiaaa-aaaar-qca3a-cai";

fn p(s: &str) -> candid::Principal {
    candid::Principal::from_text(s).unwrap()
}
fn v3(a: &str, b: &str, c: &str) -> Vec<candid::Principal> {
    vec![p(a), p(b), p(c)]
}

// ── record text → lockstep ──────────────────────────────────────────────────
//
// The lockstep is always built by the crate's own parser from a record TEXT, so
// these tests exercise the real record → lockstep → comparison path rather than
// a hand-built struct that could diverge from what the file actually says.

struct Rec {
    state: &'static str,
    boot_vault: [&'static str; 3],
    boot_upg: [&'static str; 3],
    boot_vault_threshold: u32,
    boot_upg_threshold: u32,
    /// (sequence, status, new_members, new_threshold) per plane.
    upg_rows: Vec<(u32, &'static str, [&'static str; 3], u32)>,
    vault_rows: Vec<(u32, &'static str, [&'static str; 3], u32)>,
}

impl Rec {
    /// The shape ROT-LEDGER-FILL leaves behind: rotated, snapshot still PRE,
    /// one EXECUTED row per plane carrying the POST set.
    fn rotated() -> Rec {
        Rec {
            state: "rotated",
            boot_vault: [P1, P2, P3],
            boot_upg: [P1, P2, P3],
            boot_vault_threshold: 2,
            boot_upg_threshold: 2,
            upg_rows: vec![(1, "EXECUTED", [B1, B2, B3], 2)],
            vault_rows: vec![(1, "EXECUTED", [B1, B2, B3], 2)],
        }
    }
    fn pending() -> Rec {
        Rec { state: "not-yet-performed", upg_rows: vec![], vault_rows: vec![], ..Rec::rotated() }
    }

    fn text(&self) -> String {
        let arr = |x: &[&str; 3]| format!("[\n  \"{}\",\n  \"{}\",\n  \"{}\",\n]", x[0], x[1], x[2]);
        let mut s = format!(
            "[rotation]\nschema_version = 1\nstate = \"{}\"\n\n\
             [rotation.bootstrap]\nvault_signers = {}\nvault_threshold = {}\n\
             upgrader_members = {}\nupgrader_threshold = {}\nvault_epoch = 0\n\
             snapshot_of_pins_at_commit = \"0000000000000000000000000000000000000000\"\n\n",
            self.state,
            arr(&self.boot_vault),
            self.boot_vault_threshold,
            arr(&self.boot_upg),
            self.boot_upg_threshold,
        );
        for (plane, rows) in [("upgrader", &self.upg_rows), ("vault", &self.vault_rows)] {
            for (seq, status, new, th) in rows.iter() {
                s += &format!(
                    "[[rotation.{plane}]]\nsequence = {seq}\nstatus = \"{status}\"\n\
                     old_members = [\"{P1}\", \"{P2}\", \"{P3}\"]\nnew_members = {}\n\
                     old_threshold = 2\nnew_threshold = {th}\n",
                    arr(new)
                );
                if plane == "vault" {
                    s += "old_epoch = 0\nnew_epoch = 1\nafter_upgrader_sequence = 1\n";
                }
                s += &format!(
                    "proposal_id = {}\napprovers = [\"{P1}\", \"{P3}\"]\n\
                     observed_at_ns = 1789819200000000000\nobserved_at_utc = \"2026-09-19T12:00:00Z\"\n\
                     network = \"ic\"\ncanister = \"{}\"\nread_by = \"{P1}\"\n\
                     readback_command = \"dfx canister --network ic call <c> get_x '()'\"\n\
                     readback_evidence_path = \"deployment/mainnet/evidence/x.txt\"\n\
                     readback_output_sha256 = \"00\"\npredecessor_row_sha256 = \"\"\n\n",
                    if plane == "vault" { 16 + *seq as u64 } else { *seq as u64 },
                    if plane == "vault" { VAULT } else { UPG },
                );
            }
        }
        s
    }

    fn lockstep(&self) -> vcm::RotationLockstep {
        vcm::rotation_lockstep_from_record(&self.text())
            .unwrap_or_else(|e| panic!("fixture record must yield a lockstep: {e}"))
    }
}

// ── the two checks under test, wrapped ──────────────────────────────────────

/// The Vault leg: `vault_init.did` signers/threshold vs the pinned `signers`.
fn vault_leg(
    init: &[candid::Principal],
    init_threshold: u32,
    pin: &[candid::Principal],
    pin_threshold: u32,
    l: Option<&vcm::RotationLockstep>,
) -> Vec<Violation> {
    let rec = vcm::AuthorityRecord {
        signers: pin.to_vec(),
        threshold: pin_threshold,
        upgrader: p(UPG),
    };
    vcm::authority_violations_with_rotation(init, init_threshold, &p(UPG), Some(&rec), l)
}

/// The Upgrader leg: `upgrader_init.did` recovery_members/threshold and the
/// `vault_init.did` signers vs the pinned `[recovery].members`.
fn upgrader_leg(
    upgrader_init: &[candid::Principal],
    upgrader_init_threshold: u32,
    vault_init_signers: &[candid::Principal],
    pin: &[candid::Principal],
    l: Option<&vcm::RotationLockstep>,
) -> Vec<Violation> {
    let rec = vcm::RecoveryRecord { members: pin.to_vec(), threshold: 2, vault: p(VAULT) };
    vcm::recovery_roster_violations_with_rotation(
        Some(&rec),
        vault_init_signers,
        Some((upgrader_init, upgrader_init_threshold, &p(VAULT))),
        l,
    )
}

fn details(v: &[Violation]) -> String {
    v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("\n")
}

/// Identity assertion: the named marker is present, and every OTHER marker is
/// absent. Isolation is the point — a test that only asked "did it fail" would
/// accept the wrong surface's failure as its witness.
const MARKERS: &[&str] = &[
    "pin != ledger (vault plane)",
    "pin != ledger (upgrader plane)",
    "init != bootstrap (vault plane)",
    "init != bootstrap (upgrader plane)",
    "live cross-plane: upgrader != vault",
    "install cross-plane: bootstrap upgrader_members != bootstrap vault_signers",
    "surface 1 != surface 2",
    "surface 3 != surface 1",
    "init signer set != pinned record signer set",
];

/// The violation ENUM the surface under test must report. Matching only the
/// rendered message would accept a different variant that happened to render
/// the same words (SSA landed-diff C-1(a)); the kind and the marker are
/// asserted together, and every violation returned must be of that kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// `Violation::AuthorityBindingViolation` — the Vault quorum surface.
    Authority,
    /// `Violation::RecoveryRosterViolation` — the Upgrader recovery surface.
    Roster,
}

fn is_kind(v: &Violation, k: Kind) -> bool {
    matches!(
        (v, k),
        (Violation::AuthorityBindingViolation { .. }, Kind::Authority)
            | (Violation::RecoveryRosterViolation { .. }, Kind::Roster)
    )
}

/// The general form: EVERY returned violation is `kind`, EVERY marker in
/// `expected` is present, and every OTHER marker in [`MARKERS`] is absent.
///
/// A negative that legitimately fires on two surfaces at once still goes
/// through the typed path (SSA closure C-1: the pending upgrader negative used
/// to drop the vector into rendered text and never checked the variant).
fn assert_markers(v: &[Violation], kind: Kind, expected: &[&str], ctx: &str) {
    let d = details(v);
    assert!(!v.is_empty(), "{ctx}: expected a violation, got none");
    // TYPED identity first: every violation returned is the variant this
    // surface is supposed to report, not merely something that renders alike.
    for x in v {
        assert!(
            is_kind(x, kind),
            "{ctx}: expected every violation to be {kind:?}, got {x:?}"
        );
    }
    for marker in expected {
        assert!(d.contains(marker), "{ctx}: expected marker `{marker}`, got:\n{d}");
    }
    for m in MARKERS {
        if expected.contains(m) {
            continue;
        }
        assert!(
            !d.contains(m),
            "{ctx}: marker `{m}` must NOT also fire — the intended comparison would then not be \
             the witness. Got:\n{d}"
        );
    }
}

/// The single-marker case, which is most of them.
fn assert_only(v: &[Violation], kind: Kind, marker: &str, ctx: &str) {
    assert_markers(v, kind, &[marker], ctx);
}

// ═══ A-4(i) — the positive control ═══════════════════════════════════════════

#[test]
fn a4_i_rotated_record_pins_post_init_bootstrap_passes() {
    let r = Rec::rotated();
    let l = r.lockstep();
    assert!(l.rotated, "the fixture must actually be rotated");

    let pre = v3(P1, P2, P3);
    let post = v3(B1, B2, B3);

    let v = vault_leg(&pre, 2, &post, 2, Some(&l));
    assert!(v.is_empty(), "rotated vault leg must pass, got:\n{}", details(&v));
    let v = upgrader_leg(&pre, 2, &pre, &post, Some(&l));
    assert!(v.is_empty(), "rotated upgrader leg must pass, got:\n{}", details(&v));
}

// ═══ A-4(iv) — the not-yet-performed control ════════════════════════════════

#[test]
fn a4_iv_pending_record_behaviour_is_unchanged() {
    let r = Rec::pending();
    let l = r.lockstep();
    assert!(!l.rotated, "the fixture must NOT be rotated");
    let pre = v3(P1, P2, P3);
    let post = v3(B1, B2, B3);
    assert_ne!(
        pre, post,
        "the rewritten-pin mutation below must actually change the pins — asserted, not left \
         to be inferred from differing literals"
    );

    // Pins == init: passes, exactly as before Q5-A, and identically to `None`.
    assert!(vault_leg(&pre, 2, &pre, 2, Some(&l)).is_empty());
    assert!(vault_leg(&pre, 2, &pre, 2, None).is_empty());
    assert!(upgrader_leg(&pre, 2, &pre, &pre, Some(&l)).is_empty());
    assert!(upgrader_leg(&pre, 2, &pre, &pre, None).is_empty());

    // Pins rewritten WITHOUT flipping the state is still the old failure: the
    // pre-rotation comparisons are not weakened by the existence of Q5-A.
    assert_only(
        &vault_leg(&pre, 2, &post, 2, Some(&l)),
        Kind::Authority,
        "init signer set != pinned record signer set",
        "pending + rewritten signers",
    );
    // Pre-rotation, a rewritten `[recovery].members` pin disagrees with BOTH
    // install-time surfaces at once — which is exactly why the pin rewrite could
    // not land without Q5-A. TWO markers are expected here, so this goes through
    // `assert_markers` rather than being dropped into rendered text: the typed
    // `RecoveryRosterViolation` identity is asserted for every returned
    // violation, both legacy markers are required, and every rotation-aware
    // marker is required ABSENT.
    assert_markers(
        &upgrader_leg(&pre, 2, &pre, &post, Some(&l)),
        Kind::Roster,
        &["surface 1 != surface 2", "surface 3 != surface 1"],
        "pending + rewritten members (both install-time surfaces disagree)",
    );
}

// ═══ A-4(ii) — pins still the PRE set on a rotated record ═══════════════════

#[test]
fn a4_ii_rotated_but_pins_not_rewritten_is_the_pin_ledger_violation() {
    let r = Rec::rotated();
    let l = r.lockstep();
    let pre = v3(P1, P2, P3);
    let post = v3(B1, B2, B3);
    // Baseline passes.
    assert!(vault_leg(&pre, 2, &post, 2, Some(&l)).is_empty(), "baseline");
    assert!(upgrader_leg(&pre, 2, &pre, &post, Some(&l)).is_empty(), "baseline");

    // ONE change: the pins were never rewritten.
    assert_ne!(pre, post, "the mutation must actually change the pins");
    assert_only(
        &vault_leg(&pre, 2, &pre, 2, Some(&l)),
        Kind::Authority,
        "pin != ledger (vault plane)",
        "A-4(ii) vault plane",
    );
    assert_only(
        &upgrader_leg(&pre, 2, &pre, &pre, Some(&l)),
        Kind::Roster,
        "pin != ledger (upgrader plane)",
        "A-4(ii) upgrader plane",
    );
}

#[test]
fn a4_ii_pin_threshold_is_compared_to_the_row_not_only_the_members() {
    // The row's new_threshold is 3 while the pin says 2. Members agree, so the
    // ONLY thing that can fire is the threshold leg of the same comparison.
    let pre = v3(P1, P2, P3);
    let post = v3(B1, B2, B3);

    // BASELINE, on the UNMUTATED fixture and with the SAME arguments the
    // negative below uses: both surfaces pass. Without this the negative could
    // be failing for a reason that predates the mutation.
    let ok = Rec::rotated().lockstep();
    assert_eq!(ok.last_vault_new_threshold, 2, "baseline row threshold");
    assert_eq!(ok.last_upgrader_new_threshold, 2, "baseline row threshold");
    assert!(vault_leg(&pre, 2, &post, 2, Some(&ok)).is_empty(), "vault baseline");
    assert!(upgrader_leg(&pre, 2, &pre, &post, Some(&ok)).is_empty(), "upgrader baseline");

    // ONE change: the last EXECUTED row of each plane now records threshold 3.
    let mut r = Rec::rotated();
    r.vault_rows = vec![(1, "EXECUTED", [B1, B2, B3], 3)];
    r.upg_rows = vec![(1, "EXECUTED", [B1, B2, B3], 3)];
    let l = r.lockstep();
    assert_eq!(l.last_vault_new_threshold, 3, "the mutation must have taken effect");
    assert_eq!(l.last_upgrader_new_threshold, 3, "the mutation must have taken effect");
    assert_eq!(
        l.last_vault_new_members, ok.last_vault_new_members,
        "members must NOT have moved, or the threshold leg is not isolated"
    );
    let v = vault_leg(&pre, 2, &post, 2, Some(&l));
    assert_only(&v, Kind::Authority, "pin != ledger (vault plane)", "A-4(ii) vault threshold");
    assert!(details(&v).contains("new_threshold 3"), "{}", details(&v));
    let v = upgrader_leg(&pre, 2, &pre, &post, Some(&l));
    assert_only(&v, Kind::Roster, "pin != ledger (upgrader plane)", "A-4(ii) upgrader threshold");
}

// ═══ A-4(iii) — an init .did edited to the POST set ═════════════════════════

#[test]
fn a4_iii_init_did_edited_to_the_post_set_is_the_init_bootstrap_violation() {
    let r = Rec::rotated();
    let l = r.lockstep();
    let pre = v3(P1, P2, P3);
    let post = v3(B1, B2, B3);
    // BASELINE for BOTH surfaces, each with the arguments its own negative
    // uses below — the upgrader baseline was missing (SSA C-1(a)).
    assert!(vault_leg(&pre, 2, &post, 2, Some(&l)).is_empty(), "vault baseline");
    assert!(upgrader_leg(&pre, 2, &pre, &post, Some(&l)).is_empty(), "upgrader baseline");
    assert_ne!(
        pre, post,
        "the init-payload mutation below must actually change the member vector — asserted, \
         not left to be inferred from differing literals"
    );
    assert_eq!(
        l.bootstrap_vault_signers, pre,
        "the snapshot must still hold the PRE set, or the negative is not about the init payload"
    );

    // ONE change: `vault_init.did` now claims the POST set.
    assert_only(
        &vault_leg(&post, 2, &post, 2, Some(&l)),
        Kind::Authority,
        "init != bootstrap (vault plane)",
        "A-4(iii) vault plane",
    );
    // ONE change: `upgrader_init.did` now claims the POST set. The vault_init
    // signers argument is left at PRE so only surface 3 has moved.
    assert_only(
        &upgrader_leg(&post, 2, &pre, &post, Some(&l)),
        Kind::Roster,
        "init != bootstrap (upgrader plane)",
        "A-4(iii) upgrader plane",
    );
}

#[test]
fn a4_iii_init_threshold_is_compared_to_the_bootstrap_threshold() {
    let pre = v3(P1, P2, P3);
    let post = v3(B1, B2, B3);

    // BASELINE on the unmutated fixture, same arguments as both negatives.
    let ok = Rec::rotated().lockstep();
    assert_eq!(ok.bootstrap_vault_threshold, 2, "baseline snapshot threshold");
    assert_eq!(ok.bootstrap_upgrader_threshold, 2, "baseline snapshot threshold");
    assert!(vault_leg(&pre, 2, &post, 2, Some(&ok)).is_empty(), "vault baseline");
    assert!(upgrader_leg(&pre, 2, &pre, &post, Some(&ok)).is_empty(), "upgrader baseline");

    // ONE change: both snapshot thresholds now read 3.
    let mut r = Rec::rotated();
    r.boot_vault_threshold = 3;
    r.boot_upg_threshold = 3;
    let l = r.lockstep();
    assert_eq!(l.bootstrap_vault_threshold, 3, "the mutation must have taken effect");
    assert_eq!(l.bootstrap_upgrader_threshold, 3, "the mutation must have taken effect");
    let v = vault_leg(&pre, 2, &post, 2, Some(&l));
    assert_only(&v, Kind::Authority, "init != bootstrap (vault plane)", "A-4(iii) vault threshold");
    let v = upgrader_leg(&pre, 2, &pre, &post, Some(&l));
    // Both bootstrap thresholds moved together, so the install cross-plane leg
    // stays quiet and surface 3 is the only witness.
    assert_only(&v, Kind::Roster, "init != bootstrap (upgrader plane)", "A-4(iii) upgrader threshold");
}

// ═══ A-4(v) — the two planes' LAST rows disagree (live cross-plane) ═════════

#[test]
fn a4_v_live_cross_plane_disagreement_by_one_principal() {
    let pre = v3(P1, P2, P3);
    let post = v3(B1, B2, B3);

    // BASELINE: on the unmutated fixture the two planes agree and BOTH legs
    // pass, including the upgrader leg that carries the negative below.
    let ok = Rec::rotated().lockstep();
    assert_eq!(
        ok.last_vault_new_members, ok.last_upgrader_new_members,
        "baseline: the planes must agree before the mutation"
    );
    assert!(vault_leg(&pre, 2, &post, 2, Some(&ok)).is_empty(), "vault baseline");
    assert!(upgrader_leg(&pre, 2, &pre, &post, Some(&ok)).is_empty(), "upgrader baseline");

    // ONE change: the Vault plane's last row names a different third principal.
    let mut r = Rec::rotated();
    r.vault_rows = vec![(1, "EXECUTED", [B1, B2, B3B], 2)];
    let l = r.lockstep();
    assert_ne!(
        l.last_vault_new_members, l.last_upgrader_new_members,
        "the mutation must actually make the planes disagree"
    );
    assert_eq!(
        l.last_upgrader_new_members, ok.last_upgrader_new_members,
        "only the VAULT plane may have moved"
    );
    // Each pin is kept matched to ITS OWN changed last row, so the pin↔ledger
    // legs stay green and the live cross-plane leg is isolated.
    let vault_pin = v3(B1, B2, B3B);
    let upg_pin = v3(B1, B2, B3);
    assert!(
        vault_leg(&pre, 2, &vault_pin, 2, Some(&l)).is_empty(),
        "the vault pin must still match its own row, or the isolation is lost"
    );
    assert_only(
        &upgrader_leg(&pre, 2, &pre, &upg_pin, Some(&l)),
        Kind::Roster,
        "live cross-plane: upgrader != vault",
        "A-4(v)",
    );
}

// ═══ A-4(vi) — the bootstrap halves disagree (install cross-plane) ══════════

#[test]
fn a4_vi_install_cross_plane_disagreement_by_one_principal() {
    let pre = v3(P1, P2, P3);
    let post = v3(B1, B2, B3);

    // BASELINE: on the unmutated fixture the two snapshot halves agree and the
    // upgrader leg passes.
    let ok = Rec::rotated().lockstep();
    assert_eq!(
        ok.bootstrap_upgrader_members, ok.bootstrap_vault_signers,
        "baseline: the snapshot halves must agree before the mutation"
    );
    assert!(upgrader_leg(&pre, 2, &pre, &post, Some(&ok)).is_empty(), "upgrader baseline");

    // ONE change: the snapshot's Upgrader half names a different third
    // principal. `upgrader_init.did` moves WITH it, because the artifact and
    // the snapshot of the artifact are the same install-time fact.
    let mut r = Rec::rotated();
    r.boot_upg = [P1, P2, B3B];
    let l = r.lockstep();
    assert_ne!(
        l.bootstrap_upgrader_members, l.bootstrap_vault_signers,
        "the mutation must actually make the snapshot halves disagree"
    );
    assert_eq!(
        l.bootstrap_vault_signers, ok.bootstrap_vault_signers,
        "only the UPGRADER half may have moved"
    );
    // `upgrader_init.did` is moved WITH the snapshot half it is judged against,
    // so surface 3 stays green and cannot stand in as the witness. The rows are
    // untouched, so no chain-shaped failure is involved either.
    let v = upgrader_leg(&v3(P1, P2, B3B), 2, &pre, &post, Some(&l));
    assert_only(
        &v,
        Kind::Roster,
        "install cross-plane: bootstrap upgrader_members != bootstrap vault_signers",
        "A-4(vi)",
    );
}

// ═══ last-EXECUTED-row selection ════════════════════════════════════════════

#[test]
fn the_last_executed_row_is_the_one_the_pins_are_checked_against() {
    // TWO rows per plane. The pins must match row 2, not row 1.
    let mut r = Rec::rotated();
    r.upg_rows = vec![(1, "EXECUTED", [B1, B2, B3], 2), (2, "EXECUTED", [B1, B2, B3B], 2)];
    r.vault_rows = vec![(1, "EXECUTED", [B1, B2, B3], 2), (2, "EXECUTED", [B1, B2, B3B], 2)];
    let l = r.lockstep();
    assert_eq!(l.last_vault_new_members, v3(B1, B2, B3B), "selection must take sequence 2");

    let pre = v3(P1, P2, P3);
    assert!(
        vault_leg(&pre, 2, &v3(B1, B2, B3B), 2, Some(&l)).is_empty(),
        "pins equal to the LAST row must pass"
    );
    assert_only(
        &vault_leg(&pre, 2, &v3(B1, B2, B3), 2, Some(&l)),
        Kind::Authority,
        "pin != ledger (vault plane)",
        "pins equal to the FIRST row must fail",
    );
}

#[test]
fn selection_is_by_sequence_not_by_file_order() {
    let mut r = Rec::rotated();
    // Row 2 written FIRST in the file.
    r.upg_rows = vec![(2, "EXECUTED", [B1, B2, B3B], 2), (1, "EXECUTED", [B1, B2, B3], 2)];
    r.vault_rows = vec![(2, "EXECUTED", [B1, B2, B3B], 2), (1, "EXECUTED", [B1, B2, B3], 2)];
    let l = r.lockstep();
    assert_eq!(
        l.last_upgrader_new_members,
        v3(B1, B2, B3B),
        "a reordered file must not change which row is `current`"
    );
}

// ═══ fail-closed on missing or invalid ledger state ═════════════════════════
//
// THESE THREE ARE LOADER-ERROR TESTS, not comparison negatives. They call
// `rotation_lockstep_from_record` directly, which returns `Result<_, String>` —
// so there is no `Violation` to type-assert, and `assert_only` does not apply.
// What they owe instead is the SAME single-change discipline: an UNMUTATED
// control that is asserted to LOAD, then exactly one change, then the `Err`.
// Without the control, an `expect_err` would pass on a fixture that never
// loaded in the first place.

/// The unmutated fixture every rejection test below starts from. Asserted to
/// load, so an `Err` afterwards is attributable to the one change and nothing
/// else.
fn assert_baseline_fixture_loads(ctx: &str) -> vcm::RotationLockstep {
    let l = vcm::rotation_lockstep_from_record(&Rec::rotated().text())
        .unwrap_or_else(|e| panic!("{ctx}: the UNMUTATED fixture must load, got Err: {e}"));
    assert!(l.rotated, "{ctx}: the unmutated fixture must be rotated");
    assert_eq!(l.last_vault_new_members.len(), 3, "{ctx}: and must select a vault row");
    assert_eq!(l.last_upgrader_new_members.len(), 3, "{ctx}: and an upgrader row");
    l
}

#[test]
fn a_rotated_record_with_no_executed_row_on_a_plane_fails_closed() {
    assert_baseline_fixture_loads("no-EXECUTED-row");

    let mut r = Rec::rotated();
    r.vault_rows = vec![];
    let e = vcm::rotation_lockstep_from_record(&r.text())
        .expect_err("a rotated record with an empty plane must not yield a lockstep");
    assert!(e.contains("vault"), "{e}");

    // And the row that exists but is not EXECUTED is equally not a witness.
    // Same control, same single change: only `status` moves.
    let ok = assert_baseline_fixture_loads("non-EXECUTED-row");
    let mut r = Rec::rotated();
    r.vault_rows = vec![(1, "PLACEHOLDER", [B1, B2, B3], 2)];
    assert_eq!(
        ok.last_vault_new_members,
        v3(B1, B2, B3),
        "only `status` may differ between the control and the mutation"
    );
    let e = vcm::rotation_lockstep_from_record(&r.text())
        .expect_err("a rotated record with no EXECUTED vault row must not yield a lockstep");
    assert!(e.contains("EXECUTED"), "{e}");
}

#[test]
fn an_unrecognised_state_fails_closed() {
    assert_baseline_fixture_loads("unrecognised-state");

    // ONE change: the state word, and nothing else.
    let mut r = Rec::rotated();
    assert_eq!(r.state, "rotated", "the control's state word");
    r.state = "half-rotated";
    let e = vcm::rotation_lockstep_from_record(&r.text()).expect_err("unknown state");
    assert!(e.contains("half-rotated"), "{e}");
}

#[test]
fn an_unparseable_record_fails_closed() {
    // CONTROL: well-formed TOML loads. The rejection below is therefore about
    // the TEXT being unparseable, not about the loader refusing everything.
    assert_baseline_fixture_loads("unparseable-record");

    let e = vcm::rotation_lockstep_from_record("this is not toml = = =").expect_err("garbage");
    assert!(e.contains("does not parse"), "{e}");
}

#[test]
fn a_record_with_no_rotation_table_yields_the_stricter_pre_rotation_view() {
    // Absence is not "rotated": the pins are then compared DIRECTLY to the init
    // payloads, which is the stricter of the two modes. The missing table is
    // separately a `RotationLedgerInconsistent`, owned by the ledger check.
    // CONTROL: a record with no `[rotation]` table still LOADS — absence is the
    // pre-rotation view, not an error. (Contrast the three rejection tests
    // above, where the loader returns `Err`.)
    let l = vcm::rotation_lockstep_from_record("threshold = 2\n")
        .expect("an absent [rotation] table must yield the pre-rotation view, not an error");
    assert!(!l.rotated);
    let pre = v3(P1, P2, P3);
    let post = v3(B1, B2, B3);
    assert_ne!(
        pre, post,
        "the rewritten-pin mutation below must actually change the pins — asserted, not left \
         to be inferred from differing literals"
    );
    assert!(vault_leg(&pre, 2, &pre, 2, Some(&l)).is_empty(), "baseline: pins == init passes");
    assert_only(
        &vault_leg(&pre, 2, &post, 2, Some(&l)),
        Kind::Authority,
        "init signer set != pinned record signer set",
        "no [rotation] table",
    );
}

#[test]
fn an_unreadable_ledger_state_makes_the_io_wrappers_fail_closed() {
    // SSA landed-diff C-1(b). The earlier form of this test passed `&[]` as the
    // encoded Vault init payload, so BOTH wrappers returned a DECODE violation
    // at their first step (`lib.rs` `check_authority_binding` /
    // `check_recovery_roster`, before `load_rotation_lockstep` is ever called)
    // and the claimed fail-closed path was never reached. It passed without
    // exercising the protection it named.
    //
    // The repair: a real tree with the REAL committed `vault_init.did` /
    // `upgrader_init.did` and the REAL pins, so both wrappers reach the ledger
    // loader and PASS. Only then is the LEDGER invalidated — nothing else — and
    // each wrapper is asserted to report its own kind, naming the lockstep load.
    let repo = repo_root();
    let encoded = vcm::encode_init_artifact(&repo.join(vcm::VAULT_INIT_ARTIFACT))
        .expect("the committed vault_init.did must encode");

    // BASELINE — on the committed record, both wrappers pass. This is what
    // proves the mutation below is the only reason they later fail.
    let ok = shadow(&committed_record(), "failclosed_ok");
    let v = vcm::check_authority_binding(&ok, &encoded);
    assert!(v.is_empty(), "BASELINE: the authority binding must pass: {v:?}");
    let v = vcm::check_recovery_roster(&ok, &encoded);
    assert!(v.is_empty(), "BASELINE: the recovery roster must pass: {v:?}");
    let _ = std::fs::remove_dir_all(&ok);

    // ONE change, and it is in the LEDGER only: `[rotation].state` becomes a
    // word the loader does not recognise. The pins, both `.did` files and
    // `[rotation.bootstrap]` are untouched, so nothing before the loader can
    // fail.
    let committed = committed_record();
    let mutated = committed.replacen("\nstate = \"rotated\"\n", "\nstate = \"half-rotated\"\n", 1);
    assert_ne!(mutated, committed, "the mutation must actually change the record");
    assert!(
        vcm::rotation_lockstep_from_record(&mutated).is_err(),
        "the mutation must actually make the lockstep unloadable"
    );
    let bad = shadow(&mutated, "failclosed_bad");

    let v = vcm::check_authority_binding(&bad, &encoded);
    assert!(
        v.iter().any(|x| matches!(
            x,
            Violation::AuthorityBindingViolation { detail }
                if detail.contains("cannot load the rotation lockstep")
        )),
        "the authority binding must fail CLOSED on an unloadable ledger state, naming the \
         lockstep load — got {v:?}"
    );
    let v = vcm::check_recovery_roster(&bad, &encoded);
    assert!(
        v.iter().any(|x| matches!(
            x,
            Violation::RecoveryRosterViolation { detail }
                if detail.contains("cannot load the rotation lockstep")
        )),
        "the recovery roster must fail CLOSED on an unloadable ledger state, naming the \
         lockstep load — got {v:?}"
    );
    let _ = std::fs::remove_dir_all(&bad);
}

#[test]
fn a_rotated_record_missing_a_plane_also_fails_the_io_wrappers_closed() {
    // The second way a rotated ledger becomes unloadable: it says `rotated` but
    // a plane carries no EXECUTED row, so there is nothing for the pins to be
    // checked against. Same baseline, same single-change discipline.
    let repo = repo_root();
    let encoded = vcm::encode_init_artifact(&repo.join(vcm::VAULT_INIT_ARTIFACT))
        .expect("the committed vault_init.did must encode");

    let ok = shadow(&committed_record(), "failclosed2_ok");
    assert!(vcm::check_authority_binding(&ok, &encoded).is_empty(), "BASELINE authority");
    assert!(vcm::check_recovery_roster(&ok, &encoded).is_empty(), "BASELINE roster");
    let _ = std::fs::remove_dir_all(&ok);

    // ONE change: the single `[[rotation.vault]]` row's status stops being
    // EXECUTED, so the Vault plane has no row the loader can select.
    let committed = committed_record();
    let head = committed
        .find("\n[[rotation.vault]]\nsequence")
        .expect("the committed record must carry a vault row");
    let mutated = format!(
        "{}{}",
        &committed[..head],
        committed[head..].replacen("status = \"EXECUTED\"", "status = \"SUPERSEDED\"", 1)
    );
    assert_ne!(mutated, committed, "the mutation must actually change the record");
    let e = vcm::rotation_lockstep_from_record(&mutated)
        .expect_err("the mutation must actually make the lockstep unloadable");
    assert!(e.contains("vault") && e.contains("EXECUTED"), "{e}");

    let bad = shadow(&mutated, "failclosed2_bad");
    assert!(
        vcm::check_authority_binding(&bad, &encoded).iter().any(|x| matches!(
            x,
            Violation::AuthorityBindingViolation { detail }
                if detail.contains("cannot load the rotation lockstep")
        )),
        "authority binding must fail closed"
    );
    assert!(
        vcm::check_recovery_roster(&bad, &encoded).iter().any(|x| matches!(
            x,
            Violation::RecoveryRosterViolation { detail }
                if detail.contains("cannot load the rotation lockstep")
        )),
        "recovery roster must fail closed"
    );
    let _ = std::fs::remove_dir_all(&bad);
}

// ── the real-tree scaffolding the two tests above need ─────────────────────
//
// A tree that IS the repository for every path the two wrappers read — both
// init `.did` files, `canister_ids.json`, everything — except
// `deployment/mainnet/vault_authorities.toml`, which is a REAL file this test
// writes. Nothing in the repository is modified.

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn committed_record() -> String {
    std::fs::read_to_string(repo_root().join(vcm::VAULT_AUTHORITY_RECORD)).unwrap()
}

fn shadow(record: &str, tag: &str) -> std::path::PathBuf {
    let repo = repo_root();
    let dir = std::env::temp_dir().join(format!(
        "stsh_q5a_{tag}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(dir.join("deployment/mainnet")).unwrap();
    let link_all = |src: &std::path::Path, dst: &std::path::Path, skip: &str| {
        for e in std::fs::read_dir(src).unwrap() {
            let e = e.unwrap();
            let name = e.file_name();
            if name.to_string_lossy() == skip {
                continue;
            }
            std::os::unix::fs::symlink(e.path(), dst.join(&name)).unwrap();
        }
    };
    link_all(&repo, &dir, "deployment");
    link_all(&repo.join("deployment"), &dir.join("deployment"), "mainnet");
    link_all(
        &repo.join("deployment/mainnet"),
        &dir.join("deployment/mainnet"),
        "vault_authorities.toml",
    );
    std::fs::write(dir.join("deployment/mainnet/vault_authorities.toml"), record).unwrap();
    dir
}
