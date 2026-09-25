//! B-6 / O-10 — `[wallet_bundle]` / `[wallet_bundle_transitional]` pin coverage.
//!
//! WHY THIS FILE EXISTS. At `174e158`, `grep -rn wallet_bundle
//! scripts/verify_custody_manifest/` returned NOTHING: the two bundle tables
//! were unchecked pins, and `deployment/mainnet/release_hashes.toml` carried
//! that fact as a comment about itself, across multiple lanes. The bundle is
//! what a user's browser actually executes, and `[wallet_bundle]` is the only
//! pin the Poseidon wallet-crypto wasm has.
//!
//! FIXTURE DISCIPLINE. Every case below builds its own record from a BASELINE
//! that is known-good, then introduces exactly ONE defect. Each defect case
//! asserts the baseline passes first — without that, a case could "pass"
//! because the fixture was broken all along and the checker was firing on
//! something else entirely. No expected value is copied out of
//! `release_hashes.toml`: a test whose expected value comes from the artifact
//! it checks is not independent of it, and this project has closed that defect
//! class before.
//!
//! WHAT IS DELIBERATELY *NOT* ASSERTED HERE, AND WHY THAT IS STILL TRUE AFTER THE
//! DEFECTS WERE FIXED. There is no test asserting the violation set of the LIVE
//! record, and there must not be: a test pinning "the live record produces exactly
//! these N violations" inherits the record's own values as its expected value, and
//! reddens the moment a legitimate lane changes them. The live-record test at the
//! foot of this file asserts only invariants that hold independently, plus that the
//! checker runs at all. AB-4's "zero violations at the lane head" is a PACKET claim,
//! reproduced by running the tool; the independent tests are the fixture cases.
//!
//! ROUTING NOTE, NOW DISCHARGED (HARDEN-02, 2026-09-17). When this file was
//! written, the two live defects it named — `[wallet_bundle].files = 11` against a
//! `bytes_method` stating 10, and a `source_sha` that is a real commit but not an
//! ancestor of master — were ROUTED to the owning lane, because
//! `deployment/mainnet/*` was not that lane's to write. THIS IS THAT LANE.
//! Both are fixed at this head: the prose literal is corrected to 11 (the number
//! was already right; the file-set change left the prose behind), and `source_sha`
//! is rebound to the post-rebase commit `e0c1f4d…`, evidenced by equality of all
//! three trees that govern the bundle. A SECOND orphan, `af8f3e28`, was found in a
//! superseded paragraph and is annotated there rather than deleted. See the
//! HARDEN-02 correction note at the top of `[wallet_bundle]` in the record.
//!
//! WHAT ELSE CHANGED IN THIS FILE'S SUBJECT. The record-coverage half now runs on
//! the CANONICAL gate path (`--deploy-posture`, and `--deploy-time` with it), so
//! these checks are no longer opt-in — which is why the two defects above had to be
//! fixed in the same lane that wired it: `WalletBundleUnbound` is not in
//! `DECLARABLE_KINDS`, so from that commit onward a live bundle-record violation is
//! a hard gate failure that cannot be declared pending. The BYTE measurement is the
//! separate `--wallet-bundle-bytes` mode, covered by the `bii_*` cases below.

use std::path::{Path, PathBuf};
use verify_custody_manifest as vcm;
use verify_custody_manifest::Violation;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn write_file(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

/// A real git repository with one real commit; returns that commit's SHA.
/// `source_sha` = HEAD satisfies recorded-ancestor semantics (ancestor OR
/// equal), so the provenance leg of the check is TRUTHFUL in every fixture and
/// never the thing under test except where a case says so.
fn init_git_root(root: &Path) -> String {
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(["-C", &root.to_string_lossy()])
            .args(args)
            .output()
            .expect("git must be available for provenance fixtures");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    std::fs::create_dir_all(root).unwrap();
    git(&["init", "-q"]);
    git(&["config", "user.email", "fixture@example.invalid"]);
    git(&["config", "user.name", "fixture"]);
    write_file(&root.join("seed.txt"), "wallet-bundle fixture\n");
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "fixture commit"]);
    git(&["rev-parse", "HEAD"]).trim().to_string()
}

/// The knobs each negative case turns. Defaults are the BASELINE: a record that
/// must produce zero violations.
struct Bundles {
    final_sha: String,
    transitional_sha: String,
    final_files: i64,
    final_method_count: i64,
    final_npm: String,
    transitional_npm: String,
    final_asset_sha: String,
    transitional_asset_sha: String,
    install_phase: String,
    derivation_origin: Option<String>,
    drop_transitional_table: bool,
    drop_final_command_expands: bool,
    /// M-02 (B-ii) release marker. `None` drops the whole table.
    release_state: Option<String>,
    release_reason: Option<String>,
    /// HARDEN-03 (D-1): `[wallet_bundle_release].variant`. The BASELINE leaves it
    /// absent, because the baseline state is `held` and a variant is FORBIDDEN
    /// there — so the default fixture exercises the same shape the live record
    /// carries, and `b6_live_record_holds_the_invariants_it_satisfies` and the
    /// deploy-posture suite stay green with no record edit.
    release_variant: Option<String>,
}

impl Default for Bundles {
    fn default() -> Self {
        Self {
            final_sha: "a".repeat(64),
            transitional_sha: "b".repeat(64),
            final_files: 11,
            final_method_count: 11,
            final_npm: "10.9.8 (the npm bundled with node 22.23.1)".into(),
            transitional_npm: "10.9.8 (the npm bundled with node 22.23.1)".into(),
            final_asset_sha: "c".repeat(64),
            transitional_asset_sha: "c".repeat(64),
            install_phase: "B.1 — the transitional install; superseded on the same canister by \
                            [wallet_bundle] at Phase D.8"
                .into(),
            derivation_origin: Some(
                "ABSENT — the key is omitted, not null and not empty.".into(),
            ),
            drop_transitional_table: false,
            drop_final_command_expands: false,
            release_state: Some("held".into()),
            release_reason: Some(
                "fixture: no bundle is being released at this head".into(),
            ),
            release_variant: None,
        }
    }
}

impl Bundles {
    fn render(&self, source_sha: &str) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "[wallet_bundle]\n\
             sha256          = \"{}\"\n\
             method          = \"sha256 over the LC_ALL=C-sorted per-file manifest of wallet/dist\"\n\
             path            = \"wallet/dist\"\n\
             files           = {}\n\
             bytes           = 14103504\n\
             bytes_method    = \"sum of the {} REGULAR FILE sizes; directory entries are excluded\"\n\
             command         = \"cd wallet && npm run build\"\n",
            self.final_sha, self.final_files, self.final_method_count
        ));
        if !self.drop_final_command_expands {
            s.push_str("command_expands = \"npm run build:wasm && tsc && vite build\"\n");
        }
        s.push_str(&format!("source_sha      = \"{source_sha}\"\n\n"));
        s.push_str(&format!(
            "[wallet_bundle.toolchain]\n\
             node       = \"22.23.1 (wallet/.nvmrc)\"\n\
             npm        = \"{}\"\n\
             wasm_pack  = \"0.12.1 (from node_modules/.bin)\"\n\
             rustc      = \"1.95.0\"\n\n\
             [wallet_bundle.asset_config]\n\
             file   = \"wallet/public/.ic-assets.json5 -> dist/.ic-assets.json5\"\n\
             sha256 = \"{}\"\n\n",
            self.final_npm, self.final_asset_sha
        ));
        if self.drop_transitional_table {
            s.push_str(&self.render_release_marker());
            return s;
        }
        s.push_str(&format!(
            "[wallet_bundle_transitional]\n\
             sha256          = \"{}\"\n\
             method          = \"sha256 over the LC_ALL=C-sorted per-file manifest of wallet/dist\"\n\
             path            = \"wallet/dist\"\n\
             files           = 11\n\
             bytes           = 14103435\n\
             bytes_method    = \"sum of the 11 REGULAR FILE sizes; directory entries are excluded\"\n\
             command         = \"cd wallet && npm run build:transitional\"\n\
             command_expands = \"WALLET_CONFIG_VARIANT=transitional npm run build:wasm && tsc && vite build\"\n\
             source_sha      = \"{source_sha}\"\n\
             install_phase   = \"{}\"\n\n\
             [wallet_bundle_transitional.toolchain]\n\
             node       = \"22.23.1 (wallet/.nvmrc)\"\n\
             npm        = \"{}\"\n\
             wasm_pack  = \"0.12.1 (from node_modules/.bin)\"\n\
             rustc      = \"1.95.0\"\n\n\
             [wallet_bundle_transitional.asset_config]\n\
             file   = \"wallet/public/.ic-assets.json5 -> dist/.ic-assets.json5\"\n\
             sha256 = \"{}\"\n\n\
             [wallet_bundle_transitional.launch_config]\n\
             file            = \"wallet/public/wallet-config.transitional.json -> dist/wallet-config.json\"\n\
             launch_origin   = \"https://app.stsh.fi\"\n",
            self.transitional_sha,
            self.install_phase,
            self.transitional_npm,
            self.transitional_asset_sha
        ));
        if let Some(d) = &self.derivation_origin {
            s.push_str(&format!("derivation_origin = \"{d}\"\n"));
        }
        s.push_str(&self.render_release_marker());
        s
    }

    /// M-02 (B-ii): the release-state marker. Rendered LAST so a
    /// `drop_transitional_table` fixture still carries it — the marker is a
    /// property of the record, not of either table.
    fn render_release_marker(&self) -> String {
        let mut s = String::new();
        if self.release_state.is_none()
            && self.release_reason.is_none()
            && self.release_variant.is_none()
        {
            return s;
        }
        s.push_str("\n[wallet_bundle_release]\n");
        if let Some(st) = &self.release_state {
            s.push_str(&format!("state  = \"{st}\"\n"));
        }
        if let Some(r) = &self.release_reason {
            s.push_str(&format!("reason = \"{r}\"\n"));
        }
        if let Some(va) = &self.release_variant {
            s.push_str(&format!("variant = \"{va}\"\n"));
        }
        s
    }
}

/// Materialise a fixture root: a real git repo carrying a record built from
/// `b`. Returns the root, whose removal is the caller's business.
fn fixture_root(tag: &str, b: &Bundles) -> PathBuf {
    let root = std::env::temp_dir().join(format!("vcm-wallet-bundles-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let sha = init_git_root(&root);
    write_file(&root.join(vcm::RELEASE_RECORD_ARTIFACT), &b.render(&sha));
    root
}

fn fires(v: &[Violation]) -> bool {
    v.iter().any(|x| matches!(x, Violation::WalletBundleUnbound { .. }))
}

fn rendered(v: &[Violation]) -> String {
    v.iter().map(|x| format!("{x}")).collect::<Vec<_>>().join("\n")
}

/// Every negative case runs through here, so every one of them proves the
/// BASELINE is clean before its single defect is introduced. A negative test
/// that never establishes its baseline cannot distinguish "the check fired on
/// my defect" from "the fixture was broken".
fn assert_defect_fires(tag: &str, mutate: impl Fn(&mut Bundles), needle: &str) {
    let base = Bundles::default();
    let base_root = fixture_root(&format!("{tag}-baseline"), &base);
    let base_v = vcm::check_wallet_bundles(&base_root);
    assert!(
        base_v.is_empty(),
        "[{tag}] BASELINE must be clean before the defect is introduced, got:\n{}",
        rendered(&base_v)
    );
    let _ = std::fs::remove_dir_all(&base_root);

    let mut defective = Bundles::default();
    mutate(&mut defective);
    let root = fixture_root(tag, &defective);
    let v = vcm::check_wallet_bundles(&root);
    assert!(
        fires(&v),
        "[{tag}] the defect must produce a WalletBundleUnbound violation, got nothing"
    );
    let text = rendered(&v);
    assert!(
        text.contains(needle),
        "[{tag}] the violation must SAY what is wrong (looking for `{needle}`), got:\n{text}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ── §3.1 — structural completeness ───────────────────────────────────────────

#[test]
fn b6_missing_transitional_table_is_a_violation() {
    assert_defect_fires(
        "no-transitional",
        |b| b.drop_transitional_table = true,
        "has no `[wallet_bundle_transitional]` table",
    );
}

#[test]
fn b6_missing_scalar_field_is_a_violation() {
    assert_defect_fires(
        "no-command-expands",
        |b| b.drop_final_command_expands = true,
        "missing required field `command_expands`",
    );
}

// ── §3.2 — digests well-formed, and DISTINCT ─────────────────────────────────

#[test]
fn b6_malformed_digest_is_a_violation() {
    assert_defect_fires(
        "short-digest",
        |b| b.final_sha = "abc123".into(),
        "is not 64 lowercase hex characters",
    );
}

/// The copy-paste case: two tables, one measurement. The transitional bundle
/// differs from the final one by exactly the omitted `derivationOrigin` member,
/// so equal digests are impossible unless a table was never re-measured.
#[test]
fn b6_identical_bundle_digests_are_a_violation() {
    assert_defect_fires(
        "dup-digest",
        |b| b.transitional_sha = b.final_sha.clone(),
        "record the SAME sha256",
    );
}

// ── §3.3 — files vs the count `bytes_method` states about itself ─────────────

/// This is the defect the LIVE record carries at this head (`files = 11`
/// against "sum of the 10 REGULAR FILE sizes"). It is reproduced here as a
/// FIXTURE rather than asserted against the record, so the test neither
/// inherits the record's values nor goes red when the owning lane fixes them.
#[test]
fn b6_files_disagreeing_with_bytes_method_is_a_violation() {
    assert_defect_fires(
        "files-mismatch",
        |b| b.final_method_count = 10,
        "is internally inconsistent",
    );
}

#[test]
fn b6_bytes_method_stating_no_count_is_a_violation() {
    let mut b = Bundles::default();
    b.final_method_count = 11;
    let root = fixture_root("method-no-count", &b);
    // Rewrite bytes_method to prose with no number in it at all.
    let record = root.join(vcm::RELEASE_RECORD_ARTIFACT);
    let raw = std::fs::read_to_string(&record).unwrap();
    let patched = raw.replace(
        "sum of the 11 REGULAR FILE sizes; directory entries are excluded",
        "sum of the regular file sizes",
    );
    assert_ne!(raw, patched, "the fixture rewrite must actually apply");
    std::fs::write(&record, patched).unwrap();
    let v = vcm::check_wallet_bundles(&root);
    assert!(fires(&v), "a bytes_method with no stated count must fire");
    assert!(
        rendered(&v).contains("states no file count"),
        "got:\n{}",
        rendered(&v)
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ── §3.4 — the paired toolchain tuple ────────────────────────────────────────

/// The SPLICED TUPLE. The record documents the real occurrence: node 22.23.1
/// paired with npm 10.8.2, which is the npm that ships with node 20.20.2 — a
/// tuple that never existed on this host. Here the two tables disagree, which
/// is the shape a splice takes once there are two tables restating one tuple.
#[test]
fn b6_spliced_toolchain_tuple_is_a_violation() {
    assert_defect_fires(
        "spliced-tuple",
        |b| b.transitional_npm = "10.8.2 (the npm bundled with node 20.20.2)".into(),
        "disagree",
    );
}

#[test]
fn b6_missing_toolchain_key_is_a_violation() {
    let b = Bundles::default();
    let root = fixture_root("no-wasm-pack", &b);
    let record = root.join(vcm::RELEASE_RECORD_ARTIFACT);
    let raw = std::fs::read_to_string(&record).unwrap();
    // Drop wasm_pack from the FINAL table only.
    let mut out = String::new();
    let mut in_final_toolchain = false;
    for line in raw.lines() {
        if line.starts_with('[') {
            in_final_toolchain = line.trim() == "[wallet_bundle.toolchain]";
        }
        if in_final_toolchain && line.trim_start().starts_with("wasm_pack") {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    assert_ne!(raw, out, "the fixture rewrite must actually drop a key");
    std::fs::write(&record, out).unwrap();
    let v = vcm::check_wallet_bundles(&root);
    assert!(fires(&v), "a missing toolchain key must fire");
    assert!(
        rendered(&v).contains("is missing `wasm_pack`"),
        "got:\n{}",
        rendered(&v)
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ── §3.5 — recorded-ancestor provenance, REUSED not re-written ───────────────

/// A `source_sha` that is not a commit in the repository being checked. This is
/// the same class as the LIVE record's second defect (a real commit that is not
/// an ancestor of master, left behind by a rebase) — proved here on a fixture.
#[test]
fn b6_fabricated_source_sha_is_a_violation() {
    let b = Bundles::default();
    let root = fixture_root("bad-provenance-baseline", &b);
    assert!(
        vcm::check_wallet_bundles(&root).is_empty(),
        "baseline with a truthful source_sha must be clean"
    );
    let record = root.join(vcm::RELEASE_RECORD_ARTIFACT);
    let raw = std::fs::read_to_string(&record).unwrap();
    let head = raw
        .lines()
        .find(|l| l.starts_with("source_sha"))
        .and_then(|l| l.split('"').nth(1))
        .expect("the fixture records a source_sha")
        .to_string();
    std::fs::write(&record, raw.replace(&head, &"d".repeat(40))).unwrap();
    let v = vcm::check_wallet_bundles(&root);
    assert!(fires(&v), "a fabricated source_sha must fire");
    let text = rendered(&v);
    assert!(
        text.contains("source_sha") && text.contains("not a commit object"),
        "the violation must name the field and the reason, got:\n{text}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ── §3.6 — install-phase coherence ──────────────────────────────────────────

/// The governance-fatal swap: a record that names D.8 before B.1 describes the
/// FINAL bundle going in first, which re-roots `app.stsh.fi` immediately, makes
/// the old II principals unproducible, and leaves the step-7 rotation neither
/// proposable nor approvable. Nothing errors; nothing on screen says so.
#[test]
fn b6_swapped_install_phase_order_is_a_violation() {
    assert_defect_fires(
        "phase-swap",
        |b| {
            b.install_phase =
                "D.8 — installed first, then superseded at B.1 by the transitional bundle".into()
        },
        "in that order",
    );
}

#[test]
fn b6_absent_install_phase_is_a_violation() {
    assert_defect_fires(
        "phase-absent",
        |b| b.install_phase = "   ".into(),
        "`[wallet_bundle_transitional].install_phase` is absent",
    );
}

// ── §3.7 — the asset config does not vary by variant ────────────────────────

#[test]
fn b6_divergent_asset_config_is_a_violation() {
    assert_defect_fires(
        "asset-divergence",
        |b| b.transitional_asset_sha = "e".repeat(64),
        "do NOT vary by config variant",
    );
}

// ── §3.8 — ABSENT is not EMPTY ──────────────────────────────────────────────

/// THE distinction the Phase B.1 install depends on. `evaluateSessionPolicy`
/// refuses a present-but-wrong `derivationOrigin` and PERMITS an absent one, so
/// a record that says "" instead of ABSENT describes a different bundle than
/// the one the ceremony needs — and says so in a field a reader skims.
#[test]
fn b6_empty_derivation_origin_is_not_absent() {
    assert_defect_fires(
        "origin-empty",
        |b| b.derivation_origin = Some(String::new()),
        "it must record the key as ABSENT",
    );
}

#[test]
fn b6_present_derivation_origin_value_is_a_violation() {
    assert_defect_fires(
        "origin-present",
        |b| {
            b.derivation_origin =
                Some("https://s3tyu-aaaaa-aaaab-qhdjq-cai.icp0.io".into())
        },
        "it must record the key as ABSENT",
    );
}

#[test]
fn b6_missing_derivation_origin_key_is_a_violation() {
    assert_defect_fires(
        "origin-missing",
        |b| b.derivation_origin = None,
        "records no `derivation_origin`",
    );
}

// ── Fail-closed, and the live record ────────────────────────────────────────

/// An absent record is a violation, never an empty pass. A checker that reports
/// success on a record it could not read is worse than no checker.
#[test]
fn b6_absent_record_fails_closed() {
    let root = std::env::temp_dir().join(format!("vcm-wallet-bundles-empty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let v = vcm::check_wallet_bundles(&root);
    assert!(fires(&v), "an unreadable record must fail closed, got: {v:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// The LIVE record, for the invariants that hold at this head.
///
/// Deliberately NOT a whole-verdict assertion: see the module header. The two
/// genuine defects this check found in the live record are routed to the
/// owning wallet-record lane, not frozen into a literal here.
#[test]
fn b6_live_record_holds_the_invariants_it_satisfies() {
    let root = repo_root();
    let raw = std::fs::read_to_string(root.join(vcm::RELEASE_RECORD_ARTIFACT))
        .expect("the release record must exist");
    let doc: toml::Value = raw.parse().expect("the release record must be well-formed TOML");

    for table in vcm::WALLET_BUNDLE_TABLES {
        let t = doc
            .get(table)
            .unwrap_or_else(|| panic!("the record must carry `[{table}]`"));
        let sha = t.get("sha256").and_then(|x| x.as_str()).unwrap_or_default();
        assert_eq!(sha.len(), 64, "[{table}] sha256 must be 64 hex chars");
        assert!(
            sha.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "[{table}] sha256 must be lowercase hex"
        );
        for key in vcm::WALLET_BUNDLE_TOOLCHAIN_KEYS {
            assert!(
                t.get("toolchain").and_then(|tc| tc.get(key)).is_some(),
                "[{table}.toolchain] must pin `{key}`"
            );
        }
    }

    let tuple = |table: &str| -> Vec<String> {
        vcm::WALLET_BUNDLE_TOOLCHAIN_KEYS
            .iter()
            .map(|k| {
                doc.get(table)
                    .and_then(|t| t.get("toolchain"))
                    .and_then(|tc| tc.get(*k))
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string()
            })
            .collect()
    };
    assert_eq!(
        tuple("wallet_bundle"),
        tuple("wallet_bundle_transitional"),
        "the two bundle tables restate ONE tuple; a divergence is a spliced toolchain"
    );

    let asset = |table: &str| -> String {
        doc.get(table)
            .and_then(|t| t.get("asset_config"))
            .and_then(|a| a.get("sha256"))
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(
        asset("wallet_bundle"),
        asset("wallet_bundle_transitional"),
        "the asset config does not vary by config variant"
    );

    let digest = |table: &str| -> String {
        doc.get(table)
            .and_then(|t| t.get("sha256"))
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string()
    };
    assert_ne!(
        digest("wallet_bundle"),
        digest("wallet_bundle_transitional"),
        "two bundles, two artifacts, two digests"
    );

    // And the checker must actually RUN on the real record rather than panic or
    // silently do nothing — the coverage gap this lane closed was exactly
    // "nothing in the checker mentions wallet_bundle".
    let _ = vcm::check_wallet_bundles(&root);
}

// =============================================================================
// WALLET-V13 O-3 — check (9): the FINAL bundle compiled the record's current
// `[wasm.*]` pins, or `[wallet_bundle_release].stale_pins` names EXACTLY the
// differing set. Fixture: real commits carrying real `[wasm.*]` records, so the
// check's `git show <source_sha>:<record>` reads what a lane would have built on.
// =============================================================================

const PIN_OLD: &str = "ac9336f2ac9336f2ac9336f2ac9336f2ac9336f2ac9336f2ac9336f2ac9336f2";
const PIN_NEW: &str = "994a77ff994a77ff994a77ff994a77ff994a77ff994a77ff994a77ff994a77ff";
const PIN_POOL: &str = "dca03f68dca03f68dca03f68dca03f68dca03f68dca03f68dca03f68dca03f68";

fn wasm_rows(token: &str) -> String {
    format!(
        "\n[wasm.stsh_token]\nsha256 = \"{token}\"\n\n[wasm.\"stsh-verifier\"]\nsha256 = \"{PIN_POOL}\"\n"
    )
}

/// Root with two real commits: `c_old` records the token at PIN_OLD, `c_new` at
/// PIN_NEW. The working-tree record binds `[wallet_bundle].source_sha` to
/// `final_at`, `[wallet_bundle_transitional].source_sha` to `transitional_at`,
/// pins the token at `head_token`, and acknowledges `stale_pins` (None = key absent).
fn pin_fixture(tag: &str, final_old: bool, transitional_old: bool, head_token: &str, stale_pins: Option<&str>) -> PathBuf {
    let root = std::env::temp_dir().join(format!("vcm-wallet-pins-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    init_git_root(&root);
    let git = |args: &[&str]| {
        let out = Command::new("git").args(["-C", &root.to_string_lossy()]).args(args).output().unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    let rec = root.join(vcm::RELEASE_RECORD_ARTIFACT);
    let mut shas = Vec::new();
    for token in [PIN_OLD, PIN_NEW] {
        write_file(&rec, &wasm_rows(token));
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "pins"]);
        shas.push(git(&["rev-parse", "HEAD"]));
    }
    let (c_old, c_new) = (&shas[0], &shas[1]);
    let body = Bundles::default().render(if final_old { c_old } else { c_new });
    // `render` binds BOTH tables to one sha; re-point the transitional one.
    let (head, tail) = body.split_at(body.find("[wallet_bundle_transitional]").unwrap());
    let tsha = if transitional_old { c_old } else { c_new };
    let tail = tail.replacen(if final_old { c_old } else { c_new }, tsha, 1);
    let mut record = format!("{head}{tail}");
    if let Some(p) = stale_pins {
        record.push_str(&format!("stale_pins = {p}\n"));
    }
    record.push_str(&wasm_rows(head_token));
    write_file(&rec, &record);
    root
}

fn pin_verdict(tag: &str, final_old: bool, transitional_old: bool, head_token: &str, stale_pins: Option<&str>) -> Vec<Violation> {
    let root = pin_fixture(tag, final_old, transitional_old, head_token, stale_pins);
    let v = vcm::check_wallet_bundles(&root);
    let _ = std::fs::remove_dir_all(&root);
    v
}

#[test]
fn v13_bundle_built_on_the_current_pins_is_clean() {
    let v = pin_verdict("current", false, false, PIN_NEW, None);
    assert!(v.is_empty(), "baseline must be clean, got:\n{}", rendered(&v));
}

#[test]
fn v13_stale_pin_unacknowledged_fires() {
    // The §3y shape: token re-pinned, wallet not rebuilt.
    let v = pin_verdict("stale", true, false, PIN_NEW, None);
    assert!(fires(&v), "a stale unacknowledged pin must fire");
    let text = rendered(&v);
    assert!(text.contains("\"stsh_token\"") && text.contains("stale_pins"), "must name the pin and the remedy:\n{text}");
    assert!(!text.contains("stsh-verifier"), "an unchanged pin is not stale:\n{text}");
}

#[test]
fn v13_stale_pin_acknowledged_exactly_is_clean() {
    let v = pin_verdict("acked", true, false, PIN_NEW, Some("[\"stsh_token\"]"));
    assert!(v.is_empty(), "an exact acknowledgment passes, got:\n{}", rendered(&v));
}

#[test]
fn v13_acknowledgment_that_is_no_longer_stale_fires() {
    // Residue: the wallet was rebuilt but the ack was left behind.
    let v = pin_verdict("residue", false, false, PIN_NEW, Some("[\"stsh_token\"]"));
    assert!(fires(&v), "an over-acknowledgment must fire, so an old ack cannot mask a new drift");
}

#[test]
fn v13_transitional_table_is_never_checked() {
    // Transitional bound to the OLD pins (stale by design), final bound to the current.
    let v = pin_verdict("transitional", false, true, PIN_NEW, None);
    assert!(v.is_empty(), "the transitional table must be excluded, got:\n{}", rendered(&v));
}

#[test]
fn v13_record_unreadable_at_source_sha_fails_closed() {
    // source_sha = the seed commit, which carries no record at all.
    let root = pin_fixture("unreadable", false, false, PIN_NEW, None);
    let seed = String::from_utf8(
        Command::new("git").args(["-C", &root.to_string_lossy(), "rev-list", "--max-parents=0", "HEAD"]).output().unwrap().stdout,
    ).unwrap();
    let rec = root.join(vcm::RELEASE_RECORD_ARTIFACT);
    let body = std::fs::read_to_string(&rec).unwrap();
    let final_line = body.lines().find(|l| l.starts_with("source_sha")).unwrap().to_string();
    write_file(&rec, &body.replacen(&final_line, &format!("source_sha      = \"{}\"", seed.trim()), 1));
    let v = vcm::check_wallet_bundles(&root);
    let _ = std::fs::remove_dir_all(&root);
    assert!(rendered(&v).contains("record unreadable at source_sha"), "must fail closed:\n{}", rendered(&v));
}

// =============================================================================
// M-02 (B-ii) — the BYTE measurement: the marker, the toolchain refusal, and the
// decisive byte-flip.
// =============================================================================
//
// FIXTURE DISCIPLINE, restated because this half is easier to get wrong than the
// record half: THE REAL `wallet/dist` IS NEVER WRITTEN BY ANY TEST HERE. Every
// case below builds its own directory under the fixture root. Mutating the real
// `dist` would touch a gitignored build output, depend on a wallet build having
// happened, and be order-dependent with the gate's own wallet build.
//
// WHY THESE FIXTURES PIN THE HOST'S OWN TOOLCHAIN VERSIONS. The byte check asserts
// the pinned tuple BEFORE measuring and refuses on a mismatch — which is the
// point of it, and which means a fixture pinning the RELEASE tuple could never
// reach the measurement on a host that is not running it. So the measurement
// cases pin what this host actually reports, and the refusal itself gets its own
// case that pins a tuple no host can be running. The two halves are deliberately
// not conflated: one proves the measurement compares bytes, the other proves a
// wrong tuple is refused rather than measured.

use std::process::Command;

fn host_tool_version(program: &str, args: &[&str]) -> String {
    let out = Command::new(program).args(args).output().unwrap_or_else(|e| {
        panic!(
            "[B-ii fixture] cannot run `{program} {args:?}`: {e}. This suite needs the host's \
             own node/npm/wasm-pack/rustc versions in order to build a fixture whose toolchain \
             assertion PASSES, so the byte measurement is what is under test. Install the tool \
             or run this suite on a host that has it — it is not skipped, because a skipped \
             byte-measurement test is the gap this lane exists to close."
        )
    });
    assert!(
        out.status.success(),
        "[B-ii fixture] `{program} {args:?}` exited {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    text.split_whitespace()
        .map(|t| t.trim_start_matches('v'))
        .find(|t| {
            let parts: Vec<&str> = t.split('.').collect();
            parts.len() >= 2 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        })
        .unwrap_or_else(|| panic!("[B-ii fixture] `{program} {args:?}` printed no version: {text:?}"))
        .to_string()
}

/// HARDEN-03 (D-1): the knobs the VARIANT cases need on top of `bytes_fixture`'s
/// single-table shape. Default = exactly what `bytes_fixture` has always emitted
/// (`variant` derived from the state, no transitional table), so every existing
/// case is unchanged by construction rather than by hand-editing each one.
struct BytesOpts<'a> {
    /// `Some(None)` = emit no `variant` key even under `releasing`;
    /// `Some(Some(v))` = emit exactly `v`; `None` = derive it from the state
    /// (`releasing` → `"final"`, `held` → absent), which is the correct record
    /// shape and what every pre-HARDEN-03 case means.
    variant: Option<Option<&'a str>>,
    /// `Some((sha, files, bytes))` also emits a `[wallet_bundle_transitional]`
    /// table pinning those figures, with `path = dir_name` — the same directory,
    /// because that is exactly the live record's shape and the reason the
    /// discriminator is needed at all.
    transitional: Option<(&'a str, i64, i64)>,
}

impl Default for BytesOpts<'_> {
    fn default() -> Self {
        Self { variant: None, transitional: None }
    }
}

/// A fixture record whose `[wallet_bundle]` points at `dir_name` under the root,
/// pins `sha`/`files`/`bytes`, and carries the given release state and toolchain.
#[allow(clippy::too_many_arguments)]
fn bytes_fixture(
    tag: &str,
    dir_name: &str,
    files_in_dir: &[(&str, &[u8])],
    pinned_sha: &str,
    pinned_files: i64,
    pinned_bytes: i64,
    release_state: &str,
    toolchain: (&str, &str, &str, &str),
) -> PathBuf {
    bytes_fixture_opts(
        tag,
        dir_name,
        files_in_dir,
        pinned_sha,
        pinned_files,
        pinned_bytes,
        release_state,
        toolchain,
        BytesOpts::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn bytes_fixture_opts(
    tag: &str,
    dir_name: &str,
    files_in_dir: &[(&str, &[u8])],
    pinned_sha: &str,
    pinned_files: i64,
    pinned_bytes: i64,
    release_state: &str,
    toolchain: (&str, &str, &str, &str),
    opts: BytesOpts<'_>,
) -> PathBuf {
    let root = std::env::temp_dir().join(format!("vcm-bundle-bytes-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let sha = init_git_root(&root);
    for (rel, body) in files_in_dir {
        let p = root.join(dir_name).join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
    }
    let (node, npm, wasm_pack, rustc) = toolchain;
    // The check reads `wasm-pack` from `wallet/node_modules/.bin`, NOT from PATH —
    // the record pins 0.12.1 there and a different 0.13.1 is commonly on PATH, so
    // reading PATH would compare against the wrong binary. A fixture root has no
    // node_modules, so it gets a stub that reports the version this fixture pins.
    // The production check is not weakened to accommodate the fixture; the fixture
    // provides what the production check requires.
    let bin = root.join("wallet/node_modules/.bin");
    std::fs::create_dir_all(&bin).unwrap();
    let stub = bin.join("wasm-pack");
    std::fs::write(&stub, format!("#!/bin/sh\necho \"wasm-pack {wasm_pack}\"\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut record = format!(
        "[wallet_bundle]\n\
         sha256          = \"{pinned_sha}\"\n\
         method          = \"sha256 over the LC_ALL=C-sorted per-file manifest of {dir_name}\"\n\
         path            = \"{dir_name}\"\n\
         files           = {pinned_files}\n\
         bytes           = {pinned_bytes}\n\
         bytes_method    = \"sum of the {pinned_files} REGULAR FILE sizes; directory entries are excluded\"\n\
         command         = \"cd wallet && npm run build\"\n\
         command_expands = \"npm run build:wasm && tsc && vite build\"\n\
         source_sha      = \"{sha}\"\n\n\
         [wallet_bundle.toolchain]\n\
         node       = \"{node} (fixture)\"\n\
         npm        = \"{npm} (fixture)\"\n\
         wasm_pack  = \"{wasm_pack} (fixture)\"\n\
         rustc      = \"{rustc} (fixture)\"\n\n"
    );
    // HARDEN-03: the second table, pinning the OTHER variant's figures against the
    // SAME `path` — the live record's shape, and the reason `variant` exists.
    if let Some((tsha, tfiles, tbytes)) = opts.transitional {
        record.push_str(&format!(
            "[wallet_bundle_transitional]\n\
             sha256          = \"{tsha}\"\n\
             method          = \"sha256 over the LC_ALL=C-sorted per-file manifest of {dir_name}\"\n\
             path            = \"{dir_name}\"\n\
             files           = {tfiles}\n\
             bytes           = {tbytes}\n\
             bytes_method    = \"sum of the {tfiles} REGULAR FILE sizes; directory entries are excluded\"\n\
             command         = \"cd wallet && npm run build:transitional\"\n\
             command_expands = \"WALLET_CONFIG_VARIANT=transitional npm run build:wasm && tsc && vite build\"\n\
             source_sha      = \"{sha}\"\n\
             install_phase   = \"B.1 — superseded by [wallet_bundle] at Phase D.8\"\n\n\
             [wallet_bundle_transitional.toolchain]\n\
             node       = \"{node} (fixture)\"\n\
             npm        = \"{npm} (fixture)\"\n\
             wasm_pack  = \"{wasm_pack} (fixture)\"\n\
             rustc      = \"{rustc} (fixture)\"\n\n"
        ));
    }
    record.push_str(&format!(
        "[wallet_bundle_release]\n\
         state  = \"{release_state}\"\n\
         reason = \"fixture\"\n"
    ));
    let variant = match opts.variant {
        Some(explicit) => explicit,
        None if release_state == "releasing" => Some("final"),
        None => None,
    };
    if let Some(va) = variant {
        record.push_str(&format!("variant = \"{va}\"\n"));
    }
    write_file(&root.join(vcm::RELEASE_RECORD_ARTIFACT), &record);
    root
}

/// The tuple a fixture must pin for its toolchain assertion to PASS: the host's own
/// node/npm/rustc, plus the version the fixture's own `wasm-pack` stub reports.
fn host_tuple() -> (String, String, String, String) {
    (
        host_tool_version("node", &["--version"]),
        host_tool_version("npm", &["--version"]),
        // Whatever the fixture stub is told to print; 0.12.1 matches the release pin
        // and keeps the fixture readable next to the record.
        "0.12.1".to_string(),
        host_tool_version("rustc", &["--version"]),
    )
}

/// The measurement procedure itself, checked against the record's OWN documented
/// shell pipeline rather than against its own output.
///
/// This is the independence I-B2 asks for. The digest is defined by a procedure,
/// not by a number, so the meaningful assertion is that the Rust implementation
/// and the published pipeline agree on an arbitrary directory:
///
///   cd <dir>/.. && find <dir> -type f | sed 's|^<dir>/||' | LC_ALL=C sort \
///     | while read -r f; do printf "%s  %s\n" \
///         "$(sha256sum "<dir>/$f" | cut -d' ' -f1)" "$f"; done | sha256sum
///
/// Two details this would catch and a hand-written expected value would not: a
/// sort that is not byte-wise (a locale-aware sort orders `a-b` and `aB`
/// differently), and a separator that is one space instead of `printf`'s two.
#[test]
fn bii_measurement_reproduces_the_records_own_documented_pipeline() {
    let root = std::env::temp_dir().join(format!("vcm-pipeline-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dir = root.join("dist");
    // Names chosen to separate a byte-wise sort from a locale-aware one, plus a
    // nested path, an empty file, and one holding non-UTF8 bytes.
    for (rel, body) in [
        ("a-b.js", &b"alpha"[..]),
        ("aB.js", &b"beta"[..]),
        ("Z.js", &b"zulu"[..]),
        ("zk/spend.zkey", &[0x00u8, 0xFF, 0x10][..]),
        (".well-known/ii-alternative-origins", &b"{}"[..]),
        ("empty.txt", &b""[..]),
    ] {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
    }

    let measured = vcm::measure_bundle_dir(&dir).expect("the fixture directory must measure");

    let script = "find dist -type f | sed 's|^dist/||' | LC_ALL=C sort \
                  | while read -r f; do printf \"%s  %s\\n\" \
                      \"$(sha256sum \"dist/$f\" | cut -d' ' -f1)\" \"$f\"; done \
                  | sha256sum | cut -d' ' -f1";
    let out = Command::new("bash")
        .arg("-c")
        .arg(script)
        .current_dir(&root)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "[B-ii] cannot run the record's documented pipeline via bash/find/sha256sum: {e}. \
                 NOT skipped: without this, `measure_bundle_dir` would only ever be compared \
                 against itself, and the digest is DEFINED by that pipeline"
            )
        });
    assert!(out.status.success(), "pipeline failed: {}", String::from_utf8_lossy(&out.stderr));
    let shell_digest = String::from_utf8_lossy(&out.stdout).trim().to_string();

    assert_eq!(
        measured.sha256, shell_digest,
        "the Rust measurement must reproduce the record's own documented procedure byte for byte"
    );
    assert_eq!(measured.files, 6, "six regular files; directory entries excluded");
    assert_eq!(
        measured.bytes,
        (5 + 4 + 4 + 3 + 2 + 0) as i64,
        "bytes is the sum of the regular file sizes"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// AB-1, THE DECISIVE NEGATIVE TEST. One byte of one served JS file flipped -> the
/// byte check FAILS. The baseline is asserted to pass FIRST, so the case cannot
/// "pass" because the fixture was broken all along.
#[test]
fn bii_ab1_one_flipped_byte_fails_the_byte_check() {
    let tuple = host_tuple();
    let tuple_refs = (
        tuple.0.as_str(),
        tuple.1.as_str(),
        tuple.2.as_str(),
        tuple.3.as_str(),
    );
    let clean: &[(&str, &[u8])] = &[
        ("index.js", &b"export const ok = 1;\n"[..]),
        ("assets/app.js", &b"console.log('hello');\n"[..]),
    ];

    // BASELINE: measure the clean directory, pin those figures, expect zero
    // violations.
    let probe = bytes_fixture(
        "ab1-probe", "dist", clean, &"0".repeat(64), 0, 0, "held", tuple_refs,
    );
    let truth = vcm::measure_bundle_dir(&probe.join("dist")).expect("probe measures");
    let _ = std::fs::remove_dir_all(&probe);

    let base = bytes_fixture(
        "ab1-baseline", "dist", clean, &truth.sha256, truth.files, truth.bytes, "releasing",
        tuple_refs,
    );
    let (base_v, base_report) = vcm::check_wallet_bundle_bytes(&base);
    assert!(
        base_v.is_empty(),
        "[AB-1] BASELINE must pass before the byte is flipped, got:\n{}\nreport:\n{base_report}",
        rendered(&base_v)
    );
    assert!(
        base_report.contains("OWED"),
        "[AB-1] the baseline must have MEASURED, not declared itself not-owed; report:\n{base_report}"
    );
    let _ = std::fs::remove_dir_all(&base);

    // DEFECT: exactly one byte of one served JS file differs, with the SAME pinned
    // figures. `files` and `bytes` are unchanged by a flip, so the digest is the
    // only thing that can catch it — which is the whole reason a byte check exists
    // alongside the record's counts.
    let flipped: &[(&str, &[u8])] = &[
        ("index.js", &b"export const ok = 1;\n"[..]),
        ("assets/app.js", &b"console.log('hellO');\n"[..]),
    ];
    let root = bytes_fixture(
        "ab1-flipped", "dist", flipped, &truth.sha256, truth.files, truth.bytes, "releasing",
        tuple_refs,
    );
    let (v, report) = vcm::check_wallet_bundle_bytes(&root);
    assert!(
        fires(&v),
        "[AB-1] one flipped byte MUST fail the byte check; report:\n{report}"
    );
    assert!(
        rendered(&v).contains("sha256"),
        "[AB-1] the violation must name the digest mismatch, got:\n{}",
        rendered(&v)
    );
    // And the counts really were identical, so the digest is what caught it.
    let flipped_measured = vcm::measure_bundle_dir(&root.join("dist")).unwrap();
    assert_eq!(flipped_measured.files, truth.files, "the flip did not change `files`");
    assert_eq!(flipped_measured.bytes, truth.bytes, "the flip did not change `bytes`");
    assert_ne!(flipped_measured.sha256, truth.sha256, "only the digest moved");
    let _ = std::fs::remove_dir_all(&root);
}

/// AB-3 (i): the toolchain assertion REFUSES on mismatch — a violation, never a
/// skip and never a pass. A digest measured under a different tuple is a different
/// number, not weaker evidence about the pinned one.
#[test]
fn bii_ab3_toolchain_mismatch_is_a_violation_and_nothing_is_measured() {
    let clean: &[(&str, &[u8])] = &[("index.js", &b"export const ok = 1;\n"[..])];
    // The record pins a tuple no host can be running, and pins the CORRECT digest
    // for the directory — so if the check measured anyway it would pass, and the
    // only thing that can fail this case is the tuple assertion itself.
    let probe = bytes_fixture(
        "ab3-tc-probe", "dist", clean, &"0".repeat(64), 0, 0, "held",
        ("0.0.0", "0.0.0", "0.0.0", "0.0.0"),
    );
    let truth = vcm::measure_bundle_dir(&probe.join("dist")).expect("probe measures");
    let _ = std::fs::remove_dir_all(&probe);

    let root = bytes_fixture(
        "ab3-tc", "dist", clean, &truth.sha256, truth.files, truth.bytes, "releasing",
        ("0.0.0", "0.0.0", "0.0.0", "0.0.0"),
    );
    let (v, report) = vcm::check_wallet_bundle_bytes(&root);
    assert!(
        fires(&v),
        "[AB-3] a toolchain mismatch must be a VIOLATION; report:\n{report}"
    );
    assert!(
        rendered(&v).contains("MISMATCH") || rendered(&v).contains("could not be measured"),
        "[AB-3] the violation must name the tuple, got:\n{}",
        rendered(&v)
    );
    assert!(
        report.contains("measurement NOT ATTEMPTED"),
        "[AB-3] nothing may be measured under a mismatched tuple — the report must say the \
         measurement was not attempted, so a reader cannot mistake a refusal for a comparison; \
         report:\n{report}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// AB-3 (ii): the marker is itself checked. An absent table, an absent `state`, an
/// unrecognised `state` and an absent `reason` are each violations of the MANDATORY
/// record-coverage half — so "the measurement did not run" can never be inferred
/// from silence.
///
/// HARDEN-03 (AC-9) extends this to `variant`: the marker now carries a second
/// field, and it is checked by the same mandatory half and in the same way —
/// required exactly when `state = "releasing"`, forbidden under `held`, and an
/// unrecognised value refused rather than guessed. The per-case detail lives in
/// `hard03_marker_variant_presence_rule_is_checked_on_the_record_half`; the two
/// cases here keep the two fields' rules asserted TOGETHER, so a future edit that
/// made one field's absence mask the other's would be caught in this test rather
/// than in neither.
#[test]
fn bii_ab3_the_release_marker_is_itself_checked() {
    for (tag, mutate, needle) in [
        (
            "marker-variant-absent-while-releasing",
            Box::new(|b: &mut Bundles| b.release_state = Some("releasing".into()))
                as Box<dyn Fn(&mut Bundles)>,
            "declares no `variant`",
        ),
        (
            "marker-variant-under-held",
            Box::new(|b: &mut Bundles| b.release_variant = Some("transitional".into())),
            "is `held` but the table declares",
        ),
    ] {
        assert_defect_fires(tag, |b| mutate(b), needle);
    }
    for (tag, mutate, needle) in [
        (
            "marker-absent",
            Box::new(|b: &mut Bundles| {
                b.release_state = None;
                b.release_reason = None;
            }) as Box<dyn Fn(&mut Bundles)>,
            "no `[wallet_bundle_release]` table",
        ),
        (
            "marker-state-absent",
            Box::new(|b: &mut Bundles| b.release_state = None),
            "declares no `state`",
        ),
        (
            "marker-state-unknown",
            Box::new(|b: &mut Bundles| b.release_state = Some("maybe".into())),
            "not one of",
        ),
        (
            "marker-reason-absent",
            Box::new(|b: &mut Bundles| b.release_reason = None),
            "declares no `reason`",
        ),
    ] {
        assert_defect_fires(tag, |b| mutate(b), needle);
    }
}

/// AB-3 (iii): marker says RELEASING and `dist` is absent or stale -> FAILS CLOSED.
///
/// This is the shape that matters most, because absent is the NORMAL state:
/// `wallet/dist` is gitignored, so a check that read absence as agreement would
/// restore exactly the gap this lane closed.
#[test]
fn bii_ab3_releasing_with_an_absent_or_stale_dist_fails_closed() {
    let tuple = host_tuple();
    let tuple_refs = (
        tuple.0.as_str(),
        tuple.1.as_str(),
        tuple.2.as_str(),
        tuple.3.as_str(),
    );

    // (a) ABSENT: the record says releasing and names a directory that does not
    // exist.
    let root = bytes_fixture(
        "ab3-absent", "dist", &[], &"a".repeat(64), 11, 14_103_504, "releasing", tuple_refs,
    );
    let (v, report) = vcm::check_wallet_bundle_bytes(&root);
    assert!(
        fires(&v),
        "[AB-3] releasing + absent dist must FAIL CLOSED, never read as agreement; report:\n{report}"
    );
    assert!(
        rendered(&v).contains("FAILS CLOSED"),
        "[AB-3] the violation must say so, got:\n{}",
        rendered(&v)
    );
    let _ = std::fs::remove_dir_all(&root);

    // (b) STALE: the directory exists and is a real bundle, but it is an older one —
    // one file short and smaller — against the pinned figures. "Present" is not
    // "current", which is the state the real `wallet/dist` was measured in.
    let current: &[(&str, &[u8])] = &[
        ("index.js", &b"export const ok = 1;\n"[..]),
        (".well-known/ii-alternative-origins", &b"{\"alternativeOrigins\":[]}"[..]),
    ];
    let probe = bytes_fixture(
        "ab3-stale-probe", "dist", current, &"0".repeat(64), 0, 0, "held", tuple_refs,
    );
    let truth = vcm::measure_bundle_dir(&probe.join("dist")).expect("probe measures");
    let _ = std::fs::remove_dir_all(&probe);

    let stale: &[(&str, &[u8])] = &[("index.js", &b"export const ok = 1;\n"[..])];
    let root = bytes_fixture(
        "ab3-stale", "dist", stale, &truth.sha256, truth.files, truth.bytes, "releasing",
        tuple_refs,
    );
    let (v, report) = vcm::check_wallet_bundle_bytes(&root);
    assert!(fires(&v), "[AB-3] releasing + stale dist must fail; report:\n{report}");
    let text = rendered(&v);
    assert!(text.contains("sha256"), "the digest mismatch must be named: {text}");
    assert!(text.contains("files"), "the file-count mismatch must be named too: {text}");
    let _ = std::fs::remove_dir_all(&root);
}

/// The `held` path is a DECLARED state, not a skip: it reports what it did and why,
/// and it does not measure. Paired with the marker cases above, that is what makes
/// "not measured here" auditable.
#[test]
fn bii_held_is_a_declared_state_and_says_so() {
    let tuple = host_tuple();
    let root = bytes_fixture(
        "bii-held",
        "dist",
        &[],
        &"a".repeat(64),
        11,
        14_103_504,
        "held",
        (tuple.0.as_str(), tuple.1.as_str(), tuple.2.as_str(), tuple.3.as_str()),
    );
    let (v, report) = vcm::check_wallet_bundle_bytes(&root);
    assert!(
        v.is_empty(),
        "held must not produce violations — the directory is legitimately absent:\n{}",
        rendered(&v)
    );
    assert!(
        report.contains("NOT OWED AT THIS HEAD") && report.contains("not a skip"),
        "the report must DECLARE the state rather than fall silent; report:\n{report}"
    );
    assert!(
        report.contains("fixture"),
        "and it must name the recorded reason, so the declaration is auditable; report:\n{report}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// =============================================================================
// HARDEN-03 — (A) the release VARIANT discriminator, (B) tree-shape refusals.
// =============================================================================
//
// WHY (A) EXISTS. Before this lane `check_wallet_bundle_bytes` read
// `doc.get("wallet_bundle")` unconditionally, and BOTH tables record
// `path = "wallet/dist"`. There was therefore NO STATE in which a Phase B.1 lane
// could have its transitional `dist` measured: flipping the marker to `releasing`
// compared the transitional tree against the FINAL digest and failed. That is why
// `[wallet_bundle_transitional]`'s digest is packet-evidenced and `[wallet_bundle]`'s
// is checker-evidenced — a difference in evidentiary status between two rows that
// look identical in the file.
//
// WHY THE FIXTURES MODEL THE TWO VARIANTS FAITHFULLY. The real bundles differ in
// exactly ONE file, `wallet-config.json`, whose `derivationOrigin` member is
// present in the final build and ABSENT in the transitional one (the record calls
// it a 69-byte delta). The fixtures below reproduce that shape rather than using
// two arbitrary directories, so the case they prove is the case B.1 will meet.

/// The FINAL bundle's shape: `wallet-config.json` CARRIES `derivationOrigin`.
const FINAL_FILES: &[(&str, &[u8])] = &[
    ("index.html", b"<!doctype html><script src=/assets/app.js></script>\n"),
    ("assets/app.js", b"console.log('stsh');\n"),
    (
        "wallet-config.json",
        b"{\n  \"launchOrigin\": \"https://app.stsh.fi\",\n  \"derivationOrigin\": \"https://s3tyu-aaaaa-aaaab-qhdjq-cai.icp0.io\"\n}\n",
    ),
];

/// The TRANSITIONAL bundle's shape: identical, except the key is OMITTED. That
/// omission is the property the step-7 signer rotation depends on.
const TRANSITIONAL_FILES: &[(&str, &[u8])] = &[
    ("index.html", b"<!doctype html><script src=/assets/app.js></script>\n"),
    ("assets/app.js", b"console.log('stsh');\n"),
    (
        "wallet-config.json",
        b"{\n  \"launchOrigin\": \"https://app.stsh.fi\"\n}\n",
    ),
];

fn tuple_refs(t: &(String, String, String, String)) -> (&str, &str, &str, &str) {
    (t.0.as_str(), t.1.as_str(), t.2.as_str(), t.3.as_str())
}

/// Measure a variant's tree through the PRODUCTION measurement, never a literal.
/// No expected digest is written down anywhere in this file: both come from
/// `measure_bundle_dir` over a probe, so the cases stay independent of the
/// artifact they check.
fn measure_variant(
    tag: &str,
    files: &[(&str, &[u8])],
    tuple: (&str, &str, &str, &str),
) -> vcm::MeasuredBundle {
    let probe = bytes_fixture(tag, "dist", files, &"0".repeat(64), 0, 0, "held", tuple);
    let m = vcm::measure_bundle_dir(&probe.join("dist")).expect("the probe tree must measure");
    let _ = std::fs::remove_dir_all(&probe);
    m
}

/// A record carrying BOTH tables at the same `path`, with the marker `releasing`
/// and the given variant, over `on_disk`.
fn variant_fixture(
    tag: &str,
    on_disk: &[(&str, &[u8])],
    variant: Option<&str>,
    fin: &vcm::MeasuredBundle,
    tr: &vcm::MeasuredBundle,
    tuple: (&str, &str, &str, &str),
) -> PathBuf {
    bytes_fixture_opts(
        tag,
        "dist",
        on_disk,
        &fin.sha256,
        fin.files,
        fin.bytes,
        "releasing",
        tuple,
        BytesOpts {
            variant: Some(variant),
            transitional: Some((tr.sha256.as_str(), tr.files, tr.bytes)),
        },
    )
}

/// AC-1 + AC-2 + AC-3, run together so each negative's BASELINE is the positive
/// immediately above it, in the same record, with only the directory or the
/// declared variant changed. AC-2 is the decisive one: it is the case that is
/// structurally IMPOSSIBLE to express before this lane.
#[test]
fn hard03_variant_selects_the_table_the_measurement_is_compared_against() {
    let t = host_tuple();
    let tup = tuple_refs(&t);
    let fin = measure_variant("h3-probe-final", FINAL_FILES, tup);
    let tr = measure_variant("h3-probe-transitional", TRANSITIONAL_FILES, tup);
    assert_ne!(
        fin.sha256, tr.sha256,
        "the two variant trees must measure DIFFERENTLY, or none of the cases below discriminate \
         anything — this mirrors the record's own `two bundles, two digests` requirement"
    );

    // AC-1 (and the baseline for AC-2): transitional declared, transitional tree.
    let root = variant_fixture("h3-ac1", TRANSITIONAL_FILES, Some("transitional"), &fin, &tr, tup);
    let (v, report) = vcm::check_wallet_bundle_bytes(&root);
    assert!(
        v.is_empty(),
        "[AC-1] a transitional `dist` declared as `transitional` must PASS — this is the state \
         that did not exist before HARDEN-03, and Phase B.1 needs it. Got:\n{}\nreport:\n{report}",
        rendered(&v)
    );
    assert!(
        report.contains("wallet_bundle_transitional") && report.contains("transitional"),
        "[AC-1] the report must NAME the table it measured against, so a reader never infers \
         which pin was compared; report:\n{report}"
    );
    let _ = std::fs::remove_dir_all(&root);

    // AC-2, THE DECISIVE CROSS-VARIANT NEGATIVE: the same record, the same declared
    // variant, but the FINAL tree on disk. Before this lane this case could not
    // fail, because it could not be expressed.
    let root = variant_fixture("h3-ac2", FINAL_FILES, Some("transitional"), &fin, &tr, tup);
    let (v, report) = vcm::check_wallet_bundle_bytes(&root);
    assert!(
        fires(&v),
        "[AC-2] the FINAL tree declared as `transitional` must FAIL; report:\n{report}"
    );
    let text = rendered(&v);
    assert!(
        text.contains("CROSS-VARIANT"),
        "[AC-2] D-2 requires a NAMED diagnostic, not a bare sha comparison: the measured digest \
         IS the other table's pin, so the failure is `the wrong variant was built`. Got:\n{text}"
    );
    assert!(
        text.contains("FINAL variant only") && text.contains("build:transitional"),
        "[AC-2] and it must say that the gate builds the final variant only and name the \
         out-of-gate transitional command — a confusing-but-correct failure is how a future lane \
         loosens a check for the wrong reason. Got:\n{text}"
    );
    assert!(
        text.contains("do NOT re-pin") || text.contains("NOT re-pin"),
        "[AC-2] the remedy must be stated as rebuild, never re-pin. Got:\n{text}"
    );
    let _ = std::fs::remove_dir_all(&root);

    // AC-3, the mirror: the transitional tree declared as `final`.
    let root = variant_fixture("h3-ac3", TRANSITIONAL_FILES, Some("final"), &fin, &tr, tup);
    let (v, report) = vcm::check_wallet_bundle_bytes(&root);
    assert!(
        fires(&v),
        "[AC-3] a transitional `dist` declared as `final` must FAIL; report:\n{report}"
    );
    let text = rendered(&v);
    assert!(
        text.contains("`[wallet_bundle].sha256`") && text.contains("CROSS-VARIANT"),
        "[AC-3] the violation must name the FINAL table as the one compared against, and identify \
         the tree as the other variant. Got:\n{text}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// AC-4 on the BYTE half: `releasing` with no `variant`, and with an unrecognised
/// one, are refusals — and NOTHING is measured, exactly as for an unrecognised
/// `state`. Defaulting either way is the mis-comparison this lane removes.
#[test]
fn hard03_releasing_needs_a_recognised_variant_on_the_byte_half() {
    let t = host_tuple();
    let tup = tuple_refs(&t);
    let fin = measure_variant("h3-probe-ac4-f", FINAL_FILES, tup);
    let tr = measure_variant("h3-probe-ac4-t", TRANSITIONAL_FILES, tup);

    // BASELINE: the same record WITH a correct variant passes, so the cases below
    // cannot pass because the fixture was broken.
    let base = variant_fixture("h3-ac4-baseline", FINAL_FILES, Some("final"), &fin, &tr, tup);
    let (bv, breport) = vcm::check_wallet_bundle_bytes(&base);
    assert!(
        bv.is_empty(),
        "[AC-4] BASELINE must pass first, got:\n{}\nreport:\n{breport}",
        rendered(&bv)
    );
    let _ = std::fs::remove_dir_all(&base);

    for (tag, variant, needle) in [
        ("h3-ac4-absent", None, "no `variant` is declared"),
        ("h3-ac4-unknown", Some("staging"), "is `staging`, not one of"),
    ] {
        let root = variant_fixture(tag, FINAL_FILES, variant, &fin, &tr, tup);
        let (v, report) = vcm::check_wallet_bundle_bytes(&root);
        assert!(
            fires(&v),
            "[AC-4/{tag}] must be a violation, not a guess; report:\n{report}"
        );
        let text = rendered(&v);
        assert!(
            text.contains(needle),
            "[AC-4/{tag}] the violation must SAY what is wrong (looking for `{needle}`):\n{text}"
        );
        assert!(
            !report.contains("measured   files="),
            "[AC-4/{tag}] nothing may be MEASURED when the record does not say which bundle is on \
             disk — the tree here is the FINAL one and the final pin is correct, so a check that \
             defaulted to `final` would PASS this case and hide the defect; report:\n{report}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// AC-4 + AC-5 on the RECORD half, where the marker's structure is the mandatory
/// obligation. `held` + a `variant` is the leftover-from-a-reverted-release shape:
/// harmless today, and the thing the next lane to flip `state` would inherit.
#[test]
fn hard03_marker_variant_presence_rule_is_checked_on_the_record_half() {
    for (tag, mutate, needle) in [
        (
            "variant-absent-while-releasing",
            Box::new(|b: &mut Bundles| b.release_state = Some("releasing".into()))
                as Box<dyn Fn(&mut Bundles)>,
            "declares no `variant`",
        ),
        (
            "variant-unrecognised",
            Box::new(|b: &mut Bundles| {
                b.release_state = Some("releasing".into());
                b.release_variant = Some("staging".into());
            }),
            "is not one of",
        ),
        (
            "variant-present-while-held",
            Box::new(|b: &mut Bundles| b.release_variant = Some("final".into())),
            "is `held` but the table declares",
        ),
    ] {
        assert_defect_fires(tag, |b| mutate(b), needle);
    }
}

/// And the POSITIVE for the record half: `releasing` WITH a recognised variant is
/// clean. Without this, the three negatives above would be satisfied by a rule
/// that rejected `releasing` outright.
#[test]
fn hard03_releasing_with_a_recognised_variant_is_clean_on_the_record_half() {
    for variant in vcm::WALLET_BUNDLE_VARIANTS {
        let mut b = Bundles::default();
        b.release_state = Some("releasing".into());
        b.release_variant = Some(variant.to_string());
        b.release_reason = Some(format!("fixture: releasing the {variant} bundle"));
        let root = fixture_root(&format!("h3-releasing-{variant}"), &b);
        let v = vcm::check_wallet_bundles(&root);
        assert!(
            v.is_empty(),
            "[{variant}] `releasing` with a recognised variant must be CLEAN on the record half, \
             got:\n{}",
            rendered(&v)
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// AC-8, DRIFT-LOCK. D-1 chose to reuse `WalletBundleUnbound` rather than add a
/// kind, so the `DECLARABLE_KINDS` exclusion is preserved BY CONSTRUCTION. This
/// test is what turns "by construction" into something a later lane cannot undo
/// by accident: `--deploy-posture` compares the observed violation-key set to
/// `[deploy_gate].expected_pending` for EXACT set equality, so a declarable
/// bundle kind would let a live wallet-bundle violation be declared pending and
/// ride a green gate. It never may be.
#[test]
fn hard03_wallet_bundle_unbound_is_never_declarable() {
    assert!(
        !vcm::DECLARABLE_KINDS.contains(&"WalletBundleUnbound"),
        "`WalletBundleUnbound` must NEVER be declarable in `[deploy_gate].expected_pending` — the \
         wallet bundle is what a user's browser executes, and a declarable kind would let a live \
         bundle violation be declared pending instead of fixed"
    );
    assert_eq!(
        vcm::DECLARABLE_KINDS.len(),
        4,
        "the declarable set is FOUR kinds; HARDEN-03 added no violation kind (it reuses \
         `WalletBundleUnbound` for the variant rules), so a change in this count means a kind was \
         introduced somewhere and this exclusion needs re-checking"
    );
    // And the variant vocabulary is positionally paired with the table list — the
    // pairing the byte half resolves through. A list that grew on one side only
    // would silently mis-select a table.
    assert_eq!(
        vcm::WALLET_BUNDLE_VARIANTS.len(),
        vcm::WALLET_BUNDLE_TABLES.len(),
        "`variant` names a table POSITIONALLY; the two lists must stay the same length"
    );
    for (i, v) in vcm::WALLET_BUNDLE_VARIANTS.iter().enumerate() {
        assert_eq!(
            vcm::wallet_bundle_table_for_variant(v),
            Some(vcm::WALLET_BUNDLE_TABLES[i]),
            "variant `{v}` must select `{}`",
            vcm::WALLET_BUNDLE_TABLES[i]
        );
    }
    assert_eq!(
        vcm::wallet_bundle_table_for_variant("staging"),
        None,
        "an unrecognised variant resolves to NOTHING — it is never guessed into a table"
    );
}

// ── (B) tree-shape refusals in `measure_bundle_dir` (D-4, and SSA C-1) ────────
//
// THE DEFECT THESE PIN. The record's published procedure is
// `find dist -type f | … | sha256sum`, and `find` defaults to `-P` (never
// dereference). Measured with GNU findutils and with the `bfs` build this shell
// aliases as `find`: a symlink to a file is `-type l`, so `-type f` OMITS it, and
// a symlinked directory is not descended. The Rust walker used `fs::metadata`,
// which RESOLVES — so it counted a symlink as a regular file and would descend a
// symlinked directory. The two verification paths genuinely diverged, and the
// six-ordinary-file fixture of
// `bii_measurement_reproduces_the_records_own_documented_pipeline` could not see
// it: that test guarantees agreement on symlink-free trees only, which is a much
// narrower claim than its name suggests.
//
// AND THERE ARE TWO DISTINCT FAILURE MODES, not one (SSA C-1):
//   * a symlink to a REAL file      — the shell omits it, `fs::metadata` COUNTS it
//                                     → the two paths produce different DIGESTS;
//   * a DANGLING symlink            — the shell omits it silently, `fs::metadata`
//                                     ERRORS → one path ABORTS with an opaque
//                                     `cannot stat`, indistinguishable from a
//                                     disk fault.
// Each gets its own fixture below. The general symlink case does NOT implicitly
// cover the dangling one: it is the dangling case whose behaviour actually
// changes from "opaque I/O error" to "clear tree-shape refusal", and it is the
// one most likely to appear in a real build tree.
//
// THE FIX IS REFUSAL, NOT IMITATION. Matching `find -P`'s omission would leave a
// file inside the shipped tree that no digest covers, and an omitted file is
// exactly as dangerous as a doubled one. So every assertion below is that the
// measurement REFUSES — never that some particular `find` build's output was
// reproduced. That also keeps these cases independent of which `find` is on this
// host, which is the author-machine-only defect class.

/// A clean tree of ordinary files and REAL nested directories, written fresh.
#[cfg(unix)]
fn clean_tree(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("vcm-treeshape-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for (rel, body) in [
        ("index.html", &b"<!doctype html>\n"[..]),
        ("assets/app.js", &b"console.log(1);\n"[..]),
        ("zk/spend.zkey", &[0x00u8, 0xFF][..]),
    ] {
        let p = root.join("dist").join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
    }
    root
}

/// AC-6(a): a symlink to a REAL file inside the tree is REFUSED — asserted as a
/// refusal, not as an omitted-or-counted file. The BASELINE (the same tree
/// without the link) is measured first, so the case cannot pass because the
/// fixture was broken.
#[cfg(unix)]
#[test]
fn hard03_symlink_to_a_real_file_is_refused() {
    let root = clean_tree("symlink-file");
    let dist = root.join("dist");
    let baseline = vcm::measure_bundle_dir(&dist).expect("[AC-6a] the clean BASELINE must measure");
    assert_eq!(baseline.files, 3, "[AC-6a] baseline is three ordinary files");

    std::os::unix::fs::symlink("app.js", dist.join("assets/alias.js")).unwrap();
    let err = vcm::measure_bundle_dir(&dist)
        .expect_err("[AC-6a] a symlink to a real file MUST be refused, not resolved and counted");
    assert!(
        err.contains("SYMBOLIC LINK") && err.contains("alias.js"),
        "[AC-6a] the refusal must name the tree shape AND the offending entry, so a reader can \
         fix the tree rather than guess at an I/O fault: {err}"
    );
    assert!(
        err.contains("-P") || err.contains("OMITS"),
        "[AC-6a] and it must say WHY resolving it would be wrong — the published procedure would \
         never have seen the file: {err}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// AC-6(b), SSA C-1: a DANGLING symlink — target does not exist. This is the
/// second, DISTINCT failure mode. The old code's `fs::metadata` could not stat
/// the absent target and returned `cannot stat …`, which surfaced as the
/// "measured directory is unusable" arm and reads like a disk fault; the shell
/// procedure, meanwhile, skips it silently and still produces a digest. After the
/// fix both are one clear tree-shape refusal.
#[cfg(unix)]
#[test]
fn hard03_dangling_symlink_is_refused_as_a_tree_shape_not_as_a_stat_failure() {
    let root = clean_tree("symlink-dangling");
    let dist = root.join("dist");
    let baseline = vcm::measure_bundle_dir(&dist).expect("[AC-6b] the clean BASELINE must measure");

    // The target is deliberately OUTSIDE the tree and does not exist.
    std::os::unix::fs::symlink("../../nowhere/absent.js", dist.join("dangling.js")).unwrap();
    assert!(
        !dist.join("dangling.js").exists(),
        "[AC-6b] the fixture must really be DANGLING — `Path::exists` follows the link, so a \
         `true` here would mean the target was accidentally created and this case is testing the \
         symlink-to-a-real-file mode instead"
    );
    assert!(
        std::fs::symlink_metadata(dist.join("dangling.js")).is_ok(),
        "[AC-6b] …while the link itself is present, which is exactly the asymmetry the fix rests \
         on: `symlink_metadata` sees it, `metadata` cannot"
    );

    let err = vcm::measure_bundle_dir(&dist).expect_err("[AC-6b] a dangling symlink MUST be refused");
    assert!(
        err.contains("SYMBOLIC LINK") && err.contains("dangling.js"),
        "[AC-6b] it must be refused AS A TREE SHAPE, naming the entry — not reported as an \
         inability to stat something: {err}"
    );
    assert!(
        !err.contains("cannot stat"),
        "[AC-6b] and specifically NOT as the opaque `cannot stat` the old `fs::metadata` walker \
         produced, which a reader would read as an I/O fault and retry rather than fix: {err}"
    );

    // And the clean baseline still measures identically once the link is removed —
    // the refusal is about the link, not about the tree having been touched.
    std::fs::remove_file(dist.join("dangling.js")).unwrap();
    assert_eq!(
        vcm::measure_bundle_dir(&dist).expect("measures again"),
        baseline,
        "[AC-6b] removing the link restores the ORIGINAL measurement exactly"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// AC-6(c): a symlinked DIRECTORY is refused and NOT descended. `find -P` does not
/// descend one; the old `fs::metadata` walker did, via `meta.is_dir()`. Refusing
/// also closes the directory-cycle case for free.
#[cfg(unix)]
#[test]
fn hard03_symlinked_directory_is_refused_and_not_descended() {
    let root = clean_tree("symlink-dir");
    let dist = root.join("dist");
    let _ = vcm::measure_bundle_dir(&dist).expect("[AC-6c] the clean BASELINE must measure");

    // A link to a REAL sibling directory: resolving it would double every file
    // under `assets/` under a second set of paths.
    std::os::unix::fs::symlink("assets", dist.join("mirror")).unwrap();
    let err = vcm::measure_bundle_dir(&dist)
        .expect_err("[AC-6c] a symlinked directory MUST be refused, never descended");
    assert!(
        err.contains("SYMBOLIC LINK") && err.contains("mirror"),
        "[AC-6c] the refusal must name it: {err}"
    );
    assert!(
        !err.contains("mirror/app.js"),
        "[AC-6c] and it must be refused AT the link — a message naming a path INSIDE it would \
         mean the walker descended first: {err}"
    );

    // The self-referential case, which is the cycle: refusing the link refuses it.
    std::fs::remove_file(dist.join("mirror")).unwrap();
    std::os::unix::fs::symlink(".", dist.join("loop")).unwrap();
    let err = vcm::measure_bundle_dir(&dist)
        .expect_err("[AC-6c] a self-referential directory link must be refused, not recursed");
    assert!(err.contains("SYMBOLIC LINK"), "[AC-6c] {err}");
    let _ = std::fs::remove_dir_all(&root);
}

/// AC-6(d): a FIFO is refused. `-type f` omits it; treating it as a regular file
/// would make `fs::read` BLOCK FOREVER, so silence here is not even a safe
/// default — a gate that hung would be worse than one that failed.
#[cfg(unix)]
#[test]
fn hard03_a_fifo_is_refused() {
    let root = clean_tree("fifo");
    let dist = root.join("dist");
    let _ = vcm::measure_bundle_dir(&dist).expect("[AC-6d] the clean BASELINE must measure");

    let fifo = dist.join("pipe");
    let out = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "[AC-6d] cannot run `mkfifo`: {e}. NOT skipped: a special-file case that silently \
                 does not run is the same gap this lane closed — the walker's `else` arm would \
                 then be asserted by nothing. Install coreutils or run this suite on a host with \
                 it, as this file already requires bash/find/sha256sum/git."
            )
        });
    assert!(out.status.success(), "[AC-6d] mkfifo failed: {}", String::from_utf8_lossy(&out.stderr));

    let err = vcm::measure_bundle_dir(&dist).expect_err("[AC-6d] a FIFO MUST be refused");
    assert!(
        err.contains("NOT A REGULAR FILE") && err.contains("pipe"),
        "[AC-6d] the refusal must name the shape and the entry: {err}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// AC-6, END TO END: the refusal surfaces through `check_wallet_bundle_bytes` as
/// the existing fail-closed `WalletBundleUnbound`, with the tree-shape sentence
/// intact — not swallowed, and not rewritten into a bare digest mismatch. A
/// refusal that only exists inside `measure_bundle_dir` is not yet a gate finding.
#[cfg(unix)]
#[test]
fn hard03_a_refused_tree_shape_fails_the_byte_check_closed() {
    let t = host_tuple();
    let tup = tuple_refs(&t);
    let fin = measure_variant("h3-probe-shape", FINAL_FILES, tup);
    let tr = measure_variant("h3-probe-shape-t", TRANSITIONAL_FILES, tup);

    // BASELINE: the correct tree, correctly declared, passes.
    let root = variant_fixture("h3-shape-baseline", FINAL_FILES, Some("final"), &fin, &tr, tup);
    let (bv, breport) = vcm::check_wallet_bundle_bytes(&root);
    assert!(
        bv.is_empty(),
        "[AC-6/e2e] BASELINE must pass first, got:\n{}\nreport:\n{breport}",
        rendered(&bv)
    );

    // Then add one dangling symlink to that very tree — nothing else changes, so
    // the pinned digest/files/bytes are still exactly right for the real files.
    std::os::unix::fs::symlink("../gone/x.js", root.join("dist/dangling.js")).unwrap();
    let (v, report) = vcm::check_wallet_bundle_bytes(&root);
    assert!(
        fires(&v),
        "[AC-6/e2e] a refused tree shape must FAIL CLOSED on the byte half; report:\n{report}"
    );
    let text = rendered(&v);
    assert!(
        text.contains("FAILS CLOSED") && text.contains("SYMBOLIC LINK"),
        "[AC-6/e2e] the fail-closed arm must carry the tree-shape reason through, or the operator \
         sees `the measured directory is unusable` and nothing actionable. Got:\n{text}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// AC-7, CLEAN-TREE REGRESSION. The switch from `fs::metadata` to
/// `symlink_metadata` changes how EVERY entry is classified, so the thing most
/// worth pinning is that it changed nothing for ordinary trees: real nested
/// directories are still descended, and the digest still reproduces the record's
/// own published shell pipeline. `bii_measurement_reproduces_the_records_own_documented_pipeline`
/// above covers the flat-ish six-file case; this one is deliberately deeper.
#[test]
fn hard03_clean_trees_measure_exactly_as_before() {
    let root = std::env::temp_dir().join(format!("vcm-clean-regression-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dist = root.join("dist");
    let content: &[(&str, &[u8])] = &[
        ("index.html", &b"<!doctype html>\n"[..]),
        ("assets/app.js", &b"console.log(1);\n"[..]),
        ("assets/nested/deeper/chunk.js", &b"export const x = 2;\n"[..]),
        (".well-known/ii-alternative-origins", &b"{\"alternativeOrigins\":[]}"[..]),
        ("zk/spend.zkey", &[0x00u8, 0xFF, 0x10][..]),
        ("empty.txt", &b""[..]),
    ];
    for (rel, body) in content {
        let p = dist.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
    }

    let measured = vcm::measure_bundle_dir(&dist).expect("a clean tree must still measure");
    assert_eq!(
        measured.files,
        content.len() as i64,
        "every REAL nested directory is still descended — `symlink_metadata` classifies a real \
         directory as a directory, and a regression here would silently SHRINK a bundle digest"
    );
    assert_eq!(
        measured.bytes,
        content.iter().map(|(_, b)| b.len() as i64).sum::<i64>(),
        "bytes is still the sum of the regular file sizes"
    );

    // And still byte-for-byte the record's own procedure — the definition of the
    // digest, not merely a number this implementation agrees with itself about.
    let script = "find dist -type f | sed 's|^dist/||' | LC_ALL=C sort \
                  | while read -r f; do printf \"%s  %s\\n\" \
                      \"$(sha256sum \"dist/$f\" | cut -d' ' -f1)\" \"$f\"; done \
                  | sha256sum | cut -d' ' -f1";
    let out = Command::new("bash")
        .arg("-c")
        .arg(script)
        .current_dir(&root)
        .output()
        .unwrap_or_else(|e| panic!("[AC-7] cannot run the documented pipeline: {e}"));
    assert!(out.status.success(), "pipeline failed: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        measured.sha256,
        String::from_utf8_lossy(&out.stdout).trim(),
        "[AC-7] the tree-shape refusal must not have moved the digest construction for clean \
         trees — on a symlink-free tree the two paths still agree exactly, which is what makes \
         the two live pinned digests reproducible after this change"
    );
    let _ = std::fs::remove_dir_all(&root);
}
