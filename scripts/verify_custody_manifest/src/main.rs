// Custody manifest coverage gate + §8 size invariant — blocking gate checks.
//
//   verify_custody_manifest [--coverage-only|--sizes-only|--deploy-time|--deploy-posture|--wallet-bundles|--wallet-bundle-bytes] [<repo-root>]
//
// Default: run the §13.2a coverage gate against
//   <root>/deployment/mainnet/custody_manifest.toml  (manifest)
//   <root>/dfx.json                                   (D1)
//   <root>/canister_ids.json                          (D2)
// plus the §8 size invariant over built artifacts. run_gate.sh runs the two
// halves separately: coverage before the build (blocking lint), sizes after
// the Wasm builds (so every payload class is measured, not PENDING).
//
// `--deploy-time` (INT-02): runs the build-time coverage checks AND the
// deploy-time class — currently the independent vault deployment init
// artifact (deployment/mainnet/vault_init.did), which is BLOCKING
// pre-deployment and fails with PendingDeploymentArtifact until L4 produces
// the artifact. Deliberately NOT part of the build-time gate, so
// ./run_gate.sh stays green while the artifact is legitimately pending.
//
// `--deploy-posture` (R-3b S2): runs the SAME full set as `--deploy-time`, then
// compares the OBSERVED key set (Violation::key(), built from typed fields) to
// the DECLARED `[deploy_gate].expected_pending` set in the manifest, for EXACT
// set equality. This is the mode ./run_gate.sh runs: it makes every deploy-time
// check execute on every gate run while the legitimately-pending obligations
// are DECLARED rather than skipped. A surplus key, a shortfall, or a same-kind
// SWAP is a set difference and exits 1. Under `posture = "launch"` the observed
// set must be EMPTY.
//
// Exit 0 = clean. Exit 1 = violations (prints every one, typed). Exit 2 = usage/IO.

use std::path::PathBuf;
use std::process::ExitCode;
use verify_custody_manifest as vcm;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut sizes_only = false;
    let mut coverage_only = false;
    let mut deploy_time = false;
    let mut deploy_posture = false;
    let mut repin = false;
    let mut repin_write = false;
    let mut wallet_bundles = false;
    let mut wallet_bundle_bytes = false;
    let mut root = PathBuf::from(".");
    while let Some(a) = args.next() {
        match a.as_str() {
            "--sizes-only" => sizes_only = true,
            "--coverage-only" => coverage_only = true,
            "--deploy-time" => deploy_time = true,
            "--deploy-posture" => deploy_posture = true,
            "--repin" => repin = true,
            "--write" => repin_write = true,
            "--wallet-bundles" => wallet_bundles = true,
            "--wallet-bundle-bytes" => wallet_bundle_bytes = true,
            other => root = PathBuf::from(other),
        }
    }

    if repin_write && !repin {
        eprintln!(
            "verify_custody_manifest: --write is only meaningful with --repin (default --repin \
             mode is dry-run: it prints a diff and writes nothing)."
        );
        return ExitCode::from(2);
    }

    // ── The FOUR mode flags are MUTUALLY EXCLUSIVE ──────────────────────────
    //
    // Each selects a DIFFERENT SUBSET of the gate, so any combination silently
    // narrows what a zero exit code means. Rejecting only one pair was the
    // original defect: the hazard is the whole class, not one member of it.
    //
    //   --deploy-time --coverage-only : runs the release check while skipping
    //       the §8 artifact half, so a pinned hash could pass having been
    //       compared to nothing.
    //   --deploy-time --sizes-only    : `if !sizes_only` skips the entire
    //       coverage/deploy-time block, so check_deploy_time never runs at all
    //       and the process can exit 0 with NO roster, authority, receipt or
    //       release-identity validation — a deploy-time verdict from a run that
    //       performed no deploy-time check.
    //   --coverage-only --sizes-only  : both halves are skipped. A no-op that
    //       reports success.
    //   --deploy-posture <anything>   : R-3b. --deploy-posture asserts the
    //       DECLARED pending set against the FULL deploy-time set. Combined
    //       with any narrowing flag it would compare the declaration against a
    //       subset, so a declared-pending obligation whose check was skipped
    //       would read as satisfied. Same hazard class, same refusal.
    //
    // A gate that exits 0 having checked nothing is worse than one that fails:
    // it is indistinguishable from a real pass in a log.
    let modes: Vec<&str> = [
        (sizes_only, "--sizes-only"),
        (coverage_only, "--coverage-only"),
        (deploy_time, "--deploy-time"),
        (deploy_posture, "--deploy-posture"),
        (repin, "--repin"),
        (wallet_bundles, "--wallet-bundles"),
        (wallet_bundle_bytes, "--wallet-bundle-bytes"),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, name)| *name)
    .collect();
    if modes.len() > 1 {
        eprintln!(
            "verify_custody_manifest: mode flags are mutually exclusive, got {}.\n\
             Each flag selects a different SUBSET of the gate, so any combination narrows what \
             exit 0 means — up to a run that checks nothing and still reports success. Pass \
             exactly one of --coverage-only, --sizes-only, --deploy-time, --deploy-posture, \
             --repin, --wallet-bundles, --wallet-bundle-bytes, or none for the full build-time \
             gate.",
            modes.join(" ")
        );
        return ExitCode::from(2);
    }

    // ── B-6 / O-10: --wallet-bundles ─────────────────────────────────────────
    //
    // The wallet bundle pins, checked. Its OWN mode rather than a new stage of
    // the build-time or deploy-time gate: `--deploy-posture` compares the
    // observed violation-key set to the DECLARED `[deploy_gate].expected_pending`
    // set for EXACT set equality, so folding a new kind in would turn the gate
    // red unless `deployment/mainnet/custody_manifest.toml` declared it — and
    // the lane that added this check reads the record, it does not write it.
    // Exit 1 on violations, exit 0 clean: the same contract every other mode has.
    if wallet_bundles {
        let v = vcm::check_wallet_bundles(&root);
        for viol in &v {
            println!("{viol}");
        }
        if v.is_empty() {
            println!(
                "verify_custody_manifest --wallet-bundles: OK — both [wallet_bundle] and \
                 [wallet_bundle_transitional] are structurally complete, mutually consistent, \
                 and provenance-authenticated."
            );
            return ExitCode::SUCCESS;
        }
        eprintln!(
            "verify_custody_manifest --wallet-bundles: {} violation(s) — the wallet bundle is \
             the artifact users actually load, and these pins are what a verifier reproduces.",
            v.len()
        );
        return ExitCode::from(1);
    }

    // ── M-02 (B-ii): --wallet-bundle-bytes ───────────────────────────────────
    //
    // The BYTE measurement of the released wallet bundle — the half that cannot
    // live on the build-time path, because `wallet/dist` is gitignored and the
    // gate builds it AFTER the custody posture stage. Its own mode, run by
    // run_gate.sh after the wallet build.
    //
    // It is never a bare skip and never a bare fail. The
    // `[wallet_bundle_release]` marker says whether a bundle is being released at
    // this head; the record-coverage half checks that the marker EXISTS and is
    // recognised, so "held" is a declared state rather than an absence. Under
    // "releasing" the marker's `variant` says WHICH of the two bundles is on
    // disk — both tables record `path = "wallet/dist"`, so without it the
    // measurement would compare whatever was built against the FINAL pin
    // (HARDEN-03, D-1) — the pinned toolchain tuple is asserted before anything
    // is measured and a mismatch is a violation, and an absent or non-matching
    // `dist` fails closed. The report line below names the variant and the table
    // it selected, so a reader never has to infer which pin was compared.
    if wallet_bundle_bytes {
        let (v, report) = vcm::check_wallet_bundle_bytes(&root);
        println!("verify_custody_manifest --wallet-bundle-bytes:");
        for line in report.lines() {
            println!("  {line}");
        }
        for viol in &v {
            println!("{viol}");
        }
        if v.is_empty() {
            println!(
                "  VERDICT:  OK — the wallet-bundle byte measurement is satisfied at this head \
                 (see the state line above for whether it was OWED and measured, or DECLARED \
                 not owed; those are different outcomes and both are printed, never inferred)."
            );
            return ExitCode::SUCCESS;
        }
        eprintln!(
            "verify_custody_manifest --wallet-bundle-bytes: {} violation(s) — the bundle is the \
             artifact a user's browser executes, and this is the only check that compares its \
             recorded digest against measured bytes.",
            v.len()
        );
        return ExitCode::from(1);
    }

    // ── R-3a: --repin ────────────────────────────────────────────────────────
    if repin {
        return run_repin(&root, repin_write);
    }

    // ── R-3b S2: --deploy-posture ────────────────────────────────────────────
    if deploy_posture {
        return run_deploy_posture(&root);
    }

    let mut failures = 0usize;

    if !sizes_only {
        let manifest_path = root.join("deployment/mainnet/custody_manifest.toml");
        let manifest = match vcm::load_manifest(&manifest_path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("verify_custody_manifest: {e}");
                return ExitCode::from(2);
            }
        };
        let d1 = match vcm::load_d1(&root.join("dfx.json")) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("verify_custody_manifest: {e}");
                return ExitCode::from(2);
            }
        };
        let d2 = match vcm::load_d2(&root.join("canister_ids.json")) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("verify_custody_manifest: {e}");
                return ExitCode::from(2);
            }
        };

        let violations = vcm::check_coverage(&manifest, &d1, &d2);
        // DID fixture drift lock (blocking): pinned fixtures must equal the
        // committed target DIDs (git show HEAD).
        let drift = vcm::check_did_fixtures(&root);
        // Cutover binding (blocking): Vault REQUIRED_CUTOVER ↔ manifest rows
        // ↔ encoded vault init payload.
        let cutover = vcm::check_cutover_binding(&root, &manifest);
        // §P.1 partition (blocking): 2 bootstrap-ring + 9 governed targets,
        // ring evidence pinned as a separately hashed ceremony input, and the
        // D5 receipt contract stated over the governed half only.
        let partition = vcm::check_partition(&root, &manifest);
        let mut violations = [violations, drift, cutover, partition].concat();
        if deploy_time {
            violations.extend(vcm::check_deploy_time(&root, &manifest));
            // M-02 (B-i): kept in step with run_deploy_posture, whose comment says
            // it runs "exactly the set --deploy-time reports". If the bundle record
            // check were added to only one of the two, that statement would quietly
            // stop being true and the posture comparison would be against a set
            // --deploy-time never produces.
            violations.extend(vcm::check_wallet_bundles(&root));
            // ROT-LEDGER: same reason, same pairing. The identity-rotation
            // ledger is a deploy-time obligation and must be in BOTH sets or
            // the posture comparison would be against a set --deploy-time
            // never produces.
            violations.extend(vcm::check_rotation_ledger(&root));
        }
        if violations.is_empty() {
            println!(
                "verify_custody_manifest: OK — every candidate in D1∪D2∪D3∪D4∪D5 ({} dfx entries, \
                 {} id records, {} D3, {} D4, {} D5 receipts) has exactly one disposition; \
                 no fact conflicts; no stale evidence; {} axis-2 authority fields ruled.",
                d1.len(),
                d2.len(),
                manifest.sources.d3.candidates.len(),
                manifest.sources.d4.candidates.len(),
                manifest.sources.d5.receipts.len(),
                manifest.authority_fields.len(),
            );
        } else {
            eprintln!(
                "verify_custody_manifest: {} COVERAGE VIOLATION(S)\n",
                violations.len()
            );
            for v in &violations {
                eprintln!("  • {v}\n");
            }
            failures += violations.len();
        }
    }

    // ── §8 encoded-message size invariant ────────────────────────────────────
    if !coverage_only {
        let (measured, artifact_violations) = vcm::measure_payloads(&root);
        for v in &artifact_violations {
            eprintln!("  • {v}\n");
        }
        failures += artifact_violations.len();
        let size_violations = vcm::check_sizes(&measured);
        for m in &measured {
            println!(
                "verify_custody_manifest: measured {:>9} bytes  {}  (bound {})",
                m.encoded_bytes,
                m.label,
                vcm::GATE_SIZE_BOUND_BYTES
            );
        }
        if !size_violations.is_empty() {
            eprintln!();
            for v in &size_violations {
                eprintln!("  • {v}\n");
            }
            failures += size_violations.len();
        }
    }

    if failures > 0 {
        eprintln!(
            "verify_custody_manifest: {failures} violation(s). The coverage contract is freeze \
             §13.2a; the size invariant is freeze §8. Neither is routed around."
        );
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}


/// R-3b S2: assert the DECLARED deploy posture against the OBSERVED one.
///
/// Runs the full `--deploy-time` violation set, projects it through
/// `Violation::key()` — which reads TYPED fields, never `detail` — and compares
/// the result to `[deploy_gate].expected_pending` for EXACT set equality. Not
/// "at most", not "contains", not kind-plus-count: a surplus key, a shortfall,
/// or a same-kind SWAP (the same kind and the same count, a different
/// obligation) is a set difference and fails.
///
/// The verdict is LOUD on pass (AC-10): silence would make "declared and
/// observed agree" indistinguishable in a log from "this stage did not run".
fn run_deploy_posture(root: &PathBuf) -> ExitCode {
    let manifest_path = root.join("deployment/mainnet/custody_manifest.toml");
    // load_manifest validates [deploy_gate] and returns Err — exit 2 — for an
    // unknown posture, a `launch` posture carrying an allowlist, a duplicate
    // key, or a key whose kind is not declarable. That happens BEFORE any check
    // runs, which is the point: a malformed declaration is a usage error, never
    // a violation to be weighed against observations.
    let manifest = match vcm::load_manifest(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("verify_custody_manifest: {e}");
            return ExitCode::from(2);
        }
    };
    let d1 = match vcm::load_d1(&root.join("dfx.json")) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("verify_custody_manifest: {e}");
            return ExitCode::from(2);
        }
    };
    let d2 = match vcm::load_d2(&root.join("canister_ids.json")) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("verify_custody_manifest: {e}");
            return ExitCode::from(2);
        }
    };

    // Exactly the set `--deploy-time` reports.
    let mut violations = vcm::check_coverage(&manifest, &d1, &d2);
    violations.extend(vcm::check_did_fixtures(root));
    violations.extend(vcm::check_cutover_binding(root, &manifest));
    violations.extend(vcm::check_partition(root, &manifest));
    violations.extend(vcm::check_deploy_time(root, &manifest));
    // M-02 (B-i): RECORD coverage for the two `[wallet_bundle*]` tables, MANDATORY
    // and unconditional. It reads no bytes of `wallet/dist`, so absorbing it here
    // asks nothing new of a routine gate run — no build, no host toolchain, no
    // gitignored artifact. Before this it was an opt-in mode the gate never
    // invoked, which is why two live defects in the record sat green across
    // several lanes.
    //
    // `WalletBundleUnbound` is NOT in DECLARABLE_KINDS, so from this point every
    // live bundle-record violation is a hard gate failure that cannot be declared
    // pending. That is exactly why the record fixes and this wiring are ONE lane:
    // split apart, the wiring half would leave master un-gateable.
    violations.extend(vcm::check_wallet_bundles(root));
    // ROT-LEDGER: the identity-rotation ledger, on the deploy-time path the
    // gate actually invokes (`run_gate.sh` runs --deploy-posture; it never runs
    // --wallet-bundles). The well-formed pre-rotation state surfaces here as a
    // DECLARABLE PendingDeploymentArtifact key; every corrupt-ledger condition
    // surfaces as RotationLedgerInconsistent, which is NOT in DECLARABLE_KINDS
    // and is therefore refused at load if anyone ever declares it — so it can
    // only appear as a SURPLUS difference, and a surplus turns the gate RED.
    violations.extend(vcm::check_rotation_ledger(root));

    let observed = vcm::observed_keys(&violations);
    let declared = vcm::declared_pending(&manifest.deploy_gate);
    let posture = manifest.deploy_gate.posture.as_str();

    let surplus: Vec<&String> = observed.difference(&declared).collect();
    let shortfall: Vec<&String> = declared.difference(&observed).collect();

    println!("verify_custody_manifest --deploy-posture:");
    println!("  posture:  {posture}");
    println!("  declared: {declared:?}");
    println!("  observed: {observed:?}");

    // BOTH directions, always, including on the pass. A loud pass that printed
    // only the two sets would leave a reader to diff them by eye; the two
    // differences the verdict actually turns on are printed in the tool's own
    // words, so "surplus = [], shortfall = []" is evidence rather than an
    // inference from the verdict line.
    println!("  surplus (observed, NOT declared):   {surplus:?}");
    println!("  shortfall (declared, NOT observed): {shortfall:?}");

    if surplus.is_empty() && shortfall.is_empty() {
        if posture == "launch" {
            println!(
                "  VERDICT:  OK — launch posture, ZERO deploy-time violations observed. Every \
                 deploy-time check ran and every one passed."
            );
        } else {
            println!(
                "  VERDICT:  OK — pre-ceremony posture, observed set equals the declared set \
                 exactly ({} obligation(s) legitimately pending). Every deploy-time check ran.",
                declared.len()
            );
        }
        return ExitCode::SUCCESS;
    }

    eprintln!();
    eprintln!("verify_custody_manifest: DEPLOY POSTURE MISMATCH (posture `{posture}`).");
    if !surplus.is_empty() {
        eprintln!(
            "  SURPLUS (observed, NOT declared) — these are REGRESSIONS, not pending work:"
        );
        for k in &surplus {
            eprintln!("    + {k}");
        }
    }
    if !shortfall.is_empty() {
        eprintln!(
            "  SHORTFALL (declared, NOT observed) — the declaration is stale; an obligation it \
             names is no longer reported:"
        );
        for k in &shortfall {
            eprintln!("    - {k}");
        }
    }
    eprintln!();
    for v in &violations {
        eprintln!("  • {v}\n");
    }
    eprintln!(
        "Reconcile deployment/mainnet/custody_manifest.toml's [deploy_gate].expected_pending \
         against the observed set above. Flipping posture to \"launch\" is a reviewed ONE-LINE \
         change, after which expected_pending must be [] and the observed set must be empty."
    );
    ExitCode::from(1)
}

// ─────────────────────────────────────────────────────────────────────────────
// R-3a — `--repin`: rewrite the `[wasm.*]` rows of the release record from the
// artifacts actually on disk.
//
// WHAT THIS IS NOT. It is not an authorisation to re-pin. Producing pins that
// mean anything requires the gate's own sanitised environment, a CLEAN build,
// the exact `[build] command` package set, and the final reviewed head — none
// of which this tool can verify about its own caller. An argv/env "I was run
// from the gate" marker was considered and DROPPED: a marker a child process
// does not inherit is trivially forged and buys nothing. The obligation is
// therefore printed on EVERY invocation, honoured by process discipline
// (ARCHITECTURE.md law 7) plus SSA's independent reproduction, and never claimed as
// a mechanism.
//
// WHAT IT DOES ENFORCE, because these are locally decidable:
//   1. the tree must be CLEAN — re-pinning from a dirty tree records bytes
//      built from source no reviewer has seen;
//   2. every `INLINE_PAYLOAD_ARTIFACTS` entry must be present on disk — a
//      missing artifact must be a refusal, never a silently omitted row.
//
// REPIN-FIX (2026-09-18, over the SETTLEMENT 723-line-delete escalation). The
// previous implementation anchored on `text.find("[wasm.<pkg>]")` — a raw
// substring search with no awareness of TOML structure at all. That matched
// the header text anywhere it occurred, including inside PROSE inside a
// comment ("...reproduced [wasm.vault] and [wasm.upgrader] EXACTLY as
// recorded here..." — a sentence that exists verbatim in the real release
// record). It then hunted for the next "\n[" to find the table's end, which
// stops at ANY line starting with `[` — including one inside a historical
// comment block — so a false anchor plus a false end-of-table together
// deleted hundreds of lines of protected commentary and spliced a hash row
// into the middle of prose. The rewrite below:
//   - never treats a line as a table header (or a table boundary) unless its
//     TRIMMED content is a real header, i.e. starts with `[` and is NOT
//     itself a comment line (comment lines are identified by trimmed content
//     starting with `#`, which is the only comment form TOML has — no block
//     comments exist to worry about);
//   - matches the target header only against a trimmed line that is EXACTLY
//     `[wasm.<pkg>]` or `[wasm."<pkg>"]` — never a substring;
//   - touches ONLY the `sha256`, `bytes`, and `path` value lines it finds
//     inside that table's exact line range, preserving indentation and any
//     trailing same-line comment verbatim; every other byte in the file,
//     comments included, is untouched;
//   - refuses (exit 1, writes nothing) on any structural mismatch: a target
//     table missing or duplicated, or a `sha256`/`bytes`/`path` key missing
//     zero times where one is required or duplicated where one is expected,
//     or a file that does not parse as TOML at all;
//   - defaults to DRY RUN: it prints a unified-style diff to stdout and
//     writes nothing unless `--write` is also given;
//   - reports each row under the label actually matched in the file (the
//     previous version could print a hash under a stale/wrong pkg label —
//     the SETTLEMENT-lane mislabelling bug).
fn run_repin(root: &std::path::Path, write: bool) -> ExitCode {
    println!(
        "verify_custody_manifest --repin: run this only as a step of `./run_gate.sh`'s \
         sanitised environment; SSA independently reproduces all ten hashes before \
         countersign (dispatch ruling condition 3)."
    );

    // ── Guard 1: the tree must be clean.
    let status = std::process::Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["status", "--porcelain"])
        .output();
    let status = match status {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        Ok(o) => {
            eprintln!(
                "verify_custody_manifest --repin: REFUSED — `git status` failed in {}: {}",
                root.display(),
                String::from_utf8_lossy(&o.stderr)
            );
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("verify_custody_manifest --repin: REFUSED — cannot run git: {e}");
            return ExitCode::from(2);
        }
    };
    if !status.trim().is_empty() {
        eprintln!(
            "verify_custody_manifest --repin: REFUSED — the working tree is DIRTY.\n\
             Pins recorded from a dirty tree describe bytes built from source no reviewer has \
             seen, and the record would assert an identity for a commit that does not exist. \
             Commit or stash first. Offending paths:\n{}",
            status.trim()
        );
        return ExitCode::from(1);
    }

    // ── Guard 2: every shipped artifact must be present.
    let wasm_dir = root.join("target/wasm32-unknown-unknown/release");
    let missing: Vec<&str> = vcm::INLINE_PAYLOAD_ARTIFACTS
        .iter()
        .filter(|(_, f)| !wasm_dir.join(f).is_file())
        .map(|(_, f)| *f)
        .collect();
    if !missing.is_empty() {
        eprintln!(
            "verify_custody_manifest --repin: REFUSED — MISSING ARTIFACT: {} not built under \
             {}.\nAbsence is never a skip: a row omitted because its Wasm was missing would \
             leave that artifact unpinned, which is the exact hole R-3a closes. Run the gate's \
             phase-2 production build first.",
            missing.join(", "),
            wasm_dir.display()
        );
        return ExitCode::from(1);
    }

    // ── Read + validate structure.
    let record_path = root.join(vcm::RELEASE_RECORD_ARTIFACT);
    let text = match std::fs::read_to_string(&record_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "verify_custody_manifest --repin: REFUSED — cannot read {}: {e}",
                record_path.display()
            );
            return ExitCode::from(2);
        }
    };

    // The file must parse as TOML at all before we touch it line-by-line —
    // catches truncation/syntax damage a purely line-oriented pass would
    // happily "fix" a hole into.
    if let Err(e) = text.parse::<toml::Value>() {
        eprintln!(
            "verify_custody_manifest --repin: REFUSED — {} does not parse as TOML: {e}\n\
             Structural mismatches are refusals, never partial rewrites.",
            record_path.display()
        );
        return ExitCode::from(1);
    }

    match repin_rewrite(&text, root, wasm_dir.as_path()) {
        Err(errs) => {
            eprintln!(
                "verify_custody_manifest --repin: REFUSED — structural mismatch(es) in {}:",
                record_path.display()
            );
            for e in &errs {
                eprintln!("  - {e}");
            }
            eprintln!("Nothing was written.");
            ExitCode::from(1)
        }
        Ok(outcome) => {
            print!("{}", render_diff(&text, &outcome.new_text, &record_path));
            if outcome.new_text == text {
                println!("verify_custody_manifest --repin: no change — every pinned hash already matches disk.");
            } else if write {
                if let Err(e) = std::fs::write(&record_path, &outcome.new_text) {
                    eprintln!(
                        "verify_custody_manifest --repin: cannot write {}: {e}",
                        record_path.display()
                    );
                    return ExitCode::from(2);
                }
                println!("verify_custody_manifest --repin: WROTE {}", record_path.display());
            } else {
                println!(
                    "verify_custody_manifest --repin: DRY RUN — no file written. Re-run with \
                     --write to apply the diff above."
                );
            }
            for row in &outcome.rows {
                println!(
                    "  {:<22} [{}] sha256 old: {}  ->  new: {}",
                    row.pkg, row.header, row.old_sha, row.new_sha
                );
            }
            println!(
                "  {} row(s) checked; `asserts_identity_at`, `source_sha`, `[build] command` \
                 and every other field are UNTOUCHED — re-arming is a separate binding act.",
                outcome.rows.len()
            );
            ExitCode::SUCCESS
        }
    }
}

struct RepinRow {
    pkg: &'static str,
    header: String,
    old_sha: String,
    new_sha: String,
}

struct RepinOutcome {
    new_text: String,
    rows: Vec<RepinRow>,
}

/// True iff `trimmed` (already whitespace-trimmed) is a TOML comment line —
/// the only comment form TOML has, so this is a complete, exact test.
fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with('#')
}

/// True iff `trimmed` is a genuine TOML table-header line: `[...]`, not a
/// comment, not an array-of-tables `[[...]]`.
fn is_table_header_line(trimmed: &str) -> bool {
    !is_comment_line(trimmed)
        && trimmed.starts_with('[')
        && !trimmed.starts_with("[[")
        && trimmed.ends_with(']')
}

/// Replaces exactly the quoted string value on a `key = "value"` line,
/// preserving everything else on the line (leading indentation/spacing
/// before `=`, and any trailing same-line comment) byte-for-byte.
fn replace_quoted_value(line: &str, new_value: &str) -> Option<String> {
    let eq = line.find('=')?;
    let after_eq = &line[eq + 1..];
    let first_quote = after_eq.find('"')?;
    let rest = &after_eq[first_quote + 1..];
    let second_quote = rest.find('"')?;
    let prefix = &line[..eq + 1 + first_quote + 1];
    let suffix = &rest[second_quote..]; // includes the closing quote onward
    Some(format!("{prefix}{new_value}{suffix}"))
}

/// Replaces the bare numeric value on a `key = 123` line (optionally followed
/// by a trailing comment), preserving the rest of the line byte-for-byte.
fn replace_numeric_value(line: &str, new_value: u64) -> Option<String> {
    let eq = line.find('=')?;
    let prefix = &line[..eq + 1];
    let after_eq = &line[eq + 1..];
    // Value runs to the first char that can't be part of a bare integer;
    // whatever remains (whitespace + optional `#comment`) is preserved.
    let value_end = after_eq
        .find(|c: char| !(c.is_ascii_digit() || c.is_whitespace()))
        .unwrap_or(after_eq.len());
    let sep_len = after_eq[..value_end].len() - after_eq[..value_end].trim_start().len();
    let sep = &after_eq[..sep_len];
    let suffix = &after_eq[value_end..];
    Some(format!("{prefix}{sep}{new_value}{suffix}"))
}

/// Finds the single non-comment line in `lines[range]` whose trimmed content
/// starts with `key` followed by an `=`. Returns `Ok(None)` if absent,
/// `Ok(Some(idx))` if exactly one, `Err(())` if more than one (duplicate key).
fn find_unique_key_line(lines: &[&str], range: std::ops::Range<usize>, key: &str) -> Result<Option<usize>, ()> {
    let mut found = None;
    for i in range {
        let trimmed = lines[i].trim();
        if is_comment_line(trimmed) {
            continue;
        }
        let Some(k) = trimmed.split('=').next() else { continue };
        if k.trim() == key {
            if found.is_some() {
                return Err(());
            }
            found = Some(i);
        }
    }
    Ok(found)
}

fn repin_rewrite(
    text: &str,
    root: &std::path::Path,
    wasm_dir: &std::path::Path,
) -> Result<RepinOutcome, Vec<String>> {
    // split_inclusive keeps line terminators attached so re-joining is exact.
    let raw_lines: Vec<&str> = text.split_inclusive('\n').collect();
    // Trimmed-of-terminator view used for matching; index-aligned with raw_lines.
    let lines: Vec<&str> = raw_lines.iter().map(|l| l.trim_end_matches('\n').trim_end_matches('\r')).collect();

    let mut new_lines: Vec<String> = raw_lines.iter().map(|l| l.to_string()).collect();
    let mut rows = Vec::new();
    let mut errors = Vec::new();

    for (pkg, file) in vcm::INLINE_PAYLOAD_ARTIFACTS {
        let bare = format!("[wasm.{pkg}]");
        let quoted = format!("[wasm.\"{pkg}\"]");

        let matches: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| {
                let t = l.trim();
                !is_comment_line(t) && (t == bare || t == quoted)
            })
            .map(|(i, _)| i)
            .collect();

        let header_idx = match matches.as_slice() {
            [] => {
                errors.push(format!(
                    "`{pkg}`: no `[wasm.{pkg}]` table found — a missing table is refused, \
                     never silently appended"
                ));
                continue;
            }
            [only] => *only,
            many => {
                errors.push(format!(
                    "`{pkg}`: `[wasm.{pkg}]` table appears {} times (lines {})",
                    many.len(),
                    many.iter().map(|i| (i + 1).to_string()).collect::<Vec<_>>().join(", ")
                ));
                continue;
            }
        };

        // Table body runs until the next real table header (any table),
        // never stopping on a `[` that appears inside a comment line.
        let table_end = ((header_idx + 1)..lines.len())
            .find(|&i| is_table_header_line(lines[i].trim()))
            .unwrap_or(lines.len());
        let body = (header_idx + 1)..table_end;

        let sha_idx = match find_unique_key_line(&lines, body.clone(), "sha256") {
            Ok(Some(i)) => i,
            Ok(None) => {
                errors.push(format!("`{pkg}`: `[wasm.{pkg}]` has no `sha256` key"));
                continue;
            }
            Err(()) => {
                errors.push(format!("`{pkg}`: `[wasm.{pkg}]` has a duplicate `sha256` key"));
                continue;
            }
        };
        let bytes_idx = match find_unique_key_line(&lines, body.clone(), "bytes") {
            Ok(v) => v,
            Err(()) => {
                errors.push(format!("`{pkg}`: `[wasm.{pkg}]` has a duplicate `bytes` key"));
                continue;
            }
        };
        let path_idx = match find_unique_key_line(&lines, body.clone(), "path") {
            Ok(v) => v,
            Err(()) => {
                errors.push(format!("`{pkg}`: `[wasm.{pkg}]` has a duplicate `path` key"));
                continue;
            }
        };

        let old_sha = lines[sha_idx]
            .split_once("\"")
            .and_then(|(_, r)| r.split_once('"'))
            .map(|(h, _)| h.to_string())
            .unwrap_or_default();

        let wasm_path = wasm_dir.join(file);
        let bytes = match std::fs::read(&wasm_path) {
            Ok(b) => b,
            Err(e) => {
                errors.push(format!("`{pkg}`: cannot read {}: {e}", wasm_path.display()));
                continue;
            }
        };
        let new_sha = vcm::sha256_hex(&bytes);

        let old_terminator = if raw_lines[sha_idx].ends_with("\r\n") {
            "\r\n"
        } else if raw_lines[sha_idx].ends_with('\n') {
            "\n"
        } else {
            ""
        };
        let Some(new_sha_line) = replace_quoted_value(lines[sha_idx], &new_sha) else {
            errors.push(format!("`{pkg}`: could not parse the `sha256` line to rewrite it"));
            continue;
        };
        new_lines[sha_idx] = format!("{new_sha_line}{old_terminator}");

        if let Some(bi) = bytes_idx {
            let term = if raw_lines[bi].ends_with("\r\n") { "\r\n" } else if raw_lines[bi].ends_with('\n') { "\n" } else { "" };
            if let Some(new_line) = replace_numeric_value(lines[bi], bytes.len() as u64) {
                new_lines[bi] = format!("{new_line}{term}");
            }
        }
        if let Some(pi) = path_idx {
            let term = if raw_lines[pi].ends_with("\r\n") { "\r\n" } else if raw_lines[pi].ends_with('\n') { "\n" } else { "" };
            let rel = format!("target/wasm32-unknown-unknown/release/{file}");
            if let Some(new_line) = replace_quoted_value(lines[pi], &rel) {
                new_lines[pi] = format!("{new_line}{term}");
            }
        }

        rows.push(RepinRow {
            pkg,
            header: lines[header_idx].trim().to_string(),
            old_sha,
            new_sha,
        });
    }

    let _ = root; // reserved for future path-relative diagnostics
    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(RepinOutcome { new_text: new_lines.concat(), rows })
}

/// A small, dependency-free unified-style diff: since the only lines that can
/// ever change are the specific value lines `repin_rewrite` computed, this
/// walks both texts and prints a hunk (with 2 lines of context) around each
/// run of changed lines, rather than pulling in a diff crate.
fn render_diff(old: &str, new: &str, path: &std::path::Path) -> String {
    if old == new {
        return String::new();
    }
    let old_lines: Vec<&str> = old.split_inclusive('\n').collect();
    let new_lines: Vec<&str> = new.split_inclusive('\n').collect();
    let mut out = format!("--- a/{}\n+++ b/{}\n", path.display(), path.display());
    let n = old_lines.len().min(new_lines.len());
    let mut i = 0;
    while i < n {
        if old_lines[i] == new_lines[i] {
            i += 1;
            continue;
        }
        let start = i.saturating_sub(2);
        let mut j = i;
        while j < n && old_lines[j] != new_lines[j] {
            j += 1;
        }
        let end = (j + 2).min(n);
        out.push_str(&format!("@@ line {} @@\n", start + 1));
        for k in start..i {
            out.push_str(&format!(" {}", old_lines[k]));
        }
        for k in i..j {
            out.push_str(&format!("-{}", old_lines[k]));
            out.push_str(&format!("+{}", new_lines[k]));
        }
        for k in j..end {
            out.push_str(&format!(" {}", old_lines[k]));
        }
        i = end.max(j);
    }
    out
}
