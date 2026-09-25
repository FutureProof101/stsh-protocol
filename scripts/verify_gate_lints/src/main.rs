use std::path::Path;
use std::process::exit;

use verify_gate_lints::data::{
    BindingRegistry, BoundTestSuites, CeilingRegistry, ClaimsBaseline, ClaimsPatterns, Corpus,
    NoSkipsPatterns,
};
use verify_gate_lints::target_cfg::TargetAtoms;
use verify_gate_lints::*;

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("verify_gate_lints: {msg}");
    exit(EXIT_REFUSE);
}

fn data_dir(root: &Path) -> std::path::PathBuf {
    root.join("scripts").join("gate_lints")
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!(
            "usage: verify_gate_lints <claims|refused-ceilings|bindings|no-skips|scope|census|pool-accounting-census> \
             [<workspace-root>] [options]"
        );
        exit(EXIT_REFUSE);
    }
    let sub = args[0].clone();
    let positional: Vec<&String> = args[1..].iter().filter(|a| !a.starts_with("--")).collect();
    let root = workspace_root(positional.first().map(|s| s.as_str()));
    let root = root.canonicalize().unwrap_or(root);

    match sub.as_str() {
        "claims" => run_claims(&root),
        "refused-ceilings" => run_ceilings(&root),
        "bindings" => run_bindings(&root),
        "no-skips" => run_no_skips(&root),
        "census" => run_census(&root),
        "pool-accounting-census" => run_pool_accounting_census(&root),
        "scope" => run_scope(&root, &args),
        other => die(format!("unknown subcommand `{other}`")),
    }
}

fn report(stage: &str, violations: &[String], extra: &[String]) -> ! {
    for line in extra {
        println!("{line}");
    }
    if violations.is_empty() {
        println!("{stage}: OK — 0 findings");
        exit(EXIT_OK);
    }
    eprintln!("\n{stage}: {} finding(s):", violations.len());
    for v in violations {
        eprintln!("  {v}");
    }
    exit(EXIT_FINDINGS);
}

fn run_claims(root: &Path) -> ! {
    let d = data_dir(root);
    let corpus: Corpus = data::load(&d.join("CORPUS.toml")).unwrap_or_else(|e| die(e));
    let pats: ClaimsPatterns = data::load(&d.join("claims_patterns.toml")).unwrap_or_else(|e| die(e));
    let baseline: ClaimsBaseline =
        data::load(&d.join("claims_baseline.toml")).unwrap_or_else(|e| die(e));
    let outcome = claims::run(root, &corpus, &pats, &baseline);
    let marked = outcome.hits.iter().filter(|h| h.marker.is_some()).count();
    let extra = vec![format!(
        "claims: {} normative cost/rate hit(s) over the governed corpus; {} carry an in-source \
         marker, {} are annotated in claims_baseline.toml, {} are neither.\n\
         claims: the automated guarantee is MARKER + REFERENT EXISTENCE only — it is not a proof \
         that any measurement is true or measures the attached claim (brief §2 AMBER-1).",
        outcome.hits.len(),
        marked,
        outcome.baseline_discharged,
        outcome.hits.len() - marked - outcome.baseline_discharged
    )];
    report("claims", &outcome.violations, &extra);
}

fn target_or_die(root: &Path) -> TargetAtoms {
    TargetAtoms::capture(root).unwrap_or_else(|e| die(e))
}

/// The atom set for the environment `cargo test` actually compiles in — the
/// HOST, because neither committed gate invocation passes `--target`
/// (SSA landed-diff round 3, RED-7). Used ONLY by `bindings`; every
/// production-view census keeps [`target_cfg::PRODUCTION_TARGET`].
fn host_target_or_die(root: &Path) -> TargetAtoms {
    TargetAtoms::capture_host(root).unwrap_or_else(|e| die(e))
}

fn run_ceilings(root: &Path) -> ! {
    let d = data_dir(root);
    let reg: CeilingRegistry =
        data::load(&d.join("refused_call_ceilings.toml")).unwrap_or_else(|e| die(e));
    let target = target_or_die(root);
    let outcome = ceilings::run(root, &reg, &target).unwrap_or_else(|e| die(e));
    let mut extra = vec![format!(
        "refused-ceilings: production-view #[update] census (testing / production), \
         cfg evaluated under rustc's atoms for {}:",
        target_cfg::PRODUCTION_TARGET
    )];
    let (mut t, mut p) = (0, 0);
    for (name, testing, production) in &outcome.per_crate {
        if *testing == 0 && *production == 0 {
            continue;
        }
        t += testing;
        p += production;
        extra.push(format!("  {name:<22} {testing:>4} / {production:>4}"));
    }
    extra.push(format!("  {:<22} {t:>4} / {p:>4}", "TOTAL"));
    extra.push(format!(
        "refused-ceilings: {} obligated production endpoint(s); {} ceiling row(s), {} explicit UNGUARDED row(s).",
        outcome.obligated.len(),
        reg.row.len(),
        reg.unguarded.len()
    ));
    report("refused-ceilings", &outcome.violations, &extra);
}

fn run_bindings(root: &Path) -> ! {
    let d = data_dir(root);
    let reg_path = root.join("tests").join("BINDING_REGISTRY.toml");
    let raw = std::fs::read_to_string(&reg_path)
        .unwrap_or_else(|e| die(format!("{}: {e}", reg_path.display())));
    let reg: BindingRegistry = toml::from_str(&raw)
        .unwrap_or_else(|e| die(format!("{}: {e}", reg_path.display())));
    let suites: BoundTestSuites =
        data::load(&d.join("BOUND_TEST_SUITES.toml")).unwrap_or_else(|e| die(e));
    let gate = std::fs::read_to_string(root.join("run_gate.sh"))
        .unwrap_or_else(|e| die(format!("run_gate.sh: {e}")));
    // The TEST view: host atoms, because `cargo test` has no `--target`.
    let target = host_target_or_die(root);
    let outcome = bindings::run(root, &reg, &raw, &suites, &gate, &target);
    // A row whose effective cfg could not be EVALUATED is a refusal (exit 2),
    // never a silent pass — the same rule the cfg evaluator applies everywhere.
    if !outcome.refusals.is_empty() {
        die(format!(
            "bindings: {} row(s) could not be evaluated:\n  {}",
            outcome.refusals.len(),
            outcome.refusals.join("\n  ")
        ));
    }
    let extra = vec![format!(
        "bindings: posture = \"{}\"; {} registered binding row(s) checked, each evaluated \
         effectively-compiled in the gate's test view (`test = true`, HOST target atoms \
         `{}` — `cargo test` passes no `--target` — cfg over the crate's resolved default \
         closure plus the features its gate invocation passes).",
        reg.posture,
        outcome.checked,
        target
            .map
            .get("target_arch")
            .and_then(|v| v.iter().next().cloned())
            .unwrap_or_default()
    )];
    report("bindings", &outcome.violations, &extra);
}

fn run_no_skips(root: &Path) -> ! {
    let d = data_dir(root);
    let pats: NoSkipsPatterns =
        data::load(&d.join("no_skips_patterns.toml")).unwrap_or_else(|e| die(e));
    let baseline: verify_gate_lints::data::NoSkipsBaseline =
        data::load(&d.join("no_skips_baseline.toml")).unwrap_or_else(|e| die(e));
    let index = no_skips::FnIndex::build(root);
    let mut files = 0usize;
    // Findings grouped by (file, owner_fn, shape) so a key's site COUNT can be
    // compared with the count its baseline row records — see
    // `no_skips::apply_baseline` (SSA landed-diff round 1, RED-2).
    let mut found: std::collections::BTreeMap<(String, String, u8), Vec<String>> =
        Default::default();
    for r in no_skips::scan_roots(root) {
        for f in census::rust_files(&r) {
            let Ok(text) = std::fs::read_to_string(&f) else { continue };
            let rel = f.strip_prefix(root).unwrap_or(&f).display().to_string();
            files += 1;
            match no_skips::scan_file(&rel, &text, &pats, &index) {
                Ok(findings) => {
                    for x in findings {
                        found
                            .entry((x.file.clone(), x.owner_fn.clone(), x.shape))
                            .or_default()
                            .push(x.to_string());
                    }
                }
                Err(e) => die(e),
            }
        }
    }
    let (violations, suppressed) = no_skips::apply_baseline(&found, &baseline);
    let extra = vec![format!(
        "no-skips: {suppressed} pre-existing site(s) annotated in no_skips_baseline.toml \
         (each with a reason and an owning lane); they are NOT fixed, only recorded.\n\
         no-skips: {files} file(s) scanned over #[test] fns and fixture loaders, seven structural \
         shapes plus the bare-`#[ignore]` rule.\n\
         no-skips: KNOWN GAP (disclosed, not closed) — a skip dispatched through a `dyn Trait` \
         custom check is outside the seven shapes and is not detected."
    )];
    report("no-skips", &violations, &extra);
}

fn run_census(root: &Path) -> ! {
    // Not a gate stage — a reporting helper used to regenerate the packet's
    // per-crate table with the SAME walk the ceiling stage uses.
    let target = target_or_die(root);
    println!("# rustc --print cfg --target {}", target_cfg::PRODUCTION_TARGET);
    for line in target.raw.lines() {
        println!("#   {line}");
    }
    println!("crate,testing_view,production_view");
    let (mut t, mut p) = (0usize, 0usize);
    for (name, dir) in census::canister_crates(root) {
        match census::census_crate(&name, &dir, root, &target) {
            Ok(c) => {
                t += c.testing.len();
                p += c.production.len();
                println!("{name},{},{}", c.testing.len(), c.production.len());
            }
            Err(e) => die(e),
        }
    }
    println!("TOTAL,{t},{p}");
    println!();
    println!("did,update_methods,query_methods");
    for (name, dir) in census::canister_crates(root) {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut dids: Vec<_> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "did").unwrap_or(false))
            .collect();
        dids.sort();
        for d in dids {
            let Ok(text) = std::fs::read_to_string(&d) else { continue };
            let all = did::service_methods(&text);
            let up = all.iter().filter(|m| !m.is_query).count();
            println!(
                "{},{},{}",
                d.file_name().unwrap().to_string_lossy(),
                up,
                all.len() - up
            );
        }
        let _ = &name;
    }
    exit(EXIT_OK);
}

/// FU1-2 pool accounting-statics reference-count census (lane R-11).
///
/// Not a `run_gate.sh` stage: the gate-visible surface is the crate's own
/// `#[test] fu1_2_known_bypass_census`, which `cargo test --workspace` runs.
/// This subcommand exists so the same walk can be re-derived by hand for a
/// packet without re-running the whole test binary.
fn run_pool_accounting_census(root: &Path) -> ! {
    let target = target_or_die(root);
    let observed =
        pool_accounting_census::observe(root, &target).unwrap_or_else(|e| die(e));
    println!("fn,static,reads,writes");
    for o in &observed {
        println!("{},{},{},{}", o.func, o.stat, o.reads, o.writes);
    }
    let violations = pool_accounting_census::run(root, &target).unwrap_or_else(|e| die(e));
    let extra = vec![format!(
        "pool-accounting-census: {} observed (fn, static) cell(s) over the six accounting \
         statics; {} expectation row(s); writer set {:?}; {} retired bypass fn(s) baselined \
         at zero references.",
        observed.len(),
        pool_accounting_census::EXPECTED.len(),
        pool_accounting_census::EXPECTED_WRITER_SET,
        pool_accounting_census::RETIRED_BYPASSES.len()
    )];
    report("pool-accounting-census", &violations, &extra);
}

fn run_scope(root: &Path, args: &[String]) -> ! {
    let mut base = None;
    let mut files: Vec<String> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                base = args.get(i + 1).cloned();
                i += 2;
            }
            "--files" => {
                i += 1;
                while i < args.len() && !args[i].starts_with("--") {
                    files.push(args[i].clone());
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    let Some(base) = base else { die("scope requires --base <SHA>") };
    if files.is_empty() {
        die("scope requires --files <paths...>");
    }
    let rep = scope::run(root, &base, &files);
    for l in &rep.lines {
        println!("{l}");
    }
    exit(if rep.ok { EXIT_OK } else { EXIT_FINDINGS });
}
