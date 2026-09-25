// =============================================================================
// STSH — MemoryId registry lint  (BRIEF_UPGRADE_PERSISTENCE_HARDENING_V2 #4)
// =============================================================================
//
// Machine enforcement of the append-only MemoryId rule (CTO ruling 2026-07-27).
// The Markdown registry stays the human record; THIS is what enforces it.
//
// Why it has to be a build gate and not a review habit: recycling a MemoryId
// does not fail loudly. `ic-stable-structures` simply hands the new structure
// the old region's bytes, so a decommissioned checkpoint gets reinterpreted as
// live state of a different type. There is no runtime error to catch — the
// corruption is silent and durable. The only reliable defence is refusing to
// build.
//
// SOURCE OF TRUTH = the code, for what is ACTUALLY allocated.
// DECLARED EXPECTATION = `docs/MEMORY_ID_REGISTRY.md`, the canonical IN-REPO
// registry (CTO Phase 0 Ruling 1: git is truth, the lint checks the tree; the
// office copy is a mirror reconciled FROM this file, not its source).
// Disagreement is always an error: either the code drifted or the registry did.
//
// The registry is parsed directly — it is a build input, not documentation, so
// there is no second machine-readable artifact that could drift from the human
// one. Rows are positional: Canister | MemoryId | Structure | Status | Notes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct Config {
    pub canisters: Vec<CanisterConfig>,
}

#[derive(Debug, Default)]
pub struct CanisterConfig {
    pub name: String,
    pub active: Vec<u8>,
    pub retired: Vec<u8>,
}

/// Parse the canonical in-repo registry.
///
/// Reads the allocation table (Canister | MemoryId | Structure | Status | Notes)
/// and cross-checks the "Frozen retire list" table against it. A malformed row
/// is a hard error, not a skip: silently ignoring a row the author believed was
/// enforced is the one failure mode a registry lint must never have.
pub fn parse_registry(md: &str) -> Result<Config, String> {
    #[derive(PartialEq)]
    enum Section {
        None,
        Alloc,
        Frozen,
    }

    let mut by_canister: BTreeMap<String, CanisterConfig> = BTreeMap::new();
    let mut frozen: BTreeSet<(String, u8)> = BTreeSet::new();
    let mut section = Section::None;
    let mut seen_alloc_rows = 0usize;

    for (i, line) in md.lines().enumerate() {
        let t = line.trim();
        if t.starts_with("## ") {
            let h = t.to_lowercase();
            section = if h.contains("allocation table") {
                Section::Alloc
            } else if h.contains("frozen retire list") {
                Section::Frozen
            } else {
                Section::None
            };
            continue;
        }
        if !t.starts_with('|') || section == Section::None {
            continue;
        }
        let cols: Vec<&str> = t.trim_matches('|').split('|').map(|c| c.trim()).collect();
        // Header and separator rows.
        if cols.first().map(|c| c.eq_ignore_ascii_case("canister")).unwrap_or(false) {
            continue;
        }
        if cols.iter().all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':')) {
            continue;
        }

        // SSA P2: inside a table, EVERY non-header row parses completely or
        // errors. Silently `continue`-ing a short or mistyped row would drop a
        // real allocation out of enforcement while the file still looks correct
        // to a human reader — the same vacuous-pass class as P1.
        match section {
            Section::Alloc => {
                if cols.len() < 4 {
                    return Err(format!(
                        "line {}: allocation row has {} column(s), expected at least 4 \
                         (Canister | MemoryId | Structure | Status | Notes): `{t}`",
                        i + 1,
                        cols.len()
                    ));
                }
                let name = cols[0].to_string();
                let id: u8 = cols[1].parse().map_err(|_| {
                    format!(
                        "line {}: {name} MemoryId `{}` is not a number — a mistyped ID would \
                         silently drop this allocation from enforcement.",
                        i + 1,
                        cols[1]
                    )
                })?;
                let entry = by_canister.entry(name.clone()).or_insert_with(|| CanisterConfig {
                    name: name.clone(),
                    ..Default::default()
                });
                match cols[3].to_ascii_lowercase().as_str() {
                    "active" => entry.active.push(id),
                    "retired" => entry.retired.push(id),
                    other => {
                        return Err(format!(
                            "line {}: {name} MemoryId {id} has Status `{other}` — must be \
                             exactly `active` or `retired`. An unrecognised status would \
                             silently drop the row from enforcement.",
                            i + 1
                        ))
                    }
                }
                seen_alloc_rows += 1;
            }
            Section::Frozen => {
                if cols.len() < 2 {
                    return Err(format!(
                        "line {}: frozen-retire-list row has {} column(s), expected at least 2 \
                         (Canister | Frozen ID | Retired by): `{t}`",
                        i + 1,
                        cols.len()
                    ));
                }
                let id: u8 = cols[1].parse().map_err(|_| {
                    format!(
                        "line {}: frozen-list MemoryId `{}` is not a number",
                        i + 1,
                        cols[1]
                    )
                })?;
                frozen.insert((cols[0].to_string(), id));
            }
            Section::None => unreachable!("filtered above"),
        }
    }

    if seen_alloc_rows == 0 {
        return Err("no allocation rows parsed — the registry table is missing or its \
                    column layout changed. Refusing to pass vacuously."
            .to_string());
    }

    // Cross-check: the frozen retire list must exactly match the retired rows.
    let retired_rows: BTreeSet<(String, u8)> = by_canister
        .values()
        .flat_map(|c| c.retired.iter().map(|id| (c.name.clone(), *id)))
        .collect();
    for entry in frozen.difference(&retired_rows) {
        return Err(format!(
            "{} {} is in the frozen retire list but is not marked `retired` in the \
             allocation table — the two halves of the registry disagree.",
            entry.0, entry.1
        ));
    }
    for entry in retired_rows.difference(&frozen) {
        return Err(format!(
            "{} {} is marked `retired` in the allocation table but is missing from the \
             frozen retire list — a retirement that is not frozen can be recycled.",
            entry.0, entry.1
        ));
    }

    Ok(Config {
        canisters: by_canister.into_values().collect(),
    })
}

/// One `MemoryId::new(N)` found in source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub id: u8,
    pub file: String,
    pub line: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// THE ONE LEGAL FORM (policy, CTO-visible; SSA + Architect endorsed)
//
//   Every stable-memory allocation MUST be written exactly as
//       MemoryId::new(<unsuffixed decimal u8 literal>)
//   Every other construction is a BLOCKING error.
//
// Why so strict: a lint that cannot name the ID cannot inventory it, and an
// un-inventoried allocation passes vacuously on BOTH sides (absent from code
// scan, absent from registry) — which is the exact corruption this gate exists
// to prevent. One legal spelling makes "did we see every allocation?" decidable.
//
// Why an AST and not a smarter regex: two lexical holes were found in a row —
// first literal-only argument matching (missed `MemoryId::new(MEM_ID)`, which
// was LIVE in canisters/vetkeys), then substring matching on `MemoryId::new(`
// (misses `MemoryId :: new(7)`, `MemoryId::new (7)`, and the multiline form).
// Text-matching cannot close the class; token spacing is infinitely variable.
// `syn` parses to an AST where formatting, comments and string literals are
// structurally irrelevant, so those holes cannot exist.
// ─────────────────────────────────────────────────────────────────────────────

use proc_macro2::Span;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::Visit;

/// A construction the lint refuses to accept. Always blocking — never a skip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub file: String,
    pub line: usize,
    /// What was found, and the fix.
    pub detail: String,
}

/// Everything one source tree yielded.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub allocations: Vec<Allocation>,
    pub rejected: Vec<Rejected>,
    /// `const`/`static` items whose type is (or contains) `MemoryId`.
    /// LEGAL in a canister crate — that is how every canister declares its IDs.
    /// BLOCKING in a shared crate: a shared `const MemoryId` is a usable ID with
    /// no `MemoryId::new` at the point of use, which is the cross-crate escape.
    pub bindings: Vec<Rejected>,
}

impl ScanResult {
    pub fn is_empty(&self) -> bool {
        self.allocations.is_empty() && self.rejected.is_empty() && self.bindings.is_empty()
    }
}

const CANONICAL_FQ: &str = "ic_stable_structures :: memory_manager :: MemoryId :: new";

struct Scanner<'a> {
    path: &'a str,
    out: ScanResult,
}

impl<'a> Scanner<'a> {
    fn line(&self, span: Span) -> usize {
        span.start().line
    }

    fn reject(&mut self, span: Span, detail: String) {
        self.out.rejected.push(Rejected {
            file: self.path.to_string(),
            line: self.line(span),
            detail,
        });
    }

    /// Does this type mention `MemoryId` anywhere (incl. `Option<MemoryId>`)?
    fn mentions_memory_id(ty: &syn::Type) -> bool {
        ty.to_token_stream()
            .to_string()
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|t| t == "MemoryId")
    }
}

impl<'ast, 'a> Visit<'ast> for Scanner<'a> {
    /// Aliasing the type defeats path recognition: `use ...MemoryId as Mid;`
    /// then `Mid::new(7)` reads as an unrelated call. Ban the alias, not the
    /// (unbounded) set of names it could take.
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        fn walk(tree: &syn::UseTree, found: &mut Vec<(String, Span)>) {
            match tree {
                syn::UseTree::Path(p) => walk(&p.tree, found),
                syn::UseTree::Group(g) => g.items.iter().for_each(|t| walk(t, found)),
                syn::UseTree::Rename(r) if r.ident == "MemoryId" => {
                    found.push((r.rename.to_string(), r.rename.span()))
                }
                _ => {}
            }
        }
        let mut found = Vec::new();
        walk(&node.tree, &mut found);
        for (alias, span) in found {
            self.reject(
                span,
                format!(
                    "`MemoryId` is aliased as `{alias}`. Aliasing hides allocations from the \
                     registry lint. Import it under its own name and write \
                     `MemoryId::new(<literal>)`."
                ),
            );
        }
        syn::visit::visit_item_use(self, node);
    }

    /// `type Mid = MemoryId;` is the same evasion by another route.
    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if Scanner::mentions_memory_id(&node.ty) {
            let span = node.ident.span();
            let name = node.ident.to_string();
            self.reject(
                span,
                format!(
                    "type alias `{name}` resolves to `MemoryId`. Aliasing hides allocations \
                     from the registry lint — use `MemoryId` directly."
                ),
            );
        }
        syn::visit::visit_item_type(self, node);
    }

    /// A function that RETURNS a `MemoryId` is a construction wrapper: the real
    /// allocation happens inside it, invisibly, and callers pass a bare integer.
    /// This is exactly how `canisters/vetkeys` hid three allocations.
    ///
    /// Functions that ACCEPT a `MemoryId` are deliberately NOT rejected — see
    /// the note in the crate docs. They cannot hide anything: the caller still
    /// has to construct the value in canonical form, in plain sight.
    fn visit_signature(&mut self, node: &'ast syn::Signature) {
        if let syn::ReturnType::Type(_, ty) = &node.output {
            if Scanner::mentions_memory_id(ty) {
                let span = node.ident.span();
                let name = node.ident.to_string();
                self.reject(
                    span,
                    format!(
                        "fn `{name}` returns a `MemoryId`. A constructor wrapper hides the \
                         allocation from the registry lint — construct it at the call site as \
                         `MemoryId::new(<literal>)` instead."
                    ),
                );
            }
        }
        syn::visit::visit_signature(self, node);
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        if Scanner::mentions_memory_id(&node.ty) {
            let name = node.ident.to_string();
            self.out.bindings.push(Rejected {
                file: self.path.to_string(),
                line: self.line(node.ident.span()),
                detail: format!("`const {name}: MemoryId`"),
            });
        }
        syn::visit::visit_item_const(self, node);
    }

    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        if Scanner::mentions_memory_id(&node.ty) {
            let name = node.ident.to_string();
            self.out.bindings.push(Rejected {
                file: self.path.to_string(),
                line: self.line(node.ident.span()),
                detail: format!("`static {name}: MemoryId`"),
            });
        }
        syn::visit::visit_item_static(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*node.func {
            let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
            let n = segs.len();
            let is_memory_id_new = n >= 2 && segs[n - 2] == "MemoryId" && segs[n - 1] == "new";

            if is_memory_id_new {
                // Canonical paths only: bare, or the fully-qualified one.
                let joined = p.path.to_token_stream().to_string();
                let bare = n == 2;
                let fq = joined == CANONICAL_FQ;
                if !bare && !fq {
                    self.reject(
                        p.span(),
                        format!(
                            "`{joined}` is a non-canonical path to `MemoryId::new`. Use bare \
                             `MemoryId::new(<literal>)` or the fully-qualified \
                             `ic_stable_structures::memory_manager::MemoryId::new(<literal>)`."
                        ),
                    );
                } else if node.args.len() != 1 {
                    self.reject(
                        node.span(),
                        format!(
                            "`MemoryId::new` called with {} arguments; expected exactly one \
                             unsuffixed decimal literal.",
                            node.args.len()
                        ),
                    );
                } else {
                    match &node.args[0] {
                        syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Int(int),
                            ..
                        }) if int.suffix().is_empty() => match int.base10_parse::<u8>() {
                            Ok(id) => self.out.allocations.push(Allocation {
                                id,
                                file: self.path.to_string(),
                                line: self.line(node.span()),
                            }),
                            Err(_) => self.reject(
                                node.span(),
                                format!(
                                    "`MemoryId::new({})` is not a valid u8.",
                                    int.base10_digits()
                                ),
                            ),
                        },
                        syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Int(int),
                            ..
                        }) => self.reject(
                            node.span(),
                            format!(
                                "`MemoryId::new({}{})` carries a type suffix. Write it \
                                 unsuffixed: `MemoryId::new({})`.",
                                int.base10_digits(),
                                int.suffix(),
                                int.base10_digits()
                            ),
                        ),
                        other => self.reject(
                            node.span(),
                            format!(
                                "`MemoryId::new({})` does not take a decimal literal, so the \
                                 lint cannot determine which ID it allocates. Write it as \
                                 `MemoryId::new(<literal>)` and register it in \
                                 docs/MEMORY_ID_REGISTRY.md.",
                                other.to_token_stream()
                            ),
                        ),
                    }
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

/// Extract every allocation from one source file, rejecting every
/// non-canonical construction.
///
/// Comments, string literals and raw strings are structurally absent from the
/// AST, so they can neither hide an allocation nor fake one — including the
/// retirement tombstones this campaign leaves behind, and this lint's own
/// diagnostics, which quote the very call they scan for.
pub fn scan_source(path: &str, src: &str) -> ScanResult {
    let file = match syn::parse_file(src) {
        Ok(f) => f,
        Err(e) => {
            // Unparseable source is BLOCKING, never a skip: a file the lint
            // cannot read is a file whose allocations it cannot inventory.
            return ScanResult {
                allocations: vec![],
                bindings: vec![],
                rejected: vec![Rejected {
                    file: path.to_string(),
                    line: e.span().start().line,
                    detail: format!(
                        "could not be parsed as Rust ({e}) — the lint cannot inventory \
                         allocations in a file it cannot parse."
                    ),
                }],
            };
        }
    };
    let mut scanner = Scanner {
        path,
        out: ScanResult::default(),
    };
    scanner.visit_file(&file);
    scanner.out
}

// ─────────────────────────────────────────────────────────────────────────────
// SCAN SET — derived from the workspace, never a hardcoded glob
//
// SSA HOLD #3: the visitor is per-source-file, so a MemoryId constructed in a
// first-party crate OUTSIDE the scanned set escapes entirely:
//
//     helper crate (unscanned):  pub const ID7: MemoryId = MemoryId::new(7);
//     canister:                  mem(ID7);   // no MemoryId::new in scanned source
//
// Two changes close it. (1) The scan set is derived from the workspace manifest
// — members, their first-party path-dependencies (transitively), and the
// workspace-EXCLUDED vetkeys crate — so a newly added first-party crate is
// scanned automatically instead of being silently omitted. (2) MemoryId
// construction is confined to canister crates (see `check`), so there is no
// off-canister construction site left to hide in.
//
// Third-party sources are NEVER scanned: `ic_stable_structures` itself calls
// `MemoryId::new` legitimately, and flagging its internals would be noise that
// trains people to ignore the lint.
//
// ACCEPTED RESIDUAL (out of scope by design, CTO-signed 2026-07-28):
// deliberate `unsafe` fabrication of a MemoryId — e.g. `transmute` from a u8 —
// is outside a syntax-based lint's threat model. No guard is built for it. Its
// cover is the canister crates' no-unsafe posture plus code review. See the
// Phase 1 report for the per-crate `#![forbid(unsafe_code)]` audit that
// determines whether that cover is enforcement or convention.
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// SCAN SET — complete BY CONSTRUCTION (SSA HOLD #4)
//
// The previous derivation walked the workspace graph: `workspace.members`, a
// hardcoded `vetkeys` exception, and ordinary `[dependencies]` path deps. That
// is ENUMERATIVE, and it leaked every round — it missed `workspace.exclude`
// entries, target-specific dep tables (`target.'cfg(...)'.dependencies`),
// build-dependencies, and standalone crates. `circuits/rust-spike` was already
// omitted, which disproved the claim that every first-party crate was derived.
// A future excluded canister (as vetkeys is) or a cfg-gated path helper could
// construct and export a MemoryId and never enter the set — and confinement
// only protects crates that are actually scanned.
//
// So discovery no longer asks the workspace graph what exists. It walks the
// repo and finds EVERY `Cargo.toml`. Completeness stops depending on
// inclusion rules that can be forgotten.
//
// FAIL-CLOSED ON THE UNKNOWN: a manifest under the repo root that is not on the
// explicit exclude list below is FIRST-PARTY and IS scanned. An unclassified
// crate gets scanned, never silently skipped. Excluding something is an
// explicit, documented decision — never a default, and never an omission.
//
// ACCEPTED RESIDUAL (out of scope by design, CTO-signed 2026-07-28):
// deliberate `unsafe` fabrication of a MemoryId — e.g. `transmute` from a u8 —
// is outside a syntax-based lint's threat model. No guard is built for it. Its
// cover is the canister crates' no-unsafe posture plus code review. See the
// Phase 1 report for the per-crate `#![forbid(unsafe_code)]` audit that
// determines whether that cover is enforcement or convention.
// ─────────────────────────────────────────────────────────────────────────────

/// Directory names never scanned, wherever they appear.
///
/// `target` is build output and contains vendored third-party sources —
/// `ic_stable_structures` legitimately calls `MemoryId::new` internally, and
/// flagging its internals would be noise that trains people to ignore the lint.
/// `.git` and `node_modules` hold no first-party Rust.
pub const EXCLUDED_DIR_NAMES: &[&str] = &["target", ".git", "node_modules"];

/// Repo-relative path prefixes never scanned. Every entry is a deliberate,
/// documented decision — this list is the ONLY way something first-party-looking
/// escapes the scan.
///
/// `.worktrees` holds agent-created git worktrees: FULL COPIES of this
/// repository at other commits. Scanning them would double-count every crate
/// and surface findings from stale code as if they were live — e.g. the
/// pre-hardening `mem(id: u8)` vetkeys helper still exists in one of them.
pub const EXCLUDED_PATH_PREFIXES: &[&str] = &[".worktrees"];

/// A first-party crate in the scan set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateInfo {
    pub name: String,
    pub dir: PathBuf,
    /// Canister crates MAY construct MemoryIds (as registered literals).
    /// Shared/helper crates may not — see `check`.
    pub is_canister: bool,
}

/// Everything one crate yielded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateScan {
    pub info: CrateInfo,
    pub result: ScanResult,
}

#[derive(serde::Deserialize)]
struct Manifest {
    #[serde(default)]
    package: Option<ManifestPackage>,
    #[serde(default)]
    lib: Option<ManifestLib>,
    #[serde(default)]
    dependencies: BTreeMap<String, toml::Value>,
}

#[derive(serde::Deserialize, Default)]
struct ManifestPackage {
    #[serde(default)]
    name: String,
}

#[derive(serde::Deserialize, Default)]
struct ManifestLib {
    #[serde(default, rename = "crate-type")]
    crate_type: Vec<String>,
}

/// A canister crate compiles to a Wasm canister: a `cdylib` that depends on
/// `ic-cdk`. Derived from the manifest, not from a path convention, so it stays
/// correct if the layout moves — and so `circuits/poseidon-wasm` (a `cdylib`
/// with no `ic-cdk`) is correctly treated as a shared crate.
fn is_canister_crate(m: &Manifest) -> bool {
    let cdylib = m
        .lib
        .as_ref()
        .map(|l| l.crate_type.iter().any(|t| t == "cdylib"))
        .unwrap_or(false);
    m.dependencies.keys().any(|k| k == "ic-cdk") && cdylib
}

fn is_excluded(root: &Path, path: &Path) -> bool {
    if path
        .file_name()
        .map(|f| EXCLUDED_DIR_NAMES.iter().any(|e| f == *e))
        .unwrap_or(false)
    {
        return true;
    }
    let rel = path.strip_prefix(root).unwrap_or(path);
    let rel_s = rel.to_string_lossy().replace('\\', "/");
    EXCLUDED_PATH_PREFIXES
        .iter()
        .any(|p| rel_s == *p || rel_s.starts_with(&format!("{p}/")))
}

/// Discover every first-party crate by walking the repo for `Cargo.toml`.
///
/// Errors are PROPAGATED, never defaulted: a malformed manifest, an unreadable
/// directory, an ambiguous crate name, or a degenerate (empty) result is a hard
/// error. An empty scan set that reads as "nothing to check" is the vacuous
/// pass this whole lint exists to prevent.
pub fn discover_crates(root: &Path) -> Result<Vec<CrateInfo>, String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        let entries = std::fs::read_dir(dir)
            .map_err(|e| format!("cannot read directory {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("cannot read entry in {}: {e}", dir.display()))?;
            let path = entry.path();
            let ty = entry
                .file_type()
                .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
            if ty.is_dir() {
                if is_excluded(root, &path) {
                    continue;
                }
                walk(root, &path, out)?;
            } else if path.file_name().map(|f| f == "Cargo.toml").unwrap_or(false) {
                out.push(path);
            }
        }
        Ok(())
    }

    let mut manifests = Vec::new();
    walk(root, root, &mut manifests)?;

    let mut out: Vec<CrateInfo> = Vec::new();
    for manifest_path in manifests {
        let raw = std::fs::read_to_string(&manifest_path)
            .map_err(|e| format!("cannot read {}: {e}", manifest_path.display()))?;
        // A malformed manifest is a HARD ERROR: silently skipping it would drop
        // an entire crate out of the scan without anyone noticing.
        let m: Manifest = toml::from_str(&raw)
            .map_err(|e| format!("malformed manifest {}: {e}", manifest_path.display()))?;
        // Virtual manifests (a workspace root with no [package]) declare no
        // crate of their own and have no src/ — nothing to scan.
        let Some(pkg) = m.package.as_ref() else { continue };
        let dir = manifest_path
            .parent()
            .ok_or_else(|| format!("{} has no parent", manifest_path.display()))?
            .to_path_buf();
        let name = dir
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| pkg.name.clone());
        if let Some(prev) = out.iter().find(|c| c.name == name) {
            return Err(format!(
                "two first-party crates share the directory name `{name}` ({} and {}). The \
                 registry keys on this name, so the allocations could not be attributed \
                 unambiguously.",
                prev.dir.display(),
                dir.display()
            ));
        }
        out.push(CrateInfo {
            name,
            is_canister: is_canister_crate(&m),
            dir,
        });
    }

    if out.is_empty() {
        return Err(format!(
            "no first-party crates discovered under {} — refusing to report a vacuous pass \
             on an empty scan set.",
            root.display()
        ));
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Scan every discovered first-party crate. Keyed by crate directory name,
/// which is what `docs/MEMORY_ID_REGISTRY.md` uses.
///
/// This is the production path `main` calls; every error above surfaces through
/// it rather than degrading to an empty result.
pub fn scan_tree(root: &Path) -> Result<BTreeMap<String, CrateScan>, String> {
    let set = discover_crates(root)?;
    let mut found: BTreeMap<String, CrateScan> = BTreeMap::new();
    for info in set {
        let mut result = ScanResult::default();
        if info.dir.is_dir() {
            collect_rs(root, &info.dir, &mut result)
                .map_err(|e| format!("scanning {}: {e}", info.dir.display()))?;
        }
        found.insert(info.name.clone(), CrateScan { info, result });
    }
    Ok(found)
}

fn collect_rs(root: &Path, dir: &Path, out: &mut ScanResult) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if is_excluded(root, &path) {
                continue;
            }
            collect_rs(root, &path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let src = std::fs::read_to_string(&path)?;
            let r = scan_source(&path.to_string_lossy(), &src);
            out.allocations.extend(r.allocations);
            out.rejected.extend(r.rejected);
            out.bindings.extend(r.bindings);
        }
    }
    Ok(())
}

/// Compare code against config. Returns every violation found — the lint
/// reports ALL of them rather than dying on the first, so one run tells the
/// whole story.
pub fn check(
    config: &Config,
    code: &BTreeMap<String, CrateScan>,
) -> Vec<String> {
    let mut errors = Vec::new();

    // A non-canonical construction blocks before anything else. If the lint
    // cannot name the ID, no downstream verdict about that ID means anything —
    // silence here would be the vacuous pass.
    for (name, scan) in code {
        for r in &scan.result.rejected {
            errors.push(format!("{name}: {}:{} — {}", r.file, r.line, r.detail));
        }
    }

    // ── Confinement (SSA HOLD #3) ────────────────────────────────────────────
    //
    // MemoryIds may only be constructed inside a canister crate, as registered
    // literals. A shared crate holding `pub const ID7: MemoryId = ...` (or
    // constructing one at all) hands canisters a usable ID with no
    // `MemoryId::new` at the point of use — the allocation is real but appears
    // in no canister's inventory. Removing the construction site removes the
    // hiding place; there is nothing to exempt.
    for (name, scan) in code {
        if scan.info.is_canister {
            continue;
        }
        for a in &scan.result.allocations {
            errors.push(format!(
                "{name} is a SHARED crate and must not construct MemoryIds — \
                 `MemoryId::new({})` at {}:{}. Construct them only inside a canister crate, \
                 as a literal registered in docs/MEMORY_ID_REGISTRY.md.",
                a.id, a.file, a.line
            ));
        }
        for b in &scan.result.bindings {
            errors.push(format!(
                "{name} is a SHARED crate and must not hold MemoryId-typed items — {} at \
                 {}:{}. A shared MemoryId constant is usable from a canister with no \
                 `MemoryId::new` at the point of use, so the allocation appears in no \
                 inventory.",
                b.detail, b.file, b.line
            ));
        }
    }
    let configured: BTreeMap<&str, &CanisterConfig> =
        config.canisters.iter().map(|c| (c.name.as_str(), c)).collect();

    for (canister, scan) in code {
        // Only canister crates participate in registry reconciliation. Shared
        // crates are covered by the confinement rule above and own no IDs.
        if !scan.info.is_canister {
            continue;
        }
        let allocs = &scan.result.allocations;
        // Canisters that allocate nothing and are not configured are simply not
        // participants (stub canisters, library crates). Skip silently.
        let Some(cfg) = configured.get(canister.as_str()) else {
            if !allocs.is_empty() {
                errors.push(format!(
                    "{canister}: allocates {} MemoryId(s) but has NO entry in \
                     docs/MEMORY_ID_REGISTRY.md. Add one (and the office registry) in this \
                     same change.",
                    allocs.len()
                ));
            }
            continue;
        };

        let active: BTreeSet<u8> = cfg.active.iter().copied().collect();
        let retired: BTreeSet<u8> = cfg.retired.iter().copied().collect();

        // 5. config self-consistency, checked first — an ID that is both active
        //    and retired makes every downstream verdict meaningless.
        for id in active.intersection(&retired) {
            errors.push(format!(
                "{canister}: MemoryId {id} is listed as BOTH active and retired in \
                 docs/MEMORY_ID_REGISTRY.md. Retirement is permanent; it cannot be active."
            ));
        }

        // 1. duplicate within a canister
        let mut seen: BTreeMap<u8, &Allocation> = BTreeMap::new();
        for a in allocs {
            if let Some(prev) = seen.get(&a.id) {
                errors.push(format!(
                    "{canister}: MemoryId {} allocated TWICE — {}:{} and {}:{}. Two \
                     structures sharing a region will corrupt each other.",
                    a.id, prev.file, prev.line, a.file, a.line
                ));
            } else {
                seen.insert(a.id, a);
            }
        }

        for (id, a) in &seen {
            // 2. reuse of a retired ID — the silent-corruption case
            if retired.contains(id) {
                errors.push(format!(
                    "{canister}: MemoryId {id} is RETIRED but is allocated at {}:{}. \
                     Retired IDs are frozen forever: reusing one hands the new structure \
                     the decommissioned region's bytes. Take the next free ID instead.",
                    a.file, a.line
                ));
            }
            // 3. allocated in code, absent from config
            if !active.contains(id) && !retired.contains(id) {
                errors.push(format!(
                    "{canister}: MemoryId {id} is allocated at {}:{} but is MISSING from \
                     docs/MEMORY_ID_REGISTRY.md. Every allocation must be declared in the same \
                     change that introduces it.",
                    a.file, a.line
                ));
            }
        }

        // 4. declared active, no code
        for id in &active {
            if !seen.contains_key(id) {
                errors.push(format!(
                    "{canister}: docs/MEMORY_ID_REGISTRY.md declares MemoryId {id} active, but \
                     no allocation exists in code. If it was retired, move it to `retired`; \
                     if it was never used, remove it."
                ));
            }
        }
    }

    // A configured canister that vanished from the tree entirely.
    for cfg in &config.canisters {
        if !code.contains_key(&cfg.name) {
            errors.push(format!(
                "{}: declared in docs/MEMORY_ID_REGISTRY.md but no canisters/{}/src exists.",
                cfg.name, cfg.name
            ));
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str, active: Vec<u8>, retired: Vec<u8>) -> Config {
        Config {
            canisters: vec![CanisterConfig {
                name: name.into(),
                active,
                retired,
            }],
        }
    }

    fn crate_scan(name: &str, is_canister: bool, r: ScanResult) -> BTreeMap<String, CrateScan> {
        let mut m = BTreeMap::new();
        m.insert(
            name.to_string(),
            CrateScan {
                info: CrateInfo {
                    name: name.to_string(),
                    dir: PathBuf::from(name),
                    is_canister,
                },
                result: r,
            },
        );
        m
    }

    fn code(name: &str, ids: &[u8]) -> BTreeMap<String, CrateScan> {
        crate_scan(
            name,
            true,
            ScanResult {
                allocations: ids
                    .iter()
                    .enumerate()
                    .map(|(i, id)| Allocation {
                        id: *id,
                        file: "x.rs".into(),
                        line: i + 1,
                    })
                    .collect(),
                rejected: vec![],
                bindings: vec![],
            },
        )
    }

    /// Assert a source fragment BLOCKS, and that the message names the fix.
    ///
    /// Deliberately does NOT require zero allocations: a construction wrapper
    /// legitimately trips both signals — its signature is rejected AND the
    /// canonical call in its body is a real allocation. Suppressing the second
    /// would hide a live ID.
    fn blocks(src: &str, expect: &str) {
        let r = scan_source("x.rs", src);
        assert_eq!(r.rejected.len(), 1, "must reject exactly once: {r:?}");
        assert!(
            r.rejected[0].detail.contains(expect),
            "message must name the problem (`{expect}`); got: {}",
            r.rejected[0].detail
        );
        // ...and it must actually reach the operator as a violation.
        assert!(
            !check(&cfg("c", vec![], vec![]), &crate_scan("c", true, r)).is_empty(),
            "must block the gate"
        );
    }

    /// Assert a source fragment RESOLVES to exactly these IDs, cleanly.
    fn resolves(src: &str, ids: &[u8]) {
        let r = scan_source("x.rs", src);
        assert!(r.rejected.is_empty(), "must not reject valid form: {r:?}");
        assert_eq!(
            r.allocations.iter().map(|a| a.id).collect::<Vec<_>>(),
            ids.to_vec(),
            "wrong IDs recovered"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // The class closure: formatting is structurally irrelevant to an AST.
    //
    // These are the forms the previous (substring-matching) scanner could not
    // see at all — they recorded NEITHER an allocation NOR a rejection, so a
    // missing registry row passed vacuously. They are now SEEN and inventoried.
    //
    // NOTE — deviation from the dispatch's "blocking examples" list, flagged
    // deliberately: `MemoryId :: new(7)` and `MemoryId::new (7)` are listed
    // there as forms that must FAIL. They parse to an AST identical to
    // `MemoryId::new(7)` — they ARE the canonical construction, merely spaced
    // differently (and rustfmt would normalise them). Rejecting them would
    // require re-introducing lexical inspection on top of the AST, which is the
    // fragility SSA told us to stop doing. The defect was INVISIBILITY, not
    // spelling; resolving them fixes it. Asserted here rather than assumed.
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn whitespace_token_variants_resolve_and_are_inventoried() {
        resolves("const A: MemoryId = MemoryId :: new(7);", &[7]);
        resolves("const A: MemoryId = MemoryId::new (7);", &[7]);
        resolves("const A: MemoryId = MemoryId  ::  new  ( 7 );", &[7]);
    }

    #[test]
    fn multiline_literal_resolves() {
        resolves("const A: MemoryId = MemoryId\n    ::new(\n        7\n    );", &[7]);
    }

    #[test]
    fn fully_qualified_canonical_path_resolves() {
        resolves(
            "const A: MemoryId = ic_stable_structures::memory_manager::MemoryId::new(7);",
            &[7],
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Blocking examples (dispatch §"Blocking examples")
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn symbolic_const_argument_blocks() {
        blocks(
            "const ID: u8 = 3;\nconst A: MemoryId = MemoryId::new(ID);",
            "does not take a decimal literal",
        );
    }

    #[test]
    fn expression_argument_blocks() {
        blocks(
            "const A: MemoryId = MemoryId::new(6 + 1);",
            "does not take a decimal literal",
        );
    }

    #[test]
    fn suffixed_literal_blocks() {
        blocks("const A: MemoryId = MemoryId::new(7u8);", "type suffix");
    }

    #[test]
    fn aliased_import_blocks() {
        blocks(
            "use ic_stable_structures::memory_manager::MemoryId as Mid;",
            "aliased as `Mid`",
        );
    }

    #[test]
    fn type_alias_blocks() {
        blocks("type Mid = MemoryId;", "resolves to `MemoryId`");
    }

    #[test]
    fn constructor_wrapper_fn_blocks() {
        let src = "fn make_memory_id(n: u8) -> MemoryId { MemoryId::new(0) }";
        blocks(src, "returns a `MemoryId`");
        // The canonical call inside the wrapper is still a REAL allocation and
        // must be inventoried — rejecting the wrapper must not make the ID it
        // constructs disappear.
        let r = scan_source("x.rs", src);
        assert_eq!(
            r.allocations.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![0],
            "the wrapper's own allocation must not vanish"
        );
    }

    #[test]
    fn non_canonical_path_blocks() {
        blocks(
            "const A: MemoryId = my_shim::MemoryId::new(7);",
            "non-canonical path",
        );
    }

    #[test]
    fn multiline_non_literal_blocks() {
        blocks(
            "const A: MemoryId = MemoryId::new(\n    ID\n);",
            "does not take a decimal literal",
        );
    }

    /// A helper that ACCEPTS a `MemoryId` is legal and must NOT be rejected —
    /// it cannot hide anything, because the caller still constructs the value
    /// in canonical form in plain sight. This is the shape `canisters/vetkeys`
    /// now uses; rejecting it would break the very fix that made those three
    /// allocations visible.
    #[test]
    fn helper_accepting_a_memory_id_is_allowed() {
        resolves(
            "fn mem(id: MemoryId) -> Memory { get(id) }\nfn f() { mem(MemoryId::new(0)); }",
            &[0],
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // No false positives — the hardening must not invent allocations either
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn comments_and_strings_are_not_allocations() {
        // Line comment — the retirement tombstone this campaign leaves behind.
        resolves("// const MEM_STABLE_STATE: MemoryId = MemoryId::new(1);\nfn f() {}", &[]);
        // Normal string — the lint's own diagnostics quote the call it scans for.
        resolves(r#"fn f() { panic!("use MemoryId::new(7) and register it"); }"#, &[]);
        // Raw string.
        resolves(r##"fn f() { let s = r#"MemoryId::new(9)"#; }"##, &[]);
        // Nested block comment.
        resolves("/* outer /* inner MemoryId::new(4) */ still comment */\nfn f() {}", &[]);
        // Doc comment.
        resolves("/// See MemoryId::new(5)\nfn f() {}", &[]);
    }

    #[test]
    fn tombstone_plus_live_allocation_records_only_the_live_one() {
        resolves(
            "const A: MemoryId = MemoryId::new(0);\n\
             // const OLD: MemoryId = MemoryId::new(1);   // RETIRED\n\
             const B: MemoryId = MemoryId::new(2);",
            &[0, 2],
        );
    }

    #[test]
    fn unparseable_source_blocks_rather_than_being_skipped() {
        let r = scan_source("x.rs", "fn broken( {");
        assert!(r.allocations.is_empty());
        assert_eq!(r.rejected.len(), 1);
        assert!(r.rejected[0].detail.contains("could not be parsed"), "{r:?}");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Registry-row parsing (SSA P2) and the append-only rule
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn short_allocation_row_errors() {
        let md = "## Machine-enforced allocation table\n\n\
                  | Canister | MemoryId | Structure | Status |\n|---|---:|---|---|\n\
                  | c | 0 | X |\n";
        let e = parse_registry(md).expect_err("a 3-column row must not be skipped");
        assert!(e.contains("column(s), expected at least 4"), "{e}");
    }

    #[test]
    fn non_numeric_memory_id_row_errors() {
        let md = "## Machine-enforced allocation table\n\n\
                  | Canister | MemoryId | Structure | Status |\n|---|---:|---|---|\n\
                  | c | oh | X | active |\n";
        let e = parse_registry(md).expect_err("a mistyped ID must not be skipped");
        assert!(e.contains("is not a number"), "{e}");
    }

    #[test]
    fn unknown_status_row_errors() {
        let md = "## Machine-enforced allocation table\n\n\
                  | Canister | MemoryId | Structure | Status |\n|---|---:|---|---|\n\
                  | c | 0 | X | maybe |\n";
        let e = parse_registry(md).expect_err("an unknown status must not be skipped");
        assert!(e.contains("must be \n                             exactly") || e.contains("Status `maybe`"), "{e}");
    }

    // ══════════════════════════════════════════════════════════════════════
    // SSA HOLD #3 — cross-crate escape
    // ══════════════════════════════════════════════════════════════════════

    fn shared_with(src: &str) -> BTreeMap<String, CrateScan> {
        crate_scan("helper", false, scan_source("h.rs", src))
    }

    #[test]
    fn shared_crate_constructing_a_memory_id_blocks() {
        let e = check(&Config::default(), &shared_with("fn f() { let _ = MemoryId::new(7); }"));
        assert!(
            e.iter().any(|m| m.contains("SHARED crate and must not construct")),
            "{e:?}"
        );
    }

    #[test]
    fn shared_crate_memory_id_const_blocks() {
        let e = check(&Config::default(), &shared_with("pub const ID7: MemoryId = MemoryId::new(7);"));
        assert!(
            e.iter().any(|m| m.contains("must not hold MemoryId-typed items")),
            "the shared CONST is the escape vehicle: {e:?}"
        );
    }

    #[test]
    fn shared_crate_memory_id_static_blocks() {
        let e = check(&Config::default(), &shared_with("pub static ID7: MemoryId = MemoryId::new(7);"));
        assert!(e.iter().any(|m| m.contains("must not hold MemoryId-typed items")), "{e:?}");
    }

    /// `fn -> MemoryId` is blocked everywhere, shared crate included — this is
    /// the other half of the escape SSA described.
    #[test]
    fn shared_crate_memory_id_returning_fn_blocks() {
        let e = check(&Config::default(), &shared_with("pub fn id7() -> MemoryId { MemoryId::new(7) }"));
        assert!(e.iter().any(|m| m.contains("returns a `MemoryId`")), "{e:?}");
    }

    /// A canister crate declaring `const MEM_X: MemoryId = MemoryId::new(0);`
    /// is the NORMAL, required shape — confinement must not break it.
    #[test]
    fn canister_crate_memory_id_const_is_legal() {
        let scan = scan_source("c.rs", "const MEM_X: MemoryId = MemoryId::new(0);");
        assert_eq!(scan.bindings.len(), 1, "the binding is still recorded");
        let e = check(&cfg("c", vec![0], vec![]), &crate_scan("c", true, scan));
        assert!(e.is_empty(), "a canister-crate MemoryId const must be legal: {e:?}");
    }

    // ══════════════════════════════════════════════════════════════════════
    // SSA HOLD #4 — scan-set completeness BY CONSTRUCTION
    //
    // Every test here goes through the PRODUCTION `scan_tree` path — the same
    // function `main` calls — because the previous round's completeness test
    // exercised the derivation helper directly and so never covered the
    // `unwrap_or_default` that turned a derivation error into an empty pass.
    // ══════════════════════════════════════════════════════════════════════

    fn fixture(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vmi_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    /// Minimal repo: a workspace root plus one canister crate, so the fixture
    /// is never degenerate.
    fn base_repo(root: &Path) {
        write(&root.join("Cargo.toml"), "[workspace]\nmembers = [\"canisters/alpha\"]\n");
        write(
            &root.join("canisters/alpha/Cargo.toml"),
            "[package]\nname = \"alpha\"\n[lib]\ncrate-type = [\"cdylib\"]\n[dependencies]\nic-cdk = \"0.16\"\n",
        );
        write(&root.join("canisters/alpha/src/lib.rs"), "pub fn a() {}\n");
    }

    /// The shape that must be caught however the crate is (or is not) wired
    /// into the workspace graph.
    const SNEAK: &str = "pub const ID7: MemoryId = MemoryId::new(7);\n";

    fn caught(root: &Path, crate_name: &str) -> bool {
        let scanned = scan_tree(root).expect("production scan must succeed");
        assert!(
            scanned.contains_key(crate_name),
            "{crate_name} must be IN the scan set; got {:?}",
            scanned.keys().collect::<Vec<_>>()
        );
        check(&Config::default(), &scanned)
            .iter()
            .any(|m| m.contains(crate_name) && m.contains("SHARED crate"))
    }

    /// `workspace.exclude` — the shape `vetkeys` already has. Graph traversal
    /// missed these unless hardcoded by name.
    #[test]
    fn workspace_exclude_crate_is_scanned() {
        let root = fixture("wsexclude");
        write(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"canisters/alpha\"]\nexclude = [\"canisters/excluded\"]\n",
        );
        write(
            &root.join("canisters/alpha/Cargo.toml"),
            "[package]\nname = \"alpha\"\n[lib]\ncrate-type = [\"cdylib\"]\n[dependencies]\nic-cdk = \"0.16\"\n",
        );
        write(&root.join("canisters/alpha/src/lib.rs"), "pub fn a() {}\n");
        write(&root.join("canisters/excluded/Cargo.toml"), "[package]\nname = \"excluded\"\n[dependencies]\n");
        write(&root.join("canisters/excluded/src/lib.rs"), SNEAK);
        assert!(caught(&root, "excluded"), "a workspace-excluded crate must still be scanned");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `target.'cfg(...)'.dependencies` — invisible to a plain `[dependencies]`
    /// path-dep walk.
    #[test]
    fn target_cfg_path_dependency_is_scanned() {
        let root = fixture("targetcfg");
        base_repo(&root);
        let mut m = std::fs::read_to_string(root.join("canisters/alpha/Cargo.toml")).unwrap();
        m.push_str("\n[target.'cfg(target_arch = \"wasm32\")'.dependencies]\ncfghelper = { path = \"../../cfghelper\" }\n");
        write(&root.join("canisters/alpha/Cargo.toml"), &m);
        write(&root.join("cfghelper/Cargo.toml"), "[package]\nname = \"cfghelper\"\n[dependencies]\n");
        write(&root.join("cfghelper/src/lib.rs"), SNEAK);
        assert!(caught(&root, "cfghelper"), "a cfg-gated path dep must be scanned");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `[build-dependencies]` path helpers — likewise invisible.
    #[test]
    fn build_dependency_path_helper_is_scanned() {
        let root = fixture("builddep");
        base_repo(&root);
        let mut m = std::fs::read_to_string(root.join("canisters/alpha/Cargo.toml")).unwrap();
        m.push_str("\n[build-dependencies]\nbuildhelper = { path = \"../../buildhelper\" }\n");
        write(&root.join("canisters/alpha/Cargo.toml"), &m);
        write(&root.join("buildhelper/Cargo.toml"), "[package]\nname = \"buildhelper\"\n[dependencies]\n");
        write(&root.join("buildhelper/src/lib.rs"), SNEAK);
        assert!(caught(&root, "buildhelper"), "a build-dependency helper must be scanned");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A standalone crate referenced by nothing at all — the `circuits/rust-spike`
    /// shape, which the graph walk omitted entirely.
    #[test]
    fn standalone_unreferenced_crate_is_scanned() {
        let root = fixture("standalone");
        base_repo(&root);
        write(&root.join("circuits/rust-spike/Cargo.toml"), "[package]\nname = \"rust-spike\"\n[dependencies]\n");
        write(&root.join("circuits/rust-spike/src/lib.rs"), SNEAK);
        assert!(caught(&root, "rust-spike"), "an unreferenced first-party crate must be scanned");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Third-party under `target/` is never scanned — `ic_stable_structures`
    /// legitimately calls `MemoryId::new` internally.
    #[test]
    fn vendored_third_party_under_target_is_never_scanned() {
        let root = fixture("vendored");
        base_repo(&root);
        write(
            &root.join("target/vendor/ic_stable_structures/Cargo.toml"),
            "[package]\nname = \"ic_stable_structures\"\n[dependencies]\n",
        );
        write(
            &root.join("target/vendor/ic_stable_structures/src/lib.rs"),
            "pub fn internal() { let _ = MemoryId::new(3); }\n",
        );
        let scanned = scan_tree(&root).expect("scan");
        assert!(
            !scanned.contains_key("ic_stable_structures"),
            "third-party under target/ must never be scanned"
        );
        assert!(
            !check(&Config::default(), &scanned)
                .iter()
                .any(|m| m.contains("ic_stable_structures")),
            "a third-party MemoryId::new must not be flagged"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── P2: errors PROPAGATE through the production path, never default ────

    #[test]
    fn malformed_manifest_is_a_hard_error_not_a_skip() {
        let root = fixture("badmanifest");
        base_repo(&root);
        write(&root.join("broken/Cargo.toml"), "[package\nname = oops\n");
        let e = scan_tree(&root).expect_err("a malformed manifest must fail the run");
        assert!(e.contains("malformed manifest"), "{e}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_scan_set_is_a_hard_error_not_a_vacuous_pass() {
        let root = fixture("emptyset");
        // A virtual workspace manifest with no member crates: discovery finds
        // a Cargo.toml but no [package], so the set is degenerate.
        write(&root.join("Cargo.toml"), "[workspace]\nmembers = []\n");
        let e = scan_tree(&root).expect_err("an empty scan set must fail the run");
        assert!(e.contains("no first-party crates discovered"), "{e}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ambiguous_duplicate_crate_name_is_a_hard_error() {
        let root = fixture("dupname");
        base_repo(&root);
        // Same directory name in two places — the registry keys on it, so the
        // allocations could not be attributed unambiguously.
        write(&root.join("other/alpha/Cargo.toml"), "[package]\nname = \"alpha2\"\n[dependencies]\n");
        write(&root.join("other/alpha/src/lib.rs"), "pub fn a() {}\n");
        let e = scan_tree(&root).expect_err("a duplicate crate dir name must fail the run");
        assert!(e.contains("share the directory name"), "{e}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn clean_config_passes() {
        assert!(check(&cfg("c", vec![0, 2], vec![1]), &code("c", &[0, 2])).is_empty());
    }

    #[test]
    fn duplicate_within_canister_fails() {
        let e = check(&cfg("c", vec![0], vec![]), &code("c", &[0, 0]));
        assert!(e.iter().any(|m| m.contains("allocated TWICE")), "{e:?}");
    }

    #[test]
    fn reuse_of_retired_id_fails() {
        let e = check(&cfg("c", vec![0, 1], vec![1]), &code("c", &[0, 1]));
        assert!(e.iter().any(|m| m.contains("is RETIRED")), "{e:?}");
    }

    #[test]
    fn code_allocation_missing_from_config_fails() {
        let e = check(&cfg("c", vec![0], vec![]), &code("c", &[0, 7]));
        assert!(e.iter().any(|m| m.contains("MISSING from")), "{e:?}");
    }

    #[test]
    fn config_entry_with_no_code_fails() {
        let e = check(&cfg("c", vec![0, 9], vec![]), &code("c", &[0]));
        assert!(e.iter().any(|m| m.contains("no allocation exists")), "{e:?}");
    }

    #[test]
    fn same_id_across_different_canisters_is_legal() {
        let mut c = code("a", &[0, 1]);
        c.extend(code("b", &[0, 1]));
        let config = Config {
            canisters: vec![
                CanisterConfig { name: "a".into(), active: vec![0, 1], retired: vec![] },
                CanisterConfig { name: "b".into(), active: vec![0, 1], retired: vec![] },
            ],
        };
        assert!(check(&config, &c).is_empty(), "independent stable memories");
    }

    #[test]
    fn id_both_active_and_retired_is_rejected() {
        let e = check(&cfg("c", vec![0, 1], vec![1]), &code("c", &[0, 1]));
        assert!(e.iter().any(|m| m.contains("BOTH active and retired")), "{e:?}");
    }
}
