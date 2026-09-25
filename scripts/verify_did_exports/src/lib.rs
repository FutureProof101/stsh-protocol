// =============================================================================
// verify_did_exports — did-vs-exports equivalence (D1) + amount-boundary
// census (D2) for the STSH estate. Host tool only; never linked into a Wasm.
// =============================================================================
// W3 3-1, CTO packet V3 (89721d12…, SSA countersigned c1c1bb53…).
//
// D1: for every canister enrolled IN SCOPE by the checked-in census, the set of
//     callable Candid service methods declared in the tracked `.did` must equal
//     the set of effective exported names of that crate's `#[query]`/`#[update]`
//     endpoints, both directions. Lifecycle entry points (init, pre_upgrade,
//     post_upgrade, heartbeat, inspect_message) are NOT service methods and are
//     never demanded of a `.did`.
//
// D2: no raw `u128`/`i128` may be reachable from an untrusted public endpoint —
//     as a direct parameter or transitively through aliases, structs, variants,
//     options, vectors and tuples — unless it is on the reviewed allowlist.
//     Install/init arguments ARE part of D2's universe even though `#[init]` is
//     outside D1's method universe.
//
// Both halves fail closed. Anything the tool cannot RESOLVE — an attribute form
// it does not recognise, a cfg predicate it cannot evaluate, a type it cannot
// follow — is a hard failure with a named reason, never a silent omission.

// R-1 (token supply integrity) gate lints — see each module's own header.
pub mod r1_deviation_register;
pub mod r1_ledger_boundary;
pub mod r1_ledger_maps;
pub mod r1_proc_macro_deps;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

// ── Census / allowlist data model ────────────────────────────────────────────

/// The universe is this file, not a glob. A `canisters/*` crate that exposes
/// endpoints and is absent from the census is a hard failure: enrol it or
/// exclude it by name with a reason.
#[derive(Debug, Deserialize)]
pub struct Census {
    #[serde(default)]
    pub canister: Vec<CanisterEntry>,
    /// Named, dated did-vs-exports drift exceptions (packet §3). Amount
    /// boundaries can NEVER be excepted here — they STOP and refer up.
    #[serde(default)]
    pub exception: Vec<Exception>,
}

#[derive(Debug, Deserialize)]
pub struct CanisterEntry {
    /// Repo-relative crate directory, e.g. `canisters/token`.
    pub krate: String,
    /// Repo-relative tracked `.did`. Required when `in_scope`.
    #[serde(default)]
    pub did: Option<String>,
    pub in_scope: bool,
    /// Mandatory for every entry; the reason an exclusion is legitimate.
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct Exception {
    pub krate: String,
    /// `did_method_missing_from_exports` | `export_missing_from_did`
    pub kind: String,
    pub method: String,
    pub date: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct Allowlist {
    /// Reviewed raw-amount boundaries (C4 §4 rule 2). Builders never add rows.
    #[serde(default)]
    pub amount: Vec<AmountEntry>,
    /// R2-1 (c), ruled by CTO_ADJUDICATION_MINI_QUEUE_2026-08-23 §2(c): the
    /// deliberately-published reporting surfaces are enrolled BY STRUCT, one
    /// class-row each, rather than by field — `SupplyInvariantReport`,
    /// `VestingSchedule`, `FeeLogEntry` and their kin publish amounts on purpose.
    /// Each row states its field count, and the count is a DRIFT LOCK: a silently
    /// added amount field changes the count and REDs the gate, which is what stops
    /// a class-row from becoming a blanket licence.
    ///
    /// Authorship is A1's and review is SSA-1's (builders never enrol). This is
    /// the enforcement the rows are written against.
    #[serde(default)]
    pub amount_struct: Vec<AmountStructEntry>,
    /// Type names the traversal cannot follow into (foreign/std/candid types
    /// with no in-tree definition), each declared with the reason it cannot
    /// carry a raw u128/i128. Declared data, not a silent skip.
    #[serde(default)]
    pub opaque: Vec<OpaqueEntry>,
}

#[derive(Debug, Deserialize)]
pub struct AmountEntry {
    pub krate: String,
    pub endpoint: String,
    /// Exact traversal path as this tool prints it, e.g.
    /// `amount: u128` or `proposal_type: ProposalType::SetFee.new_fee: u128`.
    pub path: String,
    /// The gate that makes this boundary safe.
    pub gate: String,
    pub reason: String,
    /// R2-1 §2(b) D-1/L, ruled: a row that is valid ONLY while a canister is absent
    /// from the launch install set names the `dfx.json` canister KEY here, and the
    /// checker REDs while that key is present. The condition is ASSERTED, not
    /// asserted-about: the matcher below reads `krate + endpoint + path` and has
    /// never read a `reason` string, so an exclusion carried in prose would have
    /// kept the gate green the day staking shipped.
    ///
    /// The key is written out because crate→canister inference is wrong on the
    /// first mapping it meets (`canisters/token` is `stsh_token` in dfx.json).
    #[serde(default)]
    pub launch_excluded_dfx: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AmountStructEntry {
    /// The struct/enum whose returned fields this row adjudicates, exactly as the
    /// traversal path names it (the segment after `->::`).
    pub name: String,
    /// Why this surface publishes amounts deliberately.
    pub rationale: String,
    /// How many raw-amount fields the row was reviewed against. A mismatch is a
    /// finding, in BOTH directions: an added field is unreviewed, and a removed
    /// one means the row no longer describes the surface it claims to.
    pub field_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct OpaqueEntry {
    /// SSA-1 RED on A1_R21_OPAQUE_ROW_V1: opacity is CRATE-SCOPED. A bare name was a
    /// global stop — declaring `ByteBuf` opaque for the monitor would also have
    /// silenced an unrelated future `ByteBuf` in any other crate, so the row's
    /// authored scope ("this foreign type, in this crate") and its machine scope
    /// were different things. The crate is data here, never inferred from prose.
    pub krate: String,
    pub name: String,
    pub reason: String,
}

pub fn load_census(path: &Path) -> Result<Census, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("census {}: {e}", path.display()))?;
    toml::from_str(&raw).map_err(|e| format!("census {}: {e}", path.display()))
}

pub fn load_allowlist(path: &Path) -> Result<Allowlist, String> {
    let raw =
        std::fs::read_to_string(path).map_err(|e| format!("allowlist {}: {e}", path.display()))?;
    toml::from_str(&raw).map_err(|e| format!("allowlist {}: {e}", path.display()))
}

// ── Findings ─────────────────────────────────────────────────────────────────

/// Every finding is blocking. There is no warning tier: a check that can be
/// ignored is not a gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub code: &'static str,
    pub subject: String,
    pub detail: String,
}

impl Finding {
    fn new(code: &'static str, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { code, subject: subject.into(), detail: detail.into() }
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {} — {}", self.code, self.subject, self.detail)
    }
}

// ── cfg evaluation ───────────────────────────────────────────────────────────
//
// The PRODUCTION configuration is authoritative: `test` is false and a feature
// is on only if it is in the crate's `[features] default` list. Every other
// predicate is unresolvable, and unresolvable is a hard failure — the whole
// point is that no endpoint disappears from the census by accident.

#[derive(Debug, Clone, Default)]
pub struct CfgConfig {
    pub features: BTreeSet<String>,
}

fn eval_cfg_meta(meta: &syn::Meta, cfg: &CfgConfig) -> Result<bool, String> {
    match meta {
        syn::Meta::Path(p) if p.is_ident("test") => Ok(false),
        syn::Meta::NameValue(nv) if nv.path.is_ident("feature") => match &nv.value {
            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => {
                Ok(cfg.features.contains(&s.value()))
            }
            other => Err(format!("cfg feature value is not a string literal: {}", tokens(other))),
        },
        syn::Meta::List(list) => {
            let inner: Vec<syn::Meta> = list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .map_err(|e| format!("unparseable cfg predicate: {e}"))?
                .into_iter()
                .collect();
            if list.path.is_ident("all") {
                for m in &inner {
                    if !eval_cfg_meta(m, cfg)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            } else if list.path.is_ident("any") {
                for m in &inner {
                    if eval_cfg_meta(m, cfg)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            } else if list.path.is_ident("not") {
                match inner.as_slice() {
                    [one] => Ok(!eval_cfg_meta(one, cfg)?),
                    _ => Err("cfg(not(..)) takes exactly one predicate".into()),
                }
            } else {
                Err(format!("unrecognised cfg predicate `{}`", path_str(&list.path)))
            }
        }
        other => Err(format!("unrecognised cfg predicate `{}`", tokens(other))),
    }
}

/// `Ok(true)` = the item is present in the production build.
fn item_enabled(attrs: &[syn::Attribute], cfg: &CfgConfig) -> Result<bool, String> {
    for attr in attrs {
        if !attr.path().is_ident("cfg") {
            continue;
        }
        let syn::Meta::List(list) = &attr.meta else {
            return Err("bare `#[cfg]` without a predicate".into());
        };
        let inner: syn::Meta =
            list.parse_args().map_err(|e| format!("unparseable cfg predicate: {e}"))?;
        if !eval_cfg_meta(&inner, cfg)? {
            return Ok(false);
        }
    }
    Ok(true)
}

// ── Rust source scan ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Query,
    Update,
    Init,
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub kind: EndpointKind,
    /// Effective exported name — `#[query(name = "x")]` resolves to `x`.
    pub exported_name: String,
    pub fn_name: String,
    pub file: PathBuf,
    pub line: usize,
    /// (parameter name, parameter type) in declaration order.
    pub args: Vec<(String, syn::Type)>,
    /// R2-1: the RETURN type, when the signature declares one. Before this the
    /// census read `sig.inputs` only, so no return type could reach
    /// `check_amount_boundaries` — a `-> u128` on a public query was invisible
    /// to a lint whose whole purpose is finding raw amounts at the boundary,
    /// while the identical type as a parameter failed the gate. Proven in both
    /// directions by causal probe (R2_REPORT §6/R2-1), and now by the
    /// `amount_return*` fixtures.
    pub ret: Option<syn::Type>,
}

#[derive(Debug, Clone)]
pub enum TypeDef {
    /// `type A = B;`
    Alias(syn::Type),
    /// struct/enum: (field path label, field type). Enum variants label as
    /// `Variant.field`; tuple fields label by index.
    Fields(Vec<(String, syn::Type)>),
}

#[derive(Debug, Default)]
pub struct CrateScan {
    pub endpoints: Vec<Endpoint>,
    pub types: BTreeMap<String, Vec<TypeDef>>,
}

fn path_str(p: &syn::Path) -> String {
    p.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::")
}

fn tokens<T: quote::ToTokens>(t: &T) -> String {
    quote::quote!(#t).to_string()
}

/// Import bindings in force for one file: local name → the full path it names.
/// `use ic_cdk_macros::update as endpoint;` binds `endpoint` → `ic_cdk_macros::update`.
pub type UseMap = BTreeMap<String, String>;

/// Collect the `use` leaves declared at ONE module level as local-name →
/// full-path. Renames bind the RENAMED name. Globs are not recorded: a glob
/// cannot rename, so the bare-name arm already covers it.
///
/// Inline modules are NOT descended into here. Scope is the point: SSA
/// landed-diff F1c — a flattened file-wide map lets a sibling module's
/// `use std::fmt as endpoint;` overwrite `use ic_cdk_macros::update as endpoint;`
/// and silently un-census the endpoint in the first module. Rust scoping is
/// therefore modelled directly: each module sees its own bindings layered over
/// its ancestors', and a sibling's bindings never reach it.
fn collect_uses(items: &[syn::Item], out: &mut UseMap) {
    fn tree(t: &syn::UseTree, prefix: &str, out: &mut UseMap) {
        let join = |p: &str, s: &str| if p.is_empty() { s.to_string() } else { format!("{p}::{s}") };
        match t {
            syn::UseTree::Path(p) => {
                tree(&p.tree, &join(prefix, &p.ident.to_string()), out);
            }
            syn::UseTree::Group(g) => {
                for inner in &g.items {
                    tree(inner, prefix, out);
                }
            }
            syn::UseTree::Name(n) => {
                let name = n.ident.to_string();
                out.insert(name.clone(), join(prefix, &name));
            }
            syn::UseTree::Rename(r) => {
                out.insert(r.rename.to_string(), join(prefix, &r.ident.to_string()));
            }
            syn::UseTree::Glob(_) => {}
        }
    }
    for item in items {
        if let syn::Item::Use(u) = item {
            tree(&u.tree, "", out);
        }
    }
}

/// The bindings in force inside a module: its own, layered over its ancestors'.
/// A child rebinding a name shadows the ancestor exactly as Rust does; nothing
/// is lost across sibling scopes because a sibling's map is never consulted.
fn scoped_uses(parent: &UseMap, items: &[syn::Item]) -> UseMap {
    let mut child = parent.clone();
    collect_uses(items, &mut child);
    child
}

const ENDPOINT_MACRO_PATHS: &[&str] = &[
    "query",
    "update",
    "init",
    "ic_cdk::query",
    "ic_cdk::update",
    "ic_cdk::init",
    "ic_cdk_macros::query",
    "ic_cdk_macros::update",
    "ic_cdk_macros::init",
];

/// Recognised ic-cdk endpoint attribute paths, AFTER resolving the file's own
/// import aliases. Anything whose effective LAST segment is
/// `query`/`update`/`init` but whose full path is not here is a hard failure:
/// silently ignoring an unknown qualification is exactly how an endpoint goes
/// missing from a census that claims to be complete.
///
/// SSA landed-diff F1: matching on the last segment of the WRITTEN path alone
/// let `use ic_cdk_macros::update as endpoint;` + `#[endpoint]` vanish — the
/// attribute is not named `update`, so the hard-fail arm was never reached and
/// the export disappeared from a census claiming completeness. Aliases are now
/// resolved through the file's `use` bindings before classification.
fn endpoint_kind_of(path: &syn::Path, uses: &UseMap) -> Option<Result<EndpointKind, String>> {
    let written = path_str(path);
    // Only a single-segment attribute can be an import alias; a qualified path
    // is already absolute-ish and is judged as written.
    let (full, aliased) = if path.segments.len() == 1 {
        match uses.get(&written) {
            Some(target) => (target.clone(), true),
            None => (written.clone(), false),
        }
    } else {
        (written.clone(), false)
    };

    let last = full.rsplit("::").next().unwrap_or(&full).to_string();
    let kind = match last.as_str() {
        "query" => EndpointKind::Query,
        "update" => EndpointKind::Update,
        "init" => EndpointKind::Init,
        _ => {
            // `use some::other as update;` shadows the bare name with something
            // this tool cannot classify. Refusing is the only fail-closed answer:
            // treating it as "not an endpoint" is precisely the F1 bypass.
            if aliased && ENDPOINT_MACRO_PATHS.contains(&written.as_str()) {
                return Some(Err(format!(
                    "attribute `#[{written}]` is bound by `use {full}` — the endpoint-macro name \
                     is shadowed by an unrecognised import and cannot be classified"
                )));
            }
            return None;
        }
    };

    Some(if ENDPOINT_MACRO_PATHS.contains(&full.as_str()) {
        Ok(kind)
    } else if aliased {
        Err(format!(
            "endpoint attribute `#[{written}]` resolves through `use` to unrecognised path \
             `{full}`"
        ))
    } else {
        Err(format!("unrecognised endpoint attribute path `#[{full}]`"))
    })
}

/// Pull the effective exported name out of the attribute arguments. Recognised
/// arguments: `name = "..."` (the rename that decides the exported name),
/// `guard = "..."`, `composite_query`, `manual_reply`, `decoding_quota = N`,
/// `hidden`. Anything else is a hard failure.
fn attr_exported_name(attr: &syn::Attribute) -> Result<Option<String>, String> {
    if matches!(attr.meta, syn::Meta::Path(_)) {
        return Ok(None);
    }
    let mut name = None;
    attr.parse_nested_meta(|meta| {
        let key = path_str(&meta.path);
        match key.as_str() {
            "name" => {
                let v: syn::LitStr = meta.value()?.parse()?;
                name = Some(v.value());
            }
            "guard" | "decoding_quota" | "skipping_quota" => {
                let _: syn::Expr = meta.value()?.parse()?;
            }
            "composite_query" | "manual_reply" | "hidden" => {}
            other => {
                return Err(meta.error(format!("unrecognised endpoint attribute argument `{other}`")))
            }
        }
        Ok(())
    })
    .map_err(|e| e.to_string())?;
    Ok(name)
}

fn field_types(fields: &syn::Fields) -> Vec<(String, syn::Type)> {
    match fields {
        syn::Fields::Named(named) => named
            .named
            .iter()
            .map(|f| (f.ident.as_ref().unwrap().to_string(), f.ty.clone()))
            .collect(),
        syn::Fields::Unnamed(un) => {
            un.unnamed.iter().enumerate().map(|(i, f)| (format!("{i}"), f.ty.clone())).collect()
        }
        syn::Fields::Unit => Vec::new(),
    }
}

/// Traversal state for one crate. The module GRAPH is walked, not the file
/// list: SSA landed-diff F1d — parsing every `.rs` as an independent root gave
/// each file an empty import map (so `mod foo;` lost the parent's endpoint-macro
/// alias, reproducing F1 across a file boundary) and ignored the `#[cfg]` on the
/// declaration (so a `#[cfg(test)] mod tests;` file was scanned as production).
struct ScanCtx<'a> {
    cfg: &'a CfgConfig,
    /// Files reached from a crate root through an enabled module declaration.
    visited: BTreeSet<PathBuf>,
    /// Files claimed within the CURRENT target's graph. Cleared between targets:
    /// `lib.rs` and `main.rs` may each legally declare the same `mod foo;`,
    /// but one target claiming a file twice is an invalid topology (F1h).
    claimed: BTreeSet<PathBuf>,
    /// Files and directories belonging to modules the production configuration
    /// disables. Declared as skipped, so they are not silent omissions.
    skipped: Vec<PathBuf>,
    out: CrateScan,
}

/// Resolve `mod foo;` to its file: `<dir>/foo.rs` or `<dir>/foo/mod.rs`, or an
/// explicit `#[path = "..."]`. Neither, or both, is a hard failure — a module
/// layout this tool cannot resolve is exactly the state where an endpoint goes
/// missing without anyone noticing.
fn resolve_module_file(
    attrs: &[syn::Attribute],
    dir: &Path,
    name: &str,
    declared_in: &Path,
) -> Result<PathBuf, String> {
    for attr in attrs {
        if attr.path().is_ident("path") {
            let syn::Meta::NameValue(nv) = &attr.meta else {
                return Err(format!("{}: `#[path]` without a value", declared_in.display()));
            };
            let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) = &nv.value else {
                return Err(format!(
                    "{}: `#[path]` value is not a string literal",
                    declared_in.display()
                ));
            };
            let p = dir.join(s.value());
            if !p.is_file() {
                return Err(format!(
                    "{}: `#[path = \"{}\"]` for `mod {name}` names no file",
                    declared_in.display(),
                    s.value()
                ));
            }
            return Ok(p);
        }
    }
    let flat = dir.join(format!("{name}.rs"));
    let nested = dir.join(name).join("mod.rs");
    match (flat.is_file(), nested.is_file()) {
        (true, false) => Ok(flat),
        (false, true) => Ok(nested),
        (true, true) => Err(format!(
            "{}: `mod {name}` is ambiguous — both {} and {} exist",
            declared_in.display(),
            flat.display(),
            nested.display()
        )),
        (false, false) => Err(format!(
            "{}: `mod {name};` resolves to no file ({} / {})",
            declared_in.display(),
            flat.display(),
            nested.display()
        )),
    }
}

/// The directory in which this file's child modules live: a crate root or a
/// `mod.rs` owns its own directory; `src/foo.rs` owns `src/foo/`.
fn module_dir(file: &Path) -> PathBuf {
    let dir = file.parent().unwrap_or(Path::new("")).to_path_buf();
    if file.file_name().is_some_and(|f| f == "mod.rs" || f == "lib.rs" || f == "main.rs") {
        dir
    } else {
        dir.join(file.file_stem().unwrap_or_default().to_string_lossy().to_string())
    }
}

/// The candidate paths a module declaration could own — the file and the
/// directory its children would live in. Used both to follow a module and, when
/// the production configuration disables one, to declare its whole subtree
/// skipped rather than leave it looking unreachable (SSA F1e/F1f).
fn module_candidates(attrs: &[syn::Attribute], dir: &Path, name: &str) -> Vec<PathBuf> {
    if let Some(explicit) = explicit_path(attrs) {
        let file = dir.join(&explicit);
        let subtree = module_dir(&file);
        return vec![file, subtree];
    }
    vec![dir.join(format!("{name}.rs")), dir.join(name), dir.join(name).join("mod.rs")]
}

fn explicit_path(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find(|a| a.path().is_ident("path")).and_then(|a| match &a.meta {
        syn::Meta::NameValue(nv) => match &nv.value {
            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.value()),
            _ => None,
        },
        _ => None,
    })
}

fn scan_file(
    file: &Path,
    parent_uses: &UseMap,
    claimed_by: &str,
    ctx: &mut ScanCtx,
) -> Result<(), String> {
    // SSA F1h: a second claim on the same file inside one target's graph is an
    // invalid module topology (`mod foo; mod foo;`), not a cache hit. Rust
    // rejects it; a gate that says it fails closed cannot quietly dedupe it.
    let id = identity(file)?;
    if !ctx.claimed.insert(id.clone()) {
        return Err(format!(
            "{}: file is claimed more than once in the same target's module graph ({claimed_by}) \
             — the module topology is ambiguous. Note this compares physical identity, so an \
             alias or symlink to an already-claimed file is the same claim",
            file.display()
        ));
    }
    ctx.visited.insert(id);
    let src = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let ast =
        syn::parse_file(&src).map_err(|e| format!("{}: unparseable Rust: {e}", file.display()))?;
    // A file-level `#![cfg(...)]` disables the whole file — AND everything its
    // module declarations would have owned (SSA F1f).
    if !item_enabled(&ast.attrs, ctx.cfg)? {
        ctx.skipped.push(identity_or_lexical(file));
        ctx.skipped.push(identity_or_lexical(&module_dir(file)));
        return Ok(());
    }
    let uses = scoped_uses(parent_uses, &ast.items);
    scan_items(&ast.items, file, &uses, ctx)
}

fn scan_items(
    items: &[syn::Item],
    file: &Path,
    uses: &UseMap,
    ctx: &mut ScanCtx,
) -> Result<(), String> {
    let cfg = ctx.cfg.clone();
    for item in items {
        match item {
            syn::Item::Mod(m) => {
                let name = m.ident.to_string();
                if !item_enabled(&m.attrs, &cfg)? {
                    // Disabled by the production configuration. If it is an
                    // external module, every path it could own — including an
                    // explicit `#[path]` and that file's own subtree — is
                    // declared skipped rather than left looking unreachable
                    // (SSA F1e).
                    if m.content.is_none() {
                        ctx.skipped.extend(
                            module_candidates(&m.attrs, &module_dir(file), &name)
                                .iter()
                                .map(|p| identity_or_lexical(p)),
                        );
                    }
                    continue;
                }
                match &m.content {
                    Some((_, inner)) => {
                        // The module's own bindings shadow the parent's;
                        // siblings never see each other (F1c).
                        let inner_uses = scoped_uses(uses, inner);
                        scan_items(inner, file, &inner_uses, ctx)?;
                    }
                    None => {
                        // External module: it INHERITS this scope's bindings,
                        // which is the whole of F1d.
                        let target = resolve_module_file(&m.attrs, &module_dir(file), &name, file)?;
                        let claim = format!("mod {name} in {}", file.display());
                        scan_file(&target, uses, &claim, ctx)?;
                    }
                }
            }
            syn::Item::Fn(f) => {
                if !item_enabled(&f.attrs, &cfg)? {
                    continue;
                }
                let mut found: Option<(EndpointKind, Option<String>)> = None;
                for attr in &f.attrs {
                    let Some(kind) = endpoint_kind_of(attr.path(), uses) else { continue };
                    let kind = kind.map_err(|e| {
                        format!("{}:{}: {e}", file.display(), attr.path().segments[0].ident.span().start().line)
                    })?;
                    let name = attr_exported_name(attr).map_err(|e| {
                        format!("{}: fn {}: {e}", file.display(), f.sig.ident)
                    })?;
                    found = Some((kind, name));
                }
                let Some((kind, rename)) = found else { continue };
                let args = f
                    .sig
                    .inputs
                    .iter()
                    .filter_map(|a| match a {
                        syn::FnArg::Typed(t) => Some((
                            match &*t.pat {
                                syn::Pat::Ident(i) => i.ident.to_string(),
                                other => tokens(other),
                            },
                            (*t.ty).clone(),
                        )),
                        syn::FnArg::Receiver(_) => None,
                    })
                    .collect();
                let ret = match &f.sig.output {
                    syn::ReturnType::Default => None,
                    syn::ReturnType::Type(_, ty) => Some((**ty).clone()),
                };
                ctx.out.endpoints.push(Endpoint {
                    kind,
                    exported_name: rename.unwrap_or_else(|| f.sig.ident.to_string()),
                    fn_name: f.sig.ident.to_string(),
                    file: file.to_path_buf(),
                    line: f.sig.ident.span().start().line,
                    args,
                    ret,
                });
            }
            syn::Item::Struct(s) => {
                if !item_enabled(&s.attrs, &cfg)? {
                    continue;
                }
                ctx.out.types
                    .entry(s.ident.to_string())
                    .or_default()
                    .push(TypeDef::Fields(field_types(&s.fields)));
            }
            syn::Item::Enum(e) => {
                if !item_enabled(&e.attrs, &cfg)? {
                    continue;
                }
                let mut fields = Vec::new();
                for v in &e.variants {
                    for (label, ty) in field_types(&v.fields) {
                        fields.push((format!("{}.{}", v.ident, label), ty));
                    }
                }
                ctx.out.types.entry(e.ident.to_string()).or_default().push(TypeDef::Fields(fields));
            }
            syn::Item::Type(t) => {
                if !item_enabled(&t.attrs, &cfg)? {
                    continue;
                }
                ctx.out.types
                    .entry(t.ident.to_string())
                    .or_default()
                    .push(TypeDef::Alias((*t.ty).clone()));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Physical identity of a path, not the lexical spelling that reached it.
///
/// SSA F1i: `claimed`/`visited` compared `PathBuf`s as written, so `mod foo;`
/// plus `#[path = "alias.rs"] mod alias;` where `alias.rs` symlinks to `foo.rs`
/// looked like two files and the duplicate-claim guard never fired — one target
/// claiming one physical file twice, which is the exact thing F1h promised to
/// reject. Every claim, visit and skip comparison now goes through here.
fn identity(p: &Path) -> Result<PathBuf, String> {
    std::fs::canonicalize(p).map_err(|e| format!("{}: cannot resolve path identity: {e}", p.display()))
}

/// Best-effort identity for paths that may not exist (skip candidates for
/// modules the production configuration disables). A path that is not on disk
/// cannot alias anything on disk, so the lexical form is sufficient there.
fn identity_or_lexical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut seen_dirs = BTreeSet::new();
    rust_files_inner(dir, out, &mut seen_dirs);
}

/// Directory recursion keyed by physical identity: a symlinked directory is
/// walked at most once, and a cycle does not hang the gate (SSA F1i).
fn rust_files_inner(dir: &Path, out: &mut Vec<PathBuf>, seen_dirs: &mut BTreeSet<PathBuf>) {
    let Ok(dir_id) = std::fs::canonicalize(dir) else { return };
    if !seen_dirs.insert(dir_id) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            rust_files_inner(&p, out, seen_dirs);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// A crate's manifest. Real crates carry `Cargo.toml`; this tool's own test
/// fixtures carry `Cargo.fixture.toml` instead, because a fixture tree full of
/// files literally named `Cargo.toml` IS a set of first-party crates as far as
/// the rest of the estate is concerned — `verify_memory_ids` discovers crates by
/// walking the repo for that filename, and two fixtures named `c` collided into
/// an ambiguous scan set and aborted the whole gate. Fixtures must not
/// masquerade as crates; the alternative (widening another gate's exclusion
/// list) would have blunted a lint to accommodate test data.
pub fn manifest_path(crate_dir: &Path) -> Option<PathBuf> {
    for name in ["Cargo.toml", "Cargo.fixture.toml"] {
        let p = crate_dir.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Default-feature set from the crate's own manifest. No `default` key means no
/// default features, which is the estate's actual posture (`testing` is off in
/// every production build).
pub fn default_features(crate_dir: &Path) -> Result<CfgConfig, String> {
    let manifest = manifest_path(crate_dir)
        .ok_or_else(|| format!("{}: no crate manifest", crate_dir.display()))?;
    let raw = std::fs::read_to_string(&manifest)
        .map_err(|e| format!("{}: {e}", manifest.display()))?;
    let doc: toml::Value =
        toml::from_str(&raw).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let mut features = BTreeSet::new();
    if let Some(list) = doc.get("features").and_then(|f| f.get("default")).and_then(|d| d.as_array())
    {
        for v in list {
            if let Some(s) = v.as_str() {
                features.insert(s.to_string());
            }
        }
    }
    Ok(CfgConfig { features })
}

/// Every Cargo TARGET root of a crate: the library and binaries, from explicit
/// manifest `path` keys where present and from Cargo's autodiscovery otherwise
/// (`src/lib.rs`, `src/main.rs`, `src/bin/*.rs`, `src/bin/*/main.rs`).
///
/// SSA F1g: `src/bin/helper.rs` is a legitimate separate target, not an orphan
/// module of the library. Treating the manifest's topology as the authority is
/// the difference between a gate that knows what a crate is and one that calls
/// valid Cargo layout a violation.
fn target_roots(crate_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let manifest = manifest_path(crate_dir)
        .ok_or_else(|| format!("{}: no crate manifest", crate_dir.display()))?;
    let raw =
        std::fs::read_to_string(&manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let doc: toml::Value =
        toml::from_str(&raw).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let src = crate_dir.join("src");
    let mut roots = Vec::new();
    // Autodiscovered roots may or may not exist — that is what discovery means.
    let discover = |p: PathBuf, roots: &mut Vec<PathBuf>| {
        if p.is_file() && !roots.contains(&p) {
            roots.push(p);
        }
    };
    // A DECLARED target is a promise, not a guess (SSA F1j). If the manifest
    // names a path, that file must exist; silently dropping it removes a whole
    // module graph from the census while the scan still reports success.
    let declared = |p: PathBuf, label: &str, roots: &mut Vec<PathBuf>| -> Result<(), String> {
        if !p.is_file() {
            return Err(format!(
                "{}: target {label} declares path `{}`, which is not a file — a declared target \
                 must resolve",
                manifest.display(),
                p.display()
            ));
        }
        if !roots.contains(&p) {
            roots.push(p);
        }
        Ok(())
    };

    match doc.get("lib").and_then(|l| l.get("path")).and_then(|p| p.as_str()) {
        Some(p) => declared(crate_dir.join(p), "[lib]", &mut roots)?,
        None => discover(src.join("lib.rs"), &mut roots),
    }

    let explicit_bins: Vec<&toml::Value> =
        doc.get("bin").and_then(|b| b.as_array()).map(|a| a.iter().collect()).unwrap_or_default();
    if explicit_bins.is_empty() {
        discover(src.join("main.rs"), &mut roots);
    } else {
        for bin in explicit_bins {
            let name = bin.get("name").and_then(|n| n.as_str()).ok_or_else(|| {
                format!("{}: a [[bin]] target has no name", manifest.display())
            })?;
            match bin.get("path").and_then(|p| p.as_str()) {
                Some(p) => declared(crate_dir.join(p), &format!("[[bin]] `{name}`"), &mut roots)?,
                None => {
                    // No `path`: Cargo infers one by target name. Exactly one
                    // candidate must exist — zero means the declared target has
                    // no source, more than one is ambiguous, and both are the
                    // manifest disagreeing with the tree.
                    let candidates: Vec<PathBuf> = [
                        src.join("main.rs"),
                        src.join("bin").join(format!("{name}.rs")),
                        src.join("bin").join(name).join("main.rs"),
                    ]
                    .into_iter()
                    .filter(|p| p.is_file())
                    .collect();
                    match candidates.as_slice() {
                        [one] => declared(one.clone(), &format!("[[bin]] `{name}`"), &mut roots)?,
                        [] => {
                            return Err(format!(
                                "{}: [[bin]] `{name}` declares no path and no source file was \
                                 inferred",
                                manifest.display()
                            ))
                        }
                        many => {
                            return Err(format!(
                                "{}: [[bin]] `{name}` declares no path and {} candidate sources \
                                 exist — the target is ambiguous",
                                manifest.display(),
                                many.len()
                            ))
                        }
                    }
                }
            }
        }
    }

    // Cargo's binary autodiscovery, which explicit [[bin]] sections do not
    // disable unless autobins = false.
    if doc.get("package").and_then(|p| p.get("autobins")).and_then(|a| a.as_bool()) != Some(false) {
        let bin_dir = src.join("bin");
        if bin_dir.is_dir() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(&bin_dir)
                .map_err(|e| format!("{}: {e}", bin_dir.display()))?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .collect();
            entries.sort();
            for p in entries {
                if p.is_dir() {
                    discover(p.join("main.rs"), &mut roots);
                } else if p.extension().is_some_and(|e| e == "rs") {
                    discover(p, &mut roots);
                }
            }
        }
    }

    Ok(roots)
}

/// Scan a crate by walking its MODULE GRAPH from the crate root(s), not by
/// parsing every `.rs` it can find (SSA landed-diff F1d). A file's meaning
/// depends on the declaration that pulls it in: `mod foo;` hands `foo.rs` the
/// declaring scope's import bindings, and a `#[cfg]` on that declaration decides
/// whether `foo.rs` is in the production build at all.
///
/// Nothing is skipped quietly. Every `.rs` under `src/` must be either reached
/// through the graph or attributable to a module the production configuration
/// disables; anything else is a hard failure naming the file.
pub fn scan_crate(crate_dir: &Path) -> Result<CrateScan, String> {
    let cfg = default_features(crate_dir)?;
    let roots = target_roots(crate_dir)?;
    if roots.is_empty() {
        return Err(format!(
            "{}: no crate root (src/lib.rs, src/main.rs, a manifest `path`, or src/bin/*) — the \
             module graph has no entry point",
            crate_dir.display()
        ));
    }

    let mut ctx = ScanCtx {
        cfg: &cfg,
        visited: BTreeSet::new(),
        claimed: BTreeSet::new(),
        skipped: Vec::new(),
        out: CrateScan::default(),
    };
    for root in &roots {
        // Each Cargo target is its own module graph. Two targets may legally
        // declare the same module file (`lib.rs` and `main.rs` both saying
        // `mod foo;`), so the duplicate-claim check (F1h) is per target.
        ctx.claimed.clear();
        scan_file(root, &UseMap::new(), "target root", &mut ctx)?;
    }

    let mut on_disk = Vec::new();
    rust_files(&crate_dir.join("src"), &mut on_disk);
    for f in on_disk {
        // Physical identity where the entry resolves, so an aliased path cannot
        // masquerade as an unclaimed file (F1i). A DANGLING entry has no
        // physical identity to compare — and demanding one made this loop abort
        // before it could consult the skip set that already explained the entry
        // (SSA F1k). It is matched lexically instead, exactly as the skip
        // candidate for a disabled declaration was recorded.
        let f_id = std::fs::canonicalize(&f).ok();
        if let Some(id) = &f_id {
            if ctx.visited.contains(id) {
                continue;
            }
        }
        let explained = |key: &Path, skipped: &[PathBuf]| {
            skipped.iter().any(|s| key == s || key.starts_with(s))
        };
        if f_id.as_ref().is_some_and(|id| explained(id, &ctx.skipped))
            || explained(&f, &ctx.skipped)
        {
            continue;
        }
        return Err(format!(
            "{}: file is not reachable from the crate root's module graph and is not inside a \
             cfg-disabled module — a file no `mod` declaration claims is a place an endpoint can \
             hide",
            f.display()
        ));
    }

    Ok(ctx.out)
}

// ── Candid side ──────────────────────────────────────────────────────────────

/// Callable service methods declared by a `.did`, via a REAL candid parse.
/// Returns an error for: unreadable, unparseable, or actor-less files — the
/// no-service-actor rejection that `check_candid_did` already enforces before
/// embedding, preserved here rather than re-litigated.
pub fn did_methods(did: &Path) -> Result<BTreeSet<String>, String> {
    if !did.is_file() {
        return Err(format!("{}: tracked .did is missing", did.display()));
    }
    let raw = std::fs::read_to_string(did).map_err(|e| format!("{}: {e}", did.display()))?;
    if raw.trim().is_empty() {
        return Err(format!("{}: tracked .did is empty", did.display()));
    }
    let (env, actor) = candid_parser::pretty_check_file(did)
        .map_err(|e| format!("{}: not valid candid: {e}", did.display()))?;
    let Some(actor) = actor else {
        return Err(format!("{}: declares no service", did.display()));
    };
    let service = env
        .as_service(&actor)
        .map_err(|e| format!("{}: not a service type: {e}", did.display()))?;
    Ok(service.iter().map(|(name, _)| name.clone()).collect())
}

// ── D1 — did-vs-exports equivalence ──────────────────────────────────────────

pub fn check_did_exports(root: &Path, census: &Census) -> Result<Vec<Finding>, String> {
    let mut findings = Vec::new();

    // §2.4 — the census is the universe. A canisters/* crate that exposes
    // endpoints and is not enrolled or excluded BY NAME is a hard failure.
    let listed: BTreeSet<&str> = census.canister.iter().map(|c| c.krate.as_str()).collect();
    let canisters_dir = root.join("canisters");
    if canisters_dir.is_dir() {
        let mut dirs: Vec<PathBuf> = std::fs::read_dir(&canisters_dir)
            .map_err(|e| format!("{}: {e}", canisters_dir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| manifest_path(p).is_some())
            .collect();
        dirs.sort();
        for dir in dirs {
            let rel = format!("canisters/{}", dir.file_name().unwrap().to_string_lossy());
            if listed.contains(rel.as_str()) {
                continue;
            }
            let scan = scan_crate(&dir)?;
            if scan.endpoints.is_empty() {
                findings.push(Finding::new(
                    "CENSUS-MISSING",
                    rel,
                    "crate is absent from the census — enrol or exclude it by name",
                ));
            } else {
                findings.push(Finding::new(
                    "CENSUS-MISSING",
                    rel,
                    format!(
                        "crate exposes {} endpoint(s) and is absent from the census",
                        scan.endpoints.len()
                    ),
                ));
            }
        }
    }

    for entry in &census.canister {
        let crate_dir = root.join(&entry.krate);
        if manifest_path(&crate_dir).is_none() {
            findings.push(Finding::new(
                "CENSUS-STALE",
                &entry.krate,
                "census names a crate that does not exist at this pin",
            ));
            continue;
        }
        if !entry.in_scope {
            // An excluded crate must genuinely have nothing to compare: an
            // exclusion that hides live endpoints is the failure mode the
            // census exists to prevent.
            let scan = scan_crate(&crate_dir)?;
            let callable = scan
                .endpoints
                .iter()
                .filter(|e| e.kind != EndpointKind::Init)
                .count();
            if callable > 0 && entry.did.is_some() {
                findings.push(Finding::new(
                    "CENSUS-BAD-EXCLUSION",
                    &entry.krate,
                    format!("excluded but exposes {callable} callable endpoint(s) AND has a tracked .did"),
                ));
            }
            continue;
        }

        let Some(did_rel) = entry.did.as_ref() else {
            findings.push(Finding::new(
                "CENSUS-NO-DID",
                &entry.krate,
                "in scope but names no .did",
            ));
            continue;
        };
        let did_path = root.join(did_rel);
        let declared = match did_methods(&did_path) {
            Ok(m) => m,
            Err(e) => {
                findings.push(Finding::new("DID-INVALID", &entry.krate, e));
                continue;
            }
        };

        let scan = scan_crate(&crate_dir)?;
        let exported: BTreeSet<String> = scan
            .endpoints
            .iter()
            .filter(|e| e.kind != EndpointKind::Init)
            .map(|e| e.exported_name.clone())
            .collect();

        let excepted = |kind: &str, method: &str| {
            census.exception.iter().any(|x| {
                x.krate == entry.krate && x.kind == kind && x.method == method
            })
        };

        for m in declared.difference(&exported) {
            if excepted("did_method_missing_from_exports", m) {
                continue;
            }
            findings.push(Finding::new(
                "DID-METHOD-NOT-EXPORTED",
                &entry.krate,
                format!("`{m}` is declared in {did_rel} but no endpoint exports that name"),
            ));
        }
        for m in exported.difference(&declared) {
            if excepted("export_missing_from_did", m) {
                continue;
            }
            findings.push(Finding::new(
                "EXPORT-NOT-IN-DID",
                &entry.krate,
                format!("endpoint `{m}` is exported but absent from {did_rel}"),
            ));
        }
    }

    Ok(findings)
}

// ── D2 — amount-boundary census ──────────────────────────────────────────────

/// Types the traversal terminates on structurally. `Nat`/`Int` are candid's
/// arbitrary-precision types, which is precisely what rule 3 asks raw `u128`
/// to become — they are not hits.
const TERMINAL: &[&str] = &[
    "bool", "char", "str", "String", "u8", "u16", "u32", "u64", "usize", "i8", "i16", "i32", "i64",
    "isize", "f32", "f64", "Nat", "Int", "Principal", "PhantomData",
];

/// Transparent containers: no value of their own, follow the parameters.
const CONTAINERS: &[&str] = &[
    "Vec", "Option", "Box", "Rc", "Arc", "Result", "HashMap", "BTreeMap", "HashSet", "BTreeSet",
    "VecDeque", "Cow", "Reverse", "Wrapping",
];

pub struct TypeUniverse {
    /// type name → owning crate (repo-relative dir) → definitions. Keyed by
    /// OWNER, not by bare name: a bare-name map cannot tell `external::Shared`
    /// from a local `Shared`, which is SSA landed-diff F2.
    defs: BTreeMap<String, BTreeMap<String, Vec<TypeDef>>>,
    /// cargo package name (`-` normalised to `_`, i.e. as it is written in a
    /// Rust path) → crate dir. This is what makes a qualifier resolvable.
    crates: BTreeMap<String, String>,
    /// crate dir → that crate's own type definitions. The traversal's
    /// resolution context: a bare name written INSIDE `custody-types` means
    /// custody-types' definition, whatever the endpoint's own crate calls the
    /// same word.
    by_crate: BTreeMap<String, BTreeMap<String, Vec<TypeDef>>>,
}

/// The package name a Rust path would use for this crate.
fn package_ident(crate_dir: &Path) -> Result<Option<String>, String> {
    let Some(manifest) = manifest_path(crate_dir) else { return Ok(None) };
    let raw =
        std::fs::read_to_string(&manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let doc: toml::Value =
        toml::from_str(&raw).map_err(|e| format!("{}: {e}", manifest.display()))?;
    Ok(doc
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(|n| n.replace('-', "_")))
}

impl TypeUniverse {
    /// Built from EVERY crate under `canisters/`, in-scope or not: wrapper
    /// types live in library crates (`custody-types`) that expose no endpoints
    /// of their own, and a traversal that cannot see them cannot see the
    /// wrapper case rule 3 is entirely about.
    pub fn build(root: &Path) -> Result<Self, String> {
        let mut defs: BTreeMap<String, BTreeMap<String, Vec<TypeDef>>> = BTreeMap::new();
        let mut crates: BTreeMap<String, String> = BTreeMap::new();
        let mut by_crate: BTreeMap<String, BTreeMap<String, Vec<TypeDef>>> = BTreeMap::new();
        let canisters = root.join("canisters");
        let mut dirs: Vec<PathBuf> = std::fs::read_dir(&canisters)
            .map_err(|e| format!("{}: {e}", canisters.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| manifest_path(p).is_some())
            .collect();
        dirs.sort();
        for dir in dirs {
            let rel = format!("canisters/{}", dir.file_name().unwrap().to_string_lossy());
            if let Some(pkg) = package_ident(&dir)? {
                if let Some(other) = crates.insert(pkg.clone(), rel.clone()) {
                    return Err(format!(
                        "two crates claim package name `{pkg}`: {other} and {rel} — a qualified \
                         type path cannot be resolved unambiguously"
                    ));
                }
            }
            let types = scan_crate(&dir)?.types;
            for (name, list) in &types {
                defs.entry(name.clone())
                    .or_default()
                    .entry(rel.clone())
                    .or_default()
                    .extend(list.clone());
            }
            by_crate.insert(rel, types);
        }
        Ok(Self { defs, crates, by_crate })
    }
}

struct Walk<'a> {
    /// Definitions from the crate under inspection. These win for an
    /// UNQUALIFIED name: four crates define their own distinct `InitArgs`, and
    /// keying by bare name alone silently merges them — every crate's init then
    /// inherits every other crate's fields.
    ///
    /// SSA landed-diff F2: local-first is not sufficient on its own. It only
    /// decides which colliding definition wins, and when the signature says
    /// `external::Shared` it wins WRONGLY — the qualification, which is the
    /// actual type identity, was discarded. Qualified paths are now resolved
    /// against their named crate, and an unqualified name defined in more than
    /// one other crate is ambiguous and hard-fails instead of being guessed.
    /// Repo-relative dir of the crate whose namespace is currently in force.
    /// It starts as the endpoint's crate and FOLLOWS the definition site as the
    /// traversal descends: once inside a `custody-types` struct, a bare field
    /// type means custody-types' definition, not a same-named type back in the
    /// endpoint's crate. Without this, a name that is unambiguous where it is
    /// written reads as ambiguous — or, worse, resolves to the wrong crate's
    /// definition of it.
    krate: String,
    /// R2-1 (a), ruled by CTO_ADJUDICATION_MINI_QUEUE_2026-08-23 §2(a): on the
    /// RETURN side, a value carried in the error half of a `Result` is the
    /// disclosure of a public governance parameter the caller failed against
    /// (`BelowMinimumDeposit { minimum }` class) — public by design under the fee
    /// model, and not an amount boundary in C4's sense. It is a STATED RULE here,
    /// not a silent omission: the excluded population is filed as the adjudication
    /// record, and removing this flag re-surfaces all of it and REDs the gate.
    ///
    /// False on the PARAMETER side, always: an amount ENTERING through an error
    /// type would be a boundary like any other.
    exclude_result_error_side: bool,
    universe: &'a TypeUniverse,
    /// (crate, type name) pairs. The crate is the namespace IN FORCE at the point
    /// the name is met, which follows the definition site as the traversal
    /// descends — so a declaration cannot leak across crate boundaries.
    opaque: BTreeSet<(String, String)>,
    hits: Vec<String>,
    seen: BTreeSet<String>,
}

impl Walk<'_> {
    /// Is `name` declared opaque IN THE CRATE whose namespace is currently in
    /// force? Both halves must match; a same-named type in another crate is still
    /// unfollowable and still a finding.
    fn is_opaque(&self, name: &str) -> bool {
        self.opaque.contains(&(self.krate.clone(), name.to_string()))
    }

    fn ty(&mut self, prefix: &str, ty: &syn::Type) -> Result<(), String> {
        match ty {
            syn::Type::Path(p) => {
                let seg = p
                    .path
                    .segments
                    .last()
                    .ok_or_else(|| format!("{prefix}: empty type path"))?;
                let name = seg.ident.to_string();
                if name == "u128" || name == "i128" {
                    self.hits.push(format!("{prefix}: {name}"));
                    return Ok(());
                }
                if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                    if !CONTAINERS.contains(&name.as_str())
                        && !self.defs_known(&name)
                        && !self.is_opaque(&name)
                    {
                        return Err(format!(
                            "{prefix}: generic type `{name}` is neither a known container, an \
                             in-tree type, nor a declared opaque type"
                        ));
                    }
                    // R2-1 (a): walk only the Ok half of a return-side `Result`.
                    // The Err half is out of universe by the ruled checker rule
                    // (see `exclude_result_error_side`).
                    let skip_err_side = self.exclude_result_error_side && name == "Result";
                    for (i, a) in args.args.iter().enumerate() {
                        if skip_err_side && i > 0 {
                            continue;
                        }
                        if let syn::GenericArgument::Type(t) = a {
                            self.ty(prefix, t)?;
                        }
                    }
                    if CONTAINERS.contains(&name.as_str()) {
                        return Ok(());
                    }
                }
                if TERMINAL.contains(&name.as_str()) || self.is_opaque(&name) {
                    return Ok(());
                }
                if CONTAINERS.contains(&name.as_str()) {
                    return Ok(());
                }
                let (site, defs) = self.resolve(prefix, &p.path, &name)?;
                let seen_key = format!("{site}::{name}");
                if !self.seen.insert(seen_key.clone()) {
                    return Ok(()); // recursive type; already traversed
                }
                let outer = std::mem::replace(&mut self.krate, site);
                let mut result = Ok(());
                for def in &defs {
                    result = match def {
                        TypeDef::Alias(inner) => self.ty(prefix, inner),
                        TypeDef::Fields(fields) => (|| {
                            for (label, fty) in fields {
                                let next = format!("{prefix}::{name}.{label}");
                                self.ty(&next, fty)?;
                            }
                            Ok(())
                        })(),
                    };
                    if result.is_err() {
                        break;
                    }
                }
                self.krate = outer;
                self.seen.remove(&seen_key);
                result
            }
            syn::Type::Tuple(t) => {
                for (i, inner) in t.elems.iter().enumerate() {
                    self.ty(&format!("{prefix}.{i}"), inner)?;
                }
                Ok(())
            }
            syn::Type::Array(a) => self.ty(prefix, &a.elem),
            syn::Type::Slice(s) => self.ty(prefix, &s.elem),
            syn::Type::Reference(r) => self.ty(prefix, &r.elem),
            syn::Type::Paren(p) => self.ty(prefix, &p.elem),
            syn::Type::Group(g) => self.ty(prefix, &g.elem),
            other => Err(format!("{prefix}: unsupported type form `{}`", tokens(other))),
        }
    }

    /// Resolve a type path to (definition site, definitions), preserving the
    /// path's own qualification. Returns `Err` — never a guess — when identity
    /// is ambiguous or unresolvable.
    fn resolve(
        &self,
        prefix: &str,
        path: &syn::Path,
        name: &str,
    ) -> Result<(String, Vec<TypeDef>), String> {
        let quals: Vec<String> =
            path.segments.iter().rev().skip(1).rev().map(|s| s.ident.to_string()).collect();

        // A leading segment naming another crate is TYPE IDENTITY, not decoration:
        // `external::Shared` is not the local `Shared` and must not resolve to it.
        if let Some(first) = quals.first() {
            if !matches!(first.as_str(), "crate" | "self" | "super") {
                if let Some(owner) = self.universe.crates.get(first) {
                    if *owner != self.krate {
                        return match self.universe.defs.get(name).and_then(|m| m.get(owner)) {
                            Some(d) => Ok((owner.clone(), d.clone())),
                            None => Err(format!(
                                "{prefix}: qualified type `{}` names crate `{first}` but no type \
                                 `{name}` is defined there",
                                path_str(path)
                            )),
                        };
                    }
                }
            }
        }

        // Unqualified, or qualified by an intra-crate module path: the crate
        // whose namespace is in force wins, which is what makes a name that is
        // unambiguous at its own definition site stay unambiguous here.
        if let Some(d) = self.universe.by_crate.get(&self.krate).and_then(|m| m.get(name)) {
            return Ok((self.krate.clone(), d.clone()));
        }
        match self.universe.defs.get(name) {
            None => Err(format!(
                "{prefix}: cannot follow type `{name}` — no in-tree definition and no declared \
                 opaque entry"
            )),
            Some(by_crate) if by_crate.len() == 1 => {
                let (owner, defs) = by_crate.iter().next().unwrap();
                Ok((owner.clone(), defs.clone()))
            }
            Some(by_crate) => Err(format!(
                "{prefix}: type `{name}` is defined in {} crates ({}) and this signature does not \
                 say which — qualify it; an amount boundary must never rest on a guess",
                by_crate.len(),
                by_crate.keys().cloned().collect::<Vec<_>>().join(", ")
            )),
        }
    }

    fn defs_known(&self, name: &str) -> bool {
        self.universe.defs.contains_key(name)
    }
}

/// The canister keys declared in `dfx.json`, or an error. FAIL CLOSED is the whole
/// point: an unreadable or unparseable authority file must never be reported as
/// "the key is absent", which is the reading that would silently validate every
/// `launch_excluded_dfx` row.
fn dfx_canister_keys(root: &Path) -> Result<BTreeSet<String>, String> {
    let path = root.join("dfx.json");
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let json: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("{}: not valid JSON: {e}", path.display()))?;
    let canisters = json
        .get("canisters")
        .and_then(|c| c.as_object())
        .ok_or_else(|| format!("{}: no `canisters` object", path.display()))?;
    Ok(canisters.keys().cloned().collect())
}

/// The struct/enum a traversal path attributes a hit to: the segment right after
/// the `->::` return marker, e.g. `->::FeeLogEntry.audit: u128` → `FeeLogEntry`.
/// A direct `->: u128` return has no struct and is never class-rowed — those are
/// the §2(b) population, adjudicated row by row.
fn struct_of_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("->::")?;
    let name = rest.split(['.', ':']).next()?.trim();
    if name.is_empty() { None } else { Some(name.to_string()) }
}

pub fn check_amount_boundaries(
    root: &Path,
    census: &Census,
    allowlist: &Allowlist,
) -> Result<Vec<Finding>, String> {
    let universe = TypeUniverse::build(root)?;
    let opaque: BTreeSet<(String, String)> =
        allowlist.opaque.iter().map(|o| (o.krate.clone(), o.name.clone())).collect();
    let mut findings = Vec::new();
    let mut matched: BTreeSet<usize> = BTreeSet::new();
    // R2-1 (c): struct name → number of raw-amount fields actually reachable at a
    // return boundary this run. Compared against each class-row's declared count.
    let mut struct_hits: BTreeMap<String, usize> = BTreeMap::new();

    for entry in &census.canister {
        let crate_dir = root.join(&entry.krate);
        if manifest_path(&crate_dir).is_none() {
            continue;
        }
        let scan = scan_crate(&crate_dir)?;
        for ep in &scan.endpoints {
            // Init IS in D2's universe (packet §1 D2 / F6), even though it is
            // outside D1's method-name universe.
            //
            // R2-1: returns are walked on the same footing as parameters. A raw
            // amount leaving the canister is the same boundary as one entering
            // it; the direction only changes who is reading. Return-side paths
            // are labelled `->` so an allowlist row states the direction it
            // reviewed and cannot be satisfied by a same-named parameter.
            let mut surfaces: Vec<(String, &syn::Type, bool)> = ep
                .args
                .iter()
                .map(|(n, t)| (n.clone(), t, false))
                .collect();
            if let Some(ret) = &ep.ret {
                surfaces.push(("->".to_string(), ret, true));
            }
            for (arg_name, ty, is_return) in &surfaces {
                let mut walk = Walk {
                    krate: entry.krate.clone(),
                    exclude_result_error_side: *is_return,
                    universe: &universe,
                    opaque: opaque.clone(),
                    hits: Vec::new(),
                    seen: BTreeSet::new(),
                };
                if let Err(e) = walk.ty(arg_name, ty) {
                    findings.push(Finding::new(
                        "BOUNDARY-UNRESOLVED",
                        format!("{}::{}", entry.krate, ep.exported_name),
                        e,
                    ));
                    continue;
                }
                // Same path twice = the same boundary seen through two
                // definitions of one name, not two boundaries.
                let hits: BTreeSet<String> = walk.hits.into_iter().collect();
                for hit in hits {
                    // R2-1 (c): a return-side hit inside a class-rowed struct is
                    // adjudicated by that row. Counted here so the row's declared
                    // field_count can be checked against what the tree actually
                    // publishes, below.
                    if *is_return {
                        if let Some(entry) = struct_of_path(&hit)
                            .and_then(|n| allowlist.amount_struct.iter().find(|e| e.name == n))
                        {
                            *struct_hits.entry(entry.name.clone()).or_insert(0) += 1;
                            continue;
                        }
                    }
                    let allowed = allowlist.amount.iter().position(|a| {
                        a.krate == entry.krate && a.endpoint == ep.exported_name && a.path == hit
                    });
                    if let Some(i) = allowed {
                        matched.insert(i);
                    } else {
                        findings.push(Finding::new(
                            "AMOUNT-BOUNDARY",
                            format!("{}::{}", entry.krate, ep.exported_name),
                            format!(
                                "raw amount reachable at `{hit}` ({}:{}) is not on the reviewed \
                                 allowlist — STOP and refer up (C4 §4 rule 2); builders never \
                                 enrol amount boundaries",
                                ep.file.display(),
                                ep.line
                            ),
                        ));
                    }
                }
            }
        }
    }

    // R2-1 (c) THE DRIFT LOCK. A class-row that is not checked against the tree is
    // a blanket licence; the count is what keeps it a reviewed statement about a
    // known surface. Both directions are findings: MORE fields than reviewed means
    // an amount field was added without review, FEWER means the row describes a
    // surface that no longer exists in that shape.
    for entry in &allowlist.amount_struct {
        match struct_hits.get(&entry.name) {
            Some(&actual) if actual == entry.field_count => {}
            Some(&actual) => findings.push(Finding::new(
                "AMOUNT-STRUCT-DRIFT",
                entry.name.clone(),
                format!(
                    "class-row declares {} reviewed raw-amount field(s) but {actual} are \
                     reachable at a return boundary at this pin. {} — refer up; a class-row \
                     is a reviewed statement about a known surface, not a licence for \
                     whatever the struct grows into (C4 §4 rule 2)",
                    entry.field_count,
                    if actual > entry.field_count {
                        "A raw amount field was ADDED without review"
                    } else {
                        "Fields the row was reviewed against are GONE"
                    }
                ),
            )),
            None => findings.push(Finding::new(
                "AMOUNT-STRUCT-STALE",
                entry.name.clone(),
                "class-row matched no returned boundary at this pin — the struct is no \
                 longer published, was renamed, or the row was never right"
                    .to_string(),
            )),
        }
    }

    // R2-1 §2(b) D-1/L: the launch-exclusion condition, machine-checked against
    // dfx.json. Evaluated for every conditional row whether or not it matched a
    // boundary this run, because the row's validity is a claim about the install
    // set, not about the census.
    if allowlist.amount.iter().any(|a| a.launch_excluded_dfx.is_some()) {
        match dfx_canister_keys(root) {
            Ok(keys) => {
                for a in &allowlist.amount {
                    let Some(key) = &a.launch_excluded_dfx else { continue };
                    if keys.contains(key) {
                        findings.push(Finding::new(
                            "LAUNCH-EXCLUSION-BROKEN",
                            format!("{}::{}", a.krate, a.endpoint),
                            format!(
                                "this row is valid only while `{key}` is absent from dfx.json's canister set, and it is now PRESENT. The boundary it adjudicates is reachable at launch, so the row's condition no longer holds — refer up for an unconditional publication adjudication (C4 §4 rule 2); do not delete the condition"
                            ),
                        ));
                    }
                }
            }
            Err(e) => findings.push(Finding::new(
                "LAUNCH-EXCLUSION-UNREADABLE",
                "dfx.json",
                format!(
                    "{e} — conditional allowlist rows cannot be validated. This FAILS CLOSED deliberately: an unreadable install-set authority is not evidence that a canister is excluded from it"
                ),
            )),
        }
    }

    // A stale allowlist row is a silent licence for a boundary that no longer
    // exists — or worse, that moved.
    for (i, a) in allowlist.amount.iter().enumerate() {
        if !matched.contains(&i) {
            findings.push(Finding::new(
                "ALLOWLIST-STALE",
                format!("{}::{}", a.krate, a.endpoint),
                format!(
                    "allowlist row `{}` matched no boundary at this pin — the boundary moved, was \
                     removed, or the row was never right",
                    a.path
                ),
            ));
        }
    }

    Ok(findings)
}
