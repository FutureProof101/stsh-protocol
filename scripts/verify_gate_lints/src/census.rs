//! The `#[update]` census — one `syn` walk, two views (brief §2, §3 S2).
//!
//! The SAME walk produces the production view, the testing view, and the
//! marker-obligation corpus that `refused-ceilings` consults, so the reported
//! census and the obligation set are provably the same set and can never drift
//! into two commands that disagree (brief §3 S2, path 2).
//!
//! The cfg skip rule is STRUCTURAL: an item is in a view iff the conjunction of
//! its own cfg predicates and every ENCLOSING module's cfg predicates evaluates
//! true under that view's environment. Never a fixed line-count look-back,
//! never any other proximity heuristic (invariant 9).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use syn::{Item, ItemFn, ItemMod};

use crate::cfg_eval::{effective, parse_cfg_attr, CfgError, Env, Pred};
use crate::features;
use crate::target_cfg::TargetAtoms;

/// The recognised `#[update]` attribute spellings (brief §2). This is a NET
/// over these spellings, not a completeness proof over all possible macro
/// spellings — the `.did` cross-check is what closes the name-based gap.
const UPDATE_PATHS: &[&[&str]] = &[
    &["update"],
    &["ic_cdk_macros", "update"],
    &["ic_cdk", "update"],
];

#[derive(Debug, Clone)]
pub struct UpdateSite {
    pub crate_name: String,
    pub file: PathBuf,
    pub line: usize,
    pub fn_name: String,
    /// The full text of the function, for the structural guard-shape walk.
    pub body_tokens: String,
    /// Comment markers found on the lines immediately preceding the attribute
    /// block, extracted textually — a `// RATE-LIMITED` / `// FLOOR-GUARDED`
    /// comment is not part of the AST, so this is the one deliberately textual
    /// input, and it is only ever used to ADD an obligation, never to remove one.
    pub markers: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Census {
    pub production: Vec<UpdateSite>,
    pub testing: Vec<UpdateSite>,
    /// Every non-`#[update]` fn, keyed by name, for the depth-≤3 call-graph walk.
    pub helpers: BTreeMap<String, String>,
}

impl Census {
    pub fn production_names(&self) -> BTreeSet<String> {
        self.production.iter().map(|s| s.fn_name.clone()).collect()
    }
    pub fn testing_names(&self) -> BTreeSet<String> {
        self.testing.iter().map(|s| s.fn_name.clone()).collect()
    }
}

#[derive(Debug)]
pub enum CensusError {
    Cfg(CfgError),
    Feature(features::FeatureError),
    Io(String),
    Syn(String),
}

impl std::fmt::Display for CensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CensusError::Cfg(e) => write!(f, "{e}"),
            CensusError::Feature(e) => write!(f, "{e}"),
            CensusError::Io(m) | CensusError::Syn(m) => write!(f, "{m}"),
        }
    }
}

fn attr_is_update(attr: &syn::Attribute) -> bool {
    let segs: Vec<String> = attr
        .path()
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    UPDATE_PATHS.iter().any(|want| {
        want.len() == segs.len() && want.iter().zip(segs.iter()).all(|(a, b)| *a == b.as_str())
    })
}

/// Collect the `// RATE-LIMITED` / `// FLOOR-GUARDED` markers attached to the
/// item starting at `line` — scanning upwards through the contiguous run of
/// comment/attribute lines immediately above it.
fn markers_above(lines: &[&str], line: usize) -> Vec<String> {
    let mut found = Vec::new();
    let mut i = line.saturating_sub(1); // 1-based -> 0-based, then step up
    while i > 0 {
        i -= 1;
        let t = lines[i].trim();
        if t.is_empty() || t.starts_with("#[") || t.starts_with("//") || t.starts_with("///") {
            for m in ["RATE-LIMITED", "FLOOR-GUARDED"] {
                if t.starts_with("//") && t.contains(m) {
                    found.push(m.to_string());
                }
            }
            continue;
        }
        break;
    }
    found
}

struct WalkCtx<'a> {
    crate_name: &'a str,
    file: &'a Path,
    file_rel: String,
    lines: Vec<&'a str>,
    target: &'a TargetAtoms,
}

#[allow(clippy::too_many_arguments)]
fn walk_items(
    items: &[Item],
    inherited: &[Pred],
    ctx: &WalkCtx<'_>,
    prod: &Env,
    test: &Env,
    census: &mut Census,
    external_mods: &mut Vec<(String, Vec<Pred>)>,
) -> Result<(), CensusError> {
    for item in items {
        let attrs: &[syn::Attribute] = match item {
            Item::Fn(f) => &f.attrs,
            Item::Mod(m) => &m.attrs,
            Item::Impl(i) => &i.attrs,
            Item::Struct(s) => &s.attrs,
            Item::Enum(e) => &e.attrs,
            Item::Const(c) => &c.attrs,
            Item::Static(s) => &s.attrs,
            Item::Use(u) => &u.attrs,
            Item::Type(t) => &t.attrs,
            Item::Trait(t) => &t.attrs,
            Item::Macro(m) => &m.attrs,
            _ => &[],
        };
        let mut here = inherited.to_vec();
        for attr in attrs {
            if let Some(p) = parse_cfg_attr(attr, &ctx.file_rel, ctx.target).map_err(CensusError::Cfg)? {
                here.push(p);
            }
        }
        match item {
            Item::Fn(f) => record_fn(f, &here, ctx, prod, test, census),
            Item::Mod(m) => {
                let ItemMod { content, semi, ident, .. } = m;
                if let Some((_, inner)) = content {
                    walk_items(inner, &here, ctx, prod, test, census, external_mods)?;
                } else if semi.is_some() {
                    // `mod x;` — the module body lives in another file, and this
                    // declaration's cfg attributes govern it. Record so the
                    // caller can propagate; without this an entire file's items
                    // would be evaluated with no inherited predicate at all.
                    external_mods.push((ident.to_string(), here.clone()));
                }
            }
            Item::Impl(i) => {
                for ii in &i.items {
                    if let syn::ImplItem::Fn(m) = ii {
                        let mut inner = here.clone();
                        for attr in &m.attrs {
                            if let Some(p) =
                                parse_cfg_attr(attr, &ctx.file_rel, ctx.target).map_err(CensusError::Cfg)?
                            {
                                inner.push(p);
                            }
                        }
                        record_impl_fn(m, &inner, ctx, prod, test, census);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn site_of(
    name: String,
    line: usize,
    tokens: String,
    ctx: &WalkCtx<'_>,
) -> UpdateSite {
    UpdateSite {
        crate_name: ctx.crate_name.to_string(),
        file: ctx.file.to_path_buf(),
        line,
        fn_name: name,
        body_tokens: tokens,
        markers: markers_above(&ctx.lines, line),
    }
}

fn record_fn(
    f: &ItemFn,
    preds: &[Pred],
    ctx: &WalkCtx<'_>,
    prod: &Env,
    test: &Env,
    census: &mut Census,
) {
    let name = f.sig.ident.to_string();
    // Doc attributes are STRIPPED before rendering: the structural guard walk
    // must read executable code, never prose. A doc comment that merely says
    // "rate-limited" is not a guard, and treating it as one was exactly the
    // false-positive class this strip closes.
    let tokens = {
        let mut f = f.clone();
        f.attrs.retain(|a| !a.path().is_ident("doc"));
        crate::scope::strip_doc_attrs_fn(&mut f);
        quote::quote!(#f).to_string()
    };
    if f.attrs.iter().any(attr_is_update) {
        let line = f.sig.fn_token.span.start().line;
        let site = site_of(name, line, tokens, ctx);
        if effective(preds, prod) {
            census.production.push(site.clone());
        }
        if effective(preds, test) {
            census.testing.push(site);
        }
    } else {
        census.helpers.insert(name, tokens);
    }
}

fn record_impl_fn(
    m: &syn::ImplItemFn,
    preds: &[Pred],
    ctx: &WalkCtx<'_>,
    prod: &Env,
    test: &Env,
    census: &mut Census,
) {
    let name = m.sig.ident.to_string();
    let tokens = {
        let mut m = m.clone();
        m.attrs.retain(|a| !a.path().is_ident("doc"));
        crate::scope::strip_doc_attrs_impl_fn(&mut m);
        quote::quote!(#m).to_string()
    };
    if m.attrs.iter().any(attr_is_update) {
        let line = m.sig.fn_token.span.start().line;
        let site = site_of(name, line, tokens, ctx);
        if effective(preds, prod) {
            census.production.push(site.clone());
        }
        if effective(preds, test) {
            census.testing.push(site);
        }
    } else {
        census.helpers.insert(name, tokens);
    }
}

/// Every `.rs` file under `dir`, sorted for deterministic output.
pub fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The canister crates: every directory under `canisters/` with a `Cargo.toml`.
/// Derived from the tree, never a hardcoded list, so a new crate is picked up
/// automatically rather than silently omitted.
pub fn canister_crates(root: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root.join("canisters")) else { return out };
    for e in rd.flatten() {
        let p = e.path();
        if p.join("Cargo.toml").is_file() {
            out.push((
                p.file_name().unwrap().to_string_lossy().to_string(),
                p,
            ));
        }
    }
    out.sort();
    out
}

/// Census one crate.
pub fn census_crate(
    crate_name: &str,
    crate_dir: &Path,
    root: &Path,
    target: &TargetAtoms,
) -> Result<Census, CensusError> {
    let manifest = crate_dir.join("Cargo.toml");
    let feats = features::production_features(crate_name, &manifest).map_err(CensusError::Feature)?;
    let prod = Env::production(feats.clone(), target.clone());
    let test = Env::testing(feats, target.clone());

    let src = crate_dir.join("src");
    let mut census = Census::default();
    // Two passes: the first learns each external module declaration's cfg
    // predicates, the second evaluates each file's items under the predicates
    // its own `mod x;` declaration carries.
    let files = rust_files(&src);
    let mut mod_preds: BTreeMap<PathBuf, Vec<Pred>> = BTreeMap::new();
    for file in &files {
        let text = std::fs::read_to_string(file)
            .map_err(|e| CensusError::Io(format!("{}: {e}", file.display())))?;
        let ast = syn::parse_file(&text)
            .map_err(|e| CensusError::Syn(format!("{}: {e}", file.display())))?;
        let rel = file.strip_prefix(root).unwrap_or(file).display().to_string();
        let lines: Vec<&str> = text.lines().collect();
        let ctx = WalkCtx { crate_name, file, file_rel: rel, lines, target };
        let mut external = Vec::new();
        let mut throwaway = Census::default();
        walk_items(&ast.items, &[], &ctx, &prod, &test, &mut throwaway, &mut external)?;
        let parent = file.parent().unwrap();
        let stem = file.file_stem().unwrap().to_string_lossy().to_string();
        for (name, preds) in external {
            if preds.is_empty() {
                continue;
            }
            let base = if stem == "lib" || stem == "main" || stem == "mod" {
                parent.to_path_buf()
            } else {
                parent.join(&stem)
            };
            for cand in [base.join(format!("{name}.rs")), base.join(&name).join("mod.rs")] {
                if cand.is_file() {
                    mod_preds.entry(cand).or_default().extend(preds.clone());
                }
            }
        }
    }
    for file in &files {
        let text = std::fs::read_to_string(file)
            .map_err(|e| CensusError::Io(format!("{}: {e}", file.display())))?;
        let ast = syn::parse_file(&text)
            .map_err(|e| CensusError::Syn(format!("{}: {e}", file.display())))?;
        let rel = file.strip_prefix(root).unwrap_or(file).display().to_string();
        let lines: Vec<&str> = text.lines().collect();
        let ctx = WalkCtx { crate_name, file, file_rel: rel, lines, target };
        let inherited = mod_preds.get(file).cloned().unwrap_or_default();
        let mut external = Vec::new();
        walk_items(&ast.items, &inherited, &ctx, &prod, &test, &mut census, &mut external)?;
    }
    Ok(census)
}
