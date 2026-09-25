// =============================================================================
// R-1 S4(b) — the `mod ledger_maps` visibility/cfg allowlist lint.
// =============================================================================
//
// Checks a fixed, closed, LEXICAL property: which names are visible outside
// `mod ledger_maps`, and under what cfg. It does NOT check what any of them do
// (that is AC-4a/AC-5's job), and it is independent of the occurrence lint in
// `r1_ledger_boundary` (which checks occurrence COUNT, LOCATION and file
// PROVENANCE, not visibility).
//
// Two views, both computed from the same reviewed DATA file
// (`canisters/token/ledger_maps_allowlist.toml`), never from a name list
// embedded in a brief's prose:
//
//   * production view — the `cfg = "always"` rows must equal exactly the set of
//     non-private items that carry NO `#[cfg(feature = "testing")]` attribute.
//   * testing view    — the FULL TOML set must equal exactly the FULL set of
//     non-private items (both cfgs).
//
// "Item" INCLUDES associated functions, methods, associated consts and
// associated types declared in `impl` blocks (V1 RED-1, CTO triage
// `cto-triage-ssa-landed-diff-round1-2026-09-05` §2): a `pub fn` on
// `UpgradeWitness` is a reachable raw-write seam exactly as much as a free
// `pub fn` is, and the earlier `syn::Item::Impl(_) => continue` arm made it
// invisible. Two places are walked:
//
//   * `impl` blocks INSIDE `mod ledger_maps` — inherent impls contribute their
//     non-private items; TRAIT impls contribute EVERY item regardless of
//     written visibility, because a trait method's reachability follows the
//     trait, not the `fn`.
//   * `impl` blocks ANYWHERE ELSE in the file whose self type names one of the
//     module's non-private types — the same seam, moved out of the module.
//
// Rows for these are written `Type::name` (inherent) and
// `<Type as Trait>::name` (trait impl), so an allowlist row can never be
// mistaken for the free function of the same name.
//
// A COMPILE-LEVEL guard sits underneath this lint and is not replaced by it:
// `BALANCES` / `STAKING_LOCKS` / `SUM_BALANCES` / `SUM_STAKING_LOCKS` are
// default-private to `mod ledger_maps`, and — since RED-1 round 2 — so are
// `UpgradeWitness` / `GenesisWitness` THEMSELVES, not merely their tuple
// fields. The V2 lint enumerated `impl` blocks; the SSA then wrote one inside a
// FUNCTION BODY within the module and called its `pub fn` from outside through
// the still-`pub(crate)` type, and every lint stayed green. Impl-position
// enumeration cannot win that race, because Rust permits an inherent impl
// anywhere the type is nameable, including places no item walk reaches.
//
// The enforcement is therefore that the module exposes FREE FUNCTIONS ONLY: with
// no nameable type, `ledger_maps::UpgradeWitness::whatever(..)` is E0603 at the
// call site and an out-of-module `impl ledger_maps::UpgradeWitness` does not
// resolve. The impl walks below are RETAINED as review surface, and the
// non-private-type rule in `run` is the drift-lock that keeps the compile-level
// property true.
//
// Fail-closed at every step: a file it cannot parse, a cfg form it cannot
// evaluate, or a TOML row it cannot match to a real item is a hard failure
// naming the reason — never a silent pass.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AllowlistFile {
    #[serde(default)]
    item: Vec<AllowlistRow>,
}

#[derive(Debug, Deserialize)]
struct AllowlistRow {
    name: String,
    cfg: String,
}

/// `(name, cfg)` where cfg is exactly `"always"` or `"testing"`.
type ItemSet = BTreeSet<(String, String)>;

const MODULE: &str = "ledger_maps";

pub fn run(root: &Path) -> Result<(), String> {
    let src = root.join("canisters/token/src/lib.rs");
    let toml_path = root.join("canisters/token/ledger_maps_allowlist.toml");

    let text = std::fs::read_to_string(&src)
        .map_err(|e| format!("{}: cannot read: {e}", src.display()))?;
    let file = syn::parse_file(&text)
        .map_err(|e| format!("{}: cannot parse as Rust: {e}", src.display()))?;

    let module = find_module(&file.items).ok_or_else(|| {
        format!(
            "{}: `mod {MODULE} {{ … }}` not found. The R-1 write funnel must live in \
             an inline module of that exact name; without it the two maps are \
             reachable from every function in the file again.",
            src.display()
        )
    })?;

    let mut actual = collect_visible_items(module, &src)?;

    // The module's own non-private TYPE names: an `impl` block elsewhere in the
    // file can only attach a seam to one of these.
    let module_types = module_type_names(module);
    collect_outside_impls(&file.items, &module_types, &src, &mut actual)?;

    let raw = std::fs::read_to_string(&toml_path)
        .map_err(|e| format!("{}: cannot read: {e}", toml_path.display()))?;
    // `toml` rejects a duplicate key inside one table at PARSE time, which is
    // exactly the M5-(x2f) requirement: the loader must not silently keep the
    // first or last value.
    let parsed: AllowlistFile = toml::from_str(&raw)
        .map_err(|e| format!("{}: malformed allowlist TOML: {e}", toml_path.display()))?;
    if parsed.item.is_empty() {
        return Err(format!(
            "{}: allowlist is EMPTY. An empty allowlist would pass a module with no \
             visible items and fail everything else — it is never a valid state.",
            toml_path.display()
        ));
    }
    let mut allowed: ItemSet = ItemSet::new();
    for row in &parsed.item {
        if row.cfg != "always" && row.cfg != "testing" {
            return Err(format!(
                "{}: row `{}` has cfg = \"{}\"; only \"always\" and \"testing\" are \
                 defined.",
                toml_path.display(),
                row.name,
                row.cfg
            ));
        }
        if !allowed.insert((row.name.clone(), row.cfg.clone())) {
            return Err(format!(
                "{}: duplicate allowlist row for `{}` ({}).",
                toml_path.display(),
                row.name,
                row.cfg
            ));
        }
    }

    let mut findings: Vec<String> = Vec::new();

    // ── residual check: NO non-private type may leave the module ─────────────
    //
    // RED-1 round 2 (SSA_LANDED_DIFF_R-1_V2_2026-09-05.md, CTO triage
    // `cto-triage-ssa-landed-diff-round2-2026-09-05`). Enumerating `impl`
    // positions is unwinnable: Rust lets an inherent `impl` be written inside a
    // FUNCTION BODY, and its associated functions are still reachable through
    // the type from anywhere the type is nameable. The SSA demonstrated exactly
    // that against the V2 lint, and both Wasms compiled.
    //
    // So the enforcement moved into `rustc`: `mod ledger_maps` declares no
    // non-private type at all, which makes every such `impl`-seam a resolution
    // error (E0603) at the call site rather than a shape to be hunted. What
    // remains here is the DRIFT-LOCK on that property — if a type is ever
    // widened again, this fires, whether or not an allowlist row was added for
    // it and whether or not an `impl` exists yet.
    for t in &module_types {
        findings.push(format!(
            "MODULE TYPE: `{t}` is a TYPE declared in `mod {MODULE}` with a \
             visibility broader than default-private. No type may leave this \
             module: a nameable type can carry an inherent `impl` written \
             anywhere in the crate — including inside a function body, which no \
             item walk reaches — and its associated functions then reach the \
             private maps. The module exposes FREE FUNCTIONS only. Make `{t}` \
             private; do not add an allowlist row for it (a row cannot satisfy \
             this rule)."
        ));
    }

    // ── production view ──────────────────────────────────────────────────────
    let actual_always: BTreeSet<&String> = actual
        .iter()
        .filter(|(_, c)| c == "always")
        .map(|(n, _)| n)
        .collect();
    let allowed_always: BTreeSet<&String> = allowed
        .iter()
        .filter(|(_, c)| c == "always")
        .map(|(n, _)| n)
        .collect();
    for n in actual_always.difference(&allowed_always) {
        findings.push(format!(
            "PRODUCTION VIEW: `{n}` is visible outside `mod {MODULE}` in EVERY build \
             and has no `cfg = \"always\"` row in {}. Every non-private item is a \
             reachable seam and must be reviewed.",
            toml_path.display()
        ));
    }
    for n in allowed_always.difference(&actual_always) {
        findings.push(format!(
            "PRODUCTION VIEW: {} claims `{n}` (cfg = \"always\") but no such \
             non-private item exists in `mod {MODULE}` without a \
             `#[cfg(feature = \"testing\")]` attribute. Either the item was \
             removed/narrowed, or it is in fact testing-gated (the V5 RED-1 gap).",
            toml_path.display()
        ));
    }

    // ── testing view ─────────────────────────────────────────────────────────
    for (n, c) in actual.difference(&allowed) {
        findings.push(format!(
            "TESTING VIEW: `{n}` (cfg = \"{c}\") is visible outside `mod {MODULE}` \
             and has no matching row in {}.",
            toml_path.display()
        ));
    }
    for (n, c) in allowed.difference(&actual) {
        findings.push(format!(
            "TESTING VIEW: {} carries a row for `{n}` (cfg = \"{c}\") that matches no \
             item in `mod {MODULE}`.",
            toml_path.display()
        ));
    }

    if findings.is_empty() {
        println!(
            "  ledger_maps allowlist: OK — {} non-private items, both views match \
             {} rows.",
            actual.len(),
            allowed.len()
        );
        Ok(())
    } else {
        Err(findings.join("\n"))
    }
}

fn find_module(items: &[syn::Item]) -> Option<&Vec<syn::Item>> {
    for item in items {
        if let syn::Item::Mod(m) = item {
            if m.ident == MODULE {
                return m.content.as_ref().map(|(_, items)| items);
            }
        }
    }
    None
}

/// The module's DIRECT items (never a nested submodule's), reduced to
/// `(name, cfg)` for every item whose visibility is broader than default-private.
///
/// `thread_local! { … }` is an `ItemMacro` whose token stream is a sequence of
/// perfectly ordinary `static` items, so it is re-parsed and its statics are
/// treated as direct items of the module — otherwise widening `BALANCES` to
/// `pub(crate)` inside that macro would be invisible here (mutation M5-(x2a)).
fn collect_visible_items(items: &[syn::Item], src: &Path) -> Result<ItemSet, String> {
    let mut out = ItemSet::new();
    collect_into(items, src, &mut out, true)?;
    Ok(out)
}

fn collect_into(
    items: &[syn::Item],
    src: &Path,
    out: &mut ItemSet,
    allow_macro_recursion: bool,
) -> Result<(), String> {
    for item in items {
        let (name, vis, attrs): (String, &syn::Visibility, &Vec<syn::Attribute>) = match item {
            syn::Item::Fn(i) => (i.sig.ident.to_string(), &i.vis, &i.attrs),
            syn::Item::Struct(i) => (i.ident.to_string(), &i.vis, &i.attrs),
            syn::Item::Enum(i) => (i.ident.to_string(), &i.vis, &i.attrs),
            syn::Item::Const(i) => (i.ident.to_string(), &i.vis, &i.attrs),
            syn::Item::Static(i) => (i.ident.to_string(), &i.vis, &i.attrs),
            syn::Item::Type(i) => (i.ident.to_string(), &i.vis, &i.attrs),
            syn::Item::Mod(i) => (i.ident.to_string(), &i.vis, &i.attrs),
            syn::Item::Trait(i) => (i.ident.to_string(), &i.vis, &i.attrs),
            syn::Item::Union(i) => (i.ident.to_string(), &i.vis, &i.attrs),
            syn::Item::Use(i) => {
                if !matches!(i.vis, syn::Visibility::Inherited) {
                    return Err(format!(
                        "{}: `mod {MODULE}` contains a NON-PRIVATE `use` item. A \
                         re-export is a visible seam this lint cannot name by a \
                         single identifier; it is refused outright.",
                        src.display()
                    ));
                }
                continue;
            }
            syn::Item::Macro(m) => {
                if allow_macro_recursion && path_is(&m.mac.path, "thread_local") {
                    let inner = syn::parse2::<syn::File>(m.mac.tokens.clone()).map_err(|e| {
                        format!(
                            "{}: cannot re-parse `thread_local!` body inside `mod \
                             {MODULE}` as items: {e}. This lint refuses to guess.",
                            src.display()
                        )
                    })?;
                    collect_into(&inner.items, src, out, false)?;
                    continue;
                }
                return Err(format!(
                    "{}: `mod {MODULE}` contains a macro invocation this lint does not \
                     recognise (`{}`). A macro can declare items of any visibility, so \
                     an unrecognised one is a hard failure, never a pass.",
                    src.display(),
                    quote_path(&m.mac.path)
                ));
            }
            syn::Item::Impl(i) => {
                // V1 RED-1: an `impl` block inside the module is a seam carrier.
                collect_impl_items(i, src, out, None)?;
                continue;
            }
            syn::Item::Verbatim(_) => continue,
            other => {
                return Err(format!(
                    "{}: `mod {MODULE}` contains an item kind this lint does not \
                     classify ({other:?}). Fail closed.",
                    src.display()
                ))
            }
        };

        if matches!(vis, syn::Visibility::Inherited) {
            continue;
        }
        let cfg = classify_cfg(attrs, &name, src)?;
        out.insert((name, cfg));
    }
    Ok(())
}

/// The non-private TYPE names declared directly by the module. Only these can
/// carry an out-of-module `impl` seam that this lint must review.
fn module_type_names(items: &[syn::Item]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for item in items {
        let (name, vis) = match item {
            syn::Item::Struct(i) => (i.ident.to_string(), &i.vis),
            syn::Item::Enum(i) => (i.ident.to_string(), &i.vis),
            syn::Item::Union(i) => (i.ident.to_string(), &i.vis),
            syn::Item::Type(i) => (i.ident.to_string(), &i.vis),
            _ => continue,
        };
        if !matches!(vis, syn::Visibility::Inherited) {
            out.insert(name);
        }
    }
    out
}

/// The last path segment of an `impl`'s self type, or `None` when the self type
/// is not a plain path (`impl Trait for Vec<T>` and friends).
fn self_type_name(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(p) if p.qself.is_none() => {
            p.path.segments.last().map(|s| s.ident.to_string())
        }
        syn::Type::Reference(r) => self_type_name(&r.elem),
        syn::Type::Group(g) => self_type_name(&g.elem),
        syn::Type::Paren(p) => self_type_name(&p.elem),
        _ => None,
    }
}

/// Walk every `impl` block in the file that is NOT inside `mod ledger_maps`, and
/// enumerate the items of those whose self type is one of the module's own
/// non-private types.
fn collect_outside_impls(
    items: &[syn::Item],
    module_types: &BTreeSet<String>,
    src: &Path,
    out: &mut ItemSet,
) -> Result<(), String> {
    for item in items {
        match item {
            // The module itself was already walked by `collect_visible_items`.
            syn::Item::Mod(m) if m.ident == MODULE => continue,
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = m.content.as_ref() {
                    collect_outside_impls(inner, module_types, src, out)?;
                }
            }
            syn::Item::Impl(i) => {
                let Some(name) = self_type_name(&i.self_ty) else {
                    continue;
                };
                if module_types.contains(&name) {
                    collect_impl_items(i, src, out, Some(&name))?;
                }
            }
            _ => continue,
        }
    }
    Ok(())
}

/// Reduce one `impl` block to `(row name, cfg)` entries.
///
/// * inherent impl — only items whose written visibility is broader than
///   default-private are reachable, so only those are enumerated.
/// * trait impl — EVERY item is enumerated. A trait method carries no
///   visibility of its own; it is callable wherever the trait and the type are
///   in scope, so "no `pub`" is not privacy here.
///
/// `outside` names the enclosing context for the error text (`None` = the item
/// is inside `mod ledger_maps`).
fn collect_impl_items(
    node: &syn::ItemImpl,
    src: &Path,
    out: &mut ItemSet,
    outside: Option<&str>,
) -> Result<(), String> {
    let self_name = self_type_name(&node.self_ty).ok_or_else(|| {
        format!(
            "{}: `mod {MODULE}` contains an `impl` block whose self type is not a \
             plain path. This lint cannot name the seam it declares, so it refuses \
             rather than skipping it.",
            src.display()
        )
    })?;
    let trait_name = node
        .trait_
        .as_ref()
        .map(|(_, p, _)| quote_path(p));
    let is_trait_impl = trait_name.is_some();
    let prefix = match &trait_name {
        Some(t) => format!("<{self_name} as {t}>"),
        None => self_name.clone(),
    };
    let where_ = match outside {
        Some(_) => format!(
            "an `impl` block OUTSIDE `mod {MODULE}` on the module type `{self_name}`"
        ),
        None => format!("an `impl` block inside `mod {MODULE}`"),
    };

    for it in &node.items {
        let (name, vis, attrs): (String, Option<&syn::Visibility>, &Vec<syn::Attribute>) =
            match it {
                syn::ImplItem::Fn(f) => {
                    (f.sig.ident.to_string(), Some(&f.vis), &f.attrs)
                }
                syn::ImplItem::Const(c) => (c.ident.to_string(), Some(&c.vis), &c.attrs),
                syn::ImplItem::Type(t) => (t.ident.to_string(), Some(&t.vis), &t.attrs),
                other => {
                    return Err(format!(
                        "{}: {where_} contains an associated item kind this lint does \
                         not classify ({other:?}). A macro or verbatim item can declare \
                         an associated function of any visibility. Fail closed.",
                        src.display()
                    ))
                }
            };

        // Inherent impl: default-private associated items are unreachable from
        // outside the module, exactly like a private free fn.
        // Trait impl: visibility is not written on the item, so every one counts.
        if !is_trait_impl {
            match vis {
                Some(syn::Visibility::Inherited) | None => continue,
                _ => {}
            }
        }

        // A `#[cfg(feature = "testing")]` on the impl BLOCK gates every item in
        // it; either position means "testing".
        let block_cfg = classify_cfg(&node.attrs, &prefix, src)?;
        let item_cfg = classify_cfg(attrs, &name, src)?;
        let cfg = if block_cfg == "testing" || item_cfg == "testing" {
            "testing".to_string()
        } else {
            "always".to_string()
        };

        out.insert((format!("{prefix}::{name}"), cfg));
    }
    Ok(())
}

/// `"testing"` iff the item carries exactly `#[cfg(feature = "testing")]`;
/// `"always"` if it carries no `cfg` at all. ANY other `cfg` form is a hard
/// failure — this lint has no cfg evaluator and will not pretend to one.
fn classify_cfg(
    attrs: &[syn::Attribute],
    name: &str,
    src: &Path,
) -> Result<String, String> {
    let mut cfg = "always".to_string();
    for a in attrs {
        if !a.path().is_ident("cfg") {
            continue;
        }
        let tokens = a.meta.require_list().map(|l| l.tokens.to_string());
        match tokens.as_deref() {
            Ok("feature = \"testing\"") => cfg = "testing".to_string(),
            other => {
                return Err(format!(
                    "{}: item `{name}` in `mod {MODULE}` carries a `cfg` this lint \
                     cannot evaluate: {other:?}. Only `#[cfg(feature = \"testing\")]` \
                     is defined here; anything else is a hard failure.",
                    src.display()
                ))
            }
        }
    }
    Ok(cfg)
}

fn path_is(p: &syn::Path, name: &str) -> bool {
    p.segments.len() == 1 && p.segments[0].ident == name
}

fn quote_path(p: &syn::Path) -> String {
    p.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}
