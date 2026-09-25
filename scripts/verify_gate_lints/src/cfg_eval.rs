//! A real Boolean cfg-predicate evaluator (brief §3 S2, invariants 10/13).
//!
//! NOT an atom-presence search, NOT a substring match, NOT a line-proximity
//! heuristic. Each `#[cfg(...)]` argument is parsed into a predicate tree over
//! `not` / `all` / `any` with leaf atoms `test`, `feature = "…"`, and
//! `target_* = "…"`, and evaluated against a named environment.
//!
//! An atom the vocabulary does not cover is a HARD ERROR (exit 2) naming the
//! file:line and the offending fragment verbatim — never a silent `false`,
//! never a silent `true`, never a skip. (Brief §0 ruling 4, extended to the
//! target family by V12 and re-scoped to rustc's real key set by the
//! 2026-09-05 ruling addendum.)

use std::collections::BTreeSet;
use syn::{Attribute, Expr, Lit, Meta, MetaNameValue};

use crate::target_cfg::TargetAtoms;

/// A hard error. The caller prints it and exits 2.
#[derive(Debug, Clone)]
pub struct CfgError {
    pub file: String,
    pub line: usize,
    pub fragment: String,
    pub reason: String,
}

impl std::fmt::Display for CfgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: {} — offending fragment: `{}`",
            self.file, self.line, self.reason, self.fragment
        )
    }
}

/// The environment a predicate is evaluated against.
///
/// `features` is ALWAYS a computed value — the crate's resolved `default`
/// closure (see [`crate::features`]) — never a hardcoded literal, not even a
/// hardcoded empty one (invariant 11). `target` is ALWAYS rustc's printed atom
/// set for the production triple (invariant 13, as amended).
#[derive(Clone, Debug)]
pub struct Env {
    pub test: bool,
    pub features: BTreeSet<String>,
    pub target: TargetAtoms,
}

impl Env {
    /// Production view for a crate: `test = false`, features = the crate's own
    /// resolved `default` closure, target = rustc's atoms for wasm32.
    pub fn production(features: BTreeSet<String>, target: TargetAtoms) -> Self {
        Env { test: false, features, target }
    }

    /// Testing view: production, with `feature("testing")` forced true, and
    /// NOTHING ELSE CHANGED.
    ///
    /// `test` stays FALSE here, and that is deliberate. The testing view names
    /// the `--features testing` Wasm — the nine `*_test.wasm` binaries
    /// `run_gate.sh` builds in phase 1 (ARCHITECTURE.md law 7). `cargo build
    /// --features testing` does NOT set `cfg(test)`; only a `cargo test` unit
    /// build does, and that build produces no Wasm at all. So a
    /// `#[cfg(test)] #[update]` item ships in NEITHER Wasm and belongs in
    /// NEITHER view.
    ///
    /// BRIEF DEFECT, recorded rather than silently resolved. Brief V12's
    /// AC-2c states two mutations that cannot both hold: M2c-2
    /// (`#[cfg(test)] #[update]`) requires the testing view to GROW, which
    /// needs `test = true`; M2c-6 (`#[cfg(all(feature = "testing",
    /// not(test)))]`) requires the testing view to grow too, which needs
    /// `test = false`. Under `test = true` M2c-6 fails; under `test = false`
    /// M2c-2 and M2c-3 report (0, 0) instead of (+1, 0). `test = false` is the
    /// model that matches what the two views actually MEAN, and it reproduces
    /// the brief's own §2 per-crate table exactly (165 / 80), because zero base
    /// sites are excluded by `cfg(test)` in either model. The packet records
    /// M2c-2/M2c-3's corrected expectation as a brief-side counting defect of
    /// the same class as V5–V11's.
    pub fn testing(mut features: BTreeSet<String>, target: TargetAtoms) -> Self {
        features.insert("testing".to_string());
        Env { test: false, features, target }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pred {
    Test,
    Feature(String),
    Target { key: String, value: String },
    Not(Box<Pred>),
    All(Vec<Pred>),
    Any(Vec<Pred>),
}

impl Pred {
    pub fn eval(&self, env: &Env) -> bool {
        match self {
            Pred::Test => env.test,
            Pred::Feature(name) => env.features.contains(name),
            Pred::Target { key, value } => env.target.matches(key, value),
            Pred::Not(inner) => !inner.eval(env),
            Pred::All(children) => children.iter().all(|c| c.eval(env)),
            Pred::Any(children) => children.iter().any(|c| c.eval(env)),
        }
    }
}

/// Parse one `#[cfg(...)]` attribute's argument into a predicate tree.
/// Returns `Ok(None)` for an attribute that is not `cfg` at all.
pub fn parse_cfg_attr(
    attr: &Attribute,
    file: &str,
    target: &TargetAtoms,
) -> Result<Option<Pred>, CfgError> {
    if !attr.path().is_ident("cfg") {
        return Ok(None);
    }
    let line = attr.pound_token.spans[0].start().line;
    // `#[cfg(...)]` is a list-form meta; anything else is malformed.
    let list = match &attr.meta {
        Meta::List(list) => list,
        other => {
            return Err(CfgError {
                file: file.to_string(),
                line,
                fragment: quote::quote!(#other).to_string(),
                reason: "malformed cfg attribute (expected `cfg(<predicate>)`)".into(),
            })
        }
    };
    let inner: Meta = list
        .parse_args::<Meta>()
        .map_err(|e| CfgError {
            file: file.to_string(),
            line,
            fragment: list.tokens.to_string(),
            reason: format!("could not parse cfg predicate: {e}"),
        })?;
    Ok(Some(parse_meta(&inner, file, line, target)?))
}

fn parse_meta(
    meta: &Meta,
    file: &str,
    line: usize,
    target: &TargetAtoms,
) -> Result<Pred, CfgError> {
    let err = |fragment: String, reason: String| CfgError {
        file: file.to_string(),
        line,
        fragment,
        reason,
    };
    match meta {
        // Bare path atom: only `test` is in the vocabulary. `debug_assertions`,
        // `unix`, a build-script-emitted custom cfg, etc. are hard errors — the
        // brief's §3 OUT says extending the vocabulary is a follow-on change,
        // never a silent pass-through.
        Meta::Path(path) => {
            if path.is_ident("test") {
                Ok(Pred::Test)
            } else {
                Err(err(
                    quote::quote!(#path).to_string().replace(' ', ""),
                    "unrecognised cfg atom (vocabulary is `test`, `feature = \"…\"`, \
                     and the `target_*` keys rustc prints for wasm32-unknown-unknown)"
                        .into(),
                ))
            }
        }
        Meta::NameValue(MetaNameValue { path, value, .. }) => {
            let key = path
                .get_ident()
                .map(|i| i.to_string())
                .unwrap_or_else(|| quote::quote!(#path).to_string().replace(' ', ""));
            let lit = match value {
                Expr::Lit(expr_lit) => match &expr_lit.lit {
                    Lit::Str(s) => s.value(),
                    other => {
                        return Err(err(
                            format!("{key} = {}", quote::quote!(#other)),
                            "cfg name/value literal must be a string".into(),
                        ))
                    }
                },
                other => {
                    return Err(err(
                        format!("{key} = {}", quote::quote!(#other)),
                        "cfg name/value must be a literal".into(),
                    ))
                }
            };
            if key == "feature" {
                return Ok(Pred::Feature(lit));
            }
            if key.starts_with("target_") {
                // The ruling addendum: the key set is rustc's, not a table in
                // this file. A `target_*` key rustc did not print (e.g.
                // `target_frobnicate`) is a hard error, exit 2.
                if !target.knows(&key) {
                    return Err(err(
                        key.clone(),
                        format!(
                            "unknown target cfg key `{key}` — not printed by \
                             `rustc --print cfg --target {}`",
                            crate::target_cfg::PRODUCTION_TARGET
                        ),
                    ));
                }
                return Ok(Pred::Target { key, value: lit });
            }
            Err(err(
                format!("{key} = \"{lit}\""),
                "unrecognised cfg atom (vocabulary is `test`, `feature = \"…\"`, \
                 and the `target_*` keys rustc prints for wasm32-unknown-unknown)"
                    .into(),
            ))
        }
        Meta::List(list) => {
            let head = list
                .path
                .get_ident()
                .map(|i| i.to_string())
                .unwrap_or_default();
            let children = list
                .parse_args_with(
                    syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
                )
                .map_err(|e| {
                    err(
                        list.tokens.to_string(),
                        format!("could not parse `{head}(...)` arguments: {e}"),
                    )
                })?;
            let mut parsed = Vec::new();
            for child in children.iter() {
                parsed.push(parse_meta(child, file, line, target)?);
            }
            match head.as_str() {
                "not" => {
                    if parsed.len() != 1 {
                        return Err(err(
                            list.tokens.to_string(),
                            format!("`not(...)` takes exactly one child, got {}", parsed.len()),
                        ));
                    }
                    Ok(Pred::Not(Box::new(parsed.pop().expect("len checked"))))
                }
                "all" => {
                    if parsed.is_empty() {
                        return Err(err(list.tokens.to_string(), "`all()` needs ≥1 child".into()));
                    }
                    Ok(Pred::All(parsed))
                }
                "any" => {
                    if parsed.is_empty() {
                        return Err(err(list.tokens.to_string(), "`any()` needs ≥1 child".into()));
                    }
                    Ok(Pred::Any(parsed))
                }
                other => Err(err(
                    quote::quote!(#list).to_string(),
                    format!("unrecognised cfg combinator `{other}` (expected not/all/any)"),
                )),
            }
        }
    }
}

/// Effective inclusion: the conjunction of every predicate in scope (the item's
/// own cfg attributes AND every enclosing module's), evaluated under `env`.
pub fn effective(preds: &[Pred], env: &Env) -> bool {
    preds.iter().all(|p| p.eval(env))
}
