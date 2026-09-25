// =============================================================================
// R-1 S4(b2) + S4(b3-belt) — the caller-boundary occurrence lint and the
// identifier-synthesizing-macro name belt, over rustc's OWN file census.
// =============================================================================
//
// THE CENSUS IS NOT AN ENUMERATION THIS LINT WROTE. It is cargo/rustc's dep-info
// `.d` record of every source file rustc read to build `stsh_token`. That is the
// whole point of V10: `lib.rs`-only scanning missed `include!`; a directory walk
// missed `#[path]`; the answer is not a fourth ban but reading what the compiler
// itself reported. Consequently there is no Rust language feature through which
// source can reach the compiler without also appearing here.
//
// A MISSING `.d` IS A HARD FAILURE, never a skip and never a fallback to a
// weaker census (exit code 3, distinct from a finding's exit code 1).
//
// Three categorical bans (`include!`, a `build.rs` in the token crate, and a
// `#[path]` whose target resolves outside `canisters/token/`) run FIRST. They are
// DEFENCE IN DEPTH, not the completeness mechanism: with any of them disabled the
// census still contains the widened file, and Layers 1/2 still fire.
//
// Layer 1 (AST): `syn::ItemFn` definitions, every `syn::Path`'s last segment, and
// every name a `syn::UseTree` introduces (`Rename` resolves to the renamed-FROM
// identifier). Catches direct calls, `use … as` aliases, and function-item
// bindings.
//
// Layer 2 (TOKEN): every `syn::Macro` node — invocations AND `macro_rules!`
// definitions — scanned as raw tokens, recursing into `Group`s. This layer never
// resolves anything, so `syn`'s inability to expand macros stops mattering.
//
// The belt (b3-belt) reuses the same census and bans, by name, any `use`,
// `extern crate`, macro-invocation path, or `macro_rules!` body naming a crate on
// `identifier_synthesizing_macro_denylist.toml`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use proc_macro2::TokenTree;
use serde::Deserialize;
use syn::spanned::Spanned;
use syn::visit::Visit;

/// The four identifiers whose one-legitimate-caller property this lint enforces.
pub const TRACKED: [(&str, &str); 4] = [
    ("restore_from_checkpoint", "post_upgrade"),
    ("witness_for_post_upgrade", "restore_from_checkpoint"),
    ("seed_at_genesis", "init"),
    ("witness_for_init", "seed_at_genesis"),
];

/// Distinct exit code for "the compiler's own record is absent" (AC-7l). It is
/// deliberately NOT 1: a missing input is not a finding.
pub const EXIT_NO_DEPINFO: u8 = 3;

pub struct Options {
    /// AC-7j M7m what-if: disable the `include!` ban only.
    pub disable_include_ban: bool,
    /// AC-7k M7p what-if: disable the `#[path]` ban only.
    pub disable_path_ban: bool,
    /// AC-7o M-compile-fail what-if: disable the (b3-belt) name scan only.
    pub disable_belt: bool,
    /// AC-7i demonstration: report Layer-1 counts only, to show Layer 1 alone
    /// would stay GREEN at exactly the count that looks correct.
    pub ast_layer_only: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            disable_include_ban: false,
            disable_path_ban: false,
            disable_belt: false,
            ast_layer_only: false,
        }
    }
}

#[derive(Debug, Deserialize)]
struct DenylistFile {
    #[serde(default)]
    name: Vec<DenylistRow>,
}

#[derive(Debug, Deserialize)]
struct DenylistRow {
    value: String,
}

/// `Err(msg)` is a finding (exit 1). `Err` with the sentinel prefix below is the
/// missing-`.d` hard failure (exit 3) — the caller maps it.
pub const NO_DEPINFO_SENTINEL: &str = "R1-NO-DEPINFO\n";

pub fn run(root: &Path, opts: &Options) -> Result<(), String> {
    let census = resolve_census(root)?;
    if census.is_empty() {
        return Err(format!(
            "{NO_DEPINFO_SENTINEL}stsh_token's dep-info file lists no source files. \
             Refusing to run over an empty census."
        ));
    }

    let mut findings: Vec<String> = Vec::new();
    let mut parsed: Vec<(PathBuf, syn::File)> = Vec::new();
    for p in &census {
        let text = std::fs::read_to_string(p)
            .map_err(|e| format!("{}: census member cannot be read: {e}", p.display()))?;
        let f = syn::parse_file(&text)
            .map_err(|e| format!("{}: census member cannot be parsed as Rust: {e}", p.display()))?;
        parsed.push((p.clone(), f));
    }

    // ── step 0: the three categorical bans (defence in depth) ────────────────
    let token_dir = root.join("canisters/token");
    if token_dir.join("build.rs").exists() {
        findings.push(format!(
            "BAN(build.rs): {} exists. A build script that writes source the crate \
             then compiles is banned outright in this crate — its output would be an \
             ungoverned member of the census.",
            token_dir.join("build.rs").display()
        ));
    }
    for (path, file) in &parsed {
        if !opts.disable_include_ban {
            let mut v = IncludeBanVisitor { hits: Vec::new() };
            v.visit_file(file);
            for span in v.hits {
                findings.push(format!(
                    "BAN(include!): {}:{}:{} — `include!` pulls a second file's source \
                     into this crate. Banned unconditionally at any visibility, any \
                     cfg, any position. (`include_str!`/`include_bytes!` are data, not \
                     source, and are NOT flagged.)",
                    path.display(),
                    span.0,
                    span.1
                ));
            }
        }
        if !opts.disable_path_ban {
            for (name, target, line, col) in path_attr_modules(file) {
                let base = path.parent().unwrap_or(Path::new("."));
                let resolved = normalize(&base.join(&target));
                if !resolved.starts_with(&token_dir) {
                    findings.push(format!(
                        "BAN(#[path] outside the crate): {}:{line}:{col} — `mod {name}` \
                         compiles {} , which resolves OUTSIDE {}. The attribute's \
                         presence with an out-of-crate target IS the violation.",
                        path.display(),
                        resolved.display(),
                        token_dir.display()
                    ));
                }
            }
        }
    }

    // ── the belt (b3-belt) ───────────────────────────────────────────────────
    if !opts.disable_belt {
        let denylist = load_denylist(root)?;
        for (path, file) in &parsed {
            let mut v = BeltVisitor {
                deny: &denylist,
                hits: Vec::new(),
            };
            v.visit_file(file);
            for (kind, name, line, col) in v.hits {
                findings.push(format!(
                    "BELT({kind}): {}:{line}:{col} — names the identifier-synthesizing \
                     macro crate `{name}`. A crate that assembles NEW identifiers from \
                     fragments defeats the token layer by construction, so naming it \
                     from token source is refused regardless of what either proc-macro \
                     allowlist contains and regardless of the local alias, if any.",
                    path.display()
                ));
            }
        }
    }

    // ── steps 1-5: the occurrence walk ───────────────────────────────────────
    let mut fn_spans: Vec<(String, PathBuf, (usize, usize), (usize, usize))> = Vec::new();
    for (path, file) in &parsed {
        let mut v = FnSpanVisitor { out: Vec::new() };
        v.visit_file(file);
        for (name, s, e) in v.out {
            fn_spans.push((name, path.clone(), s, e));
        }
    }
    for required in ["post_upgrade", "init", "restore_from_checkpoint", "seed_at_genesis"] {
        if !fn_spans.iter().any(|(n, ..)| n == required) {
            return Err(format!(
                "`fn {required}` was not found anywhere in stsh_token's dep-info census \
                 ({} files). The occurrence lint cannot bind a caller boundary to a \
                 function it cannot locate.",
                census.len()
            ));
        }
    }

    for (ident, required_fn) in TRACKED {
        let mut occurrences: Vec<Occurrence> = Vec::new();
        for (path, file) in &parsed {
            let mut v = OccurrenceVisitor {
                ident,
                ast_only: opts.ast_layer_only,
                out: Vec::new(),
            };
            v.visit_file(file);
            for mut o in v.out {
                o.file = path.clone();
                occurrences.push(o);
            }
        }
        let defs = occurrences.iter().filter(|o| o.is_definition).count();
        let total = occurrences.len();
        if total != 2 {
            findings.push(format!(
                "OCCURRENCE(`{ident}`): expected exactly 2 occurrences across the \
                 census (its own `fn` definition + one use inside `fn {required_fn}`), \
                 found {total} ({defs} definition(s)):\n{}",
                render(&occurrences)
            ));
            continue;
        }
        if defs != 1 {
            findings.push(format!(
                "OCCURRENCE(`{ident}`): found {defs} definitions; exactly one is \
                 required:\n{}",
                render(&occurrences)
            ));
            continue;
        }
        let use_site = occurrences.iter().find(|o| !o.is_definition).unwrap();
        if use_site.always_out_of_bounds {
            findings.push(format!(
                "OCCURRENCE(`{ident}`): the single non-definition occurrence is inside \
                 a `macro_rules!` DEFINITION, which can never be \"inside\" one \
                 legitimate caller — its body is emitted fresh at every future \
                 expansion site, none of which this lint can predict:\n{}",
                render(&occurrences)
            ));
            continue;
        }
        let inside = fn_spans.iter().any(|(n, p, s, e)| {
            n == required_fn && *p == use_site.file && within(*s, *e, use_site.start)
        });
        if !inside {
            findings.push(format!(
                "OCCURRENCE(`{ident}`): the count is 2, but the non-definition \
                 occurrence is NOT lexically inside `fn {required_fn}`'s body. A \
                 same-count relocation is still a boundary violation:\n{}",
                render(&occurrences)
            ));
        }
    }

    if findings.is_empty() {
        println!(
            "  ledger boundary: OK — census {} file(s) from rustc's own dep-info; \
             4 tracked identifiers at exactly 2 occurrences each; 3 bans clean; belt \
             clean.",
            census.len()
        );
        Ok(())
    } else {
        Err(findings.join("\n"))
    }
}

// ── census ───────────────────────────────────────────────────────────────────

/// Locate `stsh_token`'s newest `.d` under the wasm32 release deps directory and
/// union every right-hand-side path across all of its lines.
pub fn resolve_census(root: &Path) -> Result<Vec<PathBuf>, String> {
    let deps = root.join("target/wasm32-unknown-unknown/release/deps");
    // cargo names a cdylib's dep-info `stsh_token.d` and an rlib/bin's
    // `stsh_token-<fingerprint>.d`; both shapes are accepted, newest wins.
    let glob = format!("{}/stsh_token.d and {}/stsh_token-*.d", deps.display(), deps.display());
    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&deps) {
        for e in rd.flatten() {
            let p = e.path();
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if (name == "stsh_token.d" || name.starts_with("stsh_token-"))
                && name.ends_with(".d")
            {
                let mtime = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                candidates.push((mtime, p));
            }
        }
    }
    if candidates.is_empty() {
        return Err(format!(
            "{NO_DEPINFO_SENTINEL}stsh_token's dep-info file is MISSING.\n  \
             searched: {glob}\n  \
             produce it with:\n    \
             cargo build --target wasm32-unknown-unknown --release -p stsh_token --locked\n  \
             This lint does NOT fall back to a directory walk or any other weaker \
             census, and does NOT report \"0 findings\": without the compiler's own \
             record of what it compiled, the completeness claim this lint makes is \
             simply not available."
        ));
    }
    candidates.sort_by_key(|(t, _)| *t);
    let (_, newest) = candidates.last().unwrap().clone();

    let text = std::fs::read_to_string(&newest)
        .map_err(|e| format!("{}: cannot read dep-info: {e}", newest.display()))?;
    let mut out: BTreeSet<PathBuf> = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(rhs) = split_after_target(line) else {
            continue;
        };
        for raw in split_unescaped_spaces(rhs) {
            if raw.is_empty() {
                continue;
            }
            let p = PathBuf::from(&raw);
            let p = if p.is_absolute() { p } else { root.join(p) };
            let p = normalize(&p);
            if p.extension().and_then(|e| e.to_str()) == Some("rs") && p.exists() {
                out.insert(p);
            }
        }
    }
    Ok(out.into_iter().collect())
}

/// Split a dep-info line at its first UNESCAPED `:` — a Windows-style drive
/// letter or an escaped colon inside a path must not split it.
fn split_after_target(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b':' {
            return Some(line[i + 1..].trim_start());
        }
        i += 1;
    }
    None
}

fn split_unescaped_spaces(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            ' ' | '\t' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

// ── denylist ─────────────────────────────────────────────────────────────────

pub fn load_denylist(root: &Path) -> Result<BTreeSet<String>, String> {
    let p = root.join("canisters/token/identifier_synthesizing_macro_denylist.toml");
    let raw = std::fs::read_to_string(&p)
        .map_err(|e| format!("{}: cannot read denylist: {e}", p.display()))?;
    let parsed: DenylistFile = toml::from_str(&raw)
        .map_err(|e| format!("{}: malformed denylist TOML: {e}", p.display()))?;
    if parsed.name.is_empty() {
        return Err(format!("{}: denylist is EMPTY — refusing to run a belt with nothing in it.", p.display()));
    }
    // A crate name reaches Rust source with `-` normalised to `_`, so both spellings
    // are compared. (`concat-idents` in the TOML also matches `concat_idents` here.)
    let mut out = BTreeSet::new();
    for row in parsed.name {
        out.insert(row.value.replace('-', "_"));
        out.insert(row.value.clone());
    }
    Ok(out)
}

// ── visitors ─────────────────────────────────────────────────────────────────

struct IncludeBanVisitor {
    hits: Vec<(usize, usize)>,
}

impl<'ast> Visit<'ast> for IncludeBanVisitor {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac.path.segments.len() == 1 && mac.path.segments[0].ident == "include" {
            let s = mac.span().start();
            self.hits.push((s.line, s.column));
        }
        syn::visit::visit_macro(self, mac);
    }
}

fn path_attr_modules(file: &syn::File) -> Vec<(String, String, usize, usize)> {
    struct V {
        out: Vec<(String, String, usize, usize)>,
    }
    impl<'ast> Visit<'ast> for V {
        fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
            for a in &m.attrs {
                if a.path().is_ident("path") {
                    if let syn::Meta::NameValue(nv) = &a.meta {
                        if let syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Str(s),
                            ..
                        }) = &nv.value
                        {
                            let sp = m.span().start();
                            self.out
                                .push((m.ident.to_string(), s.value(), sp.line, sp.column));
                        }
                    }
                }
            }
            syn::visit::visit_item_mod(self, m);
        }
    }
    let mut v = V { out: Vec::new() };
    v.visit_file(file);
    v.out
}

struct FnSpanVisitor {
    out: Vec<(String, (usize, usize), (usize, usize))>,
}

impl<'ast> Visit<'ast> for FnSpanVisitor {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        let s = f.block.span().start();
        let e = f.block.span().end();
        self.out.push((
            f.sig.ident.to_string(),
            (s.line, s.column),
            (e.line, e.column),
        ));
        syn::visit::visit_item_fn(self, f);
    }
}

struct Occurrence {
    file: PathBuf,
    start: (usize, usize),
    layer: &'static str,
    is_definition: bool,
    always_out_of_bounds: bool,
}

struct OccurrenceVisitor {
    ident: &'static str,
    ast_only: bool,
    out: Vec<Occurrence>,
}

impl OccurrenceVisitor {
    fn push(&mut self, span: proc_macro2::Span, layer: &'static str, def: bool, oob: bool) {
        let s = span.start();
        self.out.push(Occurrence {
            file: PathBuf::new(),
            start: (s.line, s.column),
            layer,
            is_definition: def,
            always_out_of_bounds: oob,
        });
    }
}

impl<'ast> Visit<'ast> for OccurrenceVisitor {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if f.sig.ident == self.ident {
            self.push(f.sig.ident.span(), "AST/definition", true, false);
        }
        syn::visit::visit_item_fn(self, f);
    }

    fn visit_path(&mut self, p: &'ast syn::Path) {
        if let Some(last) = p.segments.last() {
            if last.ident == self.ident {
                self.push(last.ident.span(), "AST/path", false, false);
            }
        }
        syn::visit::visit_path(self, p);
    }

    fn visit_use_tree(&mut self, t: &'ast syn::UseTree) {
        match t {
            syn::UseTree::Name(n) if n.ident == self.ident => {
                self.push(n.ident.span(), "AST/use", false, false)
            }
            // `use … as x;` — the RENAMED-FROM identifier is the naming occurrence.
            syn::UseTree::Rename(r) if r.ident == self.ident => {
                self.push(r.ident.span(), "AST/use-rename", false, false)
            }
            syn::UseTree::Path(p) if p.ident == self.ident => {
                self.push(p.ident.span(), "AST/use-path", false, false)
            }
            _ => {}
        }
        syn::visit::visit_use_tree(self, t);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if !self.ast_only {
            // A `macro_rules!` DEFINITION's body can never be "inside" one caller.
            let is_rules = mac.path.segments.len() == 1
                && mac.path.segments[0].ident == "macro_rules";
            let n = count_ident(mac.tokens.clone(), self.ident);
            for _ in 0..n {
                self.push(mac.span(), "TOKEN/macro", false, is_rules);
            }
            // A `macro_rules! NAME` definition carries NAME in `mac.ident`, not in
            // its tokens; the body tokens are what matter and are counted above.
        }
        syn::visit::visit_macro(self, mac);
    }

    fn visit_item_macro(&mut self, m: &'ast syn::ItemMacro) {
        if !self.ast_only {
            let is_rules = m.mac.path.segments.len() == 1
                && m.mac.path.segments[0].ident == "macro_rules";
            if is_rules {
                let n = count_ident(m.mac.tokens.clone(), self.ident);
                for _ in 0..n {
                    self.push(m.span(), "TOKEN/macro_rules", false, true);
                }
                // Do not recurse: visit_macro would double-count the same tokens.
                return;
            }
        }
        syn::visit::visit_item_macro(self, m);
    }
}

fn count_ident(ts: proc_macro2::TokenStream, ident: &str) -> usize {
    let mut n = 0;
    for tt in ts {
        match tt {
            TokenTree::Ident(i) => {
                if i == ident {
                    n += 1;
                }
            }
            TokenTree::Group(g) => n += count_ident(g.stream(), ident),
            _ => {}
        }
    }
    n
}

struct BeltVisitor<'a> {
    deny: &'a BTreeSet<String>,
    hits: Vec<(&'static str, String, usize, usize)>,
}

impl<'a> BeltVisitor<'a> {
    fn check(&mut self, kind: &'static str, name: String, span: proc_macro2::Span) {
        if self.deny.contains(&name) {
            let s = span.start();
            self.hits.push((kind, name, s.line, s.column));
        }
    }
}

impl<'a, 'ast> Visit<'ast> for BeltVisitor<'a> {
    // Layer A, sub-walk 1 — `use` bindings, rename-resolved.
    fn visit_item_use(&mut self, u: &'ast syn::ItemUse) {
        let mut roots: Vec<(String, proc_macro2::Span)> = Vec::new();
        collect_use_roots(&u.tree, &mut roots);
        for (name, span) in roots {
            self.check("use", name, span);
        }
        syn::visit::visit_item_use(self, u);
    }

    // Layer A, sub-walk 2 — `extern crate`, matched on `ident`, NEVER `rename`.
    fn visit_item_extern_crate(&mut self, c: &'ast syn::ItemExternCrate) {
        self.check("extern crate", c.ident.to_string(), c.ident.span());
        syn::visit::visit_item_extern_crate(self, c);
    }

    // Layer B — the macro's own path, tolerant of a leading `::`; plus AC-7o-bis,
    // a `macro_rules!` BODY naming a banned crate.
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Some(first) = mac.path.segments.first() {
            self.check("macro invocation path", first.ident.to_string(), first.ident.span());
        }
        if mac.path.segments.len() == 1 && mac.path.segments[0].ident == "macro_rules" {
            let names: Vec<String> = self.deny.iter().cloned().collect();
            for n in names {
                let hits = count_ident(mac.tokens.clone(), &n);
                for _ in 0..hits {
                    self.check("macro_rules! body", n.clone(), mac.span());
                }
            }
        }
        syn::visit::visit_macro(self, mac);
    }
}

/// The crate-root segment a `UseTree` ultimately names, for every branch —
/// `Path` recurses, `Name` is itself the root when the `use` starts there,
/// `Rename` compares the renamed-FROM `ident` (never the alias), and `Group`
/// recurses into every child.
fn collect_use_roots(t: &syn::UseTree, out: &mut Vec<(String, proc_macro2::Span)>) {
    match t {
        syn::UseTree::Path(p) => out.push((p.ident.to_string(), p.ident.span())),
        syn::UseTree::Name(n) => out.push((n.ident.to_string(), n.ident.span())),
        syn::UseTree::Rename(r) => out.push((r.ident.to_string(), r.ident.span())),
        syn::UseTree::Glob(_) => {}
        syn::UseTree::Group(g) => {
            for child in &g.items {
                collect_use_roots(child, out);
            }
        }
    }
}

fn within(s: (usize, usize), e: (usize, usize), p: (usize, usize)) -> bool {
    p >= s && p <= e
}

fn render(os: &[Occurrence]) -> String {
    os.iter()
        .map(|o| {
            format!(
                "    {} at {}:{}:{}{}",
                o.layer,
                o.file.display(),
                o.start.0,
                o.start.1,
                if o.is_definition { " [definition]" } else { "" }
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
