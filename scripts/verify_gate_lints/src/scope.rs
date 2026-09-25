//! `scope` — PACKET-ONLY tool (brief §3 S5). NEVER a `run_gate.sh` stage.
//!
//! Proves a declared file list is behaviourally inert against a builder-supplied
//! base SHA, by parsed-token-stream equivalence with comments and doc-attributes
//! stripped. The base side is read via `git show <sha>:<path>`, never from a
//! working-tree copy (invariant 2). No fixed base is wired into any gate script;
//! the base is an argument, supplied once at landing time (AC-11).

use std::path::Path;
use std::process::Command;

fn git_show(root: &Path, sha: &str, path: &str) -> Option<String> {
    let out = Command::new("git")
        .current_dir(root)
        .args(["show", &format!("{sha}:{path}")])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Strip comments (syn already drops them) and doc-attributes, then render the
/// token stream canonically.
fn canonical(src: &str) -> Result<String, String> {
    let mut ast = syn::parse_file(src).map_err(|e| e.to_string())?;
    strip_doc_attrs_file(&mut ast);
    Ok(quote::quote!(#ast).to_string())
}

/// Strip doc attributes from a free function, recursively through its body's
/// nested items. Shared with the census so the structural guard walk never
/// reads prose.
pub fn strip_doc_attrs_fn(f: &mut syn::ItemFn) {
    f.attrs.retain(|a| !is_doc(a));
    strip_block(&mut f.block);
}

pub fn strip_doc_attrs_impl_fn(m: &mut syn::ImplItemFn) {
    m.attrs.retain(|a| !is_doc(a));
    strip_block(&mut m.block);
}

fn strip_block(b: &mut syn::Block) {
    for stmt in &mut b.stmts {
        if let syn::Stmt::Item(i) = stmt {
            strip_item(i);
        }
    }
}

fn is_doc(attr: &syn::Attribute) -> bool {
    attr.path().is_ident("doc")
}

fn strip_doc_attrs_file(f: &mut syn::File) {
    f.attrs.retain(|a| !is_doc(a));
    for item in &mut f.items {
        strip_item(item);
    }
}

fn strip_item(item: &mut syn::Item) {
    macro_rules! s {
        ($v:expr) => {
            $v.attrs.retain(|a| !is_doc(a))
        };
    }
    match item {
        syn::Item::Fn(v) => s!(v),
        syn::Item::Const(v) => s!(v),
        syn::Item::Static(v) => s!(v),
        syn::Item::Struct(v) => {
            s!(v);
            for fl in v.fields.iter_mut() {
                fl.attrs.retain(|a| !is_doc(a));
            }
        }
        syn::Item::Enum(v) => {
            s!(v);
            for var in v.variants.iter_mut() {
                var.attrs.retain(|a| !is_doc(a));
            }
        }
        syn::Item::Use(v) => s!(v),
        syn::Item::Type(v) => s!(v),
        syn::Item::Macro(v) => s!(v),
        syn::Item::Trait(v) => s!(v),
        syn::Item::Impl(v) => {
            s!(v);
            for ii in &mut v.items {
                match ii {
                    syn::ImplItem::Fn(m) => m.attrs.retain(|a| !is_doc(a)),
                    syn::ImplItem::Const(c) => c.attrs.retain(|a| !is_doc(a)),
                    syn::ImplItem::Type(t) => t.attrs.retain(|a| !is_doc(a)),
                    _ => {}
                }
            }
        }
        syn::Item::Mod(v) => {
            s!(v);
            if let Some((_, items)) = &mut v.content {
                for i in items {
                    strip_item(i);
                }
            }
        }
        _ => {}
    }
}

pub struct ScopeReport {
    pub lines: Vec<String>,
    pub ok: bool,
}

pub fn run(root: &Path, base: &str, files: &[String]) -> ScopeReport {
    let mut lines = Vec::new();
    let mut ok = true;
    lines.push(format!("scope: base = {base}"));
    for path in files {
        let head_src = match std::fs::read_to_string(root.join(path)) {
            Ok(s) => s,
            Err(e) => {
                lines.push(format!("  MISSING-AT-HEAD {path}: {e}"));
                ok = false;
                continue;
            }
        };
        let base_src = git_show(root, base, path);
        match base_src {
            None => lines.push(format!("  NEW  {path} (absent at base — no equivalence to prove)")),
            Some(b) => {
                let (ch, cb) = (canonical(&head_src), canonical(&b));
                match (ch, cb) {
                    (Ok(h), Ok(bb)) if h == bb => lines.push(format!("  PASS {path}")),
                    (Ok(h), Ok(bb)) => {
                        ok = false;
                        let span = first_divergence(&h, &bb);
                        lines.push(format!("  FAIL {path} — first differing token span: {span}"));
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        ok = false;
                        lines.push(format!("  FAIL {path} — parse error: {e}"));
                    }
                }
            }
        }
    }
    // Cross-check: any file touched between base and HEAD that was NOT declared.
    let out = Command::new("git")
        .current_dir(root)
        .args(["diff", "--name-only", &format!("{base}..HEAD")])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let touched: Vec<String> = String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::to_string)
                .collect();
            let undeclared: Vec<&String> =
                touched.iter().filter(|t| !files.contains(t)).collect();
            if undeclared.is_empty() {
                lines.push("  cross-check: every touched file is declared".into());
            } else {
                lines.push(format!(
                    "  cross-check: {} touched file(s) NOT declared: {}",
                    undeclared.len(),
                    undeclared
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        _ => lines.push("  cross-check: git diff unavailable".into()),
    }
    ScopeReport { lines, ok }
}

fn first_divergence(a: &str, b: &str) -> String {
    let at: Vec<&str> = a.split_whitespace().collect();
    let bt: Vec<&str> = b.split_whitespace().collect();
    for (i, (x, y)) in at.iter().zip(bt.iter()).enumerate() {
        if x != y {
            let lo = i.saturating_sub(4);
            let hi = (i + 5).min(at.len());
            return format!(
                "token #{i}: HEAD `{}` vs base `{}` (HEAD context: … {} …)",
                x,
                y,
                at[lo..hi].join(" ")
            );
        }
    }
    format!("token count differs: HEAD {} vs base {}", at.len(), bt.len())
}
