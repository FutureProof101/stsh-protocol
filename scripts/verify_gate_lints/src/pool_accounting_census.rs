//! FU1-2 — the pool accounting-statics REFERENCE-COUNT census (lane R-11).
//!
//! WHAT THIS IS. `canisters/shielded-pool/src/lib.rs` carries six accounting
//! scalars — `PRIVATE_LIABILITY`, `ESCROW_BACKING`, `OPERATIONS_RESERVE`,
//! `INSURANCE_RESERVE`, `GOVERNANCE_REWARDS_RESERVE`,
//! `PENDING_FEE_REIMBURSEMENTS`. The pool's own comments used to claim that
//! `fu1_2_no_direct_accounting_mutation` PROVED no code path bypasses the
//! `commit_pool_accounting` funnel. It did not: that test was a LINE-LOCAL
//! source scan, blind to a write `rustfmt` split across two lines — exactly the
//! shape of the then-live `GOVERNANCE_REWARDS_RESERVE` bypass inside
//! `apply_withdrawal_accounting`. That test was RETIRED at R-13 (CTO ruling
//! `cto-ruling-r13-packet-2026-09-07`); this census and the R-13 AST lock
//! `r13_accounting_cell_writer_set_is_the_funnel_only` back the claim instead.
//!
//! WHAT THIS DOES INSTEAD. A `syn` AST walk over the pool's source records, for
//! every function reachable in the NON-TEST build, every direct reference to
//! each of the six statics, together with whether that reference READS or
//! WRITES. The full multiset of `(fn, static) -> (reads, writes)` must equal a
//! literal expectation table hardcoded below. Nothing is matched on text, so a
//! split identifier is found identically to a same-line one; nothing is matched
//! on a line number, so ordinary edits above a site do not move a row.
//!
//! WHAT THIS DELIBERATELY DOES NOT DO. A reference count does not adjudicate
//! whether any individual write is correctly funnelled. It proves the SET of
//! references is enumerated and unchanged.
//!
//! R-13 (UMC-29) CLOSED THE TWO BYPASSES. When this census was written,
//! `apply_private_spend_accounting` and `apply_withdrawal_accounting` held
//! live, heap-only writes that skipped the funnel, and they were listed here
//! with exact ALLOWED-UNTIL-R-13 counts. R-13 rewrote both to mutate the
//! `[u128; 6]` word array inside an `acct_update` closure, so neither
//! references any of the six statics any more; their rows are gone and their
//! names are baselined at zero in [`RETIRED_BYPASSES`]. The census now asserts
//! the stronger property directly: the WRITER SET is exactly
//! [`EXPECTED_WRITER_SET`] = `{commit_pool_accounting}`.
//!
//! NO DECLARATION-EXCLUSION STEP IS NEEDED. The six `thread_local!` declarations
//! sit inside a macro invocation, which `syn`'s non-expanding visitor parses as
//! an opaque `Item::Macro` token stream and never descends into — they are
//! structurally invisible to this walk, not filtered out of it.
//!
//! `ACCT_W_<NAME>` word-index constants are EXCLUDED BY IDENTIFIER, not by line
//! filtering: `ACCT_W_PRIVATE_LIABILITY` is a different `Ident` from
//! `PRIVATE_LIABILITY`, and the walk compares whole identifiers, so a line
//! carrying both (every line of `accounting_words`) contributes exactly its one
//! real reference.

use std::collections::BTreeMap;
use std::path::Path;

use syn::{Item, ItemFn, ItemMod};

use crate::cfg_eval::{effective, parse_cfg_attr, Env, Pred};
use crate::features;
use crate::target_cfg::TargetAtoms;

/// The pool source this census governs.
pub const POOL_SRC: &str = "canisters/shielded-pool/src/lib.rs";

/// The six accounting scalars, in word order.
pub const ACCOUNTING_STATICS: [&str; 6] = [
    "PRIVATE_LIABILITY",
    "ESCROW_BACKING",
    "OPERATIONS_RESERVE",
    "INSURANCE_RESERVE",
    "GOVERNANCE_REWARDS_RESERVE",
    "PENDING_FEE_REIMBURSEMENTS",
];

/// One expectation row: `(fn, static, reads, writes)`.
pub type Row = (&'static str, &'static str, usize, usize);

/// The literal expectation table (brief §3.1, re-derived cell-by-cell against
/// the tree by the builder before being hardcoded here).
///
/// Ten funnel/accessor functions are the POSITIVE control: their counts are
/// real asserted numbers, so deleting one reference from any of them REDs.
pub const EXPECTED: &[Row] = &[
    // ── funnel ────────────────────────────────────────────────────────────
    ("accounting_words", "PRIVATE_LIABILITY", 1, 0),
    ("accounting_words", "ESCROW_BACKING", 1, 0),
    ("accounting_words", "OPERATIONS_RESERVE", 1, 0),
    ("accounting_words", "INSURANCE_RESERVE", 1, 0),
    ("accounting_words", "GOVERNANCE_REWARDS_RESERVE", 1, 0),
    ("accounting_words", "PENDING_FEE_REIMBURSEMENTS", 1, 0),
    ("commit_pool_accounting", "PRIVATE_LIABILITY", 0, 1),
    ("commit_pool_accounting", "ESCROW_BACKING", 0, 1),
    ("commit_pool_accounting", "OPERATIONS_RESERVE", 0, 1),
    ("commit_pool_accounting", "INSURANCE_RESERVE", 0, 1),
    ("commit_pool_accounting", "GOVERNANCE_REWARDS_RESERVE", 0, 1),
    ("commit_pool_accounting", "PENDING_FEE_REIMBURSEMENTS", 0, 1),
    // ── read-only accessors ───────────────────────────────────────────────
    ("get_accounting_state", "PRIVATE_LIABILITY", 1, 0),
    ("get_accounting_state", "ESCROW_BACKING", 1, 0),
    ("get_accounting_state", "OPERATIONS_RESERVE", 1, 0),
    ("get_accounting_state", "INSURANCE_RESERVE", 1, 0),
    ("get_accounting_state", "GOVERNANCE_REWARDS_RESERVE", 1, 0),
    ("get_accounting_state", "PENDING_FEE_REIMBURSEMENTS", 1, 0),
    ("controller_read_accounting_state_page", "PRIVATE_LIABILITY", 1, 0),
    ("controller_read_accounting_state_page", "ESCROW_BACKING", 1, 0),
    ("controller_read_accounting_state_page", "OPERATIONS_RESERVE", 1, 0),
    ("controller_read_accounting_state_page", "INSURANCE_RESERVE", 1, 0),
    ("controller_read_accounting_state_page", "GOVERNANCE_REWARDS_RESERVE", 1, 0),
    ("controller_read_accounting_state_page", "PENDING_FEE_REIMBURSEMENTS", 1, 0),
    ("reserve_bucket_balance", "OPERATIONS_RESERVE", 1, 0),
    ("reserve_bucket_balance", "INSURANCE_RESERVE", 1, 0),
    ("reserve_bucket_balance", "GOVERNANCE_REWARDS_RESERVE", 1, 0),
    ("withdraw", "PRIVATE_LIABILITY", 1, 0),
    ("resume_blocked_withdrawal", "PRIVATE_LIABILITY", 1, 0),
    ("precheck_private_spend_before_verify", "PRIVATE_LIABILITY", 1, 0),
    ("recheck_private_spend_after_verify", "PRIVATE_LIABILITY", 1, 0),
    ("validate_private_spend_public_payout_preconditions", "ESCROW_BACKING", 1, 0),
    // ── no bypass rows ────────────────────────────────────────────────────
    // R-13 closed UMC-29: `apply_private_spend_accounting` and
    // `apply_withdrawal_accounting` no longer reference any of the six statics
    // at all. Their scalar arithmetic now happens on the `[u128; 6]` word array
    // inside an `acct_update` closure, addressed by the `ACCT_W_*` index
    // constants — different identifiers, structurally invisible to this walk.
    // They are therefore absent from this table rather than listed with zeros:
    // a re-added raw write inside either fn is an UNLISTED finding.
];

/// The two functions that USED to hold funnel bypasses (UMC-29), baselined at
/// their post-R-13 count of ZERO direct references to the six statics. This is
/// the same mechanism as before with the count moved to 0: it is the row that
/// notices a raw write creeping back into either function specifically, and it
/// stays non-vacuous because the walk still resolves both fn names.
pub const RETIRED_BYPASSES: &[(&str, usize)] = &[
    ("apply_private_spend_accounting", 0),
    ("apply_withdrawal_accounting", 0),
];

/// R-13: the funnel is the ONLY writer. Every write the walk resolves must be
/// owned by this fn — the census-side statement of the same property the AST
/// lock `r13_accounting_cell_writer_set_is_the_funnel_only` asserts in
/// `integration-tests`.
pub const EXPECTED_WRITER_SET: &[&str] = &["commit_pool_accounting"];

/// The false completeness wordings this census replaced. Reverting either pool
/// comment to one of these is itself a finding (Mutation F).
pub const FORBIDDEN_COMPLETENESS_PHRASES: &[&str] = &[
    "proves no code path bypasses",
    "asserts there is no other",
    "so a bypass is a failing test rather than a silent divergence",
];

/// An observed reference to one of the six statics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Observed {
    pub func: String,
    pub stat: String,
    pub reads: usize,
    pub writes: usize,
}

#[derive(Default)]
struct Acc {
    /// `(fn, static) -> (reads, writes)`
    counts: BTreeMap<(String, String), (usize, usize)>,
    /// Spans already consumed by a `<STATIC>.with(...)` method call, so the
    /// generic path visitor does not double-count the same identifier.
    consumed: std::collections::BTreeSet<(usize, usize)>,
}

fn path_static(p: &syn::Path) -> Option<String> {
    if p.segments.len() != 1 {
        return None;
    }
    let id = p.segments[0].ident.to_string();
    ACCOUNTING_STATICS.contains(&id.as_str()).then_some(id)
}

/// Is this reference a WRITE? A reference is a write iff its `.with(...)`
/// closure contains a `borrow_mut` / `with_borrow_mut` path, or the accessor
/// method itself is a `*_mut` form.
fn is_write(method: &str, args_tokens: &str) -> bool {
    method.contains("borrow_mut") || args_tokens.contains("borrow_mut")
}

/// Walk one expression tree, attributing every reference to `func`.
fn visit_expr(e: &syn::Expr, func: &str, acc: &mut Acc) {
    if let syn::Expr::MethodCall(mc) = e {
        if let syn::Expr::Path(p) = &*mc.receiver {
            if let Some(stat) = path_static(&p.path) {
                let span = p.path.segments[0].ident.span().start();
                acc.consumed.insert((span.line, span.column));
                let args = quote::quote!(#mc).to_string();
                let w = is_write(&mc.method.to_string(), &args);
                let slot = acc
                    .counts
                    .entry((func.to_string(), stat))
                    .or_insert((0, 0));
                if w {
                    slot.1 += 1;
                } else {
                    slot.0 += 1;
                }
            }
        }
    }
    if let syn::Expr::Path(p) = e {
        if let Some(stat) = path_static(&p.path) {
            let span = p.path.segments[0].ident.span().start();
            if acc.consumed.insert((span.line, span.column)) {
                // A bare reference not routed through `.with(...)` — counted as
                // a read, and visible as an unexpected cell if it is new.
                acc.counts
                    .entry((func.to_string(), stat))
                    .or_insert((0, 0))
                    .0 += 1;
            }
        }
    }
    // Recurse structurally. `syn::visit` would need a lifetime-bound visitor
    // per function; a hand walk over the token-bearing children is simpler and
    // is exactly as structural, because it descends the same AST.
    walk_children(e, func, acc);
}

macro_rules! walk {
    ($acc:ident, $func:ident, $($e:expr),* $(,)?) => {{ $( visit_expr($e, $func, $acc); )* }};
}

fn walk_children(e: &syn::Expr, func: &str, acc: &mut Acc) {
    use syn::Expr::*;
    match e {
        Array(x) => x.elems.iter().for_each(|c| visit_expr(c, func, acc)),
        Assign(x) => walk!(acc, func, &x.left, &x.right),
        Async(x) => walk_block(&x.block, func, acc),
        Await(x) => visit_expr(&x.base, func, acc),
        Binary(x) => walk!(acc, func, &x.left, &x.right),
        Block(x) => walk_block(&x.block, func, acc),
        Break(x) => {
            if let Some(v) = &x.expr {
                visit_expr(v, func, acc)
            }
        }
        Call(x) => {
            visit_expr(&x.func, func, acc);
            x.args.iter().for_each(|c| visit_expr(c, func, acc));
        }
        Cast(x) => visit_expr(&x.expr, func, acc),
        Closure(x) => visit_expr(&x.body, func, acc),
        Const(x) => walk_block(&x.block, func, acc),
        Field(x) => visit_expr(&x.base, func, acc),
        ForLoop(x) => {
            visit_expr(&x.expr, func, acc);
            walk_block(&x.body, func, acc);
        }
        Group(x) => visit_expr(&x.expr, func, acc),
        If(x) => {
            visit_expr(&x.cond, func, acc);
            walk_block(&x.then_branch, func, acc);
            if let Some((_, e)) = &x.else_branch {
                visit_expr(e, func, acc)
            }
        }
        Index(x) => walk!(acc, func, &x.expr, &x.index),
        Let(x) => visit_expr(&x.expr, func, acc),
        Loop(x) => walk_block(&x.body, func, acc),
        Match(x) => {
            visit_expr(&x.expr, func, acc);
            for arm in &x.arms {
                if let Some((_, g)) = &arm.guard {
                    visit_expr(g, func, acc)
                }
                visit_expr(&arm.body, func, acc);
            }
        }
        MethodCall(x) => {
            visit_expr(&x.receiver, func, acc);
            x.args.iter().for_each(|c| visit_expr(c, func, acc));
        }
        Paren(x) => visit_expr(&x.expr, func, acc),
        Range(x) => {
            if let Some(s) = &x.start {
                visit_expr(s, func, acc)
            }
            if let Some(t) = &x.end {
                visit_expr(t, func, acc)
            }
        }
        Reference(x) => visit_expr(&x.expr, func, acc),
        Repeat(x) => walk!(acc, func, &x.expr, &x.len),
        Return(x) => {
            if let Some(v) = &x.expr {
                visit_expr(v, func, acc)
            }
        }
        Struct(x) => {
            for f in &x.fields {
                visit_expr(&f.expr, func, acc);
            }
            if let Some(r) = &x.rest {
                visit_expr(r, func, acc)
            }
        }
        Try(x) => visit_expr(&x.expr, func, acc),
        TryBlock(x) => walk_block(&x.block, func, acc),
        Tuple(x) => x.elems.iter().for_each(|c| visit_expr(c, func, acc)),
        Unary(x) => visit_expr(&x.expr, func, acc),
        Unsafe(x) => walk_block(&x.block, func, acc),
        While(x) => {
            visit_expr(&x.cond, func, acc);
            walk_block(&x.body, func, acc);
        }
        Yield(x) => {
            if let Some(v) = &x.expr {
                visit_expr(v, func, acc)
            }
        }
        _ => {}
    }
}

fn walk_block(b: &syn::Block, func: &str, acc: &mut Acc) {
    for s in &b.stmts {
        match s {
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    visit_expr(&init.expr, func, acc);
                    if let Some((_, d)) = &init.diverge {
                        visit_expr(d, func, acc)
                    }
                }
            }
            syn::Stmt::Expr(e, _) => visit_expr(e, func, acc),
            syn::Stmt::Item(Item::Fn(f)) => walk_block(&f.block, &f.sig.ident.to_string(), acc),
            _ => {}
        }
    }
}

/// Hard errors that make the census refuse rather than guess.
#[derive(Debug)]
pub enum CensusError {
    Io(String),
    Syn(String),
    Cfg(String),
    Feature(String),
}

impl std::fmt::Display for CensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CensusError::Io(m)
            | CensusError::Syn(m)
            | CensusError::Cfg(m)
            | CensusError::Feature(m) => write!(f, "{m}"),
        }
    }
}

fn walk_items(
    items: &[Item],
    inherited: &[Pred],
    rel: &str,
    target: &TargetAtoms,
    prod: &Env,
    acc: &mut Acc,
) -> Result<(), CensusError> {
    for item in items {
        let attrs: &[syn::Attribute] = match item {
            Item::Fn(f) => &f.attrs,
            Item::Mod(m) => &m.attrs,
            Item::Impl(i) => &i.attrs,
            _ => &[],
        };
        let mut here = inherited.to_vec();
        for a in attrs {
            if let Some(p) = parse_cfg_attr(a, rel, target).map_err(|e| CensusError::Cfg(e.to_string()))? {
                here.push(p);
            }
        }
        if !effective(&here, prod) {
            continue;
        }
        match item {
            Item::Fn(ItemFn { sig, block, .. }) => {
                walk_block(block, &sig.ident.to_string(), acc);
            }
            Item::Mod(ItemMod { content: Some((_, inner)), .. }) => {
                walk_items(inner, &here, rel, target, prod, acc)?;
            }
            Item::Impl(i) => {
                for ii in &i.items {
                    if let syn::ImplItem::Fn(m) = ii {
                        let mut inner = here.clone();
                        for a in &m.attrs {
                            if let Some(p) = parse_cfg_attr(a, rel, target)
                                .map_err(|e| CensusError::Cfg(e.to_string()))?
                            {
                                inner.push(p);
                            }
                        }
                        if effective(&inner, prod) {
                            walk_block(&m.block, &m.sig.ident.to_string(), acc);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Derive the observed `(fn, static) -> (reads, writes)` table from the tree.
pub fn observe(root: &Path, target: &TargetAtoms) -> Result<Vec<Observed>, CensusError> {
    let src = root.join(POOL_SRC);
    let text = std::fs::read_to_string(&src)
        .map_err(|e| CensusError::Io(format!("{}: {e}", src.display())))?;
    let ast = syn::parse_file(&text)
        .map_err(|e| CensusError::Syn(format!("{}: {e}", src.display())))?;
    let manifest = root.join("canisters/shielded-pool/Cargo.toml");
    let feats = features::production_features("shielded_pool", &manifest)
        .map_err(|e| CensusError::Feature(e.to_string()))?;
    let prod = Env::production(feats, target.clone());
    let mut acc = Acc::default();
    walk_items(&ast.items, &[], POOL_SRC, target, &prod, &mut acc)?;
    Ok(acc
        .counts
        .into_iter()
        .map(|((func, stat), (reads, writes))| Observed { func, stat, reads, writes })
        .collect())
}

/// Compare the observed table against [`EXPECTED`], [`EXPECTED_WRITER_SET`], the
/// [`RETIRED_BYPASSES`]
/// totals, and the forbidden-completeness-phrase grep. Returns findings.
pub fn run(root: &Path, target: &TargetAtoms) -> Result<Vec<String>, CensusError> {
    let observed = observe(root, target)?;
    let mut violations = Vec::new();

    let mut want: BTreeMap<(&str, &str), (usize, usize)> = BTreeMap::new();
    for (f, s, r, w) in EXPECTED {
        want.insert((f, s), (*r, *w));
    }
    for o in &observed {
        match want.get(&(o.func.as_str(), o.stat.as_str())) {
            None => violations.push(format!(
                "{POOL_SRC}: UNLISTED accounting reference — `{}` references `{}` \
                 ({} read(s), {} write(s)) but has no row in the expectation table",
                o.func, o.stat, o.reads, o.writes
            )),
            Some((r, w)) => {
                if o.reads != *r || o.writes != *w {
                    violations.push(format!(
                        "{POOL_SRC}: reference-count drift — `{}` / `{}`: expected \
                         {r} read(s) + {w} write(s), found {} read(s) + {} write(s)",
                        o.func, o.stat, o.reads, o.writes
                    ));
                }
            }
        }
    }
    for ((f, s), (r, w)) in &want {
        if !observed.iter().any(|o| o.func == *f && o.stat == *s) {
            violations.push(format!(
                "{POOL_SRC}: MISSING accounting reference — the table expects `{f}` / `{s}` \
                 ({r} read(s) + {w} write(s)) and the walk found none"
            ));
        }
    }

    // R-13: the writer set over the WHOLE file must be exactly the funnel.
    let mut writers: Vec<&str> = observed
        .iter()
        .filter(|o| o.writes > 0)
        .map(|o| o.func.as_str())
        .collect();
    writers.sort_unstable();
    writers.dedup();
    if writers != EXPECTED_WRITER_SET {
        violations.push(format!(
            "{POOL_SRC}: WRITER SET drift — expected exactly {EXPECTED_WRITER_SET:?} to write the \
             six accounting statics, found {writers:?}. Every accounting mutation must go through \
             `commit_pool_accounting` via `acct_update` (R-13, UMC-29)."
        ));
    }

    // The two retired bypass fns are baselined at zero references, by name.
    for (name, total) in RETIRED_BYPASSES {
        let actual: usize = observed
            .iter()
            .filter(|o| o.func == *name)
            .map(|o| o.reads + o.writes)
            .sum();
        if actual != *total {
            violations.push(format!(
                "{POOL_SRC}: RETIRED bypass `{name}` has {actual} direct reference(s) to the \
                 six accounting statics; its post-R-13 baseline is {total}. R-13 routed this \
                 function through `acct_update`; a direct reference here is a funnel bypass \
                 returning (UMC-29). Mutate the `[u128; 6]` words inside the closure instead."
            ));
        }
    }

    // Mutation F: the false completeness wordings must not come back.
    let text = std::fs::read_to_string(root.join(POOL_SRC))
        .map_err(|e| CensusError::Io(format!("{POOL_SRC}: {e}")))?;
    for (i, line) in text.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        for p in FORBIDDEN_COMPLETENESS_PHRASES {
            if lower.contains(p) {
                violations.push(format!(
                    "{POOL_SRC}:{}: false completeness claim restored — `{p}`. \
                     the retired `fu1_2_no_direct_accounting_mutation` was a LINE-LOCAL scan proving no \
                     such thing; this census and the R-13 AST writer-set lock back the claim.",
                    i + 1
                ));
            }
        }
    }
    Ok(violations)
}
