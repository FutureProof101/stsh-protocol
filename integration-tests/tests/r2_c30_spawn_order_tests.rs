// =============================================================================
// STSH — R-2 (C-30) AC-7a: spawn-then-count STATEMENT ORDER, AST-bound
// BRIEF_R2_C30_FEE_MARKER_V3_2026-09-04.
// =============================================================================
//
// WHAT THIS TEST PROVES, AND WHAT IT DOES NOT.
//
// It proves ONE thing: in `spawn_treasury_fee_notification` — the single
// spawning function through which every treasury fee notification, immediate and
// batched, now flows — the call to `note_notification_spawned()` PRECEDES the
// call to `ic_cdk::spawn` in STATEMENT ORDER in the source.
//
// It proves NOTHING about runtime observability, and that is not a weakness to
// be papered over: the executor polls a spawned future to its first `await`
// synchronously, so swapping the two statements has NO behavioural witness from
// outside the canister. There is nothing to assert against a live replica. That
// is precisely why the ordering is bound TEXTUALLY here, and why the
// behavioural half of AC-7 (the increment and the resolve actually happening) is
// carried by the high-water-mark test in `r2_c30_fee_marker_tests.rs`.
//
// WHY AN AST AND NOT A SUBSTRING. A substring oracle — "does
// `note_notification_spawned` appear before `ic_cdk::spawn` in the file text?" —
// is satisfiable by a COMMENT or a string literal. Someone could swap the two
// executable statements, leave a comment mentioning the counter above the spawn,
// and the check would stay green. Comments are not in the AST at all, and string
// literals parse as `ExprLit`, never `ExprCall`. So this walks the function's
// body statements in order and looks at CALL EXPRESSIONS only.
//
// The decoy case is exercised as a mutation in the packet (M7a-decoy): the two
// executable statements swapped AND a comment plus a string literal containing
// `note_notification_spawned()` inserted before the spawn. It must stay RED.
//
// NOT-FOUND IS RED, NEVER A SKIP. A test that returns early when it cannot find
// the function it checks can never go red — it would survive the function being
// renamed, deleted, or refactored away, which is the exact change most likely to
// break the ordering it guards.

use syn::visit::Visit;
use syn::{Expr, ExprCall, File, ImplItemFn, Item, ItemFn, UnOp};

const POOL_SRC: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../canisters/shielded-pool/src/lib.rs"
);

/// The single spawning function every treasury fee notification goes through.
const SPAWNING_FN: &str = "spawn_treasury_fee_notification";
/// The flush path, which must reach the treasury through that same function.
const FLUSH_FN: &str = "flush_fee_accrual";

/// The trailing path segment of a call expression, e.g. `ic_cdk::spawn` → "spawn".
fn call_tail(call: &ExprCall) -> Option<String> {
    match &*call.func {
        Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    }
}

/// Every call expression inside a function body, in source order.
struct CallOrder {
    calls: Vec<String>,
}

impl<'ast> Visit<'ast> for CallOrder {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Some(name) = call_tail(node) {
            self.calls.push(name);
        }
        syn::visit::visit_expr_call(self, node);
    }
}

/// Collect free functions by name.
struct FnFinder {
    want: &'static str,
    found: Option<ItemFn>,
}

impl<'ast> Visit<'ast> for FnFinder {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if node.sig.ident == self.want {
            assert!(
                self.found.is_none(),
                "AC-8: ambiguous function name {}",
                self.want
            );
            self.found = Some(node.clone());
        }
        syn::visit::visit_item_fn(self, node);
    }
    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        syn::visit::visit_impl_item_fn(self, node);
    }
}

/// Resolve the complete production module tree before any closure/macro scan.
/// Missing/ambiguous modules, path overrides and repeated source files fail
/// closed; a new module cannot silently escape the source-side privacy proof.
fn parse_pool() -> File {
    parse_source_tree(std::path::Path::new(POOL_SRC))
}

fn parse_source_tree(path: &std::path::Path) -> File {
    let path = path.canonicalize().expect("AC-8: source root must exist");
    let root = path.parent().unwrap();
    let src = std::fs::read_to_string(&path).expect("AC-8: source must be readable");
    let mut file = syn::parse_file(&src).expect("AC-8: source must parse");
    assert!(
        !file
            .attrs
            .iter()
            .any(|a| a.path().is_ident("cfg") || a.path().is_ident("cfg_attr")),
        "AC-8: inner source cfg needs explicit resolver support"
    );
    let mut seen = std::collections::BTreeSet::from([path.clone()]);
    expand_modules(&mut file.items, root, root, &mut seen);
    file
}

fn item_attrs(item: &Item) -> &[syn::Attribute] {
    match item {
        Item::Fn(x) => &x.attrs,
        Item::Mod(x) => &x.attrs,
        Item::Macro(x) => &x.attrs,
        Item::Impl(x) => &x.attrs,
        Item::Const(x) => &x.attrs,
        Item::Static(x) => &x.attrs,
        Item::Struct(x) => &x.attrs,
        Item::Enum(x) => &x.attrs,
        Item::Type(x) => &x.attrs,
        Item::Trait(x) => &x.attrs,
        Item::Use(x) => &x.attrs,
        Item::ExternCrate(x) => &x.attrs,
        Item::ForeignMod(x) => &x.attrs,
        Item::TraitAlias(x) => &x.attrs,
        Item::Union(x) => &x.attrs,
        _ => &[],
    }
}

fn expand_modules(
    items: &mut Vec<Item>,
    directory: &std::path::Path,
    root: &std::path::Path,
    seen: &mut std::collections::BTreeSet<std::path::PathBuf>,
) {
    // Excluding a testing-only parent excludes its whole subtree. Production
    // callers/queries and file-scope macros are still walked without exceptions.
    items.retain(|item| !is_testing_gated(item_attrs(item)));
    for item in items {
        let Item::Mod(module) = item else { continue };
        assert!(
            !module.attrs.iter().any(|a| a.path().is_ident("path")),
            "AC-8: #[path] module override needs explicit resolver support"
        );
        let child_dir = directory.join(module.ident.to_string());
        if let Some((_, children)) = &mut module.content {
            expand_modules(children, &child_dir, root, seen);
            continue;
        }
        let flat = directory.join(format!("{}.rs", module.ident));
        let nested = child_dir.join("mod.rs");
        assert!(
            flat.is_file() ^ nested.is_file(),
            "AC-8: module {} must resolve to exactly one of {} or {}",
            module.ident,
            flat.display(),
            nested.display()
        );
        let source = if flat.is_file() { flat } else { nested };
        let source = source
            .canonicalize()
            .expect("AC-8: module canonicalization");
        assert!(source.starts_with(root), "AC-8: module escapes source root");
        assert!(
            seen.insert(source.clone()),
            "AC-8: recursive or duplicate module source: {}",
            source.display()
        );
        let text = std::fs::read_to_string(&source).expect("AC-8: read module");
        let mut parsed = syn::parse_file(&text).expect("AC-8: parse module");
        assert!(
            !parsed
                .attrs
                .iter()
                .any(|a| a.path().is_ident("cfg") || a.path().is_ident("cfg_attr")),
            "AC-8: inner module cfg needs explicit resolver support"
        );
        expand_modules(&mut parsed.items, &child_dir, root, seen);
        module.content = Some((syn::token::Brace::default(), parsed.items));
        module.semi = None;
    }
}

fn calls_in(file: &File, name: &'static str) -> Vec<String> {
    let mut finder = FnFinder {
        want: name,
        found: None,
    };
    finder.visit_file(file);
    let f = finder.found.unwrap_or_else(|| {
        panic!(
            "AC-7a: function `{name}` NOT FOUND in {POOL_SRC}. This is a FAILURE, not \
             a skip: a rename, deletion, or refactor of the spawning function is \
             exactly the change that would break the spawn-then-count ordering, and a \
             test that quietly passes when its subject is gone guards nothing."
        )
    });
    let mut order = CallOrder { calls: Vec::new() };
    order.visit_block(&f.block);
    order.calls
}

#[test]
fn ac7a_note_notification_spawned_precedes_the_spawn_in_statement_order() {
    let file = parse_pool();
    let calls = calls_in(&file, SPAWNING_FN);

    let i_count = calls
        .iter()
        .position(|c| c == "note_notification_spawned")
        .unwrap_or_else(|| {
            panic!(
                "AC-7a: `{SPAWNING_FN}` contains no CALL to `note_notification_spawned`. \
                 A comment or a string literal mentioning it does not count — this walk \
                 sees only `ExprCall` nodes. Calls found, in order: {calls:?}"
            )
        });
    let i_spawn = calls.iter().position(|c| c == "spawn").unwrap_or_else(|| {
        panic!(
            "AC-7a: `{SPAWNING_FN}` contains no CALL to `ic_cdk::spawn`. \
             Calls found, in order: {calls:?}"
        )
    });

    assert!(
        i_count < i_spawn,
        "AC-7a: ruling V2 §3(2) requires `note_notification_spawned()` to be the \
         statement IMMEDIATELY BEFORE `ic_cdk::spawn`, so a future the upgrade \
         discards is always already counted. In `{SPAWNING_FN}` the counter call is \
         at call-index {i_count} and the spawn at {i_spawn}. Calls in order: {calls:?}"
    );
}

#[test]
fn ac7a_the_flush_reaches_the_treasury_through_the_one_spawning_function() {
    let file = parse_pool();
    let calls = calls_in(&file, FLUSH_FN);
    assert!(
        calls.iter().any(|c| c == SPAWNING_FN),
        "AC-7a: `{FLUSH_FN}` must notify the treasury through `{SPAWNING_FN}`, the \
         one function that states the spawn-then-count ordering. A second, private \
         spawn site inside the flush would carry no such ordering and nothing would \
         say so. Calls found, in order: {calls:?}"
    );
}

/// The spawning function must also be what the IMMEDIATE path uses, so the two
/// paths cannot drift into two different orderings.
#[test]
fn ac7a_the_immediate_path_uses_the_same_spawning_function() {
    let file = parse_pool();
    let calls = calls_in(&file, "notify_treasury_fee");
    assert!(
        calls.iter().any(|c| c == SPAWNING_FN),
        "AC-7a: `notify_treasury_fee` (the ShieldFee / UnshieldFee path) must go \
         through `{SPAWNING_FN}` too. Calls found, in order: {calls:?}"
    );
}

/// AC-11b (the half that is a SOURCE property, not a behaviour): public
/// `withdraw` must STILL be fail-closed after R-2.
///
/// This is bound to the AST rather than driven through PocketIC deliberately.
/// `withdraw` asserts operator authority BEFORE the fail-closed guard, so a
/// non-controller call is rejected on AUTHORITY and never reaches the guard at
/// all — a PocketIC test written that way passes whether or not the guard is
/// there, which is a test that cannot fail. The guard's presence in the call
/// path is the checkable claim; the behavioural half of AC-11b is the
/// `UnshieldFee` immediacy test, which drives the PRODUCTION finalizer directly.
#[test]
fn ac11b_public_withdraw_still_calls_the_fail_closed_guard() {
    let file = parse_pool();
    let calls = calls_in(&file, "withdraw");
    assert!(
        calls.iter().any(|c| c == "reject_unbound_withdrawal_proof"),
        "AC-11b: `withdraw` must still call `reject_unbound_withdrawal_proof` \
         (Decision 7 — removed only in Phase 5). R-2 does not open this path. \
         Calls found, in order: {calls:?}"
    );
}

// =============================================================================
// AC-13 / M13c — the flush-window FLOOR is defined BY REFERENCE.
// =============================================================================
//
// WHY THIS TEST HAD TO EXIST. The behavioural AC-13 test cannot bind this. It
// transcribes `ATTESTATION_BUCKET_NS` as a literal — it must, because a check
// that reads the constant it checks cannot fail — and so does the mutation:
// replacing `FEE_FLUSH_WINDOW_FLOOR_NS = ATTESTATION_BUCKET_NS` with the literal
// `300_000_000_000` leaves every setter boundary at the same number, and the
// behavioural test passes unchanged. It was run, it stayed GREEN, and that is
// recorded in the packet: the criterion was NOT met by the behavioural test, and
// this is the binding that meets it.
//
// The claim "by reference, never a second literal" is a claim about the SOURCE,
// so it is checked in the source. Two literals that agree today are exactly the
// state that drifts tomorrow — which is the whole reason the brief demanded the
// reference.

/// The item defining `FEE_FLUSH_WINDOW_FLOOR_NS`, and its initialiser expression.
fn floor_const_expr(file: &File) -> Expr {
    for item in &file.items {
        if let Item::Const(c) = item {
            if c.ident == "FEE_FLUSH_WINDOW_FLOOR_NS" {
                return (*c.expr).clone();
            }
        }
    }
    panic!(
        "AC-13: `FEE_FLUSH_WINDOW_FLOOR_NS` NOT FOUND at module scope in {POOL_SRC}. \
         Not found is a FAILURE, never a skip."
    )
}

#[test]
fn ac13_the_flush_window_floor_is_attestation_bucket_ns_by_reference() {
    let file = parse_pool();
    let expr = floor_const_expr(&file);

    // Peel a unary minus / parens so `-(300_000_000_000)` cannot sneak past.
    let mut e = &expr;
    loop {
        match e {
            Expr::Paren(p) => e = &p.expr,
            Expr::Unary(u) if matches!(u.op, UnOp::Neg(_)) => e = &u.expr,
            _ => break,
        }
    }

    match e {
        Expr::Path(p) => {
            let name = p
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            assert_eq!(
                name, "ATTESTATION_BUCKET_NS",
                "AC-13: the flush-window floor must BE `ATTESTATION_BUCKET_NS`, so a fee \
                 surface can never resolve time more finely than the solvency attestation \
                 already does. It is currently the path `{name}`."
            );
        }
        other => panic!(
            "AC-13: `FEE_FLUSH_WINDOW_FLOOR_NS` must be defined as the IDENTIFIER \
             `ATTESTATION_BUCKET_NS`, never as a second literal — two literals that \
             agree today are what drift tomorrow. Its initialiser is a \
             {} expression instead.",
            match other {
                Expr::Lit(_) => "literal",
                Expr::Binary(_) => "binary-arithmetic",
                Expr::Call(_) => "call",
                _ => "non-path",
            }
        ),
    }
}

// =============================================================================
// AC-8 (SOURCE leg) — the accrual has NO public read path, proved as a CLOSURE
// over the source, not as a list of endpoint names someone must remember.
// SSA_LANDED_DIFF_R-2_V1_2026-09-05 RED-1;
// CTO_TRIAGE_SSA_LANDED_DIFF_ROUND1_2026-09-05 §2.
// =============================================================================
//
// THE LEAK THE SSA DEMONSTRATED. The intra-window accrual lives in exactly one
// place — `PENDING_FEE_ACCRUAL_CELL` (MemoryId 23), read through
// `read_fee_accrual()`. The SSA added a production `#[query] fn window_status()`
// returning `read_fee_accrual()[0].to_le_bytes()`, declared it in the DID, and an
// anonymous caller then read 7,000,000 operations-bps of accrual mid-window: the
// exact per-spend quantity C-30 exists to hide. The previous AC-8 test stayed
// GREEN, because it only forbade THREE hard-coded names.
//
// The property is not "these three names are absent". It is "no reachable public
// endpoint returns a value derived from the accrual cell". This test proves the
// SOURCE half of that as a closure:
//
//   1. The set of functions that so much as NAME the accrual cell or its
//      accessors is pinned. Adding a getter that calls `read_fee_accrual()` adds
//      its name to that set and this test goes RED — including the SSA's exact
//      `window_status`.
//   2. NONE of the functions in that set is an exported entry point (`#[query]`,
//      `#[update]`, or their `ic_cdk::`-qualified spellings). So no endpoint
//      reads the accrual DIRECTLY, and an INDIRECT read would have to call one of
//      the pinned accessors — which (1) forbids.
//
// The BEHAVIOURAL half — every nullary public query is byte-identical across a
// fee-bearing spend inside the window — is
// `ac8_no_public_pool_query_moves_inside_the_window` in
// `r2_c30_fee_marker_tests.rs`. Either leg alone goes RED on the SSA's mutation;
// they are kept separate because one is a claim about the source and the other a
// claim about the running canister.

/// Every identifier through which the intra-window accrual can be reached.
/// `PENDING_FEE_ACCRUAL_CELL` is the storage; the other four are the ONLY
/// accessors, and they are private (no `pub`, no export attribute).
const ACCRUAL_IDENTS: &[&str] = &[
    "PENDING_FEE_ACCRUAL_CELL",
    "read_fee_accrual",
    "write_fee_accrual",
    "accrue_private_transfer_fee",
    "drain_fee_accrual",
];

/// The functions permitted to name any of `ACCRUAL_IDENTS`, each with the reason
/// it is here. This list is the closure: anything else naming the accrual — a
/// getter, a helper an endpoint calls, a debug hook — makes the computed set
/// differ from this one and fails.
const ACCRUAL_TOUCHERS: &[(&str, &str)] = &[
    ("init", "writes the zero accrual at genesis; returns nothing"),
    ("terminal_payout", "R-15 internal terminal transition accrues stored split and returns unit, never an accrual value"),
    ("read_fee_accrual", "the private read accessor itself"),
    ("write_fee_accrual", "the private write accessor itself"),
    ("accrue_private_transfer_fee", "the private accrue helper"),
    ("drain_fee_accrual", "the private drain, called only by the flush"),
    ("flush_fee_accrual", "the boundary flush; publishes the BATCH, never the accrual"),
];

/// The attribute spellings that make a function a public canister entry point.
fn is_entry_point(attrs: &[syn::Attribute]) -> Option<String> {
    for a in attrs {
        let path = a
            .path()
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        let tail = path.rsplit("::").next().unwrap_or("").to_string();
        if matches!(tail.as_str(), "query" | "update") {
            return Some(path);
        }
    }
    None
}

/// Collect every identifier appearing anywhere in a syntax subtree.
#[derive(Default)]
struct Idents {
    seen: std::collections::BTreeSet<String>,
}

impl<'ast> Visit<'ast> for Idents {
    fn visit_ident(&mut self, node: &'ast syn::Ident) {
        self.seen.insert(node.to_string());
    }

    /// SSA round 2, RED-1. `syn` parses a macro invocation body as an OPAQUE
    /// token stream: `vec![read_fee_accrual()[0]]` contains no `syn::Ident`
    /// node at all, so an identifier walk that only implements `visit_ident`
    /// cannot see it. That is exactly how the SSA's `window_status` leak
    /// survived every check in round 1. Token streams are therefore scanned as
    /// text — `to_string()` on the stream, split on non-identifier characters —
    /// which is deliberately CONSERVATIVE: it sees an accrual name wherever it
    /// appears in the macro body, in any position, expanded or not.
    ///
    /// `visit_item_macro` (a `macro_rules!` DEFINITION, or an item-position
    /// invocation) delegates to this method by `syn`'s default walk, so both
    /// invocations and `macro_rules!` bodies are covered here.
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.seen.extend(idents_in_tokens(node));
        syn::visit::visit_macro(self, node);
    }
}

/// Every identifier-shaped word in a macro's token stream.
fn idents_in_tokens(mac: &syn::Macro) -> Vec<String> {
    mac.tokens
        .to_string()
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(|w| w.to_string())
        .collect()
}

/// The accrual identifiers named inside a macro token stream, if any.
fn accrual_idents_in_macro(mac: &syn::Macro) -> Vec<String> {
    let words: std::collections::BTreeSet<String> = idents_in_tokens(mac).into_iter().collect();
    ACCRUAL_IDENTS
        .iter()
        .filter(|i| words.contains(**i))
        .map(|i| i.to_string())
        .collect()
}

/// The printed path of a macro invocation (`vec`, `macro_rules`, `std::vec`).
fn macro_path(mac: &syn::Macro) -> String {
    mac.path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// Every function in the file — free functions and `impl` methods alike — with
/// its name, its attributes, and whether its BODY names the accrual.
struct AccrualScan {
    touchers: std::collections::BTreeMap<String, Vec<String>>,
    entry_points_touching: Vec<(String, String)>,
    /// SSA round 2, RED-1: every macro token stream that names the accrual, with
    /// the function that ENCLOSES it (`None` = file/item scope, e.g. a
    /// `macro_rules!` definition or an item-position invocation, neither of
    /// which is inside any function and so is invisible to the body walk).
    macro_hits: Vec<(Option<String>, String, Vec<String>)>,
    /// The enclosing-function stack maintained during the walk.
    fn_stack: Vec<String>,
}

impl AccrualScan {
    fn record(&mut self, name: String, attrs: &[syn::Attribute], block: &syn::Block) {
        let mut ids = Idents::default();
        ids.visit_block(block);
        let hits: Vec<String> = ACCRUAL_IDENTS
            .iter()
            .filter(|i| ids.seen.contains(**i))
            .map(|i| i.to_string())
            .collect();
        if hits.is_empty() {
            return;
        }
        if let Some(attr) = is_entry_point(attrs) {
            self.entry_points_touching.push((name.clone(), attr));
        }
        assert!(self.touchers.insert(name.clone(), hits).is_none(),
            "AC-8: duplicate accrual-touching function name {name}; qualify the closure rather than collapse it");
    }
}

impl<'ast> Visit<'ast> for AccrualScan {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let name = node.sig.ident.to_string();
        self.record(name.clone(), &node.attrs, &node.block);
        self.fn_stack.push(name);
        syn::visit::visit_item_fn(self, node);
        self.fn_stack.pop();
    }
    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let name = node.sig.ident.to_string();
        self.record(name.clone(), &node.attrs, &node.block);
        self.fn_stack.push(name);
        syn::visit::visit_impl_item_fn(self, node);
        self.fn_stack.pop();
    }
    /// Reached for EVERY macro in the file — expression, statement, type and
    /// item position, `macro_rules!` definitions included — whether or not it
    /// sits inside a function.
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let hits = accrual_idents_in_macro(node);
        if !hits.is_empty() {
            self.macro_hits
                .push((self.fn_stack.last().cloned(), macro_path(node), hits));
        }
        syn::visit::visit_macro(self, node);
    }
}

fn scan_accrual() -> AccrualScan {
    scan_accrual_file(&parse_pool())
}
fn scan_accrual_file(file: &File) -> AccrualScan {
    let mut scan = AccrualScan {
        touchers: std::collections::BTreeMap::new(),
        entry_points_touching: Vec::new(),
        macro_hits: Vec::new(),
        fn_stack: Vec::new(),
    };
    scan.visit_file(&file);
    scan
}

/// The accessors must still EXIST. A test whose subject has been renamed away
/// would otherwise pass vacuously with an empty scan.
#[test]
fn ac8_the_accrual_accessors_exist_under_the_names_this_test_pins() {
    let file = parse_pool();
    let mut identifiers = Idents::default();
    identifiers.visit_file(&file);
    for ident in ACCRUAL_IDENTS {
        assert!(
            identifiers.seen.contains(*ident),
            "AC-8: `{ident}` is not present in {POOL_SRC}. Not found is a FAILURE, \
             never a skip: if the accrual has been renamed, the closure below is \
             scanning for identifiers that no longer exist and cannot fail."
        );
    }
}

#[test]
fn ac8_no_canister_entry_point_reads_the_accrual_cell() {
    let scan = scan_accrual();
    assert!(
        scan.entry_points_touching.is_empty(),
        "AC-8 (SSA RED-1): a public canister entry point names the intra-window \
         accrual. An anonymous caller can then read the per-spend fee quantity that \
         C-30 exists to hide — the SSA's `window_status` leak, reproduced. \
         Offending entry points (function, attribute): {:?}",
        scan.entry_points_touching
    );
}

#[test]
fn ac8_the_set_of_functions_naming_the_accrual_is_exactly_the_pinned_closure() {
    let scan = scan_accrual();
    let got: std::collections::BTreeSet<String> = scan.touchers.keys().cloned().collect();
    let want: std::collections::BTreeSet<String> = ACCRUAL_TOUCHERS
        .iter()
        .map(|(n, _)| n.to_string())
        .collect();

    let added: Vec<&String> = got.difference(&want).collect();
    let gone: Vec<&String> = want.difference(&got).collect();

    assert!(
        added.is_empty(),
        "AC-8 (SSA RED-1): {added:?} now name(s) the intra-window accrual. This set is \
         PINNED because it is what makes the no-public-read-path claim a closure: an \
         endpoint cannot read the accrual directly (that is \
         `ac8_no_canister_entry_point_reads_the_accrual_cell`) and cannot read it \
         indirectly either, because the only functions that can are these and none is \
         reachable from an endpoint as a value. If the new function is a legitimate \
         internal accrual site, add it here WITH ITS REASON — and say in the packet why \
         it cannot flow to a caller. Pinned set and reasons: {ACCRUAL_TOUCHERS:?}"
    );
    assert!(
        gone.is_empty(),
        "AC-8: {gone:?} no longer name the accrual. Either the accrual logic moved — in \
         which case this closure is no longer scanning the real code — or the pin is \
         stale. Both are RED."
    );
}

// -----------------------------------------------------------------------------
// SSA landed-diff round 2, RED-1 — the two bindings the round-1 closure lacked.
// CTO_TRIAGE_SSA_LANDED_DIFF_ROUND2_2026-09-05.md, R-2 row;
// SSA_LANDED_DIFF_R-2_V2_2026-09-05.md RED-1.
// -----------------------------------------------------------------------------

/// No macro token stream anywhere in the pool may name the accrual unless the
/// function enclosing it is in the pinned closure.
///
/// The SSA's counterexample was `vec![read_fee_accrual()[0].to_le_bytes()]`
/// inside a `#[query]`: legal Rust, an ordinary macro, and INVISIBLE to a
/// `visit_ident` walk, because `syn` never parses the macro body into `Ident`
/// nodes. This test looks at the token stream itself, so it also covers the
/// harder case the body walk cannot reach AT ALL: a `macro_rules!` DEFINITION
/// at file scope whose expansion would generate an accrual-reading endpoint.
/// There is no enclosing function for such a body, so `owner` is `None` and any
/// hit is a violation outright.
///
/// ONE file-scope macro legitimately names the accrual: the `thread_local!` that
/// DECLARES the stable cell. It is pinned by (macro path, identifier) below, and
/// a permitted body must additionally contain no entry-point attribute spelling,
/// so the allowance cannot be widened into a hiding place for a generated
/// `#[query]`.
const ACCRUAL_FILE_SCOPE_MACROS: &[(&str, &str, &str)] = &[(
    "thread_local",
    "PENDING_FEE_ACCRUAL_CELL",
    "the `thread_local!` that DECLARES the stable cell (MemoryId 23); it is the \
     storage itself, exports nothing, and cannot expand to an entry point",
)];

#[test]
fn ac8_no_macro_token_stream_outside_the_closure_names_the_accrual() {
    let scan = scan_accrual();
    let permitted: std::collections::BTreeSet<&str> =
        ACCRUAL_TOUCHERS.iter().map(|(n, _)| *n).collect();

    let violations: Vec<String> = scan
        .macro_hits
        .iter()
        .filter(|(owner, path, hits)| match owner {
            None => !ACCRUAL_FILE_SCOPE_MACROS
                .iter()
                .any(|(p, ident, _)| p == path && hits.len() == 1 && hits[0] == *ident),
            Some(f) => !permitted.contains(f.as_str()),
        })
        .map(|(owner, path, hits)| {
            format!(
                "{}!(…) in {} names {hits:?}",
                path,
                owner
                    .clone()
                    .unwrap_or_else(|| "<file scope — no enclosing fn>".to_string())
            )
        })
        .collect();

    assert!(
        violations.is_empty(),
        "AC-8 (SSA round 2, RED-1): the intra-window accrual is named inside a macro \
         token stream that the pinned closure does not permit. A macro body is opaque \
         to the identifier walk, so this is how an accrual read reaches a public \
         endpoint without any of the other AC-8 checks moving — the SSA's \
         `vec![read_fee_accrual()[0]…]` leak. Violations: {violations:?}. Pinned \
         closure: {ACCRUAL_TOUCHERS:?}. Permitted file-scope macros: \
         {ACCRUAL_FILE_SCOPE_MACROS:?}"
    );

    // NON-VACUITY. Every file-scope allowance must correspond to a macro that is
    // REALLY there: a stale allowance would silently permit a future macro that
    // reuses the name.
    for (path, ident, reason) in ACCRUAL_FILE_SCOPE_MACROS {
        assert!(
            scan.macro_hits
                .iter()
                .any(|(owner, p, hits)| owner.is_none()
                    && p == path
                    && hits.iter().any(|h| h == ident)),
            "AC-8: `{path}!` is allowed to name `{ident}` at file scope (\"{reason}\") \
             but no such macro was found in {POOL_SRC}. A stale allowance is a hole."
        );
    }

    // A permitted file-scope macro body must not contain an entry-point attribute
    // spelling, so the allowance cannot become a place to GENERATE a public read.
    let file = parse_pool();
    struct Bodies(Vec<(String, String)>);
    impl<'ast> Visit<'ast> for Bodies {
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            self.0.push((macro_path(node), node.tokens.to_string()));
            syn::visit::visit_macro(self, node);
        }
    }
    let mut bodies = Bodies(Vec::new());
    bodies.visit_file(&file);
    for (path, ident, _) in ACCRUAL_FILE_SCOPE_MACROS {
        for (p, body) in bodies
            .0
            .iter()
            .filter(|(p, b)| p == path && b.contains(ident))
        {
            let flat = body.replace(' ', "");
            assert!(
                !(flat.contains("#[query")
                    || flat.contains("#[update")
                    || flat.contains("::query")
                    || flat.contains("::update")),
                "AC-8: the permitted `{p}!` body naming `{ident}` contains an \
                 entry-point attribute spelling. The allowance exists only because \
                 that macro cannot expand to a public endpoint; it now can."
            );
        }
    }
}

/// The exported method names in the pool DID and the non-`testing` canister
/// entry points in the pool source must be the SAME SET.
///
/// The syntax walk above reasons about functions it can see. An endpoint
/// GENERATED by a macro has no `ItemFn` to walk, so it would be absent from
/// every source-side check while still being callable — and it must be declared
/// in the DID to be callable at all. This cross-check closes that gap from the
/// other side: a DID method with no ordinary source definition is a violation
/// regardless of what the syntax walk did or did not see, and a source entry
/// point missing from the DID means the DID-driven behavioural probe in
/// `r2_c30_fee_marker_tests.rs` is enumerating an incomplete interface.
#[test]
fn ac8_did_method_set_equals_the_source_entry_point_set() {
    let did = pool_did_method_names();
    assert!(
        did.len() > 40,
        "AC-8: the DID method parser found only {} methods; the pool publishes far \
         more. A parser that finds nothing cross-checks nothing.",
        did.len()
    );

    let src = production_entry_point_names();
    assert!(
        src.len() > 40,
        "AC-8: only {} non-testing entry points were found in {POOL_SRC}. Finding \
         none is RED, never a pass.",
        src.len()
    );

    let did_only: Vec<&String> = did.difference(&src).collect();
    let src_only: Vec<&String> = src.difference(&did).collect();

    assert!(
        did_only.is_empty(),
        "AC-8 (SSA round 2): {did_only:?} are declared in the pool DID but have NO \
         ordinary `#[query]`/`#[update]` function of that name in the production \
         source. A callable endpoint the syntax walk cannot see — a macro-generated \
         one, for instance — is exactly the case the AST closure alone cannot \
         exclude, so it is RED here."
    );
    assert!(
        src_only.is_empty(),
        "AC-8: {src_only:?} are production `#[query]`/`#[update]` entry points in \
         {POOL_SRC} but are NOT declared in the pool DID. The behavioural probe \
         enumerates its endpoints FROM the DID, so an undeclared endpoint is \
         unprobed — the probe's coverage claim is only as complete as this equality."
    );
}

/// The method names declared in the pool DID `service` block.
fn pool_did_method_names() -> std::collections::BTreeSet<String> {
    let did = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../canisters/shielded-pool/shielded_pool.did"
    ))
    .expect("the pool DID must be readable");
    let stripped: String = did
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let svc = stripped
        .find("service")
        .expect("the pool DID must declare a `service`");
    let open = stripped[svc..]
        .find("-> {")
        .expect("the service must declare a method block")
        + svc
        + 4;
    let chars: Vec<char> = stripped[open..].chars().collect();
    let mut depth = 1usize;
    let mut end = chars.len();
    for (i, c) in chars.iter().enumerate() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    let body: String = chars[..end].iter().collect();

    let mut out = std::collections::BTreeSet::new();
    let mut d = 0i32;
    let mut cur = String::new();
    for c in body.chars() {
        match c {
            '(' | '{' => d += 1,
            ')' | '}' => d -= 1,
            _ => {}
        }
        if c == ';' && d == 0 {
            let e = std::mem::take(&mut cur);
            let e = e.split_whitespace().collect::<Vec<_>>().join(" ");
            if let Some(colon) = e.find(" : ").or_else(|| e.find(':')) {
                let name = e[..colon].trim().to_string();
                if !name.is_empty()
                    && name.chars().all(|c| c.is_alphanumeric() || c == '_')
                    && e[colon..].contains("->")
                {
                    out.insert(name);
                }
            }
        } else {
            cur.push(c);
        }
    }
    out
}

/// The token text inside an attribute's parentheses, or "" if it has none.
fn attr_tokens(a: &syn::Attribute) -> String {
    match &a.meta {
        syn::Meta::List(l) => l.tokens.to_string(),
        _ => String::new(),
    }
}

/// Does this attribute list carry `#[cfg(feature = "testing")]`?
fn is_testing_gated(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        assert!(
            !a.path().is_ident("cfg_attr"),
            "AC-8: cfg_attr needs explicit resolver support"
        );
        if !a.path().is_ident("cfg") {
            return false;
        }
        match attr_tokens(a).replace(' ', "").as_str() {
            "test" | "feature=\"testing\"" => true,
            "not(feature=\"testing\")" => false,
            other => {
                panic!("AC-8: unsupported cfg {other}; extend the production census explicitly")
            }
        }
    })
}

/// The exported name of an entry point: `#[query(name = "x")]` wins over the
/// function's own name, as `ic_cdk` exports it.
fn exported_name(attrs: &[syn::Attribute], fn_name: &str) -> String {
    for a in attrs {
        let tail = a
            .path()
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if !matches!(tail.as_str(), "query" | "update") {
            continue;
        }
        let text = attr_tokens(a);
        if let Some(i) = text.find("name") {
            let rest = &text[i..];
            if let Some(open) = rest.find('"') {
                if let Some(close) = rest[open + 1..].find('"') {
                    return rest[open + 1..open + 1 + close].to_string();
                }
            }
        }
    }
    fn_name.to_string()
}

/// Every canister entry point present in a PRODUCTION build — i.e. not gated
/// behind `#[cfg(feature = "testing")]`, on the function or on any module
/// enclosing it.
fn production_entry_point_names() -> std::collections::BTreeSet<String> {
    production_entry_points_file(&parse_pool())
}
fn production_entry_points_file(file: &File) -> std::collections::BTreeSet<String> {
    struct Ep {
        out: std::collections::BTreeSet<String>,
        testing_depth: usize,
    }
    impl Ep {
        fn take(&mut self, name: &str, attrs: &[syn::Attribute]) {
            if is_entry_point(attrs).is_none() {
                return;
            }
            if self.testing_depth > 0 || is_testing_gated(attrs) {
                return;
            }
            let exported = exported_name(attrs, name);
            assert!(
                self.out.insert(exported.clone()),
                "AC-8: duplicate exported entry-point name {exported}"
            );
        }
    }
    impl<'ast> Visit<'ast> for Ep {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            let gated = is_testing_gated(&node.attrs);
            if gated {
                self.testing_depth += 1;
            }
            syn::visit::visit_item_mod(self, node);
            if gated {
                self.testing_depth -= 1;
            }
        }
        fn visit_item_fn(&mut self, node: &'ast ItemFn) {
            self.take(&node.sig.ident.to_string(), &node.attrs);
            syn::visit::visit_item_fn(self, node);
        }
        fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
            self.take(&node.sig.ident.to_string(), &node.attrs);
            syn::visit::visit_impl_item_fn(self, node);
        }
    }
    let mut ep = Ep {
        out: std::collections::BTreeSet::new(),
        testing_depth: 0,
    };
    ep.visit_file(&file);
    ep.out
}

// A real out-of-line module must remain inside both source privacy checks.
// Mutate the parsed source, not the production file, to model a newly added
// public accrual getter and prove both detectors see it across the module edge.
#[test]
fn ac8_expanded_payout_module_leak_mutation_is_detected() {
    let mut file = parse_pool();
    let module = file
        .items
        .iter_mut()
        .find_map(|item| match item {
            Item::Mod(m) if m.ident == "payout_retry" => Some(m),
            _ => None,
        })
        .expect("R-15 production module must be present");
    let children = &mut module.content.as_mut().expect("module must be expanded").1;
    children.push(syn::parse_quote! {
        #[query]
        fn r15_leak_mutation() -> u128 { vec![read_fee_accrual()[0]][0] }
    });
    let scan = scan_accrual_file(&file);
    assert!(scan.touchers.contains_key("r15_leak_mutation"));
    assert!(!ACCRUAL_TOUCHERS
        .iter()
        .any(|(name, _)| *name == "r15_leak_mutation"));
    assert!(scan
        .entry_points_touching
        .iter()
        .any(|(name, _)| name == "r15_leak_mutation"));
    assert!(scan
        .macro_hits
        .iter()
        .any(
            |(owner, _, hits)| owner.as_deref() == Some("r15_leak_mutation")
                && hits.iter().any(|name| name == "read_fee_accrual")
        ));
    let endpoints = production_entry_points_file(&file);
    assert!(endpoints.contains("r15_leak_mutation"));
    assert!(!pool_did_method_names().contains("r15_leak_mutation"));
}

#[test]
fn ac8_duplicate_accrual_function_names_are_rejected() {
    let file = syn::parse_file(
        "fn alias(){read_fee_accrual();} mod other { fn alias(){read_fee_accrual();} }",
    )
    .unwrap();
    assert!(std::panic::catch_unwind(|| scan_accrual_file(&file)).is_err());
}

#[test]
fn ac8_module_resolution_is_fail_closed_and_inherits_testing_cfg() {
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = std::env::temp_dir().join(format!(
        "r15-module-census-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let _fixture = Fixture(dir.clone());
    let root = dir.join("lib.rs");
    std::fs::write(&root, "mod absent;").unwrap();
    assert!(std::panic::catch_unwind(|| parse_source_tree(&root)).is_err());
    std::fs::write(&root, "mod child;").unwrap();
    std::fs::write(dir.join("child.rs"), "").unwrap();
    std::fs::create_dir(dir.join("child")).unwrap();
    std::fs::write(dir.join("child/mod.rs"), "").unwrap();
    assert!(std::panic::catch_unwind(|| parse_source_tree(&root)).is_err());
    std::fs::write(&root, "#[path=\"child.rs\"] mod child;").unwrap();
    assert!(std::panic::catch_unwind(|| parse_source_tree(&root)).is_err());
    std::fs::write(&root, "#[cfg(feature=\"testing\")] mod absent; #[cfg(test)] mod also_absent; #[cfg(not(feature=\"testing\"))] fn production() {} ").unwrap();
    let parsed = parse_source_tree(&root);
    assert_eq!(parsed.items.len(), 1);
    assert!(matches!(&parsed.items[0], Item::Fn(f) if f.sig.ident == "production"));
    // An inline testing-only parent must suppress an otherwise missing child.
    std::fs::write(
        &root,
        "#[cfg(feature=\"testing\")] mod hidden { mod missing; } ",
    )
    .unwrap();
    assert!(parse_source_tree(&root).items.is_empty());
    #[cfg(unix)]
    {
        std::fs::write(&root, "mod loopback;").unwrap();
        std::os::unix::fs::symlink(&root, dir.join("loopback.rs")).unwrap();
        assert!(std::panic::catch_unwind(|| parse_source_tree(&root)).is_err());
    }
}
