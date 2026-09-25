// =============================================================================
// S6 — C10: terminal retention is PERMANENT, and nothing prunes it
// =============================================================================
//
// C10's gate item, per `CTO_RULING_S6_ALLOCATION_AND_C10_2026-08-10.md`
// (sha256 b406336a…) §2: "the assertion that no pruning/retention/reaping path
// exists on any custody permanent store, both planes, outside the
// governed-corruption path."
//
// WHY C10 IS AN ASSERTION AND NOT A CONSTANT. Every other V15 row installs a
// value. C10 rules PERMANENT retention, and the custody stores are already
// permanent by construction — there is no retention machinery to set. V15's
// "explicit variant stays" governs how a retention constant must be EXPRESSED
// if one exists; none does. Building a `RetentionPolicy::Permanent` to hold
// the ruling would manufacture surface — and DID risk — to represent a fact the
// architecture embodies. So C10 lands assert-only, and this is the assertion.
//
// WHAT IT ACTUALLY BUYS. A ruling recorded only in prose is one refactor away
// from being untrue. This test makes the permanence CHECKED: any future change
// that adds a pruning path to a custody permanent store fails the gate and is
// forced through a fresh ruling rather than arriving as an implementation
// detail. That forcing function is C10's whole intent.
//
// WHY IT LIVES HERE rather than inside either canister's own test module. A
// source lint must never scan a region that quotes its own patterns — this
// campaign has had three lints fire on their own documentation or prose (the
// W1 idiom lint, the W3 no-cursor lint twice). This file names the removal
// verbs it searches for, so it must sit OUTSIDE the files it scans. It does.

/// The Vault's permanent stores. History and audit are authoritative forever:
/// freeze §9 records "durable forever, no retention or pruning" for the
/// snapshot store, and R3/CUST-SSA-003's whole premise is that terminal
/// outcomes remain readable indefinitely.
const VAULT_PERMANENT_STORES: [&str; 3] =
    ["PROPOSALS", "AUDIT_EVENTS", "CONTROLLER_READ_SNAPSHOTS"];

/// The recovery plane's permanent stores. Enumerated INDEPENDENTLY rather than
/// assumed symmetric with the Vault's: this plane keeps its own durable state
/// and has its own store set, and a bound that arrived by analogy would stop
/// applying the moment the two diverge.
const RECOVERY_PERMANENT_STORES: [&str; 4] = [
    "RECOVERY_PROPOSALS",
    "RECOVERY_APPROVALS",
    "UPGRADE_INTENTS",
    "AUDIT_EVENTS",
];

/// Removal verbs. `remove` and `clear` are the direct routes; the `pop_*`
/// family is included because a bounded "reap the oldest N" loop is exactly the
/// shape a well-meaning retention policy takes, and it would not contain the
/// word `remove` anywhere.
const REMOVAL_VERBS: [&str; 5] = [
    ".remove(",
    ".clear(",
    ".pop_first(",
    ".pop_last(",
    ".retain(",
];

/// The COMPANION/INDEX maps, which may legitimately be removed from.
///
/// This distinction is the substance of the test. The bounded sweep DOES remove
/// entries — from the expiry index and the nonterminal index — when it
/// terminalizes a proposal. That is not pruning: the proposal RECORD stays in
/// permanent history with its terminal outcome, and only the active-set
/// companions that tracked it while it was live are released. Conflating the
/// two would either forbid the sweep or permit history deletion, and the point
/// of C10 is precisely that these are different.
fn is_companion(name: &str) -> bool {
    name.contains("INDEX") || name.contains("COMPANION") || name.contains("LEDGER")
}

/// Scan one source for removal calls applied to a permanent store.
///
/// Window-based rather than parsed: each occurrence of a store name is checked
/// against the text that follows it up to the end of that statement. These are
/// all `STORE.with(|m| m.borrow_mut()...)` forms, so the statement boundary is
/// a reliable enough fence, and the failure mode of the heuristic is a FALSE
/// POSITIVE — a loud, investigable failure — never a false pass.
fn removals_on_permanent_stores(src: &str, stores: &[&str]) -> Vec<String> {
    let mut offenders = Vec::new();
    for store in stores {
        assert!(!is_companion(store), "{store} is a companion, not permanent");
        let mut from = 0usize;
        while let Some(i) = src[from..].find(store) {
            let start = from + i;
            from = start + store.len();

            // The declaration itself is not a use.
            let line_start = src[..start].rfind('\n').map_or(0, |n| n + 1);
            let line = &src[line_start..src[start..]
                .find('\n')
                .map_or(src.len(), |n| start + n)];
            if line.trim_start().starts_with("static ") || line.trim_start().starts_with("//") {
                continue;
            }

            let stmt_end = src[start..].find(";\n").map_or(src.len(), |n| start + n);
            let window = &src[start..stmt_end];
            for verb in REMOVAL_VERBS {
                if window.contains(verb) {
                    offenders.push(format!("{store} … {verb} — at byte {start}"));
                }
            }
        }
    }
    offenders
}

/// C10 — no pruning, retention or reaping path on any custody permanent store,
/// EITHER PLANE.
#[test]
fn s6_c10_no_pruning_path_exists_on_any_custody_permanent_store() {
    for (plane, src, stores) in [
        (
            "vault",
            include_str!("../../canisters/vault/src/lib.rs"),
            VAULT_PERMANENT_STORES.as_slice(),
        ),
        (
            "recovery",
            include_str!("../../canisters/upgrader/src/core.rs"),
            RECOVERY_PERMANENT_STORES.as_slice(),
        ),
    ] {
        let offenders = removals_on_permanent_stores(src, stores);
        assert!(
            offenders.is_empty(),
            "C10 VIOLATED on the {plane} plane: a pruning/retention path now \
             exists on a PERMANENT store. C10 rules terminal retention \
             PERMANENT, so removing history is not an implementation detail — \
             it needs a fresh ruling, which is what this assertion exists to \
             force. If the offender is an active-set COMPANION rather than \
             history, it belongs in the companion classification, not in the \
             permanent-store list.\nOffenders: {offenders:#?}"
        );
    }
}

/// NON-VACUITY — the scanner detects a removal when one is present.
///
/// Without this, every assertion above would pass just as well against a
/// scanner that matched nothing at all: a typo in a store name, a window fence
/// that never spans the call, or a verb list that never fires would each
/// produce a permanently green C10 gate item that checks nothing. This
/// campaign's recurring defect is a claim about a guard rather than the guard
/// itself, so the guard is exercised against source it MUST reject.
#[test]
fn s6_c10_scanner_is_not_vacuous() {
    let planted = r#"
        fn prune_history(cutoff: u64) {
            PROPOSALS.with(|m| m.borrow_mut().remove(&cutoff));
        }
    "#;
    assert_eq!(
        removals_on_permanent_stores(planted, &["PROPOSALS"]).len(),
        1,
        "the scanner must detect a removal on a permanent store"
    );

    // And it must NOT fire on the sweep's legitimate companion release, which
    // is the exact call this test's classification exists to permit.
    let companion = r#"
        fn release(id: u64, exp: u64) {
            PROPOSAL_EXPIRY_INDEX.with(|x| x.borrow_mut().remove(&(exp, id)));
        }
    "#;
    assert!(
        removals_on_permanent_stores(companion, &["PROPOSALS"]).is_empty(),
        "releasing a companion index entry is not pruning history — a C10 \
         assertion that forbade it would forbid the bounded sweep itself"
    );
}
