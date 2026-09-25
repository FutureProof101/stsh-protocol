// R-3a AC-4 — `run_gates_from_strs` is not a public record-blind surface.
//
// THE DEFECT THIS LOCKS. `run_gates_from_strs` runs `gate_d` and
// `gate_v_pre_install` and NOTHING ELSE — no genesis-principal record, no
// GP0..GP6. While it was `pub`, any caller outside this crate could reach for
// it, get a green `Vec<CheckResult>`, and report "the genesis gates pass" from
// a surface that never looked at the record the roles are bound to. That is not
// a hypothetical: 49 call sites in this workspace were on it, and R-3 had to
// retarget several of them onto the record-bearing surface one by one.
//
// The fix is visibility, not documentation: dropping `pub` makes any surviving
// out-of-crate call site a COMPILE ERROR, so the workspace building at all is
// the migration's proof. This test locks the visibility itself, so a future
// `pub` restored "to make a test easier" is caught here rather than by whoever
// next audits the call graph.
//
// WHY IT PARSES THE SOURCE. A text grep for "pub fn run_gates_from_strs" is a
// text lock: a reformat, a `pub(crate)`, or an attribute between the keyword
// and the name defeats or falsely trips it. `syn` gives the real visibility of
// the real item.

// BINDING: B-R3A-STRING-API-PRIVATE

/// `true` iff the top-level `fn` named `name` has INHERITED (private)
/// visibility. Returns `bool` deliberately: `syn::Visibility` implements
/// neither `PartialEq` nor `Debug` under the `full` feature alone, and pulling
/// `extra-traits`/`printing`/`quote` in to compare or print it would be a
/// dependency added for an assertion's convenience.
fn fn_visibility(src: &str, name: &str) -> bool {
    let file = syn::parse_file(src).expect("lib.rs must parse as Rust");
    for item in &file.items {
        if let syn::Item::Fn(f) = item {
            if f.sig.ident == name {
                return matches!(f.vis, syn::Visibility::Inherited);
            }
        }
    }
    panic!("no top-level fn named `{name}` in lib.rs — the lock's subject moved or was renamed");
}

#[test]
fn r3a_run_gates_from_strs_is_not_pub() {
    let src = include_str!("../src/lib.rs");

    let blind_is_private = fn_visibility(src, "run_gates_from_strs");
    let dir_is_private = fn_visibility(src, "run_gates_on_dir");

    // Each side asserted individually, so a failure names WHICH one moved.
    assert!(
        blind_is_private,
        "`run_gates_from_strs` must NOT be `pub`: it runs gate_d and \
         gate_v_pre_install only, with no genesis-principal record and no GP0..GP6, \
         so a `pub` record-blind surface lets an out-of-crate caller report a green \
         genesis verdict from a run that never read the record"
    );
    assert!(
        !dir_is_private,
        "`run_gates_on_dir` must REMAIN `pub` — it is the record-bearing surface \
         callers are meant to use. If both went private the assert_ne! below would \
         still fire, but for the wrong reason"
    );

    // The property, as a discrimination: the two surfaces do not have the same
    // visibility. A change that made them agree — in either direction — is what
    // this lock exists to catch.
    assert_ne!(
        blind_is_private, dir_is_private,
        "the record-blind and record-bearing surfaces must not share a visibility"
    );
}
