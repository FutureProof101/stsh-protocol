//! AC-6 — every package name the `justfile`'s loops DERIVE is a real workspace
//! member, and every `.did` destination it writes is the one `dfx.json` reads.
//!
//! E-5. `build-opt` and `gen-did` both loop over DIRECTORY names and used
//! `${canister//-/_}` as the package name. That is right for five of the six
//! and wrong for `token`, whose package is `stsh_token` — so the loop's first
//! iteration named `token.wasm`, which no build produces, and `gen-did` wrote
//! `canisters/token/token.did`, an orphan beside the `stsh_token.did` that dfx
//! actually loads. Neither failure is visible in the justfile's own text; both
//! are visible against `cargo metadata` and `dfx.json`, which is what this test
//! reads.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root is two levels above scripts/verify_gate_lints")
        .to_path_buf()
}

/// The DIRECTORY names each `for canister in …; do … done` loop iterates over,
/// parsed out of the justfile itself rather than restated here.
fn loop_directories(justfile: &str) -> Vec<Vec<String>> {
    justfile
        .lines()
        .filter_map(|l| {
            let t = l.trim();
            let rest = t.strip_prefix("for canister in ")?;
            let names = rest.split(';').next()?.trim();
            Some(names.split_whitespace().map(str::to_string).collect())
        })
        .collect()
}

/// The mapping the justfile's own `pkg=` line performs, applied here so the test
/// derives the same package names the recipe does.
fn pkg_of(dir: &str) -> String {
    if dir == "token" {
        "stsh_token".to_string()
    } else {
        dir.replace('-', "_")
    }
}

fn workspace_packages(root: &Path) -> Vec<String> {
    let out = std::process::Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .expect("cargo metadata");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    // A dependency-free scrape of `"name":"…"` from the packages array. The
    // crate deliberately does not depend on a JSON parser (its reviewed
    // dependency set is the TCB), and the field is unambiguous in this output.
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let mut names = Vec::new();
    let mut rest = text.as_str();
    while let Some(i) = rest.find("\"name\":\"") {
        rest = &rest[i + 8..];
        if let Some(j) = rest.find('"') {
            names.push(rest[..j].to_string());
            rest = &rest[j..];
        }
    }
    names
}

#[test]
fn every_justfile_loop_derived_package_is_a_workspace_member() {
    let root = workspace_root();
    let justfile = std::fs::read_to_string(root.join("justfile")).expect("justfile");
    let loops = loop_directories(&justfile);
    assert_eq!(loops.len(), 2, "build-opt and gen-did are the two loops: {loops:?}");
    let members = workspace_packages(&root);
    assert!(members.contains(&"stsh_token".to_string()), "sanity: {members:?}");

    for dirs in &loops {
        assert!(!dirs.is_empty());
        for dir in dirs {
            assert!(
                root.join("canisters").join(dir).is_dir(),
                "`{dir}` is iterated as a DIRECTORY name and must be one"
            );
            let pkg = pkg_of(dir);
            assert!(
                members.contains(&pkg),
                "the justfile derives package `{pkg}` from directory `{dir}`, which is not a \
                 workspace member — the recipe names an artifact no build produces"
            );
        }
    }

    // The unmapped derivation — what the recipe did before this lane — is
    // exactly what fails. Two derivations of the same directory, differing, with
    // differing membership.
    assert_ne!(pkg_of("token"), "token".replace('-', "_"));
    assert!(
        !members.contains(&"token".to_string()),
        "`token` is a DIRECTORY, not a package; a recipe that used it as a package name \
         named `token.wasm`, which no build produces"
    );

    // And the justfile really does carry the mapping, in both loops.
    assert_eq!(
        justfile.matches("if [ \"$canister\" = \"token\" ]; then pkg=stsh_token").count(),
        2,
        "both loops must map the directory to its package"
    );
}

/// The `.did` destination `gen-did` writes must be the path `dfx.json` reads.
/// A `.did` written beside the one dfx loads is worse than none: the file dfx
/// reads goes stale silently.
#[test]
fn gen_did_destination_is_the_path_dfx_reads() {
    let root = workspace_root();
    let justfile = std::fs::read_to_string(root.join("justfile")).expect("justfile");
    let dfx = std::fs::read_to_string(root.join("dfx.json")).expect("dfx.json");
    assert!(
        justfile.contains("> canisters/$canister/$pkg.did"),
        "gen-did must write the PACKAGE-stemmed name into the DIRECTORY"
    );
    assert!(
        dfx.contains("\"canisters/token/stsh_token.did\""),
        "dfx reads the package-stemmed name for the token canister"
    );
    assert!(
        !justfile.contains("${canister//-/_}.did"),
        "the unmapped destination writes canisters/token/token.did — an orphan beside \
         the file dfx actually loads"
    );
}
