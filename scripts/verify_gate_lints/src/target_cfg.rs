//! Production target atom set, captured LIVE from the pinned toolchain.
//!
//! CTO ruling `cto-ruling-r1-r3b-green-with-notes-2026-09-05`, addendum
//! 2026-09-05 (R-L V12 SSA RED-1). The brief V12 shipped a hand-written table
//! of "exactly seven" `target_*` keys. That table is FALSE: rustc reports more
//! (`target_abi`, `target_has_atomic`, `target_feature`, …), and several of the
//! extra keys are multi-valued. A hand-maintained table therefore cannot be
//! both exhaustive and correct, and the unknown-key hard error would fire on
//! perfectly ordinary source.
//!
//! The ruling replaces it: the production target atom set is **whatever
//! `rustc --print cfg --target wasm32-unknown-unknown` prints for the pinned
//! toolchain** (`rust-toolchain.toml`), captured at run time. Multi-valued keys
//! are sets. A `target_*` key rustc does not print is a hard error (exit 2).
//!
//! This is NOT "derive the target from the host". The `--target` triple is a
//! literal constant in this file; only the *atom values for that triple* come
//! from rustc. Substituting the host triple would require editing the literal
//! below, which is TCB residual #1 (the lint's own source), and is exactly the
//! mutation M2c-19 demonstrates the shipped code does not perform: this crate
//! contains no `std::env::consts` read and no `cfg!(target_arch` evaluation of
//! its own process.

use std::collections::{BTreeMap, BTreeSet};

/// The production build target. A literal constant — the one thing that is
/// never taken from the environment. `run_gate.sh` builds every canister with
/// exactly this triple (ARCHITECTURE.md law 7 phase 1/phase 2).
pub const PRODUCTION_TARGET: &str = "wasm32-unknown-unknown";

/// The atoms rustc prints for [`PRODUCTION_TARGET`], as a key -> value-set map.
///
/// Only `target_*` keys are retained. rustc also prints non-target atoms for
/// the bare invocation (`debug_assertions`, `panic="abort"`); those are not part
/// of this evaluator's atom vocabulary (brief §3 S2: `test`, `feature = "…"`,
/// `target_*`) and an item gated on one of them is an unknown-atom hard error,
/// not a silent guess.
#[derive(Clone, Debug, Default)]
pub struct TargetAtoms {
    pub map: BTreeMap<String, BTreeSet<String>>,
    /// The verbatim rustc stdout this map was built from. Quoted in the packet.
    pub raw: String,
}

impl TargetAtoms {
    /// True iff `key` is a key rustc printed AND `value` is one of its values.
    /// The caller is responsible for rejecting unknown keys BEFORE calling this
    /// (see [`TargetAtoms::knows`]) — this function never guesses.
    pub fn matches(&self, key: &str, value: &str) -> bool {
        self.map.get(key).map(|vs| vs.contains(value)).unwrap_or(false)
    }

    pub fn knows(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.map.keys()
    }

    /// Parse a `rustc --print cfg` stdout block. Split out from [`capture`] so
    /// the fixture tests can feed a synthetic block (including a host-triple
    /// block, M2c-19) without shelling out.
    pub fn from_rustc_stdout(raw: &str) -> Self {
        let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = match line.split_once('=') {
                // `key="value"` — strip the surrounding quotes rustc emits.
                Some((k, v)) => (k.trim(), v.trim().trim_matches('"').to_string()),
                // A bare atom (`debug_assertions`). Not a target key; dropped
                // below by the `target_` filter.
                None => (line, String::new()),
            };
            if !key.starts_with("target_") {
                continue;
            }
            map.entry(key.to_string()).or_default().insert(value);
        }
        TargetAtoms { map, raw: raw.to_string() }
    }

    /// The HOST atom set — what `rustc --print cfg` prints with NO `--target`.
    ///
    /// SSA landed-diff round 3, RED-7. The production `#[update]` census is a
    /// census of the WASM binary and must keep [`PRODUCTION_TARGET`]. The
    /// `bindings` stage asks a different question: is this bound test COMPILED
    /// by the command `run_gate.sh` actually runs? That command is
    /// `cargo test --workspace --locked --no-fail-fast` — no `--target`, so it
    /// builds for the HOST. Evaluating a test's `#[cfg(...)]` against the
    /// wasm32 atom map certified `#[cfg(target_arch = "wasm32")]` tests that
    /// `cargo test … -- --list` lists ZERO of.
    ///
    /// Like [`capture`], the values come from rustc, not from this process:
    /// this crate reads no `std::env::consts` and evaluates no `cfg!` of its
    /// own. The difference is only the absence of `--target`, which is what
    /// makes it the view `cargo test` compiles.
    pub fn capture_host(workspace_root: &std::path::Path) -> Result<Self, String> {
        let out = std::process::Command::new("rustc")
            .current_dir(workspace_root)
            .args(["--print", "cfg"])
            .output()
            .map_err(|e| format!("could not run `rustc --print cfg` (host): {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "`rustc --print cfg` (host) failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let raw = String::from_utf8_lossy(&out.stdout).to_string();
        let atoms = Self::from_rustc_stdout(&raw);
        if !atoms.knows("target_arch") {
            return Err(
                "`rustc --print cfg` (host) printed no target_arch key; refusing to evaluate \
                 any cfg predicate against an empty target map"
                    .to_string(),
            );
        }
        Ok(atoms)
    }

    /// Invoke the pinned toolchain. `rust-toolchain.toml` makes plain `rustc`
    /// the pinned one for any invocation rooted inside the workspace, so the
    /// command is run with `current_dir` set to the workspace root.
    pub fn capture(workspace_root: &std::path::Path) -> Result<Self, String> {
        let out = std::process::Command::new("rustc")
            .current_dir(workspace_root)
            .args(["--print", "cfg", "--target", PRODUCTION_TARGET])
            .output()
            .map_err(|e| format!("could not run `rustc --print cfg --target {PRODUCTION_TARGET}`: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "`rustc --print cfg --target {PRODUCTION_TARGET}` failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let raw = String::from_utf8_lossy(&out.stdout).to_string();
        let atoms = Self::from_rustc_stdout(&raw);
        if !atoms.knows("target_arch") {
            return Err(format!(
                "`rustc --print cfg --target {PRODUCTION_TARGET}` printed no target_arch key; \
                 refusing to evaluate any cfg predicate against an empty target map"
            ));
        }
        Ok(atoms)
    }
}
