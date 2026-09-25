#!/usr/bin/env bash
# =============================================================================
# stsh_token_base_115526d_measure_test.wasm — the AC-10 "before" fixture.
# =============================================================================
#
# RED-2 round 2 (SSA_LANDED_DIFF_R-1_V2_2026-09-05.md, CTO triage
# `cto-triage-ssa-landed-diff-round2-2026-09-05`).
#
# AC-10's earlier "before" side was cycles burned per update message on the base
# PRODUCTION Wasm, converted to instructions through a measured cycles-per-
# instruction slope. The SSA showed that conversion is not sound as an upper
# bound, and that the direct measurement disagrees with it by a factor of ~4.
# The ruling: measure DIRECTLY on both sides. Nothing derived.
#
# The base Wasm at 115526d has no instrumentation hook, so this script builds
# one that does: base token source, UNCHANGED, plus the two measurement wrappers
# from the fixed tree appended VERBATIM. Both sides of the comparison then run
# the same wrapper code (two `performance_counter(0)` reads and one call), so
# the wrapper's own cost is identical on both sides and cancels in the delta.
#
# Nothing else is changed: no dependency, no flag, no Cargo.lock edit. The
# wrappers are appended at crate scope, exactly as they appear in the fixed
# tree, and are `#[cfg(feature = "testing")]` so the shape matches too.
#
#   usage:  scripts/build_token_base_measure_wasm.sh            (from repo root)
#
# Output: target/wasm32-unknown-unknown/release/stsh_token_base_115526d_measure_test.wasm
# Consumed by: integration-tests/build.rs -> TOKEN_BASE_MEASURE_TEST_WASM
#              integration-tests/tests/r1_supply_integrity_tests.rs (AC-10)
set -euo pipefail

BASE_SHA="115526d3a2755b6b5c9ed1f5a0014e746cff8b57"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WT="${TMPDIR:-/tmp}/stsh-token-base-measure"
OUT="$ROOT/target/wasm32-unknown-unknown/release/stsh_token_base_115526d_measure_test.wasm"

rm -rf "$WT"
git -C "$ROOT" worktree prune
git -C "$ROOT" worktree add --detach "$WT" "$BASE_SHA" >/dev/null

# The two wrappers, byte-identical to the fixed tree's (canisters/token/src/lib.rs).
cat >> "$WT/canisters/token/src/lib.rs" <<'HOOKS'

// ── AC-10 measurement wrappers, appended to the BASE source by
//    scripts/build_token_base_measure_wasm.sh. Not part of 115526d. ──────────
#[cfg(feature = "testing")]
#[update]
fn measure_icrc1_transfer_instructions_for_test(args: TransferArgs) -> (u64, bool) {
    let before = ic_cdk::api::performance_counter(0);
    let ok = icrc1_transfer(args).is_ok();
    let after = ic_cdk::api::performance_counter(0);
    (after - before, ok)
}

#[cfg(feature = "testing")]
#[update]
fn measure_icrc2_transfer_from_instructions_for_test(args: TransferFromArgs) -> (u64, bool) {
    let before = ic_cdk::api::performance_counter(0);
    let ok = icrc2_transfer_from(args).is_ok();
    let after = ic_cdk::api::performance_counter(0);
    (after - before, ok)
}
HOOKS

( cd "$WT" && cargo build --target wasm32-unknown-unknown --release \
      -p stsh_token --features testing --locked )

mkdir -p "$(dirname "$OUT")"
cp "$WT/target/wasm32-unknown-unknown/release/stsh_token.wasm" "$OUT"
sha256sum "$OUT"

git -C "$ROOT" worktree remove --force "$WT"
