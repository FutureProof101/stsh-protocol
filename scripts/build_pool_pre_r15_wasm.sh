#!/usr/bin/env bash
# Exact, unmodified predecessor for R-15 real cross-Wasm migration evidence.
# Uses an immutable git archive and a separate build target; never cargo clean.
# Output is hash-checked before replacing the fixture consumed by the gate.
set -euo pipefail

BASE_SHA="9f7c81e7747860eeeeaae3a8a4f1aaa19a32340e"
EXPECTED_SHA="c692823ed72779972aa0bf2c7db0fd2ed90c9289449ccf89e5554f1c720069b5"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/target"
SOURCE="$(mktemp -d "$ROOT/target/r15-predecessor.XXXXXX")"
BUILD="$ROOT/target/r15-predecessor-build"
OUT="$ROOT/target/wasm32-unknown-unknown/release/shielded_pool_pre_r15_test.wasm"

git -C "$ROOT" archive "$BASE_SHA" | tar -x -C "$SOURCE"
env -i HOME="$HOME" PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    CARGO_TARGET_DIR="$BUILD" "$HOME/.cargo/bin/cargo" build \
    --manifest-path "$SOURCE/Cargo.toml" --target wasm32-unknown-unknown \
    --release -p shielded_pool --features testing --locked
ARTIFACT="$BUILD/wasm32-unknown-unknown/release/shielded_pool.wasm"
ACTUAL="$(sha256sum "$ARTIFACT" | cut -d" " -f1)"
if [[ "$ACTUAL" != "$EXPECTED_SHA" ]]; then
    echo "R-15 predecessor hash mismatch: expected $EXPECTED_SHA; actual $ACTUAL" >&2
    echo "Reproducing toolchain: rustc 1.95.0 (59807616e); cargo 1.95.0 (f2d3ce0bd)." >&2
    exit 1
fi
mkdir -p "$(dirname "$OUT")"
cp "$ARTIFACT" "$OUT"
printf 'R-15 predecessor source %s; retained archive directory %s\n' "$BASE_SHA" "$SOURCE"
sha256sum "$OUT"
