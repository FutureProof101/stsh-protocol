#!/bin/bash
# =============================================================================
# F-010 — embed candid:service metadata into cargo-built canister Wasms
# =============================================================================
# ICRC-21 explicitly recommends (and interface-discovery tooling expects) the
# `candid:service` custom section, so `dfx canister metadata <id> candid:service`
# returns the interface. dfx-driven builds embed it automatically via the
# `metadata` entries in dfx.json; PLAIN `cargo build` Wasms do NOT carry it.
#
# Run this AFTER `cargo build --target wasm32-unknown-unknown --release ...`
# and BEFORE installing a cargo-built Wasm anywhere that tooling will inspect
# (mainnet deploys through dfx do not need it).
#
# Requires ic-wasm (https://github.com/dfinity/ic-wasm):
#   cargo install ic-wasm    # or a release binary on PATH / $IC_WASM
#
# Usage: ./scripts/embed_candid_metadata.sh [repo_root]
# =============================================================================
set -eu
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
TARGET="$ROOT/target/wasm32-unknown-unknown/release"
IC_WASM="${IC_WASM:-ic-wasm}"

command -v "$IC_WASM" >/dev/null 2>&1 || {
    echo "ic-wasm not found (set \$IC_WASM or cargo install ic-wasm)"; exit 1;
}

# Validate the .did BEFORE handing it to ic-wasm. ic-wasm embeds whatever bytes
# it is given and performs no Candid parse, so a malformed (or simply wrong)
# .did is published as the canister's interface on a CLEAN EXIT — a zero status
# that proves nothing.
#
# The check is a REAL PARSE, delegated to the check_candid_did host binary in
# scripts/verify_genesis_manifest (that crate already depends on candid_parser).
# The structural delimiter check this replaces could not decide syntax: it
# accepted `service : { method : (nat) -> (nat) nonsense };`.
#
# Locating the helper: $CANDID_CHECK if set, else the crate's built binary under
# $ROOT/target/{release,debug}. A helper that is missing is a HARD FAILURE, not
# a skip — a skipped validation is the clean-exit-proves-nothing failure again.
CANDID_CHECK="${CANDID_CHECK:-}"
if [ -z "$CANDID_CHECK" ]; then
    for c in "$ROOT/target/release/check_candid_did" "$ROOT/target/debug/check_candid_did"; do
        [ -x "$c" ] && { CANDID_CHECK="$c"; break; }
    done
fi
[ -n "$CANDID_CHECK" ] && [ -x "$CANDID_CHECK" ] || {
    echo "candid validator not found: build it with" >&2
    echo "  cargo build --release --manifest-path scripts/verify_genesis_manifest/Cargo.toml --bin check_candid_did" >&2
    echo "or set \$CANDID_CHECK to the binary. Refusing to embed unvalidated candid." >&2
    exit 1
}
echo "candid validator: $CANDID_CHECK"

check_did() { # did_file label
    local did="$1" label="$2"
    "$CANDID_CHECK" "$did" || { echo "FAIL: $label: $did rejected by candid parser" >&2; return 1; }
}

embed() { # wasm_file did_file
    local wasm="$TARGET/$1" did="$ROOT/$2"
    [ -f "$wasm" ] || { echo "skip: $1 not built"; return 0; }
    check_did "$did" "$1" || return 1
    "$IC_WASM" "$wasm" -o "$wasm" metadata candid:service -f "$did" -v public
    echo "embedded candid:service into $1 ($("$IC_WASM" "$wasm" metadata | tr '\n' ' '))"
}

embed stsh_token.wasm     canisters/token/stsh_token.did
embed shielded_pool.wasm  canisters/shielded-pool/shielded_pool.did
embed staking.wasm        canisters/staking/staking.did
embed vesting.wasm        canisters/vesting/vesting.did
embed treasury.wasm       canisters/treasury/treasury.did
embed merkle_tree.wasm    canisters/merkle-tree/merkle_tree.did
embed nullifier_registry.wasm canisters/nullifier-registry/nullifier_registry.did
embed stsh_verifier.wasm  canisters/verifier/verifier.did
embed vault.wasm          canisters/vault/vault.did
embed upgrader.wasm       canisters/upgrader/upgrader.did
echo "done"
