#!/bin/bash
# =============================================================================
# F-010 / EXT-DBR-002 — HARD candid:service gate (present-AND-non-empty else FAIL)
# =============================================================================
# ICRC-21 + interface-discovery tooling expect the `candid:service` custom
# metadata section on the deployed token. This script EXITS NON-ZERO when it is
# absent OR empty — closing the silent hole in embed_candid_metadata.sh, which
# returns 0 ("skip") on a missing artifact.
#
# Modes:
#   default            — verify the LOCAL token Wasm (pre-deploy gate) via ic-wasm.
#   VERIFY_ONCHAIN=1   — verify the DEPLOYED mainnet token canister via dfx.
#
# Never skips. Local mode requires TWO things (ic-wasm 0.9.11 caveat: the per-name
# `metadata candid:service` prints "Cannot find metadata …" to STDOUT with exit 0
# for an ABSENT section, so its output alone can't prove presence):
#   (a) the section is LISTED by `ic-wasm <wasm> metadata`  → present, not absent;
#   (b) the extracted DID is NON-WHITESPACE (sentinel filtered) → not an empty section.
# A missing tool, a missing artifact, an absent section, or an empty section all FAIL.
# Wired into the mainnet install flow after `dfx deploy` — see docs/A7_INSTALL_RUNBOOK.md
# (the old `just deploy-mainnet` recipe was deleted at 4dd9bca).
#
# ic-wasm >= 0.9.11 required.
#
# Usage: ./scripts/verify_candid_metadata.sh [repo_root]
# =============================================================================
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
IC_WASM="${IC_WASM:-ic-wasm}"
TOKEN_WASM="$ROOT/target/wasm32-unknown-unknown/release/stsh_token.wasm"

fail() { echo "FAIL (candid:service gate): $*" >&2; exit 1; }
nonblank() { [ -n "$(printf '%s' "$1" | tr -d '[:space:]')" ]; }

if [ "${VERIFY_ONCHAIN:-}" = "1" ]; then
    command -v dfx >/dev/null 2>&1 || fail "dfx not found — cannot verify on-chain candid:service"
    meta="$(dfx canister --network ic metadata stsh_token candid:service 2>/dev/null || true)"
    nonblank "$meta" || fail "on-chain stsh_token candid:service is MISSING or EMPTY"
    echo "OK: on-chain stsh_token carries a non-empty candid:service"
else
    command -v "$IC_WASM" >/dev/null 2>&1 || fail "ic-wasm not found (set \$IC_WASM) — cannot verify candid:service"
    [ -f "$TOKEN_WASM" ] || fail "token Wasm not built at $TOKEN_WASM — cannot verify candid:service (NO silent skip)"
    # (a) section PRESENT (listed) — the reliable present/absent signal.
    "$IC_WASM" "$TOKEN_WASM" metadata 2>/dev/null | grep -q "candid:service" \
        || fail "$TOKEN_WASM is MISSING the candid:service section (run scripts/embed_candid_metadata.sh / build via dfx)"
    # (b) extracted content real (non-empty; drop the 'Cannot find …' sentinel defensively).
    did="$("$IC_WASM" "$TOKEN_WASM" metadata candid:service 2>/dev/null || true)"
    case "$did" in *"Cannot find metadata"*) did="" ;; esac
    nonblank "$did" || fail "$TOKEN_WASM candid:service section is EMPTY"
    echo "OK: stsh_token.wasm carries a non-empty candid:service ($(printf '%s' "$did" | wc -c) bytes)"
fi
