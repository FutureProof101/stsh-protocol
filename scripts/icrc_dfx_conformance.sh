#!/bin/bash
# =============================================================================
# STSH ICRC-1/2 — dfx CLI conformance calls (BRIEF_ICRC_COMPATIBILITY_AUDIT §7.3)
# =============================================================================
# Lane 4 deliverable. Every call below must succeed WITHOUT --type raw or any
# manual Candid override; a call that needs a workaround is a Medium finding.
#
# USAGE:
#   ./icrc_dfx_conformance.sh <network> <token_canister_id> [recipient_principal]
#   e.g. ./icrc_dfx_conformance.sh local  stsh_token
#        ./icrc_dfx_conformance.sh ic     <mainnet-token-principal> <recipient>
#
# NOTE (execution environment): dfx 0.32 is GLIBC-broken in the WSL validation
# box, so this script is part of the DEFERRED-LIVE set — run it at the mainnet
# (or any working-replica) smoke test. It performs ONE update call per method
# class with amount 1 base unit; everything else is queries.
# =============================================================================
set -eu
NET="${1:?network (local|ic)}"
TOKEN="${2:?token canister id/name}"
RECIPIENT="${3:-aaaaa-aa}"   # override with a real principal for transfer tests

# A findings counter, not just an echo: `if ! …` swallows every failure, so
# without this the script exited 0 whatever happened and the operator's only
# signal was a line of output nobody was required to read.
FAILED=0

run() {
    echo
    echo "── $*"
    if ! dfx canister --network "$NET" call "$@"; then
        echo "*** FINDING: call failed or needed a workaround: $*"
        FAILED=1
    fi
}

echo "== ICRC-1 queries =="
run "$TOKEN" icrc1_name
run "$TOKEN" icrc1_symbol
run "$TOKEN" icrc1_decimals
run "$TOKEN" icrc1_fee
run "$TOKEN" icrc1_total_supply
run "$TOKEN" icrc1_minting_account
run "$TOKEN" icrc1_metadata
run "$TOKEN" icrc1_supported_standards
run "$TOKEN" icrc1_balance_of "(record { owner = principal \"$RECIPIENT\"; subaccount = null })"

echo "== ICRC-2 queries =="
run "$TOKEN" icrc2_allowance "(record { account = record { owner = principal \"$RECIPIENT\"; subaccount = null }; spender = record { owner = principal \"$RECIPIENT\"; subaccount = null } })"

echo "== ICRC-21 =="
run "$TOKEN" icrc21_canister_call_consent_message "(record { method = \"icrc1_transfer\"; arg = blob \"\"; user_preferences = record { language = null } })"

echo "== ICRC-1/2 updates (1 base unit; caller pays the live fee per call) =="
run "$TOKEN" icrc1_transfer "(record { to = record { owner = principal \"$RECIPIENT\"; subaccount = null }; amount = 1; fee = null; memo = null; created_at_time = null; from_subaccount = null })"
run "$TOKEN" icrc2_approve "(record { spender = record { owner = principal \"$RECIPIENT\"; subaccount = null }; amount = 1; expected_allowance = null; expires_at = null; fee = null; memo = null; created_at_time = null; from_subaccount = null })"

echo
echo "Done. Grep output for '*** FINDING' — none means the dfx CLI surface is clean."
exit "$FAILED"
