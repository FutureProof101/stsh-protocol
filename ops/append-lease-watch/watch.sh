#!/usr/bin/env bash
# =============================================================================
# STSH append-lease watcher (P-ROOT / C-ROOT-1)
#
# Polls the CONTROLLER-GATED shielded-pool view `get_append_lease_owner`
# (owner, phase, generation, acquired_at_ns, phase_started_at_ns), applies
# per-phase age thresholds, and ALERTS ONLY.
#
#   - It NEVER mutates canister state and NEVER force-releases the lease —
#     there is no such endpoint, by design. Resolution is a human following
#     canisters/shielded-pool/APPEND_LEASE_RUNBOOK.md.
#   - It must run under an identity whose principal is the pool's stored
#     CONTROLLER (the operator identity); other callers are rejected.
#
# Usage:
#   POOL_CANISTER_ID=<id> [NETWORK=ic] [IDENTITY=operator] ./watch.sh
#   ./watch.sh --self-test     # offline parser check against representative
#                              # free/held candid-JSON replies (no dfx needed)
#
# Configuration (env, seconds unless noted):
#   POOL_CANISTER_ID   required (watch mode) — shielded-pool canister id/name
#   NETWORK            dfx network (default: ic)
#   IDENTITY           dfx identity to call with (default: current identity)
#   INTERVAL           poll interval               (default 60)
#   THRESH_SNAPSHOTTING          default 300   (5 min  — lost-callback shape)
#   THRESH_APPEND_IN_FLIGHT      default 300   (5 min  — lost-callback shape)
#   THRESH_RECONCILE_IN_FLIGHT   default 300   (5 min  — lost-callback shape)
#   THRESH_APPEND_UNKNOWN        default 900   (15 min — operator reconcile due)
#   THRESH_ROOT_PENDING          default 900   (15 min — operator roll-forward due)
#   WEBHOOK_URL        optional — POST a JSON alert {text: ...} (e.g. Slack)
#
# Alert lines are written to stdout prefixed with "ALERT" (machine-greppable);
# normal heartbeats are prefixed with "ok".
# =============================================================================
set -euo pipefail

# jq is required in EVERY mode (parsing); check before set -e can kill us
# mid-pipeline with an opaque error.
command -v jq >/dev/null 2>&1 || {
  echo "ALERT watcher-misconfig: jq not on PATH (required for reply parsing)" >&2
  exit 2
}

# ── Reply parsing (one door for the loop AND the self-test) ──────────────────
# dfx `--output json` renders the candid reply:
#   free lease → [null]        held lease → [ { owner, phase: {Variant:null},
#   generation, acquired_at_ns, phase_started_at_ns } ]  (nat64s as strings)
# parse_reply REPLY → prints "free" | "held <PHASE> <PHASE_STARTED_NS> <GEN>"
# | "unparseable".
parse_reply() {
  local reply="$1"
  local compact
  compact=$(printf '%s' "$reply" | tr -d '[:space:]')
  if [ "$compact" = "[null]" ] || [ "$compact" = "null" ]; then
    echo "free"
    return 0
  fi
  local phase started gen
  phase=$(printf '%s' "$reply" | jq -r '.. | objects | .phase? // empty | keys[0]' 2>/dev/null | head -1) || true
  started=$(printf '%s' "$reply" | jq -r '.. | objects | .phase_started_at_ns? // empty' 2>/dev/null | head -1 | tr -d '"_') || true
  gen=$(printf '%s' "$reply" | jq -r '.. | objects | .generation? // empty' 2>/dev/null | head -1 | tr -d '"_') || true
  if [ -z "${phase}" ] || [ -z "${started}" ]; then
    echo "unparseable"
    return 0
  fi
  echo "held ${phase} ${started} ${gen:-?}"
}

threshold_for_phase() {
  case "$1" in
    Snapshotting)               echo "${THRESH_SNAPSHOTTING:-300}" ;;
    AppendInFlight)             echo "${THRESH_APPEND_IN_FLIGHT:-300}" ;;
    ReconcileInFlight)          echo "${THRESH_RECONCILE_IN_FLIGHT:-300}" ;;
    AppendUnknown)              echo "${THRESH_APPEND_UNKNOWN:-900}" ;;
    AppendConfirmedRootPending) echo "${THRESH_ROOT_PENDING:-900}" ;;
    *)                          echo 0 ;; # unknown phase => alert immediately
  esac
}

# ── Self-test: run the parser against representative replies ─────────────────
if [ "${1:-}" = "--self-test" ]; then
  fail=0
  free_sample='[null]'
  held_sample='[
    {
      "owner": { "Spend": { "spend_id": "5" } },
      "phase": { "AppendUnknown": null },
      "generation": "3",
      "acquired_at_ns": "1750000000000000000",
      "phase_started_at_ns": "1750000600000000000"
    }
  ]'
  garbage_sample='{"unexpected": true}'

  r=$(parse_reply "$free_sample")
  [ "$r" = "free" ] || { echo "SELF-TEST FAIL: free sample → '$r' (expected 'free')"; fail=1; }

  r=$(parse_reply "$held_sample")
  [ "$r" = "held AppendUnknown 1750000600000000000 3" ] || {
    echo "SELF-TEST FAIL: held sample → '$r' (expected 'held AppendUnknown 1750000600000000000 3')"; fail=1; }

  r=$(parse_reply "$garbage_sample")
  [ "$r" = "unparseable" ] || { echo "SELF-TEST FAIL: garbage sample → '$r' (expected 'unparseable')"; fail=1; }

  t=$(threshold_for_phase AppendUnknown)
  [ "$t" = "900" ] || { echo "SELF-TEST FAIL: AppendUnknown threshold → '$t' (expected 900)"; fail=1; }
  t=$(threshold_for_phase SomeFuturePhase)
  [ "$t" = "0" ] || { echo "SELF-TEST FAIL: unknown phase threshold → '$t' (expected 0 = alert now)"; fail=1; }

  if [ "$fail" -eq 0 ]; then
    echo "self-test ok"
    exit 0
  fi
  exit 1
fi

# ── Watch mode ───────────────────────────────────────────────────────────────
POOL="${POOL_CANISTER_ID:?POOL_CANISTER_ID is required}"
NETWORK="${NETWORK:-ic}"
INTERVAL="${INTERVAL:-60}"
WEBHOOK_URL="${WEBHOOK_URL:-}"

IDENTITY_ARGS=()
if [ -n "${IDENTITY:-}" ]; then
  IDENTITY_ARGS=(--identity "$IDENTITY")
fi

command -v dfx >/dev/null 2>&1 || {
  echo "ALERT watcher-misconfig: dfx not on PATH" >&2
  exit 2
}

send_alert() {
  local msg="$1"
  echo "ALERT $msg"
  if [ -n "$WEBHOOK_URL" ]; then
    # Best-effort; a webhook failure must not kill the watcher.
    curl -fsS -m 10 -X POST -H 'Content-Type: application/json' \
      --data "{\"text\": \"[stsh append-lease] ${msg}\"}" "$WEBHOOK_URL" \
      >/dev/null 2>&1 || echo "ALERT webhook-delivery-failed"
  fi
}

while true; do
  # Controller-gated query.
  if ! REPLY=$(dfx canister "${IDENTITY_ARGS[@]}" --network "$NETWORK" \
        call --query --output json "$POOL" get_append_lease_owner '()' 2>&1); then
    send_alert "poll-failed: ${REPLY//$'\n'/ }"
    sleep "$INTERVAL"
    continue
  fi

  PARSED=$(parse_reply "$REPLY")
  case "$PARSED" in
    free)
      echo "ok lease-free $(date -u +%FT%TZ)"
      ;;
    unparseable)
      send_alert "unparseable-reply: ${REPLY//$'\n'/ }"
      ;;
    held\ *)
      read -r _ PHASE PHASE_STARTED_NS GENERATION <<<"$PARSED"
      NOW_NS=$(date +%s%N)
      AGE_S=$(( (NOW_NS - PHASE_STARTED_NS) / 1000000000 ))
      LIMIT_S=$(threshold_for_phase "$PHASE")
      if [ "$AGE_S" -ge "$LIMIT_S" ]; then
        send_alert "lease OVER-AGE: phase=${PHASE} age=${AGE_S}s threshold=${LIMIT_S}s generation=${GENERATION}. Follow canisters/shielded-pool/APPEND_LEASE_RUNBOOK.md — do NOT force-release (no such operation exists)."
      else
        echo "ok lease-held phase=${PHASE} age=${AGE_S}s (threshold ${LIMIT_S}s) $(date -u +%FT%TZ)"
      fi
      ;;
  esac

  sleep "$INTERVAL"
done
