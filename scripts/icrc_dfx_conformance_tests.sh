#!/bin/bash
# =============================================================================
# STSH — host-side harness for scripts/icrc_dfx_conformance.sh (R-10 item 4)
# =============================================================================
# Verifies (1) icrc_dfx_conformance.sh propagates failure and still exits 0 on a
# clean sweep, and (2) it is named in MAINNET_DEPLOYMENT.md's Gate C rehearsal
# step. `dfx` is stubbed, so this runs with no replica, no network and no dfx
# binary — which is the whole point: the script under test is permanently
# rehearsal-only (its assertion is about the dfx CLI's own Candid inference, a
# thing PocketIC bypasses entirely), so its exit-code behaviour would otherwise
# have nothing checking it until someone ran it on mainnet.
#
# Not gate-wired, deliberately (GATE_TOOL_CENSUS.toml, invoked_by_gate = false):
# run it by hand or from a review packet.
set -eu
cd "$(dirname "$0")/.."   # scripts/ -> repo root; runnable from any cwd

echo "== Stage 1: exit-code propagation =="
STUB_BIN="$(mktemp -d)"
trap 'rm -rf "$STUB_BIN"' EXIT

cat > "$STUB_BIN/dfx" <<'STUB'
#!/bin/bash
exit 1
STUB
chmod +x "$STUB_BIN/dfx"
OUT1="$(mktemp)"
if PATH="$STUB_BIN:$PATH" ./scripts/icrc_dfx_conformance.sh ic dummy dummy > "$OUT1" 2>&1; then
  CODE1=0
else
  CODE1=$?
fi
rm -f "$OUT1"
# Exactly 1 — the script's own FAILED value — not merely "nonzero". A 126 or
# 127 means the script was never executed (lost exec bit, bad interpreter), and
# accepting any nonzero code would let that environment failure read as proof
# the propagation works.
if [ "$CODE1" -ne 1 ]; then
  echo "RED: icrc_dfx_conformance.sh exited $CODE1 with every dfx call failing; expected 1" >&2
  exit 1
fi
echo "GREEN: exit code $CODE1 with a stubbed all-failing dfx"

cat > "$STUB_BIN/dfx" <<'STUB'
#!/bin/bash
echo '(record {})'
exit 0
STUB
chmod +x "$STUB_BIN/dfx"
OUT2="$(mktemp)"
if PATH="$STUB_BIN:$PATH" ./scripts/icrc_dfx_conformance.sh ic dummy dummy > "$OUT2" 2>&1; then
  CODE2=0
else
  CODE2=$?
fi
rm -f "$OUT2"
if [ "$CODE2" -ne 0 ]; then
  echo "RED: icrc_dfx_conformance.sh exited $CODE2 with every dfx call succeeding" >&2
  exit 1
fi
echo "GREEN: exit code 0 with a stubbed all-succeeding dfx"

echo "== Stage 2: rehearsal-time naming =="
if ! grep -q "icrc_dfx_conformance.sh" MAINNET_DEPLOYMENT.md; then
  echo "RED: MAINNET_DEPLOYMENT.md no longer names icrc_dfx_conformance.sh in its Gate C rehearsal-time checks" >&2
  exit 1
fi
echo "GREEN: MAINNET_DEPLOYMENT.md names icrc_dfx_conformance.sh"
