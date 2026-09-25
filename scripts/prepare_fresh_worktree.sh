#!/usr/bin/env bash
# O-12 — prepare a FRESH worktree to the point where ./run_gate.sh can run.
#
# WHY THIS EXISTS. A fresh worktree cannot run the gate. It is missing the
# built Wasms, the hand-provisioned predecessor fixtures, both ptau files, the
# circom witness helpers and three `npm ci` trees — and the failures that
# result look exactly like regressions. The observable signature of each
# preparation gap, and why it is NOT a regression, is documented in
# docs/FRESH_WORKTREE_GATE_PREP.md. That mapping is the part that saves the
# launch-week hour; this script is the part that fixes it.
#
# This is PREPARATION, not a gate leg. It does not change what ./run_gate.sh
# checks, does not run tests, and never re-pins anything. Gate composition is
# deliberately untouched (B-3/B-9/B-19 are post-cutover work).
#
#   ./scripts/prepare_fresh_worktree.sh            # report only (default)
#   ./scripts/prepare_fresh_worktree.sh --prepare  # run the reproducible steps
#
# Exit 0 = every derived prerequisite is present. Exit 1 = something is
# missing, and for each one the exact producing command is printed. Exit 2 =
# the script could not derive the prerequisite set at all, which is a failure
# of this script, not of the tree — and is never reported as "nothing missing".
#
# THE ARTIFACT SET IS DERIVED FROM THE TREE, NEVER HARDCODED. Records disagree
# about the count (41 vs 42), and any number written here would be wrong the
# moment a lane adds a fixture. The set comes from:
#   * run_gate.sh's own TEST_CANISTERS and PROD_PACKAGES arrays,
#   * the ("ENV_VAR", "file.wasm") table in integration-tests/build.rs, and
#   * every `*.wasm` string literal in the integration and canister test suites
#     (which is how the fixtures build.rs does NOT export are found).
# The derived count is printed as OUTPUT. A prerequisite this script can name
# but for which no committed recipe can be found is an ERROR — an unlisted
# reproducibility claim, not a pass.

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BOLD=$'\033[1m'; RESET=$'\033[0m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
PREPARE=0
for a in "$@"; do
  case "$a" in
    --prepare) PREPARE=1 ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a (see --help)" >&2; exit 2 ;;
  esac
done

die() { echo "${RED}prepare_fresh_worktree: $*${RESET}" >&2; exit 2; }

WASM_DIR="${CARGO_TARGET_DIR:-$ROOT/target}/wasm32-unknown-unknown/release"
VETKEYS_WASM_DIR="$ROOT/canisters/vetkeys/target/wasm32-unknown-unknown/release"

[[ -f run_gate.sh ]] || die "run_gate.sh not found — this must run from inside the repository"
[[ -f integration-tests/build.rs ]] || die "integration-tests/build.rs not found"

# ── 1. Derive the artifact universe ─────────────────────────────────────────

# (a) run_gate.sh's TEST_CANISTERS — the source of truth for the _test.wasm set
#     (ARCHITECTURE.md law 7(b)); read, never restated.
TEST_CANISTERS_LINE="$(grep -E '^TEST_CANISTERS=\(' run_gate.sh || true)"
[[ -n "$TEST_CANISTERS_LINE" ]] || die "run_gate.sh has no TEST_CANISTERS array — the _test.wasm set cannot be derived"
# shellcheck disable=SC2207
TEST_CANISTERS=($(sed -E 's/^TEST_CANISTERS=\(//; s/\).*$//' <<<"$TEST_CANISTERS_LINE"))
((${#TEST_CANISTERS[@]})) || die "TEST_CANISTERS parsed as empty"

# (b) run_gate.sh's PROD_PACKAGES — the packages the phase-2 build names.
# shellcheck disable=SC2207
PROD_PACKAGES=($(awk '/^PROD_PACKAGES=\(/{f=1;next} f&&/^\)/{exit} f{gsub(/#.*/,"");print}' run_gate.sh))
((${#PROD_PACKAGES[@]})) || die "PROD_PACKAGES parsed as empty"

# (c) the Wasm filenames integration-tests/build.rs resolves at compile time.
#     build.rs RESOLVES these paths; it does not build them — which is exactly
#     why a fresh worktree fails at runtime with a file-not-found.
# shellcheck disable=SC2207
BUILD_RS_WASMS=($(grep -oE '"[a-z0-9_]+\.wasm"' integration-tests/build.rs | tr -d '"' | sort -u))
((${#BUILD_RS_WASMS[@]})) || die "no Wasm names parsed out of integration-tests/build.rs"

# (d) every Wasm filename named directly by a test suite. This is how the
#     fixtures build.rs does NOT export are discovered — the d068 pre-hardening
#     trio among them, which run_gate.sh does not check either, and whose
#     absence surfaces as three panics that read like a red gate.
# shellcheck disable=SC2207
TEST_SOURCE_WASMS=($( { grep -rhoE '"[a-z0-9_]+\.wasm"' integration-tests canisters/*/tests 2>/dev/null | tr -d '"'
                        grep -rhoE '"[a-z0-9_]+_prod"|"[a-z0-9_]+_d068_prod"' canisters/*/tests 2>/dev/null \
                          | tr -d '"' | sed 's/$/.wasm/'
                      } | sort -u ))

# (e) every Wasm filename run_gate.sh itself checks for under $WASM_DIR. Some
#     fixtures are named ONLY here (the pre-VR-1 Vault, the pre-B.1 Upgrader,
#     merkle_tree_base_ef635ce) because their loaders read target/ directly with
#     no build.rs export. Loop-constructed fragments (`_test.wasm`,
#     `_base_f2d9ee7.wasm`) are dropped: they are patterns, not artifacts, and
#     the concrete names they expand to are already derived above.
# shellcheck disable=SC2207
GATE_WASMS=($(grep -oE '\$WASM_DIR/[a-z0-9_]+\.wasm|"[a-z0-9_]+_(pre|base)_[a-z0-9]+(_[a-z0-9]+)*\.wasm' run_gate.sh \
                | sed -e 's|.*/||' -e 's/"//g' | grep -vE '^_' | sort -u))

REQUIRED=()
for c in "${TEST_CANISTERS[@]}"; do REQUIRED+=("${c}_test.wasm"); done
REQUIRED+=("${BUILD_RS_WASMS[@]}" "${TEST_SOURCE_WASMS[@]}" "${GATE_WASMS[@]}")
# shellcheck disable=SC2207
REQUIRED=($(printf '%s\n' "${REQUIRED[@]}" | sort -u))

# DERIVATION SHORTFALL GUARD. If run_gate.sh names an artifact this script did
# not derive, the derivation is wrong — and a preparation tool that under-reports
# is worse than none: it says READY for a tree that cannot gate. This is an
# ERROR, never a warning, and never silently narrowed to the intersection.
DERIVED_COUNT=${#REQUIRED[@]}
SHORTFALL=()
for g in "${GATE_WASMS[@]}"; do
  printf '%s\n' "${REQUIRED[@]}" | grep -qx "$g" || SHORTFALL+=("$g")
done
if ((${#SHORTFALL[@]})); then
  echo "${RED}derivation shortfall: run_gate.sh checks artifacts this script did not derive:${RESET}" >&2
  printf '  %s\n' "${SHORTFALL[@]}" >&2
  die "the derived artifact set disagrees with run_gate.sh — fix the derivation, never the gate"
fi
echo "${BOLD}── O-12 fresh-worktree preparation ──${RESET}"
echo "  repo root         : $ROOT"
echo "  wasm dir          : $WASM_DIR"
echo "  TEST_CANISTERS    : ${#TEST_CANISTERS[@]} (${TEST_CANISTERS[*]})"
echo "  PROD_PACKAGES     : ${#PROD_PACKAGES[@]}"
echo "  derivation sources: build.rs ${#BUILD_RS_WASMS[@]} · test sources ${#TEST_SOURCE_WASMS[@]} · run_gate.sh ${#GATE_WASMS[@]}"
echo "  DERIVED Wasm set  : $DERIVED_COUNT artifacts (derived from the tree, not a stored count)"
echo

# ── 2. Recipe resolution ────────────────────────────────────────────────────
#
# SINGLE WRITER (Governance Surfaces Charter v1.0): where run_gate.sh already
# carries a producing command for an artifact, it is QUOTED from there rather
# than restated here — a second copy is a second thing to go stale. Only the
# artifacts run_gate.sh does not know about get a recipe of their own, and each
# of those points at the committed provenance document that owns it.

# Print the MISSING+=( … ) block in run_gate.sh that names $1, if any.
#
# Several gate entries are built from a LOOP variable (`${c}_base_f2d9ee7.wasm`),
# so the literal filename never appears. A second lookup therefore tries the
# distinctive fixture SUFFIX with the package prefix stripped, which is the part
# run_gate.sh does spell out. Matching on the suffix is deliberate: it is the
# token that identifies which predecessor the fixture is, and it is stable
# across the canisters that share one recipe.
gate_recipe() {
  local hit want
  for want in "$1" "$(sed -E 's/^.*(_(base|pre)_)/\1/' <<<"$1")"; do
    [[ -n "$want" ]] || continue
    hit="$(awk -v want="$want" '
      /MISSING\+=\(/ { buf=""; inblock=1; next }
      inblock && /^[[:space:]]*\)[[:space:]]*$/ { if (index(buf, want) > 0) { printf "%s", buf; exit } ; inblock=0; next }
      inblock { buf = buf $0 "\n" }
    ' run_gate.sh | sed -e 's/^"//' -e 's/"$//' -e '/^$/d')"
    [[ -n "$hit" ]] && { printf '%s\n' "$hit"; return 0; }
  done
  return 1
}

recipe_for() {
  local f="$1" c
  # Phase-1 testing-feature builds.
  for c in "${TEST_CANISTERS[@]}"; do
    if [[ "$f" == "${c}_test.wasm" ]]; then
      echo "cargo build --target wasm32-unknown-unknown --release -p $c --features testing"
      echo "    && cp \$WASM_DIR/$c.wasm \$WASM_DIR/${c}_test.wasm   (run_gate.sh phase 1/4)"
      return 0
    fi
  done
  # Phase-2 production builds: the filename is the package's own artifact.
  for c in "${PROD_PACKAGES[@]}"; do
    if [[ "$f" == "${c//-/_}.wasm" || "$f" == "${c}.wasm" ]]; then
      echo "./run_gate.sh phase 2/4 builds it: cargo build --target wasm32-unknown-unknown --release -p $c"
      return 0
    fi
  done
  # Anything else is a hand-provisioned fixture. Prefer run_gate.sh's own text.
  local from_gate=""
  if from_gate="$(gate_recipe "$f")" && [[ -n "$from_gate" ]]; then
    echo "run_gate.sh already carries the recipe (quoted, not restated):"
    printf '%s\n' "$from_gate"
    return 0
  fi
  # Fixtures run_gate.sh does NOT check. Point at the committed provenance.
  case "$f" in
    *_pre_hardening_d068_prod.wasm)
      echo "d068 pre-hardening fixture — NOT checked by run_gate.sh (its absence is three"
      echo "    runtime panics reading \"fixture missing\", which look like a red gate)."
      echo "    Full recipe: canisters/vault/tests/fixtures/d068_canonical_v1.PROVENANCE.md"
      echo "    Shape: detached worktree at d068cd5, env -i 13-package release build, copy+rename."
      return 0 ;;
    stsh_token_base_115526d_measure_test.wasm)
      echo "./scripts/build_token_base_measure_wasm.sh   (recipe committed in the script itself)"
      return 0 ;;
    shielded_pool_pre_r15_test.wasm)
      echo "./scripts/build_pool_pre_r15_wasm.sh"
      return 0 ;;
  esac
  # A named prerequisite with no committed recipe is an unlisted reproducibility
  # claim: it passes forever on the machine that happens to hold the file.
  return 1
}

# ── 3. Check every derived artifact ─────────────────────────────────────────

MISSING_NAMES=(); MISSING_RECIPES=(); NO_RECIPE=()
for f in "${REQUIRED[@]}"; do
  # The workspace-EXCLUDED vetkeys crate builds into its OWN target directory.
  # Looking for its fixtures under the workspace target would report them
  # missing forever, which is the fail-open of a preparation tool: a wrong path
  # is indistinguishable from a real gap.
  if [[ "$f" == *vetkeys* ]]; then
    [[ -f "$VETKEYS_WASM_DIR/$f" ]] && continue
  else
    [[ -f "$WASM_DIR/$f" ]] && continue
  fi
  MISSING_NAMES+=("$f")
  if r="$(recipe_for "$f")"; then
    MISSING_RECIPES+=("$r")
  else
    MISSING_RECIPES+=("NO COMMITTED RECIPE FOUND")
    NO_RECIPE+=("$f")
  fi
done
FOUND_COUNT=$(( DERIVED_COUNT - ${#MISSING_NAMES[@]} ))
echo "  present           : $FOUND_COUNT / $DERIVED_COUNT"

# ── 4. Non-Wasm prerequisites ───────────────────────────────────────────────
#
# Each is checked by run_gate.sh too; the point of repeating the CHECK (not the
# recipe) is that this script can run them, and that a reader preparing a
# machine sees the whole set in one place before a 40-minute gate starts.

OTHER_MISSING=(); OTHER_RECIPES=()
need() { # need <test-expression-result> <label> <recipe>
  [[ "$1" == "ok" ]] && return 0
  OTHER_MISSING+=("$2"); OTHER_RECIPES+=("$3")
}
t() { eval "$1" && echo ok || echo no; }

need "$(t '[[ -f circuits/ptau/powersOfTau28_hez_final_15.ptau ]]')" \
  "circuits/ptau/powersOfTau28_hez_final_15.ptau (power-15 Hermez ptau; UNTRACKED by design)" \
  "just download-ptau"
need "$(t '[[ -f circuits/ptau/pot14_final.ptau || -f circuits/build/pot14_final.ptau ]]')" \
  "pot14_final.ptau (dev trusted-setup ptau)" \
  "just download-ptau && just setup-groth16"
need "$(t '[[ -f circuits/build/spend_js/generate_witness.js && -f circuits/build/spend_js/witness_calculator.js ]]')" \
  "circuits/build/spend_js/{generate_witness,witness_calculator}.js (circom witness helpers; gitignored)" \
  "just compile-circuit   (then run_gate.sh compares spend.wasm before copying the helpers)"
need "$(t '[[ -d circuits/node_modules/circomlibjs ]]')" \
  "circuits/node_modules (circuits JS gate leg 5/5)" "npm ci --prefix circuits"
need "$(t '[[ -d wallet/node_modules ]]')" \
  "wallet/node_modules (wallet vitest leg)" "npm ci --prefix wallet"
need "$(t '[[ -d wallet/src/wasm ]]')" \
  "wallet/src/wasm (wasm-pack output the wallet suite imports)" \
  "npm ci --prefix wallet && npm run --prefix wallet build:wasm"
need "$(t '[[ -d website/solvency-status/node_modules ]]')" \
  "website/solvency-status/node_modules (D-4 website gate leg)" \
  "npm ci --prefix website/solvency-status"
need "$(t '[[ -f "$VETKEYS_WASM_DIR/stsh_vetkeys.wasm" ]]')" \
  "canisters/vetkeys Wasm (workspace-EXCLUDED crate; invisible to cargo --workspace)" \
  "cargo build --manifest-path canisters/vetkeys/Cargo.toml --target wasm32-unknown-unknown --release --locked"
need "$(t '[[ -f "$VETKEYS_WASM_DIR/vetkeys_pre_repin_67dbc40_test.wasm" ]]')" \
  "vetkeys_pre_repin_67dbc40_test.wasm (real over-capacity predecessor)" \
  "see the recipe run_gate.sh prints for it (annotated tag vetkeys/pre-repin-v1)"

# ── 5. Report ───────────────────────────────────────────────────────────────

report() {
  local i=0
  if ((${#MISSING_NAMES[@]})); then
    echo
    echo "${BOLD}${RED}MISSING Wasm artifacts (${#MISSING_NAMES[@]}):${RESET}"
    for i in "${!MISSING_NAMES[@]}"; do
      echo "  ${YELLOW}${MISSING_NAMES[$i]}${RESET}"
      printf '      %s\n' "${MISSING_RECIPES[$i]}"
    done
  fi
  if ((${#OTHER_MISSING[@]})); then
    echo
    echo "${BOLD}${RED}MISSING non-Wasm prerequisites (${#OTHER_MISSING[@]}):${RESET}"
    for i in "${!OTHER_MISSING[@]}"; do
      echo "  ${YELLOW}${OTHER_MISSING[$i]}${RESET}"
      echo "      ${OTHER_RECIPES[$i]}"
    done
  fi
  if ((${#NO_RECIPE[@]})); then
    echo
    echo "${BOLD}${RED}NO COMMITTED RECIPE (${#NO_RECIPE[@]}) — unlisted reproducibility claims:${RESET}"
    printf '  %s\n' "${NO_RECIPE[@]}"
    echo "  A fixture wired only through build.rs or a test literal, with no committed"
    echo "  recipe, passes forever on the machine that built it and can be produced"
    echo "  nowhere else. Treat this as a finding, not as noise."
  fi
}

# ── 6. --prepare: run the steps that are genuinely reproducible here ─────────
#
# The two cargo phases and the three npm installs are reproducible from the
# tree. The hand-provisioned predecessor fixtures are NOT: each is a build of a
# DIFFERENT, older commit, and rebuilding one from current source would make
# the test that consumes it vacuous (the self-inherited-fixture class). Those
# are always reported, never silently synthesised.
if ((PREPARE)); then
  echo
  echo "${BOLD}── --prepare: building what this tree can produce ──${RESET}"
  echo "  phase 1/2: testing-feature Wasms (×${#TEST_CANISTERS[@]})"
  for c in "${TEST_CANISTERS[@]}"; do
    cargo build --target wasm32-unknown-unknown --release -p "$c" --features testing
    cp "$WASM_DIR/$c.wasm" "$WASM_DIR/${c}_test.wasm"
  done
  echo "  phase 2/2: production Wasms (×${#PROD_PACKAGES[@]}) — overwrites the plain names"
  PROD_ARGS=(); for p in "${PROD_PACKAGES[@]}"; do PROD_ARGS+=(-p "$p"); done
  cargo build --target wasm32-unknown-unknown --release "${PROD_ARGS[@]}"
  echo "  vetkeys (excluded crate, own manifest)"
  cargo build --manifest-path canisters/vetkeys/Cargo.toml \
    --target wasm32-unknown-unknown --release --locked
  for d in wallet website/solvency-status circuits; do
    [[ -d "$d/node_modules" ]] || { echo "  npm ci --prefix $d"; npm ci --prefix "$d"; }
  done
  echo
  echo "  re-running the derivation after preparation…"
  exec "$0"
fi

report
if ((${#MISSING_NAMES[@]} + ${#OTHER_MISSING[@]})); then
  echo
  echo "${BOLD}${RED}NOT READY${RESET} — ${#MISSING_NAMES[@]} Wasm and ${#OTHER_MISSING[@]} other prerequisite(s) missing."
  echo "Re-run with --prepare to build what this tree can produce; the predecessor"
  echo "fixtures above must be provisioned by their own recipes (they are builds of"
  echo "OLDER commits and a rebuild from current source would make their tests vacuous)."
  echo "Which failures are preparation gaps rather than regressions:"
  echo "  docs/FRESH_WORKTREE_GATE_PREP.md"
  exit 1
fi
echo
echo "${BOLD}${GREEN}READY${RESET} — all $DERIVED_COUNT derived Wasm artifacts and every non-Wasm"
echo "prerequisite are present. ./run_gate.sh can run. This script asserts PRESENCE;"
echo "run_gate.sh remains the only thing that asserts a verdict."
