#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  STSH — CANONICAL GATE RUNNER
# ─────────────────────────────────────────────────────────────────────────────
#
#  One command runs the COMPLETE gate:
#
#      ./run_gate.sh            # strict — the real gate
#      just gate                # same thing via the task runner
#
#  WHY THIS EXISTS
#
#  The workspace `cargo test` does NOT cover everything, in two ways that both
#  fail SILENTLY — the dangerous kind:
#
#   1. `canisters/vetkeys` is workspace-EXCLUDED (ic-cdk 0.16 vs 0.20 `links`
#      conflict). An excluded crate is invisible to `cargo test --workspace`:
#      its suite does not run, does not fail, and does not appear in the tally.
#      Before this script, it ran only if a human remembered a prose line in
#      `.ai-context.md`. "Green" could mean "vetkeys never ran."
#
#   2. Integration tests load canister Wasms from disk at RUNTIME
#      (integration-tests/build.rs resolves paths; it does NOT build them). Skip
#      the two-phase build and you either test a stale Wasm or hit a runtime
#      "file not found" that reads exactly like a regression and is not one.
#
#   3. Two JS packages sit outside cargo entirely and were, at different times,
#      enforced by nobody: `wallet` (closed by C-14) and
#      `website/solvency-status` (closed by D-4 ruling 3, 2026-08-26). The
#      website one mattered because CERTIFIED_SNAPSHOT_ENCODING.md declares a
#      THREE-ARTIFACT LOCKSTEP — canister encoder, integration parser, and the
#      page's `verify.ts` — and the third had no gate behind it.
#
#  This runner closes all three. It builds every artifact, verifies each one
#  exists before running anything, runs the workspace suite, the excluded
#  vetkeys suite, and both JS suites, and prints a per-suite summary with a
#  single overall verdict.
#
#  HOST PROVISIONING — the fresh-tree gap, stated rather than discovered:
#  a clean clone does NOT run this gate as-is. It needs, beyond the toolchain:
#    * the historical base Wasms and the circom helpers (recipe in Phase 2b/2c
#      below — this remains the documented gap);
#    * node + npm for BOTH JS legs (`wallet` also needs wasm-pack);
#    * `npm ci` from each package's committed lockfile — done in Phase 2c and
#      Phase 2d, never `npm install`, so the gate cannot drift on a resolver.
#  Every one of these fails LOUDLY through the consolidated Phase 3 MISSING list
#  and `die` (exit 1). None of them silently skips a leg.
#
#  DESIGN RULE: fail loud, never skip. Every missing prerequisite stops the run
#  and prints the exact command that produces it. A PARTIAL run is never
#  reported as a pass.
#
#  See ARCHITECTURE.md law #7 (two-phase build) and law #10 (WSL-only execution).
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
#  R-3b S4(i) — SELF-SANITISING PREAMBLE.  THE RE-EXEC LINE BELOW MUST BE THE
#  FIRST EXECUTABLE STATEMENT IN THIS FILE.  Do not move it, do not add a
#  statement above it.
#
#  WHY: everything else in this gate — the `builtin exit 1` terminators, the
#  whole-file ban list, the census's blocking-form grammar — reasons about text
#  INSIDE this file. A shell function exported by the PARENT process
#  (`exit(){ :; }; export -f exit`) is inherited BEFORE bash reads line 1, so no
#  grammar over this file's own text can see it, and every `|| die` in the gate
#  becomes fail-open while every static check still passes.
#
#  HOW (V2, after SSA_LANDED_DIFF_R-3b_V1_2026-09-05 RED-1). The re-exec is
#  UNCONDITIONAL and is keyed on an ARGV MARKER, not on inspected state.
#
#  The V1 design made the re-exec CONDITIONAL on four probes of live process
#  state (`builtin compgen -A function`, an `env` name-set comparison, a
#  BASH_ENV test, a BASH_FUNC_* grep). Every one of those probes was itself a
#  command word the parent could shadow: `builtin` is an ordinary command name,
#  and bash resolves a FUNCTION named `builtin` ahead of the builtin of that
#  name. A parent exporting
#
#      builtin() { case "$1" in exec|exit) return 0;; esac; command builtin "$@"; }
#      export -f builtin
#
#  neutered `builtin exec` (no re-exec happened at all) and `builtin exit`
#  (every `|| die` became fail-open) while leaving the gate text, the lint, the
#  committed data, the startup files, PATH, the shell binary and the toolchain
#  completely untouched. Reproduced by SSA, and reproduced again in this lane's
#  scratch experiment before the fix. THE LESSON: a check that must RUN in the
#  hostile environment in order to decide whether to LEAVE it is defeated by
#  shadowing the check.
#
#  So the decision is no longer a check. `[ "${1:-}" = "--stsh-sanitised" ]`
#  reads ARGV — which a parent cannot set without invoking the gate with that
#  literal argument — and everything else re-execs. There is no state to
#  inspect, no probe to shadow, and no path through this line that reaches the
#  gate body in an environment this script did not itself create with `env -i`.
#
#  The MARKER IS ARGV, NOT ENVIRONMENT. That distinction is the whole design:
#  the V1 comment's objection to a marker ("a parent that can export a hostile
#  function can export a hostile marker with equal ease") is true of an
#  ENVIRONMENT marker and false of an argv one. `export STSH_GATE_SANITISED=1`
#  in the parent is inert here — nothing reads the environment for the
#  decision. A parent that runs `./run_gate.sh --stsh-sanitised` DOES suppress
#  the re-exec; that is a deliberate act by whoever invokes the gate, is named
#  in the census TCB paragraph, and is caught in any case by the post-re-exec
#  assertion below, which is what makes the marker unprofitable rather than
#  merely awkward.
#
#  THE FOUR STATE CHECKS SURVIVE — AS AN ASSERTION, NOT AS THE TRIGGER. After
#  the marker is seen, the same four questions are asked of the process we are
#  actually running in, and a violation DIES. They can no longer be gamed into
#  skipping sanitation, because by the time they run sanitation has already
#  happened unconditionally; their only remaining job is to catch a sanitised
#  child that is somehow not clean (a hostile BASH_ENV startup file, a modified
#  `env`/`bash` binary, a parent that supplied the argv marker itself).
#
#  Every external command is invoked by ABSOLUTE PATH (/usr/bin/env, /bin/bash,
#  /usr/bin/cut, /usr/bin/sort, /usr/bin/tr, /bin/grep): a word containing a
#  slash is never subject to shell-function lookup. TCB RESIDUAL, graded NOTE:
#  `exec`, `[` and `test` in the re-exec line are shell builtins and therefore
#  have no absolute-path form. A parent that exports a FUNCTION named `exec`,
#  `[` or `test` can still intercept that one line. Those three names, plus
#  BASH_ENV/ENV startup files and a modified bash/env/coreutils binary, are the
#  named TCB — see scripts/GATE_TOOL_CENSUS.toml. CI runners MUST NOT set
#  BASH_ENV, and MUST NOT pass `--stsh-sanitised`.
#
#  The sanitised child's environment is exactly SEVEN names: CARGO_HOME HOME
#  PATH PWD RUSTUP_HOME SHLVL _ . PWD/SHLVL/_ are set by bash itself; the other
#  four are passed explicitly. OLDPWD is deliberately NOT passed — bash discards
#  an empty/non-directory OLDPWD, and under an argv marker there is no fixpoint
#  requirement that made V1 need it.
# ─────────────────────────────────────────────────────────────────────────────
[ "${1:-}" = "--stsh-sanitised" ] || exec /usr/bin/env -i HOME="$HOME" PATH="$PATH" CARGO_HOME="${CARGO_HOME:-}" RUSTUP_HOME="${RUSTUP_HOME:-}" /bin/bash --noprofile --norc "$0" --stsh-sanitised "$@"
builtin shift
# ── POST-RE-EXEC ASSERTION (not the trigger; see above) ──────────────────────
__stsh_gate_allow="CARGO_HOME HOME PATH PWD RUSTUP_HOME SHLVL _"
__stsh_gate_dirty=""
[ -n "$(builtin compgen -A function)" ] && __stsh_gate_dirty="$__stsh_gate_dirty (a)a-shell-function-exists"
[ "$(/usr/bin/env | /usr/bin/cut -d= -f1 | LC_ALL=C /usr/bin/sort | /usr/bin/tr '\n' ' ')" \
  != "$(builtin printf '%s\n' $__stsh_gate_allow | LC_ALL=C /usr/bin/sort | /usr/bin/tr '\n' ' ')" ] \
  && __stsh_gate_dirty="$__stsh_gate_dirty (b)environment-name-set-differs"
[ -n "${BASH_ENV+x}" ] && __stsh_gate_dirty="$__stsh_gate_dirty (c)BASH_ENV-is-set"
/usr/bin/env | /bin/grep -q '^BASH_FUNC_' && __stsh_gate_dirty="$__stsh_gate_dirty (d)BASH_FUNC_-export-present"
if [ -n "$__stsh_gate_dirty" ]; then
  builtin printf '%s\n' "GATE ABORTED: post-sanitisation assertion failed:$__stsh_gate_dirty" >&2
  builtin printf '%s\n' "The gate re-exec'd under \`/usr/bin/env -i /bin/bash --noprofile --norc\` and the resulting process is STILL not clean. Do not re-run until this is understood: a BASH_ENV/ENV startup file, a modified bash/env/coreutils binary, or a parent that invoked this script with \`--stsh-sanitised\` itself are the candidates. All three are named TCB residuals." >&2
  builtin exit 1
fi
builtin unset __stsh_gate_allow __stsh_gate_dirty

# NOTE: deliberately not `set -e` — we want to run every stage and summarise,
# rather than dying at the first failing suite. Failures are tracked explicitly.
set -uo pipefail

GATE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$GATE_ROOT" || exit 1
# shellcheck disable=SC1091
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

MODE="strict"
case "${1:-}" in
  --partial) MODE="partial" ;;
  --help|-h)
    sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0 ;;
  "") ;;
  *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
esac

# R-3b S4(h): the terminating statement is `builtin exit 1`, NOT bare `exit 1`.
# Bash resolves a shell FUNCTION ahead of a builtin of the same name, so a
# function named `exit` — defined anywhere whose definition reaches this call —
# would make a bare `exit 1` return control with $? == 0 and turn every `|| die`
# in the gate fail-open, while every text-level check still passed. `builtin`
# looks its argument up ONLY among shell builtins; the function-lookup step is
# skipped entirely, so no definition anywhere can intervene.
die() { echo; echo "${RED}${BOLD}GATE ABORTED${RESET}: $*" >&2; builtin exit 1; }

# W3 3-1 §2.5: an early blocking check must reach the CANONICAL VERDICT line,
# not just exit nonzero somewhere above it. The VERDICT block is the only truth
# anyone reads out of this script; a check that fails outside it is a check that
# can be missed. `die` aborts before the results section, so the two candid
# checks below use this instead — same blocking behaviour, but the failure is
# stated where the verdict is read.
verdict_fail() {
  echo
  echo "${BOLD}═══ VERDICT ═══${RESET}"
  echo "${RED}${BOLD}GATE FAILED${RESET} — $*"
  # R-3b S4(h): `builtin exit`, never bare `exit` — see the note on `die` above.
  builtin exit 1
}

# ── Law #10: WSL-only ────────────────────────────────────────────────────────
case "$GATE_ROOT" in
  /mnt/*) die "repo is on a Windows mount ($GATE_ROOT). Law #10 requires WSL-native execution." ;;
esac

LOG_DIR="$(mktemp -d)"
trap 'rm -rf "$LOG_DIR"' EXIT
WORKSPACE_LOG="$LOG_DIR/workspace.log"
VETKEYS_LOG="$LOG_DIR/vetkeys.log"
WALLET_LOG="$LOG_DIR/wallet_vitest.log"
WALLET_BUILD_LOG="$LOG_DIR/wallet_build.log"
# Fail-closed by construction (D-4 ruling 3): initialised NONZERO so an
# unset value — a leg that never ran — can never satisfy the verdict test.
WEBSITE_RC=1
WEBSITE_LOG="$LOG_DIR/website_vitest.log"
WEBSITE_BUILD_LOG="$LOG_DIR/website_build.log"
# Same fail-closed construction for the circuits leg (A6.6): seeded NONZERO so a
# leg that never ran can never satisfy the verdict test. The circuits JS suite is
# the ONLY harness that can execute the in-circuit value bound's own rejection
# vector, so a circuit change with no gated harness is not acceptable.
CIRCUITS_RC=1
CIRCUITS_LOG="$LOG_DIR/circuits.log"

echo "${BOLD}═══ STSH GATE ═══${RESET}"
echo "root:   $GATE_ROOT"
echo "commit: $(git rev-parse --short HEAD 2>/dev/null || echo '?') ($(git branch --show-current 2>/dev/null || echo '?'))"
echo "mode:   $MODE"
echo

# ── PocketIC ─────────────────────────────────────────────────────────────────
if [[ -z "${POCKET_IC_BIN:-}" ]]; then
  if command -v dfx >/dev/null 2>&1; then
    POCKET_IC_BIN="$(dfx cache show 2>/dev/null)/pocket-ic"
  fi
fi
[[ -n "${POCKET_IC_BIN:-}" && -x "$POCKET_IC_BIN" ]] || die \
"PocketIC binary not found.
  export POCKET_IC_BIN=\$(dfx cache show)/pocket-ic"
export POCKET_IC_BIN
echo "pocket-ic: $POCKET_IC_BIN"
echo

# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING LINT — MemoryId append-only rule (HARDENING V2 acceptance #4)
#
# Runs FIRST, before any build: it is seconds of work, and a violation means
# the tree must not be built at all. Recycling a MemoryId does not fail loudly
# at runtime — ic-stable-structures hands the new structure the retired
# region's bytes and the corruption is silent and durable. Refusing to build is
# the only reliable defence.
#
# Source of truth is the CODE; docs/MEMORY_ID_REGISTRY.md is the declared expectation —
# the canonical IN-REPO registry (git is truth, per CTO Phase 0 Ruling 1; the
# office copy is a mirror reconciled FROM it).
# ─────────────────────────────────────────────────────────────────────────────
echo "${BOLD}── Lint: MemoryId append-only registry check ──${RESET}"
if ! cargo run --release -q -p verify-memory-ids -- "$GATE_ROOT" ; then
  die "MemoryId registry lint FAILED — see the violations above.
       This is a blocking gate check (HARDENING V2 acceptance #4).
       Reconcile canisters/*/src against docs/MEMORY_ID_REGISTRY.md, and update the
       office mirror in the same pass."
fi
echo

# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING LINT — R-10: the TEST_CANISTERS comment must not restate a count,
# and must not omit a member of the array it introduces.
#
# A comment reading `THE <spelled-out count> test-feature canisters.` sat above
# an array of a different length for months.
# Nothing re-read it, so the prose drifted while the array grew, and a reader
# who trusted the comment built the wrong set. Prose that restates a fact the
# code already carries is a second source of truth with no lint behind it.
#
# The checks are orthogonal by design:
#   (i)  no spelled-out number, and no digit run, sitting within a few words of
#        a canister noun anywhere in this file — a count belongs to the array,
#        not to a comment above it;
#   (ii) every name the live TEST_CANISTERS array carries is mentioned in the
#        divider-delimited comment block immediately preceding the array's own
#        assignment line.
#
# Growing or shrinking the array trips neither check on its own; only a
# reintroduced numeral, or an actually-omitted member, does.
#
# `# COUNT-OK: <reason>` is the reviewed escape hatch for a genuine, non-drifting
# numeral elsewhere in the file. None exists today.
# ─────────────────────────────────────────────────────────────────────────────
echo "${BOLD}── Lint: TEST_CANISTERS comment carries no stale count and omits no array member (R-L) ──${RESET}"

ANTI_COUNT_RE='\b(one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|[0-9]+)\b([[:space:]]+[A-Za-z-]+){0,3}[[:space:]]+canisters?\b'
ARRAY_LINE_NO="$(grep -n '^TEST_CANISTERS=' run_gate.sh | head -1 | cut -d: -f1)"
if [ -z "$ARRAY_LINE_NO" ]; then
  verdict_fail "run_gate.sh has no ^TEST_CANISTERS= assignment line — this lint cannot
       locate the array it is meant to guard, and a lint that silently finds nothing
       to check is exactly the shape R-L forbids."
fi
COUNT_HITS="$(grep -inE "$ANTI_COUNT_RE" run_gate.sh \
  | grep -v "^${ARRAY_LINE_NO}:" \
  | grep -v 'COUNT-OK:' || true)"
if [ -n "$COUNT_HITS" ]; then
  verdict_fail "run_gate.sh restates a canister count in prose instead of deferring to the
       TEST_CANISTERS array (ARCHITECTURE.md law 7(b)); offending line(s):
$COUNT_HITS"
fi

# Membership: the comment block is isolated by the nearest PAIR of rule-divider
# lines before the assignment, so an unrelated mention of the same word
# elsewhere in the file cannot mask an omission in THIS block.
DIVIDERS_BEFORE="$(grep -n '^# \(─\)\{1,\}$' run_gate.sh | awk -F: -v n="$ARRAY_LINE_NO" '$1<n{print $1}')"
BLOCK_CLOSE="$(tail -n1 <<<"$DIVIDERS_BEFORE")"
BLOCK_OPEN="$(tail -n2 <<<"$DIVIDERS_BEFORE" | head -n1)"
if [ -z "$BLOCK_OPEN" ] || [ -z "$BLOCK_CLOSE" ] || [ "$BLOCK_OPEN" = "$BLOCK_CLOSE" ]; then
  verdict_fail "run_gate.sh's TEST_CANISTERS assignment is not preceded by a divider-delimited
       comment block — the membership check has nothing to read, which is a silent skip."
fi
COMMENT_BLOCK="$(sed -n "${BLOCK_OPEN},${BLOCK_CLOSE}p" run_gate.sh)"
ARRAY_MEMBERS="$(sed -n "${ARRAY_LINE_NO}p" run_gate.sh | sed -E 's/^TEST_CANISTERS=\(//; s/\)$//')"
for m in $ARRAY_MEMBERS; do
  if ! grep -q "$m" <<<"$COMMENT_BLOCK"; then
    verdict_fail "run_gate.sh's TEST_CANISTERS comment block does not mention '$m', which
         the TEST_CANISTERS array carries — every array member needs a named line in the
         preamble comment (ARCHITECTURE.md law 7(b))."
  fi
done
echo
# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING LINT — G-a: unmeasured safety claims (remediation lane R-L, §5 G-a)
#
# reviews/SWEEP_UNMEASURED_CLAIMS_V1 found 31 confirmed-unbacked normative cost
# claims in this tree, three of them Critical. A claim like "this path cannot
# drain cycles", written in a comment and believed thereafter, is load-bearing
# in exactly the way a test is — and unlike a test, nothing ever re-checks it.
#
# The rule: every line asserting a NORMATIVE property about a MACHINE COST
# (cycles, instructions, rate limits, exhaustion) must carry `MEASURED: <path
# or test name>` or `UNBACKED: <reason>`. There is NO #[allow]-style escape
# hatch, deliberately: when the pattern false-positives on prose the answer is
# a reviewed pattern edit, and when the claim is real the answer is UNBACKED.
#
# HONEST SCOPE, printed by the lint on every run: the automated guarantee is
# MARKER PRESENCE plus REFERENT EXISTENCE. It is NOT a proof that any
# measurement is true, nor that it measures the claim it is attached to. A
# MEASURED: pointing at a real test that does not exercise its claim is worse
# than no marker, and only a human read catches that.
#
# Runs before the build for the same reason the MemoryId lint does: it is
# seconds of work over the source, and needs no artifact.
# ─────────────────────────────────────────────────────────────────────────────
echo "${BOLD}── Lint: unmeasured safety claims (R-L G-a) ──${RESET}"
if ! cargo run --release -q -p verify-gate-lints -- claims "$GATE_ROOT" ; then
  die "unmeasured-claims lint FAILED — see the findings above.
       A NEW normative cost/rate claim carries no MEASURED:/UNBACKED: marker, or a
       MEASURED: referent names no file and no fn in the tree, or a baseline row in
       scripts/gate_lints/claims_baseline.toml has gone stale.
       Add the marker at the claim, or annotate it in the baseline with an honest
       reason. Do NOT widen scripts/gate_lints/claims_patterns.toml to make a real
       claim disappear — narrowing the pattern is only ever correct for prose."
fi
echo

# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING LINT — G-b: refused-call cycle ceilings (R-L §5 G-b)
#
# A rate-limited or floor-guarded endpoint has two cost paths and only one gets
# thought about. The REFUSED path is meant to be cheap — that is the whole point
# of a limiter in front of expensive work — and nothing here ever asserted it.
# A refusal costing nearly as much as the work it refuses is a CHEAPER attack,
# not a defence: the attacker no longer has to satisfy the precondition.
#
# This stage checks the OBLIGATION, not the measurement: every production-view
# #[update] that is marked (// RATE-LIMITED, // FLOOR-GUARDED) or structurally
# reaches a guard within three call levels must have a row in
# scripts/gate_lints/refused_call_ceilings.toml. The measurement itself is
# asserted by the ceiling TESTS, which read that file's literal and never a
# canister-crate constant.
#
# The census behind it is a syn walk with a REAL Boolean cfg evaluator over
# not/all/any and the atoms test / feature="…" / target_* — the target atoms
# captured live from `rustc --print cfg --target wasm32-unknown-unknown` on the
# pinned toolchain, never a hand-written table and never the host's own triple.
# Its third leg cross-checks each .did's update-method NAME SET against the
# walk's production-view result, so a macro-alias entrypoint cannot evade both
# the syntax walk and the marker census at once.
#
# KNOWN GAP, disclosed and NOT closed here (DID-MODE-01): a method whose .did
# mode disagrees with its source attribute evades this cross-check AND
# verify_did_exports, whose did_methods() returns names only. That is its own
# campaign item with its own dispatch.
# ─────────────────────────────────────────────────────────────────────────────
echo "${BOLD}── Lint: refused-call cycle ceilings (R-L G-b) ──${RESET}"
if ! cargo run --release -q -p verify-gate-lints -- refused-ceilings "$GATE_ROOT" ; then
  die "refused-call ceiling lint FAILED — see the findings above.
       Either a guarded production #[update] has no row in
       scripts/gate_lints/refused_call_ceilings.toml, or a .did declares an update
       method the source walk cannot see under any recognised #[update] spelling.
       Add a [[row]] with a MEASURED ceiling (ceil_100k(max + 3 x spread), samples recorded), or
       an explicit [[unguarded]] row with a reason. Never widen the census to make
       an endpoint disappear."
fi
echo

# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING LINT — G-c: binding-property registry (R-L §5 G-c)
#
# THE BINDING TEST IS THE EVIDENCE. Before this stage, "B-2 is bound" was a
# claim in an office document, and the repo held nothing that would notice if
# the test backing it were renamed, ignored, moved to a suite the gate does not
# run, or edited down to a single invocation that proves nothing.
#
# For every row in tests/BINDING_REGISTRY.toml the lint checks, structurally,
# that the named test exists, carries its BINDING: marker, invokes the bound
# entrypoint at least twice with DIFFERING arguments, asserts an inequality or
# rejection, is not #[ignore]d, and lives in a gate-invoked suite (checked by a
# CENSUS OF THIS FILE'S CONTENT — the invocation must appear at command position
# in a simple command, so commenting out the vetkeys leg, quoting it into an
# echo, or burying it in a here-document all turn this stage RED rather than
# silently orphaning a binding).
#
# The schema REFUSES an evidence-file or office-hash field outright rather than
# ignoring it: a binding proved by a document the gate cannot read is not proved
# in this repo.
# ─────────────────────────────────────────────────────────────────────────────
echo "${BOLD}── Lint: binding-property registry (R-L G-c) ──${RESET}"
if ! cargo run --release -q -p verify-gate-lints -- bindings "$GATE_ROOT" ; then
  die "binding registry lint FAILED — see the findings above.
       A registered binding's test is missing, unmarked, ignored, single-invocation,
       assertion-free, or lives in a suite this gate does not invoke — or an
       evidence-file/office-hash field was reintroduced into the registry schema.
       Fix the TEST. Deleting the registry row is not a fix."
fi
echo

# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING LINT — G-d: no silent skips (R-L §5 G-d)
#
# The defect class: a test or fixture loader that, on a branch testing whether a
# required fixture is present, returns without the outcome being distinguishable
# from a genuine pass. The suite goes green, the summary says the test ran, and
# nothing was checked. This is how a proof-verification suite can report success
# on a machine that has never had a proof.
#
# Structural, over #[test] fns and fixture-loader bodies, across seven committed
# syntax shapes. A NET, not a completeness proof — a skip dispatched through a
# dyn Trait custom check is a KNOWN GAP the lint prints on every run.
#
# Plus one narrow, separate rule in the same corpus: a bare #[ignore] with no
# reason is a violation. A disablement without a stated reason is indefinite by
# default.
# ─────────────────────────────────────────────────────────────────────────────
echo "${BOLD}── Lint: no silent skips (R-L G-d) ──${RESET}"
if ! cargo run --release -q -p verify-gate-lints -- no-skips "$GATE_ROOT" ; then
  die "no-skips lint FAILED — see the findings above.
       A test or fixture loader returns on an absent-precondition branch without the
       outcome being distinguishable from a pass, or a #[ignore] carries no reason.
       Make the loader FAIL LOUD, naming the missing file and the command that
       produces it. If the site predates this lint and another lane owns it, annotate
       it in scripts/gate_lints/no_skips_baseline.toml with a reason AND an owner —
       an unexplained exemption is the thing this lint exists to stop."
fi
echo

# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING LINT — S5B W7: superseded-citation inventory
#
# Amended R3 item 10 (A1_AMENDMENT_R3_ITEM10_V2, 878d685e…) SUPERSEDES the
# brief's item 10. The brief requires the citation inventory be GENERATED FROM
# THE TREE rather than enumerated by hand — the hand-written list in V1 was
# incomplete, missing production and test references alike — and that after
# repointing, ZERO references to the superseded item remain.
#
# This is that assertion. It is in the gate rather than a test because it must
# hold across the WHOLE tree (source, tests, docs, scripts), which no single
# crate's test can see.
# ─────────────────────────────────────────────────────────────────────────────
echo "${BOLD}── Lint: superseded R3.10 citation inventory (S5B W7) ──${RESET}"
# --exclude run_gate.sh: this lint's own message names the pattern it bans, so
# scanning itself is a guaranteed false positive. That is the FOURTH time in
# this change a source lint matched its own text (W1 idiom lint on its docs, W3
# no-cursor lint on its prose and then on unrelated pagination, §3 lint on its
# string literals) — including, here, in the enforcement of the rule written to
# prevent it. The rule stands and is worth restating: a lint must never scan a
# region that quotes its own patterns.
# SSA RF-4: --include=*.md added. The brief requires source, tests, DOCS and
# scripts; Markdown was excluded, so every doc citation of the superseded item
# was invisible to a lint whose whole purpose is finding them — and the docs are
# where a reader is most likely to follow one.
STALE_CITES=$(grep -rn "R3\.10" --include=*.rs --include=*.sh --include=*.toml --include=*.md \
  --exclude=run_gate.sh "$GATE_ROOT" 2>/dev/null || true)
if [ -n "$STALE_CITES" ]; then
  echo "$STALE_CITES"
  die "S5B W7: references to the SUPERSEDED R3 item 10 remain in the tree.
       They are correct citations to a requirement that no longer governs —
       amended item 10 (878d685e…) changed the MODEL from derived rebuildable
       caches to bounded authoritative companions, so a reader following one of
       these lands on the wrong contract. Repoint them to \"amended R3 item 10\"."
fi
echo

# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING LINT — custody manifest coverage gate (L0, freeze V6 §13.2a)
#
# Runs immediately after the MemoryId lint, before any build: it is seconds of
# work and a violation means the tree must not be built at all. Every candidate
# in D1∪D2∪D3∪D4∪D5 must appear exactly once in
# deployment/mainnet/custody_manifest.toml with a disposition; conflicting
# facts fail as FactConflict ONLY within the same semantic field and gate
# epoch; stale/mixed-epoch evidence fails as typed StaleEvidence (never a
# pass); absence fails only for declared-complete sources; D5 receipts
# bijective. (The §8 size-invariant half runs after the Wasm builds below.)
# ─────────────────────────────────────────────────────────────────────────────
echo "${BOLD}── Lint: custody manifest coverage gate ──${RESET}"
if ! cargo run --release -q -p verify-custody-manifest -- --coverage-only "$GATE_ROOT" ; then
  die "custody manifest coverage gate FAILED — see the violations above.
       This is a blocking gate check (freeze §13.2a). Reconcile
       deployment/mainnet/custody_manifest.toml against dfx.json /
       canister_ids.json / the evidenced sets."
fi
echo

# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING LINT — did-vs-exports equivalence + amount-boundary census (W3 3-1)
#
# Before this lane there was NO candid gate stage at all: verify_candid_metadata.sh
# checked only that stsh_token.wasm carried a non-empty candid:service, and its
# sole invocation was the mainnet deploy path in justfile:135 — never here. The
# embed pipeline embeds the tracked .did, so embedded-vs-tracked is circular; a
# real gate derives the interface from SOURCE and compares it to the .did.
#
# verify-did-exports is a STANDALONE crate (its own Cargo.toml + Cargo.lock, own
# `[workspace]`), invisible to `cargo test --workspace`, so its fixture suite is
# run explicitly here. A workspace member would have moved root Cargo.toml and
# Cargo.lock — both BUILD_INPUT_PATHS — for a host-side lint.
#
# No silent-skip path: a missing tool, an unparseable .did, an unrecognised
# attribute or cfg form, or a type the boundary traversal cannot follow all FAIL
# rather than return 0 (the embed_candid_metadata.sh return-0-skip hole is the
# named anti-pattern). justfile:135's VERIFY_ONCHAIN=1 invocation is unchanged.
# ─────────────────────────────────────────────────────────────────────────────
CANDID_TOOL="$GATE_ROOT/scripts/verify_did_exports/Cargo.toml"

echo "${BOLD}── Lint: did-vs-exports gate fixtures (W3 3-1) ──${RESET}"
if ! cargo test --manifest-path "$CANDID_TOOL" --locked -q ; then
  verdict_fail "the did-vs-exports gate's own fixture suite FAILED.
       The gate proves its failure modes with negative fixtures; if those do not
       hold, neither of the two checks below means anything."
fi
echo

# ── R-1 lint 1/3: mod ledger_maps visibility + cfg allowlist (S4(b)) ────────
# Source-only; no build dependency, so it runs here with the other host lints.
echo "${BOLD}── Lint: ledger_maps allowlist (R-1 S4(b)) ──${RESET}"
if ! cargo run --manifest-path "$CANDID_TOOL" --locked -q --bin verify_ledger_maps -- "$GATE_ROOT" ; then
  verdict_fail "ledger_maps allowlist lint FAILED — see the findings above.
       Every NON-PRIVATE item inside mod ledger_maps must have a matching row in
       canisters/token/ledger_maps_allowlist.toml, in BOTH the production and the
       testing view. A new visible item is a new reachable seam."
fi
echo

# ── R-1 lint 2/3: proc-macro dependency identity, split by edge (S4(b3)) ────
# A `cargo metadata` graph comparison — no source parsing, no dependency on the
# Phase-1/Phase-2 builds or the .d file — so it also runs before them.
echo "${BOLD}── Lint: proc-macro allowlists, DIRECT + TRANSITIVE (R-1 S4(b3)) ──${RESET}"
if ! cargo run --manifest-path "$CANDID_TOOL" --locked -q --bin verify_proc_macro_deps -- "$GATE_ROOT" ; then
  verdict_fail "proc-macro dependency allowlist FAILED — see the findings above.
       canisters/token/proc_macro_allowlist_direct.toml and
       proc_macro_allowlist_transitive.toml are REVIEWED data: a new proc-macro
       crate, a version bump, a checksum change, or a transitive→direct edge
       promotion changes them in the same reviewed commit, or the gate is red.
       Never regenerate-and-commit them."
fi
echo

# ── R-1 lint: the ICRC deviation register is a REGISTER (AC-15) ────────────
echo "${BOLD}── Lint: ICRC deviation register (R-1 AC-15) ──${RESET}"
if ! cargo run --manifest-path "$CANDID_TOOL" --locked -q --bin verify_icrc_deviation_register -- "$GATE_ROOT" ; then
  verdict_fail "ICRC deviation register lint FAILED — see the findings above.
       Every devNNN cited in canisters/ or integration-tests/ needs an entry in
       canisters/token/NOTE_A-3_icrc_deviation.md, and every entry's named
       binding test must exist in the file the entry names. Renaming a bound
       test without updating the register is what this catches."
fi
echo

echo "${BOLD}── Lint: did-vs-exports equivalence (W3 3-1 D1) ──${RESET}"
if ! cargo run --manifest-path "$CANDID_TOOL" --locked -q --bin verify_did_exports -- "$GATE_ROOT" ; then
  verdict_fail "did-vs-exports gate FAILED — see the findings above.
       Every in-scope canister in scripts/did_export_census.toml must declare
       exactly the query/update methods its source exports, both directions.
       Deliberate omissions belong in the census's dated exception section."
fi
echo

echo "${BOLD}── Lint: amount-boundary census, C4 rule 3 (W3 3-1 D2) ──${RESET}"
if ! cargo run --manifest-path "$CANDID_TOOL" --locked -q --bin verify_amount_boundaries -- "$GATE_ROOT" ; then
  verdict_fail "amount-boundary census FAILED — see the findings above.
       A raw u128/i128 is reachable from a public endpoint — directly, through a
       wrapper field, or through an install argument — without a reviewed
       allowlist entry. This is a STOP: a new raw-amount boundary requires
       CTO/SSA adjudication (C4 §4 rule 2). Do not add allowlist rows to clear it."
fi
echo

# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING — genesis principal POSTURE (remediation lane R-3, brief §6.1)
#
# Before this stage `verify_genesis_manifest` ran on NO gate invocation: it was
# written, tested, and never executed by the gate. It could not simply be
# invoked, either — the tool is fail-closed against the committed artifacts and
# stays RED until RR-1, so `verify_genesis_manifest || die` would have left the
# gate permanently red.
#
# `--posture` is the form that CAN be gated. It runs the full Gate-D + Gate-V +
# GP0..GP6 surface and asserts the DECLARED posture in
# deployment/mainnet/genesis_principals.toml:
#
#   rr1_performed = false  →  pass IFF every failing check is inside a CLOSED,
#                             EXACT-MATCH three-member allowed set: the named
#                             DP3 placeholder sites, GP1-pending-<ROLE> for a
#                             role with no in-repo value, and
#                             GP2-value-STAKING_CANISTER — that last one only
#                             while its own DP3 sites are also still failing.
#   rr1_performed = true   →  pass IF AND ONLY IF the observed failing set is
#                             EXACTLY EMPTY. Not "no failures are expected": an
#                             assertion over the actually-observed vector.
#
# `GP1-pending-input-populated-<ROLE>` — an install input already carrying a
# non-placeholder principal under an unresolved record entry — is NEVER in the
# allowed set, at any posture. It shares a textual prefix with
# `GP1-pending-<ROLE>`, which is exactly why membership is an exact-name set and
# never a `starts_with` test.
#
# The stage prints `GENESIS-POSTURE-STAGE:` on EVERY invocation, pass or fail.
# That marker is the only evidence that distinguishes "the stage ran and passed"
# from "the stage was never invoked" — a distinction no amount of grepping this
# file's own text can make. Do not remove or rename it without updating the
# self-test that asserts on it in the same diff.
#
# Flipping `rr1_performed` to `true` is a reviewed one-line change, after which
# this stage requires the whole genesis surface to be green.
# ─────────────────────────────────────────────────────────────────────────────
echo "${BOLD}── Lint: genesis principal posture (R-3) ──${RESET}"
if ! cargo run --release -q -p verify-genesis-manifest --bin verify_genesis_manifest -- "$GATE_ROOT/deployment/mainnet" --posture ; then
  verdict_fail "genesis PRINCIPAL-POSTURE gate FAILED — see the DISALLOWED list above.
       The observed failing set is outside what deployment/mainnet/genesis_principals.toml
       declares. A GP2-value-<ROLE> mismatch means a genesis input names a principal the
       record does not — that is the H-3 defect biting, not a manifest authoring bug: fix
       the input or the record, never the allowed set. A GP1-pending-input-populated-<ROLE>
       means an install input was filled while its record entry is still PENDING — an
       uncertified principal is already in the deploy payload. A GP6-record-pin failure
       means the record's bytes moved without the paired source edit: regenerate
       GENESIS_PRINCIPAL_RECORD_SHA256 LAST, after every other edit to the record."
fi
echo

# ─────────────────────────────────────────────────────────────────────────────
# The `TEST_CANISTERS` array below is the source of truth for which
# test-feature canisters exist and how many; do not restate a count in prose
# above it (ARCHITECTURE.md law 7(b) documents each entry's per-suite consumption):
#   shielded_pool  — pool_recovery / active_root_finality / privacy_query / …
#   treasury       — inject_inflight_proposal_for_test paths
#   stsh_token     — arith_hardening (P-ARITH), token_dedup_dos, smoke_alarm
#   merkle_tree    — pmrk_public_sync (P-MRK stable-map corruption hook)
#                    + Phase-1 cross-Wasm sentinel positive case
#   nullifier_registry — Phase-1 cross-Wasm sentinel positive case
#   vesting            — Phase-1 cross-Wasm sentinel positive case
#   staking            — Phase-2 cross-Wasm sentinel positive case
#                        (treasury doubles up: inflight injection + Phase-2 probe)
#   vault               — eager_cell_feature_isolation_tests (VAULT_TEST_WASM)
#   upgrader            — eager_cell_feature_isolation_tests (UPGRADER_TEST_WASM)
# Omit any one of them and its suites fail at runtime looking like regressions.
#
# nullifier_registry/vesting/staking carry ONLY a read-only
# `eager_cell_probe_for_test` query for the Phase-1/Phase-2 sentinel positive
# case; `testing` is off by default so it is absent from every production
# Wasm — enforced by eager_cell_feature_isolation_tests, not merely asserted.
# ─────────────────────────────────────────────────────────────────────────────
TEST_CANISTERS=(shielded_pool treasury stsh_token merkle_tree nullifier_registry vesting staking vault upgrader)

# Every production Wasm integration-tests/build.rs resolves a path for.
PROD_PACKAGES=(
  stsh_token staking shielded_pool nullifier_registry merkle_tree treasury vesting
  stsh-verifier stsh-stub-verifier stub_bad_fee_token smoke_alarm_monitor
  vault upgrader
)

WASM_DIR="target/wasm32-unknown-unknown/release"

# ── PHASE 1 — testing-feature Wasms, copied to *_test.wasm ───────────────────
# MUST come first: phase 2 overwrites the plain names with production builds.
echo "${BOLD}── Phase 1/4: test-feature Wasms (×${#TEST_CANISTERS[@]}) ──${RESET}"
for c in "${TEST_CANISTERS[@]}"; do
  echo "  building $c --features testing"
  cargo build --target wasm32-unknown-unknown --release -p "$c" --features testing \
    >"$LOG_DIR/build_${c}_test.log" 2>&1 || {
      cat "$LOG_DIR/build_${c}_test.log" >&2
      die "phase-1 build failed for $c"
    }
  cp "$WASM_DIR/${c}.wasm" "$WASM_DIR/${c}_test.wasm" || die "could not copy ${c}_test.wasm"
done
echo "  ${GREEN}ok${RESET}"
echo

# ── PHASE 2 — production Wasms ───────────────────────────────────────────────
echo "${BOLD}── Phase 2/4: production Wasms (×${#PROD_PACKAGES[@]}) ──${RESET}"
PROD_ARGS=()
for p in "${PROD_PACKAGES[@]}"; do PROD_ARGS+=(-p "$p"); done
cargo build --target wasm32-unknown-unknown --release "${PROD_ARGS[@]}" \
  >"$LOG_DIR/build_prod.log" 2>&1 || {
    tail -40 "$LOG_DIR/build_prod.log" >&2
    die "phase-2 production build failed"
  }

# The excluded vetkeys canister builds from its OWN manifest — the workspace
# build above cannot produce it, and its suite needs it installed.
echo "  building canisters/vetkeys (excluded crate, own manifest)"
cargo build --manifest-path canisters/vetkeys/Cargo.toml \
  --target wasm32-unknown-unknown --release --locked \
  >"$LOG_DIR/build_vetkeys.log" 2>&1 || {
    tail -40 "$LOG_DIR/build_vetkeys.log" >&2
    die "vetkeys Wasm build failed"
  }
echo "  ${GREEN}ok${RESET}"
echo

# ── R-1 lint 3/3: caller boundary + name belt over rustc's dep-info census ──
# ORDERING IS LOAD-BEARING (brief §8): this lint reads stsh_token's dep-info `.d`
# file, which the Phase-2 `cargo build` immediately above (re)writes. It runs
# HERE, directly after that build, so no later step can be misread as having
# exercised it. It is run against the PRODUCTION build's `.d` rather than the
# Phase-1 `--features testing` one, deliberately: the shipped Wasm's census is
# the one whose caller boundary ships. (`#[cfg(feature = "testing")]` source is
# still IN that census — cfg strips items after parsing, and the census is the
# file list, not the item list — so nothing is lost by the choice.)
#
# Exit 3 means stsh_token's `.d` is absent: a hard failure, never a skip and
# never a fallback to a weaker census. It surfaces in the VERDICT block.
echo "${BOLD}── Lint: ledger caller boundary + macro-name belt (R-1 S4(b2)/(b3-belt)) ──${RESET}"
cargo run --manifest-path "$CANDID_TOOL" --locked -q --bin verify_ledger_boundary -- "$GATE_ROOT"
R1_BOUNDARY_RC=$?
if (( R1_BOUNDARY_RC == 3 )); then
  verdict_fail "ledger caller-boundary lint could NOT RUN: stsh_token's dep-info
       record is missing (exit 3). This is NOT a clean result — the lint refuses
       to fall back to a directory walk, because a census the lint author
       enumerates is exactly what RED-1 (V9) falsified. Rebuild:
         cargo build --target wasm32-unknown-unknown --release -p stsh_token --locked"
elif (( R1_BOUNDARY_RC != 0 )); then
  verdict_fail "ledger caller-boundary lint FAILED — see the findings above.
       restore_from_checkpoint / seed_at_genesis / witness_for_post_upgrade /
       witness_for_init must each occur EXACTLY TWICE across the census — their
       own definition, plus one use inside post_upgrade / init respectively —
       and no file in the census may use include!, a token-crate build.rs, an
       out-of-crate #[path], or name an identifier-synthesizing macro crate."
fi
echo

# ── PHASE 2b — §8 encoded-message size invariant (L0, freeze V6 §8) ─────────
# Runs AFTER the Wasm builds so every payload class is MEASURED, not pending:
# complete encoded Candid messages (every born-under-vault install_code
# payload — token's is largest, carrying the genesis allocation — plus C1
# UpgraderUpgrade and trigger_vault_upgrade / propose_recovery) against the
# 2 MiB platform limit minus the stated safety margin. Exceeding is a gate
# FAILURE forcing a governed artifact-staging redesign and fresh SSA review —
# inline-only is a spec invariant; never route around with chunking.
echo "${BOLD}── Phase 2b: §8 encoded-message size invariant ──${RESET}"
if ! cargo run --release -q -p verify-custody-manifest -- --sizes-only "$GATE_ROOT" ; then
  die "§8 size invariant FAILED — an encoded payload exceeds the gate bound.
       Inline-only is a spec invariant (freeze §8): this is an escalation,
       never a chunk-store route-around."
fi
echo

# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING — custody DEPLOY POSTURE (R-3b S3 stage 1)
#
# Before this stage, `check_deploy_time` ran on NO gate invocation: the gate
# passed --coverage-only and --sizes-only and never --deploy-time, so authority
# binding, the recovery roster, release identity and launch evidence were
# written, tested, and never executed by the gate. Authority binding and the
# roster PASS at base — that is exactly the problem: nothing would have noticed
# if they stopped.
#
# This stage runs the FULL deploy-time set and asserts the DECLARED posture in
# deployment/mainnet/custody_manifest.toml's [deploy_gate] against the OBSERVED
# one, as EXACT SET EQUALITY over Violation::key() strings built from TYPED
# fields. Legitimately-pending pre-ceremony obligations stay green by being
# DECLARED, not by skipping the check. A surplus key is a regression; a
# shortfall means the declaration is stale; a same-kind SWAP is neither and is
# still a set difference.
#
# Placed after Phase 2b so the Phase-2 Wasms exist for any check that reads
# them.
# ─────────────────────────────────────────────────────────────────────────────
echo "${BOLD}── Phase 2b′: custody deploy-posture (R-3b) ──${RESET}"
if ! cargo run --release -q -p verify-custody-manifest -- --deploy-posture "$GATE_ROOT" ; then
  die "custody DEPLOY-POSTURE gate FAILED — the observed deploy-time key set does not
       equal the declared one. See the SURPLUS/SHORTFALL lists above.
       Reconcile deployment/mainnet/custody_manifest.toml's [deploy_gate].expected_pending.
       A SURPLUS key is a REGRESSION in a deploy-time check — fix the code, do not
       declare it away. Flipping posture to \"launch\" is a reviewed ONE-LINE change,
       after which expected_pending must be [] and the observed set must be empty."
fi
echo

# ── PHASE 2b″ — A-7 install kit (lane A-7) ───────────────────────────────────
#
# Re-encodes every committed non-genesis init artifact
# (deployment/mainnet/<canister>_init.did) against its canister's OWN interface
# and requires byte-identity with the committed .bin the Owner uploads to the
# `#/operator` page, re-derives both recorded sha256s, resolves every principal
# in every install argument against the nine J-18 births plus the Vault,
# cross-checks each wasm_sha256 against release_hashes.toml, and enforces the
# shielded_pool RR-1 hold in both directions.
#
# Before A-7 no gate validated a non-genesis init artifact at all:
# verify_genesis_manifest reads only token/vesting init, and
# verify_custody_manifest --deploy-time only the vault/upgrader artifacts. Seven
# installs had nothing to hash, review or replay.
#
# Placed AFTER the vetkeys build above: vetkeys is the one role with no [wasm.*]
# pin (D1), so its Wasm hash is MEASURED from that build rather than compared to
# a pin, and the artifact must already exist when this stage runs.
# ─────────────────────────────────────────────────────────────────────────────
echo "${BOLD}── Phase 2b″: A-7 install kit ──${RESET}"
# `--locked` (A-7 SSA F-2): this stage's verdict is only as good as the encoder
# that produced it, and the encoder is exact-pinned in
# scripts/verify_custody_manifest/Cargo.toml. Building it against a drifted
# lockfile would re-encode with something other than the pinned parser.
if ! cargo run --release --locked -q -p verify-custody-manifest --bin verify_a7_kit -- "$GATE_ROOT" ; then
  die "A-7 INSTALL KIT gate FAILED — deployment/mainnet/a7_install_kit.toml no longer
       describes the tree. See the typed violations above. A re-encode mismatch means a
       committed <canister>_init.bin and its reviewable .did have drifted apart: the
       operator page uploads the .bin VERBATIM and performs no encoding, so the Owner
       would install bytes that no reviewed text produces. Regenerate the .bin from the
       .did with the same encoder the kit names, and update arg_sha256."
fi
echo

# ── PHASE 2c — wallet provisioning (C-14) ────────────────────────────────────
# Carried item C-14, bound to TESTFOLD: before this stage the gate had NO wallet
# leg at all — `grep wallet run_gate.sh` returned nothing — so wallet vitest was
# reproduced by nobody through the gate, and `wallet/dist/` (a gitignored build
# output) existed only on a machine that had already run the build by hand.
#
# A fresh clone needs THREE provisioning classes, not one (measured on a clone by
# a non-author, REPRO_BASE_FRESHCLONE_V1):
#   1. the Poseidon wasm-pack artifact (wallet/src/wasm/poseidon) — without it
#      vitest dies in globalSetup and ZERO tests run;
#   2. wallet/dist/.ic-assets.json5 — the built asset-policy file that
#      asset_security_policy_r141 deliberately reads INSTEAD of public/, so a
#      source file cannot stand in for it;
#   3. circuits/build/spend_js/{generate_witness,witness_calculator}.js — shared
#      with the Rust leg's preflight entry above, needed by spend_flow_l3c.
#
# We PROVISION (1) and (2) here and fail-on-absence in Phase 3; we never soften a
# test. Missing host tools are collected, not fatal here, so Phase 3 can print ONE
# consolidated MISSING list and abort through the canonical GATE ABORTED path.
echo "${BOLD}── Phase 2c: wallet provisioning (C-14) ──${RESET}"
WALLET_TOOLS_MISSING=()
# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING — spend-artifact integrity (R-3b S3 stage 2)
#
# `scripts/verify_spend_artifacts.mjs` existed and was reached ONLY through
# npm's implicit `prebuild` hook on `npm run --prefix wallet build`. A hook is
# not a gate invocation: npm's own `ignore-scripts` config makes npm run the
# named script while silently suppressing its pre/post hooks, so every static
# link stayed intact while the verifier never ran — a state no amount of
# file-content analysis can observe, because the missing fact is not file
# content. The census therefore gives npm lifecycle hooks NO credit, ever.
#
# This is the direct, blocking invocation instead. `wallet/package.json`'s
# `prebuild` entry stays for developer convenience under a plain `npm run
# build`; it is simply never cited as gate evidence.
#
# Placed BEFORE the host-tool check below, deliberately: that check
# short-circuits the whole wallet block when node/npm/wasm-pack are missing, and
# this stage needs only `node`, so it must still run — and still be able to fail
# the gate — on a host without npm or wasm-pack.
# ─────────────────────────────────────────────────────────────────────────────
echo "${BOLD}── Lint: spend-artifact integrity (R-3b) ──${RESET}"
echo "  node scripts/verify_spend_artifacts.mjs  (direct gate invocation, not the wallet prebuild hook)"
node "$GATE_ROOT/scripts/verify_spend_artifacts.mjs" || die "verify_spend_artifacts.mjs failed — spend artifact integrity check did not pass (invoked directly by the gate; this is independent of wallet/package.json's prebuild hook)"
echo

for t in node npm wasm-pack; do
  command -v "$t" >/dev/null 2>&1 || WALLET_TOOLS_MISSING+=("$t")
done
if (( ${#WALLET_TOOLS_MISSING[@]} > 0 )); then
  echo "  ${YELLOW}skipped — host tools missing: ${WALLET_TOOLS_MISSING[*]} (reported in Phase 3)${RESET}"
else
  if [[ ! -d wallet/node_modules ]]; then
    echo "  npm ci --prefix wallet"
    npm ci --prefix wallet >"$WALLET_BUILD_LOG" 2>&1 || {
      tail -40 "$WALLET_BUILD_LOG" >&2
      die "wallet npm ci failed"
    }
  fi
  echo "  npm run --prefix wallet build:wasm  (Poseidon wasm-pack artifact)"
  npm run --prefix wallet build:wasm >>"$WALLET_BUILD_LOG" 2>&1 || {
    tail -40 "$WALLET_BUILD_LOG" >&2
    die "wallet build:wasm failed — Poseidon WASM not produced (vitest globalSetup would run ZERO tests)"
  }
  echo "  npm run --prefix wallet build          (prebuild artifact check + tsc + vite build -> wallet/dist)"
  npm run --prefix wallet build >>"$WALLET_BUILD_LOG" 2>&1 || {
    tail -60 "$WALLET_BUILD_LOG" >&2
    die "wallet build failed — wallet/dist not provisioned.
       This build carries its own prebuild step (scripts/verify_spend_artifacts.mjs);
       a failure there is a real artifact-integrity finding, not a provisioning nit."
  }
  echo "  ${GREEN}ok${RESET}"
fi
echo

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2c' — wallet-bundle BYTE measurement (M-02 half B-ii, HARDEN-02)
#
# The wallet bundle is what a user's browser actually executes, and
# `[wallet_bundle].sha256` is the pin a verifier reproduces. Nothing compared that
# pin to measured bytes before this stage: the RECORD half of
# `check_wallet_bundles` is now mandatory on the canonical path (it rides inside
# Phase 2b' --deploy-posture, needs no build and reads no bytes of dist), but the
# BYTE half could not go there for five reasons, every one of them a property of
# this script:
#
#   1. `wallet/dist` is gitignored, so absent is the NORMAL state on a clone.
#   2. Phase 2b' runs BEFORE the wallet build above, so at :787 there is nothing
#      to measure yet. That is why this stage is HERE and not there.
#   3. The wallet leg above deliberately SKIPS when host tools are missing, so a
#      fail-when-absent check would red every host without the wallet toolchain.
#   4. The gate's build is not the record's PINNED toolchain tuple.
#   5. "Present" is not "current" — a stale dist satisfies an existence check.
#
# So the check is neither a skip nor an unconditional failure. It reads
# `[wallet_bundle_release].state` from the release record: `held` means no bundle
# is being released at this head and the measurement is DECLARED not owed (the
# record half checks that the marker exists and is recognised, so this can never
# be inferred from an absent file); `releasing` means the pinned toolchain tuple
# is asserted BEFORE anything is measured, a mismatch is a VIOLATION rather than
# a skip, and an absent or non-matching dist FAILS CLOSED.
#
# Runs unconditionally, including on a host that skipped the wallet build above:
# under `held` it needs nothing from dist, and under `releasing` an absent dist is
# exactly the finding.
# ─────────────────────────────────────────────────────────────────────────────
echo "${BOLD}── Phase 2c-prime: wallet-bundle byte measurement (M-02 B-ii) ──${RESET}"
if ! cargo run --release -q -p verify-custody-manifest -- --wallet-bundle-bytes "$GATE_ROOT" ; then
  die "wallet-bundle BYTE measurement FAILED — see the violation(s) above.
       Either the pinned toolchain tuple does not match this host (a digest measured
       under any other tuple is not evidence about the pinned one — build under the
       pinned tuple, do not loosen the check), or wallet/dist does not reproduce
       the declared variant's pinned sha256/files/bytes, or the
       [wallet_bundle_release] marker is missing, unrecognised, or (HARDEN-03)
       declares state = \"releasing\" without a recognised variant.
       THIS GATE BUILDS THE FINAL VARIANT ONLY (npm run build, above). A
       transitional measurement — [wallet_bundle_transitional], variant
       \"transitional\", Phase B.1 — is a separately-invoked, OUT-OF-GATE step:
       rm -rf wallet/dist && npm run --prefix wallet build:transitional, then
       --wallet-bundle-bytes by hand. Do NOT teach this gate to build it: the
       wallet vitest leg reads dist/wallet-config.json and asserts the FINAL
       variant's derivationOrigin, so a transitional build here reds that leg.
       If no bundle is being released at this head, that is a RECORD statement:
       set deployment/mainnet/release_hashes.toml's [wallet_bundle_release].state
       to \"held\" with a reason. If a digest genuinely MOVED, that is a
       Phase-D.8-affecting event — take it to the CTO and the Owner before closing
       any packet, never a silent hand rebind."
fi
echo

# ── PHASE 2d — website provisioning (D-4 ruling 3) ───────────────────────────
# CTO ruling 3 (close-rulings disposition 52b15620…), answering the smoke-alarm
# builder's report §9.1. Before this leg existed the gate ran NO
# website/solvency-status check: `grep solvency-status run_gate.sh` returned
# nothing. That mattered because CERTIFIED_SNAPSHOT_ENCODING.md declares the
# canister encoder, the integration parser and `website/solvency-status/src/
# verify.ts` a THREE-ARTIFACT LOCKSTEP that must move together — and the third
# was enforced by nobody. It is the C-13/C-14 class verbatim: a reproducibility
# claim resting on a check no gate performs.
#
# PROVISIONING, stated because the fresh-tree story must not get quietly worse:
# this package needs node + npm only (no wasm-pack, no built artifacts), and
# `npm ci` installs from the committed `package-lock.json`. Host tool versions
# come from the wallet leg's check above — the two packages share a toolchain.
# Missing tools are collected, not fatal here, so Phase 3 prints ONE consolidated
# MISSING list and aborts through the canonical GATE ABORTED path (exit 1).
echo "${BOLD}── Phase 2d: website provisioning (D-4 ruling 3) ──${RESET}"
WEBSITE_TOOLS_MISSING=()
for t in node npm; do
  command -v "$t" >/dev/null 2>&1 || WEBSITE_TOOLS_MISSING+=("$t")
done
if (( ${#WEBSITE_TOOLS_MISSING[@]} > 0 )); then
  echo "  ${YELLOW}skipped — host tools missing: ${WEBSITE_TOOLS_MISSING[*]} (reported in Phase 3)${RESET}"
else
  if [[ ! -d website/solvency-status/node_modules ]]; then
    echo "  npm ci --prefix website/solvency-status"
    npm ci --prefix website/solvency-status >"$WEBSITE_BUILD_LOG" 2>&1 || {
      sed -n '1,40p' "$WEBSITE_BUILD_LOG" >&2
      die "npm ci failed for website/solvency-status — see the output above.
       The website leg is fail-closed by ruling: a package that cannot be
       installed is a gate failure, never a silent skip."
    }
  fi
  echo "  ${GREEN}ok${RESET}"
fi
echo

# ── PHASE 3 — verify every artifact exists BEFORE running anything ───────────
echo "${BOLD}── Phase 3/4: artifact + prerequisite preflight ──${RESET}"
MISSING=()

for c in "${TEST_CANISTERS[@]}"; do
  [[ -f "$WASM_DIR/${c}_test.wasm" ]] || MISSING+=(
"${c}_test.wasm (MANDATORY, law #7 phase 1)
    cargo build --target wasm32-unknown-unknown --release -p ${c} --features testing
    cp $WASM_DIR/${c}.wasm $WASM_DIR/${c}_test.wasm"
  )
done

declare -A PROD_WASM=(
  [stsh_token]=stsh_token.wasm [staking]=staking.wasm
  [shielded_pool]=shielded_pool.wasm [nullifier_registry]=nullifier_registry.wasm
  [merkle_tree]=merkle_tree.wasm [treasury]=treasury.wasm [vesting]=vesting.wasm
  [stsh-verifier]=stsh_verifier.wasm [stsh-stub-verifier]=stsh_stub_verifier.wasm
  [stub_bad_fee_token]=stub_bad_fee_token.wasm [smoke_alarm_monitor]=smoke_alarm_monitor.wasm
  [vault]=vault.wasm [upgrader]=upgrader.wasm
)
for p in "${PROD_PACKAGES[@]}"; do
  f="${PROD_WASM[$p]}"
  [[ -f "$WASM_DIR/$f" ]] || MISSING+=(
"$f (MANDATORY, law #7 phase 2)
    cargo build --target wasm32-unknown-unknown --release -p $p"
  )
done

# ── Environment prerequisites that are deliberately NOT committed ────────────
# These are declared in each suite's own header and asserted at point of use.
# The runner checks them UP FRONT so a 40-minute run doesn't die at minute 35.
# A-4 LANDING: the power-15 Hermez ptau. The circuits leg [5/5] now runs
# `verify:ceremony:next`, whose C1/C2/C3 read this file. It is ~37 MB and
# deliberately UNTRACKED (.gitignore circuits/**/*.ptau), so NO fresh clone
# carries it. Law 7 requires the gate to refuse up front with the exact command
# that produces it, rather than let this surface as a buried C0 FAIL deep inside
# the circuits log where it reads like a ceremony defect instead of a missing
# download.
[[ -f circuits/ptau/powersOfTau28_hez_final_15.ptau ]] || MISSING+=(
"circuits/ptau/powersOfTau28_hez_final_15.ptau (circuits gate leg [5/5] —
    verify:ceremony:next C1/C2/C3 read the ptau BINARY; pinned by sha256+blake2b in
    circuits/scripts/verify_ceremony.mjs PUBLIC_PTAU_ALLOWLIST. Untracked by design.)

    just download-ptau"
)
[[ -d circuits/node_modules/circomlibjs ]] || MISSING+=(
"circuits/node_modules/{circomlibjs,snarkjs} (pmrk_public_sync_tests — circomlibjs
    Poseidon reference; the circuits JS gate leg [5/5] also requires snarkjs, which the
    SAME install provisions — circuits/package.json pins snarkjs 0.7.5 as a dependency)
    npm ci --prefix circuits"
)
[[ -f circuits/build/spend_js/generate_witness.js && -f circuits/build/spend_js/witness_calculator.js ]] || MISSING+=(
'circuits/build/spend_js/{generate_witness.js,witness_calculator.js}
  (pmrk_public_sync_tests — circom witness generator; NOT tracked, see
   .gitignore circuits/build/spend_js/*)

    # 1. regenerate to SCRATCH — never into circuits/build (the tracked
    #    spend.wasm is the integrity referent and must not be overwritten).
    #    SANCTIONED EXCEPTION: lane A6.6 overwrote it deliberately, because the
    #    circuit source changed (MAX_NOTE_VALUE 10^11 -> 10^15, DOMAIN_CIRCUIT_
    #    VERSION 2 -> 3) and every pinned digest moved with it in one commit.
    npm ci --prefix circuits
    OUT=$(mktemp -d)
    (cd circuits && circom spend.circom --r1cs --wasm --sym --output "$OUT")
    # 2. integrity check: the regenerated circuit must be byte-identical to
    #    the TRACKED one, else the helpers do not match the M5 proving key
    cmp "$OUT/spend_js/spend.wasm" circuits/build/spend_js/spend.wasm
    # 3. copy ONLY the two helpers
    cp "$OUT/spend_js/generate_witness.js" \
       "$OUT/spend_js/witness_calculator.js" circuits/build/spend_js/
    rm -rf "$OUT"

    requires circom 2.1.9 on PATH (circuits/spend.circom:1)'
)
[[ -f "$WASM_DIR/merkle_tree_base_ef635ce.wasm" ]] || MISSING+=(
"merkle_tree_base_ef635ce.wasm (pmrk_public_sync_tests — real pre-P-MRK upgrade test)
    git worktree add --detach /tmp/stsh-base-ef635ce ef635ce \\
      && (cd /tmp/stsh-base-ef635ce && cargo build --target wasm32-unknown-unknown --release -p merkle_tree) \\
      && cp /tmp/stsh-base-ef635ce/$WASM_DIR/merkle_tree.wasm $GATE_ROOT/$WASM_DIR/merkle_tree_base_ef635ce.wasm \\
      && git worktree remove --force /tmp/stsh-base-ef635ce"
)
[[ -f "$WASM_DIR/shielded_pool_prec_v1_test.wasm" ]] || MISSING+=(
"shielded_pool_prec_v1_test.wasm (prec_recovery_index_tests — real v1→v2 schema migration)
    git worktree add --detach /tmp/stsh-prec-v1 20a6fb3 \\
      && (cd /tmp/stsh-prec-v1 && cargo build --target wasm32-unknown-unknown --release -p shielded_pool --features testing) \\
      && cp /tmp/stsh-prec-v1/$WASM_DIR/shielded_pool.wasm $GATE_ROOT/$WASM_DIR/shielded_pool_prec_v1_test.wasm \\
      && git worktree remove --force /tmp/stsh-prec-v1"
)
# SSA B1 option (a), RULED 2026-08-08: a GENUINE predecessor Upgrader binary.
#
# Built from the ANNOTATED TAG `s5b/b1a-predecessor-v1` (SHA d12df2c), so the
# evidence survives a rebase or squash of this branch — referencing the SHA
# alone made B1(a) unbuildable by anyone reconstructing the gate afterwards.
# `d12df2c` is the last commit BEFORE MemoryId 10 and the companion schema bump
# (COMPANION_STATE_SCHEMA_VERSION = 1, no NONTERMINAL_RECOVERY_PROPOSAL_INDEX).
# pic_b1a_genuine_predecessor_upgrade_fails_closed installs it, lets it write
# real durable state through its own code, and proves the current build REFUSES
# to upgrade it. An in-process or synthetic-record substitute was explicitly
# refused: the empty new index contributes nothing to the accumulator or the
# accounting, so a predecessor commitment still verifies, and only a real
# predecessor proves the sentinel is what stops it.
#
# THE HASH IS PART OF THE EVIDENCE. A rebuild from CURRENT source produces a
# Wasm that already carries MemoryId 10, against which the upgrade under test
# would simply succeed. This check fails FAST and says exactly why; the test
# carries its own independent fixture guard as well (it probes for a hook that
# only exists after the pinned commit), so the substitution is caught twice by
# unrelated mechanisms. Measured, not assumed: planting a current-source build
# here trips the hash check, and planting it with the check bypassed trips the
# in-test guard. The build is path-independent and byte-reproducible (verified
# from two distinct worktree paths).
PRE_B1_WASM="$WASM_DIR/upgrader_pre_b1_d12df2c_test.wasm"
PRE_B1_SHA256="8acec72c28c8a4fb6ac3a139cee43c6e4163bb551fe71a12e454b3562142a33b"
[[ -f "$PRE_B1_WASM" ]] || MISSING+=(
"upgrader_pre_b1_d12df2c_test.wasm (pic_b1a_genuine_predecessor_upgrade_fails_closed — real predecessor upgrade)
    git worktree add --detach /tmp/stsh-upgrader-pre-b1 s5b/b1a-predecessor-v1 \\
      && (cd /tmp/stsh-upgrader-pre-b1 && CARGO_TARGET_DIR=/tmp/stsh-upgrader-pre-b1/target cargo build --target wasm32-unknown-unknown --release -p upgrader --features testing) \\
      && cp /tmp/stsh-upgrader-pre-b1/$WASM_DIR/upgrader.wasm $GATE_ROOT/$PRE_B1_WASM \\
      && git worktree remove --force /tmp/stsh-upgrader-pre-b1
    expected sha256: $PRE_B1_SHA256"
)
if [[ -f "$PRE_B1_WASM" ]]; then
  PRE_B1_ACTUAL="$(sha256sum "$PRE_B1_WASM" | cut -d" " -f1)"
  if [[ "$PRE_B1_ACTUAL" != "$PRE_B1_SHA256" ]]; then
    die "upgrader_pre_b1_d12df2c_test.wasm has the WRONG hash.
    expected $PRE_B1_SHA256
    actual   $PRE_B1_ACTUAL
  Reproducing toolchain: rustc 1.95.0 (59807616e 2026-04-14) / cargo 1.95.0
  (f2d3ce0bd 2026-03-21) — the build is path-independent but NOT
  toolchain-independent, so a different rustc changes this hash legitimately.
  This artifact must be built from TAG s5b/b1a-predecessor-v1 (d12df2c), not from current
  source. A current-source rebuild carries MemoryId 10 and schema V2, so the
  upgrade that pic_b1a_genuine_predecessor_upgrade_fails_closed asserts is
  REFUSED would instead succeed. That test's own fixture guard also catches
  this; failing here first gives the precise diagnosis. Rebuild:
    git worktree add --detach /tmp/stsh-upgrader-pre-b1 s5b/b1a-predecessor-v1 && (cd /tmp/stsh-upgrader-pre-b1 && CARGO_TARGET_DIR=/tmp/stsh-upgrader-pre-b1/target cargo build --target wasm32-unknown-unknown --release -p upgrader --features testing) && cp /tmp/stsh-upgrader-pre-b1/$WASM_DIR/upgrader.wasm $GATE_ROOT/$PRE_B1_WASM"
  fi
fi

# W-VETKEYS launch on-ramp re-pin (brief V4 §9.1) — a GENUINE predecessor
# vetkeys binary, from BEFORE the storage/admission split.
#
# Built from the ANNOTATED TAG `vetkeys/pre-repin-v1` (SHA 67dbc409), for the
# same stated reason as the B1(a) artifact above: the evidence must survive a
# rebase or squash of the re-pin branch, and referencing a bare SHA makes the
# recipe unbuildable by anyone reconstructing the gate later.
#
# WHAT IT PROVES. At 67dbc409 the stable `GlobalDeriveWindow`'s byte bound AND
# its decode assertion are both derived from `GLOBAL_DERIVE_BUDGET` (= 100), so
# a cell written by that binary may hold up to 100 timestamps. The candidate
# lowers admission to 20. Without the split, decoding such a cell TRAPS inside
# `post_upgrade` — unrecoverable, on the very upgrade that tightens the ceiling.
# `pic_genuine_predecessor_over_capacity_window_migrates` installs this binary,
# drives >= 21 real dispatches through its OWN public surface so the cell is
# genuinely over the new budget, upgrades to the candidate, and asserts no trap
# plus newest-20 retention.
#
# TWO INDEPENDENT MECHANISMS, exactly as the B1(a) precedent does it. The hash
# check below authenticates the BYTES on every run — including when the file is
# already at rest, which is the whole point: a stale or wrong historical Wasm
# sitting in target/ would otherwise bypass provisioning entirely, because a
# recipe that only runs on absence never looks at bytes already present. The
# test carries its own independent >= 21 behavioural guard as well: a
# current-source build refuses the 21st dispatch by construction, so
# substitution is caught even with the outer check bypassed. Measured, not
# assumed — all three harness rows were demonstrated and are recorded in the
# builder close report. The build is path-independent and byte-reproducible
# (verified from two distinct worktree paths).
PRE_REPIN_WASM="canisters/vetkeys/target/wasm32-unknown-unknown/release/vetkeys_pre_repin_67dbc40_test.wasm"
PRE_REPIN_SHA256="8ce934e8176160f01ca4b5df0e8b19b971d0cf4f3f90fa4c35be91f77e503f14"
[[ -f "$PRE_REPIN_WASM" ]] || MISSING+=(
"vetkeys_pre_repin_67dbc40_test.wasm (pic_genuine_predecessor_over_capacity_window_migrates — real over-capacity window migration)
    git worktree add --detach /tmp/stsh-vetkeys-pre-repin vetkeys/pre-repin-v1 \\
      && (cd /tmp/stsh-vetkeys-pre-repin && CARGO_TARGET_DIR=/tmp/stsh-vetkeys-pre-repin/target cargo build --manifest-path canisters/vetkeys/Cargo.toml --target wasm32-unknown-unknown --release --locked) \\
      && cp /tmp/stsh-vetkeys-pre-repin/target/wasm32-unknown-unknown/release/stsh_vetkeys.wasm $GATE_ROOT/$PRE_REPIN_WASM \\
      && git worktree remove --force /tmp/stsh-vetkeys-pre-repin
    expected sha256: $PRE_REPIN_SHA256"
)
if [[ -f "$PRE_REPIN_WASM" ]]; then
  PRE_REPIN_ACTUAL="$(sha256sum "$PRE_REPIN_WASM" | cut -d" " -f1)"
  if [[ "$PRE_REPIN_ACTUAL" != "$PRE_REPIN_SHA256" ]]; then
    die "vetkeys_pre_repin_67dbc40_test.wasm has the WRONG hash.
    expected $PRE_REPIN_SHA256
    actual   $PRE_REPIN_ACTUAL
  Reproducing toolchain: rustc 1.95.0 (59807616e 2026-04-14) / cargo 1.95.0
  (f2d3ce0bd 2026-03-21) — the build is path-independent but NOT
  toolchain-independent, so a different rustc changes this hash legitimately.
  This artifact must be built from TAG vetkeys/pre-repin-v1 (67dbc409), not from
  current source. A current-source rebuild already carries the storage/admission
  split, so its window admits only 20 and it CANNOT produce the over-capacity
  cell the migration arm exists to read — the arm would pass vacuously. That
  test's own >= 21 behavioural guard also catches this; failing here first gives
  the precise diagnosis. Rebuild:
    git worktree add --detach /tmp/stsh-vetkeys-pre-repin vetkeys/pre-repin-v1 && (cd /tmp/stsh-vetkeys-pre-repin && CARGO_TARGET_DIR=/tmp/stsh-vetkeys-pre-repin/target cargo build --manifest-path canisters/vetkeys/Cargo.toml --target wasm32-unknown-unknown --release --locked) && cp /tmp/stsh-vetkeys-pre-repin/target/wasm32-unknown-unknown/release/stsh_vetkeys.wasm $GATE_ROOT/$PRE_REPIN_WASM && git worktree remove --force /tmp/stsh-vetkeys-pre-repin"
  fi
fi

# ── PRE-R-8 vetkeys predecessor (R-8 V1a, AMBER-3) ──────────────────────────
#
# `l04_07_pre_r8_revoked_to_zero_principal_is_locked_out_by_the_upgrade` needs
# the binary from BEFORE the L04-07 lane — the lane's own base commit, fc30d618
# — because the behaviour it pins is a change to LIVE STATE across the upgrade,
# not the empty-map claim. A principal that enrolled and revoked to zero under
# fc30d618 could re-bootstrap the moment before the upgrade and cannot the
# moment after, with no policy row it could ever have created (the predecessor
# has no `authorize_re_bootstrap` endpoint at all). That is a one-way door
# applied retroactively, and it is the RULED behaviour.
#
# TWO INDEPENDENT MECHANISMS, exactly as PRE_REPIN_WASM above. The hash check
# authenticates the BYTES on every run, INCLUDING when the file is already at
# rest — a recipe that only fires on absence never looks at bytes already
# present. The test carries its own behavioural guard as well: it `expect`s the
# PRE-upgrade bootstrap to SUCCEED, which a current-source build refuses by
# construction, so a substituted Wasm fails the arm even with the hash check
# bypassed.
#
# Path-independent: built and hashed identically from two distinct worktree
# paths. NOT toolchain-independent — see the die message below.
PRE_R8_WASM="canisters/vetkeys/target/wasm32-unknown-unknown/release/vetkeys_pre_r8_fc30d618_test.wasm"
PRE_R8_SHA256="59a8a33c3215bb9b6c5ad6a870d9909e5b8a255eaa84db53a50452b3d3f3ee4c"
[[ -f "$PRE_R8_WASM" ]] || MISSING+=(
"vetkeys_pre_r8_fc30d618_test.wasm (l04_07_pre_r8_revoked_to_zero_principal_is_locked_out_by_the_upgrade — the L04-07 gate applies retroactively across the upgrade)
    git worktree add --detach /tmp/stsh-vetkeys-pre-r8 fc30d618 \\
      && (cd /tmp/stsh-vetkeys-pre-r8 && CARGO_TARGET_DIR=/tmp/stsh-vetkeys-pre-r8/target cargo build --manifest-path canisters/vetkeys/Cargo.toml --target wasm32-unknown-unknown --release --locked) \\
      && cp /tmp/stsh-vetkeys-pre-r8/target/wasm32-unknown-unknown/release/stsh_vetkeys.wasm $GATE_ROOT/$PRE_R8_WASM \\
      && git worktree remove --force /tmp/stsh-vetkeys-pre-r8
    expected sha256: $PRE_R8_SHA256"
)
if [[ -f "$PRE_R8_WASM" ]]; then
  PRE_R8_ACTUAL="$(sha256sum "$PRE_R8_WASM" | cut -d" " -f1)"
  if [[ "$PRE_R8_ACTUAL" != "$PRE_R8_SHA256" ]]; then
    die "vetkeys_pre_r8_fc30d618_test.wasm has the WRONG hash.
    expected $PRE_R8_SHA256
    actual   $PRE_R8_ACTUAL
  Reproducing toolchain: rustc 1.95.0 (59807616e 2026-04-14) / cargo 1.95.0
  (f2d3ce0bd 2026-03-21) — the build is path-independent but NOT
  toolchain-independent, so a different rustc changes this hash legitimately.
  This artifact must be built from COMMIT fc30d618 (the R-8 lane's base), not
  from current source. A current-source rebuild already carries the L04-07
  gate, so its revoked-to-zero principal cannot reach the pre-upgrade state the
  arm exists to observe — the arm would fail on its own PRE-upgrade bootstrap
  expectation. Rebuild:
    git worktree add --detach /tmp/stsh-vetkeys-pre-r8 fc30d618 && (cd /tmp/stsh-vetkeys-pre-r8 && CARGO_TARGET_DIR=/tmp/stsh-vetkeys-pre-r8/target cargo build --manifest-path canisters/vetkeys/Cargo.toml --target wasm32-unknown-unknown --release --locked) && cp /tmp/stsh-vetkeys-pre-r8/target/wasm32-unknown-unknown/release/stsh_vetkeys.wasm $GATE_ROOT/$PRE_R8_WASM && git worktree remove --force /tmp/stsh-vetkeys-pre-r8"
  fi
fi

# ── VETKEYS-AGE-2MIN: the b51a8436 pre-change fixture ───────────────────────
# TWO INDEPENDENT MECHANISMS, exactly as PRE_REPIN_WASM/PRE_R8_WASM above: the
# hash check authenticates the BYTES on every run, including when the file is
# already at rest; the test ALSO carries its own behavioural guard (the OLD
# module's 900s first-sighting refusal is observed live, not assumed), so a
# substituted current-source Wasm (T=120s) fails the test even with the hash
# check bypassed. The test does NOT probe the old 512-byte cap directly; the
# loader's own hash check and an old/new byte-difference assertion are the
# other two guards.
PRE_AGE2MIN_WASM="canisters/vetkeys/target/wasm32-unknown-unknown/release/vetkeys_live_a7l2d_b51a8436_test.wasm"
PRE_AGE2MIN_SHA256="b51a8436ee45a68b0505593757a5092d7cd698f1dab5cacca2a13a20a9b9f444"
[[ -f "$PRE_AGE2MIN_WASM" ]] || MISSING+=(
"vetkeys_live_a7l2d_b51a8436_test.wasm (the combined O-4/AC-6/C-5 upgrade test — the GENUINE live a7l2d module, T=900s / WRAPPED_SECRET_MAX_BYTES=512)
    git worktree add --detach /tmp/stsh-vetkeys-age2min bd12694 \\
      && (cd /tmp/stsh-vetkeys-age2min && CARGO_TARGET_DIR=/tmp/stsh-vetkeys-age2min/target cargo build --manifest-path canisters/vetkeys/Cargo.toml --target wasm32-unknown-unknown --release --locked) \\
      && cp /tmp/stsh-vetkeys-age2min/target/wasm32-unknown-unknown/release/stsh_vetkeys.wasm $GATE_ROOT/$PRE_AGE2MIN_WASM \\
      && git worktree remove --force /tmp/stsh-vetkeys-age2min
    expected sha256: $PRE_AGE2MIN_SHA256"
)
if [[ -f "$PRE_AGE2MIN_WASM" ]]; then
  PRE_AGE2MIN_ACTUAL="$(sha256sum "$PRE_AGE2MIN_WASM" | cut -d" " -f1)"
  if [[ "$PRE_AGE2MIN_ACTUAL" != "$PRE_AGE2MIN_SHA256" ]]; then
    die "vetkeys_live_a7l2d_b51a8436_test.wasm has the WRONG hash.
    expected $PRE_AGE2MIN_SHA256
    actual   $PRE_AGE2MIN_ACTUAL
  This artifact must be the byte-identical live a7l2d module (matches
  ~/a7-kit/vetkeys.wasm, the ORIGINAL A-7 install), built from COMMIT bd12694,
  not from current source. A current-source rebuild already carries T=120s, so
  the test's OLD-module behavioural assertion (the 900s first-sighting refusal)
  would fail before any upgrade — that is this test's own second, independent
  guard against a substituted fixture (the test loader also re-checks this hash
  itself). Rebuild:
    git worktree add --detach /tmp/stsh-vetkeys-age2min bd12694 && (cd /tmp/stsh-vetkeys-age2min && CARGO_TARGET_DIR=/tmp/stsh-vetkeys-age2min/target cargo build --manifest-path canisters/vetkeys/Cargo.toml --target wasm32-unknown-unknown --release --locked) && cp /tmp/stsh-vetkeys-age2min/target/wasm32-unknown-unknown/release/stsh_vetkeys.wasm $GATE_ROOT/$PRE_AGE2MIN_WASM && git worktree remove --force /tmp/stsh-vetkeys-age2min"
  fi
fi

# Phase-1 (upgrade-persistence hardening) pre-conversion base Wasms. These still
# have the pre_upgrade checkpoint and never allocate the eager cell's MemoryId,
# so upgrading one to a converted Wasm must trap on the surviving sentinel.
for c in nullifier_registry merkle_tree vesting; do
  [[ -f "$WASM_DIR/${c}_base_f2d9ee7.wasm" ]] || MISSING+=(
"${c}_base_f2d9ee7.wasm (upgrade_tests — Phase-1 cross-Wasm sentinel trap test)
    git worktree add --detach /tmp/stsh-base-f2d9ee7 f2d9ee7 \\
      && (cd /tmp/stsh-base-f2d9ee7 && cargo build --target wasm32-unknown-unknown --release -p nullifier_registry -p merkle_tree -p vesting) \\
      && cp /tmp/stsh-base-f2d9ee7/$WASM_DIR/${c}.wasm $GATE_ROOT/$WASM_DIR/${c}_base_f2d9ee7.wasm \\
      && git worktree remove --force /tmp/stsh-base-f2d9ee7"
  )
done

# P-STK: pre-P1-fix staking Wasm. Needed to create stored state that only the
# OLD code could produce (a zero-weight-snapshot proposal, and a PendingLockOp
# without dedup_key), then prove the fixed code handles it across an upgrade.
[[ -f "$WASM_DIR/staking_base_0b88405.wasm" ]] || MISSING+=(
"staking_base_0b88405.wasm (pstk_governance_tests — cross-Wasm P1 upgrade regressions)
    git worktree add --detach /tmp/stsh-pstk-base 0b88405 \\
      && (cd /tmp/stsh-pstk-base && cargo build --target wasm32-unknown-unknown --release -p staking) \\
      && cp /tmp/stsh-pstk-base/$WASM_DIR/staking.wasm $GATE_ROOT/$WASM_DIR/staking_base_0b88405.wasm \\
      && git worktree remove --force /tmp/stsh-pstk-base"
)

# Phase-2 (upgrade-persistence hardening) pre-conversion base Wasms. These still
# have the pre_upgrade checkpoint and never allocate the Phase-2 eager cells'"'"'
# MemoryIds, so upgrading one to a converted Wasm must trap on the sentinel.
for c in treasury staking; do
  [[ -f "$WASM_DIR/${c}_base_944d8c1.wasm" ]] || MISSING+=(
"${c}_base_944d8c1.wasm (eager_cell_phase2_tests — Phase-2 cross-Wasm sentinel trap test)
    git worktree add --detach /tmp/stsh-base-944d8c1 944d8c1 \\
      && (cd /tmp/stsh-base-944d8c1 && cargo build --target wasm32-unknown-unknown --release -p treasury -p staking) \\
      && cp /tmp/stsh-base-944d8c1/$WASM_DIR/${c}.wasm $GATE_ROOT/$WASM_DIR/${c}_base_944d8c1.wasm \\
      && git worktree remove --force /tmp/stsh-base-944d8c1"
  )
done

[[ -f "$WASM_DIR/shielded_pool_base_71491f8.wasm" ]] || MISSING+=(
"shielded_pool_base_71491f8.wasm (pvk_security_epoch_tests — pre-P-VK upgrade lifecycle)
    git worktree add --detach /tmp/stsh-base-71491f8 71491f8 \\
      && (cd /tmp/stsh-base-71491f8 && cargo build --target wasm32-unknown-unknown --release -p shielded_pool) \\
      && cp /tmp/stsh-base-71491f8/$WASM_DIR/shielded_pool.wasm $GATE_ROOT/$WASM_DIR/shielded_pool_base_71491f8.wasm \\
      && git worktree remove --force /tmp/stsh-base-71491f8"
)

# R-15: actual checkpoint-v3 predecessor; a current-source fixture is invalid.
PRE_R15_WASM="$WASM_DIR/shielded_pool_pre_r15_test.wasm"
PRE_R15_SHA256="c692823ed72779972aa0bf2c7db0fd2ed90c9289449ccf89e5554f1c720069b5"
[[ -f "$PRE_R15_WASM" ]] || MISSING+=(
"shielded_pool_pre_r15_test.wasm (R-15 real predecessor upgrade tests)
    ./scripts/build_pool_pre_r15_wasm.sh
    exact source: 9f7c81e7747860eeeeaae3a8a4f1aaa19a32340e
    expected sha256: $PRE_R15_SHA256"
)
if [[ -f "$PRE_R15_WASM" ]]; then
  PRE_R15_ACTUAL="$(sha256sum "$PRE_R15_WASM" | cut -d" " -f1)"
  [[ "$PRE_R15_ACTUAL" == "$PRE_R15_SHA256" ]] || die "shielded_pool_pre_r15_test.wasm has the WRONG hash.
    expected $PRE_R15_SHA256; actual $PRE_R15_ACTUAL
    Rebuild with ./scripts/build_pool_pre_r15_wasm.sh (rustc/cargo 1.95.0)."
fi

# ── C-13: the pre-F2-REDACT pool Wasm (018331a, testing feature) ─────────────
# record_retention_tests' U1/U3 legs read env!("POOL_PRE_F2REDACT_TEST_WASM"),
# which integration-tests/build.rs exports UNCONDITIONALLY, with no existence
# check. Before this entry the gate never mentioned this Wasm: a fresh clone got
# a path to a file that was never built and the suite panicked at runtime, while
# the author's tree — where a previous lane had left the artifact in target/ —
# passed forever. That is the "gate fixtures are unlisted reproducibility claims"
# class exactly, and it is why C-13's 36/0 must reproduce in a FRESH CLONE.
#
# THE HASH IS PART OF THE EVIDENCE, for the same reason as PRE_B1 above: a
# rebuild from CURRENT source carries the post-F2-REDACT PendingDeposit shape
# (`opt principal`), which would turn U1 from a genuine old-record decode test
# into a same-Wasm round trip that cannot fail.
PRE_F2REDACT_WASM="$WASM_DIR/shielded_pool_pre_f2redact_test.wasm"
PRE_F2REDACT_SHA256="b4e7222ddb4c0dd0e7c83579e79624d34c763a003fd750d550fac2839a620b9b"
PRE_F2REDACT_RECIPE="git worktree add --detach /tmp/stsh-pre-f2redact-018331a 018331a \\
      && (cd /tmp/stsh-pre-f2redact-018331a && CARGO_TARGET_DIR=/tmp/stsh-pre-f2redact-018331a/target cargo build --target wasm32-unknown-unknown --release -p shielded_pool --features testing) \\
      && cp /tmp/stsh-pre-f2redact-018331a/$WASM_DIR/shielded_pool.wasm $GATE_ROOT/$PRE_F2REDACT_WASM \\
      && git worktree remove --force /tmp/stsh-pre-f2redact-018331a"
[[ -f "$PRE_F2REDACT_WASM" ]] || MISSING+=(
"shielded_pool_pre_f2redact_test.wasm (record_retention_tests U1/U3 — real pre-F2-REDACT decode compatibility)
    $PRE_F2REDACT_RECIPE
    expected sha256: $PRE_F2REDACT_SHA256"
)
if [[ -f "$PRE_F2REDACT_WASM" ]]; then
  PRE_F2REDACT_ACTUAL="$(sha256sum "$PRE_F2REDACT_WASM" | cut -d" " -f1)"
  if [[ "$PRE_F2REDACT_ACTUAL" != "$PRE_F2REDACT_SHA256" ]]; then
    die "shielded_pool_pre_f2redact_test.wasm has the WRONG hash.
    expected $PRE_F2REDACT_SHA256
    actual   $PRE_F2REDACT_ACTUAL
  Reproducing toolchain: rustc 1.95.0 (59807616e 2026-04-14) / cargo 1.95.0
  (f2d3ce0bd 2026-03-21) — as with PRE_B1 the build is path-independent but NOT
  toolchain-independent, so a different rustc changes this hash legitimately.
  This artifact must be built from 018331a (the last commit BEFORE F2-REDACT),
  not from current source: a current-source rebuild already carries the redacted
  'opt principal' PendingDeposit, so U1's old-record-widens-to-Some assertion
  would become a same-Wasm round trip that cannot fail. Rebuild:
    $PRE_F2REDACT_RECIPE"
  fi
fi

# ── VR-1: the live pre-VR-1 production Vault (db2cf90) ───────────────────────
# pic_vr1_stranded_management_install_reconciles_after_upgrade installs THIS
# module — the one actually running on cpdab — strands a management InstallCode
# in OutcomeUnknown, proves the pre-VR-1 Vault has no reconcile route for it,
# then upgrades to the VR-1 Vault in-test and reconciles. A rebuild from CURRENT
# source already carries the widened reconcile route, which would make the
# "pre-VR-1 refuses" leg vacuous — the self-inherited-fixture class. Hence the
# literal hash, and hence this entry: the loader reads the file straight from
# target/ with no existence check, so without it a fresh clone fails at runtime
# with a file-not-found that looks like a regression.
PRE_VR1_VAULT_WASM="$WASM_DIR/vault_pre_vr1_d7d128b8_prod.wasm"
PRE_VR1_VAULT_SHA256="d7d128b87f4d91de48f959e6f128771a02100cf1c93d8f4dbc0d0200bdae6578"
PRE_VR1_VAULT_RECIPE="git worktree add --detach /tmp/stsh-pre-vr1-db2cf90 db2cf90 \\
      && env -i HOME=\"\$HOME\" CARGO_HOME=\"\$HOME/.cargo\" RUSTUP_HOME=\"\$HOME/.rustup\" \\
         PATH=\"\$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\" \\
         cargo build --locked --manifest-path /tmp/stsh-pre-vr1-db2cf90/Cargo.toml \\
           --target wasm32-unknown-unknown --release -p vault \\
      && cp /tmp/stsh-pre-vr1-db2cf90/$WASM_DIR/vault.wasm $GATE_ROOT/$PRE_VR1_VAULT_WASM \\
      && git worktree remove --force /tmp/stsh-pre-vr1-db2cf90
    full provenance: canisters/vault/tests/fixtures/d068_canonical_v1.PROVENANCE.md"
[[ -f "$PRE_VR1_VAULT_WASM" ]] || MISSING+=(
"vault_pre_vr1_d7d128b8_prod.wasm (pic_vr1_stranded_management_install_reconciles_after_upgrade
    — the module live on cpdab, built from master db2cf90, NOT from current source)
    $PRE_VR1_VAULT_RECIPE
    expected sha256: $PRE_VR1_VAULT_SHA256"
)
if [[ -f "$PRE_VR1_VAULT_WASM" ]]; then
  PRE_VR1_VAULT_ACTUAL="$(sha256sum "$PRE_VR1_VAULT_WASM" | cut -d" " -f1)"
  [[ "$PRE_VR1_VAULT_ACTUAL" == "$PRE_VR1_VAULT_SHA256" ]] || die "vault_pre_vr1_d7d128b8_prod.wasm has the WRONG hash.
    expected $PRE_VR1_VAULT_SHA256
    actual   $PRE_VR1_VAULT_ACTUAL
  This fixture must be the PRE-VR-1 Vault (master db2cf90). A rebuild from
  current source carries the widened reconcile route and makes the test's
  \"pre-VR-1 has no route out\" leg vacuous. Rebuild:
    $PRE_VR1_VAULT_RECIPE"
fi

# ── R-1: the two token base fixtures (115526d) ───────────────────────────────
# Both are read by r1_supply_integrity_tests through integration-tests/build.rs,
# which exports their paths UNCONDITIONALLY with no existence check — the
# "gate fixtures are unlisted reproducibility claims" class. Neither was listed
# here before; on the author's machine they sit in target/ and the suite passes
# forever, while a fresh clone panics at runtime with a file-not-found that
# looks like a regression.
[[ -f "$WASM_DIR/stsh_token_base_115526d.wasm" ]] || MISSING+=(
"stsh_token_base_115526d.wasm (r1_supply_integrity_tests AC-7a/AC-7b — the real
    pre-R-1 v2 checkpoint, whose sum_* fields are literally ABSENT)
    git worktree add --detach /tmp/stsh-token-base 115526d3a2755b6b5c9ed1f5a0014e746cff8b57 \\
      && (cd /tmp/stsh-token-base && cargo build --target wasm32-unknown-unknown --release -p stsh_token --locked) \\
      && cp /tmp/stsh-token-base/$WASM_DIR/stsh_token.wasm $GATE_ROOT/$WASM_DIR/stsh_token_base_115526d.wasm \\
      && git worktree remove --force /tmp/stsh-token-base"
)

# The AC-10 "before" side (RED-2 round 2). Base source at 115526d plus the two
# performance_counter wrappers appended verbatim, built --features testing, so
# BOTH sides of the hot-path comparison are measured the same way. The whole
# recipe — including the appended wrappers — is the committed script, because a
# hand-applied patch is not a recipe.
[[ -f "$WASM_DIR/stsh_token_base_115526d_measure_test.wasm" ]] || MISSING+=(
"stsh_token_base_115526d_measure_test.wasm (r1_supply_integrity_tests AC-10 —
    the directly measured 'before' side)
    ./scripts/build_token_base_measure_wasm.sh"
)

# ── R-4 RED-1: the pre-schema-3 monitor Wasm (115526d) ───────────────────────
# smoke_alarm_monitor_tests test_sam_10 reads env!("MONITOR_PRE_V3_TEST_WASM"),
# exported unconditionally by integration-tests/build.rs. Same class as C-13
# above: unlisted here, a fresh clone gets a path to a file that was never built.
#
# THE HASH IS PART OF THE EVIDENCE. A rebuild from CURRENT source carries the
# schema-3 SolvencySnapshot (with supply_invariant_unavailable) in its stable
# checkpoint, which would turn test_sam_10 from a genuine v2->v3 state-migration
# test into the same-Wasm round trip test_sam_05 already performs — and that
# round trip is exactly what failed to catch the RED-1 cutover trap.
PRE_V3_MONITOR_WASM="$WASM_DIR/smoke_alarm_monitor_pre_v3_test.wasm"
PRE_V3_MONITOR_SHA256="afdcfd86c806abb74574fba7415e7c9144cae78eeabfe52a551f863788c11295"
PRE_V3_MONITOR_RECIPE="git worktree add --detach /tmp/stsh-monitor-pre-v3-115526d 115526d \\
      && (cd /tmp/stsh-monitor-pre-v3-115526d && CARGO_TARGET_DIR=/tmp/stsh-monitor-pre-v3-115526d/target cargo build --target wasm32-unknown-unknown --release -p smoke_alarm_monitor) \\
      && cp /tmp/stsh-monitor-pre-v3-115526d/$WASM_DIR/smoke_alarm_monitor.wasm $GATE_ROOT/$PRE_V3_MONITOR_WASM \\
      && git worktree remove --force /tmp/stsh-monitor-pre-v3-115526d"
[[ -f "$PRE_V3_MONITOR_WASM" ]] || MISSING+=(
"smoke_alarm_monitor_pre_v3_test.wasm (smoke_alarm_monitor_tests test_sam_10 — real schema-2 -> schema-3 upgrade)
    $PRE_V3_MONITOR_RECIPE
    expected sha256: $PRE_V3_MONITOR_SHA256"
)
if [[ -f "$PRE_V3_MONITOR_WASM" ]]; then
  PRE_V3_MONITOR_ACTUAL="$(sha256sum "$PRE_V3_MONITOR_WASM" | cut -d" " -f1)"
  if [[ "$PRE_V3_MONITOR_ACTUAL" != "$PRE_V3_MONITOR_SHA256" ]]; then
    die "smoke_alarm_monitor_pre_v3_test.wasm has the WRONG hash.
    expected $PRE_V3_MONITOR_SHA256
    actual   $PRE_V3_MONITOR_ACTUAL
  Reproducing toolchain: rustc 1.95.0 (59807616e 2026-04-14) / cargo 1.95.0
  (f2d3ce0bd 2026-03-21) — the build is path-independent but NOT toolchain-
  independent, so a different rustc changes this hash legitimately.
  This artifact must be built from 115526d (the last commit BEFORE the schema
  2->3 bump), not from current source. Rebuild:
    $PRE_V3_MONITOR_RECIPE"
  fi
fi

# ── D-4 ruling 3: website leg prerequisites (see Phase 2d) ───────────────────
for t in "${WEBSITE_TOOLS_MISSING[@]}"; do
  MISSING+=(
"$t (website/solvency-status leg — D-4 ruling 3; the encoding doc's three-artifact
    lockstep depends on this suite. Install node + npm.)"
  )
done
[[ -d website/solvency-status/node_modules ]] || MISSING+=(
"website/solvency-status/node_modules (website vitest + typecheck leg)
    npm ci --prefix website/solvency-status"
)

# ── C-14: wallet leg prerequisites (see Phase 2c) ────────────────────────────
for t in "${WALLET_TOOLS_MISSING[@]}"; do
  case "$t" in
    node|npm) MISSING+=(
"$t (wallet vitest leg — wallet/package.json engines: node 22.23.1, npm 10.9.8)
    install Node 22.23.1 (nvm install 22.23.1) — npm ships with it"
) ;;
    wasm-pack) MISSING+=(
"wasm-pack (wallet vitest leg — builds circuits/poseidon-wasm into wallet/src/wasm/poseidon)
    cargo install wasm-pack --locked"
) ;;
  esac
done
[[ -f wallet/src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm ]] || MISSING+=(
"wallet/src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm (wallet vitest globalSetup — without it ZERO wallet tests run)
    npm ci --prefix wallet && npm run --prefix wallet build:wasm"
)
[[ -f wallet/dist/.ic-assets.json5 ]] || MISSING+=(
"wallet/dist/.ic-assets.json5 (asset_security_policy_r141 — C-14; the suite reads the BUILT policy, and says so:
   a source file under wallet/public cannot stand in for it)
    npm run --prefix wallet build"
)

if (( ${#MISSING[@]} > 0 )); then
  echo
  echo "${RED}${BOLD}MISSING PREREQUISITES (${#MISSING[@]}):${RESET}"
  for m in "${MISSING[@]}"; do
    echo
    echo "  ${YELLOW}• ${m}${RESET}"
  done
  echo
  if [[ "$MODE" == "strict" ]]; then
    die "refusing to run a partial gate. Provision the above, or re-run with --partial
       (which reports PARTIAL and is NOT a valid gate result)."
  fi
  echo "${YELLOW}${BOLD}--partial: continuing with prerequisites missing.${RESET}"
  echo "${YELLOW}Suites depending on them WILL fail. This run cannot be reported as a pass.${RESET}"
  echo
else
  echo "  ${GREEN}all artifacts and prerequisites present${RESET}"
fi
echo

# ── PHASE 4 — run all five legs ──────────────────────────────────────────────
echo "${BOLD}── Phase 4/4: test execution ──${RESET}"

echo "  [1/5] workspace (ic-cdk 0.16)"
# --no-fail-fast is REQUIRED: without it cargo stops at the first failing suite,
# so one broken suite hides the true state of every suite after it.
cargo test --workspace --locked --no-fail-fast -- --test-threads=1 \
  >"$WORKSPACE_LOG" 2>&1
WORKSPACE_RC=$?

echo "  [2/5] canisters/vetkeys (EXCLUDED crate — invisible to the workspace run)"
cargo test --manifest-path canisters/vetkeys/Cargo.toml --locked --no-fail-fast \
  >"$VETKEYS_LOG" 2>&1
VETKEYS_RC=$?

# C-14: the wallet leg. Its RC is a conjunct of the canonical verdict below — a
# leg that runs but cannot fail the gate is not a leg.
echo "  [3/5] wallet vitest (C-14 — provisioned in Phase 2c)"
# SERIAL, per the CTO amendment (W-VETKEYS lane, 2026-08-27). The suite runs
# ~560 s of test work; with vitest's default file parallelism it oversubscribes
# the CPU and the 5 s `testTimeout` on the Argon2id / IndexedDB / scanner suites
# trips — reproducibly, on the base commit as well as on any branch. Those
# failures were never assertions, only timeouts, so the parallel invocation was
# measuring the machine rather than the code. Serial costs ~40 s more wall clock
# and makes the leg deterministic.
npx --prefix wallet vitest run --root wallet --no-file-parallelism >"$WALLET_LOG" 2>&1
WALLET_RC=$?

# D-4 ruling 3: the website leg. `npm ci` ran in Phase 2d; this runs the other
# two thirds of the ruled trio. Its RC is a conjunct of the canonical verdict —
# a leg that runs but cannot fail the gate is not a leg.
# BOTH commands must pass: vitest proves the parser matches the canister's
# encoder, and `tsc --noEmit` is what catches a layout field added to the
# interface and never read. Either alone would let half a lockstep drift.
echo "  [4/5] website/solvency-status vitest + typecheck (D-4 ruling 3 — provisioned in Phase 2d)"
{
  npm run --prefix website/solvency-status test \
    && npm run --prefix website/solvency-status typecheck
} >"$WEBSITE_LOG" 2>&1
WEBSITE_RC=$?

# A6.6: the circuits JS leg. `adversarial.test.js` is the only place the widened
# in-circuit value bound is actually EXERCISED — it drives the compiled circuit
# with a public_amount one e8s above MAX_NOTE_VALUE and requires the witness to
# fail. Nothing in the Rust workspace can do that. Its RC is a conjunct of the
# canonical verdict below, and it is captured rather than `die`d, so a failure
# here reports alongside the other four legs instead of truncating the run.
# Prerequisite (circuits/node_modules) is checked in Phase 1; one
# `npm ci --prefix circuits` provisions both circomlibjs and snarkjs.
#
# A-4 LANDING adds the ceremony acceptance evidence to this leg:
#   verify:ceremony:next     — C1..C6 over the mainnet-v2 production material
#                              (Hermez power-15 ptau + drand round 6460200).
#                              ONLY `next` is gated. `m5` is superseded and is
#                              NOT wired in: it would read artifacts A-4
#                              overwrote and fail for the wrong reason.
#   test:ceremony-supersede  — the supersede mechanism cannot attach to the LIVE
#                              generation. Without this, a stray `superseded` key
#                              on `next` would skip every check above and still
#                              exit 0, i.e. a green gate that verified nothing.
# The ptau these need is checked as a Phase-1 prerequisite above.
echo "  [5/5] circuits JS suite (adversarial + poseidon + ceremony acceptance, A6.6/A-4)"
{
  npm run test:adversarial --prefix circuits \
    && npm run test:poseidon --prefix circuits \
    && npm run verify:ceremony:next --prefix circuits \
    && npm run test:ceremony-supersede --prefix circuits
} >"$CIRCUITS_LOG" 2>&1
CIRCUITS_RC=$?
echo

# ── Summary ──────────────────────────────────────────────────────────────────
summarise() {
  local label="$1" log="$2"
  echo "${BOLD}── $label ──${RESET}"
  awk -v G="$GREEN" -v R="$RED" -v X="$RESET" '
    /^ *Running / { split($2, a, "/"); suite = a[length(a)]; sub(/-[0-9a-f]+$/, "", suite); next }
    /^ *Doc-tests/ { suite = "doc-tests"; next }
    /^test result:/ {
      status = ($3 == "ok." ? G "PASS" X : R "FAIL" X)
      printf "  %-6s %-45s %s\n", status, (suite == "" ? "(unknown)" : suite), substr($0, index($0, "result:") + 8)
    }
  ' "$log"
  awk '
    /^test result:/ {
      for (i = 1; i <= NF; i++) {
        if ($i == "passed;")  p += $(i-1)
        if ($i == "failed;")  f += $(i-1)
        if ($i == "ignored;") g += $(i-1)
      }
    }
    END { printf "  TOTAL: %d passed / %d failed / %d ignored\n", p, f, g }
  ' "$log"
  echo
}

# vitest reports in its own shape, so it gets its own reader. Both the file-level
# and test-level lines are printed: "39 passed" files with "16 failed" tests is a
# state the Rust summariser has no equivalent for, and hiding either half is how a
# leg starts meaning less than it looks like it means.
summarise_vitest() {
  local label="$1" log="$2"
  echo "${BOLD}── $label ──${RESET}"
  if [[ ! -s "$log" ]]; then
    echo "  ${RED}no output${RESET}"
    echo
    return
  fi
  grep -E "^ *(Test Files|Tests|Duration) " "$log" | sed 's/^/  /'
  echo
}

# The circuits harness is a plain node script with its own reporting shape (a
# "── Results: N passed, M failed, K skipped ──" trailer). It gets its own reader
# for the same reason vitest does: a leg summarised in someone else's format
# quietly stops saying what it means.
summarise_circuits() {
  local label="$1" log="$2"
  echo "${BOLD}── $label ──${RESET}"
  if [[ ! -s "$log" ]]; then
    echo "  ${RED}no output${RESET}"
    echo
    return
  fi
  grep -E "^── Results:" "$log" | sed 's/^/  /'
  grep -hoE "^ *✗ FAIL .*" "$log" | sed 's/^ */  /' | head -20
  echo
}

echo "${BOLD}═══ RESULTS ═══${RESET}"
echo
summarise "WORKSPACE" "$WORKSPACE_LOG"
summarise "VETKEYS (excluded crate)" "$VETKEYS_LOG"
summarise_vitest "WALLET (vitest, C-14)" "$WALLET_LOG"
summarise_vitest "WEBSITE solvency-status (vitest + tsc, D-4 ruling 3)" "$WEBSITE_LOG"
summarise_circuits "CIRCUITS (adversarial + poseidon, A6.6)" "$CIRCUITS_LOG"

# Any suite that failed, with its failing test names — so the summary is
# actionable without reopening the logs.
if (( WORKSPACE_RC != 0 || VETKEYS_RC != 0 || WALLET_RC != 0 || WEBSITE_RC != 0 || CIRCUITS_RC != 0 )); then
  echo "${BOLD}── failing tests ──${RESET}"
  grep -hoE '^test [A-Za-z0-9_:]+ \.\.\. FAILED' "$WORKSPACE_LOG" "$VETKEYS_LOG" \
    | sed 's/^test /  /; s/ \.\.\. FAILED//' | sort -u
  if (( WALLET_RC != 0 )); then
    grep -hoE "^ *(FAIL|×) .*" "$WALLET_LOG" | sed 's/^ */  /' | sort -u | head -40
  fi
  if (( CIRCUITS_RC != 0 )); then
    # The circuits harness prints "  ✗ FAIL  <name>" per vector and a final
    # "── Results: N passed, M failed ──" line; surface both, or a circuits
    # failure would fail the gate with an empty explanation.
    grep -hoE "^ *✗ FAIL .*|^── Results:.*" "$CIRCUITS_LOG" \
      | sed 's/^ */  /' | sort -u | head -40
  fi
  if (( WEBSITE_RC != 0 )); then
    # tsc errors have no FAIL/× marker, so surface those too — otherwise a
    # typecheck-only failure would fail the gate with an empty explanation.
    grep -hoE "^ *(FAIL|×) .*|^.*error TS[0-9]+:.*" "$WEBSITE_LOG" \
      | sed 's/^ */  /' | sort -u | head -40
  fi
  echo
  echo "  full logs were written to a temp dir; re-run with the suite name to reproduce, e.g."
  echo "    cargo test --workspace --locked --test <suite> -- --test-threads=1"
  echo
fi

echo "${BOLD}═══ VERDICT ═══${RESET}"
if (( WORKSPACE_RC == 0 && VETKEYS_RC == 0 && WALLET_RC == 0 && WEBSITE_RC == 0 && CIRCUITS_RC == 0 )); then
  if [[ "$MODE" == "partial" ]]; then
    echo "${YELLOW}${BOLD}PARTIAL${RESET} — suites ran, but prerequisites were missing."
    echo "This is NOT a valid gate result. Provision and re-run without --partial."
    exit 1
  fi
  echo "${GREEN}${BOLD}GATE PASSED${RESET} — workspace, vetkeys, wallet vitest, website solvency-status AND circuits all ran and all passed."
  exit 0
fi
echo "${RED}${BOLD}GATE FAILED${RESET} (workspace rc=$WORKSPACE_RC, vetkeys rc=$VETKEYS_RC, wallet rc=$WALLET_RC, website rc=$WEBSITE_RC, circuits rc=$CIRCUITS_RC)"
exit 1
