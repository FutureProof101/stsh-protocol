# Preparing a fresh worktree to run the gate (O-12)

**What this page is for.** A fresh clone or worktree **cannot run `./run_gate.sh`**.
It is missing built Wasms, hand-provisioned predecessor fixtures, both ptau files,
the circom witness helpers and three `npm ci` trees. The failures that result look
exactly like regressions and are not. This page maps each preparation gap to its
observable signature, so that recognising one costs a minute instead of an hour —
and that mapping is the point of the page.

**The executable form is `scripts/prepare_fresh_worktree.sh`** (`just prepare-worktree`,
or `just prepare-worktree-run` to build what the tree can produce). Prose drifts;
the script derives its artifact set from the tree on every run. Use the script;
read this page when something it reports needs interpreting.

**This is preparation, NOT a gate leg.** The script asserts PRESENCE. `run_gate.sh`
remains the only thing that asserts a verdict, and its composition is unchanged —
running the preparation step never substitutes for a gate, and a green preparation
run is not evidence about any test.

## Why a count is not written here

Records disagree about how many artifacts there are (41 in one place, 42 in
another). Any number written on this page would be wrong the moment a lane adds a
fixture. The script therefore **derives** the set and prints the count as output,
from four sources unioned:

| Source | What it contributes |
|---|---|
| `run_gate.sh` `TEST_CANISTERS` | the `_test.wasm` set (law 7(b): that array is the source of truth) |
| `run_gate.sh` `PROD_PACKAGES` | the production Wasms the phase-2 build produces |
| `integration-tests/build.rs` | every Wasm the integration suites resolve at compile time — `build.rs` RESOLVES these paths, it does **not** build them |
| the test sources + `run_gate.sh`'s own prerequisite checks | the hand-provisioned fixtures named nowhere else, including the ones `run_gate.sh` does not check |

If `run_gate.sh` names an artifact the script did not derive, that is an **error**
(a derivation shortfall), not a warning. A preparation tool that under-reports says
READY for a tree that cannot gate, which is worse than no tool.

## Preparation gap vs regression — signatures

Every row below is a **preparation gap**. None of them is a code defect, and none
should be bisected, reverted, or reported as a regression.

| Observable signature | What it actually is | Fix |
|---|---|---|
| `No such file or directory … <name>_test.wasm` at test runtime | phase 1 of the two-phase build never ran, so the testing-feature Wasm was never created | `just prepare-worktree-run`, or run_gate.sh's phase 1 for that canister |
| A test panics `fixture missing` / `d068 … fixture missing` | one of the `*_pre_hardening_d068_prod.wasm` trio is absent. `run_gate.sh` does **not** check these, so nothing warns first — three panics that read like a red gate | rebuild per `canisters/vault/tests/fixtures/d068_canonical_v1.PROVENANCE.md` |
| `immutable d068 predecessor Vault missing at …` | same class, Vault side (`canisters/vault/tests/pic_tests.rs`) | same provenance document |
| A fixture is present but its `assert_eq!` on a literal sha256 fails | the fixture was rebuilt **from current source** instead of from its recorded predecessor commit. This is the dangerous one: it is a real failure, and the "fix" of re-pinning the literal would make the test vacuous | rebuild from the recorded commit; never re-pin the literal |
| Circuits leg fails; `*.ptau` not found | the ptau files are deliberately untracked (`.gitignore circuits/**/*.ptau`), so no fresh clone has them | `just download-ptau` |
| Circuits leg fails on `generate_witness.js` / `witness_calculator.js` | the circom witness helpers are gitignored build output | `just compile-circuit` (run_gate.sh compares `spend.wasm` before copying them) |
| Wallet vitest leg: many failures concentrated in one spend/L3C file | `wallet/src/wasm` (the wasm-pack output) or `wallet/node_modules` is absent | `npm ci --prefix wallet && npm run --prefix wallet build:wasm` |
| Website `solvency-status` leg does not run at all | `website/solvency-status/node_modules` absent | `npm ci --prefix website/solvency-status` |
| vetkeys suite passes suspiciously fast, or is absent from the tally | `canisters/vetkeys` is workspace-EXCLUDED (ic-cdk 0.16 vs 0.20 `links` conflict) and is invisible to `cargo test --workspace`; it needs its own invocation and its own target directory | `cargo test --manifest-path canisters/vetkeys/Cargo.toml --locked` |
| A gate run looks catastrophically broken from some point onward | `--no-fail-fast` was omitted, so one missing prerequisite hid the true state of every suite after it | re-run the gate as `run_gate.sh` invokes it |

**A genuine regression does not appear in this table.** If a failure's signature is
not here and the artifact it needs is present, treat it as real.

## What the script will NOT do for you

`--prepare` builds the two cargo phases, the excluded vetkeys crate and the three
npm trees. It **never synthesises a predecessor fixture** from current source.
Each of those fixtures is a build of a specific older commit, and its test exists
precisely to prove that code behaves correctly against state only the older module
could have written. A fixture rebuilt from current source makes its own test
vacuous — the self-inherited-fixture class this project has closed before. Those
artifacts are always reported with their recipe, never produced silently.

It also never runs `--repin`, never runs `cargo clean`, and never touches
`deployment/mainnet/*`. Pinned release Wasms are judged only under `run_gate.sh`'s
`env -i` re-exec with its exact `build.command`; an interactive build can present
different or stale bytes, so nothing here is evidence about a pin.

## Related pages

- `ARCHITECTURE.md` law 7 — the gate, the two-phase build, and why hand-assembly keeps
  going wrong. That law is the authority; this page does not restate it.
- `run_gate.sh` — the executable gate, and the owner of every prerequisite recipe
  it checks. The preparation script **quotes** those recipes rather than copying
  them; a second copy is a second thing to go stale.
