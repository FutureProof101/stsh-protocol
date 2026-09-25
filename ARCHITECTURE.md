# STSH — Architecture and invariants

This file describes how the STSH repository is put together and the invariants
("laws") the code is built to keep. Code comments across the tree cite these
laws by number ("law 3", "law 7(f)"), so the numbering is stable: laws that
govern only the project's internal release process are marked as reserved
rather than renumbered.

## Non-negotiable law

The ICRC public ledger and the escrow reserve are the supply boundary — not the
shielded pool. The shielded pool can never become a second source of truth for
supply. Any change that would let it is a regression.

## Tech stack

- **Canisters**: Rust, Cargo workspace, `ic-cdk` 0.16, `candid` 0.10,
  `ic-stable-structures` 0.6. Deployed with `dfx` (`dfx.json` at the repository
  root).
- **Release profile**: `lto = true`, `opt-level = 'z'`, `strip = true`,
  `panic = "abort"`, `overflow-checks = true`. The profile is tuned for small
  Wasm, except `overflow-checks`, which is a deliberate size-for-safety trade: a
  silent integer wrap in a release binary becomes a trap, not a wrong number.
  A gate check fails if `overflow-checks` is ever removed.
- **Wallet frontend**: vanilla TypeScript + Vite + Vitest. `@dfinity/agent`,
  `candid`, `identity` and `principal` (pinned in `wallet/package.json`),
  `@dfinity/oisy-wallet-signer` for wallet-signer integration, `wasm-pack` for
  the Rust-compiled wallet crypto, and `idb` for local note storage. The wallet
  uses no UI framework.
- **ZK pipeline**: `circom` (`circuits/spend.circom`) and `snarkjs` for setup
  and proof generation; a custom `ark-groth16`/`ark-bn254` Rust verifier
  (`canisters/verifier`). Poseidon hashing uses `light-poseidon` with
  `ark-bn254`/`ark-ff`, pinned to circomlib-compatible parameters (see
  `POSEIDON_PARAMS.md`). Poseidon parameters are never changed on one side
  (circuit or Rust) without the other, and the zero-root regression test is
  re-run on any change.

## Canister map

| Canister | Role |
|---|---|
| `token` | Custom ICRC-1/ICRC-2 ledger (hand-rolled, no reference ledger). Its known ICRC deviations are listed in `canisters/token/NOTE_A-3_icrc_deviation.md`. |
| `shielded-pool` | Core privacy pool: `shield_deposit`, `withdraw`, `private_spend`, 6-bucket accounting, nullifier reservation state machine |
| `nullifier-registry` | Spent-nullifier tracking, `insert_batch` |
| `merkle-tree` | Commitment tree, Poseidon(2) hashing |
| `treasury` | Accounting view over pool-held protocol reserves. Treasury does not custody real STSH; `execute_withdrawal` disburses through a pool-authorized path, not from treasury's own ledger balance. |
| `vesting` | Token vesting schedules; `claim` pays out through a real `icrc1_transfer` |
| `staking` | Public staking, voting weight, rewards — **not installed at launch**, and absent from `dfx.json`; the pool and token staking principals are pinned to the Vault |
| `verifier` | Standalone Groth16 proof-verification canister, called inter-canister (async) from `shielded-pool` |
| `fee-policy` | Shared library crate (`crate-type = ["lib"]`, no `ic-cdk` dependency): pure fee types and calculations consumed by `shielded-pool`; the wallet mirrors its math. It is not deployed as a canister. |
| `vault` | Custody signer canister (multisig proposals for upgrades and parameters) |
| `upgrader` | Recovery/upgrade plane |
| `vetkeys` | Standalone crate with its own manifest (`ic-cdk` 0.20); excluded from the workspace |
| `smoke-alarm-monitor` | Standalone certified solvency monitor (`canisters/smoke-alarm-monitor`); reads the pool's attestation |
| `solvency_status` | Asset canister serving reserves.stsh.fi (`website/solvency-status`) |
| `wallet_frontend` | Asset canister serving app.stsh.fi (`wallet/`) |
| `custody-types` / `eager-cell` / `field-utils` | Library crates, not deployed |
| `stub-verifier` / `stub-bad-fee-token` | Test scaffolding, never deployed |

## Laws

1. **Deposit: fixed denominations. Withdraw: custom amount.** `shield_deposit`
   enforces `DENOMINATIONS: [u128; 5] = [1_000, 10_000, 100_000, 1_000_000, 10_000_000] STSH`
   via `PoolError::InvalidDenomination`, so deposits are fixed-denomination
   only. `withdraw` takes a custom amount (identity private, figure visible); a
   fixed-denomination withdraw is a design option and is not implemented.
   `withdraw` is fail-closed today (`reject_unbound_withdrawal_proof` in the pool)
   until the proof-bound withdraw path lands. There is no variable-amount
   deposit flow: the deposit constraint is load-bearing for the commitment
   model.
2. **Nullifier reservation semantics.** A reserved nullifier blocks concurrent
   withdrawal of the same note. `SolvencyBlocked` preserves the reservation
   rather than releasing it; resume restores exactly that state and does not
   re-derive it.
3. **Stage-before-finalize ordering in `private_spend`.** Output data is recorded
   durably in `PENDING_OUTPUTS` before the parent input nullifier is finalized.
   Outputs are **not** appended to the active Merkle tree until nullifier
   finality is confirmed (`insert_batch` success); the Merkle append happens
   **after** confirmed finality, never before. The active Merkle tree therefore
   only ever contains finalized, spendable commitments, and a root becomes a
   valid spend anchor only once finalized promotion inserts it into
   `accepted_spend_roots`. The earlier outputs-first order created orphan,
   independently spendable outputs when the nullifier insert failed; it must
   not come back. See `PUBLIC_SIGNALS_BINDING.md` §4.3/§6.5.
4. **Verifier calls are async and inter-canister, never in-process.**
   `shielded-pool` calls the separate `verifier` canister. An in-process stub
   verifier is permitted only inside explicit test scaffolding, never in a code
   path that ships.
5. **Fee model is gross/net with live `icrc1_fee` queries.** No hardcoded
   ICP-fee assumptions — see `docs/STSH_FEE_POLICY.md`. Fee snapshots in
   `private_spend` are taken before nonzero fees are activated.
6. **Data contracts are load-bearing across three artifacts at once.**
   `PUBLIC_SIGNALS_SCHEMA.md`, `PUBLIC_SIGNALS_BINDING.md` and
   `SNARKJS_TO_CANDID_ENCODING.md` together define the contract between the
   circuit, the prover and the canister. A change to public-signal ordering or
   encoding updates all three in the same change.
   **Note-domain freeze.** Once real unspent notes exist, the four circuit
   note-domain constants — `DOMAIN_POOL_CANISTER_ID`, `DOMAIN_ASSET_ID`,
   `DOMAIN_CIRCUIT_VERSION` and `DOMAIN_NETWORK_ID` — are frozen unless an
   explicit note-migration mechanism exists. The ptau, zkey and verification key
   are not themselves covered by this freeze. Any re-pin updates the circuit,
   wallet, vectors, manifest and rebuilt artifacts atomically.
7. **`./run_gate.sh` is the canonical gate.** The build/test sequence is not
   hand-assembled.

   ```bash
   ./run_gate.sh        # or: just gate
   ```

   It runs the blocking lints; the two-phase build of the testing-feature Wasms
   named in `run_gate.sh`'s `TEST_CANISTERS` array plus the history-bound
   fixtures `integration-tests/build.rs` resolves; the workspace suite; the
   workspace-excluded `canisters/vetkeys` suite; the wallet vitest leg (serial);
   the `website/solvency-status` leg; and the `circuits` JS leg. It prints a
   per-suite summary and one verdict, and it refuses to run if a prerequisite is
   missing, printing the exact command that produces it.

   The mechanics it encapsulates:

   **(a) Two phases, not one.** `cargo build --target wasm32-unknown-unknown --release`
   before `cargo test` is necessary but not sufficient. `integration-tests/build.rs`
   resolves Wasm paths at compile time but does not build them; tests load Wasm
   with `std::fs::read` at runtime, against whatever is already on disk.

   **(b) The test-Wasm set.** `run_gate.sh`'s `TEST_CANISTERS` array is the
   source of truth for which canisters get a `--features testing` build copied
   to `<name>_test.wasm`; it is not restated here. Each of those Wasms exposes
   test-only endpoints. The `testing` feature is off by default, so those
   endpoints are absent from every production Wasm; a test enforces this by
   scanning the shipped binaries.

   ```bash
   # Phase 1 — testing-feature builds, copied to the _test names (MUST come first)
   for c in <each TEST_CANISTERS member>; do
     cargo build --target wasm32-unknown-unknown --release -p "$c" --features testing
     cp target/wasm32-unknown-unknown/release/"$c".wasm \
        target/wasm32-unknown-unknown/release/"$c"_test.wasm
   done

   # Phase 2 — production Wasms (overwrites the plain names back to non-testing)
   cargo build --target wasm32-unknown-unknown --release \
     -p stsh_token -p staking -p shielded_pool -p nullifier_registry -p merkle_tree \
     -p treasury -p vesting -p stsh-verifier -p stsh-stub-verifier \
     -p stub_bad_fee_token -p smoke_alarm_monitor -p vault -p upgrader
   ```

   **(c) `--no-fail-fast` is required.** Without it cargo stops at the first
   failing suite, and one missing artifact hides the true state of every suite
   after it:
   ```bash
   cargo test --workspace --locked --no-fail-fast -- --test-threads=1
   ```

   **(d) The workspace run is not the whole gate.** `canisters/vetkeys` is
   excluded from the workspace (an `ic-cdk` 0.16 vs 0.20 `links` conflict), so
   `cargo test --workspace` never sees it. It needs its own invocation:
   ```bash
   cargo test --manifest-path canisters/vetkeys/Cargo.toml --locked
   ```

   **(e), (e-i)** Reserved: internal release-process rules (not published).

   **(g)** Reserved: internal release-process rule for binding the wallet
   bundle to the canister pins (not published). The gate check that enforces it,
   `check_wallet_bundles` check (9) in `scripts/verify_custody_manifest`, is in
   this repository.

   **(f) Pinned release Wasms are judged only under the gate's sanitised
   environment.** `deployment/mainnet/release_hashes.toml` pins the shipped
   Wasms (`[wasm.*]` rows). Their sha256 is reproducible only from a clean build
   under `run_gate.sh`'s `env -i` re-execution with the exact `build.command`;
   an interactive shell or a no-op rebuild can present different or stale
   bytes. Any source edit in a pinned crate that shifts a line above a
   `panic`/`expect`/`trap` site changes the Wasm even if it is comment-only.
   Either preserve line counts or re-pin and disclose the re-pin.

   **(f) addendum — quiescence is path-based, not content-based.** The release
   record's `asserts_identity_at` quiescence check for a pinned canister disarms
   on any file touched under that canister's `canisters/*` path, including a
   docs-only change; a revert does not re-arm it. A change that touches
   `canisters/*` is followed by a record-only rebind of `asserts_identity_at`
   before the gate runs, so the gate judges the Wasm the release record attests
   to.

   Omitting a phase-1 canister silently never creates its `_test.wasm`; the test
   then fails at runtime with a clear "file not found", which looks like a
   regression but is not one. `integration-tests/build.rs` documents the same
   mechanics at source level; `run_gate.sh` is the executable form.
8. Reserved (internal repository-location rule, not published).
9. **Pre-commit checklist for the mainline branch.** Before any rebase,
   cherry-pick or commit directly on the mainline branch, run and read
   `git status --short`, `git diff --stat`, `git diff --cached --stat` and
   `git diff --cached --name-only`, and state the intended file list before
   committing. A commit labelled "docs-only" must show only documentation files
   in `git diff --cached --name-only`; anything else is investigated before
   committing. The rule exists because a mislabelled docs commit once carried
   unrelated source files and silently reverted a fail-closed guard.
10. **Linux-native execution.** The gate refuses a repository on a `/mnt/*`
    Windows mount; build and test on a native Linux filesystem.
