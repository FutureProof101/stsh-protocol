# STSH

STSH is a privacy pool on the Internet Computer. It holds fixed-denomination
shielded notes of the STSH ICRC-1/ICRC-2 token (1,000 / 10,000 / 100,000 /
1,000,000 / 10,000,000 STSH). Spends are proved with Groth16 over BN254 (the
circom circuit `circuits/spend.circom`), and proofs are verified on-chain by a
separate verifier canister. The token supply is fixed at 1,000,000,000 STSH with
no minting. The ICRC ledger and the pool's escrow are the supply boundary, so
the pool cannot mint.

This repository is the source of the deployed system. See `ARCHITECTURE.md` for
the design invariants, `SECURITY.md` for reporting vulnerabilities,
`TRUSTED_SETUP.md` for the proving-key ceremony, and `PROVENANCE.md` for how this
export was made.

## What is private, and what is public

- **Hidden:** which note funds a spend.
- **Public:** deposits; the payout recipient and amount; and the Internet
  Identity account that submits each spend, which is permanent consensus
  history.
- If you deposited only once, the payout can be linked to that deposit.
- Withdraw (unshield) is not built. Private send to another person and
  hidden-sender withdraw come later.

Details: `docs/OBSERVER_MODEL.md`.

## Trust model today

- Upgrades and parameter changes go through a 2-of-3 Vault multisig. **The
  founder currently holds two of the three keys.**
- The founder's key is **still a direct controller** of the Vault and Upgrader
  canisters, and founder machine keys control the app and reserves asset
  canisters. Direct founder control ends at the next controller cutover.
- Fee changes need 2 of 3 signers and are capped at +10% per day.
- Genesis and treasury tokens are held by founder keys today; multisig custody
  comes later.
- **No external audit.** An external audit is planned, not started. Reviews so
  far are internal, including AI-assisted red teams.
- The solvency monitor (`awir7-…`) and reserves.stsh.fi make a drain visible;
  they cannot stop one.
- Vault proposals are not yet publicly listed.

Details: `docs/OBSERVER_MODEL.md`, `docs/PAUSE_MATRIX.md`.

## Trusted setup

The proving key comes from the public Hermez phase-1 ceremony, then one phase-2
contribution by the project operator, finalized by a public drand beacon.
Soundness depends on that single operator having destroyed its secret
randomness. See `TRUSTED_SETUP.md`.

## Architecture

| Canister | Role |
|---|---|
| `token` | Custom ICRC-1/ICRC-2 ledger |
| `shielded-pool` | Core privacy pool: deposit, spend, accounting, nullifier reservation |
| `nullifier-registry` | Spent-nullifier tracking |
| `merkle-tree` | Commitment tree, Poseidon(2) hashing |
| `treasury` | Accounting view over pool-held protocol reserves (holds no STSH itself) |
| `vesting` | Token vesting schedules |
| `staking` | Not installed at launch |
| `verifier` | Groth16 proof verification, called inter-canister by the pool |
| `fee-policy` | Library crate for fee math (not deployed) |
| `vault` | Custody multisig signer |
| `upgrader` | Recovery/upgrade plane |
| `vetkeys` | Standalone crate (own manifest, excluded from the workspace) |
| `smoke-alarm-monitor` | Certified solvency monitor |
| `solvency_status` / `wallet_frontend` | Asset canisters for reserves.stsh.fi / app.stsh.fi |

Repository layout: `canisters/` (canister crates), `circuits/` (circuit, keys,
ceremony tooling), `wallet/` (app.stsh.fi), `website/solvency-status/`
(reserves.stsh.fi), `integration-tests/`, `scripts/` (release and gate tooling),
`deployment/mainnet/` (public release records), `ops/`. The invariants the code
keeps are in `ARCHITECTURE.md` (laws 1-7, 9, 10).

## Deployed canisters (mainnet)

| Canister | Principal |
|---|---|
| token | `clv7x-haaaa-aaaar-qchha-cai` |
| shielded_pool | `cxrfg-qaaaa-aaaar-qchfa-cai` |
| verifier | `arjxl-zqaaa-aaaar-qchia-cai` |
| merkle_tree | `cmuzd-kyaaa-aaaar-qchhq-cai` |
| nullifier_registry | `ccwul-riaaa-aaaar-qchgq-cai` |
| treasury | `cqqds-5yaaa-aaaar-qchfq-cai` |
| vesting | `cfxs7-4qaaa-aaaar-qchga-cai` |
| vetkeys | `a7l2d-caaaa-aaaar-qchja-cai` |
| smoke_alarm_monitor | `awir7-uiaaa-aaaar-qchiq-cai` |
| Vault | `cpdab-saaaa-aaaar-qca2q-cai` |
| Upgrader | `cgal5-eiaaa-aaaar-qca3a-cai` |
| wallet frontend (app.stsh.fi) | `s3tyu-aaaaa-aaaab-qhdjq-cai` |
| solvency status (reserves.stsh.fi) | `pyeop-7yaaa-aaaam-ajfja-cai` |

How to check a canister: `dfx canister --ic --identity anonymous info <id>`
prints its module hash. Compare it with `deployment/mainnet/release_hashes.toml`
`[wasm.*].sha256` (vetkeys: `deployment/mainnet/a7_install_kit.toml`
`wasm_sha256`; the two asset canisters: `deployment/mainnet/custody_manifest.toml`).

## Prerequisites

- Linux x86_64, on a native filesystem. The gate refuses a repository under
  `/mnt/*`.
- Rust 1.95.0 via rustup, with the `wasm32-unknown-unknown` target
  (`rust-toolchain.toml`; installed automatically).
- dfx 0.28.0. The gate takes PocketIC from `$(dfx cache show)/pocket-ic`,
  matched to the `pocket-ic = "9"` crate.
- Node 22.23.1 with npm 10.9.8 (`wallet/package.json` engines, `wallet/.nvmrc`,
  `wallet/TOOLCHAIN.md`).
- `wasm-pack` (`cargo install wasm-pack --locked`); circom 2.1.9
  (`circuits/spend.circom`); snarkjs 0.7.5 (`circuits/package.json`, installed by
  `npm ci`).
- `just`, `b2sum`/`sha256sum`, `git`.

## Build

```bash
cargo build --target wasm32-unknown-unknown --release -p stsh_token -p staking -p shielded_pool -p nullifier_registry -p merkle_tree -p treasury -p vesting -p stsh-verifier -p stsh-stub-verifier -p stub_bad_fee_token -p smoke_alarm_monitor -p vault -p upgrader
cargo build --manifest-path canisters/vetkeys/Cargo.toml --target wasm32-unknown-unknown --release --locked
```

The first command is the exact `[build].command` recorded in
`deployment/mainnet/release_hashes.toml`.

## Reproducing the pinned release hashes

Run the build inside the gate's sanitised environment (`env -i` with only
`HOME`, `PATH`, `CARGO_HOME` and `RUSTUP_HOME`), from a clean `target/`, then
compare `sha256sum target/wasm32-unknown-unknown/release/<pkg>.wasm` with the
`[wasm.*]` rows of `deployment/mainnet/release_hashes.toml`.

The release Wasms embed dependency source paths under the original builder's CARGO_HOME, `/home/jonni/.cargo`, and path remapping is not used, so byte-identical reproduction needs `CARGO_HOME` at exactly that path (for example inside a container).

The recorded reproductions were all made on one host (see the header of
`release_hashes.toml`); cross-machine reproduction has not yet been
independently demonstrated. Directories such as `~/stsh`, `~/a7-kit` and
`~/stsh-walletdeploy` that appear in records and runbooks are operator-local
working directories.

## Tests and the gate

The gate is `./run_gate.sh`: a two-phase build, `--no-fail-fast`, a separate
vetkeys invocation, and five legs (workspace, vetkeys, wallet vitest, website,
circuits). It fails loudly on any missing prerequisite and prints the command
that produces it. Preparing a clone:

- `just download-ptau` (checks both digests);
- `npm ci --prefix circuits`, `npm ci --prefix wallet`,
  `npm ci --prefix website/solvency-status`;
- `npm run --prefix wallet build:wasm`;
- the circom witness helpers (the recipe is printed by `run_gate.sh`);
- the ICRC reference ledger at `target/icrc-ref/ic-icrc1-ledger.wasm.gz`
  (dfinity/ic release `ledger-suite-icrc-2026-03-09`, sha256
  `354dd6ecfdc72b5409805b31dea22c9db11df6e14095a5a68924eb63535e6d8a`);
- `scripts/prepare_fresh_worktree.sh` lists whatever is still missing.

**A clone of this repository cannot return a PASSED gate.** Two parts of the
gate need the private development history this export does not carry: (1) the
release-identity check, which requires the recorded source commits to be
ancestors of HEAD; (2) upgrade-regression tests, which need predecessor Wasms
built from earlier commits. The full gate was run once, on 2026-09-25, and
passed, on a private tree that differs from this commit only in this README and
`PROVENANCE.md` (see `PROVENANCE.md`, "Invariants"). A clone can
verify the build, the pinned hashes (above), the circuit chain
(`TRUSTED_SETUP.md`), and the history-independent unit suites. See
`docs/FRESH_WORKTREE_GATE_PREP.md`.

## Code-comment ids

Comments cite internal tracking ids (e.g. QA-DEF-034, H-3, R-11 E-7, EXT-2, lane
names). They point to the project's private defect and review ledgers, not to
files in this repository.

## Security, licence, provenance

- Security: `SECURITY.md`.
- Licence: Apache-2.0 (`LICENSE`), Copyright 2026 STSH contributors. Bundled
  fonts are under the SIL Open Font License (licence files beside the fonts).
- Provenance: `PROVENANCE.md`.
