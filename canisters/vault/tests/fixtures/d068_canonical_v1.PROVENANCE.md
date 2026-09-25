# d068 Vault canonical-action fixture provenance

Source commit: `d068cd5dc29fa032016272a1cd5eedd89239180b`.
Disposable detached checkout: `<scratch>/stsh-d068-encoder`.
The checkout was created from the canonical repository with `git worktree add --detach`.
Only the test emitter in `d068_encoder_emitter.patch` was added there. It calls the
predecessor's unchanged private `canonical_action_bytes`; it does not import or
invoke the new legacy mirror.

Generation command:

`cargo test --locked -p vault --lib emit_d068_canonical_v1_goldens -- --nocapture`

Hashes at generation:

- patched predecessor `canisters/vault/src/lib.rs`: `a80d2b940dc36cfd2907ff5fc7e91558a8b6530568b07a3a200be31e85224d8b`
- complete generation log: `35de3c8baee13f3dfc2aeb742a6453665b376da2fd19bd1bd18fa3f0f6032115`
- filtered golden fixture: `714f51f353da5aeafafd9a9025f0e15210206e0913f65204c9588e4f87ca3275`
- emitter patch: `2019f171044334350016802520e32e1ad41b19755616b4ad4ab61497ee8f5845`

The fixture contains 39 rows: all 21 predecessor application variants, all five
predecessor read variants, all seven management variants, and the six remaining
outer variants. Artifact-bearing rows are emitted after the predecessor's own
clearing transform. Expected bytes are immutable review inputs, never regenerated
from the current mirror.


## Production predecessor Wasm fixtures

The populated upgrade tests use production Wasms built from the same exact source
commit, without the canonical-action emitter patch. The reproducible native WSL
recipe is a clean detached d068 checkout with a sanitized environment and the
repository's pinned Rust toolchain:

`env -i HOME=/home/jonni CARGO_HOME=/home/jonni/.cargo RUSTUP_HOME=/home/jonni/.rustup PATH=/home/jonni/.cargo/bin:/home/jonni/.nvm/versions/node/v22.23.1/bin:/home/jonni/.local/share/dfx/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin cargo build --locked --target wasm32-unknown-unknown --release -p stsh_token -p staking -p shielded_pool -p nullifier_registry -p merkle_tree -p treasury -p vesting -p stsh-verifier -p stsh-stub-verifier -p stub_bad_fee_token -p smoke_alarm_monitor -p vault -p upgrader`

Immutable copied fixture names and raw SHA-256 values:

- `vault_pre_hardening_d068_prod.wasm`: `e5fc99984703f95113942105f66dfe2e7c95fc07391daf9e85d5bcb4a5451f65`
- `shielded_pool_pre_hardening_d068_prod.wasm`: `73f198e73de8255781e4fe423a33da841fb6ffb75acb6667b380ae44250607ea`
- `stsh_token_pre_hardening_d068_prod.wasm`: `35c5b17240eccca9e46203b8ded5fb737914e573757cb000bd1579c7dad14032`

The test loaders compare the predecessor bytes to these literal values before
installation. These production fixtures have no test emitter or source patch.


## VR-1 predecessor Wasm fixture (the live pre-VR-1 production Vault)

`pic_vr1_stranded_management_install_reconciles_after_upgrade` reproduces the
mainnet defect (stranded Vault proposal #10) against the module that is
ACTUALLY live on `cpdab-saaaa-aaaar-qca2q-cai`, then upgrades to the VR-1
module in-test. A current-source rebuild would already carry the widened
reconcile route, so the "pre-VR-1: no reconcile route admits a management
target" leg would become vacuous — the same self-inherited-fixture class as
`shielded_pool_pre_f2redact_test.wasm`. The fixture is therefore pinned by
literal hash and built from `master` @ `db2cf90` (the VR-1 base), NOT from
current source. It is never committed to the repo; the loader reads it from
`target/wasm32-unknown-unknown/release/` (override:
`VAULT_PRE_VR1_TEST_WASM`).

Recipe — a clean detached `db2cf90` checkout built under the SAME sanitized
environment `run_gate.sh` re-execs with (the 13-package `build.command`), then
copied under the fixture name:

```
git worktree add --detach /tmp/stsh-pre-vr1-db2cf90 db2cf90
env -i HOME=/home/jonni CARGO_HOME=/home/jonni/.cargo RUSTUP_HOME=/home/jonni/.rustup \
  PATH="$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  cargo build --locked --manifest-path /tmp/stsh-pre-vr1-db2cf90/Cargo.toml \
  --target wasm32-unknown-unknown --release -p vault
cp /tmp/stsh-pre-vr1-db2cf90/target/wasm32-unknown-unknown/release/vault.wasm \
   <repo>/target/wasm32-unknown-unknown/release/vault_pre_vr1_d7d128b8_prod.wasm
git worktree remove --force /tmp/stsh-pre-vr1-db2cf90
```

- `vault_pre_vr1_d7d128b8_prod.wasm`: `d7d128b87f4d91de48f959e6f128771a02100cf1c93d8f4dbc0d0200bdae6578`

This is the value `deployment/mainnet/release_hashes.toml` pinned for
`[wasm.vault]` BEFORE VR-1, and the module hash an anonymous
`dfx canister info cpdab-saaaa-aaaar-qca2q-cai` reports pre-upgrade. Toolchain:
rustc 1.95.0 / cargo 1.95.0 — a different toolchain changes this hash
legitimately.
