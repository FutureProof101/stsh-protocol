# Wallet toolchain contract (AC-2 — pinned, Phase B inherits this)

**Node `22.23.1` (Jod LTS) + npm `10.9.8` (the npm bundled with that Node
release). Exact — not "Node 22", not "an npm 10".** Pinned in `engines` and
`packageManager` in `package.json`, and in `.nvmrc` (`nvm use` picks it up).

## Install contract

```bash
nvm use            # -> v22.23.1 (installs via `nvm install` if absent)
npm ci             # PLAIN. --legacy-peer-deps is FORBIDDEN; if plain npm ci
                   # fails, the dependency tree is broken — fix it, don't flag it.
```

## Single-SDK-tree assertion (run after any dependency change)

```bash
npm ls @dfinity/agent @dfinity/candid @dfinity/identity @dfinity/principal
```

Must show ONE `3.4.3` tree — every entry `3.4.3` or `deduped`, ZERO
`invalid`/`UNMET` peers, and no nested second major anywhere (the pre-AC-2
defect was a 2.4.1 top-level tree coexisting with a nested 3.4.3 tree under
`@dfinity/vetkeys`).

## Pinned dependency set (Owner-ruled, SSA-reviewed — exact, no carets)

| Package | Version |
|---|---|
| `@dfinity/agent`, `@dfinity/candid`, `@dfinity/identity`, `@dfinity/principal`, `@dfinity/auth-client` | `3.4.3` |
| `@dfinity/vetkeys` | `0.4.0` |
| `@dfinity/oisy-wallet-signer` | `0.4.0` |
| `@dfinity/utils` | `3.2.0` |
| `@dfinity/ledger-icp` | `5.0.0` |
| `@dfinity/ledger-icrc` | `3.0.0` |
| `@dfinity/zod-schemas` | `1.1.0` |
| `zod` | `3.25.76` |

Notes:
- `@dfinity/auth-client@3.4.3` peers on **exactly** `3.4.3` core packages —
  the family upgrades in lockstep or not at all.
- The ledger/utils/zod pins exist because OISY `0.4.0` peers on them; they are
  direct dependencies so the resolved versions are explicit, not incidental.
- OISY `0.4.0` `engines` is the source of the Node/npm floor
  (`node >= 22`, `npm >= 10.9 < 11`).

## Why this exists

AC-2 (corrective lane, 2026-07-17): the Campaign-A install contract was false —
`npm ci` needed an undocumented `--legacy-peer-deps` and two `@dfinity` majors
coexisted. Phase B imports `@dfinity/vetkeys` AND builds agent actors, so a
split tree would land both majors in one runtime graph. This contract is the
fix; **Phase B cuts from the corrected master and inherits it unchanged.**
