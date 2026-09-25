# A-7 install runbook — the nine installs

**Audience:** the Owner, at the `#/operator` page of app.stsh.fi, with a signer
identity in the Vault quorum.
**Companion record:** `deployment/mainnet/a7_install_kit.toml` — the
machine-readable table this document walks through. Every hash quoted here lives
there, and `./run_gate.sh` re-derives all of them on every run
(`cargo run -p verify-custody-manifest --bin verify_a7_kit`). If this document
and the kit ever disagree, **the kit is right and one of them is a defect** —
stop and report it.
**GENESIS INSTALLS ARE NOW IN SCOPE (RR-1b, 2026-09-13).** `stsh_token` (§3.6)
and `vesting` (§3.7) used to be out of scope here: they are governed by
`deployment/mainnet/genesis_manifest.toml` and Gate-D, and that has not changed —
their `.did` files ARE the Gate-D genesis artifacts and this runbook does not
author them. What changed is that they now have kit rows, so their arguments are
encoded, hashed and replayed by the same committed tool as every other install
instead of being carried to the console by hand. Gate-D still rules the CONTENT;
this runbook rules the UPLOAD.

**Out of scope:** `vault` and `upgrader` were installed at J-18. The repo-root
`MAINNET_DEPLOYMENT.md` remains the overall deployment reference.

---

## 0. What the operator page actually does

Understanding this is what makes the two hash fields meaningful rather than
ceremonial.

- You pick a **Wasm file** and an **arg file**. The page uploads the **raw bytes
  of both**. It performs **no Candid encoding** — the arg file you select IS the
  install argument (`wallet/src/ui/pages/operator.ts:664-667`,
  `wallet/src/operator/proposals.ts` `codePayload`). This is why the kit ships a
  pre-encoded `.bin` for every canister: the `.did` text is for **review**, the
  `.bin` is what you **upload**.
- You type **`expected_wasm_hash`** and **`expected_arg_hash`**. The Vault
  recomputes sha256 over the uploaded bytes at **propose** and again at
  **execute**, and refuses if either differs.
- The page hashes your **Wasm** locally and shows you the result, and refuses to
  build the proposal unless it equals both what you typed and the `[wasm.*]` pin
  in `deployment/mainnet/release_hashes.toml`.
- **The page does NOT hash the arg file and shows you nothing about it**
  (`operator.ts:628-636` displays the Wasm hash only). Your `sha256sum` of the
  `.bin`, run yourself before you type, is the only independent check on that
  side. Do not skip it.

So, for every row:

```
upload   deployment/mainnet/<canister>_init.bin
type     expected_arg_hash  = the kit's  arg_sha256
type     expected_wasm_hash = the kit's  wasm_sha256
```

`arg_text_sha256` in the kit is the hash of the reviewable **text**. It pins
what was reviewed. **Never type it anywhere.**

---

## 1. Before you start

### 1.1 Get the Wasms from a gate build, not an interactive one

Pinned Wasm bytes are reproducible **only** from a clean build under
`run_gate.sh`'s `env -i` re-execution with its exact package set (ARCHITECTURE.md law
7(f)). An interactive rebuild, or a no-op rebuild over a stale target directory,
can present different bytes — and the operator page will hard-refuse the upload
when the local hash misses the pin (`wallet/src/operator/proposals.ts:227-234`).
That refusal is the system working. Do not work around it.

```bash
cd "$STSH_ROOT" && ./run_gate.sh
```

Then take each file from `target/wasm32-unknown-unknown/release/` and check it:

```bash
sha256sum target/wasm32-unknown-unknown/release/stsh_verifier.wasm
# must equal the kit's wasm_sha256 for `verifier`
```

No Wasm is copied into the repository. The build output is the artifact.

### 1.2 Hash every arg file

```bash
cd "$STSH_ROOT"
sha256sum deployment/mainnet/*_init.bin
```

Check each against the kit's `arg_sha256`. Note that **verifier, merkle_tree and
nullifier_registry produce byte-identical arg files** — all three take
`(principal)` = the pool — so all three share
`18d4539ba181134e41fd6a7d4a91d84ba610766514a1765d5fe077a33fc26f79`. The arg hash
therefore **cannot** tell those three installs apart. The **target principal** is
the only thing that can. Check the target twice on those three.

### 1.3 Re-verify the targets are still virgin

Immediately before each install, anonymously:

```bash
dfx canister --network ic info <target principal>
```

Expect `Module hash: None` and `Controllers: cpdab-saaaa-aaaar-qca2q-cai` (the
Vault alone). A module hash that is not `None` means something was already
installed — stop.

### 1.4 What is NOT an install step

**Fee activation.** The pool comes up on `launch_defaults`, which are fee-free.
Nonzero fees arrive later as a `PoolSetGovernanceFeeParams` governance proposal
at A-5/A-6. There is no fee value in any init argument and none should be added.

---

## 2. Install order

```
  1. verifier
  2. merkle_tree
  3. nullifier_registry
  4. treasury
  5. vetkeys
  6. stsh_token             ← GENESIS
  7. vesting                ← GENESIS, after the token
  ─────────────────  [RR-1 GATE — CLEARED 2026-09-13, see §4]
  8. shielded_pool
  9. smoke_alarm_monitor    ← must be last
 9a. pool VK activation ceremony (PROT-24) — NOT an install; see §5a
```

**Step 9a is not optional and is not an install.** After the nine installs the
pool is still at `PINNED_CIRCUIT_VERSION = 0` and every spend is rejected
`CircuitVersionMismatch`. §5a is the Vault proposal + lazy-activation trigger
that fixes that, and it must be done before A-5/A-6 and before the pool is
opened.

**Before you install `stsh_token` (step 6), Gate-D must be all green.** That is
one command, and its last line is the only thing you need to read:

```bash
cargo run -p verify-genesis-manifest --bin verify_genesis_manifest \
  deployment/mainnet | tail -1
# must print exactly:  GATE-D + GATE-V(pre-install): PASS
```

Since RR-1b the committed record declares `rr1_performed = true`, which makes
the posture stage STRICT: the observed failing set must be **exactly empty**, and
a single failing check of any kind anywhere exits nonzero. If that line is not
`PASS`, **stop** — do not install the ledger. There is no partial-genesis state
worth being in.

Three of those steps are hard constraints; the rest is convention that keeps the
read-backs meaningful:

- **RR-1 before shielded_pool** (§4). Hard — and **already satisfied**: RR-1a
  (`a067074`) rebound `[pool_init]`, lane A-7 REBASE corrected the two roots it
  had written to the pre-amendment DPOOL-5/7 sources, RR-1b resolved the last
  placeholder principal, and the kit's `hold` row is cleared. The pool is
  installable in this window.
- **stsh_token before vesting.** Hard. The vesting init argument NAMES the token
  canister, and the 12,500,000,000,000,000 base units the vesting canister
  custodies are minted by the TOKEN install. Reverse the two and you have a
  vesting canister pointing at an uninstalled ledger and a read-back with
  nothing to read.
- **stsh_token before shielded_pool.** The pool's `token_canister` trust root is
  `clv7x…`; installing the pool first is not fatal but leaves it pointing at an
  empty shell until step 6 lands.
- **smoke_alarm_monitor last.** Its `init` arms a zero-delay timer that performs
  an immediate first refresh reading the token, the pool and the treasury
  balance (`canisters/smoke-alarm-monitor/src/lib.rs:633-641`). Installed before
  those exist it comes up on a `CallFailed` snapshot and retries on the next
  5-minute interval — not a brick, but a monitor whose first published snapshot
  is red for no real reason.

No other init makes an inter-canister call. The pool's `init` is purely local
(`canisters/shielded-pool/src/lib.rs:4152-4210`).

---

## 3. The seven installs to do first

For each: dropdown **`Management.InstallCode`**, pick the **role** in the
canister dropdown, paste the **target**, upload the **Wasm** and the **arg**,
type the **two hashes**, submit.

**R-1 (SSA rehearsal, `SSA_REHEARSAL_MAINNET_SEQUENCE_R1_2026-09-14.md`):
submitting/proposing is NOT an approval.** `propose_inner` writes the record
with zero approvals; `APPROVALS` is only ever written by `approve_inner`
(`vault/src/lib.rs:3205-3246`, `:3358-3363`). Quorum is `approvals.len() >=
threshold` = **two distinct `approve` calls** (`:3371`) — the proposing signer's
own submission does not count as the first of them. Sequence per install:

1. II 1 proposes on the page (this submit).
2. II 1 approves on the page (yes — the same signer, a second explicit action).
3. II 2 approves on the page (or, if II 2 is unavailable on the page, II 2 or
   `4f6wg` approves via `dfx … approve '(<id>, vec { <commitment hash> })'` —
   `approve` requires the `expected_action_hash` argument bound to the
   commitment, id-alone is refused, CUST-SSA-001; read it from
   `get_proposal '(<id>)' --query` as a signer, not anonymously — `get_proposal`
   is signer-gated).

**R-11 — wrong-target install is terminal, not reconcilable** (a right-looking
byte-identical arg hash on the wrong canister still executes). Before EVERY
propose in this section, re-run the §1.3 anonymous pre-check on that specific
target and confirm `Module hash: None` and `Controllers:
cpdab-saaaa-aaaar-qca2q-cai` — read the target back aloud against the kit row
before Propose, and again before each Approve.

### 3.1 verifier

| | |
|---|---|
| role (dropdown) | `verifier` |
| target | `arjxl-zqaaa-aaaar-qchia-cai` |
| Wasm | `target/wasm32-unknown-unknown/release/stsh_verifier.wasm` |
| `expected_wasm_hash` | `5a7dcc4997419e65cd16fa3436a9189b7535e5137beb01ee17edff7292c81141` |
| arg file | `deployment/mainnet/verifier_init.bin` |
| `expected_arg_hash` | `18d4539ba181134e41fd6a7d4a91d84ba610766514a1765d5fe077a33fc26f79` |

The pin lives under `[wasm."stsh-verifier"]`, not `[wasm.verifier]`: the dfx
canister name is `verifier` but the cargo package is `stsh-verifier`. The
dropdown role stays `verifier`; the page resolves the alias for you.

The single init argument is the **authorized pool caller** (DEF-083) — every
verification entry point rejects any other caller.

Read back:
```bash
dfx canister --network ic info arjxl-zqaaa-aaaar-qchia-cai
dfx canister --network ic call --query arjxl-zqaaa-aaaar-qchia-cai get_authorized_pool '()'
```
Expect the module hash to equal the pin, and the pool principal
`cxrfg-qaaaa-aaaar-qchfa-cai`.

### 3.2 merkle_tree

| | |
|---|---|
| role | `merkle_tree` |
| target | `cmuzd-kyaaa-aaaar-qchhq-cai` |
| Wasm | `target/wasm32-unknown-unknown/release/merkle_tree.wasm` |
| `expected_wasm_hash` | `ebbac752e4a48249d6ee105fe77dd517a3094cf7161eba6dfef162133ffcb221` |
| arg file | `deployment/mainnet/merkle_tree_init.bin` |
| `expected_arg_hash` | `18d4539ba181134e41fd6a7d4a91d84ba610766514a1765d5fe077a33fc26f79` |

Read back:
```bash
dfx canister --network ic info cmuzd-kyaaa-aaaar-qchhq-cai
dfx canister --network ic call --query cmuzd-kyaaa-aaaar-qchhq-cai get_authority_refs '()'
```

### 3.3 nullifier_registry

| | |
|---|---|
| role | `nullifier_registry` |
| target | `ccwul-riaaa-aaaar-qchgq-cai` |
| Wasm | `target/wasm32-unknown-unknown/release/nullifier_registry.wasm` |
| `expected_wasm_hash` | `d4bf8493731351d53a589113e99b23261a8fb7255f1e2ac967e8c077e400a951` |
| arg file | `deployment/mainnet/nullifier_registry_init.bin` |
| `expected_arg_hash` | `18d4539ba181134e41fd6a7d4a91d84ba610766514a1765d5fe077a33fc26f79` |

Read back:
```bash
dfx canister --network ic info ccwul-riaaa-aaaar-qchgq-cai
dfx canister --network ic call --query ccwul-riaaa-aaaar-qchgq-cai get_authority_refs '()'
```

### 3.4 treasury

| | |
|---|---|
| role | `treasury` |
| target | `cqqds-5yaaa-aaaar-qchfq-cai` |
| Wasm | `target/wasm32-unknown-unknown/release/treasury.wasm` |
| `expected_wasm_hash` | `0e314c758ae2a96509dbe9660bf9255de0f11ac5e8f5b02621c1bb2179d8e4a1` |
| arg file | `deployment/mainnet/treasury_init.bin` |
| `expected_arg_hash` | `b7eb28ed6ebe43a06e992b4f7b49a879715cd779c091e0528654ab9894ac5c00` |

Three **positional** principals — `(token_canister, pool_canister, controller)`
= `(clv7x…, cxrfg…, cpdab…)`. The controller is the Vault. The treasury is an
accounting view and must not custody real STSH
(`canisters/treasury/CUSTODY_DECISION.md`, Option 2).

Read back:
```bash
dfx canister --network ic info cqqds-5yaaa-aaaar-qchfq-cai
dfx canister --network ic call --query cqqds-5yaaa-aaaar-qchfq-cai get_canister_refs_readback '()'
```

### 3.5 vetkeys — the one unpinned role

| | |
|---|---|
| role | `vetkeys` |
| target | `a7l2d-caaaa-aaaar-qchja-cai` |
| Wasm | `canisters/vetkeys/target/wasm32-unknown-unknown/release/stsh_vetkeys.wasm` |
| `expected_wasm_hash` | `b51a8436ee45a68b0505593757a5092d7cd698f1dab5cacca2a13a20a9b9f444` |
| arg file | `deployment/mainnet/vetkeys_init.bin` |
| `expected_arg_hash` | `a88ec81ce02baed916d215a4206da0ee50906bfae00534b2326583ee8ebf3ad8` |

**Read this before you tick the acknowledgement box.** `vetkeys` is a
workspace-EXCLUDED crate and carries **no `[wasm.*]` pin** in
`release_hashes.toml` — by ruling (D1), not by omission. Its Wasm comes from a
different target directory (note the path above), built by the gate from the
crate's own manifest. The page therefore cannot check its bytes against a
reviewed pin and will refuse the proposal unless you tick
**"unpinned role (vetkeys)"**. The Vault has no on-chain note field, so
**record the Owner ruling id in your operator log** at the moment you tick it.

The hash above is *measured*, not pinned: `verify_a7_kit` hashes the gate's build
output directly. Confirm it yourself against a fresh gate build before
uploading.

Authority: `CTO_BOARD_RECONCILED_2026-09-11.md` (5b7350d5) D1 row
"vetkeys installed at A-7"; `MAINNET_DEPLOYMENT.md:375`/`:418` (adjudication
`b216902b…`, 2026-08-27). The in-repo "D1, 2026-08-14" references are the
**staking** exclusion — a different ruling — and are not authority for this.

Init is `("key_1", opt principal clv7x-haaaa-aaaar-qchha-cai)`. `"key_1"` is the
**production** VetKD key name; a test key name on mainnet derives from a
non-production master secret and is not a configuration mistake you can fix
afterwards.

Read back:
```bash
dfx canister --network ic info a7l2d-caaaa-aaaar-qchja-cai
dfx canister --network ic call --query a7l2d-caaaa-aaaar-qchja-cai get_config '()'
dfx canister --network ic call --query a7l2d-caaaa-aaaar-qchja-cai get_token_canister '()'
```

---

### 3.6 stsh_token — GENESIS

**Gate-D must be green before this step.** See the command at the top of §2. Do
not proceed on a `FAIL`.

| | |
|---|---|
| role | `stsh_token` |
| target | `clv7x-haaaa-aaaar-qchha-cai` |
| Wasm | `target/wasm32-unknown-unknown/release/stsh_token.wasm` |
| `expected_wasm_hash` | `a90318da268875caf8c8cfa4983a9039f4dda67e58a8a4d319ac979c0d19db0f` |
| arg file | `deployment/mainnet/stsh_token_init.bin` (not published in the public export; see PROVENANCE.md) |
| `expected_arg_hash` | `e7d6960802dcc4feeff9790632f6214700ff45dc91063e818263893e010963fb` |

This is **the ledger**, and this install **mints the entire genesis supply** —
100,000,000,000,000,000 base units (1,000,000,000 STSH), distributed across the
eleven allocation rows of `genesis_manifest.toml`. There is no second chance and
no re-mint: the allocation table is consumed at init.

The argument is `deployment/mainnet/stsh_token_init.did`, the canonical Gate-D
artifact — the same file `verify_genesis_manifest` checks field-by-field against
the manifest. This runbook does not author it and you must not edit it; editing
it changes `expected_arg_hash`.

Read back — **both numbers, before you go anywhere near §3.7**:
```bash
dfx canister --network ic info clv7x-haaaa-aaaar-qchha-cai
dfx canister --network ic call --query clv7x-haaaa-aaaar-qchha-cai \
  icrc1_total_supply '()'
dfx canister --network ic call --query clv7x-haaaa-aaaar-qchha-cai \
  icrc1_balance_of '(record { owner = principal "cfxs7-4qaaa-aaaar-qchga-cai"; subaccount = null })'
```

| read-back | must be |
|---|---|
| `icrc1_total_supply` | `100_000_000_000_000_000` |
| `icrc1_balance_of` (vesting canister `cfxs7…`) | `12_500_000_000_000_000` |

That second figure is **founders 12,000,000,000,000,000 plus legal counsel
500,000,000,000,000** — the vesting canister custodies BOTH grants (D-4 V2), so
`12_500_000_000_000_000` is correct and a bare `12_000_000_000_000_000` means the
counsel grant did not land. `dfx` prints these with underscore separators.

### 3.7 vesting — GENESIS, after the token

| | |
|---|---|
| role | `vesting` |
| target | `cfxs7-4qaaa-aaaar-qchga-cai` |
| Wasm | `target/wasm32-unknown-unknown/release/vesting.wasm` |
| `expected_wasm_hash` | `760488eb60d9b23bd3b612b122fb183ea5f9c1525208709e580956cf1ee59b27` |
| arg file | `deployment/mainnet/vesting_init.bin` |
| `expected_arg_hash` | `d5f5f795be167025f80fc862e20ae2675a08a53d148f05e14f08abd24bd07705` |

**Only after §3.6 has read back both numbers.** `token_canister` here is
`clv7x…` and `claim` performs a real `icrc1_transfer` against it.

Two schedules, one canister:

| # | beneficiary | amount | cliff | linear |
|---|---|---|---|---|
| 0 | founder `ib4mm-7l7xb-lc4bu-t25ya-t3ahs-5zvaz-kkfef-5ezep-pbngz-mexxv-sae` | 12,000,000,000,000,000 | 6 | 30 |
| 1 | legal counsel `7edga-wl3vz-46g37-jaog6-amxwd-bgfjh-36hnf-we7up-3sfju-ual6g-fqe` | 500,000,000,000,000 | 0 | 12 |

BOTH schedules were RE-BOUND at RR-1b REDO (2026-09-21) to their
CANISTER-ROOTED (s3tyu native-origin) values — the pre-cutover `app.stsh.fi`
values are ALIASES the production wallet cannot present. Schedule 0 is attested
by `reviews/RECORD_FOUNDER_1_BENEFICIARY_NATIVE_2026-09-21.md` (`987805a1…`) and
schedule 1 by `reviews/RECORD_LEGAL_COUNSEL_BENEFICIARY_NATIVE_2026-09-21.md`
(`e9d4a04e…`); each digest is the `provenance` pointer its role carries in
`genesis_principals.toml`.

Read back:
```bash
dfx canister --network ic info cfxs7-4qaaa-aaaar-qchga-cai
dfx canister --network ic call --query cfxs7-4qaaa-aaaar-qchga-cai list_schedules '()'
dfx canister --network ic call --query cfxs7-4qaaa-aaaar-qchga-cai \
  get_canister_refs_readback '()'
```

`list_schedules` (there is **no** `get_schedules` — `vesting.did:61-63`) must
return **two** records matching the table above exactly: the two beneficiary
principals, totals `12_000_000_000_000_000` and `500_000_000_000_000`, and the
two shapes 6/30 and 0/12. Check the counsel principal character by character
against the row above — it is the one value in the whole genesis set that was
resolved last and has the least prior exposure.

---

## 4. [RR-1 GATE] — CLEARED

**This gate is satisfied. The pool install is no longer held.** The section is
kept because the order it imposed is still the order to install in, and because
what it was protecting is worth knowing before you approve §4.1.

What it held. `genesis_manifest.toml` `[pool_init]` pins the pool's four trust
roots — `token_canister`, `treasury_canister`, `staking_canister`, `controller`.
While those named the **P0-3 placeholder** principals rather than the D5
principals carried in `shielded_pool_init.did`, the record and the install
artifact disagreed by construction, and installing the pool in that state would
have put the live pool's trust roots outside the reach of the gate that exists
to check them.

How it cleared, in two steps:

1. **RR-1a** (`a067074`) rebound `[pool_init]` to real production principals.
2. **Lane A-7 REBASE** (2026-09-13) corrected the two of those four that RR-1a
   had written to the sources the PRE-amendment DPOOL-5/7 named —
   `treasury_canister` to the treasury **CANISTER** `cqqds-5yaaa-aaaar-qchfq-cai`
   (not the ledger's treasury ACCOUNT holder) and `controller` to the **Vault**
   `cpdab-saaaa-aaaar-qca2q-cai` (not the vesting controller multisig), per
   `RULING_RECORD_POOL_TRUST_ROOTS_2026-09-13`. DPOOL-5 now reads this kit's
   `treasury` `target` and DPOOL-7 reads `vault_authorities.toml`
   `[recovery].vault`; the old equalities are refused by name, and a new
   DPOOL-5b refuses any placeholder in those four fields.

`verify_a7_kit` enforces the hold in both directions: **required** while the two
disagree, **cleared** once they agree. With them in agreement, an empty `hold` is
not merely permitted — it is required, and re-adding it REDs the gate. A stale
hold is as much a defect as a missing one.

`cargo test --locked -p verify-genesis-manifest` is green on the rebound record.
Since **RR-1b** (2026-09-13) the tree's failing set is **exactly empty**: the
counsel beneficiary — the last P0-3 placeholder — is resolved at both sites and
in the record, and `rr1_performed = true` makes the posture stage refuse anything
but an empty set.

**One stale string, deliberately left.** The header of
`deployment/mainnet/shielded_pool_init.did` still reads `DRAFT ONLY, HELD`.
Ignore it. That file's bytes are hash-pinned by `arg_text_sha256` and, through
the re-encode, by `arg_sha256` — the number you type as `expected_arg_hash` —
so correcting a comment in it would change the hash you are about to check. The
authority on whether the install is held is the kit's `hold` row, which the gate
enforces; the `.did` header is prose no gate reads.

The pool's `arg_sha256` did **not** change: the artifact already carried the D5
principals when the kit was written, so nothing was re-derived. The value in
§4.1 is current.

### 4.1 shielded_pool (step 8)

| | |
|---|---|
| role | `shielded_pool` |
| target | `cxrfg-qaaaa-aaaar-qchfa-cai` |
| Wasm | `target/wasm32-unknown-unknown/release/shielded_pool.wasm` |
| `expected_wasm_hash` | `77b719e20aeb938786549509b052f8a6434c1f5b5bb7151112b7f5a6c2caffd0` |
| arg file | `deployment/mainnet/shielded_pool_init.bin` |
| `expected_arg_hash` | `be113f2c64e2d8a6daff981325aeaac2f4d77fe9ae4c2345f565833a34b2199b` (unchanged by RR-1a / A-7 REBASE — the artifact was not re-derived) |

Two fields deserve a second look before you submit:

- `staking_canister = cpdab-…` — the **Vault**, not a staking canister. Staking
  is not installed at launch (D1) and the field is pinned to the Vault by
  freeze §14. It looks wrong; it is correct.
- `verifier_canister = opt arjxl-…` — supplying it here is what keeps
  `private_spend` from coming up fail-closed on `VerifierUnavailable`. It is
  declared init-writable in `custody_manifest.toml` as `authority_field
  VERIFIER_CANISTER` because the interface could not express it.

`initial_vk_hash` is `sha256(circuits/verification_key.json)` =
`84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914`, equal to
`genesis_manifest [pool_init].vk_hash` (A-4).

Read back:
```bash
dfx canister --network ic info cxrfg-qaaaa-aaaar-qchfa-cai
dfx canister --network ic call --query cxrfg-qaaaa-aaaar-qchfa-cai get_verifier_canister '()'
```

---

## 5. smoke_alarm_monitor — last (step 9)

| | |
|---|---|
| role | `smoke_alarm_monitor` |
| target | `awir7-uiaaa-aaaar-qchiq-cai` |
| Wasm | `target/wasm32-unknown-unknown/release/smoke_alarm_monitor.wasm` |
| `expected_wasm_hash` | `8428ee40bb4f3d73c53102ccd8b9d7ae6790d83fd19ed79e92cdb14e7414f8dc` |
| arg file | `deployment/mainnet/smoke_alarm_monitor_init.bin` |
| `expected_arg_hash` | `0a0d97ed86197ab85b521d9cde5559495607146a631a02468481c36e2b733cf1` |

**Its config is immutable and the canister is blackholed at launch.** There are
no setters. `validate_config` traps at install on an anonymous or management
principal, an interval below the minimum, a staleness bound tighter than the
interval, or a capacity outside `1..=4096` — install is the last moment a wrong
value is still fixable. Cadence: 5-minute refresh, 15-minute staleness bound,
288 history slots (24 h).

This is the certified solvency monitor that reads the **pool attestation**. It is
**not** the `reserves.stsh.fi` page — that is the `solvency_status` asset
canister, `pyeop-7yaaa-aaaam-ajfja-cai`.

Read back:
```bash
dfx canister --network ic info awir7-uiaaa-aaaar-qchiq-cai
dfx canister --network ic call --query awir7-uiaaa-aaaar-qchiq-cai get_config '()'
dfx canister --network ic call --query awir7-uiaaa-aaaar-qchiq-cai get_health_status '()'
```

`get_config` must echo the four principals and the three cadence numbers exactly.
`get_health_status` may read unhealthy for one refresh interval immediately after
install; it should go green within 5 minutes once every source is installed.

---

## 5a. Pool VK activation ceremony — step 9a (PROT-24)

**This is an install BLOCKER, not a nicety. Installing the pool without doing
this leaves `PINNED_CIRCUIT_VERSION` at `0` and every spend rejected
`CircuitVersionMismatch` (`canisters/shielded-pool/src/lib.rs:7951`).** The
shipped wallet bundle pins `circuitVersion: 3`
(`wallet/src/zk/spendManifest.json`) and `wallet/src/zk/artifacts.ts` throws
`circuit version mismatch: pool 0 vs manifest 3` **before** any `private_spend`
is even sent — so the symptom is "the wallet is broken", with nothing wrong on
chain to point at. Source: `ASTRA_PHASE2_ROADMAP_V1` §1.1/§6, SSoT V9.1 §8
item **9a**. Owner ceremony work; **no code change and no kit edit** — the kit's
`shielded_pool_init.did` already names the Vault as governance controller.

**Do this after the pool install (step 8) and after the monitor (step 9), and
BEFORE A-5/A-6 and the separate Owner word that opens the pool.**

### 5a.1 The proposal

The only writer of the pin is the pool's `schedule_vk_activation`
(`shielded_pool.did:801`), gated by `assert_governance_controller`, which
resolves to the pool's `staking` principal — the **Vault `cpdab-saaaa-aaaar-qca2q-cai`** per `deployment/mainnet/shielded_pool_init.did:67` and
`genesis_manifest.toml`. So it is a normal Vault 2-of-3 proposal, in the
**Application** plane:

```
VaultActionKind = variant { Application : ActionRequest }
ActionRequest   = variant {
  PoolScheduleVkActivation : record { nat32; blob; nat64; nat64 }
}
```
(`canisters/vault/vault.did:141`, `:262-266`; Rust
`custody-types/src/lib.rs:852` `PoolScheduleVkActivation(u32, [u8;32], u64, u64)`.)

The four fields, in order — they are positional, unnamed, and easy to swap:

| # | field | value for this ceremony |
|---|---|---|
| 1 | `new_version : nat32` | **`3`** |
| 2 | `new_vk_hash : blob` (32 bytes) | **`84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914`** — the mainnet-v2 LAUNCH VK, == `sha256(circuits/verification_key.json)` == the verifier's `vk_hash()`. Encode as 32 raw bytes, **not** as the 64-character text. |
| 3 | `activation_timestamp_ns : nat64` | **T** — a UTC instant in the FUTURE. `schedule_vk_activation` returns `Err("Activation timestamp must be in the future")` if `T <= now`. Choose T comfortably after the expected quorum time, not minutes after propose. |
| 4 | `old_key_cutoff_ns : nat64` | **the deadline**, and it must be **strictly greater than T** (`Err("Old key cutoff must be after activation")`). It is validated and persisted as `OLD_VK_CUTOFF_AT` but is **NOT consulted** by verification: there is **NO dual-key grace window** — activation at T is an immediate hard swap. Do not plan around a grace period that does not exist. |

**Operator-page form fields — READ THIS BEFORE OPENING THE PAGE.** The operator
page does **not** carry this action. Its V1 action surface is deliberately
CLOSED to four `Management` variants plus `UpdateSignerSet`; every `Application`
variant, including `PoolScheduleVkActivation`, is explicitly unreachable from it
(`wallet/src/operator/proposals.ts` header). There are therefore **no form
fields to fill** — no Wasm picker, no arg-file upload, no `expected_wasm_hash` /
`expected_arg_hash` boxes. §0 of this runbook does not apply to step 9a. The
proposal is made by a direct signer-authenticated call to the Vault:

```bash
# propose (any signer). Second arg = caller-requested lifetime in ns; null = ruled default.
dfx canister --network ic call cpdab-saaaa-aaaar-qca2q-cai propose \
  '(variant { Application = variant { PoolScheduleVkActivation = record {
       3 : nat32;
       blob "<32 RAW BYTES of 84dba305…6914>";
       <T> : nat64;
       <T + Δ> : nat64;
  } } }, null)'
```
Returns `Ok : nat64` — **record the proposal id.**

**R-1 (SSA rehearsal): the propose call above is NOT an approval** —
`propose_inner` writes zero approvals; quorum is **two** distinct `approve`
calls (`vault/src/lib.rs:3205-3246`, `:3358-3371`). Do the rotation (board
step 7) BEFORE this proposal (a signer-set epoch bump kills any proposal left
non-terminal) — and within that rotation window, **Upgrader
`propose_membership_rotation` FIRST, then Vault `UpdateSignerSet`, each read
back before the next** (R-7, SSA rehearsal): the two planes are independent,
and rotating the Vault first while the Upgrader keeps the old roster risks a
recovery plane stuck at 1-of-3 if the Upgrader rotation then fails. Exact sequence:

1. `propose` as `4f6wg` (above) → record the proposal id.
2. `get_proposal '(<id>)' --query` as **any signer identity** (anonymous
   returns `null`) → read the commitment hash.
3. `approve` as `4f6wg` via dfx, bound to that commitment hash:
   ```bash
   dfx canister --network ic call cpdab-saaaa-aaaar-qca2q-cai approve \
     '(<id> : nat64, vec { <commitment hash bytes from step 2> })' \
     --identity default
   ```
4. `approve` by one II on `#/operator`, pasting the same commitment hash
   (approving by id alone is refused — CUST-SSA-001).

Adding this action to the operator page is UI backlog (SSoT O-11); do not wait
for it, and do not improvise a generic dispatcher.

### 5a.2 Trigger the activation — it does NOT happen by itself

Activation is **lazy**. `maybe_activate_pending_vk` is called only from
`verify_proof_envelope` (`shielded-pool/src/lib.rs:7945`) and from
`private_spend` — **never from a query.** Passing T changes nothing on its own:
the attestation keeps reporting version `0` until an update call runs the swap.

**R-8 (SSA rehearsal): "make one `private_spend`, it may be rejected" is not a
sufficient instruction — most hand-built calls reject BEFORE reaching the
activation code at all, and that silent rejection looks exactly like the
"expected" rejection this section used to wave through.** `private_spend`
(`shielded-pool/src/lib.rs:5662`) reaches `validate_private_spend_static`
(`:11292`) → `verify_proof_envelope` (`:7945`, the only other caller of
`maybe_activate_pending_vk` besides the recheck at `:11696`) **only after**
passing, in order:

1. `AnonymousCaller` (`:5562`) — **the call must be signed**, not anonymous.
2. `SPENDS_PAUSED` (`:5566`) — spends must not be paused.
3. `recovery_gate()` (`:5578`) — the recovery plane must not be blocking.
4. `assert_deployment_config()` (`:5585`) — the call's
   `expected_deployment_config_hash` must be **`null`** (`None` is the only
   value that passes unconditionally, `:10789-10792`); any other value returns
   `DeploymentConfigMismatch` and activates NOTHING — this is the failure mode
   most likely to be mistaken for the "expected" rejection.
5. The idempotency branch (`:5591-5605`) — use a **fresh** `spend_id`, never a
   replayed one.
6. The fee-params snapshot.
7. `proof_bytes` size ≤ `EXPECTED_GROTH16_PROOF_BYTES` and `encrypted_outputs`
   not oversized (`:11272-11289`).

Only after all seven does the call reach `verify_proof_envelope`, activate the
pending VK, and then fail on the actual proof content.

**The success SIGNAL to look for on this call is the error
`PoolError::CircuitVersionMismatch { expected, got }`
(`canisters/shielded-pool/src/lib.rs:3199`, `:7952`) — and `expected` MUST
read `3`.** `expected` is the pool's OWN pinned circuit version, read back
after the activation swap: `expected == 3` means the activation ran;
`expected == 0` means it did NOT — that call, however "rejected" it looked,
did not reach `maybe_activate_pending_vk`, and this is the failure most
likely to be mis-recorded as a success. `got` is whatever version the proof
happened to cite and is not diagnostic either way. **Any error other than
`CircuitVersionMismatch` (in particular `DeploymentConfigMismatch`) means the
trigger did NOT reach the activation code and nothing was activated.** Write
and rehearse the exact candid call text on a replica before the ceremony,
signed, with `expected_deployment_config_hash = null` and a fresh `spend_id`
— do not compose it at the console. Record which call it was and its exact
error including the `expected` value.

**The call's error is a same-call signal, not the record.** It is read once,
in the moment, and cannot be re-queried afterward. The authoritative,
durable criterion for whether 9a succeeded is 5a.3's query read-back below —
`get_circuit_version() == 3` — which is idempotent, independently
re-checkable at any later time, and is what the wallet and the smoke-alarm
monitor both actually rely on. Do not close the ceremony record on the call
error alone; close it on the 5a.3 read-back.

Do not attempt to verify before T has passed and the triggering call has been
made: a query read at that point reports `0` and looks like a failed ceremony.

### 5a.3 Read back, then open

```bash
dfx canister --network ic call --query cxrfg-qaaaa-aaaar-qchfa-cai get_circuit_version '()'
dfx canister --network ic call --query cxrfg-qaaaa-aaaar-qchfa-cai get_pinned_vk_hash '()'
dfx canister --network ic call --query cxrfg-qaaaa-aaaar-qchfa-cai get_deployment_attestation '()'
```

All three must agree before the pool is opened:
- `get_circuit_version()` = `(3 : nat32)`.
- `get_pinned_vk_hash()` = `84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914`
  = the verifier's `vk_hash()`.
- `get_deployment_attestation()` shows `circuit_version = 3` and the same
  `vk_hash`. This is the query the smoke-alarm monitor reads.
- The wallet release panel's **Circuit version** row agrees
  (`wallet/src/release/walletPanel.ts`).

**Record in the ceremony record: the proposal id, its execution outcome, T, the
deadline, and the triggering `private_spend` call.**

---

## 6. After all installs

- `canister_ids.json` maps only `shielded_pool` and `solvency_status`, so every
  command in this runbook uses **raw principals**. Do not expect `dfx` to resolve
  the others by name.
- `custody_manifest.toml` rows whose `launch_value = "PENDING(...)"` stay PENDING
  text after A-7. Rebinding them is a **separate record lane** — nothing in this
  runbook changes them.
- Next in sequence: the ring closure and controller cutover, which are governed
  by `MAINNET_DEPLOYMENT.md` and the custody freeze, not by this document.

## 6b. Reconciling an `OutcomeUnknown` install (VR-1)

**When you need this.** A Vault `InstallCode`/`Upgrade` proposal reached quorum,
the Vault made the management call, and the management canister **rejected** it
(e.g. `Canister <target> is out of cycles`). The Vault maps every call rejection
to `OutcomeUnknown`: the proposal keeps its artifact bytes and keeps the
**single-flight lock** on that target, so a re-proposed install on the same
target is refused `IllegalSourceState` (the operator page surfaces this only in
the top notice — it can look like "no proposal appeared"). Nothing happened
on-chain; the install simply never applied.

This happened live on 2026-09-13 with proposal **#10** (InstallCode →
`cmuzd-kyaaa-aaaar-qchhq-cai`, `merkle_tree.wasm`). VR-1 is the fix: the
existing `ReconcileUpgraderUpgrade` action now also admits a target whose action
is `Management::InstallCode` or `Management::Upgrade`.

**No install or top-up should be attempted until the Vault carries VR-1 and the
stranded proposal is terminalized.**

**Sizing the top-up — 34-node prices (2026-09-14).** Subnet `pzp6e-…-yae` is a
**34-node** application subnet, not the 13-node default most in-tree cycle figures
were derived against (source: CTO handoff 2026-09-13 item 2; SSoT V9 §1 row **D9-4**).
Application-subnet pricing scales with node count, so 13-node figures understate cost
by **×≈2.6** (34 ÷ 13 = 2.615): canister creation is **≈1.3 T**, not the ≈0.5 T a
13-node reading implies, which is why each 2 T birth left only ≈0.7 T and why
proposal **#10 above is the live instance of 34-node under-funding** — it was
rejected `out of cycles, top up ≥162B`. **Owner sizing, standing: top up 1 T per
canister immediately before each install, and 2 T for the pool (`cxrfg`).** Do not
size from memory or from any 13-node figure elsewhere in the tree. (The
`CREATE_CANISTER_CYCLES = 2_000_000_000_000` constant in `canisters/vault/src/lib.rs`
still carries the 13-node comment; correcting it is roadmap item **PL-7**, out of
scope while source freeze `2297a6c` holds. The nine canisters are already born, so
the constant has no further effect before launch.)

### 6b.1 Upgrade the Vault (Owner, sole controller during the bootstrap window)

Anonymous pre-check — confirm what is running before you replace it:

```bash
dfx canister --network ic info cpdab-saaaa-aaaar-qca2q-cai
```

Expect the PRE-VR-1 module hash
`0xd7d128b87f4d91de48f959e6f128771a02100cf1c93d8f4dbc0d0200bdae6578` and
`Controllers: 4f6wg-...` (the Owner identity — the ring is not closed yet).

Upgrade. The Vault's `post_upgrade` takes **no argument**, so pass none (`dfx`
sends the empty tuple `()` by default):

```bash
dfx canister --network ic install cpdab-saaaa-aaaar-qca2q-cai \
  --mode upgrade \
  --wasm ~/stsh-vaultdeploy/wasm/vault_vr1_ee690263.wasm \
  --identity default
```

**R-10 (SSA rehearsal):** use the staged, hash-verified file
`~/stsh-vaultdeploy/wasm/vault_vr1_ee690263.wasm` — **not**
`target/wasm32-unknown-unknown/release/vault.wasm`, which does not exist in a
clean tree and is not what the board stages; the two resolve to the same bytes
only if the Owner rebuilds first, and the staged file is already
hash-verified. Its sha256 must equal `[wasm.vault]` in
`deployment/mainnet/release_hashes.toml` (`ee690263…4ed8f8`).

Post-check — the **authoritative** post-check is the anonymous module hash,
not `get_build_info`:

```bash
dfx canister --network ic info cpdab-saaaa-aaaar-qca2q-cai
```

Expect `Module hash: 0xee690263c1e0cf0ae33c4afdaf8fb77233791e0b741ee6e4302824c55d4ed8f8`.

**R-4 (SSA rehearsal): `get_build_info` is NOT proof of VR-1.** It returns only
`format!("vault v{CARGO_PKG_VERSION}")` — a crate-version string
(`vault/src/lib.rs:6445-6448`) — which cannot distinguish VR-1 from pre-VR-1 if
the crate version did not move. It is optional supplementary evidence ("must be
readable"), never the success criterion:

```bash
dfx canister --network ic call cpdab-saaaa-aaaar-qca2q-cai get_build_info '()' --query
dfx canister --network ic call cpdab-saaaa-aaaar-qca2q-cai get_governance_summary '()' --query
# threshold 2, 3 signers, epoch unchanged
```

Governance is untouched by the upgrade: signers, threshold, every proposal and
its commitment hash, and the single-flight lock all survive.

### 6b.2 Observe the target, then propose the reconcile

The evidence must be **observed, not assumed**, and it must be **fresh**. Take
the observation and the timestamp together:

```bash
dfx canister --network ic info cmuzd-kyaaa-aaaar-qchhq-cai   # module hash, controllers
date +%s%N                                                    # observed_at_ns — take it HERE
```

`dfx canister status` is **controller-gated** and you are not a controller of
`cmuzd` (the Vault is), so do not try to call it — `info` is the anonymous
surface and it carries the two facts that matter.

For #10 the true observation is: `Module hash: None`, `Controllers:
cpdab-saaaa-aaaar-qca2q-cai`. Submit `observed_canister_status = variant
{ Running }` as the asserted default: for THIS reconcile it is **not
load-bearing**. The terminal mapping requires module hash == expected AND
Running AND controllers == [Vault] (lib.rs `execute_reconcile_upgrader_upgrade`),
so with `observed_module_hash = null` the first conjunct already fails and the
mapping yields `Failed` whatever the status says. That `Failed` IS the intended
terminalization of #10.

Two hard freshness rules (`MAX_EVIDENCE_AGE_NS` = 24h):

- `observed_at_ns` must be **newer than the target proposal's intent stamp**
  (#10: 2026-09-13 ~12:26Z), and not in the future; and
- the reconcile must be proposed **and approved to quorum within 24h** of
  `observed_at_ns`.

Violate either and the reconcile self-fails, the target is left untouched
(still `OutcomeUnknown`, still locked), and you simply propose a new one with a
fresh observation. That is safe by design.

Propose as signer `4f6wg` (the operator page has no reconcile form yet):

```bash
dfx canister --network ic call cpdab-saaaa-aaaar-qca2q-cai propose '(
  variant { ReconcileUpgraderUpgrade = record {
    proposal_id = 10 : nat64;
    objective_evidence = record {
      observed_upgrader_principal = principal "cmuzd-kyaaa-aaaar-qchhq-cai";
      observed_module_hash = null;
      observed_controllers = vec { principal "cpdab-saaaa-aaaar-qca2q-cai" };
      observed_canister_status = variant { Running };
      observed_at_ns = <the date +%s%N value> : nat64;
    };
  }},
  null
)' --identity default
```

`propose` takes **two** arguments — `propose : (VaultActionKind, opt nat64)` —
so the trailing `null` is required. Omit it and the call is rejected on arity
before any of the above is even read.

**What that second argument is (O-9 correction).** It is the **caller-requested
proposal lifetime, in nanoseconds** — NOT an "expected-epoch" argument, and not
the governance epoch. `vault.did` states it at the `propose` declaration: *"R3.1 —
the optional argument is the CALLER-REQUESTED lifetime in ns. null takes the
ruled default. A caller cannot choose an effectively permanent expiry: an explicit
request is bounds-checked, and refused outright while the bounds are unruled."*
`propose_inner` binds it as `requested_lifetime_ns` and resolves it through
`resolve_expiry_with(proposal_lifetime_bounds(), created_at_ns,
requested_lifetime_ns)`, rejecting with `VaultError::LifetimeOutOfBounds` **before**
any durable write — so a rejected lifetime leaves no proposal and consumes no id.
Passing `null` here is the intended call; it takes the ruled default lifetime.

The **expected-epoch** concept is a different mechanism and a different argument:
it is the `approve` second argument — the **expected commitment hash** read from
the proposal view (`vault.did`, R1.5) — together with the governance-epoch
binding. Do not conflate the two; §5a.1's gloss ("Second arg = caller-requested
lifetime in ns; null = ruled default") is the correct reading for `propose`
everywhere in this runbook.

`observed_upgrader_principal` is a **frozen field name** (custody-types is not
edited by VR-1). For a management target it carries the **target** principal —
here `cmuzd`, not the Upgrader. Get this wrong and the reconcile fails closed
with the target untouched.

**R-1 (SSA rehearsal): the propose call above is NOT an approval.**
`propose_inner` writes the record with zero approvals; quorum is **two**
distinct `approve` calls (`vault/src/lib.rs:3205-3246`, `:3358-3371`) — `4f6wg`
must ALSO call `approve`, it does not count as approver #1 by virtue of having
proposed. Exact sequence for this reconcile:

1. `propose` as `4f6wg` (above) → record the returned proposal id.
2. `get_proposal '(<id>)' --query` as **any signer identity** (anonymous
   returns `null` — `get_proposal` is signer-gated) → read the commitment hash
   bound to this proposal.
3. `approve` as `4f6wg` via dfx, bound to that commitment hash:
   ```bash
   dfx canister --network ic call cpdab-saaaa-aaaar-qca2q-cai approve \
     '(<id> : nat64, vec { <commitment hash bytes from step 2> })' \
     --identity default
   ```
4. `approve` by one II on `#/operator`, pasting the same commitment hash.

**R-2 (SSA rehearsal): the operator page shows nothing to check for a
reconcile proposal.** The page's `actionSummary` has no branch for
`ReconcileUpgraderUpgrade` and falls through to the bare action name — the
card literally reads `ReconcileUpgraderUpgrade`, with **no target, no
proposal id, no evidence** (`operator.ts:385-413`), even though the Approve
control is offered unconditionally (`:483-512`). **Before approving on the
page, the II signer must independently read `get_proposal '(<id>)' --query`
by dfx (or the equivalent signer-authenticated query) and compare the decoded
`target` and `observed_*` evidence fields against what was actually observed
in §6b.2 above** — the page cannot be used to perform that check itself.

### 6b.3 Confirm, then resume

```bash
dfx canister --network ic call cpdab-saaaa-aaaar-qca2q-cai get_proposal '(10 : nat64)' --query
```

Expect #10 `outcome = variant { Failed }` — module hash `None` means the install
never applied, so `Failed` is the CORRECT terminalization — with its artifact
bytes cleared and a `Reconciled` audit event carrying the approving signer set.
The reconcile proposal itself shows `Executed`. `Executed` on the target would
only be returned if the observed module hash had matched the proposal's
`expected_wasm_hash` under controllers exactly `[Vault]` and status `Running`.

The lock is now gone: a fresh `InstallCode` on `cmuzd` is admitted. Top up the
target first (§1.1 / the cycle notes), then re-propose the install and continue
the §3 order from `merkle_tree`.

Reconciliation is **exactly once**: #10 is terminal and can never be reconciled,
re-proposed, or re-triggered again.

## 6b-bis. Operator reconcile evidence — pointer

Post-launch pool reconciles are **not** governed by this runbook. One rule is
pointed at here because it is destructive and irreversible and there is no
tombstone to recover from: before asserting `NotExecuted` on a stuck deposit
(`reconcile_deposit_transfer_not_executed`), the operator must gather and record
the ledger evidence set **outside the canister**, because the endpoint deletes the
record, the nonce and the recovery locator and writes nothing in their place.

See **`docs/POOL_OPERATOR_RECONCILE_RULES.md`** §1. That page is the single writer
for this rule; do not restate it here.

## 6c. Identity rotation — pointer

**This runbook does not own principal collection or signer/recovery rotation.**
Those are WT-1 Phase B/C steps (brief `BRIEF_WT1` V3, `0a80d32a` + Addendum A
V2 `5f1e8730`) — see the board, not this document, for the full procedure.

One rule from that phase is restated here because it is easy to get wrong on
the transitional bundle this runbook's installs run under: **each role (Owner,
II 2, founder, counsel) must log in at BOTH origins — `https://app.stsh.fi`
(alias-rooted) and the `s3tyu` native origin (`https://s3tyu-….icp0.io`,
canister-rooted) — and record BOTH principals as a pair.** The two origins
render an identical UI, so a session opened from a bookmark, a redirect, or a
link in the alt-origins doc can silently collect the alias-rooted principal
instead, and that principal would then be baked into an immutable genesis
argument (token/vesting) with no way to correct it later. **The
canister-rooted (native-origin) principal is the roster value** used
everywhere downstream (RR-1b, genesis args, signer/recovery rosters); the
alias-rooted principal is recorded only as a labelled negative, never used.
Source: `SSA_REHEARSAL_MAINNET_SEQUENCE_R1_2026-09-14.md` R-6.

**Where the rotation is RECORDED (ROT-LEDGER, 2026-09-19).** The `[rotation]`
ledger in `deployment/mainnet/vault_authorities.toml` is the in-repo record of
what the rotation actually did, per plane, and it is machine-checked on every
gate run (`verify_custody_manifest --deploy-posture`). Read its header block
first: the `signers` / `[recovery].members` pinned above it are INSTALL-TIME
pins, and once the rotation executes they and the live canisters disagree by
design until the record-only lane ROT-LEDGER-FILL reconciles them.

The Owner's read-back evidence is what that lane consumes, so collect it at the
rotation and do not paraphrase it: per plane, the proposal id, the two approving
principals, the exact command text, the COMPLETE unedited stdout saved to a file
under `deployment/mainnet/evidence/`, `date +%s%N` plus the UTC time at
read-back, the identity that performed the read, and confirmation that
`list_proposals` showed zero non-terminal proposals before the Vault rotation.
The Upgrader plane rotates first; the ledger checks that ordering.

## 7. Regenerating the artifacts (maintainers)

The `.bin` files are reproducible from the `.did` text by a committed tool, on
any machine:

```bash
cargo run -p verify-custody-manifest --bin verify_a7_kit -- --emit .
```

`--emit` re-encodes each `.did` against its canister's own interface using
`candid_parser` 0.1.4 — the same parser `didc` is built on, and the same code
path the verification uses — then verifies. The gate never passes `--emit`: a
gate that can rewrite the artifact it checks checks nothing. After a regenerate,
update `arg_sha256` / `arg_text_sha256` in the kit and re-run the gate.

`init_type` is **not** hand-typed. `--emit` prints no type, so the canonical
rendering comes from the tool's own check-1 diagnostic: seed a deliberately
wrong `init_type`, run `verify_a7_kit`, and paste the `<iface> declares
\`<rendered>\`` half of the message it prints. A hand-written init type that
happens to be equivalent but not identical is a gate failure, and typing one
from the `.did` by eye is how you get one.

The two genesis `.bin` files added at RR-1b were additionally reproduced
**outside this tool** with `didc 0.6.2`
(`didc encode -d <interface>.did -t '<init_type>' "$(cat <arg>.did)"`), byte for
byte, exactly as the seven earlier ones were. That is the independence claim: the
committed bytes are not merely what this repo's own encoder happens to produce.
