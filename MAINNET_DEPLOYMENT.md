# STSH Mainnet Deployment Record

Status: PARTIAL — the ceremony fields are now LAUNCH-FINAL. **The mainnet-v2 trusted setup RAN on 2026-09-12 (lane A-4): phase 1 is the PUBLIC Hermez powers-of-tau (power 15, 54 named contributors + beacon), phase 2 is a single operator contribution finalized by the pre-announced public drand beacon at round 6460200. F6-1 is CLOSED.** The remaining trust assumption is the single-operator phase 2, disclosed in `docs/ceremony/CEREMONY_RECORD_v3.md` §4.2 (E10/CR-12); the community multi-party re-ceremony stays POST-launch and is no longer a launch blocker. The domain constants and verifier init-args description are final. Deploy-time fields (tagged release commit, per-canister Wasm hashes, controllers, init args) remain `TODO` until the real mainnet install.

This is the Gate C deliverable named in the launch framework's 10-step work order (item 5) and is part of the auditability publication list.

## How to fill this in

For each canister: build from a clean checkout of the tagged release commit, record the Wasm hash with `sha256sum`, record the exact init args passed to `dfx deploy --network ic`, and record the controller principal(s) set at install time. Do this from the live `~/stsh` tree, not from any local mirror — hashes from a stale checkout are worthless here.

**`OWED AT INSTALL` markers (B-1).** A per-canister field tagged **OWED AT INSTALL — not yet recorded** is an install-time value — a Wasm hash, an init-arg record, a controller principal — that is a **ceremony byproduct**: it does not exist until the Owner performs the install, and it cannot be derived from the repository. Each marker names the install step of `docs/A7_INSTALL_RUNBOOK.md` §2 that supplies it and the artifact it is read back from. They are marked rather than left blank because a bare `- Wasm hash:` is indistinguishable from an oversight, and the distinction is the whole point: these are **owed**, not **missed**. Never fill one from a value that "looks derivable" — if it looks derivable, it is a guess, and a guessed hash or principal in this record is worse than an empty one.

**Rollback/emergency procedures are complete (B-1, verified 2026-09-15).** All eight `- Rollback/emergency procedure:` sections — `stsh_token`, `shielded_pool`, `nullifier_registry`, `merkle_tree`, `verifier`, `treasury`, `vesting`, `wallet_frontend` — carry the full seven-point structure (Authorization / Upgrade-vs-reinstall / Target artifact / Pre-change fixture / State-compatibility one-way doors / Post-rollback verification / What is NOT recoverable), plus the `stsh_vetkeys` break-glass paragraph. Any record that still lists these as blank is stale; do not re-open the item on the strength of a line-number citation without reading the sections.

## Deployment-wide fields

| Field | Value |
|---|---|
| Deployment commit hash | TODO — tag the release commit once Gate A closes |
| Verification key hash | `84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914` (sha256 of `circuits/verification_key.json` — **LAUNCH VK, produced by the mainnet-v2 launch ceremony, 2026-09-12: phase 1 = the PUBLIC Hermez powers-of-tau (powersOfTau28_hez_final_15.ptau, 54 named contributions + beacon); phase 2 = one operator contribution (`FutureProof operator 2026-09-12`) finalized by the pre-announced public drand beacon, mainnet chain round 6460200 (`drand mainnet round 6460200`, iterationsExp 10, LAST contribution). Record: `docs/ceremony/CEREMONY_RECORD_v3.md`**) |
| Trusted setup ceremony transcript reference | `docs/ceremony/CEREMONY_RECORD_v3.md` (generation `mainnet-v2`, run 2026-09-12). Phase 1 is the PUBLIC Hermez ptau — NOT single-participant. Phase 2 is ONE operator contribution finalized by the pre-announced drand round 6460200 beacon; the single-operator phase-2 residual is disclosed in record §4.2 (E10/CR-12) and is the remaining trust assumption. `verify_ceremony.mjs --generation next` is all-PASS and is wired into `./run_gate.sh` leg [5/5]; `--generation m5` is SUPERSEDED and reports SKIP. |
| Pool/verifier controller parity (P15-002 / DEF-078) | TODO — verify post-install: pool and verifier controllers are exactly [Vault], matching `deployment/mainnet/custody_manifest.toml` and the P15-002 gate under `### verifier` |
| Denomination ladder (K-1, A6.6) | Five tiers: **1,000 / 10,000 / 100,000 / 1,000,000 / 10,000,000 STSH** (`DENOMINATIONS`, pool + wallet mirror). Authority: `OWNER_RULING_LAUNCH_LADDER` 2026-09-08, re-affirming S9 D-3. Smaller tiers are opened later by pool upgrade as the price rises. The TOP tier fixes the circuit's value bound — `MAX_NOTE_VALUE` = `CIRCUIT_MAX_VALUE_E8S` = 10^15 e8s — so the two can never be changed independently. |
| Exit-boundary disclosure (A6.6) | The top denomination and the circuit bound are the SAME number, so there is no headroom above a top-rung note: at any nonzero fee the fee is paid FROM the note, and the largest exitable `public_amount` is therefore strictly below the note's face value. "Exit the whole note" is not an operation the system can perform. This is the fee model working as designed, not a defect — but it is user-visible and is stated here so it is not discovered in production. |
| TVL cap (K-4, A6.6) | **60,000,000 STSH.** Authority: `OWNER_RULING_TVL_CAP_60M` 2026-09-08 (K-4 / J-9 closed). **A documented operational parameter with NO code enforcement** — no canister rejects a deposit that would carry total value locked past this figure, and no test asserts it. It is a monitoring and governance threshold, not an invariant; treating it as enforced would be a false assurance. |
| Network | `ic` (mainnet) per `dfx.json` |
| dfx version used for build | TODO — record exact version; see `REPRODUCIBLE_BUILD_REVIEW.md` for why this needs pinning |
| Rust toolchain version used for build | TODO — record exact version; currently unpinned, see `REPRODUCIBLE_BUILD_REVIEW.md` |

## Per-canister record

Canister list below is taken from the workspace `Cargo.toml` members and `canisters/` directory (`dfx.json` at the release commit is the list — 13 entries at d018ab85: 10 rust + 1 custom (`vetkeys`) + 2 assets (`wallet_frontend`, `solvency_status`), `staking` deliberately absent per D1); record the SHA at release cut, not here.

### stsh_token
- Wasm hash: **OWED AT INSTALL — not yet recorded.** Supplied by install **step 6** (`docs/A7_INSTALL_RUNBOOK.md` §2). Read back from `deployment/mainnet/release_hashes.toml` `[wasm.stsh_token]`, which must equal the `wasm_sha256` of the `stsh_token` entry in `deployment/mainnet/a7_install_kit.toml`; `./run_gate.sh` re-derives both. Reproducible **only** under the gate's `env -i` build (law 7(f)). Do not invent a value.
- Init args: **the canonical artifact `deployment/mainnet/stsh_token_init.did` ONLY** —
  verified field-by-field against the approved manifest `deployment/mainnet/genesis_manifest.toml`
  (P-ARITH G-1; supersedes the old "pull from `TOKENOMICS_PROPOSAL.md`" line). The deploy
  passes THIS FILE via `--argument-file`; hand-reconstructed init args are a Gate-D violation.
- **Gate-D (P-ARITH + R-3 principal binding, REQUIRED before install — RR-2):**
  RR-1 is FIVE numbered steps, not one, since remediation lane R-3 (H-3). Filling the
  three install inputs is no longer sufficient: the inputs are checked against
  `deployment/mainnet/genesis_principals.toml`, an INDEPENDENT record that no deploy
  path reads. A principal written coherently into all three inputs but absent from the
  record is exactly the attack `GP2-value-<ROLE>` exists to refuse.

  1. **Resolve the record first.** For each role in `deployment/mainnet/genesis_principals.toml`,
     replace `principal = "PENDING"` with the ruled production principal and
     `provenance = "PENDING"` with a digest listed in `GENESIS_ATTESTATION_DIGESTS`
     (`scripts/verify_genesis_manifest/src/lib.rs`). A role marked
     `binding = "vault_authorities"` is CROSS-BOUND — leave it alone; its value is read
     from `deployment/mainnet/vault_authorities.toml`'s `[recovery].vault` and must never
     be copied into the record.
  2. **Fill the same principals into the three install inputs** — `genesis_manifest.toml`,
     `stsh_token_init.did` and `vesting_init.did` (RR-1 proper). The cross-bound role's
     sites take the Vault principal (freeze §14).
     Do NOT do this before step 1: an input populated under a still-`PENDING` record entry
     is refused by `GP1-pending-input-populated-<ROLE>`, at any posture.
  3. **Flip `rr1_performed` to `true`** in the record. This makes the gate STRICTER, not
     laxer: from that point the posture stage passes only when the observed failing set is
     EXACTLY EMPTY.
  4. **Regenerate the record pin LAST**, after every other edit to the record, and update
     `GENESIS_PRINCIPAL_RECORD_SHA256` in `scripts/verify_genesis_manifest/src/lib.rs` in
     the SAME diff — the pairing is the point:
     `sha256sum deployment/mainnet/genesis_principals.toml`
  5. **Run the gate.** `cargo run -p verify-genesis-manifest --bin verify_genesis_manifest --`
     (defaults to `deployment/mainnet`). Every check must PASS — the pre-R-3 set (checked
     sum == TOTAL_SUPPLY, canonical `subaccount = null`, custody/lock/vesting policy per
     bucket, `treasury` == treasury-allocation recipient, `fee_collector` non-null and !=
     treasury, founders recipient == the vesting canister) AND the principal-binding family
     `GP0`–`GP6`. Record the three printed artifact SHA-256 hashes HERE.

  `./run_gate.sh` runs the same tool in `--posture` form on every invocation and fails the
  gate when the observed failing set leaves what the record declares.
- **Gate-V phase 1 (pre-install, same run):** token `founders` recipient == the vesting-canister
  principal AND Σ(ALL schedules in `vesting_init.did`) == the **founders + counsel** allocation,
  checked arithmetic. The check is `V6-schedule-sum-eq-custody-allocation` in
  `scripts/verify_genesis_manifest`; the amount is NOT restated here — it is derived by that tool
  from `deployment/mainnet/genesis_manifest.toml`'s own allocation rows, and the figure this
  paragraph used to quote was the FOUNDERS-only total, which the check has not compared against
  since D-4 V2. Kept honest by `umc05_gate_v_doc_states_the_custody_formula_by_reference`.
- **Gate-V phase 2 (post-install — RR-3):** query `icrc1_balance_of(vesting canister)` on the
  token and sum the installed `list_schedules`, then run
  `cargo run -p verify-genesis-manifest -- deployment/mainnet --post-install
  --vesting-balance <N> --schedule-sum <M>` — both must equal the founders + counsel allocation. Fail
  closed on any mismatch; record the output HERE.
- Controller(s): **OWED AT INSTALL — not yet recorded.** Set at install **step 6** and read back with the `read_back` command in the `stsh_token` entry of `deployment/mainnet/a7_install_kit.toml` (`dfx canister --network ic info <id>`). Post-cutover the expected value is exactly `[Vault]` — see § *Ring closure* and `deployment/mainnet/custody_manifest.toml`. Record the observed principal(s); do not transcribe the expectation as if it were an observation.
- Upgrade policy:
  - **H-3 dedup time-index migration (STATE_VERSION 1→2).** A fresh mainnet install
    starts at v2 with an empty dedup map, so the one-shot migration is **INERT at
    launch** — there is nothing to reconstruct. It runs only if a canister already on
    v1 (a populated `TRANSFER_DEDUP` from a prior deploy) is upgraded to v2:
    `post_upgrade` back-fills `TRANSFER_DEDUP_BY_TIME` from the surviving primary map,
    dropping already-expired entries, **all-or-nothing**. If `TRANSFER_DEDUP` exceeds
    `MAX_MIGRATION_ENTRIES` (200,000 — sized ~6× under the `install_code`/`post_upgrade`
    DTS budget) the migration **traps and aborts the upgrade, leaving v1 running with
    state intact** (fail-closed; never a partial back-fill).
  - **Over-limit v1 recovery runbook** (not expected at launch — the fresh install is
    v2): prune is lazy and capped, so an over-sized `TRANSFER_DEDUP` shrinks only as
    subsequent `created_at_time` ops run. Drain the dedup window — its horizon is 24h
    `TX_DEDUP_WINDOW_NS` + 5min `PERMITTED_DRIFT_NS` — under low volume until the map
    is below the limit, then re-attempt the upgrade; or ship a staged intermediate
    version that back-fills in bounded chunks. Do **NOT** reinstall (see "Never
    reinstall as recovery").
  - **`stsh_token` MUST be upgraded with `pre_upgrade` — never `skip_pre_upgrade`.**
    All heap-only state (`BLOCK_HEIGHT`, fee reserve, mint flag, canister principals,
    and the migration `state_version`) is checkpointed to `STABLE_STATE_CELL` **only**
    in `pre_upgrade`. Skipping it either traps on an empty checkpoint (fresh install —
    the existing `post_upgrade` empty-cell trap) or restores a **stale** snapshot after
    any prior activity, resetting `BLOCK_HEIGHT` and producing **duplicate block
    indices**. Stable maps survive; heap state does not. There is no supported
    operational reason to skip `pre_upgrade` on this canister. The protective
    fresh-install trap is regression-guarded by
    `integration-tests/tests/h3_followup_skip_pre_tests.rs` (a real `install_code` with
    `skip_pre_upgrade: Some(true)` must trap; balances + the `BLOCK_HEIGHT` counter are
    proven preserved). **Known residual (not overclaimed):** this rule + the empty-cell
    trap make the fresh-install skip-pre path safe and forbid skip-pre operationally,
    but they do **not** eliminate the skip-pre-*after-a-normal-upgrade* silent-corruption
    path — mitigated by the operational rule until a persistence redesign or a
    `pre_upgrade`/`post_upgrade` clean-shutdown handshake lands (tracked future item, not
    a launch blocker).
- Dependencies: none
- Post-deploy checks: `icrc1_total_supply` matches finalized allocation; `icrc1_metadata` correct; minting authority matches decided policy (renounced vs. multisig)
- Rollback/emergency procedure:
  - **1. Authorization.** A rollback is a **new Vault 2-of-3 proposal** (`cpdab`), never a shortcut and never a direct `dfx` call — post-cutover the Vault is the sole controller and the `deploy-mainnet` recipe has been deleted (B-2), so no non-Vault install path exists. The Upgrader recovery plane is the fallback initiator only under its own documented break-glass conditions.
  - **2. Upgrade vs reinstall.** **Reinstall is UNCONDITIONALLY FORBIDDEN.** `upgrade` preserves stable memory; `reinstall` erases it. This canister IS the ICRC public ledger — one half of the supply boundary that ARCHITECTURE.md's non-negotiable law names. Erasing it erases every balance, allowance and block, and there is no second source of truth to rebuild from. Rollback = **governed upgrade** to the prior pinned Wasm, or forward-fix. Nothing else.
  - **3. Target artifact + where the bytes come from.** A rollback installs a *prior pinned* Wasm. `deployment/mainnet/release_hashes.toml` `[wasm.stsh_token]` (sha256 `a90318da268875caf8c8cfa4983a9039f4dda67e58a8a4d319ac979c0d19db0f`) is the **only** source of truth for those bytes, and it is reproducible **only** from a clean build under `run_gate.sh`'s `env -i` re-exec with the exact 13-package `build.command` (law 7(f)) — an interactive shell or a no-op rebuild can present different or stale bytes. Verify with `sha256sum target/wasm32-unknown-unknown/release/stsh_token.wasm` against that row **before** the proposal is drafted. Never rebuild a "close enough" binary under time pressure.
  - **4. Pre-change fixture (is the target real?).** **None exists.** No `stsh_token_pre_*` fixture is resolved by `integration-tests/build.rs` or checked by `run_gate.sh`. The only genuine predecessor is a Wasm rebuilt from the prior release commit under the `env -i` gate build (pattern: `scripts/build_pool_pre_r15_wasm.sh`). Until such a fixture exists, **no predecessor upgrade of this canister has ever been rehearsed** — treat a rollback as untested and prefer forward-fix.
  - **5. State compatibility — one-way doors.** The newer Wasm may have written stable structures — ledger blocks, the dedup index, `BLOCK_HEIGHT`, allowance records — in a format the older one cannot decode; a failed `post_upgrade` on a ledger is unrecoverable. Note also the standing rule recorded above: `skip_pre_upgrade` is operationally forbidden on this canister. *Hold unsupported populated-state recovery pending an independently reviewed migration that preserves identity and state. Apply a governed forward corrective upgrade when the current format supports it; do not assume a previous Wasm can decode state written by a newer version.*
  - **6. Post-rollback verification.** `icrc1_total_supply` equals the finalized genesis allocation and reconciles against the escrow reserve; `icrc1_metadata`, `icrc1_decimals`, `icrc1_fee` unchanged; `icrc1_balance_of` on the treasury, vesting and pool principals matches pre-rollback values; the smoke-alarm monitor (`awir7`) returns a green, freshly certified snapshot.
  - **7. What is NOT recoverable.** Any block appended by the newer Wasm whose encoding the older cannot decode; the entire ledger if a reinstall is performed. **A reinstall here is a protocol-ending event, not an incident.**

### shielded_pool
- Wasm hash: **OWED AT INSTALL — not yet recorded.** Supplied by install **step 8** (`docs/A7_INSTALL_RUNBOOK.md` §2). Read back from `deployment/mainnet/release_hashes.toml` `[wasm.shielded_pool]`, which must equal the `wasm_sha256` of the `shielded_pool` entry in `deployment/mainnet/a7_install_kit.toml`; `./run_gate.sh` re-derives both. Reproducible **only** under the gate's `env -i` build (law 7(f)). Do not invent a value.
- Init args: **OWED AT INSTALL — not yet recorded.** Supplied by install **step 8**. The canonical artifact is `deployment/mainnet/shielded_pool_init.did`, encoded and hashed as the `shielded_pool` entry in `deployment/mainnet/a7_install_kit.toml` (`arg_did` / `arg_bin` / `arg_sha256` / `arg_text_sha256`). Record the exact `.did` text actually uploaded; hand-reconstructed args are a Gate-D violation. Do not invent a value.
- Controller(s): **OWED AT INSTALL — not yet recorded.** Set at install **step 8** and read back with the `read_back` command in the `shielded_pool` entry of `deployment/mainnet/a7_install_kit.toml` (`dfx canister --network ic info <id>`). Post-cutover the expected value is exactly `[Vault]` — see § *Ring closure* and `deployment/mainnet/custody_manifest.toml`. Record the observed principal(s); do not transcribe the expectation as if it were an observation. **P15-002:** must also equal the `verifier` controllers.
- Upgrade policy: (note: stable-persisted heap scalars per Track C — confirm post-upgrade hook runs clean on staging before mainnet)
- Dependencies: stsh_token, nullifier_registry, merkle_tree, verifier
- Post-deploy checks: `get_spend_status` reachable; verifier canister principal correctly wired; anchor/root checks pass against a real deposit. **P15-002:** `dfx canister --network ic info <pool>` controllers == [Vault]; and == the verifier's controllers. A verifier controllable by a non-pool-controller fails launch (DEF-078).
- **Launch fee activation (fee-build lane) — scripted, NOT a code default.** The
  pool's `GovernanceFeeParams::launch_defaults()` is deliberately **fee-free**
  (fail-safe: a fresh or mis-configured install never silently charges). The
  deploy script submits the existing typed Vault
  `Application(PoolSetGovernanceFeeParams(...))` proposal and records its
  executed result — this is a required step, not a manual afterthought or a
  signer-direct pool call. Use the documented launch configuration from its single
  source of truth: `stsh_fee_policy::MAINNET_LAUNCH_*` /
  `GovernanceFeeParams::mainnet_launch_config()`.

  **THE VALUES ARE NOT WRITTEN HERE, AND MUST NOT BE.** This document names the
  constant each field is set from; the constant is the single source of truth, and a
  figure transcribed into prose is the drift this section already suffered once
  (see the correction note below). Governing model:
  `OWNER_RULING_FEE_MODEL_CONSOLIDATED_2026-08-21` (`7db63d10103b8cb4`) for the
  model shape and the 0.25% value fee; `OWNER_RULING_FEE_FLOOR_2_5_STSH`
  2026-09-08 for the flat minimum and the fixed spend fee, both **2.5 STSH**
  (`250_000_000` e8s), superseding the 0.1 STSH of 2026-08-21. The guardrail
  band (floor 0.1 STSH, ceiling 5 STSH, 24 h cooldown) is unchanged.

  | Field to set | Read its value from |
  |---|---|
  | `shield_fee_bps` | `stsh_fee_policy::MAINNET_LAUNCH_SHIELD_FEE_BPS` |
  | `unshield_fee_bps` | `stsh_fee_policy::MAINNET_LAUNCH_UNSHIELD_FEE_BPS` |
  | `shield_flat_minimum_fee_e8s` | `stsh_fee_policy::MAINNET_LAUNCH_FLAT_MINIMUM_FEE_E8S` = 2.5 STSH — strictly INSIDE the guardrail band, no longer equal to `FLAT_MINIMUM_FEE_FLOOR_E8S` (0.1 STSH) |
  | `unshield_flat_minimum_fee_e8s` | the same constant as the shield side |
  | `protocol_private_spend_fee_stsh` | `stsh_fee_policy::MAINNET_LAUNCH_SPEND_FEE_E8S` (`FixedStsh` mode; the XDR-pegged target lands with the oracle lane) |
  | `params_epoch` | canister-stamped at bootstrap — an assertion, not a choice (see the guardrails below); the wallet `FeeQuote` binds to `fee_model_version` + `params_epoch` |

  The effective value fee is `max(flat_minimum, amount * bps / BPS_DENOMINATOR)`
  (integer floor), so the flat minimum dominates at small amounts. Shield charges it
  **on top**; the exit path takes it **from** the amount.

  > **Correction, 2026-08-23 (DOCFIX-2).** This block previously transcribed a flat
  > minimum of `100_000_000_000` e8s ("1,000 STSH") and cited RB-SWARM-A1 (2026-07-31)
  > as its authority. **Both were stale**: the shipped constant is `10,000×` smaller,
  > and that 2026-07-31 authority is superseded by `7db63d10103b8cb4`. The wrong
  > figure is recorded here rather than silently removed, because an operator who
  > acted on the old text would have set a flat minimum by that same factor too
  > large. Read the constants; never this prose.

  **The in-circuit fee wall is a DIFFERENT quantity with a different authority.** It is
  not a governance fee parameter, does not appear in this table, and must not be
  conflated with the flat minimum. Its source is the circuit itself
  (`circuits/spend.circom`'s `MAX_NOTE_VALUE`, mirrored as
  `shielded_pool::CIRCUIT_MAX_VALUE_E8S` and pinned equal to it by a source-parsing
  test). Separate values, separate lanes.

  Apply through a typed Vault Application(PoolSetGovernanceFeeParams(...)) proposal
  and require its receipt to be Executed immediately after install, before opening
  to the public. A signer-direct pool call is not an authorized deployment route.

  **Setter guardrails (RB-SWARM-A1).** This call is now the pool's ONE-SHOT bootstrap: it is
  exempt from the per-call change cap and the 24h cooldown, and that exemption closes
  permanently the moment it succeeds. Every subsequent tuning call is fully guarded
  (every bound read from its constant, none transcribed here: rates within
  `FEE_BPS_FLOOR`…`FEE_BPS_CEILING`; flat minimum within `FLAT_MINIMUM_FEE_FLOOR_E8S`…
  `FLAT_MINIMUM_FEE_CEILING_E8S`; private-spend fee within
  `PRIVATE_SPEND_FEE_FLOOR_E8S`…`PRIVATE_SPEND_FEE_CEILING_E8S`; rate movement capped
  at `MAX_BPS_CHANGE_PER_UPDATE` ABSOLUTE bps per call; STSH-amount movement bounded by
  `FEE_AMOUNT_MAX_RATIO_NUM`/`FEE_AMOUNT_MAX_RATIO_DEN` in both directions; cooldown
  `FEE_UPDATE_COOLDOWN_NS`, canister-owned). `params_epoch` in the argument is an **assertion**:
  it must equal the epoch the canister will store (1 at bootstrap) or the call is rejected —
  the caller never chooses the stored value. There is deliberately **no path** back to
  fee-free values through this endpoint.
- **R-15 payout memo key hard-gate — before opening the pool.**
  Submit the typed Vault Application(PoolInitializePayoutMemoKey) proposal and
  require its executed payload to decode exactly as Result<bool, PoolError> with
  Ok(true). Then submit ReadModel(PoolReadPayoutMemoKeyReady) and require a
  durable snapshot whose response is exactly Some(true). None is unauthorized
  and Some(false) is not readiness. Record both receipts and the snapshot ID.
  The initializer obtains randomness inside the canister; operators never supply or receive the key.
  Repeating initialization is safe and does not replace an existing Ready key.
  A new public-payout spend that cannot establish key readiness fails before
  note finality; lazy provisioning does not replace this pre-open readiness check.
  Preserve MemoryId 25 through upgrades; never repair a funded pool by reinstalling.

- **Initial-launch custody route complement (manifest and runbook census).**

  | Operation | Route status | Required deployment evidence |
  |---|---|---|
  | Initialize payout memo key | Existing typed Vault application route | Executed proposal/receipt with exact Ok(true) |
  | Read payout memo-key readiness | Existing typed Vault read-model route | Snapshot with exact Some(true) |
  | Read token supply reconciliation | Existing typed Vault read-model route | Select the unique Bound stsh_token BornUnderVault creation receipt ID through the signer-gated audit listing; the proposal commits that ID and the target receives empty args. Require a complete fold: `INCOMPLETE` is not a healthy supply verdict |
  | Set launch governance fee parameters | Existing typed Vault application route | Executed proposal/receipt using policy constants |
  | Read fee launch predicate/state | Existing public pool reads | Record fee_params_match_mainnet_launch_config and get_fee_governance_state |
  | Change fee-flush window | Future/policy-held operation | The 1 h default needs no launch setter; no new Vault route is introduced here |
  | Controller parity and cutover | Existing management/cutover ceremony | Record manifest-derived controller evidence |
  | Manifest authority readbacks | Existing public canister reads | Record actual pool, token, merkle, nullifier, treasury, vesting and verifier values |
  | Token allocation and vesting schedules | Existing public token and vesting reads | Record supply, balances, metadata and list_schedules |
  | Spend status | Existing owner-or-controller pool read | The live witness uses the actual wallet submitter |
  | IC controller/module state | Existing dfx canister info read | Record manifest-derived state; no new Vault route |
  | Vesting outstanding claim markers before a later populated upgrade | Missing required future route | Controller-only query is unreachable to ordinary Vault governance; hold that upgrade pending separate reviewed design |


  This covers the current custody manifest operations required for initial launch.
  It is not an exhaustive audit of every operator or future policy action, and it
  does not close the later populated-vesting upgrade gap recorded above.

  **Vault downgrade boundary.** The populated compatibility witnesses cover the
  supported forward d068-to-current upgrade. They do not approve a reverse upgrade
  to a pre-hardening Vault after new action or snapshot variants have been persisted;
  that downgrade remains held without explicit populated downgrade evidence. Recover
  with a governed forward corrective upgrade that preserves history. Never reinstall,
  delete proposals or snapshots, or rewrite stored proposal hashes.

- **P15-002 fee hard-gate — pool MUST NOT open to the public until this passes.**
  The pool now exposes this check directly, so it is a boolean rather than a human
  reading raw Candid:
  `dfx canister --network ic call <pool> fee_params_match_mainnet_launch_config '()'` → must be `(true)`.
  It returns `true` only when the LIVE params are EXACTLY
  `GovernanceFeeParams::mainnet_launch_config()` — every field, including the
  canister-stamped `params_epoch = 1`. `get_governance_fee_params` remains available
  for diagnosing a `false`.

  This is an **initial-launch predicate, not a permanent health check**: it legitimately
  returns `false` after the first governance tuning call. Assert on it in the deploy
  window only.

  `get_fee_governance_state '()'` reports the canister-owned control state
  (`last_fee_update_ns`, `params_epoch`, `launch_fee_activated`, `fee_update_cooldown_ns`) —
  `launch_fee_activated = true` confirms the bootstrap was consumed.

  A pool still on the fee-free defaults (or any mismatch) **fails launch** — the
  "live at launch" requirement is enforced here, operationally, not by a code default.

  > **THREAD-B INTERLOCK — open, not owned by RB-SWARM-A1.** The canister-side
  > deliverable is the query above. Making P15-002 impossible to skip still requires
  > the A7 deploy script to call `fee_params_match_mainnet_launch_config` immediately
  > after `set_governance_fee_params` and **fail the deploy** (non-zero exit) on
  > `false`, rather than leaving it as a checklist box a human ticks. That script edit
  > is a Thread B artifact and is deliberately not duplicated here.
- **R-2 (C-30) fee-flush window.** At launch the window is the code default (1 h) unless the Owner rules otherwise; read it back with `dfx canister --network ic call <pool> get_fee_flush_window_ns '()'` and paste the output. It is bounded to `[300 s, 24 h]` the default needs no launch setter; nondefault tuning is future/policy-held. A shorter window narrows the anonymity set of each published `PrivateTransferFee` row; a longer one only delays treasury settlement.
- **R-15 payout memo-key readiness — pool MUST NOT open to the public until this passes (J-27a, SSoT V8 §A.2).**
  R-15 derives every private-payout ICRC memo from an HMAC key held in the MemoryId 25
  CONTROL cell; a fresh install boots with `key = None`, and any `private_spend` that
  reaches payout dispatch before the key exists fails closed with
  `PayoutMemoKeyNotReady`. The key is provisioned once, from `raw_rand`, by an
  operator-controller call — this is a deploy-sequence step, not a code default:
  1. Submit Application(PoolInitializePayoutMemoKey) through the Vault and require
     exact Ok(true). Repetition is idempotent and does not rotate a Ready key.
  2. Submit ReadModel(PoolReadPayoutMemoKeyReady) through the Vault and require
     the stored snapshot response Some(true). Preserve proposal, receipt and snapshot IDs.
  Both steps sit AFTER install/upgrade and BEFORE the typed fee-parameter proposal;
  the key survives upgrades (CONTROL is stable) and is never reprovisioned by an upgrade.
- **R-15 legacy-payout absence — target-adoption prerequisite (J-27b; R-15 brief V4 §8, countersign 2026-09-08).**
  The R-15 module refuses to reconstruct a pre-R-15 non-terminal payout: on upgrade
  from STATE_VERSION 3 it traps `R15 ambiguous legacy adoption` if the CONTROL cell is
  already populated, and never resubmits a legacy record into a newly invented request.
  Before installing an R-15 Wasm on ANY target that has previously run the pool, record
  in the deployment packet one of:
  (a) **fresh install** — the target has never executed a public-payout spend (the intended mainnet path); state this explicitly with the install command and the pre-install `dfx canister --network ic status <pool>` showing no prior module, or
  (b) **verified absence** — the pre-upgrade operator active-listing pagination returns no non-terminal payout operation IDs, pasted in full, or
  (c) a separately reviewed, evidence-based migration plan (SSA GREEN on file) — reinstalling or deleting a funded pool is NOT an allowed workaround.
  Already-Finalized legacy records stay final and acquire no new memos or accruals.
- Rollback/emergency procedure:
  - **1. Authorization.** A rollback is a **new Vault 2-of-3 proposal** (`cpdab`), never a shortcut and never a direct `dfx` call — post-cutover the Vault is the sole controller and the `deploy-mainnet` recipe has been deleted (B-2), so no non-Vault install path exists. The pool holds user funds; the CTO reads the whole of this section aloud before the proposal is signed.
  - **2. Upgrade vs reinstall.** **Reinstall is UNCONDITIONALLY FORBIDDEN.** `upgrade` preserves stable memory; `reinstall` erases it. Reinstall destroys the nullifier reservation state machine, `PENDING_OUTPUTS`, the accepted-spend-root ring and every payout record — breaking laws **2** (a reserved nullifier must survive) and **3** (stage-before-finalize ordering; the active tree must contain only finalized commitments) and orphaning every shielded note. Rollback = **governed upgrade** to the prior pinned Wasm, or forward-fix. `skip_pre_upgrade` is forbidden.
  - **3. Target artifact + where the bytes come from.** A rollback installs a *prior pinned* Wasm. `deployment/mainnet/release_hashes.toml` `[wasm.shielded_pool]` (sha256 `77b719e20aeb938786549509b052f8a6434c1f5b5bb7151112b7f5a6c2caffd0`) is the **only** source of truth for those bytes, and it is reproducible **only** from a clean build under `run_gate.sh`'s `env -i` re-exec with the exact 13-package `build.command` (law 7(f)) — an interactive shell or a no-op rebuild can present different or stale bytes. Verify with `sha256sum target/wasm32-unknown-unknown/release/shielded_pool.wasm` against that row **before** the proposal is drafted. Never rebuild a "close enough" binary under time pressure.
  - **4. Pre-change fixture (is the target real?).** **Two exist, and they are the model for every other entry.** `target/wasm32-unknown-unknown/release/shielded_pool_pre_r15_test.wasm` — the exact `9f7c81e` checkpoint-v3 predecessor, rebuilt by `./scripts/build_pool_pre_r15_wasm.sh`, hash pinned in `run_gate.sh` (`PRE_R15_SHA256 = c692823e…`); and `target/wasm32-unknown-unknown/release/shielded_pool_pre_f2redact_test.wasm` — built from `018331a` (the last commit before F2-REDACT), resolved by `integration-tests/build.rs` as `POOL_PRE_F2REDACT_TEST_WASM`, recipe and hash in `run_gate.sh` (C-13 block). Both prove a real predecessor→current upgrade decodes; **neither proves the reverse direction**, which is what a rollback actually performs.
  - **5. State compatibility — one-way doors.** Read `docs/MEMORY_ID_REGISTRY.md` for this canister's MemoryId rows and confirm, row by row, that the older Wasm can decode every structure the newer one may have written. Specific known doors: the R-15 payout CONTROL cell (an R-15 Wasm traps `R15 ambiguous legacy adoption` on an already-populated cell), the F2-REDACT `PendingDeposit` `opt principal` widening, `STATE_VERSION`, the pinned circuit version / VK activation state, and the append-lease state — a lease left at `AppendUnknown` never times out on-chain and must be reconciled through the documented admission path, not by rollback. *Hold unsupported populated-state recovery pending an independently reviewed migration that preserves identity and state. Apply a governed forward corrective upgrade when the current format supports it; do not assume a previous Wasm can decode state written by a newer version.*
  - **6. Post-rollback verification.** `get_deployment_attestation` returns the expected `circuit_version` and `vk_hash` (this is the query the smoke-alarm monitor reads); `get_circuit_version()` = `(3 : nat32)` and `get_pinned_vk_hash` = `84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914`; `get_spend_status` reachable; the merkle root and `is_accepted_spend_root` agree with the `merkle_tree` canister; the verifier principal is still wired and controller parity (P15-002) holds; the monitor's solvency snapshot is green.
  - **7. What is NOT recoverable.** Any nullifier finalized, output promoted, or payout advanced by the newer Wasm in a format the older cannot decode. **A reinstall makes every outstanding shielded note permanently unspendable and the pool permanently insolvent against the escrow reserve.** There is no recovery.

### nullifier_registry
- Wasm hash: **OWED AT INSTALL — not yet recorded.** Supplied by install **step 3** (`docs/A7_INSTALL_RUNBOOK.md` §2). Read back from `deployment/mainnet/release_hashes.toml` `[wasm.nullifier_registry]`, which must equal the `wasm_sha256` of the `nullifier_registry` entry in `deployment/mainnet/a7_install_kit.toml`; `./run_gate.sh` re-derives both. Reproducible **only** under the gate's `env -i` build (law 7(f)). Do not invent a value.
- Init args: **OWED AT INSTALL — not yet recorded.** Supplied by install **step 3**. The canonical artifact is `deployment/mainnet/nullifier_registry_init.did`, encoded and hashed as the `nullifier_registry` entry in `deployment/mainnet/a7_install_kit.toml` (`arg_did` / `arg_bin` / `arg_sha256` / `arg_text_sha256`). Record the exact `.did` text actually uploaded; hand-reconstructed args are a Gate-D violation. Do not invent a value.
- Controller(s): **OWED AT INSTALL — not yet recorded.** Set at install **step 3** and read back with the `read_back` command in the `nullifier_registry` entry of `deployment/mainnet/a7_install_kit.toml` (`dfx canister --network ic info <id>`). Post-cutover the expected value is exactly `[Vault]` — see § *Ring closure* and `deployment/mainnet/custody_manifest.toml`. Record the observed principal(s); do not transcribe the expectation as if it were an observation.
- Upgrade policy: (stable-persisted per Track C)
- Dependencies: none
- Post-deploy checks: empty registry at genesis; `insert_batch` reachable only from shielded_pool principal
- Rollback/emergency procedure:
  - **1. Authorization.** A rollback is a **new Vault 2-of-3 proposal** (`cpdab`), never a shortcut and never a direct `dfx` call — post-cutover the Vault is the sole controller and the `deploy-mainnet` recipe has been deleted (B-2), so no non-Vault install path exists.
  - **2. Upgrade vs reinstall.** **Reinstall is UNCONDITIONALLY FORBIDDEN.** `upgrade` preserves stable memory; `reinstall` erases it. The registry is the sole record of spent nullifiers. Erasing it makes every already-spent note spendable again — an unbounded double-spend against the pool and a direct breach of law 2. Rollback = **governed upgrade** to the prior pinned Wasm, or forward-fix.
  - **3. Target artifact + where the bytes come from.** A rollback installs a *prior pinned* Wasm. `deployment/mainnet/release_hashes.toml` `[wasm.nullifier_registry]` (sha256 `d4bf8493731351d53a589113e99b23261a8fb7255f1e2ac967e8c077e400a951`) is the **only** source of truth for those bytes, and it is reproducible **only** from a clean build under `run_gate.sh`'s `env -i` re-exec with the exact 13-package `build.command` (law 7(f)) — an interactive shell or a no-op rebuild can present different or stale bytes. Verify with `sha256sum target/wasm32-unknown-unknown/release/nullifier_registry.wasm` against that row **before** the proposal is drafted. Never rebuild a "close enough" binary under time pressure.
  - **4. Pre-change fixture (is the target real?).** **None exists.** `run_gate.sh` builds `nullifier_registry_test.wasm` only as the cross-Wasm positive case for `eager_cell_sentinel`; no `nullifier_registry_pre_*` predecessor fixture is pinned anywhere. Build one from the prior release commit under the `env -i` gate build before relying on a rollback; until then treat it as unrehearsed.
  - **5. State compatibility — one-way doors.** The spent-nullifier map and its `insert_batch` batching/index structures are the one-way door: an older Wasm that cannot decode a row written by the newer one traps in `post_upgrade`, and a registry that fails to open is indistinguishable, from the pool's side, from a registry that forgot. *Hold unsupported populated-state recovery pending an independently reviewed migration that preserves identity and state. Apply a governed forward corrective upgrade when the current format supports it; do not assume a previous Wasm can decode state written by a newer version.*
  - **6. Post-rollback verification.** Registry size equals the pre-rollback count (never lower — a lower count is a **stop-everything** signal); `insert_batch` is reachable **only** from the `shielded_pool` principal and rejects any other caller; a known-spent nullifier still reads as spent.
  - **7. What is NOT recoverable.** Every nullifier inserted by the newer Wasm that the older cannot decode. **If the count comes back lower than it went in, the supply boundary has been breached: halt the pool before anything else.**

### merkle_tree
- Wasm hash: **OWED AT INSTALL — not yet recorded.** Supplied by install **step 2** (`docs/A7_INSTALL_RUNBOOK.md` §2). Read back from `deployment/mainnet/release_hashes.toml` `[wasm.merkle_tree]`, which must equal the `wasm_sha256` of the `merkle_tree` entry in `deployment/mainnet/a7_install_kit.toml`; `./run_gate.sh` re-derives both. Reproducible **only** under the gate's `env -i` build (law 7(f)). Do not invent a value.
- Init args: (Poseidon zero-root values — confirm these match `POSEIDON_PARAMS.md`, not the old SHA-256 stub zeros)
- Controller(s): **OWED AT INSTALL — not yet recorded.** Set at install **step 2** and read back with the `read_back` command in the `merkle_tree` entry of `deployment/mainnet/a7_install_kit.toml` (`dfx canister --network ic info <id>`). Post-cutover the expected value is exactly `[Vault]` — see § *Ring closure* and `deployment/mainnet/custody_manifest.toml`. Record the observed principal(s); do not transcribe the expectation as if it were an observation.
- Upgrade policy: (stable-persisted counters per Track C)
- Dependencies: none
- Post-deploy checks: root at genesis matches the documented Poseidon zero-root, not `[0u8;32]`
- Rollback/emergency procedure:
  - **1. Authorization.** A rollback is a **new Vault 2-of-3 proposal** (`cpdab`), never a shortcut and never a direct `dfx` call — post-cutover the Vault is the sole controller and the `deploy-mainnet` recipe has been deleted (B-2), so no non-Vault install path exists.
  - **2. Upgrade vs reinstall.** **Reinstall is UNCONDITIONALLY FORBIDDEN.** `upgrade` preserves stable memory; `reinstall` erases it. The tree is the commitment history every existing note's membership proof is anchored to. Erasing it invalidates every outstanding note and breaks law 3's single-authoritative-anchor property. Rollback = **governed upgrade** to the prior pinned Wasm, or forward-fix.
  - **3. Target artifact + where the bytes come from.** A rollback installs a *prior pinned* Wasm. `deployment/mainnet/release_hashes.toml` `[wasm.merkle_tree]` (sha256 `ebbac752e4a48249d6ee105fe77dd517a3094cf7161eba6dfef162133ffcb221`) is the **only** source of truth for those bytes, and it is reproducible **only** from a clean build under `run_gate.sh`'s `env -i` re-exec with the exact 13-package `build.command` (law 7(f)) — an interactive shell or a no-op rebuild can present different or stale bytes. Verify with `sha256sum target/wasm32-unknown-unknown/release/merkle_tree.wasm` against that row **before** the proposal is drafted. Never rebuild a "close enough" binary under time pressure.
  - **4. Pre-change fixture (is the target real?).** **None exists.** `merkle_tree_test.wasm` is a testing-feature build (P-MRK corruption hook, `eager_cell_sentinel`), **not** a predecessor. No `merkle_tree_pre_*` fixture is pinned. Build one from the prior release commit under the `env -i` gate build first; a rollback to a binary nobody can rebuild is not a procedure.
  - **5. State compatibility — one-way doors.** Leaf storage, the leaf counter, the root ring and the Poseidon parameterisation are all one-way doors. **Poseidon parameters must be identical on both sides** (`POSEIDON_PARAMS.md`, law 6): a rollback across any parameter change silently re-hashes the tree to a different root and is a re-genesis, not a rollback. Note the pool traps on leaf-count drift during lease reconciliation, so a tree that came back short will halt deposits rather than corrupt quietly. *Hold unsupported populated-state recovery pending an independently reviewed migration that preserves identity and state. Apply a governed forward corrective upgrade when the current format supports it; do not assume a previous Wasm can decode state written by a newer version.*
  - **6. Post-rollback verification.** Leaf count equals the pre-rollback count exactly; the current root equals the pre-rollback root and is present in the pool's `accepted_spend_roots` (`is_valid_anchor` true for the anchors the wallet is using); at genesis only, the root equals the documented Poseidon zero-root and **not** `[0u8;32]`.
  - **7. What is NOT recoverable.** Any commitment appended by the newer Wasm the older cannot decode. **A reinstall permanently unmoors every outstanding note from its anchor — the notes still exist and can never be proven again.**

### verifier
- Wasm hash: **OWED AT INSTALL — not yet recorded.** Supplied by install **step 1** (`docs/A7_INSTALL_RUNBOOK.md` §2). Read back from `deployment/mainnet/release_hashes.toml` `[wasm."stsh-verifier"]`, which must equal the `wasm_sha256` of the `verifier` entry in `deployment/mainnet/a7_install_kit.toml`; `./run_gate.sh` re-derives both. Reproducible **only** under the gate's `env -i` build (law 7(f)). Do not invent a value.
- Init args: the **authorized pool caller principal** (`service : (principal) ->`, `verifier.did` — DEF-083 pool-caller gate). The VK is NOT an init arg: it is compiled into the Wasm (`include_str!` of `circuits/verification_key.json` — the mainnet-v2 LAUNCH VK since A-4, 2026-09-12) and checked at runtime via `vk_hash()` against the pool's `PINNED_VK_HASH`.
- Controller(s): **OWED AT INSTALL — not yet recorded.** Set at install **step 1** and read back with the `read_back` command in the `verifier` entry of `deployment/mainnet/a7_install_kit.toml` (`dfx canister --network ic info <id>`). Post-cutover the expected value is exactly `[Vault]` — see § *Ring closure* and `deployment/mainnet/custody_manifest.toml`. Record the observed principal(s); do not transcribe the expectation as if it were an observation. **P15-002:** must also equal the `shielded_pool` controllers.
- Upgrade policy: **manifest-governed through Vault, with controller set exactly [Vault], identical to the pool's controller set** — the P15-002 / DEF-078 gate. VK upgrade governance per the Gate A checklist item "verification key governance process locked".
- Dependencies: none
- Post-deploy checks: known-good proof verifies; an actual wallet/submitter sends a tampered proof/public signal through the pool to the verifier, reaches proof verification, and is rejected. A direct signer call to the verifier is rejected by `assert_pool_caller` before verification and does not satisfy this check. **AR1-14 — the tampered-proof leg is load-bearing, not a formality:** the workspace builds a `stub_verifier.wasm` (test scaffolding, absent from `dfx.json` but a release-build output all the same) whose `vk_hash()` is CONFIGURABLE, so it would pass the pool's automated `set_verifier_canister` attestation while verifying nothing. The precise claim: tampered-proof rejection is the **required behavioural backstop** — the check that detects a verifier which self-reports the expected VK hash while verifying nothing, which the automated attestation cannot do. It is **not** the only risk-reducing surface in the deploy path: absence from `dfx.json`, distinct artifact naming, and the recorded Wasm-hash and controller-parity rows above all reduce the chance of installing the wrong Wasm. None of them detects a *correctly named, correctly hashed* verifier that does not verify — so this check must be executed and its output pasted, not marked done. **P15-002 controller parity (from the verifier side):** `dfx canister --network ic info <verifier>` controller set == the pool's == [Vault]. `vk_hash()` reachable and returns `84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914` == the pool's `get_pinned_vk_hash` == `sha256(circuits/verification_key.json)`. **Evidence capture:** paste both raw `dfx canister info` outputs into this record (same pattern as the A1 ceremony-packet canister-status JSON).
- Rollback/emergency procedure:
  - **1. Authorization.** A rollback is a **new Vault 2-of-3 proposal** (`cpdab`), never a shortcut and never a direct `dfx` call — post-cutover the Vault is the sole controller and the `deploy-mainnet` recipe has been deleted (B-2), so no non-Vault install path exists. Controller set must remain exactly `[Vault]` and identical to the pool's (P15-002 / DEF-078) through the whole operation.
  - **2. Upgrade vs reinstall.** **Upgrade preferred; reinstall is technically survivable here and still requires its own authorization.** The verifier holds no user state — the VK is compiled in (`include_str!` of `circuits/verification_key.json`) and the only init arg is the authorized pool caller principal. A reinstall therefore loses nothing but **must** re-pass the identical init tuple, or the pool's calls are rejected by `assert_pool_caller`. It is not a routine action.
  - **3. Target artifact + where the bytes come from.** A rollback installs a *prior pinned* Wasm. `deployment/mainnet/release_hashes.toml` `[wasm."stsh-verifier"]` (sha256 `5a7dcc4997419e65cd16fa3436a9189b7535e5137beb01ee17edff7292c81141`) is the **only** source of truth for those bytes, and it is reproducible **only** from a clean build under `run_gate.sh`'s `env -i` re-exec with the exact 13-package `build.command` (law 7(f)) — an interactive shell or a no-op rebuild can present different or stale bytes. Verify with `sha256sum target/wasm32-unknown-unknown/release/stsh_verifier.wasm` against that row **before** the proposal is drafted. Never rebuild a "close enough" binary under time pressure.
  - **4. Pre-change fixture (is the target real?).** **None exists** as a `_pre_*` Wasm. The functional equivalent is the pinned `[wasm."stsh-verifier"]` row plus `vk_hash()` self-report — and self-report is **not** sufficient: `stub_verifier.wasm` is a release-build output whose `vk_hash()` is CONFIGURABLE and which verifies nothing. The behavioural backstop below is what makes the target real.
  - **5. State compatibility — one-way doors.** None on the verifier's own state (it has none). The real compatibility door is the **VK**: rolling back to a Wasm carrying a different compiled-in VK breaks `vk_hash()` parity with the pool's `PINNED_VK_HASH` and rejects every proof. Rolling back across a DOMAIN_* change is forbidden outright once real unspent notes exist (law 6). *Hold unsupported populated-state recovery pending an independently reviewed migration that preserves identity and state. Apply a governed forward corrective upgrade when the current format supports it; do not assume a previous Wasm can decode state written by a newer version.*
  - **6. Post-rollback verification.** `vk_hash()` = `84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914` = the pool's `get_pinned_vk_hash` = `sha256(circuits/verification_key.json)`; `dfx canister --network ic info <verifier>` controllers == the pool's == `[Vault]`; a known-good proof verifies **through the pool**; and a tampered proof sent through the pool is rejected — paste the raw output of both legs, do not mark them done.
  - **7. What is NOT recoverable.** Nothing of the verifier's own. What is not recoverable is any proof **accepted** while a wrong or stubbed verifier was installed: those spends are final on the pool side and cannot be reversed.

### treasury
- Wasm hash: **OWED AT INSTALL — not yet recorded.** Supplied by install **step 4** (`docs/A7_INSTALL_RUNBOOK.md` §2). Read back from `deployment/mainnet/release_hashes.toml` `[wasm.treasury]`, which must equal the `wasm_sha256` of the `treasury` entry in `deployment/mainnet/a7_install_kit.toml`; `./run_gate.sh` re-derives both. Reproducible **only** under the gate's `env -i` build (law 7(f)). Do not invent a value.
- Init args: **OWED AT INSTALL — not yet recorded.** Supplied by install **step 4**. The canonical artifact is `deployment/mainnet/treasury_init.did`, encoded and hashed as the `treasury` entry in `deployment/mainnet/a7_install_kit.toml` (`arg_did` / `arg_bin` / `arg_sha256` / `arg_text_sha256`). Record the exact `.did` text actually uploaded; hand-reconstructed args are a Gate-D violation. Do not invent a value.
- Controller(s): **OWED AT INSTALL — not yet recorded.** Set at install **step 4** and read back with the `read_back` command in the `treasury` entry of `deployment/mainnet/a7_install_kit.toml` (`dfx canister --network ic info <id>`). Post-cutover the expected value is exactly `[Vault]` — see § *Ring closure* and `deployment/mainnet/custody_manifest.toml`. Record the observed principal(s); do not transcribe the expectation as if it were an observation.
- Upgrade policy: (upgrade persistence added per `#71`)
- Dependencies: stsh_token
- Post-deploy checks: `icrc1_fee` live-query wired correctly; reserve buckets initialized per `STSH_FEE_POLICY.md`
- Rollback/emergency procedure:
  - **1. Authorization.** A rollback is a **new Vault 2-of-3 proposal** (`cpdab`), never a shortcut and never a direct `dfx` call — post-cutover the Vault is the sole controller and the `deploy-mainnet` recipe has been deleted (B-2), so no non-Vault install path exists.
  - **2. Upgrade vs reinstall.** **Reinstall is UNCONDITIONALLY FORBIDDEN.** `upgrade` preserves stable memory; `reinstall` erases it. Treasury is an accounting view over pool-held protocol reserves (Option 2, `canisters/treasury/CUSTODY_DECISION.md`) — it must never custody real STSH, so a reinstall loses no tokens, but it erases the in-flight proposal records and the six-bucket accounting that `execute_withdrawal` and the fee policy depend on, and that record cannot be reconstructed from the ledger alone. Rollback = **governed upgrade** to the prior pinned Wasm, or forward-fix.
  - **3. Target artifact + where the bytes come from.** A rollback installs a *prior pinned* Wasm. `deployment/mainnet/release_hashes.toml` `[wasm.treasury]` (sha256 `0e314c758ae2a96509dbe9660bf9255de0f11ac5e8f5b02621c1bb2179d8e4a1`) is the **only** source of truth for those bytes, and it is reproducible **only** from a clean build under `run_gate.sh`'s `env -i` re-exec with the exact 13-package `build.command` (law 7(f)) — an interactive shell or a no-op rebuild can present different or stale bytes. Verify with `sha256sum target/wasm32-unknown-unknown/release/treasury.wasm` against that row **before** the proposal is drafted. Never rebuild a "close enough" binary under time pressure.
  - **4. Pre-change fixture (is the target real?).** **None exists.** `treasury_test.wasm` is a testing-feature build (`inject_inflight_proposal_for_test`), not a predecessor; no `treasury_pre_*` fixture is pinned. Build one from the prior release commit under the `env -i` gate build before relying on a rollback.
  - **5. State compatibility — one-way doors.** The bucket balances, the in-flight proposal set and the eager-cell state (Phase 2) are the doors. An in-flight disbursement that the older Wasm cannot decode leaves a proposal neither executable nor cancellable. **Quiesce: confirm the in-flight proposal set is empty before proposing the rollback**, and record the listing in the packet. *Hold unsupported populated-state recovery pending an independently reviewed migration that preserves identity and state. Apply a governed forward corrective upgrade when the current format supports it; do not assume a previous Wasm can decode state written by a newer version.*
  - **6. Post-rollback verification.** The six reserve buckets sum to the pre-rollback totals and match `STSH_FEE_POLICY.md`; `icrc1_fee` is queried live (no hardcoded value); `icrc1_balance_of(treasury)` is **zero** — treasury holding real STSH is itself the defect; the in-flight proposal set is empty.
  - **7. What is NOT recoverable.** Any accrual or proposal state written by the newer Wasm the older cannot decode. A disbursement already executed on the pool-authorized path is final and is **not** unwound by rolling treasury back — the two are not transactional together.

### vesting
- Wasm hash: **OWED AT INSTALL — not yet recorded.** Supplied by install **step 7** (`docs/A7_INSTALL_RUNBOOK.md` §2). Read back from `deployment/mainnet/release_hashes.toml` `[wasm.vesting]`, which must equal the `wasm_sha256` of the `vesting` entry in `deployment/mainnet/a7_install_kit.toml`; `./run_gate.sh` re-derives both. Reproducible **only** under the gate's `env -i` build (law 7(f)). Do not invent a value.
- Init args: **the canonical artifact `deployment/mainnet/vesting_init.did` ONLY** (P-ARITH
  G-1/G-2; supersedes the old `TOKENOMICS_PROPOSAL.md` §3 line). Founder beneficiaries live
  here — never as the token allocation recipient; every founder schedule is cliff 6 /
  linear 30 (§0.4 Option A, LOCKED). Gate-D + Gate-V (see the stsh_token section) verify
  this artifact against `deployment/mainnet/genesis_manifest.toml` before and after install.
- Controller(s): **OWED AT INSTALL — not yet recorded.** Set at install **step 7** and read back with the `read_back` command in the `vesting` entry of `deployment/mainnet/a7_install_kit.toml` (`dfx canister --network ic info <id>`). Post-cutover the expected value is exactly `[Vault]` — see § *Ring closure* and `deployment/mainnet/custody_manifest.toml`. Record the observed principal(s); do not transcribe the expectation as if it were an observation.
- Upgrade policy: (upgrade persistence added per `#71`)
- Dependencies: stsh_token
- Post-deploy checks: claim against a test schedule returns expected amount; real `icrc1_transfer` confirmed (`#47`)
- Rollback/emergency procedure:
  - **1. Authorization.** A rollback is a **new Vault 2-of-3 proposal** (`cpdab`), never a shortcut and never a direct `dfx` call — post-cutover the Vault is the sole controller and the `deploy-mainnet` recipe has been deleted (B-2), so no non-Vault install path exists.
  - **2. Upgrade vs reinstall.** **Reinstall is UNCONDITIONALLY FORBIDDEN.** `upgrade` preserves stable memory; `reinstall` erases it. Vesting holds the founder and allocation schedules and the record of what has already been claimed. A reinstall re-opens every claim already paid — a direct double-disbursement against the ledger. Rollback = **governed upgrade** to the prior pinned Wasm, or forward-fix.
  - **3. Target artifact + where the bytes come from.** A rollback installs a *prior pinned* Wasm. `deployment/mainnet/release_hashes.toml` `[wasm.vesting]` (sha256 `760488eb60d9b23bd3b612b122fb183ea5f9c1525208709e580956cf1ee59b27`) is the **only** source of truth for those bytes, and it is reproducible **only** from a clean build under `run_gate.sh`'s `env -i` re-exec with the exact 13-package `build.command` (law 7(f)) — an interactive shell or a no-op rebuild can present different or stale bytes. Verify with `sha256sum target/wasm32-unknown-unknown/release/vesting.wasm` against that row **before** the proposal is drafted. Never rebuild a "close enough" binary under time pressure.
  - **4. Pre-change fixture (is the target real?).** **None exists.** `vesting_test.wasm` is the `eager_cell_sentinel` cross-Wasm positive case, not a predecessor; no `vesting_pre_*` fixture is pinned. Build one from the prior release commit under the `env -i` gate build before relying on a rollback.
  - **5. State compatibility — one-way doors.** Schedules, claimed-to-date counters and the eager-cell state are the doors. Init args are **not** re-passed on an upgrade — the schedules in stable memory are authoritative, and `deployment/mainnet/vesting_init.did` is a genesis artifact: changing it is a re-genesis, never a rollback step. *Hold unsupported populated-state recovery pending an independently reviewed migration that preserves identity and state. Apply a governed forward corrective upgrade when the current format supports it; do not assume a previous Wasm can decode state written by a newer version.*
  - **6. Post-rollback verification.** Every schedule reads back byte-identical to the pre-rollback listing and to `deployment/mainnet/vesting_init.did` as cross-checked by Gate-D/Gate-V against `genesis_manifest.toml`; claimed-to-date per beneficiary is unchanged (**never lower**); every founder schedule is still cliff 6 / linear 30; a `claim` against a test schedule returns the expected amount and settles via a real `icrc1_transfer`.
  - **7. What is NOT recoverable.** Any claim recorded by the newer Wasm the older cannot decode — and a claimed-to-date counter that comes back **lower** means the paid amount can be claimed again. Treat any downward movement as a stop-everything event; the transfer itself cannot be reversed.

### staking — **NOT INSTALLED AT LAUNCH** (D1, ratified 2026-08-14)

**The staking canister is EXCLUDED from the launch install set.** It is not
deployed, not installed, and has no mainnet principal at launch. There are
therefore no Wasm hash, init args, controller, upgrade-policy, post-deploy-check
or rollback fields to fill in here — this section is a deliberate exclusion
record, not an unfilled canister record.

This SUPERSEDES the previous "staking is disabled at launch defaults per M7
scope" wording. That wording asserted a *disabled* posture with no implementing
mechanism: no init flag, no gate, and no post-deploy check could have
established it, because "disabled" was never implemented anywhere. Non-installation
is the mechanism, and it is enforced by absence.

Consequences that MUST hold at launch (each already recorded in
`deployment/mainnet/custody_manifest.toml` — see the exclusion note there):

- `shielded_pool.STAKING` is pinned to the **Vault** principal, never to a
  staking-canister principal (V7 Ruling A; freeze §14).
- `stsh_token.staking_canister` is pinned to the **Vault** principal at RR-1,
  never to a staking-canister principal (freeze §14). The field is required and
  fails closed, so it cannot simply be omitted.
- Nothing in the launch install sequence, verification list, or smoke checklist
  installs, configures, or calls a staking canister.

Introducing staking is a **post-launch** governance action under the staking gate
(freeze §15), which must migrate BOTH the pool's and the token's stored staking
principals off the Vault. Nothing about that migration — including any voter-lock
choice (D2, still undecided) — is decided or encoded here.

### fee-policy — N/A: library crate (`crate-type = ["lib"]`), never deployed; resolved 2026-06-21 (ARCHITECTURE.md canister map).

### wallet_frontend (asset canister, optional at first launch)
- Asset hashes:
- Controller(s): **OWED AT INSTALL — not yet recorded.** `wallet_frontend` is an **asset canister and is not one of the nine A-7 installs** — the `s3tyu` canister is adopted at cutover, so there is no `a7_install_kit.toml` entry and no `[wasm.*]` row for it. Read the controllers back with `dfx canister --network ic info s3tyu-…` after the cutover step that transfers them, and record the observed value.
- Points to correct canister IDs for stsh_token / shielded_pool (confirm against this record, not hardcoded elsewhere):
- Rollback/emergency procedure:
  - **1. Authorization.** `wallet_frontend` (`s3tyu`) is an **asset canister**, not a Wasm install: a rollback is a re-upload of a prior bundle by the authorized asset controller, and after cutover that authorization runs through the Vault like any other mutation. A rollback is a new authorized action, never a shortcut, and never `dfx deploy --network ic` (the `deploy-mainnet` recipe has been deleted, B-2).
  - **2. Upgrade vs reinstall.** Re-uploading assets is non-destructive to the protocol: the wallet holds **no protocol state**. Note storage is client-side (`idb`, per browser) and is **not** affected either way. Reinstalling the asset canister itself is unnecessary and is not authorized.
  - **3. Target artifact + where the bytes come from.** The prior bundle is pinned by `deployment/mainnet/release_hashes.toml` `[wallet_bundle].sha256` (`55c101529c1b486700e05b394f547ff0973ce162a52fc516ed3fa17b8053e35a`) with its own `[wallet_bundle.toolchain]` and `[wallet_bundle.asset_config]` (`.ic-assets.json5`, sha256 `2d81c2d50837bcaf4fb13cb53045be4ccb322f10df0cbe49ef075d3ad3b91bf1`) rows. **Known gap:** `verify_custody_manifest` does not read `[wallet_bundle]` (B-6 / SSoT O-10), so this row is verified by hand — `sha256sum` the built bundle against it and paste the output.
  - **4. Pre-change fixture.** **None, and none is possible in the Wasm sense.** The prior bundle must be rebuilt from its pinned source commit with the recorded node/npm/wasm-pack versions; the `[wallet_bundle].reproduction` block records which dimensions were and were not varied (`node_is_load_bearing = false`; the rustc dimension was NOT varied; CR-12 remains OPEN). Confirm the rebuild reproduces the pinned sha256 before uploading.
  - **5. State compatibility — one-way doors.** The bundle is bound to the canister ids, the verifier pin, the `derivationOrigin` and alternative origins, and `spendManifest.json`'s `circuitVersion`. Rolling the bundle back below the pool's **active** circuit version makes every spend throw `circuit version mismatch` client-side before any `private_spend` is sent (see §8 item 9a / PROT-24). A `derivationOrigin` change rotates every user's Internet Identity principal and is **not** reversible by rolling the bundle back — the notes are then unreachable from the new principal. *Do not assume a previous bundle is compatible with state a newer one established.*
  - **6. Post-rollback verification.** The served asset hashes match the pinned bundle; the wallet release panel shows the expected commit, verifier pin and **Circuit version** row, and that row agrees with the pool's `get_circuit_version()`; canister ids resolve to the ids in **this** record and not to any hardcoded value elsewhere; Internet Identity login returns the **same** principal as before the rollback; the production CSP contains no `http://localhost:*`.
  - **7. What is NOT recoverable.** Any user's identity binding broken by a `derivationOrigin` change, and any client-side note metadata a user lost by clearing browser storage while a broken bundle was live. Notes themselves are never lost by a wallet rollback — they live in the pool — but a user who cannot derive the right principal cannot reach them.

### stsh_vetkeys (H-2 — additive; NOT on mainnet at merge)
- Wasm hash: **OWED AT INSTALL — not yet recorded.** Supplied by install **step 5** (`docs/A7_INSTALL_RUNBOOK.md` §2). `vetkeys` is the **one unpinned role**: its `a7_install_kit.toml` entry carries `wasm_row = ""`, so there is no `[wasm.*]` row in `deployment/mainnet/release_hashes.toml` to read it back from — record the `sha256sum` of the gate-built Wasm here at install time (runbook §3.5). Do not invent a value.
- Init args: `(text, opt principal)` — **(1)** the vetKD key name, **`"key_1"` for production mainnet** (`"test_key_1"` / `"dfx_test_key"` only on local/testnet); **(2)** W-VETKEYS §D: the **token canister principal**, whose `icrc1_balance_of` answers first-derive eligibility (CTO adjudication `b216902b…`, 2026-08-27). Both are install-time decisions, not code; the frozen application constants (`DOMAIN_SEPARATOR = "stsh.wallet.notes.v1"`, `KEY_NAME = "notes"`) are compiled in.
  - The second argument is TRAILING and OPTIONAL, so the historical one-argument install remains candid-valid — but **omitting it on mainnet leaves the canister UNCONFIGURED, and an unconfigured canister refuses every FIRST-EVER derive** with the retryable `EligibilityCheckUnavailable`. That is fail-closed by design (never "eligible"), and it means no new principal can bootstrap until the token id is set. Pass it at install.
  - **UPGRADE takes the same optional argument**, so configuring a live canister never requires a reinstall (see G3 below — reinstall is break-glass): `Some(p)` writes it, and **`None` PRESERVES whatever is stored** (absent stays absent, set stays set). A routine upgrade passing no argument therefore cannot silently unconfigure the canister.
  - Read it back with `get_token_canister()` — it returns `opt principal` and is the check the post-deploy step below uses.
- Controller(s): **must be under Owner's own controller, NOT a third-party site builder.** A builder-owned prototype ID is not an acceptable permanent home for load-bearing crypto state.
- Upgrade policy: **G2 — the canister ID is LOAD-BEARING crypto state. Upgrade-in-place FOREVER; NEVER reinstall-to-a-new-ID.** `vetkd_public_key`/`vetkd_derive_key` derive from this canister's own principal, so a redeploy under a new ID returns a different verification key → every previously IBE-encrypted note payload becomes undecryptable and cross-device/recovery breaks. Any operation that would change the ID is a full re-key migration (decrypt-and-re-issue under the new identity while the old remains available), not a redeploy. `post_upgrade` is fail-closed (H-2/A1): it TRAPS rather than boot from a test-key default, so a broken StableCell-preserve assumption aborts the upgrade instead of silently re-keying every user.
- Dependencies: the IC management canister (`vetkd_public_key` / `vetkd_derive_key`), **plus ONE outbound read-only `icrc1_balance_of` query to the token canister**, made only for a principal's FIRST-EVER derive (W-VETKEYS §D; SSA-GREENed as a narrow amendment to the original zero-coupling freeze). No inbound coupling; pool/verifier/registry/merkle remain untouched. No second coupling may be added without a new ruling.
- Post-deploy checks:
  - `get_config()` returns `("stsh.wallet.notes.v1", "key_1")` — the pinned namespace + the production curve key.
  - `get_token_canister()` returns `opt` the **mainnet token canister principal** — not `null`, and not a testnet id. A `null` here means first-ever derives are refused fail-closed, i.e. no new user can bootstrap; a WRONG id means eligibility is answered by the wrong ledger. Check the value, not just that it is non-null.
  - **A3 wallet gate (MUST land before the FIRST mainnet derive):** the wallet production bootstrap MUST call `assertCanisterConfig(canister, "key_1")` — it now asserts BOTH the domain separator AND the key name, so a canister accidentally on `"test_key_1"` is rejected loudly client-side. Wiring the bootstrap to pass `"key_1"` is the deferred wallet auth-bridge lane's job; it is a HARD gate here.
  - Wire `createVetkeysActor(canisterId, …)` to the pinned ID recorded above (not an injected/defaulted ID).
  - **Namespace freeze:** the instant the canister is on mainnet AND a user shields the first IBE payload, the canister ID, `DOMAIN_SEPARATOR`, `KEY_NAME`, and the `len‖principal‖name` input encoding all become one-way doors. Confirm all four are final before the first mainnet derive.
- Rollback/emergency procedure: **G3 — reinstall is BREAK-GLASS only, not routine or presently authorized.** Prefer a governed upgrade. Any last-resort reinstall must keep the SAME canister ID and exactly the same `DOMAIN_SEPARATOR`, `KEY_NAME`, and input encoding, and must pass init args exactly as `("key_1", opt <mainnet token principal>, opt <mainnet shielded_pool principal>)` — the third arg (LAUNCH-HARDEN-04 O-1(b)) sets `DEVICE_CHECK_CALLER` (MemoryId 20); omitting it leaves `has_active_device` refusing `CallerNotConfigured`, so every pool spend fails closed `DEVICE_CHECK_UNAVAILABLE`. These conditions can preserve key derivability; they do not recover erased wallet state. Reinstall wipes the entire KeyManager and W-VETKEYS stable state: access-control and shared-key grants, device registrations, wrapped envelopes, bootstrap tickets, consumed nonces, derive quotas, established-principal markers, and the §D token-canister configuration, the device-approval policy flags and the pool device-check caller <!-- MEMORY_ID_RANGE:vetkeys --> (**the full `vetkeys` MemoryId 3-20 range — see the `vetkeys` rows in `docs/MEMORY_ID_REGISTRY.md` for the authoritative, current list; do not restate it anywhere else**). Before any separately authorized break-glass reinstall: (1) verify the canister ID is unchanged; (2) verify the domain, key namespace, input encoding, and exact init tuple above; and (3) explicitly acknowledge every listed access-control, shared-key, device, envelope, ticket, nonce, quota, principal-marker, and token-configuration loss. Hold unsupported populated-state recovery pending an independently reviewed migration that preserves identity and state. Apply a governed forward corrective upgrade when the current format supports it; do not assume a previous Wasm can decode state written by a newer version. D1 remains separately held.

## IC-level controllers (DEF-081)

| Canister | IC controller | Decision |
|---|---|---|
| shielded-pool | Vault, as the custody manifest requires | BornUnderVault |
| verifier | Vault, matching the pool and custody manifest | BornUnderVault |
| token | Vault | BornUnderVault |
| other manifest targets | Follow each manifest disposition; BornUnderVault targets use Vault | |

## App-level principals (DEF-081)

| Principal | Value | Notes |
|---|---|---|
| fee_collector | TBD — neutral II, distinct from treasury_canister | Decision 3; token init arg added in DEF-080 |
| treasury canister | TBD | |
| STAKING_CANISTER (pool governance) | TBD — **the Vault principal**, NOT a staking-canister principal (staking is not installed at launch: D1, ratified 2026-08-14; freeze §14) | DEF-079: gates schedule_vk_activation |
| stsh_token `staking_canister` (init arg) | TBD — **the Vault principal**, same rule as above; required field, fails closed, so it is pinned rather than omitted (freeze §14) | Replaced at RR-1; no setter — post-launch change is a governance upgrade (freeze §15) |

## Init arg assertions (pre-deploy check — DEF-081)

Run these checks against the prepared init args BEFORE any `dfx deploy --network ic`:

- [ ] `fee_collector != treasury_canister_principal` [Decision 3]
- [ ] `verifier.AUTHORIZED_POOL == shielded_pool principal` [DEF-083 — verifier init arg]
- [ ] `pool.STAKING_CANISTER == Vault principal` [DEF-079 — governance gate; staking NOT installed at launch (D1, ratified 2026-08-14), so this MUST NOT be a staking-canister principal — freeze §14]
- [ ] `token.staking_canister == Vault principal` [same rule — freeze §14; required init field, fails closed]
- [ ] no launch install/verification step deploys, installs, or configures a staking canister [D1]
- [ ] pool.CONTROLLER == Vault and pool/verifier IC controller sets equal [Vault], matching the custody manifest
- [ ] `vetkeys` init arg 1 is exactly `"key_1"` and arg 2 is `opt <mainnet stsh_token principal>` [W-VETKEYS §D, CTO adjudication `b216902b…`; omitting arg 2 leaves first-ever derives refused fail-closed]; arg 3 (LAUNCH-HARDEN-04) is `opt <mainnet shielded_pool principal>` — omitting it leaves the pool device check refused fail-closed

## Verifier key (DEF-081/DEF-082)

- PINNED_VK_HASH: `84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914`
  (sha256 of `circuits/verification_key.json`; **LAUNCH VK — mainnet-v2 launch ceremony, 2026-09-12: phase 1 = the PUBLIC Hermez powers-of-tau (powersOfTau28_hez_final_15.ptau, 54 named contributions + beacon); phase 2 = one operator contribution (`FutureProof operator 2026-09-12`) finalized by the pre-announced public drand beacon, mainnet chain round 6460200 (`drand mainnet round 6460200`, iterationsExp 10, LAST contribution). Record: `docs/ceremony/CEREMONY_RECORD_v3.md`**)
- DOMAIN_POOL_CANISTER_ID: the real mainnet pool principal `cxrfg-qaaaa-aaaar-qchfa-cai`
  (Fr-encoded) — the pool born under the Vault at J-18 (2026-09-12). RE-ENCODED at A-3
  FINALIZE for generation `mainnet-v2` and baked into the recompiled R1CS. The A1 value
  `ohspu-zqaaa-aaaad-qmasq-cai` is HISTORICAL and is recorded `out_of_scope` /
  HOSTILE-UNCONTROLLED in `deployment/mainnet/custody_manifest.toml`; severing the domain
  from it is the A-3 security control [DEF-082 resolved; see POSEIDON_PARAMS.md]
- verifier Wasm hash: recorded above; also cross-referenced by
  `VerifierKeyUpgradePayload.verifier_wasm_hash` in governance proposals — a
  deployment verification artifact, NOT a runtime TCB guarantee [DEF-078]

## M5 blockers (do not deploy to mainnet until resolved)

- [x] DEF-082: DOMAIN_POOL_CANISTER_ID — RESOLVED (Vault-born mainnet principal `cxrfg-qaaaa-aaaar-qchfa-cai` re-encoded at A-3 FINALIZE, 2026-09-12; A1's ohspu value is historical)
- [x] DEF-082: LAUNCH VK committed — the mainnet-v2 ceremony RAN 2026-09-12 (A-4). Phase 1 public Hermez power-15 ptau; phase 2 one operator contribution finalized by drand round 6460200 (the LAST contribution, beacon generator `e45908ee…65194`, verified byte-for-byte against two independent drand endpoints). VK `84dba305…`. **F6-1 CLOSED.** Residual, disclosed not fixed: phase 2 had a single operator (record §4.2, E10/CR-12); the community multi-party re-ceremony stays post-launch
- [ ] DEF-046/048: ZK compatibility items (M5 gate)
- [ ] Standardized `withdraw` stays fail-closed pending the zero-private-change circuit question (M5 agenda; WRL re-enable lane)
- [ ] P15-002: pool/verifier controller parity verified post-install (see the gate under `### verifier`)
- [ ] R-15: typed Vault readiness proposal executed and its snapshot is exactly Some(true); record proposal, receipt and snapshot IDs.
- [ ] P15-002 (fee): deploy script submitted the typed Vault `Application(PoolSetGovernanceFeeParams(...))` proposal, recorded its Executed result, AND confirmed the live params nonzero + matching `mainnet_launch_config` (the values are the constants tabulated under `### shielded_pool`, restated nowhere) — pool MUST NOT open to the public until this passes (see the fee hard-gate under `### shielded_pool`)
- [ ] R-2 (C-30): `get_fee_flush_window_ns` read back and recorded (default 3_600_000_000_000 ns unless the Owner ruled otherwise); value within [300_000_000_000, 86_400_000_000_000]

## Post-deploy verification commands (Gate C)

- Confirm the launch fee config is live. **Prefer the boolean over reading raw Candid:** `dfx canister --network ic call <pool> fee_params_match_mainnet_launch_config '()'` must return `(true)` — it compares every field against `mainnet_launch_config()` itself, so it cannot drift from the constants the way a transcribed expectation can. `get_governance_fee_params '()'` remains for diagnosing a `false`; assert its fields against the constants tabulated under `### shielded_pool`, and `spend_fee_mode = opt variant { FixedStsh }` (the P15-002 fee hard-gate)
- Confirm verifier controller matches pool controller: `dfx canister info verifier --network ic` (compare against `dfx canister info shielded_pool --network ic`)
- Confirm PINNED_VK_HASH: `dfx canister call verifier vk_hash --network ic` (must equal the pool's `get_pinned_vk_hash`)
- Confirm fee_collector != treasury: query `token.get_authority_refs()` (`canisters/token/stsh_token.did`), which returns `{ treasury; fee_collector; staking_canister }` and traps fail-closed on an uninitialised treasury/staking, and compare the two principals live. Cross-check against the recorded token init args in this document — the record is the corroboration, no longer the only source.
- Run the full integration test suite against live canisters (staging subnet first)
- Run the ICRC-1/2 dfx CLI conformance sweep: `./scripts/icrc_dfx_conformance.sh ic <token-canister-id> <recipient-principal>` — DEFERRED-LIVE (requires a working `dfx` + a reachable replica; not runnable in this repo's WSL validation box, see the script's own header). A nonzero exit or any `*** FINDING` line in the output is a blocker, not a note.

## Post-deploy smoke test checklist (Gate C)

- [ ] Clean build from tagged commit reproduces recorded Wasm hashes (rebuild independently and diff)
- [ ] All canister principals recorded above match what's actually installed on mainnet
- [ ] Controllers verified via `dfx canister --network ic info` for every canister
- [ ] Frontend (if deployed) points to the correct canister IDs
- [ ] Vault PoolReadPayoutMemoKeyReady snapshot returned exactly Some(true), IDs pasted (J-27a) before the first private_spend
- [ ] Legacy-payout-absence posture (a)/(b)/(c) recorded in the packet (J-27b)
- [ ] One real shield_deposit → private_spend → withdraw cycle executed end to end against the deployed canisters
- [ ] Actual wallet/submitter sent one tampered proof through the deployed pool to the verifier, the call reached proof verification, and verification rejected it

## Ring closure — terminating the bootstrap-window exception (AR2-S3-02)

**This is the step that ends the exception, and it was absent from every checklist here.**
`deployment/mainnet/vault_authorities.toml:49-53` records that during the bootstrap window the
machine identity `4f6wg-…-cae` is **BOTH sole controller** of the two empty (codeless)
canisters **AND** a future Vault quorum member — **no quorum stands in that path**. The
exception is limited to codeless canisters holding no authority and **MUST terminate at ring
closure**. Until it does, any claim that no single human or device key holds unilateral
controller authority is a **POST-CUTOVER claim** and must not be made about the current
window.

The end state is gated per-canister by `custody_manifest.toml`'s `set_controller_at_cutover`
dispositions, but the **terminating act itself** had no checklist row — an end state that is
gated while its terminating step is untracked is how a temporary exception becomes permanent
without anyone deciding that it should.

### The order is THREE steps, and it is not interchangeable (J-17b, SSA F-13 / G-03)

Controller changes are IC **management-canister** actions. The Vault is **not** a controller
of `pyeop-…` (reserves) or `s3tyu-…` (wallet) today — their controllers are `4f6wg-…-cae` and
`cnbb4-…-oqe`. A `Management.UpdateSettings` proposal raised against a target the Vault does
not yet control **passes quorum and then fails at execution**: the Vault cannot change the
settings of a canister it is not a controller of, and the quorum is spent on a call that
cannot land. Raising it early is therefore not merely premature, it burns a proposal and its
retained-payload budget.

- [ ] **Step 1 — Owner adds the Vault as a controller, with dfx.** For each target,
      `dfx canister --network ic update-settings --add-controller cpdab-saaaa-aaaar-qca2q-cai <target>`.
      This is an Owner mainnet action performed with the bootstrap controller, **not** a Vault
      action and **not** something the operator page can do. Confirm with anonymous
      `dfx canister --network ic info <target>` and read the controller list from the output.
- [ ] **Step 2 — and only then — the Vault sets the final controller set.** A
      `Management.UpdateSettings` proposal, raised and approved at Vault quorum through the
      `#/operator` page, whose `controllers` vector is the ring's final set. The page shows the
      target's current controllers **only** from `dfx canister info` output the operator pastes
      in — there is no controller read model on the Vault and a browser cannot query the
      management canister — and it warns when that pasted output does not name `cpdab-…`.
- [ ] **Step 3 — Owner removes the bootstrap controller from the Vault and the Upgrader.**
      `4f6wg-…-cae` is no longer a controller of either — verified by anonymous
      `dfx canister --network ic info` on both, read from the output rather than from intent.
      This is an Owner dfx action on the ring canisters themselves, **not** a Vault action;
      the operator page deliberately offers no button for it.
- [ ] Every `set_controller_at_cutover` row in `deployment/mainnet/custody_manifest.toml` is
      discharged, and each canister's controller set is the ring's, not an individual's
- [ ] `vault_authorities.toml`'s bootstrap-window exception is marked **TERMINATED**, dated,
      with the `dfx canister info` evidence attached — the record closes where it was opened
- [ ] Only after all of the above may the "no unilateral controller authority" claim be made,
      and it is made about the **post-cutover** state explicitly

**This checklist records the steps. It does not perform them** — steps 1 and 3 are Owner-held
mainnet dfx actions, and step 2 is a Vault quorum action taken by the signers.

## Rollback plan

TBD — to be written alongside the release-cut runbook. Constraints that are
already fixed (do not violate them in whatever plan lands here):

### Never reinstall as recovery (DEF-095)

**The supported recovery path for a stateful canister is a governed `upgrade` whose
compatibility with the populated state has been demonstrated. `install_code` mode
`reinstall` wipes stable memory and is not recovery.** In particular:

- nullifier-registry loses the entire NULLIFIERS spent-set, re-admitting every
  historically spent nullifier.
- shielded-pool loses pending operations, accepted roots, terminal indexes, and
  its accounting checkpoint.
- merkle-tree loses the commitment tree backing every note.
- stsh_vetkeys loses the full G3 state listed above. Preserving its canister ID
  and key namespace can preserve derivability, but cannot restore devices,
  envelopes, tickets, nonces, quotas, grants, or token configuration.

If an upgrade traps, keep the canister and its identity intact and diagnose the
compatibility boundary. Use a governed forward corrective upgrade supported by
populated-state evidence. Do not reinstall, invent a snapshot/export/restore
path, or assume that installing a previous Wasm is safe after newer code has
persisted state.

## Eager-cell conversion boundary — historical disposable fixtures only

The 2026-07-28 eager-cell conversion for `nullifier-registry`, `merkle-tree`,
and `vesting` introduced new stable cells (MemoryIds 2, 5, and 3 respectively)
with all-0xFF sentinels. A pre-conversion disposable fixture with no valuable
state could historically be wiped and initialized afresh during local
rehearsal. That procedure is historical fixture context, not a recovery
instruction for a populated canister and not evidence about current mainnet
state.

A direct pre-conversion-to-converted upgrade traps when the new cell retains its
sentinel. For any populated canister at that boundary, preserve the canister ID
and state and hold the operation pending an independently reviewed migration.
There is no supported export/restore route in this runbook. Standing up a new
deployment does not recover the old commitment tree, vesting state, or spent
nullifiers, and reinstalling the registry can reopen spent nullifiers.

Cross-Wasm sentinel coverage is in
`integration-tests/tests/eager_cell_sentinel_tests.rs`. It demonstrates the
historical boundary; it does not authorize a populated reinstall or a blanket
downgrade.

## Pre-upgrade operator checklist (DEF-096) — MANDATORY mainnet invariant

Under a live upgrade, any in-flight inter-canister callback is LOST: the reply
arrives against post-upgrade code and the pre-upgrade execution context is
gone. Every async reconcile/recovery endpoint in the pool contains such an
await — `reconcile_deposit_commitment`, `reconcile_deposit_append_unknown`,
`reconcile_nullifier_insert`, `reconcile_pending_spend` (which internally
drives the private async `reconcile_active_append` step), plus
`reconcile_withdrawal_registry_insert` and
`reconcile_withdrawal_ledger_transfer`, which the list above omitted: they are
DORMANT while `withdraw` is fail-closed (anti-drift law #1), and dormant is not
the same as absent — an operator who re-enables the withdraw path inherits the
same stop-before-upgrade obligation on both. As do the normal
deposit/spend paths. Policy
(PM decision Q1, 2026-07-01): stop-before-upgrade is a documented operational
invariant — there is deliberately no code recovery framework for lost
callbacks in the current Mode A posture (withdrawals disabled; shield + spend
protocol fees live at launch per the fee hard-gate above, unshield fee dormant
on the fail-closed withdraw path).

Before EVERY canister upgrade on mainnet:

1. **Confirm no in-flight reconcile operations are pending.** Check with the
   existing public get_deposit_status and the wallet submitter owner-or-controller
   get_spend_status for recently operated records. Use typed Vault read-model
   proposals for PoolReadPendingOutputPromotions and PoolReadAccountingState and
   preserve their snapshots. Authority readbacks are public for pool, token, merkle,
   nullifier, treasury, vesting and verifier. Then inspect treasury
   `list_proposals()` / `get_subaccount_balances()` for disbursement state.
   TBD: no direct query exists yet for ALL reconcile in-flight states;
   operator must use existing status/accounting queries and pending-record
   views until a dedicated pre-upgrade drain query is added. The pool and
   treasury remain as described above.

1a. **Vesting outstanding claim markers are a future route hold.**
   `list_outstanding_claim_markers` is a controller-only query and the current Vault
   catalogue has no typed inter-canister route for it. A fresh-install absence is not
   evidence for a later populated upgrade. Before any later populated-vesting upgrade,
   require an approved authenticated bounded observation of outstanding markers and
   applicable quiescence/drain evidence; read visibility alone does not make the upgrade
   safe. Hold the upgrade pending that separately reviewed reachability and drain design.
   If active vesting must be upgraded during launch, this remains a launch blocker. Do
   not add a generic proxy or use signer-direct failure as evidence.
1b. **Staking — check no proposal is currently `Executing`.** The PRE-upgrade
   check is `list_proposals_by_status(opt Executing)` returning empty. A
   proposal in `Executing` is mid-execution; upgrading across it strands the
   proposal permanently, because `execute_proposal` writes `Executing` before
   its await and both of its guards then reject every future attempt.

   `reconcile_stuck_proposal(proposal_id, Executed | NotExecuted)` is the
   **POST-HOC RECOVERY** for a proposal already found stuck. It is **NOT** a
   pre-upgrade check and does not make an upgrade safe: it is controller-only,
   refuses until the proposal has been `Executing` for the ratified threshold
   (24 h), and **never re-issues the proposal's action** — it records an
   operator's off-chain determination of whether that action landed. A record
   it settles carries a `RECONCILED:`-prefixed `execution_result`, so a later
   reader can tell operator adjudication from ordinary execution.

   **Launch posture (D1):** staking is EXCLUDED at launch, so this step is
   INERT pre-launch — there are no live proposals to strand. It is retained
   here, not deleted, so the step exists the moment staking is enabled.

   **These surfaces make state VISIBLE; they do not make an upgrade safe.**
   Neither canister gained a quiescence control in this lane: nothing prevents
   a new claim or a new proposal execution from starting between your read and
   your upgrade. Re-read immediately before upgrading, and treat a non-empty
   result as a stop.
2. **Emergency-pause pool spends before upgrade if any reconcile is
   in-flight** (`emergency_pause_spends`, and `emergency_pause_deposits` if
   the in-flight operation is a deposit-path reconcile). Wait for the
   in-flight call to settle — do not upgrade to "cancel" it.
   **The pause does not stop the reconcile itself** — no reconcile endpoint is
   pause-gated. It stops new deposits and spends arriving while you wait, which
   is what this step asks for. `docs/PAUSE_MATRIX.md` is the single source for
   which paths each flag does and does not gate; read it before relying on a
   pause for anything.
3. **After upgrade, verify stable state is coherent before unpausing:**
   execute `PoolReadAccountingState` through the Vault and require a coherent
   snapshot. Re-run the referenced invariant tests for the exact I-02A ledger
   identity, I-02B solvency conditions and I-02C launch-model zero reimbursement
   balance; re-check the records from step 1, then `unpause_spends` /
   `unpause_deposits`.
4. **Never upgrade with active inter-canister calls in the reconcile
   family.** A lost reconcile callback strands the record in its pre-await
   status at best; at worst it desynchronizes the pool from the Merkle /
   nullifier / token canisters in ways the post-upgrade code cannot observe.

## Operational notes (pre-mainnet requirements)

- **Operator-reconcile runbook required before mainnet (F14-010).** The pool's
  operator-triggered reconcile endpoints (`reconcile_pending_spend`,
  `reconcile_deposit_commitment`, `reconcile_deposit_append_unknown`, and
  related recovery paths) need a documented, step-by-step operator runbook —
  when to invoke each, in what order, and what the expected end states are.
  This note records the requirement; the runbook itself is **still not written**.
  **Partially discharged:** `docs/POOL_OPERATOR_RECONCILE_RULES.md` now states the
  evidence obligation for `reconcile_deposit_transfer_not_executed` — the one
  reconcile whose decision the canister cannot verify and whose effect is an
  unrecoverable deletion. Every other endpoint in the family remains
  undocumented, so F14-010 stays OPEN.
- **`PENDING_FEE_REIMBURSEMENTS` is inactive at launch (F14-011).** The bucket
  exists in code but is dead because no code path credits it — the fee-
  reimbursement mechanism is not wired. This is independent of the now-nonzero
  launch protocol fees: charging shield/spend fees routes them to the ops/
  insurance **reserves** (I-02A), never to this reimbursements bucket. The
  DEF-087 accounting invariant tests assert it is always 0 at launch (I-02C).
  If a reimbursement path ever credits it, I-02C must be revisited in the same
  change.

## Solvency surface: schema-3 transition (R-4)

| deploy step | live page accepts | monitor emits | reader outcome |
|---|---|---|---|
| before (today) | `{2}` (v2-only page) | schema 2 | `HOLDS`/`VIOLATED` only; `UNAVAILABLE` never renders (schema 2 has no bit 4) |
| after page deploy, before monitor cutover | `{2,3}` (dual-accept page) | schema 2 (unchanged) | same as "before" — the page can now parse schema 3 but the monitor has not started emitting it, so nothing changes for the reader yet |
| after monitor deploy (cutover) | `{2,3}` (unchanged by this step) | schema 3 | `UNAVAILABLE` now renders correctly when bit 4 is set; `HOLDS`/`VIOLATED` unchanged otherwise |
| after v2-retirement cleanup (out of this lane, named in §3 OUT) | `{3}` only | schema 3 (unchanged) | unchanged from the prior row; only dead v2-acceptance code is removed |

The order is **page-first**, not free. The dual-accept page must be deployed to
`reserves.stsh.fi` and confirmed live-serving BEFORE `smoke-alarm-monitor` is
installed with `SCHEMA_VERSION = 3`. The reason is structural, not stylistic: a
v2-only page rejects a v3 leaf outright, because the v2 reserved-bit mask
requires bits 4–7 to be zero and bit 4 is exactly what v3 sets — that frozen
mask is asserted directly by `website/solvency-status/src/verify.test.ts`
("frozen V1-shape v2 mask"). A monitor-first cutover therefore does not degrade
gracefully; it turns the public solvency page into a parse failure for every
reader until the page catches up. Note that only the page-deploy step ever
changes what the page accepts — the monitor-deploy step does not.

**The monitor cutover is an UPGRADE of a live canister, not a fresh install.**
The running monitor's stable checkpoint is `STATE_VERSION = 1`, whose
`SolvencySnapshot` has no `supply_invariant_unavailable` field. A required (that
is, non-`opt`) Candid record field absent from the stored bytes FAILS subtyping,
so decoding that checkpoint straight into the schema-3 record traps
(`Subtyping error: field supply_invariant_unavailable is not optional field`)
and the IC REJECTS the upgrade. `post_upgrade` therefore dispatches on an
explicit probed `version` and migrates the `STATE_VERSION = 1` layout in place —
the field reads `false` ("no arithmetic error was reported", the truthful value
for a measurement taken before the signal existed) and the record is re-stamped
`schema_version = 3`, since the leaf it is about to certify is v3-encoded. This
is exercised end to end by `test_sam_10`, which installs the module built from
115526d, populates it with real refreshes and upgrades it to the current one;
`test_sam_05`, being a same-module upgrade, cannot bind this transition. Do not
"simplify" the arm away: `#[serde(default)]` does NOT make a Candid field
optional during subtype checking.

Dual-accept is retained after cutover on purpose, so a monitor ROLLBACK to
schema 2 stays safe without a second page redeploy. It is temporary: the
follow-up cleanup lane — **v2-acceptance retirement** (drop the v2 branch and
its mask from `verify.ts`, tighten to schema 3 only) — runs once the monitor is
confirmed emitting schema 3 in production, and produces the fourth row above.
