# Shielded-pool upgrade bootstrap runbook (P-REC / K3-005)

**Scope:** the operator procedure for upgrading `shielded_pool` across the
**one-shot P-REC recovery-index migration** (`recovery_index_version 0 → 1`) and,
thereafter, for keeping every upgrade's `post_upgrade` cost bounded.

This runbook exists because two `post_upgrade` scans are bounded by a hard cap
(`MAX_UPGRADE_SCAN = 1_000`) and **trap over the cap rather than truncate**
(trapping is the safe choice — silently dropping in-flight records would strand
funds / reopen a nullifier window). If `PENDING_SPENDS` or `PENDING_DEPOSITS`
holds more than the cap of records, the upgrade aborts and rolls back. The fix is
never to raise the cap blindly — it is to **prune terminal records and settle
in-flight ones below the cap first.**

## Why the index cannot just be rebuilt every upgrade (K3-005)

Invalid/failed spends are **free** — an invalid proof is rejected *before* fee
accounting, so even the 0.1-STSH launch spend fee does not price-out junk-record
growth. Fees are therefore **not** the mitigation. The structural mitigation is:

- The recovery index performs **exactly ONE** main-map scan, ever — the one-shot
  `recovery_index_version == 0` migration below. Every subsequent upgrade is
  **index-only** (the migration block is skipped once the version is stamped).
- Terminal / no-recovery records are **prunable** (`prune_terminal_records`) and
  must be pruned so they never contribute to upgrade-scan cost.
- **Trap-no-stamp:** if the one-shot migration traps (cap exceeded, or the
  build-verification cardinality check fails), the whole upgrade rolls back and
  `recovery_index_version` stays `0`. A half-built index is therefore **never**
  treated as complete — the next upgrade re-runs the build from scratch.

## Procedure — the four steps: pause → prune → assert-count → resume

### 1. PAUSE

Stop new deposits and spends so the pending maps do not grow under you while you
prune, and so no record is mid-flight across the upgrade boundary.

Quiescence (DEF-096): the two flags gate BOTH the primary entry points
(`shield_deposit`, `private_spend`) AND the public retry endpoints
(`retry_deposit_commitment`, `retry_private_spend_payout`). With both set, all
four reject with `Paused` before any state write or inter-canister call, so no
outbound call originates from the pool on these paths. Pausing defers a pending
retry; it never strands a record — the retry resumes unchanged after step 4.

```
dfx canister call shielded_pool emergency_pause_deposits '()'
dfx canister call shielded_pool emergency_pause_spends   '()'
```

Either the governance or the operator authority may pause (DEF-079).
`emergency_pause_spends` also bumps the security epoch (P-VK/POOL-04).

Confirm:

```
dfx canister call shielded_pool is_deposits_paused '()'   # -> (true)
dfx canister call shielded_pool is_spends_paused   '()'   # -> (true)
```

### 2. PRUNE (repeat until the maps are safely below the cap)

Prune terminal records (indexed first, then legacy) and settle/reconcile any
non-terminal in-flight records via their dedicated reconcile endpoints
(`reconcile_pending_spend`, `reconcile_nullifier_insert`,
`reconcile_deposit_append_unknown`, `reconcile_private_spend_payout`, …). Prune
is bounded per call and resumable — drain the backlog with repeated calls:

```
dfx canister call shielded_pool prune_terminal_records '(record {
  older_than_ns          = <retention cutoff ns>;
  max_records            = 1000;
  prune_spends           = true;
  prune_deposits         = true;
  scan_legacy_spends     = true;
  scan_legacy_deposits   = true;
  max_scan_records       = 10000;
  legacy_spend_cursor    = null;
  legacy_deposit_cursor  = null;
})'
```

Repeat (advancing the legacy cursors from each `PruneResult`) until
`PENDING_SPENDS` and `PENDING_DEPOSITS` are each **well under 1 000** records.
The active (recovery-required) record count is the real driver — terminal records
should be gone; only genuinely in-flight operations remain, and those are expected
to be few.

### 3. ASSERT-COUNT (before AND after the upgrade)

**Before** the upgrade, record the active-index cardinality and version (a
`testing`-feature build exposes this directly; a production build infers it from
the `list_my_active_*` pages the operator's own tooling walks):

```
# testing build:
dfx canister call shielded_pool recovery_index_counts_for_test '()'
#   -> (deposits, spends, version)
```

Perform the upgrade (`dfx canister install --mode upgrade` / the deployment
pipeline). Then **assert** the invariant:

- **First upgrade (version 0 → 1):** after the upgrade, `version == 1` and the
  index cardinality equals the number of recovery-required records the one-shot
  migration classified. The migration's own build-verification (cardinality of
  the built index == the classified count) has already run inside `post_upgrade`
  and would have **trapped** — aborting the upgrade with `version` still `0` —
  had it disagreed. So a successful upgrade to `version == 1` is itself the
  assertion; re-reading `recovery_index_counts_for_test` confirms it externally.
- **Later upgrades (version already 1):** cardinality must be **unchanged** by the
  upgrade (the migration block is skipped; only inline maintenance touches the
  index). Any change means an inline hook is mis-wired — investigate before
  resuming traffic.

If `version` is still `0` after an upgrade attempt, the migration **trapped**
(cap exceeded or verification failed) and the upgrade rolled back — return to
step 2, prune further, and retry.

### 4. RESUME

Once the counts assert clean:

```
dfx canister call shielded_pool unpause_deposits '()'
dfx canister call shielded_pool unpause_spends   '()'
```

Unpause is operator-controller only (narrower than pause, by design).

## Notes

- The recovery index (`ACTIVE_DEPOSIT_INDEX` / `ACTIVE_SPEND_INDEX`) is
  **locator-only**: it stores `(owner, commitment)` / `(owner, spend_id)` and no
  status. A record's live status is always read from the authoritative
  `PENDING_DEPOSITS` / `PENDING_SPENDS` record, so the index can never carry a
  stale status.
- `list_my_active_deposits` / `list_my_active_spends` are **advisory** caller-gated
  queries (L0-H): a wallet uses them to re-discover its own in-flight operations
  from a fresh device, then drives recovery through an **authoritative update**
  (retry/reconcile) — a query never changes a note's spendability.

---

## FU1-1 — the post-upgrade recovery scan (lane A-5)

**What changed.** A pool whose pending maps exceed `MAX_UPGRADE_SCAN` used to be
**un-upgradeable**: `pre_upgrade` and `post_upgrade` both scanned the main maps in
one shot and trapped over the cap. The scan is now **resumable**. On an unstamped
pool the four one-shot main-map phases run through a durable cursor
(MemoryId 21): `post_upgrade` performs the first chunk, and the remainder is
completed by ordinary gated traffic.

### What an operator sees

While the cursor is pending, the affected ingress paths return

> `PoolError::RecoveryInProgress("post-upgrade recovery scan in progress: ~N records remaining …")`

**This is temporary and self-clearing.** Every gated update advances the scan by one
chunk *before* refusing, so `N` falls as callers retry, and the last refused caller
is the one that opens the pool.

### The one operator test that matters — is it resumable, or stuck?

**Call a gated update twice and compare `N`.**

| Observation | Meaning | Action |
|---|---|---|
| `N` **falls** between calls | Normal recovery. Working as designed. | **Wait.** Do not intervene. |
| `N` **does not change**, or calls trap with a **P-ROOT invariant violation** | The scan is **stuck**, not progressing | **Intervene** — see below |

A stuck pool is a different state from `RecoveryInProgress` and says so in its own
trap text: *"THIS IS NOT RecoveryInProgress AND WILL NOT CLEAR ON ITS OWN."*

### Do NOT toggle the operator pause

`is_deposits_paused` / `is_spends_paused` report the **operator flags only** and are
unaffected by a recovery closure. An operator pause returns `Paused`; a recovery
closure returns `RecoveryInProgress`. They are deliberately distinguishable by both
the error and the query. Pausing does not help recovery and only adds a second
reason to refuse.

### P-ROOT violation discovered during recovery — the stuck case

If a lease-free record (or an invalid `CommitmentAppendInFlight` with no expected
leaf index) is found **beyond the first chunk**, the trap rolls back that
continuation message, the cursor does not advance, and the pool stays closed
indefinitely. Retrying will not help.

**Remedy:** resolve the offending record on the **previous Wasm**, then upgrade
again. The trap names the record and its status.

If the same violation is found **inside chunk 1**, it is discovered during
`post_upgrade` and simply **rejects the upgrade** — the canister keeps running the
previous Wasm and the pool is *not* stuck.

### Dev / rehearsal — REINSTALL, not upgrade

FU1-2 moved the six accounting scalars into an eager cell (MemoryId 20) and bumped
`STATE_VERSION`. A pool predating it **cannot be upgraded in place**: the version
gate and the accounting sentinel both trap, by design. The pre-FU1-2 boundary is a
**reinstall boundary**. On dev and rehearsal deployments, `dfx canister install
--mode reinstall` after settling in-flight operations; never try to migrate across it.

### Release identity — B-2 / B-5 inherit a pre-ceremony-freeze re-verify

Lane A-5's single authorised `PoolError` variant (`RecoveryInProgress`) lives in
`canisters/custody-types`, which **`vault` and `upgrader` both depend on**, so both
custody-ring Wasms recompiled and their `deployment/mainnet/release_hashes.toml`
pins moved. They were re-pinned as a **deliberate, attributed ceremony step** on the
principal's ruling (`OWNER_RULING_A-5_repin_2026-08-21`), with the cause recorded in
the file as the DID-variant commit.

**Carried into the pre-ceremony freeze, and owed there — not here:**

- `[wasm.vault]` and `[wasm.upgrader]` are **re-verified with the full rebind**, by
  the R2.6 procedure in `release_hashes.toml` (fresh root, fresh `CARGO_TARGET_DIR`,
  `build.command` verbatim, ≥2 independent reproductions). The A-5 re-pin was
  observed twice by ONE builder on ONE machine — corroboration, not R2.6
  independence.
- `build.cargo_lock_sha256` is **stale** against the tree and was deliberately left
  stale by the A-5 re-pin's fence (only the two custody-ring rows and their comment
  moved). It is rebound at the freeze, with every other row.
- `build.asserts_identity_at` was **not** moved. Re-arming byte-equality is its own
  binding act at the release commit, in a commit touching only the record.

A mismatch found at the freeze is a **stop-and-report**, exactly as the record says
— never a refresh to make a gate go green.

### The count reaches ZERO, and the completing call is not refused (SSA-A5-D1)

Sharpening the operator test above. The remaining-work count does not merely fall
across calls — it reaches **exactly zero** when the scan finishes, and the call that
finishes it is **not refused**: it performs its chunk, completes the scan, and returns
normally. The pool is open from that call onward.

So a **non-zero count that stops falling is a stall, not a finish** — that distinction
is what makes the count actionable. It holds even when the scan removes records as it
goes: H-1 normalization deletes pre-mutation spends (`Requested` / `VerificationPending`)
during the scan, and the work snapshot subtracts each cancelled future visit rather
than counting work that no longer exists.
