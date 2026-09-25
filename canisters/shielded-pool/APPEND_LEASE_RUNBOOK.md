# Append-Lease Operator Runbook (P-ROOT / C-ROOT-1)

**Audience:** the pool operator (holder of the stored CONTROLLER principal).
**Scope:** detecting and resolving a stuck pool-wide append lease.
**Status:** normative. The procedures below are the ONLY authorized ways to
resolve a stuck lease. There is **no force-release**: no production endpoint
clears the lease cell directly, the lease **never times out on-chain**, and no
such mechanism may be added — a forced release while a Merkle append's outcome
is unknown is exactly the double-append / unfinalized-anchor defect (C-ROOT-1)
this design closes.

---

## 1. What the lease is

At most **one unresolved Merkle append** may exist across the whole pool at a
time — deposits (`shield_deposit` / `retry_deposit_commitment`) and spend-output
promotion (`private_spend` / `reconcile_pending_spend`) share one durable lease.
While it is held, every other append attempt is turned away with the retryable
`CommitmentAppendFailed("pool-wide append lease held …")`. A lease stuck in a
non-live phase therefore stalls **all** pool appends until an operator resolves
it — detection and resolution are security-relevant operations, not hygiene.

Phases (closed five-variant enum):

| Phase | Meaning | Self-resolving? |
|---|---|---|
| `Snapshotting` | acquired; pre-append snapshot reads in flight; no append issued | yes, within one call — persistent only after a lost callback |
| `AppendInFlight` | `append_commitment(s)` issued; outcome pending | yes, within one call — persistent only after a lost callback |
| `AppendUnknown` | transport-unknown append; the leaf MAY exist | **no — operator reconcile required** |
| `ReconcileInFlight` | a controller reconcile is in flight | yes, within one call — persistent only after a lost callback |
| `AppendConfirmedRootPending` | leaf/outputs confirmed; accepted-root + head write not yet durable | **no — operator roll-forward required** |

## 2. Detection

Run `ops/append-lease-watch` (see its README) continuously. It polls the
**controller-gated** `get_append_lease_owner` view (owner, phase, generation,
`acquired_at_ns`, `phase_started_at_ns`), applies the per-phase thresholds in
§3, and **alerts only** — it never mutates state. The public
`get_append_lease_status` getter deliberately exposes only
`{held, phase, age_bucket}` and is not sufficient for operations.

## 3. Per-phase alert thresholds (defaults)

A live call resolves its lease phases within seconds. Sustained age in the same
phase means a lost callback or an outage:

| Phase | Alert after | Rationale |
|---|---|---|
| `Snapshotting` | 5 min | only persists if the snapshot callback was lost |
| `AppendInFlight` | 5 min | only persists if the append callback was lost |
| `ReconcileInFlight` | 5 min | only persists if the reconcile callback was lost |
| `AppendUnknown` | 15 min | legitimately waits for an operator; alert to start §4 |
| `AppendConfirmedRootPending` | 15 min | legitimately waits for an operator; alert to start §4 |

## 4. Authorized resolution — by (phase, owner-record status) tuple

First read the owner from `get_append_lease_owner`, then the owner record
(`get_deposit_status(commitment)` / `get_spend_status(spend_id)` as controller).
Every legal tuple has exactly one procedure. Any tuple **outside** these tables
is an invariant breach: stop and escalate (§5) — the next upgrade will refuse to
proceed past it by design.

### 4.1 Deposit-owned lease

| Phase | Record status | Procedure |
|---|---|---|
| `AppendUnknown` | `CommitmentAppendUnknown` | `reconcile_deposit_append_unknown(commitment)` — Merkle-verifies via `get_leaf`; finalizes (credit exactly once → terminal `CommitmentRootAccepted`, lease released) or reverts to retryable (lease released). `AmbiguousMerkleState` → §5. |
| `AppendConfirmedRootPending` | `CommitmentAppended{..}` | `reconcile_deposit_commitment(commitment)` — continue-finalization roll-forward: accepted-root insert + head write from one `get_scan_head`, terminal transition, **then** release. Never release before the insert. |
| `Snapshotting` | `TransferConfirmedCommitmentPending` | lost snapshot callback. No live endpoint mutates the lease here; perform a **no-op canister upgrade** — `post_upgrade` verifies the tuple and releases (record stays retryable; complete it with `retry_deposit_commitment`). |
| `AppendInFlight` | `CommitmentAppendInFlight` | lost append callback. Perform a **no-op canister upgrade** — `post_upgrade` normalizes the pair to (`AppendUnknown`, `CommitmentAppendUnknown`); then run the `AppendUnknown` row. |
| `ReconcileInFlight` | `CommitmentReconcileInFlight` | lost reconcile callback. **No-op upgrade** → pair returns to (`AppendUnknown`, `CommitmentAppendUnknown`); re-run the reconcile. |

### 4.2 Spend-owned lease

| Phase | Record status | Procedure |
|---|---|---|
| `AppendUnknown` | `ActiveAppendUnknown{..}` | `reconcile_pending_spend(spend_id)` — `get_leaf`-verifies the batch: confirmed → finalize (root + head + accounting, release before any payout step); not committed → `AppendRetryScheduled` (release; call again to retry). `AmbiguousMerkleState` → §5. |
| `AppendConfirmedRootPending` | `ActiveRootPending` | `reconcile_pending_spend(spend_id)` — continue-finalization under the retained lease; releases after `RootAccepted` + accounting. |
| `Snapshotting` | `NullifierFinalizedOutputsPending` / `ActiveAppendRejected{..}` | lost snapshot callback. **No-op upgrade** releases; then `reconcile_pending_spend` retries the promotion. |
| `AppendInFlight` | `ActiveAppendInFlight` | lost append callback. **Do not attempt a reconcile** — it is rejected in this phase by design (the original callback could still be live; double-append risk). **No-op upgrade** normalizes to (`AppendUnknown`, `ActiveAppendUnknown`); then the `AppendUnknown` row. |
| `ReconcileInFlight` | `ActiveAppendUnknown{..}` | lost reconcile callback. **No-op upgrade** returns the lease to `AppendUnknown`; re-run the reconcile. |

Notes:
- A "no-op upgrade" is a normal `dfx canister install --mode upgrade` with the
  **same** production Wasm. `post_upgrade` performs the tuple verification and
  the pinned normalization/release; it never force-releases and never guesses.
- All reconcile endpoints are idempotent and compare owner + generation + phase
  before mutating; re-running them is safe.
- A payout stuck at `PayoutUnknown` does **not** hold the lease (release happens
  before the payout await). Resolve it independently via
  `reconcile_private_spend_payout` per the existing payout runbook.

## 5. Escalation (do not improvise)

Escalate to the architect/PM — do not retry, do not upgrade repeatedly, never
attempt to clear state by reinstall — when:
- any reconcile returns `AmbiguousMerkleState` (a foreign leaf occupies the
  expected slot; deterministic attribution is impossible on-chain);
- the observed (phase, record status) tuple is outside the §4 tables;
- an upgrade is rejected by the `post_upgrade` verification (illegal tuple,
  pre-lease unresolved record, or head-migration pin);
- `commit_accepted_root_head` trapped (head fork / count mismatch) — this is a
  supply-boundary invariant violation, not an operational condition.

## 6. Related invariants (context, not procedure)

- The lease is stored in its own stable cell (MemoryId 14) and survives
  upgrades; `post_upgrade` verifies it against the owner record and refuses the
  upgrade on disagreement.
- `AcceptedRootHead` (MemoryId 15) advances only through
  `commit_accepted_root_head`, monotonically, from a single atomic
  `get_scan_head` read taken under the lease.
- After the P-REC recovery-index stamp, upgrade verification reads only the
  active recovery indexes — terminal-record volume never blocks an upgrade.
