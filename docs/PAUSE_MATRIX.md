# Pause matrix — what the operator pause flags actually stop

**This page is the single source for pause behaviour.** Other documents point
here; they do not restate the cells. If another page disagrees with this table,
this table is right and the other page is a defect.

There are exactly **two** pause flags, both in the shielded pool, both
`thread_local! { static … RefCell<bool> }` declared together:

```rust
static DEPOSITS_PAUSED:  RefCell<bool> = RefCell::new(false);
static SPENDS_PAUSED:    RefCell<bool> = RefCell::new(false);
```

They are **read in exactly four places** in the whole canister. That is the
entire reach of the pause mechanism; everything else in the table below is
blocked — or not blocked — by something other than pause.

> **The single most common error about this system: "pause blocks all exits."**
> It is wrong in both directions. `withdraw` is not pause-gated at all, and
> `withdraw` is nevertheless closed — by a different mechanism, on a different
> authority, with a different removal condition. Read the rows, not the summary.

---

## 1. The matrix

Legend: **gated** = this flag causes the call to return `PoolError::Paused`;
**—** = this flag is not read on this path.

| # | User-visible path | Entry point | `DEPOSITS_PAUSED` | `SPENDS_PAUSED` | What else blocks it |
|---|---|---|---|---|---|
| 1 | Deposit submission | `shield_deposit` | **gated** → `Paused` | — | Anonymous caller → `AnonymousCaller` (checked **before** pause). Non-ladder amount → `InvalidDenomination`. Post-upgrade recovery scan incomplete → `RecoveryInProgress` (checked **after** pause). |
| 2 | Deposit retry / completion | `retry_deposit_commitment`, `settle_deposit_transfer` | **gated** → `Paused` | — | `recovery_gate()` → `RecoveryInProgress`. Status must be commitment-pending; a pause **defers** the retry and never strands the record. **`settle_deposit_transfer` (HARDEN-03-SETTLEMENT) joins this row, NOT row 7**, even though it resolves a stuck record the way a reconcile does: it **originates an outbound token call** from the deposit path, and W2 2-1/DEF-096's rule is that a paused pool originates no such call. It is also OPEN (caller-agnostic), so it has no `assert_operator_controller()` and could not sit in row 7 on authority grounds either. Replay-safe for the same reason `retry_deposit_commitment` is: the record stays `TransferPending`, which is precisely the state the endpoint resumes from, so a pause defers and never strands. |
| 3 | Private spend | `private_spend` | — | **gated** → `Paused` | Anonymous caller → `AnonymousCaller` (before pause). `recovery_gate()` (after pause). `PINNED_CIRCUIT_VERSION` mismatch → `CircuitVersionMismatch`. Proof rejection by the `verifier` canister → `ProofRejected`. |
| 4 | Private-spend payout retry | `retry_private_spend_payout` | — | **gated** → `Paused` | `recovery_gate()`. Record must be `PayoutPending`; every other status returns its own typed error. Outcome is readable only by the submitter or a controller (`PayoutOutcomePrivate`). |
| 5 | **Fresh `withdraw`** | `withdraw` | **—** | **—** | **Not pause-gated; fail-closed by `reject_unbound_withdrawal_proof` until Phase 5.** The guard is unconditional and runs on every call: *"Decision 7: removed only in Phase 5"*. `recovery_gate()` runs before it. |
| 6 | Completion of an already-verified payout — blocked/interrupted withdrawal | `resume_blocked_withdrawal`, `reconcile_withdrawal_registry_insert`, `reconcile_withdrawal_ledger_transfer` | **—** | **—** | Not pause-gated. Authority: the record's submitter **or** a controller (Hard Stop #8). `recovery_gate()`. Dormant in practice while row 5 is fail-closed — dormant is not absent. |
| 7 | Deposit-path admin / recovery reconciles | `reconcile_deposit_commitment`, `reconcile_deposit_append_unknown`, `reconcile_deposit_transfer_not_executed` | **—** | **—** | Not pause-gated. `assert_operator_controller()` first, then `recovery_gate()`. See `docs/POOL_OPERATOR_RECONCILE_RULES.md` for the evidence obligation on the last of these. **This row's membership is UNCHANGED by HARDEN-03-SETTLEMENT** — `settle_deposit_transfer` is row 2, not here (see that row). What did change is `reconcile_deposit_transfer_not_executed`'s behaviour: it is now fail-closed on the settlement sidecar, refusing with `PoolError::DepositNotReconcilable` (the same variant whether a settlement claim is live or merely required — see `docs/POOL_OPERATOR_RECONCILE_RULES.md` §1.6) rather than destroying a record a post-lane pool created. Its pause posture, its authority and its gate ordering are all untouched. |
| 8 | Spend-path admin / recovery reconciles | `reconcile_nullifier_insert`, `reconcile_pending_spend`, `reconcile_private_spend_payout` | **—** | **—** | Not pause-gated. Controller/operator authority, then `recovery_gate()`. |
| 9 | Treasury disbursement | `treasury_disburse`, `reconcile_treasury_disburse` | **—** | **—** | Not pause-gated. Pool-authorized path only; the treasury custodies no STSH (Option 2, `canisters/treasury/CUSTODY_DECISION.md`). |
| 10 | Pause/unpause and emergency controls | `emergency_pause_deposits`, `emergency_pause_spends`, `unpause_deposits`, `unpause_spends`, `emergency_disable_circuit_version` | **—** | **—** | Not self-gated. Authority differs per call — see §2. |

**Rows 5–10 carry no pause check of any kind.** Pausing the pool does not stop a
reconcile, does not stop a treasury disbursement, and does not stop a withdrawal
completion; conversely, unpausing the pool does not open `withdraw`.

---

## 2. Who may pause, and who may unpause

The authorities are **asymmetric by design** — it is easier to close the pool
than to open it.

| Call | Authority | Side effects |
|---|---|---|
| `emergency_pause_deposits` | `assert_governance_or_operator()` — **either** authority (DEF-079) | none |
| `emergency_pause_spends` | `assert_governance_or_operator()` — **either** authority (DEF-079) | bumps the security epoch (P-VK / POOL-04) |
| `emergency_disable_circuit_version` | `assert_operator_controller()` | sets `SPENDS_PAUSED` only; bumps the security epoch. Rejects unless the argument equals the current `PINNED_CIRCUIT_VERSION`. |
| `unpause_deposits` | `assert_operator_controller()` — **operator only**, narrower than pause | none |
| `unpause_spends` | `assert_operator_controller()` — **operator only**, narrower than pause | bumps the security epoch (P-VK / POOL-04) |

**The asymmetry in that last column is real and is the operationally important
line in this table** (corrected by HARDEN-02, 2026-09-17; it previously read
"none"). `unpause_spends` bumps the security epoch and `unpause_deposits` does
not — the spend body calls `bump_security_epoch()` after clearing the flag,
carrying the comment "P-VK (POOL-04): spend unpause is a security-epoch event",
while the deposit body clears its flag and returns. A security-epoch bump
invalidates in-flight material, so an operator reading "none" here would unpause
spends believing the call is inert and be wrong about it in the one direction that
costs something. The pause side of the same asymmetry was already recorded
correctly two rows above.

Read-back queries: `is_deposits_paused`, `is_spends_paused`. Both report the
**operator flags only**.

---

## 3. Pause is not the recovery gate — do not conflate them

`recovery_gate()` / `recovery_pending()` is a **separate** closure with different
semantics, and it appears in the "what else blocks it" column of nearly every row
above.

- The pause flags are **heap** `RefCell<bool>`. They are serialized in
  `pre_upgrade` and restored in `post_upgrade`, so an operator pause does survive
  an upgrade.
- The recovery gate is derived from the **durable cursor**, never from a heap
  flag. The pool's own comment gives the reason: a heap-derived gate "would open
  exactly when it must stay shut", because the upgrade that the gate guards is the
  thing that would clear the flag. *"This survives by construction and cannot
  drift from the migration state, because it IS the migration state."*
- A recovery closure returns `RecoveryInProgress`, **not** `Paused`, and
  `is_deposits_paused` / `is_spends_paused` are **unaffected** by it. An operator
  who sees `Paused` and an operator who sees `RecoveryInProgress` are looking at
  two different conditions with two different remedies.

---

## 4. Testability

Every cell above is an assertion about a single entry point and a single flag
value. The intended shape of the corresponding test is: set the flag, call the
entry point, assert the exact typed error (or assert that the error is *not*
`Paused` for the `—` cells). The test half of this item is specified in
`BRIEF_LANE_TEST_T1` §3.3; if a cell here cannot be written as such an assertion,
the cell is too vague and this page is the thing to fix.

Note for row 3 vs row 1: the anonymous-caller check precedes the pause check on
both `shield_deposit` and `private_spend`, so an anonymous call against a paused
pool returns `AnonymousCaller`, not `Paused`. A test that calls anonymously
cannot observe the pause on those two paths.

---

## 5. Consistency notes on neighbouring documents

- `canisters/shielded-pool/UPGRADE_BOOTSTRAP_RUNBOOK.md` §1 states that the two
  flags gate `shield_deposit`, `private_spend`, `retry_deposit_commitment` and
  `retry_private_spend_payout` — rows 1–4 here. **That is correct and complete**;
  it makes no claim about `withdraw`.
- `MAINNET_DEPLOYMENT.md` § *Pre-upgrade operator checklist (DEF-096)* step 2
  directs a pause before upgrading with a reconcile in flight. Note what rows 7
  and 8 say: **the pause does not stop the reconcile itself.** It stops new
  deposits and spends from arriving while you wait for the in-flight call to
  settle, which is what that step actually asks for ("Wait for the in-flight call
  to settle — do not upgrade to 'cancel' it").
