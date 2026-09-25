# Pool operator reconcile rules — evidence obligations

**Audience:** the operator/controller principal authorized to call the shielded
pool's `reconcile_*` endpoints after launch.

**Scope.** This page states the *evidence* an operator owes before invoking a
reconcile endpoint whose decision the canister cannot verify. It is not the full
step-by-step reconcile runbook — that is still owed (`MAINNET_DEPLOYMENT.md`,
Operational notes, **F14-010**). This page discharges the F14-010 obligation for
the `NotExecuted` decision only; every other reconcile path remains undocumented
there.

Related surfaces: `docs/PAUSE_MATRIX.md` (what a pause does and does not stop),
`MAINNET_DEPLOYMENT.md` § *Pre-upgrade operator checklist (DEF-096)* (when NOT to
upgrade while a reconcile is in flight).

---

## 1. The rule — `reconcile_deposit_transfer_not_executed`

> **The `NotExecuted` assertion is operator judgement. It is not a proof, and the
> canister does not treat it as one.**

That is the pool's own position, not an outside reading. The endpoint
`reconcile_deposit_transfer_not_executed` (`canisters/shielded-pool/src/lib.rs`)
carries a `RECONCILE TRUST (DEF-050B-2)` block that says, in terms:

> "`NotExecuted` is a CONTROLLER/OPERATOR ASSERTION, not cryptographic proof."

and, under `WHY THIS STAYS ManualReconcile`:

> "Non-execution is therefore not ledger-provable."

The reason non-execution cannot be proven is structural and is worth restating,
because it is what makes an operator evidence rule the *only* available control:
a re-submission of the transfer can prove that it **did** execute (the ledger
returns `Duplicate{block}`), but a re-submission that is **not** a duplicate
**commits the transfer itself** — so the act of "verifying" non-execution would
move the user's funds. Since lane L3-INT-01 the transfer memo also binds a
**secret nonce**, so the ledger identity is not externally recomputable from the
pool's public state, and there is deliberately no fund-moving evidence endpoint.

### 1.1 What the endpoint destroys

On a `TransferPending` record the endpoint removes, in one message and with no
tombstone:

1. the pending-deposit record itself (`PENDING_DEPOSITS … remove(&key)`),
2. the deposit nonce (`remove_deposit_nonce(&key)` — "drop the nonce with the
   record (forward secrecy)"), and
3. the recovery-index locator (`deindex_deposit_record(&deposit)` — "the record
   is gone — drop its recovery locator alongside it").

**Nothing is left in the canister to audit the decision against.** If the
assertion was wrong — the transfer really did execute — the depositor's public
STSH sits in the pool's escrow account with no private note, no liability
tracking it, and now no record naming them. The pool's own comment states the
consequence: *"permanently stranded — and must be resolved by operator
reconciliation OUTSIDE this endpoint."*

Protocol solvency is unaffected either way: a `TransferPending` deposit is never
credited, so removal mints no private liability, appends no Merkle leaf, and
issues no transfer. **The harm is to one user's claim, not to the supply
boundary.** That is precisely why solvency monitoring will not surface it and why
this rule exists.

### 1.2 The evidence set — gather and record BEFORE calling

Record all five items. An assertion made without them is out of policy.

| # | Item | Why |
|---|---|---|
| 1 | The **deposit key** — the 32-byte `note_commitment` you will pass. | It is the only handle on the record, and it ceases to exist the moment the call returns `Ok`. |
| 2 | The **deposit nonce** and any other record fields you can still read (status, amount, depositor principal if present). | Destroyed with the record. Capture before, never after. |
| 3 | The **ICRC block range searched**, stated as an explicit closed interval of block indices on the STSH token ledger, plus the timestamp bounds it covers. | "I looked and found nothing" is not evidence unless the search window is stated. |
| 4 | The **positive statement that no matching transfer exists in that range**, with the matching criterion written out (from-account, to-account = the pool's escrow account, amount). | Forces the operator to commit to a falsifiable claim. |
| 5 | The **operator principal**, the wall-clock time, and the reason the reconcile was needed (i.e. what left the record at `TransferPending`). | The decision is a human act; the record must name the human. |

Items 3 and 4 are the substance. Items 1, 2 and 5 exist so a later reviewer can
re-run the search.

#### 1.2a WHICH OF THE FIVE ARE ACTUALLY OBTAINABLE AT THIS HEAD (A-DOC-1, HARDEN-02 2026-09-17)

**Items 2 and 3 cannot be produced from any exposed query at this head.** This is
stated here because a procedure that asks an operator for evidence nobody can
obtain does not make the decision safer — it converts an operator control into a
rubber stamp, and the operator carries the outcome either way. Verified directly
in source for this note, not inferred:

- **Item 2, the deposit nonce — UNOBTAINABLE BY DELIBERATE DESIGN.** The nonce
  lives in a side-map that no query reads, and that is a CTO-signed privacy
  corrective, not an oversight. `canisters/shielded-pool/src/lib.rs` states the
  rule at the map's own declaration: the nonce "must therefore NEVER reach a
  candid-encoded return type — and `PendingDeposit` IS returned by
  `get_deposit_status`", because exposing it "would re-expose the exact ~2^32
  linkage oracle SSA flagged (L3-INT-01 HOLD)". An operator who could read the
  nonce would be holding a deposit-linkage oracle. **Do not open a query for it.**
  The other fields item 2 names — status, amount, depositor principal — ARE
  readable via `get_deposit_status` and must still be captured.

- **Item 3, the ICRC block range — UNOBTAINABLE BECAUSE THE LEDGER HAS NO BLOCK
  HISTORY.** The STSH token exposes no block log at all: no ICRC-3, no
  `get_blocks`, no `get_transactions` — zero matches across
  `canisters/token/stsh_token.did`. `next_block()` is a counter that issues
  indices; nothing stores what was issued. The only per-transfer state that exists
  is `TRANSFER_DEDUP`, a 24-hour replay guard pruned on every write — a guard, not
  an archive, and it holds a rows for `created_at_time`-bearing transfers only.
  So "the closed interval of block indices searched" names a search that cannot be
  performed against this ledger, and item 4's positive statement cannot be made
  over it either. Making item 3 executable means adding a transaction log to a
  canister that will hold real supply — a new ledger-state model, out of scope of
  any hardening lane and owed its own brief.

**What the operator CAN produce, and what must therefore be recorded instead:**

| Substitute | Source |
|---|---|
| The full `get_deposit_status` record for the key — status, amount, timestamps, depositor principal if present — captured BEFORE the call. | Pool query; the nonce field is absent from it by design. |
| The pool's escrow account balance (`icrc1_balance_of`) at the time of the decision, and the total pool-held figure from the public accounting/attestation read. | Token + pool queries. These bound what could have arrived even though they cannot enumerate individual transfers. |
| A `TRANSFER_DEDUP`-scoped statement, if and only if the transfer in question would have carried `created_at_time` and the decision is being made inside the 24-hour window: whether the canonical dedup identity is present. Outside that window, or without a `created_at_time`, this yields nothing and the operator must say so rather than imply a search happened. | Token state, via the pool's own retry path. |
| Everything in items 1, 4 and 5 that does not depend on a block range: the deposit key, the explicit matching criterion the operator believes fails, and the operator principal, wall-clock time and trigger. | The operator. |

**And the standing restriction that follows (D-3, CTO ruling 2026-09-17).** While
items 2 and 3 remain unobtainable, `reconcile_deposit_transfer_not_executed` — the
destructive `NotExecuted` path — **is not to be used.** Preserve the pending claim
and escalate the ambiguity instead; an ambiguity resolved destructively, on
evidence that cannot be gathered, is a user's claim lost with no record anywhere
that it existed. This restriction is operational and effective immediately; it is
NOT a closure of the underlying finding, and the residual — whether a real
depositor's claim can be lost before the NEW-2b tombstone lands — remains an open
decision owned outside this document.

### 1.3 Where the evidence is recorded — and why it is outside the canister

**Write the evidence into the operations packet / ledger row, before the call.**

Not because an external record is preferable, but because **the canister keeps
nothing**: the endpoint's whole effect is deletion, and it writes no tombstone,
no audit entry and no counter. There is no on-chain place to put this. If a
future change ever adds one, this rule must be rewritten against it rather than
quietly satisfied by it.

State this reason in any restatement of the rule. A rule whose *reason* is
recorded survives a rewrite; a bare "record the evidence" does not.

### 1.4 Forward pointer — the durable fix

> **SUPERSEDED IN SUBSTANCE BY HARDEN-03-SETTLEMENT.** The paragraphs below
> describe the pre-lane state and are retained for provenance. Read §1.6 first.

The durable fix is a **tombstone** written in place of the erased record, so the
decision is auditable on-chain. That work is **NEW-2b, tranche T2**
(`SSOT_AMEND_T2_NEW2B_NEW6.md`), and it touches `canisters/` — barred under the
current source freeze `2297a6c`.

**No tombstone exists today.** Until NEW-2b lands, the packet/ledger record
required by §1.2 is the *only* record of the decision that will exist anywhere.

### 1.5 The counterpart that does not exist

> **PARTIALLY SUPERSEDED BY HARDEN-03-SETTLEMENT.** The `Executed` *reconcile*
> still does not exist and still must not — that part is unchanged and
> permanent. What changed is the last sentence: the button an operator was told
> to escalate for has now been built, as `settle_deposit_transfer`, and it is
> evidence-gated rather than assertion-gated. See §1.6.

There is no `Executed` reconcile endpoint, and its absence is deliberate:
advancing to a Merkle append from a bare controller assertion would mint private
liability with no ledger backing — a supply-invariant violation, and therefore a
breach of the non-negotiable law that the ICRC ledger and the escrow reserve are
the supply boundary. An operator who can positively prove execution must escalate
for a separately-scoped settlement decision; there is no button.

### 1.6 HARDEN-03-SETTLEMENT — the settlement path, and what it changed here

Authorised by `reviews/CTO_RULING_HARDEN03_SETTLEMENT_L4_AND_TIMING_2026-09-17.md`
§3. This is the "Option 2" that `docs/L4_CUSTODY_FINALIZATION_DESIGN.md` filed
under *"Separately filed (NOT L4)"* — deferred there, not excluded.

**L4's own ruling is unchanged and is not re-litigated by this lane.**
Non-execution is still not ledger-provable by re-submission: a re-submit that is
not a duplicate returns `Ok` and **commits the transfer itself**, which is the
stranded-funds trap. `PoolReconcileDepositTransferNotExecuted` is and remains
`ManualReconcile` in `canisters/custody-types`; that binding is untouched.

**What the lane adds** is the credit-side path that was always missing, plus a
durable fence that makes the *close* side safe for the first time:

1. **`settle_deposit_transfer(note_commitment)`** — OPEN (caller-agnostic), not
   operator-gated, so a stranded depositor never waits for a human. It reads an
   authoritative token-side receipt; if there is none it re-submits the
   **byte-identical** transfer and branches on the ledger's answer; and if the
   ledger can no longer answer (`TooOld`, past 24 h) the receipt is what answers
   instead. It credits only on a ledger fact — an `Applied` receipt, a
   `Duplicate{block}`, or an `Ok(block)` — and deletes only on a durable
   `Cancelled` fence.
2. **`reconcile_deposit_transfer_not_executed` is now FAIL-CLOSED** for every
   deposit a post-lane pool created. If the record's settlement sidecar
   survives, the endpoint refuses with `PoolError::DepositNotReconcilable` —
   the SAME error whether a settlement is live or merely required; see §1.6
   for why and for how to tell the two cases apart if you need to. **The
   destructive button described in §1.1 is gone for those records.** The
   evidence obligation in §1.2 therefore applies only to the legacy,
   sidecar-absent case below.
3. **The durable witness the §1.4 tombstone was meant to be now exists** — but on
   the **token**, not in the pool. A fence-confirmed close leaves a `Cancelled`
   receipt keyed by `operation_id`: a different canister from the one whose
   operator took the decision, carrying **no** `note_commitment`, readable by no
   query. An in-pool tombstone was rejected on privacy grounds, because a
   commitment-keyed permanent record collides head-on with F2-REDACT's *enforced*
   30-day destruction and with the forward secrecy `DEPOSIT_NONCES` removal
   provides. **Whether NEW-2b's deposit half now retires, narrows, or stands is a
   CTO/SSoT call this lane does not make.**

**§1.6 — telling "settle this" from "wait" when the error doesn't.** An earlier
cut of this lane returned two distinct `PoolError` variants from item 2's
refusal, so the operator's tooling could distinguish "a settlement claim is
live right now, wait" from "no live claim, but a sidecar still covers this
record — run `settle_deposit_transfer` first." A CTO ruling (2026-09-17,
Option B) collapsed both into the single existing `DepositNotReconcilable`
variant instead: the alternative widened `PoolError`, which broke drift-locked
mirrors in `canisters/custody-types` (a path dependency of `vault` and
`upgrader`) and `canisters/treasury`, re-pinning three Wasms beyond what this
lane was costed for — for a distinction that is a diagnostics nicety, not a
money-safety property. **The refusal itself is identical either way; only the
"why" moved.** To tell the two cases apart, call `get_deposit_status` (or the
equivalent settlement-sidecar query) on the record before deciding whether to
wait or to act — a live, unexpired claim means wait; anything else covered by
a sidecar means run `settle_deposit_transfer`.

**The legacy carve-out (§3.8 quarantine).** A `TransferPending` record created
*before* this lane has no settlement sidecar, so its byte-identical transfer is
not reproducible — the submitted ledger fee was never stored — and re-submitting
one could double-charge the depositor. Such records keep **today's behaviour
unchanged**, including the destructive cancel and the full §1.2 evidence
obligation. Do not fabricate a sidecar or a receipt for them, and do not reset
their state. At launch there are none: `stsh_token` is not installed on mainnet,
and after this lane every `shield_deposit` writes a sidecar in its first durable
block.

**Owed, deferred, and recorded here so it survives this lane:**
`canisters/custody-types/src/lib.rs:294-306` and `:425-437` carry reasoning about
`PoolReconcileDepositTransferNotExecuted` that HARDEN-03-SETTLEMENT narrows —
non-execution becomes objectively provable for sidecar-covered records via the
fence. The correction is a comment-only edit and is therefore **deferred under
ARCHITECTURE.md law 7(f) / R-11 E-7**, because `stsh-custody-types` is a path
dependency of `canisters/vault` and `canisters/upgrader` and editing it would
re-pin `[wasm.vault]` and `[wasm.upgrader]` for prose, on the two canisters of
the custody ring, weeks after their ceremony. **It rides the next lane that
already touches those two canisters.**

---

## 2. Authority and preconditions

`reconcile_deposit_transfer_not_executed` is gated by
`assert_operator_controller()` — the **stored app-level `CONTROLLER` principal**,
called first, before any state read. Post-cutover that is the Vault, so in
practice the call is a Vault-governed action, not a direct `dfx` call.

It also passes `recovery_gate()` (lane A-5 FU1-1), so it returns
`Err(RecoveryInProgress)` while a post-upgrade recovery scan is incomplete.

It is **not** pause-gated — see `docs/PAUSE_MATRIX.md`. Pausing deposits does not
prevent a reconcile, and must not be relied on as one.

Only a `TransferPending` deposit is reconcilable here; every other status returns
`PoolError::DepositNotReconcilable` and has its own dedicated path
(`retry_deposit_commitment` / `reconcile_deposit_commitment` /
`reconcile_deposit_append_unknown`).
