# Observer model — who can see what

**This is a factual page, not a privacy claim.** It exists because the opposite
kind of page caused real harm: the wallet previously told users the sender was
private on a flow where the submitter principal is signed by Internet Identity
and recorded on-chain (finding AR-2, 2026-08-24, hold-launch). Everything below
is stated so that a user or a reviewer can check it against the tree.

Read `docs/PAUSE_MATRIX.md` for operational state, and `ARCHITECTURE.md` for the
non-negotiable law that the **ICRC ledger and the escrow reserve are the supply
boundary — never the shielded pool**. Nothing on this page changes that.

---

## 0. The one-line version

> **The amounts that cross the pool's boundary — what goes in and what comes out —
> are public, and so are the principals who submit transactions. What is private
> is the *link* between a shielded deposit and a later shielded spend, and the
> per-note values inside the pool.**

The system hides a linkage. It does not hide participation, it does not hide the
boundary amounts, and it does not hide the fact that you called the pool.

### 0.1 "Amounts" is three different things — keep them apart

This page previously said flatly that "amounts … are public" and that the system
"does not hide value", while §1 also said an observer cannot see note values
"beyond what the denomination ladder and the payout amount already reveal". Both
sentences were defensible on their own; together they told a reader that in-pool
note values are public, which they are not. The three categories, named, each with
the inference it supports and the one it does not:

| # | Category | Public? | What it lets an observer conclude | What it does NOT let them conclude |
|---|---|---|---|---|
| 1 | **Entry and exit amounts** — the figure on a deposit into the escrow account, and the figure on a payout out of the pool | **Yes, fully.** A deposit is one of five ladder values; a payout is exact | The size of each crossing, and therefore an upper bound on any note derived from it | Which deposit a payout came from, or how the value was split inside |
| 2 | **Submitting principals** — who signed the ingress message, `private_spend` included | **Yes, fully.** II-signed, on the ledger and in ingress | That this principal participated, and when | What that principal's notes are worth, or which of its deposits a later spend draws on |
| 3 | **In-pool note values** — per-note values, change outputs, the amount inside any individual commitment | **No.** Not on the ledger, not in any public query, and not derivable from (1) | Nothing directly | — but (1) CONSTRAINS them: a note is no larger than the deposit it descends from, and a payout reveals its own amount exactly. "Not disclosed" is therefore not the same as "not constrained by public data" |

Category 3 is the one the earlier wording erased. It is also the weakest of the
three claims, for the reason in the last column: the ladder and the payout figure
constrain what an in-pool value can be even though no query reports it. This
correction is **not** a stronger privacy claim than the code supports — it states
one fact the page had contradicted itself about, and it keeps every caveat below
intact.

---

## 1. Public-ledger observer

**Who:** anyone. No special access. Reads the STSH ICRC-1/ICRC-2 ledger
(`token`) and any public canister query.

**Can see:**

- Every `icrc1_transfer` / `icrc2_transfer_from` block: from-account,
  to-account, amount, fee, memo field, timestamp, block index.
- That a given principal transferred STSH **into the pool's escrow account** —
  i.e. that this principal made a shielded deposit.
- **The deposit amount, exactly.** Deposits are **fixed-denomination** — one of
  five ladder values (`DENOMINATIONS` in `canisters/shielded-pool/src/lib.rs`;
  the ladder itself is published in `MAINNET_DEPLOYMENT.md`). A deposit is
  therefore not merely visible, it is one of five publicly known values.
- Every payout **out** of the pool: recipient account and amount.
- Aggregate pool state through public queries and the certified solvency
  attestation (`smoke-alarm-monitor`, `docs/SOLVENCY_ATTESTATION_SPEC.md`) —
  total balances and bucket accounting, not per-note data.

**Cannot see:**

- Which deposit a given payout came from. That link is what the shielded pool
  and the Groth16 spend proof protect.
- **Per-note values inside the pool** — the amount inside any individual
  commitment, and the split across change outputs. These are category 3 in §0.1:
  not on the ledger, not in any public query. Read with the qualification that
  belongs to them: the ladder and the payout figure BOUND an in-pool value even
  though nothing reports it, so this is "not disclosed", not "unknowable".
- Note commitments' preimages and spend keys.

**Caveats that matter more than the guarantees:**

- **Amount and timing are a linkage channel.** A withdrawal of an unusual amount,
  or shortly after a single deposit, can be correlated by anyone with a block
  explorer. Fixed deposit denominations exist to make the deposit side
  non-distinguishing; the **withdraw** side is a custom amount by design
  (identity private, figure visible — `ARCHITECTURE.md` anti-drift law 1). The
  anonymity set is the set of unspent notes at your denomination, and nothing
  enlarges it on your behalf.
- The transfer memo binds a **secret nonce** since lane L3-INT-01, so the ledger
  identity of a deposit is not externally recomputable — but the transfer itself
  is still fully visible.

---

## 2. Subnet node operator

**Who:** the node providers running the subnet the canisters are installed on
(`pzp6e`, 34 nodes), and anyone with access to their machines or their
boundary-node traffic.

**Can see:**

- **The full ingress message**: the calling principal, the method name, and the
  **complete, plaintext call arguments** — including the arguments to
  `private_spend`. Candid arguments are not encrypted to the canister; the subnet
  executes them.
- Call timing, frequency, source of the ingress, and response payloads.
- Canister memory as executed — a node runs the Wasm.

**This is the widest observer in the system.** A node operator who retains
ingress logs can correlate a `private_spend` call to the principal that signed
it, permanently, regardless of what the canister later stores or erases.

**Implication, stated plainly:** the shielded pool's privacy property is
*against a public-ledger observer*, not against the subnet. Threat models that
include the node operator get a materially weaker answer.

---

## 3. App / canister controller

**Who:** the controller of the pool and the other canisters. **Post-cutover this
is the Vault (`vault`), under a 2-of-3 quorum** — not a person. The pool also
keeps a separate app-level `CONTROLLER` principal used by
`assert_operator_controller()`.

**Can do:**

- Upgrade, and therefore read raw stable memory, including everything in §3.1
  below. A controller is not bounded by the canister's query surface.
- Call controller-gated reads (`get_accounting_state_for_controller_update`,
  `list_pending_output_promotions_for_controller_update`, and the reconcile
  family) and the emergency pause controls (`docs/PAUSE_MATRIX.md` §2).
- Read any individual spend or withdrawal record's status
  (`can_read_owned_or_controller`: the record's submitter **or** any controller).

### 3.1 What pool state actually contains

**Pool state is not a plaintext note ledger.** There is no map from note to
owner, no list of balances by principal, and no decryptable note content in the
canister. What it does hold:

- **Note commitments** in the Merkle tree — hashes, not values or owners.
- **Spent nullifiers** — unlinkable to the commitments they retire.
- Six-bucket aggregate accounting.
- **Per-operation records that DO carry a principal while they are live:**
  `PendingSpend.submitter` and `PendingWithdrawal.submitter`, plus a pending
  deposit's `depositor`. These gate `get_spend_status` / `get_withdrawal_status`
  to their owner.

### 3.2 The submitter principal — the honest statement

**`private_spend` is signed by Internet Identity and the submitting principal is
recorded on-chain.** It is captured at the entry point before any other work
(DEF-069) and stored on the record. So:

- **The pool knows which principal submitted which spend, while the record
  lives.** A controller can read that.
- The principal is **erased from terminal records after 7 days**
  (`REDACTION_AGE_NS`), and the record itself is destroyed after 30 days
  (`RECORD_RETENTION_NS`). An invariant in the retention sweep guarantees the
  order: *"NO RECORD IS EVER REMOVED WHILE IT STILL CARRIES A PRINCIPAL."*
- **This erasure is not retroactive privacy.** It bounds what the *canister*
  retains. It does nothing about §2 — the ingress message that carried the call
  is outside the canister's control and is not erased by anything the pool does.

Do not read §3.2 as "spends are anonymous after a week." Read it as "the pool
stops being the place that answers the question after a week."

---

## 4. Frontend / asset host

**Who:** the asset canister serving the wallet (`wallet_frontend`, app.stsh.fi /
the `s3tyu` native origin), the boundary nodes in front of it, and any network
observer between the user and those.

**Can see:**

- **Which origin you loaded and when.** Asset-canister fetches are ordinary HTTP
  through a boundary node.
- **Nothing of your notes by design.** Note storage is client-side (`idb`, in the
  browser), and the spend proof is generated **client-side** in
  wasm-compiled-to-browser crypto. Secrets do not leave the browser as secrets.

**But:**

- **The served bundle is the trust boundary.** A wallet build that were modified
  — at the asset canister, in the build pipeline, or in a dependency — could read
  everything the browser holds: notes, spend keys, the lot. This is why the wallet
  bundle is hash-pinned as a release artifact and why the supply-chain finding
  (A1 red team R14-1) is tracked as Critical. The privacy of §1–§3 assumes an
  honest bundle; none of it survives a malicious one.
- Internet Identity is **origin-bound**. The wallet pins a `derivationOrigin` to
  the `s3tyu` native origin so both entry points yield the same principal
  (WT-1); loading a look-alike origin yields a *different* principal, which is a
  correctness and a linkage hazard both.

---

## 5. Not in scope today

The following are **future**, ledgered post-launch capabilities — **PL-1, PL-2 and
PL-8**. They are named here only so that no reader mistakes them for present
behaviour:

- Anything that would remove the §2 ingress linkage.
- Anything that would make the submitter principal unobservable to a controller
  while a record is live.
- Any relayer, mixer, or third-party-submission path.

**None of these exist at launch.** If a page, a UI string, or a marketing claim
implies otherwise, that page is wrong and this one is the reference.

---

## 6. Summary table

The "sees amounts" column is split along §0.1's categories, because a single
column is what let this page contradict itself: **boundary** means category 1
(entry and exit figures), **in-pool** means category 3 (per-note values and change
splits).

| Observer | Sees your principal | Sees boundary amounts (cat. 1) | Sees in-pool note values (cat. 3) | Sees deposit↔spend link |
|---|---|---|---|---|
| Public-ledger observer | **Yes** — on deposit in / payout out | **Yes** — deposits are one of five ladder values; payouts exact | **No** — bounded by cat. 1, never reported | **No** (subject to timing/amount correlation) |
| Subnet node operator | **Yes** — every ingress, plaintext args | **Yes** | **Yes** — plaintext call arguments carry them | **Yes**, if it retains and correlates ingress |
| App/canister controller (the Vault) | **Yes**, while the record lives (≤7 days for the principal, ≤30 for the record) | **Yes** | **Yes**, for the operations whose records it can read, while they live | **Yes**, for operations in flight it adjudicates |
| Frontend / asset host | Origin + timing; **not** your notes | No | No | No |
