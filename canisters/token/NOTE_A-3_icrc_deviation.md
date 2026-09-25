# NOTE A-3 — the STSH ledger's ICRC deviation register

**Where this lives, and why.** In the repo, beside the code (CTO ruling Q4,
R-1). A deviation register that lives in an office document drifts from the
ledger it describes; one that lives beside `lib.rs` moves in the same commit.

**What a row means.** The STSH token is a hand-rolled ICRC-1/ICRC-2 ledger. A
row here is a place where its behaviour KNOWINGLY differs from the ICRC spec or
from the reference ledger — not a bug, not a conformance gap awaiting a fix. A
conformance *defect* belongs in `QA_DEFECT_LEDGER.md`, never here.

**What binds a row.** Every entry names the test function(s) and file that make
its claim falsifiable. A row with no binding test is a claim, not a register
entry — and the `verify_icrc_deviation_register` gate lint enforces exactly two
directions:

1. every `devNNN` tag cited anywhere in `canisters/` or `integration-tests/`
   has an entry here, and
2. every entry's named test function actually exists in the file it names.

Renaming a bound test without updating this file is a gate RED. So is deleting
an entry whose tag is still cited in source. That is what makes this a register
rather than a document.

---

## dev001 — no minting account

**Spec point.** ICRC-1 `icrc1_minting_account`.
**Reference behaviour.** Returns the minter's account.
**STSH behaviour.** Returns `null`.
**Why.** STSH is a FIXED-supply ledger: the entire supply is minted once at
genesis by `init` and there is no minting authority afterwards. A non-null
minting account would advertise an authority that does not exist.

**Bound by:**
- `test_differential_r06_minting_account_dev001` —
  `integration-tests/tests/token_icrc_conformance_tests.rs`

---

## dev002 — a wider permitted clock drift

**Spec point.** `created_at_time` drift window for future-dated transactions.
**Reference behaviour.** 2 minutes; a transaction 3 minutes in the future is
`CreatedInFuture`.
**STSH behaviour.** 5 minutes (`PERMITTED_DRIFT_NS`); the same transaction is
accepted.
**Why.** Documented and PM-closed before A-3. The wider window accommodates the
wallet's own signing latency without pushing legitimate transactions into a
retry loop.

**Bound by:**
- `test_differential_drift_boundaries_dev002` —
  `integration-tests/tests/token_icrc_conformance_tests.rs`

---

## dev003 — `icrc1:logo` metadata

**Spec point.** ICRC-1 metadata key set.
**Reference behaviour.** No logo key.
**STSH behaviour.** Publishes `icrc1:logo` as a Text `data:image/png;base64,`
data URL built from the committed PNG asset (`canisters/token/assets/stsh-logo.png`,
256×256 8-bit grayscale, 2,908 B, sha256
`5642d58bb3b6db0dd5efa200c2a9d3dd2812d12339629350cd0cb362486cebbc`). The PNG is
rasterised deterministically from the committed SVG
(`canisters/token/assets/stsh-logo.svg`, kept for provenance) by the committed
stdlib-only script (`canisters/token/assets/rasterize_logo.py`, sha256
`b912fc928bcdd4c795bdaeced499d3656a50c66eddd6004d8b8079e394454e40`), run from the
repo root:
`python3 canisters/token/assets/rasterize_logo.py canisters/token/assets/stsh-logo.svg canisters/token/assets/stsh-logo.png 256`.
The committed PNG (not the script) is the build input. (TOKEN-METADATA lane,
2026-09-24: SVG data URLs are not rendered by some DEX/wallet list views; PNG
data URLs are the norm.)
**Why.** DEV-003, fixed forward: wallets that render a token need a logo, and
serving it from a committed asset keeps it in-repo and reviewable rather than
fetched at runtime.

**Bound by:**
- `test_icrc1_m09_logo_absent_dev003` —
  `integration-tests/tests/token_icrc_conformance_tests.rs`

---

## dev004 — zero-amount `icrc1_transfer` is refused

**Spec point.** ICRC-1 permits zero-amount transfers.
**Reference behaviour.** Accepts, charging the fee.
**STSH behaviour.** `GenericError { error_code = 5, message = ERR_MSG_ZERO_AMOUNT }`.
**Why.** R10-1. At `DEFAULT_FEE = 0` a zero-amount transfer is a completely free
no-op that still writes a dedup entry — an unpriced state-growth vector
spammable at ingress cost alone.

**Bound by:**
- `test_icrc1_e07_zero_amount_transfer_rejected_dev004` —
  `integration-tests/tests/token_icrc_conformance_tests.rs`

---

## dev005 — the zero-amount divergence, recorded differentially

**Spec point.** The same zero-amount question as dev004, asserted as a
DIVERGENCE against a live reference ledger rather than as a single-ledger
behaviour.
**Reference behaviour.** Still accepts a zero-amount transfer.
**STSH behaviour.** Refuses, with the pinned R10-1 error code.
**Why.** Registering divergences is the differential suite's whole purpose, so
BOTH outcomes are recorded and the divergence itself is asserted — a differential
test that only asserted the STSH side would go green if the reference ledger ever
changed underneath it.

**Bound by:**
- `test_differential_self_approve_and_zero_amount_outcomes_dev005` —
  `integration-tests/tests/token_icrc_conformance_tests.rs`

---

## dev006 — zero-amount `icrc2_approve` is refused UNLESS it revokes

**Spec point.** ICRC-2 permits `icrc2_approve` with `amount = 0`
unconditionally.

**Reference behaviour.** Accepts a zero approve in every case, including when
there is no allowance to clear.

**STSH behaviour.** Refuses `amount == 0` with
`ApproveError::GenericError { error_code = 5, message = ERR_MSG_ZERO_AMOUNT }`
**only when no LIVE allowance exists** for `(from_account, spender)`. A zero
approve against a live allowance is REVOCATION and succeeds, clearing it.

"Live" follows `icrc2_allowance`'s own INCLUSIVE expiry boundary
(`time() >= expires_at` is expired), so a zero approve against an already-expired
allowance is refused: there is nothing left to revoke.

**Why the guard is NARROW rather than shaped like dev004's.** The wallet revokes
with `approve(0)` — `wallet/src/ui/shieldFlow.ts`, `revokeShieldAllowance`,
`amount: 0n` with `expectedAllowance: current.allowance`. A blanket
`amount == 0` refusal, matching `icrc1_transfer`'s, would break revocation
outright, which is a strictly worse outcome than the state-growth vector the
guard exists to close. R-1 §3 S1; CTO-ruled.

**What it closes.** At `DEFAULT_FEE = 0`, an unauthenticated-cost zero approve
against a spender with no allowance writes an `ALLOWANCES` row (and, with
`created_at_time`, a dedup row) for free — the ICRC-2 sibling of dev004's
`icrc1_transfer` vector.

**Bound by three separately named tests** — the refusal, the reference side, and
revocation, so that no single edit can make the row vacuous:
- `test_icrc2_dev006_stsh_refuses_zero_approve_without_live_allowance` —
  `integration-tests/tests/token_icrc_conformance_tests.rs`
- `test_icrc2_dev006_reference_accepts_zero_approve` —
  `integration-tests/tests/token_icrc_conformance_tests.rs`
- `test_icrc2_dev006_stsh_revokes_live_allowance_with_zero_approve` —
  `integration-tests/tests/token_icrc_conformance_tests.rs`

---

## dev007 — `expires_at` on `icrc2_approve` is DEFAULTED and CAPPED

**Spec point.** ICRC-2 declares `expires_at : opt nat64` on `ApproveArgs`. An
approval with no expiry is permitted and is the spec's default shape; the spec
places no upper bound on a supplied expiry either.

**Reference behaviour.** Accepts an approve with `expires_at = null` and stores a
never-expiring allowance. Accepts any future `expires_at`, however distant.

**STSH behaviour (TOKEN-APPROVE-TTL, 2026-09-25).** Every allowance an approve
writes is stored with an end no later than `now + MAX_APPROVAL_TTL_NS` (24 hours):

- `expires_at = null` → ACCEPTED and stored with `expires_at = now +
  MAX_APPROVAL_TTL_NS`; `icrc2_allowance` reports that value where the reference
  ledger would report `null`
- `expires_at - now > MAX_APPROVAL_TTL_NS` → ACCEPTED and CLAMPED: stored (and
  reported) as `now + MAX_APPROVAL_TTL_NS`
- `now < expires_at <= now + MAX_APPROVAL_TTL_NS` → stored as given; a lifetime of
  exactly `MAX_APPROVAL_TTL_NS` is stored as given — the boundary belongs to the
  allowed side
- `expires_at <= now` is unchanged: still `ApproveError::Expired { ledger_time }`
  (F-006)

The residual deviation is therefore narrower than it was: STSH accepts every call
shape the spec permits, but an allowance never outlives 24 hours, and a client
that sent no expiry reads one back.

**History.** HARDEN-02 (2026-09-17) shipped this row as a REFUSAL: `expires_at =
null` → `GenericError { error_code = 7 }` and over-cap → `GenericError {
error_code = 8 }`, with a zero-amount (revoking) approve exempted from the
absent-expiry refusal. Every standard ICRC-2 client — DEX front ends (ICPSwap's
approve step failed on it on 2026-09-25), wallets — approves without an expiry,
so the refusal made STSH unsellable and un-LP-able from a standard UI. Storing
with the cap applied meets H-01's reason for the refusal equally well: the stored
row always has an end. Codes 7 and 8 are RETIRED and never reused
(`dev007_error_codes_pinned`). The revoke exemption is moot — there is no refusal
left for it to sit in front of — and dev006's refusal stays reachable by
construction. `approve_dedup_key` hashes the CALLER-SENT `expires_at`, never the
effective one, so a byte-identical retry of an expiry-less approve is still a
`Duplicate` (F-004).

**What it closes (H-01).** `ALLOWANCES` grew monotonically and without bound. No
path removed a row — revoke overwrote with `amount: 0`, a drain wrote the reduced
record back, and expiry was read-side only — while `icrc2_approve` admitted a new
row from a zero-balance caller at `DEFAULT_FEE = 0` for ingress cost alone. Both
halves of the row key are caller-supplied (the approver's subaccount and the whole
spender account) and IC principals are free to generate, so nothing in this
canister limited how many distinct rows one attacker could write. The
reclamation side of the fix depends on this admission rule: an approval with no
stated end is never expired, never drained and never revoked, so no reclamation
trigger can reach it — so every stored row must carry one, which the default and
the clamp guarantee. `expires_at` stays `Option<u64>` in the stored
`AllowanceRecord` — the format is untouched (G-A2); only the write rule moved.

**What it does NOT close, stated rather than implied.** Bounding the resident set
is not the same as making the attack expensive. An attacker still makes the
canister carry a lifetime's worth of rows and pay to prune them; this makes that
recoverable and survivable, not free. Only a nonzero approve fee would move the
cost onto the attacker, and that is barred without a fee-model ruling (ARCHITECTURE.md
law 5). 24 h is a ruled candidate lifetime (D-2, 2026-09-17), not a demonstrated
resource-safety bound; the lever if the measured envelope is judged too large is
this TTL, tightened — never a global cap on the number of rows, which an attacker
can fill to lock out honest approvals.

**Compatibility with the shipped wallet, verified rather than assumed.** Both
approve paths set `expires_at` unconditionally —
`wallet/src/actors/token.ts` (`approvalExpiresAt(req.createdAtTime)`, applied to
every approve including the revoke issued by `revokeShieldAllowance`) and
`wallet/src/wallet/oisy.ts` — at `APPROVAL_TTL_NS` = 15 minutes, which is 1/96 of
the cap.

**Bound by five separately named tests** — the absent-expiry default, the
over-cap clamp, the exact boundaries, the retired-code pin, and the shipped
wallet's own call shape, so that no single edit can make the row vacuous:
- `test_aa2_dev007_absent_expiry_is_stored_with_the_cap` —
  `integration-tests/tests/token_allowance_lifetime_tests.rs`
- `aa2_approve_clamps_an_over_cap_expiry` —
  `integration-tests/tests/token_allowance_lifetime_tests.rs`
- `approval_lifetime_boundaries_are_exact` — `canisters/token/src/lib.rs`
- `dev007_error_codes_pinned` — `canisters/token/src/lib.rs`
- `test_aa2_dev007_accepts_the_shipped_wallet_shape` —
  `integration-tests/tests/token_allowance_lifetime_tests.rs`
