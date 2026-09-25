# SPEC — pool `get_solvency_attestation()` (smoke-alarm completion, D-2 + D-4)

**Status: AS BUILT.** The freeze paragraph that stood here ("SPEC ONLY. Do NOT
implement while review is pending") is **VOID** per the
D-2+D-4 ruling §5 and is struck. This is the §4 deferred delta from
`BRIEF_SMOKE_ALARM_MONITOR.md` (2026-07-10), now implemented under brief V3
(`5cd256c8…`) with SSA GREEN (`84bdff2d…`). It touches the core
`shielded-pool` canister, so it landed as an explicit, minimal, ADDITIVE change:
one new query, one hook on the existing accounting funnel, and nothing else.
Never a silent edit.

## Why

The now-phase smoke alarm proves **supply integrity + pool holdings +
freshness** from public token data. The *full* smoke alarm proves the core
solvency invariant

```
raw_delta = escrow_backing + pending_fee_reimbursements − private_liability
healthy   = raw_delta >= 0
```

Computed in **i128 with checked arithmetic**, never a wrapping or trapping
operation: this is reachable from a query, and a trapping query would deny the
very signal the alarm exists to publish. On any overflow — or a balance too large
to represent — the attestation reports `healthy = false` and the distinguished
value `i128::MIN` (fail closed). Verified against the pool's operative invariant
(1) as stated at `canisters/shielded-pool/src/lib.rs` and enforced by
`check_accounting_invariants`.

**This supersedes the old `escrow_backing == private_liability` (delta == 0)
form**, which was never the shipped rule: under invariant (1) a healthy delta is
`>= 0`, and it equals the reimbursement float in flight rather than zero.

which only the pool knows. **The operative form is invariant (1), not equality**
— see the pinned formula below. The pool's internal solvency figure
(`private_liability` / the I-02A delta) is controller-gated today (Pass 11
privacy, DEF-076) — reading it out requires this deliberate, privacy-vetted
endpoint.

## Interface (additive, read-only)

One **certified query** on the shielded pool:

```candid
type SolvencyAttestation = record {
    // min(raw_delta, 0), in e8s. ZERO in EVERY healthy state; a negative
    // violation magnitude when backing is broken; i128::MIN when the invariant
    // could not be soundly evaluated (fail closed).
    public_delta_e8s : int;
    // raw_delta >= 0, computed on the RAW value — the clamp narrows what is
    // published, it never weakens the solvency judgement.
    healthy          : bool;
    // Floored to a 300 s bucket. Never an exact mutation time.
    attested_at_ns   : nat64;
    schema_version   : nat32;
};

type CertifiedSolvencyAttestation = record {
    attestation     : SolvencyAttestation;
    canonical_bytes : blob;      // the exact 53-byte committed leaf
    certificate     : opt blob;  // null in replicated context — unverifiable
    witness         : blob;      // self-describing CBOR hash tree
};

get_solvency_attestation : () -> (CertifiedSolvencyAttestation) query;
```

**PUBLIC and ungated**, unlike `get_accounting_state` (controller-only, DEF-076).
The clamp is precisely what makes this publishable where raw buckets are not.

## Privacy constraints (load-bearing)

- Expose the **delta only** — NEVER the raw per-bucket balances
  (`escrow_backing`, `private_liability`, reserves) — Pass 11 / DEF-076: live
  per-bucket figures are an activity-timing oracle.
- **THE CLAMP IS LOAD-BEARING.** The published value is `min(raw_delta, 0)`, so
  **every** healthy state publishes exactly `0` — indistinguishably. Without the
  clamp a healthy delta equals `pending_fee_reimbursements`, and differencing it
  across time would reduce the public field to that private bucket: an
  activity-timing oracle. The earlier claim that "the delta is 0 in the healthy
  case" was **false for the shipped `>=` rule** and is withdrawn; the clamp is
  what now makes it true.
- **In a violation state the magnitude and prompt timing ARE disclosed.** An
  insolvency is exactly what the public must see. The oracle concern applies to
  healthy operation only.
- **`attested_at_ns` is quantized to a 300 s bucket** (floored to the boundary)
  before encoding — not conditionally, not "if review finds a side-channel". An
  exact mutation time is itself activity telemetry.
- **Root movement is confined to public-payload change.** A healthy-float
  mutation inside a bucket leaves the payload and the certified root
  byte-identical. The root moves only when (a) the health boundary is crossed,
  (b) the negative magnitude changes, or (c) the timestamp bucket rolls.

## Canonical encoding — AS BUILT (53 bytes)

Same discipline as the monitor (`canisters/smoke-alarm-monitor/CERTIFIED_SNAPSHOT_ENCODING.md`):
domain tag `stsh-pool-attestation-v1`, fixed-width big-endian fields, documented
offsets, fail-closed parsing. The layout is no longer "fixed at impl time" — it
is fixed here:

| Offset   | Size | Field | Notes |
|----------|------|-------|-------|
| 0..24    | 24   | domain tag | ASCII `stsh-pool-attestation-v1` |
| 24..28   | 4    | `schema_version` (u32) | currently `1` |
| 28       | 1    | `flags` (u8) | bit0 `healthy` · bits 1–7 reserved, MUST be zero |
| 29..45   | 16   | `public_delta_e8s` (i128) | two's complement · `<= 0` always |
| 45..53   | 8    | `attested_at_ns` (u64) | floored to the 300 s bucket |

The signed value is encoded in the **same representation the Candid field
carries**, so the certified bytes and the display record cannot disagree about
sign. A separate "magnitude" field would have introduced exactly that divergence.

Certified tree: a single-entry `ic-certified-map` RbTree,
`"solvency_attestation"` → these bytes, with `set_certified_data(root)`.
Verifiers MUST parse the **witness-verified leaf bytes**, never the bare Candid
record. A future second pool surface gains a sibling key; that is a future lane.

Parsers MUST reject: wrong length, wrong tag, unknown `schema_version`, any
reserved flag bit set, or a `public_delta_e8s > 0`. A parse failure renders as
red/unknown — never a permissive default.

## Certification design — AS BUILT (hybrid)

Not "timer or piggyback, decided at impl time". **Both, with different jobs:**

- **Uniform heartbeat, 300 s.** Re-encodes and re-certifies the current bucketed
  payload. Its cadence is **activity-independent**, which is the point: a pure
  piggyback plus a clamped payload would let a quiet pool drift into reader-side
  staleness, and a cadence that tracked activity would republish the very signal
  the clamp removes.
- **Accounting piggyback, narrower.** Hooks `commit_pool_accounting` — the single
  funnel through which all six accounting scalars change, guarded by the AST
  writer-set locks `r13_accounting_cell_writer_set_is_the_funnel_only` and
  `fu1_2_known_bypass_census`, so coverage is structural rather than an
  enumeration of call sites. It publishes **only** when the health bit or the
  magnitude changes, so an insolvency is certified promptly instead of waiting up
  to one heartbeat. **It never advances a healthy timestamp on a bucket roll** —
  only the heartbeat does that.
- **`init` and `post_upgrade` re-certify.** Certified data and timers do not
  survive an upgrade; omitting either would leave a live pool publishing a root
  it can no longer refresh.

**Arming, not `cfg`.** The piggyback sits on a path native unit tests also reach,
and `time()`/`set_certified_data` are ic0 imports. The obvious guard,
`#[cfg(target_arch = "wasm32")]`, is unusable: `verify_amount_boundaries` resolves
only `test`, `feature`, `all`, `any`, `not`, and aborts the whole census on
anything else. Certification is therefore armed at runtime by `init`/`post_upgrade`
and inert until armed. Consequence for evidence: an unarmed host run proves
nothing about a certified root, so **every certification claim is proven in
PocketIC, never natively.**

## Amount-boundary enrolment

`public_delta_e8s` is a reviewed raw-amount boundary, enrolled in
`scripts/amount_boundary_allowlist.toml` by CTO adjudication
(`8823976846b3…`, SSA GREEN `aa9bb3016d41…`) under C4 §4 rule 2. Bytes-only
encodings that would remove the amount from census view were **rejected
permanently** (CTO disposition `04c3892f…`).

## Monitor + website integration — LANDED (D-2/D-4, 2026-08-26: monitor `pool_attestation_source` / `pool_delta_healthy`, website `solvency-status` v2 copy)

1. Monitor init gains an optional `pool_attestation_source` — or ships as a
   monitor v2 (new canister) if the v1 monitor is already blackholed.
2. Monitor timer additionally reads `get_solvency_attestation`, folds
   `delta_healthy` into the certified snapshot (schema_version bump per the
   encoding doc).
3. Website upgrades copy from "supply + holdings, full solvency proof pending
   pool attestation" → "full solvency delta proven".

## Review requirements (recorded at spec time; the accounting-identity and `SolvencyBlocked` items are satisfied by the shipped query — the external-reviewer sign-off item is tracked in the CTO record, not here)

- Reviewer sign-off on the pool change as an explicit
  additive re-review item.
- Confirm against the canonical accounting identity (Task #214, 2026-07-01):
  `escrow_backing + operations_reserve + insurance_reserve +
  governance_rewards_reserve == pool_ledger_balance`; `private_liability` is
  the liability side; `pending_fee_reimbursements` counts in solvency only.
- Confirm interaction with `SolvencyBlocked` withdrawal states (nullifier
  reservation semantics, ARCHITECTURE.md Law #2) — the attestation must be readable
  even while a withdrawal is solvency-blocked.
