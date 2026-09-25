# Smoke Alarm — certified snapshot canonical encoding (v2)

This is the **data contract** between the monitor canister
(`canisters/smoke-alarm-monitor/src/lib.rs`), the status-page frontend
(`website/solvency-status/src/verify.ts`), and the integration tests
(`integration-tests/tests/smoke_alarm_monitor_tests.rs`). The three artifacts
must change **together, in the same change** — never one at a time (same
discipline as ARCHITECTURE.md Law #6).

## Certified tree

A single-entry `ic-certified-map` RbTree:

```
"solvency_snapshot"  →  canonical snapshot bytes (131 bytes, below)
```

`set_certified_data(root_hash)` is called after **every** snapshot commit
(timer refresh, init placeholder, post_upgrade re-certification). Certified
queries return `{ snapshot, canonical_bytes, certificate, witness }` where
`witness` is the self-describing-CBOR hash tree for the key.

Verifiers MUST parse the **witness-verified leaf bytes**, not the bare Candid
`snapshot` field — the Candid field is display convenience only.

## Canonical bytes — layout (total 131 bytes, schema_version 3)

**v3 (R-4)** adds ONE flag bit — bit 4 `supply_invariant_unavailable` — and
moves nothing else: no new field bytes, unchanged length, unchanged domain tag.
It exists because a v2 leaf cannot distinguish "the ledger computed the supply
invariant and it does not hold" (VIOLATED) from "the ledger could not compute it
at all" (UNAVAILABLE); both rendered as VIOLATED, which is a different and false
claim about the ledger.

It is a schema BUMP rather than a free bit because a v2 parser rejects any of
bits 4–7 set, by design. That rejection is exactly why the rollout is
**page-first**: the dual-accepting page must be live and serving before the
monitor is switched to emit schema 3, or every reader gets a parse failure. The
four-row deploy-state table is in `MAINNET_DEPLOYMENT.md` under
`## Solvency surface: schema-3 transition (R-4)`.

The page DUAL-ACCEPTS schema 2 and 3, each under its own reserved mask (v2:
bits 4–7 reserved; v3: bits 5–7 reserved), and rejects schema 4+ unconditionally.
A schema-2 leaf yields `supply_invariant_unavailable = false` — not "unknown":
at that schema the field does not exist and is not reportable.

**v2 (D-2 + D-4)** appends a tail and leaves every v1 offset unmoved. The
domain tag is UNCHANGED: this document reserves a tag change for an
incompatible redesign, and an append under a bumped `schema_version` is not
one. A v2 parser still rejects v1 bytes on **both** length and
`schema_version`, so nothing older can be misread as current.

All integers big-endian, fixed width. Domain-separated by a leading tag so the
committed bytes can never be confused with another STSH structure.

| Offset  | Size | Field                    | Notes |
|---------|------|--------------------------|-------|
| 0..19   | 19   | domain tag               | ASCII `stsh-smoke-alarm-v1` |
| 19..23  | 4    | `schema_version` (u32)   | currently `3` |
| 23      | 1    | `status` (u8)            | 0 Fresh · 1 Stale · 2 RefreshFailed · 3 SourceCallFailed |
| 24      | 1    | `flags` (u8)             | bit0 `supply_invariant_holds` · bit1 `healthy` · bit2 `pool_delta_healthy` · bit3 stray present · **v3** bit4 `supply_invariant_unavailable` · bits 5–7 MUST be zero |
| 25..41  | 16   | `fixed_max_supply_e8s` (u128)  | |
| 41..57  | 16   | `sum_all_balances_e8s` (u128)  | |
| 57..73  | 16   | `pool_balance_e8s` (u128)      | `icrc1_balance_of(pool_principal)` |
| 73..81  | 8    | `refreshed_at_ns` (u64)  | canister `time()` at serial sample start (conservative lower bound) |
| 81..89  | 8    | `max_staleness_ns` (u64) | from the immutable init config |
| 89      | 1    | `pool_attestation_source_status` (u8) | **v2** · 0 Ok · 1 CallFailed · 2 Malformed · 3 Stale |
| 90      | 1    | `treasury_read_status` (u8) | **v2** · same encoding, `Stale` unused |
| 91..107 | 16   | `pool_public_delta_e8s` (i128) | **v2** · two's complement · `<= 0` always · `0` in every healthy state |
| 107..115| 8    | `pool_attested_at_ns` (u64) | **v2** · the POOL's timestamp, floored to a 300 s bucket |
| 115..131| 16   | `treasury_stray_funds_e8s` (u128) | **v2** · YELLOW only — never part of `healthy` |

`flags` (offset 24) gains two v2 bits and one v3 bit:

| Bit | Meaning |
|-----|---------|
| 0   | `supply_invariant_holds` |
| 1   | `healthy` |
| 2   | **v2** `pool_delta_healthy` — the pool's own verdict on its backing |
| 3   | **v2** stray funds present (`treasury_stray_funds_e8s > 0`). A PRESENCE bit; the magnitude is its own field |
| 4   | **v3** `supply_invariant_unavailable` — set **iff** the token's report carried `arithmetic_error = Some(_)`. NEVER derived from `!supply_invariant_holds`, which is also true for an ordinary violation. Does not change `healthy`: both states were, and remain, unhealthy |
| 5–7 | reserved, MUST be zero |

### The pool attestation leaf (read, not written, by this canister)

The pool commits its own single-leaf tree under key `solvency_attestation`,
53 bytes, domain tag `stsh-pool-attestation-v1` — layout in
`docs/SOLVENCY_ATTESTATION_SPEC.md`. The monitor re-encodes that layout from the
record the pool returns and refuses the attestation as `Malformed` if the two
disagree; the certificate itself is verified by the **website**, end to end.

### Staleness of the pool attestation

Because the pool floors its timestamp, a just-issued attestation can already
look up to (but strictly less than) one 300 s bucket old. The reader threshold
is therefore

```
observed_age > max_staleness_ns + 300_000_000_000
```

with **checked** addition: on overflow the result is `stale = true`
(RED/unknown), never a wrapped, permissive tolerance. The cost of the widening
is that stale detection is delayed by at most one bucket.

## Canonical bytes — v1 layout (offsets retained by v2)

Parsers MUST reject: wrong length, wrong tag, unknown `schema_version`,
status byte > 3, or any reserved flag bit set. A parse failure renders as
red/unknown — never a permissive default.

## Fail-closed semantics

- `healthy` (bit1) is true **only** when `status == Fresh` AND both source
  calls succeeded AND the token supply invariant holds.
- A certified `Stale` status cannot be written by a dead timer, so staleness is
  the **reader's** check: red/unknown when
  `certificate /time − refreshed_at_ns > max_staleness_ns`. Both inputs are
  tamper-evident (the leaf is witness-verified; `/time` is subnet-signed).
- On a failed refresh the numeric fields carry the last successful figures
  (dashboard continuity); `status != Fresh` means "figures are from the last
  successful refresh". Status/healthy are authoritative, not the figures.

## Certifying from a path native tests reach (learned the hard way, 2026-08-26)

The pool piggybacks its attestation on `commit_pool_accounting`, the single
accounting funnel — which native unit tests also call. `time()` and
`set_certified_data` are ic0 imports that do not exist off-canister, so that hook
needs a guard.

**`#[cfg(target_arch = "wasm32")]` is NOT available in any census-scanned
canister.** `scripts/verify_did_exports`'s `verify_amount_boundaries` resolves
only `test`, `feature = "..."`, `all`, `any` and `not`; anything else aborts the
entire run — deliberately, so no endpoint can leave the census behind a predicate
the tool cannot evaluate. Measured, not assumed:

```
amount-boundary census could not complete: unrecognised cfg predicate `target_arch = "wasm32"`
```

The working pattern is **runtime arming**: `init` and `post_upgrade` — the only
paths that run exclusively on-canister — set an armed flag and certify; the
mutation piggyback is inert until armed. A host build therefore never reaches an
ic0 import, and no `cfg` is involved. It is also the honest reading: a canister
that has not been installed has no state to certify.

Corollary for evidence: an unarmed host run proves nothing about a certified
root, so every certification claim is proven in PocketIC, never natively.

## Versioning

Any layout change bumps `schema_version`, updates all three artifacts in the
same change, and updates this document. The domain tag changes only on
incompatible redesigns (`…-v2`).
