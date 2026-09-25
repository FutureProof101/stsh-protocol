# STSH — Public Solvency Signals page

Certificate-verified status page for the smoke-alarm solvency monitor
(`canisters/smoke-alarm-monitor`). Renders: token supply-invariant status, pool
holdings, last-updated, and a fail-closed health roll-up.

**Placement note:** the www.stsh.fi website does not live in this repo, so this
page is built as a self-contained Vite app here. When integrating into the real
website repo, move this directory (or embed `src/verify.ts` + `src/canister.ts`
and the page markup) — the data contract lives in
`canisters/smoke-alarm-monitor/CERTIFIED_SNAPSHOT_ENCODING.md` and must move
with it.

## Honest scope (copy rule from the brief)

This page is "Public Solvency Signals (Proof of Reserve)" — **never** "Proof of
Solvency". The pool-side `solvency_attestation()` HAS landed (lane R-4; see
`docs/SOLVENCY_ATTESTATION_SPEC.md`), so the page now proves supply integrity +
pool holdings + freshness **and** the pool's own certified backing delta — the
current copy is in `index.html` and says exactly that. The pre-attestation
instruction that used to sit here ("keep saying full solvency proof pending pool
attestation") is stale and has been removed; do not reinstate it. The page copy
is governed by `index.html`, not restated here.

## Fail-closed rendering

Green requires ALL of: certificate BLS-verifies against the root of trust →
witness root equals the certified data → leaf parses as the canonical snapshot
(`CANONICAL_LEN` in `src/verify.ts`; v2 widened it, and the length is stated
there rather than restated here) → status is Fresh → the supply invariant is
COMPUTED and holds (a `supplyInvariantUnavailable` reading is a different claim
from a violated one, and both forfeit green) → healthy flag consistent with its
own definition → the pool attestation source read is `Ok` → the pool backing
delta is healthy → not stale relative to the subnet-signed certificate `/time`.
Anything else renders red/unknown — never a stale green. This list is a
SUMMARY: the authoritative, exhaustive set is the `reasons.push(...)` arms of
`assess()` in `src/verify.ts` (pure, unit-tested), and that function is what to
read when the two disagree.

## Configuration

No hardcoded canister ids. Provide either URL params or env:

- `?monitor=<canister-id>` or `VITE_MONITOR_CANISTER_ID`
- `?host=<https://icp-api.io>` or `VITE_IC_HOST` (default `https://icp-api.io`)
- `?devroot=1` — dev builds only: fetch the local replica root key.

**Launch gate:** production must verify against the IC root key (the default —
no `fetchRootKey`) and fail closed. `devroot` is compiled out of prod builds
(`import.meta.env.DEV` guard).

## Commands

```bash
npm install
npm test          # vitest — canonical parsing + fail-closed derivation
npm run typecheck
npm run build
npm run dev       # http://localhost:5173/?monitor=<id>&host=http://127.0.0.1:8080&devroot=1
```
