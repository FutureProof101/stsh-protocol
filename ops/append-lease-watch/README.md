# append-lease-watch

Off-chain watcher for the shielded pool's pool-wide append lease
(P-ROOT / C-ROOT-1). See `canisters/shielded-pool/APPEND_LEASE_RUNBOOK.md`
for the authorized resolution procedures — this tool **detects and alerts
only**; it never mutates canister state, and no force-release exists.

## Why it exists

A transport-unknown Merkle append retains the lease until an operator
reconciles it, and while the lease is held **every** pool append (deposits and
spend promotions) is turned away. The lease never times out on-chain, so an
undetected stuck lease is a silent pool-wide append stoppage. This watcher
makes that condition loud.

## What it polls

The **controller-gated** `get_append_lease_owner` query (owner, phase,
generation, `acquired_at_ns`, `phase_started_at_ns`). The public
`get_append_lease_status` getter intentionally exposes only
`{held, phase, age_bucket}` (privacy ruling) and is not sufficient for
operational thresholds — run the watcher under the operator (controller)
dfx identity.

## Run

```bash
POOL_CANISTER_ID=<pool-canister-id> \
NETWORK=ic \
IDENTITY=operator \
./watch.sh
```

Requirements: `dfx` (the deploy toolchain version), `jq`, `curl` (only if
`WEBHOOK_URL` is set). `jq` is checked at startup in every mode; `dfx` only in
watch mode.

### Self-test

```bash
./watch.sh --self-test
```

Runs the reply parser offline against representative candid-JSON replies
(free `[null]`, a held `AppendUnknown` lease, and garbage) — no dfx, no network.
It also spot-checks the per-phase threshold table, but only TWO of its cases:
`AppendUnknown` and the unknown-phase fallback. The other four phases
(`Snapshotting`, `AppendInFlight`, `ReconcileInFlight`,
`AppendConfirmedRootPending`) are NOT exercised, so a wrong default on one of
them passes the self-test. Exit 0 = the parser behaves and those two threshold
cases hold; run it after any dfx upgrade to catch `--output json` rendering
drift.

## Thresholds

Per-phase, in seconds (see the runbook §3 for rationale):

| env var | default | phase |
|---|---|---|
| `THRESH_SNAPSHOTTING` | 300 | `Snapshotting` |
| `THRESH_APPEND_IN_FLIGHT` | 300 | `AppendInFlight` |
| `THRESH_RECONCILE_IN_FLIGHT` | 300 | `ReconcileInFlight` |
| `THRESH_APPEND_UNKNOWN` | 900 | `AppendUnknown` |
| `THRESH_ROOT_PENDING` | 900 | `AppendConfirmedRootPending` |

An unknown phase value alerts immediately (threshold 0) — the enum is closed,
so an unrecognized phase means a decoder/toolchain mismatch worth a page.

`INTERVAL` (default 60s) is the poll period; `WEBHOOK_URL`, if set, receives a
JSON `{"text": ...}` POST per alert (Slack-compatible). Alert lines on stdout
are prefixed `ALERT` for supervisor-level grepping; healthy polls print `ok`.

## What it never does

- No retries of pool operations, no reconcile calls, no upgrades.
- No force-release: there is no endpoint that clears the lease, by design.
  Resolution is a human following the runbook, tuple by tuple.
