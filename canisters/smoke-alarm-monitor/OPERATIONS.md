# Smoke Alarm monitor — operations: deploy, blackhole, cycles

Standalone solvency monitor (`smoke_alarm_monitor`). Reads ONLY public token
data; zero changes to the other backend canisters.
Data contract:
`CERTIFIED_SNAPSHOT_ENCODING.md`.

## Deploy

Target canister ids are **init args, never hardcoded**:

```bash
dfx deploy smoke_alarm_monitor --argument '(record {
  token_canister      = principal "<TOKEN_CANISTER_ID>";
  pool_principal      = principal "<POOL_CANISTER_ID>";
  refresh_interval_ns = 300_000_000_000 : nat64;   // 5 min
  max_staleness_ns    = 900_000_000_000 : nat64;   // 15 min (>= interval, enforced)
  history_capacity    = 288 : nat32;               // 24h @ 5-min cadence
})'
```

Init validation traps on: anonymous/management principals, interval < 1 s,
`max_staleness_ns < refresh_interval_ns`, capacity outside 1..=4096. **These are
permanent once blackholed — triple-check the ids.**

The config is immutable: there are no setter/admin methods. The only update
method is the anyone-callable, rate-limited (60 s) `request_refresh` liveness
valve.

## Blackhole — LAUNCH GATE ONLY, not during build/test

Blackholing (removing all controllers) makes the canister immutable so the
community can trust it isn't quietly changed. A blackholed canister **can still
be topped up by anyone** — `deposit_cycles` needs no controller rights.

Do NOT blackhole until ALL of:

1. Production token + pool canister ids final and baked into init config.
2. Monitor Wasm hash recorded (`dfx canister --network ic info smoke_alarm_monitor`
   vs `sha256sum target/wasm32-unknown-unknown/release/smoke_alarm_monitor.wasm`).
3. Certified-query validation tested from the live site (real IC root of
   trust, NOT `fetchRootKey` — see `website/solvency-status/README.md`).
4. Cycle top-up path tested (send cycles from a wallet to the canister id).
5. Burn rate measured on mainnet + runway funded (below).
6. **Owner explicitly approves immutability.**

Then:

```bash
dfx canister --network ic update-settings smoke_alarm_monitor --set-controller aaaaa-aa
# or: --remove-controller <each>   (verify with: dfx canister --network ic info)
```

(Setting the management canister `aaaaa-aa` as sole controller is the
conventional blackhole; verify the controller list is empty/inert afterwards.)

## Cycles: burn rate + runway + top-up

Cost drivers per refresh cycle: 2 inter-canister query-as-update calls to the
token + timer bookkeeping + certified-data update; plus baseline idle burn
(compute/storage reservation, small — the canister stores at most
`history_capacity` × ~200 B).

**Subnet pricing anchor (34 nodes, not 13).** The monitor is deployed to subnet
`pzp6e-…-yae`, which is a **34-node** application subnet, not the 13-node default
these figures were originally derived against. IC application-subnet pricing scales
with the node count, so every 13-node figure below is multiplied by
**×≈2.6** (34 ÷ 13 = 2.615). Source of the node count: CTO handoff 2026-09-13 item 2
and SSoT V9 §1 row **D9-4** (proposal #10 was rejected "out of cycles" precisely because
2T was a 13-node-sized creation budget). Every multiplier reference further down in this
file points back to this paragraph — it is stated once, on purpose.

Rules of thumb (34-node app subnet `pzp6e`, 2026 prices — re-measure at launch).
Each row shows `13-node value → ×≈2.6 → 34-node value` so the arithmetic is auditable:

- Inter-canister call ≈ 2.6 M cycles fixed (13-node) → **≈ 6.8 M cycles** at 34 nodes + payload bytes ≈ negligible here
- A refresh: ≈ 6–10 M cycles (13-node) → **≈ 16–26 M cycles** at 34 nodes, including
  execution.
- At 5-min cadence: ~288 refreshes/day ≈ 2–3 B cycles/day (13-node) →
  **≈ 5–8 B cycles/day** at 34 nodes ≈ 0.7–1 T cycles/year (13-node) →
  **≈ 2–3 T cycles/year** at 34 nodes, idle/storage included at this cadence.
  The old line "well under 1 T/year" is **13-node-only and no longer true** — budget
  2–3 T/year.

**Funding guidance:** deposit **20 T cycles** at launch. Against the corrected
34-node burn of ≈2–3 T/year that is a **≈7–10 year runway** (20 ÷ 3 = 6.7,
20 ÷ 2 = 10) — not the looser "multi-year" the 13-node figure justified, and not a
number to re-derive from memory. At ~15 USD-equivalent per 10 T (1 XDR/T) that is
≈30 USD-equivalent — still cheap insurance for a trust anchor. Measure the real burn
over the first week via the `get_health_status().cycles_balance` field (public),
document the observed rate here, and top up to a **≥ 5-year runway** before
blackholing. The ≥5-year rule is a **policy and does not change** with subnet
pricing; the deposit that satisfies it does — at 34-node prices ≥5 years is
**≥ 10–15 T**, where at 13-node prices it was ≥ 3.5–5 T.

**Monitoring the monitor:** `get_health_status` exposes `cycles_balance`, so
the status page (or anyone) can watch the runway. If it trends low, anyone can
top up. The 5 T below is a **worked example of the command**, not a derived
quantity: at the corrected 34-node burn 5 T buys roughly **1.5–2.5 years**, not the
"a comfortable year and then some" a 13-node reading would suggest. Size the real
top-up from the ≥5-year policy above (≥ 10–15 T), not from this literal.

```bash
dfx canister --network ic deposit-cycles 5000000000000 <MONITOR_CANISTER_ID>
```

**Freezing threshold note:** if the canister is frozen (out of cycles), timers
stop and certified reads fail → the status page shows red/unknown (fail
closed), never a stale green. Topping up un-freezes it; the next timer tick
resumes refreshes; `request_refresh` can kick it immediately.

## Upgrade policy

Pre-blackhole only. `pre/post_upgrade` persist config + snapshot + history and
re-establish certified data and timers (tested:
`test_sam_05_upgrade_preserves_state_recertifies_and_restarts_timer`). After
blackhole there are no upgrades — fixes mean deploying a NEW monitor canister
and repointing the website (the old one keeps running harmlessly).
