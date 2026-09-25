# Cycle monitor — operations: the C-26 derive-budget rules

Off-chain fleet monitor (`scripts/cycle_monitor`). It watches two things: the
cycle balance of every canister in the compiled-in register, and — since the
C-26 remedy — the **fleet-wide derive budget** on `vetkeys`.

Contract: A1 fix brief V5 (`911ef839…`), SSA GREEN (`ac5ecf18…`).

---

## §0. The one thing to internalise before reading further

**Raising the budget during an attack funds the attacker.**

The derive budget exists because `vetkd_derive_key` attaches ~26 B cycles per
call. An attacker who is being refused is costing you nothing. An attacker who
is being *served* is costing you ~26 B cycles a time. The instinct when a
capacity alert fires is to top up and raise the ceiling; that instinct is
exactly backwards when the load is adversarial.

**Sitting out is SAFE.** The failure mode of a spent budget is that new device
setups wait. Nothing is minted, nothing is spent, no key leaks, and existing
devices keep working throughout. There is no state that degrades while you take
an hour to decide.

**Do not reflexively top up.** Topping up is a deliberate, cost-capped, logged
decision (§3), never a reflex and never automatic.

---

## §1. What the monitor reports

`derive_budget_stats` is read once per run and evaluated as four rules plus a
floor limb, in the same report section, over the same query. Exit codes are
unchanged: `0` OK, `1` ALERT, `2` INCOMPLETE.

| Rule | Fires when | What it means |
|---|---|---|
| **Saturation** | the fleet has been at or over its budget continuously for `SATURATION_MIN_ELAPSED_NS` | demand is exceeding the on-ramp, sustained |
| **Concentration** | ≥ `CONCENTRATION_MIN_SAMPLE` tagged dispatches AND the mean per principal is ≥ `CONCENTRATION_MULTIPLE` | a few principals are taking many derives — organic traffic is ~1.00 each |
| **Refusal spike** | ≥ `REFUSAL_SPIKE_PER_HOUR` budget refusals in the rolling hour | offered load is above the ratified ceiling |
| **Funding wave** | ≥ `FUNDING_WAVE_PER_HOUR` new age-in periods in the rolling hour | **leading indicator** — see §2 |

Plus the floor limb: `Live { admits: false }` and
`FloorOnly { meets_pinned_floor: false }` are ALERTS (the canister is at or
below its cycle floor); `FloorOnly { meets_pinned_floor: true }` and
`Unavailable` are INCOMPLETE — the admission question was not answered, and
"could not tell" is never "fine".

**INCOMPLETE is not a soft OK.** A partial history, an epoch change, an unwired
or unreachable query all report INCOMPLETE. The monitor never extrapolates a
partial window into an hourly rate, and it never differences a counter across an
upgrade — the counters are ephemeral heap, and a reset is not a rate.

---

## §2. The funding wave — read this one differently

The held-balance-age gate means a principal's first derive is refused until its
balance has been held for T. So **the sighting happens T before the derive**.

That makes the funding wave a **leading indicator**: N principals beginning to
age in now predicts up to N first-derives one age-window from now. You get
warning before the wave arrives, which is the entire operational value of the
gate.

**Triage, in order:**

1. **Is there a known growth event?** A launch, a listing, a campaign, a press
   cycle. If yes, this is organic: route to the graduation artifact
   (`RATIFICATION_GLOBAL_DERIVE_BUDGET_50_GRADUATION_AWAITING_OWNER`,
   `225a5059…`) — which is **UNSIGNED and awaiting Owner**. It is the route, not
   the authority: raising the budget is a ratification, not an operator action.
2. **No known growth event?** Corroborate against the ledger — funding transfers
   into many fresh principals in a short window. **This is corroboration only.**
   A quiet ledger does not clear an alert and a busy one does not condemn it;
   the ledger cannot see intent and neither can this monitor.
3. **Either way it is a WARNING, never a wall.** The wave rule refuses nothing.
   The budget is the wall.

**Quiet data is not exculpatory.** The absence of a funding-wave alert does not
mean there is no attack — a slow attacker below the threshold produces no wave
at all. The same caveat the concentration rule carries applies here, for the
same reason.

---

## §3. What the age gate does and does NOT buy you

State this accurately in any incident write-up, because it is easy to overclaim.

Under two-point sampling with the ledger's hard-coded **zero** fee, **one**
0.1 STSH float satisfies arbitrarily many principals: it visits each at *t* and
again at *t + T*, and all of them age in. The gate is therefore:

- **pre-funding visibility** — the wave lands T before the derives;
- **cold-start burst damping** — freshly minted principals cannot derive for T;
- **re-tooling latency** — every new principal set costs T before it produces.

It is **NOT** a capital requirement, **NOT** a sunk cost, and **NOT** a
float-multiplication defence. **The budget remains the wall.** Nothing in this
runbook, and nothing in any close record, may say the attack is priced.

---

## §4. Treasury fee income → cycle top-up policy (documentation only)

**(A) — no automation, no treasury canister change, no DEX integration.** This
section records the policy; it does not implement one.

**(1) What funds cycles today.** The cycle wallet is funded by deliberate,
manual top-up. **Protocol fee income does NOT reach the cycle wallet
automatically.** There is no path — by design — from fee accrual to a cycles
balance: fees accrue in STSH on the ledger, cycles are ICP-derived, and nothing
converts between them without a human deciding to.

**(2) Conversion trigger, cadence, authority.** Conversion is considered when
projected runway falls below the floor in (3), on a review cadence rather than
continuously, and is authorised by the treasury authority named in the custody
chain — never by the operator running this monitor.

**(3) Runway bound.** `minimum_treasury_runway_months: 6` and
`target_treasury_runway_months: 12` (`canisters/fee-policy/src/lib.rs`). Below
the minimum is the trigger to consider conversion; the target is what a
conversion aims to restore.

**(4) The vetkeys line item.** At the ratified 20/h on-ramp, worst-case derive
burn is **~$16.72/day, ~$502 per 30 days**. That is the ceiling, not the
expectation: it assumes the budget is spent every hour of every day.

**(5) Authority and logging.** Every top-up is logged with its amount, its
authoriser and its reason. An unlogged top-up is indistinguishable from a
compromise.

**(6) THE INCIDENT CASE, STATED PLAINLY.** A top-up during an active attack
**funds a zero-marginal-cost attacker.** If it is done anyway, it must be a
deliberate decision — cost-capped in advance, logged with the cap, and taken by
the named authority. **It is never automatic and never a reflex.** The right
default during an attack is to let the budget hold and let new setups wait.

---

## §5. Running it

```bash
cargo run --manifest-path scripts/cycle_monitor/Cargo.toml --bin cycle_monitor -- \
  --url <IC endpoint> --config <path> --state <path>
```

- `--state` is the monitor's own history. **It is the only liveness input it
  has**, and it is unauthenticated and destructible: deleting it, or pointing
  the scheduler at a fresh path, erases the missed-run evidence. That is why a
  missing state file ALERTS unless `--allow-missing-state` is passed to declare
  a genuine first run.
- The state file now also carries the C-26 counter history. A file written by an
  older release still parses (every new field is `#[serde(default)]`); the
  rolling rules simply report INCOMPLETE until a full span has accumulated.
- The monitored fleet is **compiled in**, not configured. Config supplies
  per-canister parameters keyed by that identity; it cannot add to, remove from
  or redirect the watched set.

## §6. When a rule fires

| Alert | First question | Do NOT |
|---|---|---|
| Saturation | is this a known growth event? | raise the budget as an operator action |
| Concentration | which principals, and are they real users? | assume a quiet reading clears it |
| Refusal spike | is offered load above the ratified ceiling? | treat refusals as failures — they are the control working |
| Funding wave | §2 triage | treat it as a wall, or as exculpatory when quiet |
| Floor (`admits: false` / below pinned floor) | is the canister being drained, or just under-funded? | top up during an active attack without §4(6) |

For any alert, INCOMPLETE included: **the safe action is to do nothing while you
find out.** Nothing degrades while you decide.
