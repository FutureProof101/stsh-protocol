# STSH Protocol Fee, Reserve, and Staking Policy

**Status:** Formal protocol-economics and architecture requirement (2026-06-11).

This policy defines how STSH deposit, withdrawal, private-spend, reserve,
treasury, and staking economics must operate. The purpose is to ensure that
the STSH protocol remains solvent, scalable, and economically safe as usage
grows.

This policy **supersedes** any earlier "entry fee only" or "recipient-exact
withdrawal by default" model for STSH.

## 0. Reconciliation status & wallet fee contract (B3, 2026-07-10)

This section is the **authoritative reconciliation** of the fee model as
actually implemented, plus the **wallet-facing fee contract** the wallet build
and the follow-on fee-build lane consume. B3 is reconciliation + contract +
docs only: it changes **no** pool fee logic, adds **no** `GovernanceFeeParams`
fields, and pins **no** fee values. Everything below marked *incoming target*
is documented for the next lane to implement, not implemented here.

### 0.1 What is implemented today (crate ↔ pool ↔ this doc — they AGREE)

The live model is a **flat protocol-fee scaffold**, shared by the pool and the
`stsh-fee-policy` crate (pure, no runtime deps; identical math both sides):

> **UPDATE (fee-build lane, 2026-07-11):** §0.2's incoming targets are now
> **implemented**. Shield/unshield use a value fee `max(flat_minimum, amount*bps/BPS_DENOMINATOR)`
> (checked, floor); shield is **fee-ON-TOP** (note credited the full denomination,
> fee pulled on top); `spend_fee_mode` (FixedStsh / XdrPegged-fails-closed),
> `fee_model_version`, `params_epoch`, and the wallet `FeeQuote` exist. The nonzero
> launch values are governance-set at deploy (not code defaults) — see
> `MAINNET_DEPLOYMENT.md`. The table below records the ORIGINAL flat scaffold for
> history; the value-fee formulas supersede the shield/unshield rows.

| Action | Live computation (function) | Fee shape |
|---|---|---|
| `shield_deposit` | `compute_deposit_preview` → `credit = gross` (fee ON TOP: `pool_transfer_in = gross + max(flat_minimum, gross*shield_bps/BPS_DENOMINATOR)`) | value fee, fee-on-top |
| `withdraw` | `compute_withdrawal_preview` → `net = gross − ledger_fee − max(flat_minimum, gross*unshield_bps/BPS_DENOMINATOR)` | value fee, inclusive |
| `private_spend` | `expected_private_spend_fee` (`canisters/shielded-pool/src/lib.rs`) — which delegates to `GovernanceFeeParams::unshield_protocol_fee` on the exit arm and to `compute_private_spend_fee_preview` on the shielded→shielded arm | **Two shapes, by outcome.** A spend carrying a `public_payout` is an **EXIT** and pays the same value fee as any exit: `max(flat_minimum, unshield_bps × public_amount / BPS_DENOMINATOR)`, taken **from** the amount. A shielded→shielded spend (no `public_payout`) pays the flat protocol spend fee (`protocol_private_spend_fee_stsh`, `FixedStsh` mode). Corrected by DOCFIX-2 2026-08-23 from a row that described only the flat arm; the FUNCTION column was corrected by lane R-11 — the two-shape rule lives in `expected_private_spend_fee`, not in `compute_private_spend_fee_preview`, which only ever computes the flat arm. Landed in lane A-7 (`7d540d1`, merged `e1eae15`); authority `OWNER_RULING_FEE_MODEL_CONSOLIDATED_2026-08-21` (`7db63d10103b8cb4`). Values: the named constants, not this table. |

The three `protocol_*_fee_stsh` values live in `GovernanceFeeParams`
(governance-set, `set_governance_fee_params`). Native ICRC **ledger** fees are
**not** in that struct — they are queried live via `icrc1_fee` and passed in
separately. Protocol fee, ledger fee, reserve, and gross/net are therefore
already **distinct quantities** in the crate types — keep them distinct
everywhere (solvency identity I-02A + wallet UX depend on it).

### 0.2 Target values (the value-fee mechanism is IMPLEMENTED; these are the
### documented targets, and `canisters/fee-policy` is authoritative for what ships)

The fee-build lane implemented these against the contract in §0.4 (merged
2026-07-11). The values ship in code, not here: `canisters/fee-policy/src/lib.rs`
and `canisters/shielded-pool/shielded_pool.did` are the single sources of truth —
this document points at them and restates none.

- **Shield / unshield:** a **value fee in bps**, percentage-based
  (percentage model), as an **editable governance variable**. IMPLEMENTED: the
  fee-build lane merged (PR #45, 2026-07-11). `GovernanceFeeParams` carries the
  value-fee fields — see `canisters/shielded-pool/shielded_pool.did`
  (`shield_fee_bps`, `unshield_fee_bps`, `shield_flat_minimum_fee_e8s`,
  `unshield_flat_minimum_fee_e8s`) and the accessors and constants in
  `canisters/fee-policy/src/lib.rs`. Those files are the single source of
  truth for the values; **this document points at them and restates none** —
  a claim DOCFIX-2 made true on 2026-08-23, having found this very bullet
  restating the rate it disclaimed.
- **Shielded transfer (`private_spend`):** a flat launch fee
  (`MAINNET_LAUNCH_SPEND_FEE_E8S`), editable governance variable,
  **XDR-peg-ready** (the XDR target and daily oracle ride the blacklist-oracle
  lane, not this one). See §0.1's `private_spend` row: a spend that carries a
  `public_payout` is an exit and pays the exit value fee instead.
- **Token transfer:** **0** protocol fee (the STSH ICRC ledger `DEFAULT_FEE`
  is also 0; any other asset's network fee is surfaced separately).

STSH **launches with pool fees live** (not zero — the earlier "fees 0 at
launch / activate in Phase 2" framing is retired). The launch values are set
by governance via `set_governance_fee_params`; sizing draws on the measured
full `private_spend` cost of **601.4 M cycles** (pool 53.6 M · verifier 254.1 M ·
merkle 278.2 M · nullifier 15.5 M; `integration-tests/tests/full_path_private_spend_benchmark.rs`
header, 2026-06-15, PocketIC 9.0.2) — a **base/floor** figure; the PPOI sub-circuit
will add a second proof + tree, so the launch estimate must add that increment later.
(An earlier 839 M figure cited a `THROUGHPUT_RESULTS.md` that is not in the tree.)

### 0.3 Three walls on the shielded-transfer fee

1. **Uniform — never a %-of-HIDDEN-amount.** The spend fee must never be sized
   from the hidden spend amount (that would leak the amount).

   **STALE AS WRITTEN — CORRECTION DUE (DOCFIX-2).** Lane A-7 merged
   (`7d540d1`, merge `e1eae15`): a public-payout exit is now sized from **`public_amount`**,
   which is a PUBLIC signal (`circuits/spend.circom:289`), not the hidden
   amount. The wall is therefore **NOT violated** — the correction is the
   public-vs-hidden distinction, not the deletion of wall #1. A
   shielded→shielded spend (`public_payout == None`) still pays the flat
   governance value, so the sentence remains exactly true of that path.
   Recorded here so DOCFIX-2 inherits the reasoning rather than rediscovering
   it. Authority: `OWNER_RULING_FEE_MODEL_CONSOLIDATED_2026-08-21` (`7db63d10103b8cb4`).
2. **≤ 1,000 STSH.** Source-confirmed in `spend.circom:501/513/519`: the `fee`
   public signal gets both `Num2Bits(37)` and `LessThan(37)` with
   `in[1] = MAX_NOTE_VALUE + 1`, so the binding bound is
   `fee ≤ MAX_NOTE_VALUE = 10^11 e8s = 1,000 STSH` — a circuit constraint, not
   a pool constant. (Not ~1,374 / 2^37 — the `LessThan` bound is tighter and
   wins.) The documented figure must match source to avoid accepted-preview /
   rejected-execution drift. See F-B3-2.
3. **QA-DEF-022 — VERIFIED (fee-build lane).** The spend-fee escrow-debit
   accounting fix is already on master (`apply_private_spend_accounting` debits
   `ESCROW_BACKING` by the full gross `fee + public_amount`). The fee-build lane
   verified it green and **extended** I-02A coverage to the public-payout
   fee-bearing spend and to the new shield-bps fee-on-top path (the identity
   `escrow + operations + insurance + governance_rewards == pool_ledger_balance`
   holds across all of them). It is no longer an open gate.

### 0.4 Wallet-facing fee contract (B3's key deliverable)

The wallet previews fees and builds fee-bearing transactions the pool will
accept. To make drift structurally impossible:

- **The pool is the execution authority; the wallet quote is a PREVIEW only.**
  The pool re-validates the fee at execution and **rejects** any spend/withdraw
  built on a stale or mismatched fee assumption (`private_spend` already does
  this: `args.fee != expected → PrivateSpendFeeMismatch`).
- **Crate reuse preferred:** the wallet consumes the `stsh-fee-policy` wasm
  crate so the quote math is byte-identical client- and canister-side. The
  crate must **not** become a second source of truth — the pool validates.
- **All amounts base units (e8s), integer only — no floats, no frontend
  percentage math.**
- The quote **binds to `fee_model_version` + `params_epoch`** exposed by the
  pool/governance config, so a stale wallet can't silently under/over-pay.
  (Historical B3 note: both fields were added by the fee-build lane — see §0.6.)

```rust
/// Wallet-facing fee quote. Preview only — the pool is authoritative and
/// rejects any transaction whose (fee_model_version, params_epoch) or amounts
/// do not match its live config at execution time.
pub struct FeeQuote {
    pub asset: FeeAsset,          // STSH / ICP / XDR — reference unit only
    pub protocol_fee_e8s: u128,   // STSH protocol fee (income)
    pub ledger_fee_e8s:   u128,   // underlying ICRC ledger fee, if any (separate line)
    pub reserve_e8s:      u128,   // reserve withheld (shield/unshield), if any
    pub gross_amount_e8s: u128,
    pub net_amount_e8s:   u128,
    pub fee_model_version: u32,   // (incoming) pool-exposed model version
    pub params_epoch:      u64,   // (incoming) pool-exposed params epoch
}
```

`protocol_fee` / `ledger_fee` / `reserve` / gross-net stay **separate fields**
(never collapsed into one "fee") per §0.1.

**The reserve endpoints no longer exist** (removed, fee-build lane) — the wallet
reads `get_governance_fee_params` + the `FeeQuote` crate math. See F-B3-1.

### 0.5 Findings (document-and-defer — no fix in B3)

- **F-B3-1 — RESOLVED (fee-build lane, 2026-07-11).** The dead M3 reserve
  endpoints `preview_shielding_reserve` / `get_reserve_params` (and their only
  consumers `RESERVE_BPS` / `FLAT_MINIMUM_RESERVE` / `compute_shielding_reserve`)
  were **removed** — they were dead since #115 but still returned a stale 20-bps
  figure the live path never charged. Neither endpoint exists anymore (`.did`
  updated same commit), so neither can return the stale rate. The wallet uses
  `get_governance_fee_params` + the `FeeQuote` crate math (§0.4).
- **F-B3-2 — dead 10% spend-fee cap (documented intentionally inert).**
  `check_fee_cap` / `MAX_PRIVATE_SPEND_FEE_BPS` (a %-of-spend cap) is **not
  wired into `private_spend`** and must not be — a %-of-hidden-amount cap would
  leak the spend amount, violating wall #1. The real spend-fee ceiling is the
  circuit's 37-bit fee range (wall #2), whose bound is the circuit's own
  `MAX_NOTE_VALUE` mirrored as `shielded_pool::CIRCUIT_MAX_VALUE_E8S` — a
  **separate authority** from the fee model; no figure for it is restated here. The fee-build lane marked
  the function + const INTENTIONALLY INERT (misleading "Called (TODO M2)" comment
  corrected); the function + its unit test are retained only as a guard against
  re-introduction.

### 0.6 Hand-forward — DONE (fee-build lane, 2026-07-11)

The **nonzero fee mechanism** is **implemented**: value-fee fields
(`shield_fee_bps`/`unshield_fee_bps` + flat-mins) + `spend_fee_mode` +
`fee_model_version`/`params_epoch` + fee-on-top shield + the §3.5 spend-fee
snapshot + the wallet `FeeQuote`, against the §0.4 contract. QA-DEF-022 is
verified (§0.3 wall #3). The nonzero launch values (the `MAINNET_LAUNCH_*`
constants — see §0.2, not restated here) are **governance-set at deploy**
(fail-safe code default stays fee-free), hard-gated in `MAINNET_DEPLOYMENT.md`. Still future: the **XDR price oracle** (blacklist-
oracle lane; `spend_fee_mode = XdrPegged` fails closed until then) and public
withdraw re-enable (the unshield fee is dormant on the fail-closed withdraw path).

## 1. Core Principle

STSH is the protocol utility token for the STSH privacy pool. It is not
primarily designed to behave as cash. Therefore, STSH withdrawals should
prioritise:

- protocol solvency
- simple accounting
- full-balance withdrawal support
- sustainable action-cost recovery
- clear user previews

over exact-recipient settlement.

For STSH, the default withdrawal model is:

```
gross withdrawal from private balance
minus native STSH ledger fee
minus protocol action fee
equals recipient net amount
```

Future cash-like assets such as ckUSDC, ckBTC, ckETH, or shielded ICP may use
a different exact-recipient model if governance enables it.

## 2. Cost Categories

STSH user actions have two separate cost categories.

### 2.1 Native STSH ICRC Ledger Fee

The transfer fee charged by the STSH ICRC ledger when STSH moves on the
public STSH ledger. It is:

- denominated in STSH
- returned by the STSH ledger via `icrc1_fee`
- charged when STSH is moved through the STSH ledger
- applicable to deposit `transfer_from` and withdrawal `transfer`

It is **not**: an ICP ledger fee, reverse gas, the protocol shielding fee,
the verifier cost, or hard-pegged to ICP. STSH actions do not pay the ICP
ledger fee unless ICP itself is being transferred.

### 2.2 STSH Protocol Action Fee

A separate STSH-denominated fee used to recover protocol execution costs.
Covers: verifier canister execution, shielded_pool execution, inter-canister
calls, Merkle tree updates, nullifier registry writes, storage,
indexing/audit overhead, monitoring/maintenance allowance, operating reserve
margin, insurance/security reserve contribution.

Charged in STSH but calculated with reference to: measured protocol cycle
cost, ICP/cycle economics, STSH/ICP reference price, treasury runway,
governance-defined safety margin.

## 3. Important Clarification: No ICP Ledger Fee for STSH Actions

Moving, shielding, withdrawing, or privately spending STSH does not require
payment of the ICP ledger fee. The ICP ledger fee only applies when ICP
itself is transferred.

```
STSH ledger movement cost      = native STSH ICRC ledger fee
STSH privacy protocol execution = STSH protocol action fee
ICP ledger fee                  = not applicable unless ICP is transferred
```

Policy and UI must **not** describe STSH fees as: "ICP ledger fee", "ICP
accounting fee", "network gas", "user-paid gas".

Correct wording: "STSH ledger fee", "protocol shielding fee", "protocol
unshielding fee", "protocol private-spend fee", "protocol action fee".

## 4. Core Economic Risk

Protocol costs scale with the number of expensive actions, not only with the
amount deposited. Expensive actions include: Groth16 proof verification,
verifier canister calls, shielded_pool execution, Merkle updates, nullifier
writes, public ledger transfers, indexing/audit overhead, monitoring and
maintenance.

A deposit-only fee model creates an economic griefing risk: user deposits
once, protocol charges once, user performs many withdrawals or private
spends, protocol pays repeatedly. This is primarily a protocol-drain issue,
not mainly a hacking issue. Therefore every expensive action must carry its
own action-level fee.

## 5. Required Long-Term Fee Model

STSH uses a hybrid fee model:

1. Native STSH ICRC ledger fee where public STSH transfers occur
2. Protocol shielding fee on deposit
3. Protocol unshielding fee on withdrawal
4. Protocol private-spend fee where proof verification/state mutation occurs
5. Minimum withdrawal and minimum recipient protections
6. Reserve-first fee waterfall
7. Staking rewards only from surplus after runway thresholds are met

This preserves the intended ICP-native UX: no user-paid ICP gas, no hidden
treasury subsidy, full private balance withdrawal support, clear fee
preview, protocol costs covered by users at scale.

## 6. STSH Deposit / Shielding Model

On STSH shielding, the user covers: (1) native STSH ICRC `transfer_from`
ledger fee, (2) protocol shielding fee.

```
protocol_shielding_fee  = shield_protocol_fee(gross_shield_amount)

private_balance_credit  = gross_shield_amount          (fee-ON-TOP: NOT reduced)

pool_transfer_in        = gross_shield_amount + protocol_shielding_fee

public_account_debit    = pool_transfer_in + stsh_icrc_transfer_from_fee

protocol_reserve_credit = protocol_shielding_fee

=> private_balance_credit == gross_shield_amount, at EVERY parameter setting
```

The protocol shielding fee is charged **ON TOP** of the deposit — it is **never
deducted from it**. The note is credited the **full requested amount**, which is
what preserves the fixed denomination (Law #1). The escrow keeps the gross and
the reserves take the protocol fee; the native STSH ledger fee is charged on top
of both, as part of the public `transfer_from`.

`private_balance_credit == gross_shield_amount` holds at **every** parameter
setting, not only at fee-free defaults. Enforced by
`stsh_fee_policy::compute_deposit_preview`; mirrored in
`canisters/shielded-pool/src/lib.rs` (the shield-deposit block, which cites §6/§11
of this document as its source).

> **Corrected 2026-08-24 (AR1-10).** This block previously stated the superseded
> **fee-DEDUCTED** model in three of its five identities (`pool_receives`,
> `private_balance_credit`, and the closing restatement) plus the prose beneath it.
> The distinction is load-bearing, not editorial: **the pool computes the outer
> Merkle leaf itself**, so an implementer who follows a fee-deducted document binds
> `gross − fee` inside a leaf the pool binds at `gross`. The circuit derives both
> from a single `in_value`, so nothing errors anywhere — the note simply can
> **never be spent**, the tokens sit in escrow, and the user loses the whole
> denomination. Our own wallet is correct, so nothing is live; the exposure was to
> anyone implementing against this document, which is the most authoritative of the
> three surfaces that carried the stale model.

**Required STSH Deposit Preview**

Both examples below are RECOMPUTED from the live constants in
`canisters/fee-policy/src/lib.rs` and `canisters/token/src/lib.rs`, not
transcribed (lane R-11 — the previous figures were reproducible under no
configuration this tree ships). The inputs are named, so the arithmetic can be
re-derived rather than trusted:

- `DEFAULT_FEE` (`canisters/token/src/lib.rs`) = **0** — STSH's own ledger fee.
  There is no runtime update path, so the ICRC transfer fee is 0 in both configs.
- `launch_defaults()`: `shield_fee_bps` = `LAUNCH_SHIELD_FEE_BPS` = 0,
  `unshield_fee_bps` = `LAUNCH_UNSHIELD_FEE_BPS` = 0, both flat minimums 0.
- `mainnet_launch_config()`: `shield_fee_bps` = `unshield_fee_bps` =
  `MAINNET_LAUNCH_{SHIELD,UNSHIELD}_FEE_BPS` = 25 (0.25%), both flat minimums =
  `MAINNET_LAUNCH_FLAT_MINIMUM_FEE_E8S` = **2.5 STSH** (`250_000_000` e8s), and
  `protocol_private_spend_fee_stsh` = `MAINNET_LAUNCH_SPEND_FEE_E8S` = **2.5 STSH**
  — RULED by `OWNER_RULING_FEE_FLOOR_2_5_STSH` 2026-09-08 (lane A6.6/R-14),
  superseding the 0.1 STSH of 2026-08-21.

  The launch flat minimum is NO LONGER `FLAT_MINIMUM_FEE_FLOOR_E8S`. The guardrail
  band is unchanged — floor `E8S_PER_STSH / 10` = 0.1 STSH, ceiling 5 STSH, 24 h
  cooldown, <=100 bps per update — and the launch value now sits strictly inside it.

  The number is a cost basis, not a round figure: at STSH = $0.00033 and 1 T cycles
  ~ $1.33, the measured `private_spend` of 601.4 M cycles
  (`integration-tests/tests/full_path_private_spend_benchmark.rs`) costs the
  protocol ~ $0.0008, so the old 0.1 STSH fee lost ~ $0.00077 per operation and
  break-even is ~ 2.4 STSH. It also lands exactly on the value fee at the launch
  ladder's floor rung (0.25% x 1,000 STSH = 2.5 STSH), so `max(flat, bps)` is
  continuous at the floor and the flat term binds only below the ladder.

```
STSH Deposit Preview — launch_defaults() (the ZERO-FEE config that ships)
Amount to shield:               100 STSH
STSH ledger transfer fee:       0 STSH        (DEFAULT_FEE = 0)
Protocol shielding fee:         0 STSH        (max(0, 100 x 0 bps))
Private balance credited:       100 STSH
Total public STSH debit:        100 STSH

STSH Deposit Preview — mainnet_launch_config()
Amount to shield:               100 STSH
STSH ledger transfer fee:       0 STSH        (DEFAULT_FEE = 0)
Protocol shielding fee:         0.25 STSH     (max(0.1, 100 x 25/10_000))
Private balance credited:       100 STSH      (fee is ON TOP, credit == gross)
Total public STSH debit:        100.25 STSH
```

- STSH ledger transfer fee: native ICRC fee for the public `transfer_from`
  into the shielded pool.
- Protocol shielding fee: STSH-denominated protocol fee recovering canister
  cycle costs and funding operating/security reserves.
- No ICP ledger fee is paid unless ICP itself is moved.

## 7. STSH Withdrawal / Unshielding Model

Net-recipient model. The user withdraws a gross amount from private balance;
fees are deducted from that gross amount.

```
withdraw_gross_amount = recipient_net_amount + stsh_icrc_transfer_fee
                         + protocol_unshielding_fee

recipient_net_amount = withdraw_gross_amount - stsh_icrc_transfer_fee
                        - protocol_unshielding_fee

private_liability_debit = withdraw_gross_amount

protocol_reserve_credit = protocol_unshielding_fee

ledger_debit_from_pool = recipient_net_amount + stsh_icrc_transfer_fee
```

This allows a user to withdraw their full private STSH balance without
needing to leave a fee remainder inside the pool.

**Required STSH Withdrawal Preview**

```
STSH Withdrawal Preview — launch_defaults() (the ZERO-FEE config that ships)
Private balance withdrawn:      100 STSH
STSH ledger transfer fee:       0 STSH        (DEFAULT_FEE = 0)
Protocol unshielding fee:       0 STSH        (max(0, 100 x 0 bps))
Recipient receives:             100 STSH

STSH Withdrawal Preview — mainnet_launch_config()
Private balance withdrawn:      100 STSH
STSH ledger transfer fee:       0 STSH        (DEFAULT_FEE = 0)
Protocol unshielding fee:       0.25 STSH     (max(0.1, 100 x 25/10_000))
Recipient receives:             99.75 STSH    (net = gross - ledger_fee - fee)
```

- STSH ledger transfer fee: native ICRC fee consumed by the STSH ledger
  transfer from the pool to the recipient.
- Protocol unshielding fee: STSH-denominated fee recovering verifier, pool,
  storage, indexing, monitoring, and reserve costs.
- No ICP ledger fee is paid unless ICP itself is moved.

## 8. STSH Private-Spend Fee Model

A private spend may not involve a public STSH ledger transfer. Private spend
fees should not automatically include a STSH ledger transfer fee unless an
actual public STSH ledger movement occurs.

```
private_spend_total_fee = protocol_private_spend_fee
```

If the private spend causes public ledger movement, the native STSH ledger
fee must also be included.

The protocol private-spend fee covers: proof verification, shielded_pool
execution, Merkle output insertion, nullifier insertion, storage,
indexing/audit overhead, operational reserve margin.

## 9. Protocol Action Fee Formula

Launch/testing formula:

```
protocol_action_fee_stsh = measured_p95_protocol_cost_in_icp
                            ÷ stsh_icp_reference_price
                            × launch_safety_margin
```

Suggested launch setting: `launch_safety_margin = 1.25`

Mature production formula:

```
protocol_action_fee_stsh = measured_p95_protocol_cost_in_icp
                            ÷ stsh_icp_reference_price
                            × mature_safety_margin
```

Suggested mature setting: `mature_safety_margin = 1.05–1.15`

Measured protocol cost must include: verifier canister cycles, shielded_pool
cycles, inter-canister call overhead, Merkle/nullifier storage, indexing and
audit overhead, monitoring/maintenance allowance, reserve margin.

Native STSH ICRC ledger fees are separate and must not be hidden inside the
protocol action fee.

## 10. Minimum Withdrawal Rules

A minimum withdrawal amount is mandatory, to: prevent dust-exit griefing,
avoid uneconomic verifier usage, preserve operating reserves, prevent user
balances being fragmented into uneconomic exits.

```
minimum_withdrawal_gross = max(fixed_floor, total_fee × safety_multiple)

total_fee = stsh_icrc_transfer_fee + protocol_unshielding_fee
```

Suggested launch setting: `safety_multiple = 20`

There must also be a minimum recipient amount:

```
recipient_net_amount >= minimum_recipient_amount
```

This prevents withdrawals where nearly all value is consumed by fees.

## 11. Required Deposit Prechecks

```
gross_shield_amount > protocol_shielding_fee

public_balance >= gross_shield_amount + stsh_icrc_transfer_from_fee

allowance >= gross_shield_amount + stsh_icrc_transfer_from_fee

stsh_icrc_transfer_from_fee == current STSH ledger icrc1_fee

protocol_shielding_fee == active governance fee parameter

private_balance_credit >= minimum_private_credit
```

If the STSH ledger returns `BadFee`, the transaction must fail safely and
refresh the fee quote.

## 12. Required Withdrawal Prechecks

```
withdraw_gross_amount >= minimum_withdrawal_gross

withdraw_gross_amount > stsh_icrc_transfer_fee + protocol_unshielding_fee

recipient_net_amount >= minimum_recipient_amount

private_balance >= withdraw_gross_amount

pool_escrow_balance >= recipient_net_amount + stsh_icrc_transfer_fee

stsh_icrc_transfer_fee == current STSH ledger icrc1_fee

protocol_unshielding_fee == active governance fee parameter

root accepted
verifying key active
proof valid
public signals bound to request
nullifier unused
withdrawal_id unused or idempotent
```

## 13. Correct Async Withdrawal Order

With the dedicated verifier canister architecture, proof verification is
async. The correct order is:

1. Validate basic arguments.
2. Validate fee quote and governance parameters.
3. Validate root / VK / circuit metadata.
4. Call verifier canister.
5. After verifier success, re-check mutable state: root still accepted,
   nullifier still unused, withdrawal_id still valid, private balance still
   sufficient, escrow balance still sufficient.
6. Reserve nullifier / mark withdrawal pending.
7. Execute STSH ledger transfer.
8. Finalise or enter explicit retryable state.

Do not reserve the nullifier before async proof verification. After proof
verification and economic prechecks pass, reserve the nullifier before any
async ledger transfer.

## 14. Accounting Invariant

```
withdraw_gross_amount = recipient_net_amount + stsh_icrc_transfer_fee
                         + protocol_unshielding_fee
```

Accounting update:

```
private_liability   -= withdraw_gross_amount
escrow_backing       -= withdraw_gross_amount
operations_reserve   += protocol_unshielding_fee

ledger_transfer_out  = recipient_net_amount + stsh_icrc_transfer_fee
```

The native STSH ledger fee is economically covered by the user through the
gross withdrawal amount. The protocol unshielding fee is reclassified from
user-claimable shielded value into protocol reserve.

Core invariant, as the pool actually evaluates it:

```
escrow_backing + pending_fee_reimbursements >= private_liability
```

The `pending_fee_reimbursements` term is NOT optional. It is the pool's own
invariant 1 (`canisters/shielded-pool/src/lib.rs`, "Invariant 1:
escrow_backing + pending_fee_reimbursements >= private_liability"), and a
two-term statement of it understates the backing the pool is entitled to count —
which is the direction that produces a false insolvency reading, not a false
solvency one.

Protocol reserves are not counted as private user liability.

## 15. Fee Buckets

Protocol income must be separated into explicit buckets.

### 15.1 Protocol Shielding Fee
Deposit accounting overhead, initial pool operations, operations reserve
contribution, insurance/security reserve contribution.

### 15.2 Protocol Unshielding Fee
Verifier canister cycles, shielded_pool execution, inter-canister calls,
storage/indexing, safety margin.

### 15.3 Protocol Private-Spend Fee
Verifier canister cycles, Merkle output insertion, nullifier insertion,
shielded_pool execution, storage/indexing, safety margin.

### 15.4 Operations Reserve
Canister cycles, verifier canister cycles, cycle top-ups, monitoring,
maintenance, upgrades.

### 15.5 Insurance / Security Reserve
Emergency winddown, circuit/verifier bugs, failed migrations, pool
impairment, security response.

### 15.6 Governance / Staking Rewards Reserve
Disabled at launch. Only funded from surplus after runway thresholds are
met.

## 16. Fee Waterfall

1. Cover direct protocol costs
2. Refill operations / cycle reserve
3. Refill insurance / security reserve
4. Build 6–12 month operating runway
5. Only then fund staking / governance rewards

Native STSH ledger transfer fees are separate and are consumed by actual
STSH ledger transfers.

## 17. Treasury and Staking Policy

Treasury-funded cycles are acceptable for bootstrap and emergency support —
not the sustainable production model.

```
Treasury        = bootstrap + emergency reserve
Protocol fees   = normal operating cost recovery
Insurance reserve = security / winddown buffer
Staking rewards = surplus only after sustainability
```

No fee income routes to staking rewards at launch.

Bad: users pay operational fees while stakers extract yield.
Correct: users cover protocol costs; stakers/governance receive surplus only
once the system is safely capitalised.

## 18. Runway Safety Rule

No staking-fee distribution may occur unless `treasury_runway >= 6 months`.
Preferred target: `treasury_runway >= 12 months`.

```
monthly_runway_cost = expected_verifier_calls × measured_p95_verifier_cost
                       + shielded_pool_execution_costs
                       + inter_canister_call_costs
                       + storage_indexing_costs
                       + monitoring_maintenance
                       + emergency_buffer

treasury_runway = available_operating_reserve / monthly_runway_cost
```

If treasury runway falls below 6 months, staking distributions pause
automatically.

## 19. Suggested Distribution Policy

**Launch Phase**: 0% staking rewards / 80–90% operations / 10–20% insurance.
The value actually shipped inside that range is set by `launch_defaults()` in
`canisters/fee-policy/src/lib.rs` (`operations_split_bps` /
`insurance_split_bps` / `staking_rewards_split_bps`) — read it there rather than
inferring a point value from this range.

**After 6-Month Reserve**: 0–5% staking / 75–85% operations / 10–20%
insurance.

**After 12-Month Reserve**: 5–15% staking/governance / 65–80% operations /
10–20% insurance.

If reserves fall below the 6-month threshold, staking distributions pause
until the safety net is restored.

## 20. Governance Parameters

The AUTHORITATIVE list is the `GovernanceFeeParams` struct in
`canisters/fee-policy/src/lib.rs` — every public field of it is a
governance-controlled parameter, and that struct is what
`set_governance_fee_params` writes. This section is a READING AID over it and is
deliberately not a second source of truth: the list below drifted out of date
once already, omitting every value-fee field that `mainnet_launch_config()`
actually sets (`shield_fee_bps`, `unshield_fee_bps`,
`shield_flat_minimum_fee_e8s`, `unshield_flat_minimum_fee_e8s`,
`spend_fee_mode`, `params_epoch`) while still naming
`protocol_shielding_fee_stsh` / `protocol_unshielding_fee_stsh`, which the
value-fee model replaced.

```
# the value-fee parameters (what mainnet_launch_config() sets)
shield_fee_bps
unshield_fee_bps
shield_flat_minimum_fee_e8s
unshield_flat_minimum_fee_e8s
spend_fee_mode
params_epoch
protocol_private_spend_fee_stsh

# minimums
minimum_withdrawal_gross
minimum_recipient_amount
minimum_private_credit

# change control
fee_reference_price_stsh_per_icp
fee_safety_margin_bps
max_fee_change_bps_per_update
fee_update_cooldown_ns

# bucket split
operations_split_bps
insurance_split_bps
staking_rewards_split_bps

# treasury policy
staking_rewards_enabled
minimum_treasury_runway_months
target_treasury_runway_months
```

Native STSH ledger fees are NOT manually configured protocol action-fee
parameters. They must be queried from the STSH ledger using `icrc1_fee`.

### 20.1 Change bounds on a routine update (LAUNCH-HARDEN-04 O-6, 2026-09-24)

Every routine (post-bootstrap) `set_governance_fee_params` call passes TWO
distinct movement layers, plus the absolute bounds and the cooldown:

- **Increases: at most +10% of the current value per accepted update, with a
  one-unit minimum step** (1 bps for rates, 1 e8s for amounts), enforced in the
  pool setter over the seven bounded fields (`protocol_shielding_fee_stsh`,
  `protocol_unshielding_fee_stsh`, `protocol_private_spend_fee_stsh`, the two
  flat minimums, and the two rates). The rule is: refuse iff
  `new > cur + max(1, cur × 1000 / 10000)` (integer floor division). Below 10
  units a 1-unit increase is more than 10%; that minimum step is disclosed, not
  a defect. Refusal text: `FeeChangeExceedsAdvertisedBound { field, current,
  requested, max_increase_bps: 1000 }`.
- **Decreases are NOT bounded by the +10% rule.** They remain bounded by the
  separate fee-policy layer (`validate_fee_change_from`: `[old/2, old×2]` on
  amounts, ±100 bps absolute on rates, unchanged) and by the absolute floors.
  The two layers are distinct: a change the fee-policy layer refuses keeps its
  own error text (`FeeAmountChangeOutOfRatio` / `FeeRateChangeTooLarge`).
- **At most one accepted update per 24 h** (`FEE_UPDATE_COOLDOWN_NS`), unchanged.
- **`max_fee_change_bps_per_update` must equal 1000** — advertised == enforced.
  Any other value is refused (`MaxFeeChangeFieldMismatch`), on the bootstrap
  path and the routine path alike.

The launch VALUES are unchanged (25 bps shield/unshield, 2.5 STSH spend fee,
epoch 1). This tightens the change bound of the 2026-09-22 fee ruling, not its
values.

## 21. Required Tests

**Deposit:**
- deposit preview includes native STSH ICRC ledger fee
- deposit preview includes protocol shielding fee
- deposit preview makes clear no ICP ledger fee is charged for STSH movement
- public account must cover gross amount + native STSH ledger fee
- allowance must cover gross amount + native STSH ledger fee
- private balance credited with the gross amount; the shielding fee is charged on top
- protocol reserve credited with protocol shielding fee
- BadFee from STSH ledger fails safely
- STSH ledger fee change is reflected in deposit preview

**Withdrawal:**
- withdrawal preview includes native STSH ICRC ledger fee
- withdrawal preview includes protocol unshielding fee
- withdrawal preview makes clear no ICP ledger fee is charged for STSH
  movement
- full private balance can be withdrawn gross
- recipient receives net amount after fees
- private liability debits gross withdrawal amount
- escrow backing debits gross withdrawal amount
- operations reserve credits protocol unshielding fee
- STSH ledger transfer consumes recipient amount + native STSH ledger fee
- withdrawal below minimum gross rejected
- withdrawal producing recipient dust rejected
- insufficient private balance rejected
- BadFee from STSH ledger fails safely
- STSH ledger fee change is reflected in withdrawal preview
- staking rewards do not receive fee income at launch

**Governance:**
- protocol fees are governance-controlled
- native STSH ledger fees are queried, not hardcoded
- fee updates respect cooldown
- fee updates respect max change cap
- staking distributions remain disabled until runway threshold
- staking distributions pause when runway falls below threshold

## 22. Future Multi-Asset Rule

This policy applies specifically to STSH actions. For future shielded
assets, fees must be denominated correctly per asset:

```
STSH transfer fee   = STSH ledger fee, paid in STSH
ICP transfer fee    = ICP ledger fee, paid in ICP
ckBTC transfer fee  = ckBTC ledger fee, paid in ckBTC
ckUSDC transfer fee = ckUSDC ledger fee, paid in ckUSDC
```

Protocol action fees may be: charged in the shielded asset, charged in STSH,
subsidised by governance, or routed through a future fee-conversion module.
This must be explicitly defined per asset before launch — do not assume one
fee model safely applies to all shielded assets.

## 23. Final Rule

For STSH deposit, withdrawal, and private-spend actions, users economically
cover:

1. Native STSH ICRC ledger fees where public STSH ledger transfers occur.
2. STSH protocol action fees used to recover canister cycle costs and
   reserve requirements.

The STSH ICRC ledger fee is denominated in STSH and queried from the STSH
ledger via `icrc1_fee`. The STSH protocol action fee is denominated in STSH
and governance-adjusted based on: measured protocol costs, ICP/cycle
economics, STSH/ICP reference pricing, reserve runway, safety margin.

STSH actions do not pay the ICP ledger fee unless ICP itself is transferred.
The protocol must not subsidise repeated user actions from treasury or
staking reserves.

STSH must maintain:
- No user-paid ICP gas.
- No false ICP ledger-fee language for STSH actions.
- No hidden protocol subsidy.
- No unlimited subsidised withdrawals.
- No staking yield until reserve sustainability is proven.

This is a formal STSH governance and tokenomics rule.
