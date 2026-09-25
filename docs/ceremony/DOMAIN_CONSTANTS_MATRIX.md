---
id: domain-constants-matrix
type: reference
owner: A1
status: FINALIZED (A-3 FINALIZE, 2026-09-12)
date: 2026-09-12
relates-to: [docs/ceremony/CEREMONY_FREEZE_RULES.md, circuits/ceremony/domain_manifest.json]
---

# `DOMAIN_*` constants matrix — FINALIZE template

**This is the artifact A6.7 consumes.** A-3 FINALIZE (2026-09-12) filled the `mainnet-v2`
column: the four values below are DECIDED and frozen for generation `mainnet-v2`.

Machine-readable twin: `circuits/ceremony/domain_manifest.json` (the wallet freeze test
reads that file, not this one — this document carries the reasoning, the JSON carries the
values).

---

## The matrix

| # | Constant | M5 (current, `ohspu`-pinned) | mainnet-v2 | Action | Blocked on |
|---|---|---|---|---|---|
| 0 | `DOMAIN_POOL_CANISTER_ID` | `45231284858326638837332416019018714005183587760015845375348183779749­31259392`<br>← `ohspu-zqaaa-aaaad-qmasq-cai` *(historical — orphaned/HOSTILE)* | `45231284858326638837332416019018714005183587760015845375466855741078­74983936`<br>← `cxrfg-qaaaa-aaaar-qchfa-cai` | **RE-ENCODED** (A-3 FINALIZE 2026-09-12) | closed — J-18 born the pool |
| 1 | `DOMAIN_ASSET_ID` | `0` | `0` | **CONFIRMED UNCHANGED** (Owner, 2026-09-12) | closed |
| 2 | `DOMAIN_CIRCUIT_VERSION` | `3` | `3` | **BUMPED 2→3 at A6.6** | closed — A6.6 constraint diff landed |
| 3 | `DOMAIN_NETWORK_ID` | `1` | `1` | **CONFIRMED UNCHANGED** (Owner, 2026-09-12) | closed |

Index is the Poseidon(4) input position and is itself part of the contract — Poseidon is
not symmetric, so a permuted list yields a different domain and unspendable notes. The
order is asserted by `wallet/tests/domain_freeze_a3.test.ts`.

```
domainHash = Poseidon(4)[ DOMAIN_POOL_CANISTER_ID,   // 0
                          DOMAIN_ASSET_ID,           // 1
                          DOMAIN_CIRCUIT_VERSION,    // 3
                          DOMAIN_NETWORK_ID ]        // 3
```

---

## Per-constant justification

### 0 · `DOMAIN_POOL_CANISTER_ID` — RE-ENCODED (A-3 FINALIZE, 2026-09-12)

The M5 value encoded `ohspu-zqaaa-aaaad-qmasq-cai`, the pool canister found orphaned
(`Module hash: None`; controller matches neither of Owner's identities). Every note minted
under it would be bound to a canister nobody controls.

**Done.** The `mainnet-v2` value encodes `cxrfg-qaaaa-aaaar-qchfa-cai`, the pool born under the
Vault at J-18 (2026-09-12; D5 receipt proposal 1, Bound, controller `cpdab-saaaa-aaaar-qca2q-cai`).
Derived with the tool below, never transcribed.

`wallet/src/crypto/notes.ts:36` already states the governing rule — *"re-pinned at gate 2-5
ONLY if 2-9 deploys a fresh pool canister"* — and A6.5 does exactly that. So this is the
documented path, not an exception to it.

**Derivation (do not transcribe):**
```bash
node wallet/scripts/derive_domain_constants.mjs <new-pool-principal>
```
Uses the single normative DEF-108 rule and self-checks against the M5 vector before
emitting anything. See `CEREMONY_FREEZE_RULES.md` §3.

### 1 · `DOMAIN_ASSET_ID` — CONFIRMED `0` (Owner, 2026-09-12)

`0` = STSH native. Expected to stay `0`: STSH remains the single shielded asset and this
brief introduces no multi-asset support.

✅ **Affirmed by the Owner on 2026-09-12** (`RULING_RECORD_GENESIS_HOLDERS_2026-09-12.md`):
`DOMAIN_ASSET_ID = 0`. STSH remains the single shielded asset. Post-launch this value is frozen
with the rest of the commitment domain.

### 2 · `DOMAIN_CIRCUIT_VERSION` — BUMPED to `3` (A6.6, landed)

A6.6 changes the constraint set in two ways, both real shape changes rather than
coefficient tweaks:
- widened in-circuit value bound (~2⁵⁰ e8s)
- re-pinned in-circuit fee BOUND — a safety ceiling, not an economic parameter.
  Today it is `MAX_NOTE_VALUE` (`circuits/spend.circom:335`); A6.6 must set it
  `≥ 0.25% × max denomination` so the ruled fee model always fits the circuit.
  Authority: `OWNER_RULING_FEE_MODEL_CONSOLIDATED_2026-08-21` (7db63d10…), which
  supersedes DD-2 as to the NUMBER (no active cap at launch) while confirming the
  bound is non-economic. No figure is restated here: `canisters/fee-policy` and
  `circuits/spend.circom` are the single sources of truth. (The former
  `1,000 → 10,000 STSH, per D-3a/D-3b` wording is retired: the figure is superseded
  and D-3a/D-3b are phantom citations — no such rulings exist.)

Under the existing convention (`2` was itself "a single bump for all 3 stages" of circuit
finalization), a constraint-shape change warrants a bump.

**The ruling is the A6.6 circuit-diff author's, not A-3's.** Two hard consequences:
- If **yes**, it MUST land in the *same* atomic freeze as the domain re-pin — not a
  follow-up. A staggered landing is the silently-unspendable-notes failure.
- Post-launch this value is frozen with the rest of the commitment domain, **even if a
  separately-represented verifier/circuit release version later advances.** Do not couple
  the two numbers.

**Action: A6.6 circuit-diff author to rule.**

### 3 · `DOMAIN_NETWORK_ID` — CONFIRMED `1` (Owner, 2026-09-12)

`1` = ICP mainnet. Target network unchanged. Affirmed by the Owner on 2026-09-12 alongside
`DOMAIN_ASSET_ID`.

---

## Derived value

| | M5 | mainnet-v2 |
|---|---|---|
| `domainHash` decimal | `17076800395491555068286473339039486071114029588881949545487634475758427007736`<br>*(the A1 `[ohspu, 0, 2, 1]` vector — historical)* | `9578431337377839681221818034592677386495104691038362380902047525493741438900` |
| `domainHash` LE 32B hex | `f86a7fd6a66d358ddbe7d8fa7b303f5da7e63d41b7ee207c6a31359c6220c125` | `b4c713664074d78bed0527155ed4c508f8e9308fb325eec76a0e2e4e34332d15` |

Recompute from the four finalized constants; do not copy. Wallet and circuit must produce
this **identically**, checked **after** all A6.6 constraint changes are in
(`wallet/tests/domain_freeze_a3.test.ts` + the recompiled R1CS).

---

## FINALIZE fill-in procedure

1. Run the derivation tool → constant 0.
2. Record the A6.6 ruling → constant 2.
3. Record the V4 confirmation → constant 1; confirm constant 3.
4. Fill `next_value` for all four in `circuits/ceremony/domain_manifest.json`; set
   `phase: "A-3-FINALIZE"`, `status: "FINALIZED"`, `generation.next_finalized: true`.
5. Flip `PINNED_GENERATION` to `"next"` in `wallet/tests/domain_freeze_a3.test.ts`.
6. Apply all 7 artifact-matrix rows in ONE commit, with the A6.6 constraint change.
7. Recompute `domainHash`; fill `next_decimal` / `next_le32_hex`.
8. Recompile; re-pin the R1CS sha256 + constraint count.
9. Green: `cd wallet && npx vitest run tests/domain_freeze_a3.test.ts` and `./run_gate.sh`.
10. Hand to A6.7 with `PTAU_MULTIPARTY_PLAN.md`.

**Steps 1–9 executed 2026-09-12 (lane A-3 FINALIZE).** Step 10 (the ceremony) is NOT this lane.
