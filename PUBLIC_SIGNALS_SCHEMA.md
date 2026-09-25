# STSH Spend Circuit — Public Signal Schema

> Circuit version: `0.3.0-a0`
> Circuit file: `circuits/spend.circom`
>
> **WARNING:** Signal indices (0-based snarkjs `publicSignals` array positions)
> are determined by circom's compilation order, which is set by the
> `component main { public [...] }` declaration. Always **verify indices
> against the compiled `.sym` file** — do NOT hardcode without confirmation.

---

## Public Signal Ordering

The `component main { public [...] }` declaration in `spend.circom` lists signals in this order:

```circom
component main {
    public [
        anchor,                   // index 0
        nullifier_hash,           // index 1
        output_merkle_leaf_1,     // index 2  (DEF-111 value-bound leaf)
        output_merkle_leaf_2,     // index 3  (DEF-111 value-bound leaf)
        public_amount,            // index 4
        fee,                      // index 5
        recipient_principal,      // index 6  (DEF-026)
        recipient_subaccount_lo,  // index 7  (DEF-026)
        recipient_subaccount_hi   // index 8  (DEF-026)
    ]
} = STSHSpend(32);
```

> **DEF-026 (Pass 7 / P7-001):** signals **6–8** bind the public-payout
> destination into the proof. Before this, `destination` / `destination_subaccount`
> were call-arguments only — a privileged attacker could replay a valid proof with
> a substituted recipient and redirect the payout. They are now membership-bound
> public inputs: substituting any of the three fails the Groth16 pairing.

**After compilation, verify with:**
```bash
grep "^main\." circuits/build/spend.sym | sort -t. -k3 -n
```

The `.sym` file maps signal names to R1CS wire indices. The `publicSignals` array
in snarkjs corresponds to the public inputs in order of declaration.

---

## Signal Definitions

### Signal 0: `anchor`

| Field | Value |
|-------|-------|
| Type | Public input |
| Domain | BN254 Fr |
| Encoding | 32-byte little-endian (Rust canister) / decimal string (snarkjs) |
| Computed as | Root of the Merkle commitment tree at some historical state |
| Enforced by | **Circuit** — Merkle path proof verifies leaf against this root |
| Canister check | `is_accepted_anchor(root)` — root must be in the pool's durable `ACCEPTED_SPEND_ROOTS` allow-list (A2; raw Merkle roots are not anchors) |

The anchor is a historical snapshot of the commitment tree root. The circuit
proves the input note existed in the tree at the time represented by `anchor`.
Valid anchors are those inserted into `shielded_pool`'s `ACCEPTED_SPEND_ROOTS` by
finalized A2 promotion (ARCHITECTURE.md law 3).

**Format notes:**
- snarkjs: decimal string (Fr element as base-10 integer)
- Rust canister: 32-byte little-endian array via `Fr::from_le_bytes_mod_order`
- `[0u8; 32]` is never a valid anchor (Poseidon(0,0) ≠ 0 — see test_54)

---

### Signal 1: `nullifier_hash`

| Field | Value |
|-------|-------|
| Type | Public input |
| Domain | BN254 Fr |
| Encoding | 32-byte little-endian (Rust) / decimal string (snarkjs) |
| Computed as | `Poseidon(4)[domain_sep, spend_key, in_commitment, NULLIFIER_DOMAIN=2]` [Poseidon(4), t=5] (DEF-109-A) |
| Enforced by | **Circuit** — derived from private `spend_key` and the input note commitment |
| Canister check | Not already in `nullifier_registry` (double-spend prevention) |

The nullifier uniquely identifies a spent note. **DEF-109-A (full-note binding):** the
circuit derives it from `spend_key` and the input note's COMMITMENT (`in_commit.commitment`,
which binds `in_value`, `derived_pk`, `in_rho`, `in_rseed`) — not the bare `in_rho` — with
NULLIFIER_DOMAIN separation preventing cross-protocol collisions with pk or commitment
hashes. Binding the whole note closes DEF-109: two valid notes sharing `(spend_key, in_rho)`
but differing in `in_value`/`in_rseed` yield distinct nullifiers, so spending one cannot
brick the other.

**DEF-035 cross-deployment `domain_sep`:** `domain_sep` is prepended as the first
Poseidon input, binding every nullifier and commitment to one deployment's constants:
`domain_sep = Poseidon(4)[DOMAIN_POOL_CANISTER_ID, DOMAIN_ASSET_ID, DOMAIN_CIRCUIT_VERSION, DOMAIN_NETWORK_ID]`.

**AR1-12 — what this does and does not separate.** The earlier wording here said it
stops replay "on another deployment sharing the same VK". That is self-defeating as
stated: these are **compile-time circuit constants** (`circuits/spend.circom`), so two
deployments sharing a VK share the compiled circuit and therefore the same baked
`domain_sep` — the constant cannot tell them apart. Deployments with *different*
constants necessarily have *different* VKs, and those are already separated before the
circuit is reached, by the pool's `verifying_key_hash` envelope check.

What `domain_sep` does do is bind the note algebra to **one tuple of compiled constants**:
nullifiers and commitments computed under one tuple are not valid values under a different
tuple, and the binding is committed to by the VK rather than asserted at the boundary.

State the limit precisely, because the earlier wording was overbroad in one direction and it
is easy to be overbroad in the other. `domain_sep` separates deployments or version bumps
**whose compiled domain constants differ** — a new pool principal, asset, circuit version, or
network. It gives **no** separation between two deployments sharing the same tuple: a
reinstall or redeploy under the same principal, asset, circuit version and network compiles
the same `domain_sep`, and artefacts DO carry across it. Those cases are not distinguishable
by this constant, and nothing here should be read as claiming they are.
It is a circuit constant, **not** a public signal — the signal schema (count 9) is
unchanged. The same `domain_sep` is the first input of every note commitment
(Signal 2). See `POSEIDON_PARAMS.md` §Domain Separation (DEF-035).

**Important:** The canister also calls `insert_batch` on the `nullifier_registry`
after a successful spend. The circuit proves the nullifier is correctly formed;
the canister enforces uniqueness.

---

### Signal 2: `output_merkle_leaf_1`  (DEF-111 — was `output_commitment_1`)

| Field | Value |
|-------|-------|
| Type | Public input |
| Domain | BN254 Fr |
| Encoding | 32-byte little-endian (Rust) / decimal string (snarkjs) |
| Computed as | `MerkleLeaf = Poseidon(3)[out_value_1, inner_commitment_1, MERKLE_LEAF_DOMAIN=4]` [Poseidon(3), t=4], where `inner_commitment_1 = Poseidon(6)[domain_sep, out_value_1, out_recipient_pk_1, out_rho_1, out_rseed_1, COMMITMENT_DOMAIN=3]` is a private intermediate |
| Enforced by | **Circuit** — the value-bound outer leaf matches the private output note values (DEF-111 / B-prime) |
| Canister check | Inserted into the Merkle tree **as the leaf** (proof-verified; no pool recomputation) |

The first output note's **value-bound Merkle leaf**. DEF-111 changed public signals
2/3 from the inner note commitment to the outer leaf `MerkleLeaf(value, inner_commitment)`
so Merkle membership binds the note's spendable value (closing the over-value gap).
The inner commitment stays a private circuit intermediate; `domain_sep` is omitted from
the outer leaf (the inner commitment already binds it). May be a payment, change, or
self-payment.

**Zero value:** `out_value_1 = 0` is valid (empty dummy note); the leaf itself is a
nonzero domain-separated hash.

---

### Signal 3: `output_merkle_leaf_2`  (DEF-111 — was `output_commitment_2`)

Same structure as Signal 2 (value-bound Poseidon(3) leaf). The second output note,
typically a change note. `out_value_2 = 0` is explicitly allowed.

---

### Signal 4: `public_amount`

| Field | Value |
|-------|-------|
| Type | Public input |
| Domain | BN254 Fr (range-checked to [0, MAX_NOTE_VALUE]) |
| Encoding | 32-byte little-endian (Rust) / decimal string (snarkjs) |
| Computed as | Net STSH leaving the shielded pool (the proof-bound pool ledger debit); 0 for a pure private transfer, > 0 for a specific-amount public payout |
| Enforced by | **Circuit** — included in value balance; range-checked to `[0, MAX_NOTE_VALUE]` |
| Canister check | For a public payout / withdraw: must match the `icrc1_transfer` amount to the recipient |

A `private_spend`'s `public_amount` is **0 for a pure internal transfer** (note → output
notes only), or **any value up to the spender's shielded balance** when the spend carries a
*specific-amount public payout* (`PrivateSpendPublicPayout` — see `canisters/shielded-pool/src/lib.rs`).
For a `withdraw` (unshielding to a principal): `public_amount > 0`.

> **DEF-045 — `public_amount` is intentionally NOT denomination-constrained.** The fixed
> `DENOMINATIONS = [1_000, 10_000, 100_000, 1_000_000, 10_000_000] STSH` model (ARCHITECTURE.md Law #1) is enforced only for
> `shield_deposit` (`withdraw` takes a custom `gross_withdraw_amount`; fixed-denomination withdraw is
> a design option, not implemented — ARCHITECTURE.md law 1). A `private_spend`'s `public_amount` is deliberately flexible —
> any value ≤ the spender's shielded balance — to support a "specific-amount exit." The trade-off
> is that a non-standard payout amount is a unique on-chain fingerprint; this is a documented
> design choice, not a defect.

The **recipient of the public payout** IS bound into the proof as of DEF-026 —
signals 6, 7, 8 below. (Earlier revisions claimed the recipient was enforced only
at the canister layer via a `ProofEnvelope.recipient` field; that field never
existed in the canister and the claim is obsolete.)

---

### Signal 5: `fee`

| Field | Value |
|-------|-------|
| Type | Public input |
| Domain | BN254 Fr (range-checked to [0, MAX_NOTE_VALUE]) |
| Encoding | 32-byte little-endian (Rust) / decimal string (snarkjs) |
| Computed as | Protocol fee in base STSH units |
| Enforced by | **Circuit** — included in value balance; range-checked |
| Canister check | Must match pool's fee schedule; credited to treasury subaccount |

The fee deducted from the input note. Currently the shielded pool canister
computes the expected fee independently and checks it matches the public signal.

---

### Signal 6: `recipient_principal` (DEF-026)

| Field | Value |
|-------|-------|
| Type | Public input |
| Domain | BN254 Fr |
| Encoding | Principal raw bytes (≤29) into bytes[0..len], byte[31]=len (DEF-108), little-endian field element |
| Computed as | `public_payout.destination.as_slice()` into bytes[0..len] + byte[31]=len → LE Fr; `0` when there is no payout |
| Enforced by | **Circuit (DEF-112)** — explicit squaring constraint (`rp_bind <== recipient_principal * recipient_principal`, `spend.circom` Constraint 5c) **+ membership in the proof** (VK IC vector) |
| Canister check | Pool re-derives via `encode_recipient_signals` and passes to the verifier; post-verify recheck |

The destination principal of the optional public payout. **DEF-108:** `byte[31]` commits
the principal length, making the encoding injective (principals differing only by trailing
zero bytes no longer collide). `len ≤ 29` (`0x1D`) as the top byte keeps the element
canonical (`< p`). When `public_payout = None` this signal is `0`, and `public_amount`
(signal 4) must also be `0`.

> **Do not conflate the two recipients.** Signals 6–8 bind the **public-payout
> destination** (an ICRC account). The `recipient_pk` input inside the inner note
> commitment (Signal 2) binds the **shielded-note owner** — a different party via a
> different mechanism. Neither binding substitutes for the other.

---

### Signal 7: `recipient_subaccount_lo` (DEF-026)

| Field | Value |
|-------|-------|
| Type | Public input |
| Domain | BN254 Fr |
| Encoding | `destination_subaccount[0..16]` as a 128-bit little-endian field element |
| Computed as | Low 16 bytes of the 32-byte ICRC subaccount; `0` when no payout / no subaccount |
| Enforced by | **Circuit (DEF-112)** — explicit squaring constraint (`rsl_bind <== recipient_subaccount_lo * recipient_subaccount_lo`, `spend.circom` Constraint 5c) **+ membership in the proof** (VK IC vector) |
| Canister check | Pool re-derives via `encode_recipient_signals`; post-verify recheck |

---

### Signal 8: `recipient_subaccount_hi` (DEF-026)

| Field | Value |
|-------|-------|
| Type | Public input |
| Domain | BN254 Fr |
| Encoding | `destination_subaccount[16..32]` as a 128-bit little-endian field element |
| Computed as | High 16 bytes of the 32-byte ICRC subaccount; `0` when no payout / no subaccount |
| Enforced by | **Circuit (DEF-112)** — explicit squaring constraint (`rsh_bind <== recipient_subaccount_hi * recipient_subaccount_hi`, `spend.circom` Constraint 5c) **+ membership in the proof** (VK IC vector) |
| Canister check | Pool re-derives via `encode_recipient_signals`; post-verify recheck |

The 32-byte ICRC subaccount is split into two 128-bit halves so that the **full**
subaccount space round-trips (no single-field truncation). `None` subaccount → both
halves `0`. Together signals 6–8 bind the exact `(owner, subaccount)` of the payout.

---

## ZK-Enforced vs. Canister-Enforced Checks

The circuit enforces properties that require knowledge of private inputs.
The canister enforces properties that are public or policy-level.

### ZK-Enforced (circuit proves — cannot be faked without a valid proof)

| Property | How enforced |
|----------|-------------|
| Input note exists in commitment tree | Merkle path proof vs. `anchor` |
| Prover knows `spend_key` for input note | `derived_pk = Poseidon(spend_key, PK_DOMAIN)` wired into commitment |
| Nullifier correctly derived from `spend_key` + input commitment (DEF-109-A) | NullifierDerivation component |
| Output commitments correctly formed | NoteCommitment components |
| All values in [0, MAX_NOTE_VALUE] | LessThan(37) on each value signal |
| Value balance: `in = sum(outputs) + fee + public_amount` | Linear constraint |
| Within-deployment domain separation (no cross-hash collisions) | PK/NULLIFIER/COMMITMENT domain constants |
| Cross-deployment binding (no proof replay across deployments) | DEF-035 `domain_sep` prefix in the nullifier + commitment preimages |
| Public-payout recipient cannot be substituted (DEF-026 + DEF-112) | Signals 6/7/8 are public inputs — bound by an explicit in-circuit squaring constraint (DEF-112, `spend.circom` Constraint 5c) AND by membership in the VK IC vector; any substitution fails the pairing |

### Canister-Enforced (ProofEnvelope — checked in shielded_pool before accepting proof)

| Property | Where enforced | Notes |
|----------|---------------|-------|
| `anchor` is in root history | `is_accepted_anchor()` in `shielded_pool` (`ACCEPTED_SPEND_ROOTS`) | Prevents stale-root attacks |
| `nullifier_hash` not previously spent | `nullifier_registry.contains_nullifier()` / `contains_nullifiers_batch()` | Double-spend prevention |
| `circuit_version` matches expected | `ProofEnvelope.circuit_version` | Prevents old-circuit replay |
| `verifying_key_hash` matches pinned VK | `ProofEnvelope.verifying_key_hash` vs. `PINNED_VK_HASH` | VK substitution attack prevention |
| `pool_version` matches current canister | `ProofEnvelope.pool_version` | Protocol upgrade safety |
| `proof_system_id` is Groth16/BN254 | `ProofEnvelope.proof_system_id` | Multi-scheme confusion prevention |
| Asset type (ICP / ckBTC / etc.) | bound in-circuit via `domain_sep` (`DOMAIN_ASSET_ID`) — see Signal 1 and BINDING §9 | Bound |
| Pool canister identity | bound in-circuit via `domain_sep` (`DOMAIN_POOL_CANISTER_ID`) — see Signal 1 and BINDING §9 | Bound |
| Fee amount matches schedule | `fee` public signal vs. canister config | Business logic |
| Public-payout recipient (principal + subaccount) | **Circuit signals 6/7/8 (DEF-026)** | Bound in the proof; pool re-derives via `encode_recipient_signals` and rechecks post-verify |
| Minimum denomination / dust | **NOT ENFORCED anywhere** | The `input_amounts` validation this row cited was an equality/overflow check only — it contained no minimum-denomination predicate — and it was removed with the cleartext amount fields by lane F1-PRIV (R1-F1). Deposits remain fixed-denomination (`shield_deposit`); spend outputs are constrained only to `[0, MAX_NOTE_VALUE]` by the circuit range checks (`spend.circom:516-520`) |

### Items NOT Currently Enforced (Future Work)

| Property | Status | Priority |
|----------|--------|----------|
| `circuit_version` in public signals | Canister-layer only | M5 — if needed |
| Note linkability prevention | Not enforced | M5+ — viewing key scheme |

---

## Encoding Reference

### Fr element: snarkjs → Rust

snarkjs represents Fr elements as decimal strings in `publicSignals`:
```json
["123456789012345678901234567890", "99999...", ...]
```

The Rust canister expects 32-byte little-endian arrays. Conversion:
```rust
use ark_ff::PrimeField;
use num_bigint::BigUint;

fn decimal_str_to_le_bytes(s: &str) -> [u8; 32] {
    let big = BigUint::parse_bytes(s.as_bytes(), 10).unwrap();
    let mut bytes = big.to_bytes_le();
    bytes.resize(32, 0);
    bytes.try_into().unwrap()
}
```

See also `SNARKJS_TO_CANDID_ENCODING.md` for the full proof encoding specification.

---

## Value Bounds

```
MAX_NOTE_VALUE = 100_000_000_000  (10^11 base STSH units = 1000 STSH)
MIN_NOTE_VALUE = 0                (zero notes allowed — circuit level)
```

The circuit enforces `[0, MAX_NOTE_VALUE]` for all value signals.
No dust floor is enforced at any layer (see the Canister-Enforced table row and CIRCUIT_AUDIT_NOTES.md §Zero and Dust Policy).

Note: `MIN_DENOMINATION` (a dust floor) is distinct from the fixed
`DENOMINATIONS = [1_000, 10_000, 100_000, 1_000_000, 10_000_000] STSH` set. The fixed-denomination set constrains only
`shield_deposit` (ARCHITECTURE.md Law #1; `withdraw` takes a custom `gross_withdraw_amount`); it does **not** bound a `private_spend`'s
`public_amount`, which is a flexible specific-amount payout (DEF-045 — see Signal 4 above).

---

*Last updated: 2026-06-26 (DEF-026 — recipient/subaccount proof binding; signals 6/7/8 added, count 6 → 9)*
*Amended: 2026-06-28 (Pass 10 / DEF-061 — nullifier/commitment formulas updated to include the DEF-035 `domain_sep` prefix: Poseidon(4) / Poseidon(6))*
*Amended: 2026-07-06 (C3 pre-ceremony doc drift — recipient signal rows 6/7/8 updated to reflect the DEF-112 in-circuit squaring constraints (Constraint 5c); two-recipient distinction note added)*
