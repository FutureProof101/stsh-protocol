# STSH Public Signal Binding — Groth16/BN254 Spend Circuit

> Status: BINDING CONTRACT — do not modify without updating the circuit, canister, and integration tests.
> Version: 1.3 (Pass 10 / DEF-063+064 — 2026-06-28; merged the former `docs/` copy into this
> single canonical document; corrected to 9 signals / 10 IC and A2 stage-before-finalize;
> AR1-12/AR1-13 amendments 2026-08-24; E-1/E-4 corrections 2026-09-02).
> Prior: 1.1 (DEF-026 recipient binding — 2026-06-26; signals 6/7/8 added, count 6 → 9).
> Circuit: `circuits/spend.circom` (Groth16 / BN254). Proof system: `groth16-bn254`.

> **LAUNCH TRUSTED SETUP COMPLETE (mainnet-v2, 2026-09-12) — SINGLE-OPERATOR PHASE 2 DISCLOSED**
>
> **A-4 (2026-09-12), superseding the AR1-13 banner.** The launch ceremony has now RUN,
> over the ceremony-frozen `circuits/spend.circom` whose `DOMAIN_POOL_CANISTER_ID` was
> re-encoded to the Vault-born pool `cxrfg-qaaaa-aaaar-qchfa-cai` at A-3 FINALIZE
> (generation `mainnet-v2`). **Phase 1 is the PUBLIC Hermez powers-of-tau** (power 15;
> 54 named contributors plus a beacon) — it is NOT single-participant, which is what the
> superseded banner's "single-participant DEV VK" language described and what F6-1
> tracked. **F6-1 is CLOSED.** **Phase 2 is ONE operator contribution**
> (`FutureProof operator 2026-09-12`) **finalized by a pre-announced public drand beacon**
> (mainnet chain, round 6460200, iterationsExp 10) which is the LAST contribution. That
> single-operator phase 2 is the remaining trust assumption and is disclosed, not fixed
> (record §4.2, E10/CR-12); the community multi-party re-ceremony stays POST-launch.
> The VK committed at `circuits/verification_key.json` — sha256 (= `PINNED_VK_HASH`)
> `84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914`. The previous value
> `fc73ca4d…530dc8` is the SUPERSEDED M5 dev VK and survives only as `DEV_VK_HASH_HEX`, a
> deny-list entry. Proof
> verification ships as the async inter-canister `verifier` canister call (the
> historical stub is gone from production paths); invalid proofs are rejected
> on-chain. This document describes the binding for that frozen circuit.
> Full evidence: `docs/ceremony/CEREMONY_RECORD_v3.md`.

---

## 1. Purpose and Scope

The Groth16 circuit for `private_spend` produces **9 public signals** in a fixed
positional order. The snarkjs JSON representation `publicSignals[0..8]` maps
one-to-one to the 9-element signal vector built by
`shielded_pool::build_spend_public_signals`. This document is the authoritative
binding contract between those two representations.

This document also answers, per signal: **why can a valid Groth16 proof not be
reused with a substituted value for that signal?** In a Groth16 proof system,
"binding" of a public signal means the verification equation covers all R1CS
constraints simultaneously; any constraint violation — including a substituted
public input — causes the pairing check to fail. The recipient signals 6–8 are
bound by membership in the verifying key's `gamma_abc_g1` (IC) vector **and**, as of
**DEF-112**, by an explicit in-circuit constraint (see §4.7) — so their binding no
longer rests only on the implicit membership property (defense-in-depth).

> **DEF-026 (Pass 7 / P7-001):** signals **6–8** were added to bind the optional
> public-payout recipient (principal + 32-byte ICRC subaccount) into the proof.
> Count went 6 → 9; the verifying key's `gamma_abc_g1` (IC) vector went 7 → 10.

**Scope:**

- Circuit: `circuits/spend.circom` — `STSHSpend(32)`, 1-input / 2-output private spend.
- Operation: `private_spend` — shielded-pool transfer, optionally carrying a
  specific-amount public payout (signals 4 and 6–8).
- Public signals: 9 (indices 0–8 in the snarkjs `publicSignals` array).

**Out of scope for this document:**

- `fn withdraw`: the withdrawal path does **not** call
  `build_spend_public_signals` and does not route through the spend circuit
  (`reject_unbound_withdrawal_proof` fails closed). Fee policy for withdrawals is
  covered in `docs/STSH_FEE_POLICY.md`.
- Multi-input spends (M5 extension).
- Deposit path (no spend circuit involvement).
- Trusted-setup readiness (see warning above).

Any change to signal order, encoding, or meaning is a breaking change that requires:
1. Circuit recompile and new trusted setup
2. Updated Rust struct and binding verification
3. Updated test vectors in `circuits/tests/adversarial.test.js`
4. Updated integration tests
5. New audit sign-off

---

## 2. Circuit Shape and Signal Count

| Parameter | Value | Source |
|---|---|---|
| Circuit template | `STSHSpend(32)` | `spend.circom` |
| Input notes | 1 | design |
| Output notes | 2 | design |
| Tree depth | 32 (≈4 billion leaves) | `MerkleProof(32)` instantiation |
| Public signals | **9** | `component main {public [...]}` |
| `gamma_abc_g1.len()` | **10** (= 9 public signals + 1 constant term) | `verifier/src/lib.rs` |
| Hash function | Poseidon/BN254 (circomlib) | all hash templates |
| Proof system | Groth16 on BN254 | `pragma circom 2.1.9` |

The `gamma_abc_g1.len() == 10` invariant is hard-checked in the verifier before
any pairing computation (see §7). A VK compiled for a different signal count is
rejected immediately.

**Signal values in practice:**

- `public_amount` (index 4) is the proof-bound net public value leaving the pool
  ledger: `0` for a pure private transfer, `> 0` for a specific-amount public
  payout (`PrivateSpendPublicPayout`). It is assembled by
  `build_spend_public_signals` from `private_spend_public_amount(args)`. It is
  **not** denomination-constrained (DEF-045 — see §4.5).
- `fee` (index 5) must equal the governance-quoted `protocol_private_spend_fee_stsh`
  (`PrivateSpendFeeMismatch` otherwise); the launch value is the
  `MAINNET_LAUNCH_SPEND_FEE_E8S` constant, applied by the scripted bootstrap
  (MAINNET_DEPLOYMENT.md) — nonzero, not restated here. `SpendFeeNotSupported` is a
  deprecated Candid variant. See `docs/STSH_FEE_POLICY.md`.
- Signals 6–8 carry the optional public-payout recipient; all three are `0` when
  `public_payout = None` (and then `public_amount` is also `0`).

---

## 3. Signal Binding Table

| Index | Field name              | Encoding                                   | Source                                                                 |
|-------|-------------------------|--------------------------------------------|-----------------------------------------------------------------------|
| 0     | `anchor`                | BN254 Fr → 32-byte little-endian           | `ACCEPTED_SPEND_ROOTS` / Merkle root (`envelope.root_reference`)       |
| 1     | `nullifier_hash`        | BN254 Fr → 32-byte little-endian           | `Poseidon(4)[domain_sep, spend_key, in_commitment, NULLIFIER_DOMAIN]` (DEF-109-A) |
| 2     | `output_merkle_leaf_1`  | BN254 Fr → 32-byte little-endian           | `Poseidon(3)[out_value_1, inner_commitment_1, MERKLE_LEAF_DOMAIN]` (DEF-111 value-bound leaf) |
| 3     | `output_merkle_leaf_2`  | BN254 Fr → 32-byte little-endian           | `Poseidon(3)[out_value_2, inner_commitment_2, MERKLE_LEAF_DOMAIN]` (DEF-111 value-bound leaf) |
| 4     | `public_amount`         | u128 little-endian, padded to 32 bytes     | `private_spend_public_amount(args)` (0 for pure transfer; >0 for payout) |
| 5     | `fee`                   | u128 little-endian, padded to 32 bytes     | `args.fee` (must equal the governance-quoted `protocol_private_spend_fee_stsh`, else `PrivateSpendFeeMismatch`; launch value = `MAINNET_LAUNCH_SPEND_FEE_E8S`, nonzero; `SpendFeeNotSupported` is a deprecated Candid variant) |
| 6     | `recipient_principal`   | principal bytes (≤29) into bytes[0..len], byte[31]=len (DEF-108), LE Fr | `public_payout.destination` (None → `0`)                         |
| 7     | `recipient_subaccount_lo` | `subaccount[0..16]` as a 128-bit LE Fr   | `public_payout.destination_subaccount` (None → `0`)                   |
| 8     | `recipient_subaccount_hi` | `subaccount[16..32]` as a 128-bit LE Fr  | `public_payout.destination_subaccount` (None → `0`)                   |

`domain_sep` is the DEF-035 cross-deployment domain hash
`Poseidon(4)[DOMAIN_POOL_CANISTER_ID, DOMAIN_ASSET_ID, DOMAIN_CIRCUIT_VERSION, DOMAIN_NETWORK_ID]`
— a circuit constant, **not** a public signal (see §9 and `POSEIDON_PARAMS.md`
§Domain Separation). The canonical per-type encoding rules are in
`SNARKJS_TO_CANDID_ENCODING.md`.

Signal ordering is confirmed from the `component main {public [...]}` declaration
in `circuits/spend.circom` and the compiled `circuits/build/spend.sym` symbol file
(column 2 = snarkjs 1-based public index, column 4 = signal name). After any
recompilation, re-confirm from `.sym`:

```bash
grep "^main\." circuits/build/spend.sym | sort -t. -k3 -n
```

> **Warning on `.sym` portability:** `circuits/build/spend.sym` is a compiled
> build artifact, not tracked in git. The canonical authority for signal ordering
> in tracked files is the `component main {public [...]}` declaration.

**All sources agree — anchor-first throughout, no translation layer:**

| Source | Ordering | Authority |
|---|---|---|
| `circuits/spend.circom` `component main {public [...]}` | anchor-first (9) | Canonical (tracked) |
| `circuits/public.json` fixture (9 elements) | anchor-first | Compiled artifact |
| `build_spend_public_signals` (`shielded-pool/src/lib.rs`) | anchor-first (9) | Pool code |
| `parse_public_inputs` / `public_json_to_signals` (`verifier/src/lib.rs`) | anchor-first (9) | Verifier code |
| `load_valid_spend_fixture_args` (`integration-tests`) | `signals[0]=anchor` | Test code |

> **Disambiguation — signal index vs mutation order:**
>
> A2 (QA-DEF-034/036) inverted the `commit_private_spend` mutation order to
> **stage-before-finalize**: output commitments are first STAGED durably in
> `PENDING_OUTPUTS`, the parent nullifier is permanently inserted into the
> registry, and ONLY THEN are the outputs promoted to the active Merkle tree. See
> §4.3 and §6.5. This step ordering does **not** affect signal indices: the
> public-signal array is always anchor-first, with `output_commitment_1` at index
> 2 and `output_commitment_2` at index 3.

**#116 — Canonical BN254 Fr encoding requirement:**

All caller-supplied signals (`anchor`, `nullifier_hash`, `output_commitment_1`,
`output_commitment_2`) must be canonical 32-byte little-endian BN254 Fr elements:
the encoded integer must be strictly less than the Fr modulus. Non-canonical
bytes are rejected at two independent layers before any registry or Merkle key is
written:

1. `build_spend_public_signals` checks the four caller-supplied signals via
   `is_canonical_fr_le` before the async verifier call — an aliasing signal is
   rejected with `PoolError::ProofRejected`.
2. `parse_public_inputs` (verifier) also calls `is_canonical_fr_le` for every
   signal before `Fr::from_le_bytes_mod_order`.

`public_amount`, `fee`, and the recipient signals 6–8 are canonical by
construction (`public_amount`/`fee` come from `u128_to_fr_le`; a principal is
≤232 bits and each subaccount half is 128 bits — all ≪ the Fr modulus).

**#117 / #118 — INFLIGHT reservation gate (does not affect signal ordering):**

`commit_private_spend` gates concurrent calls carrying the same nullifier through
a heap-only `INFLIGHT_NULLIFIERS` reservation. This closes the race window
between the async nullifier recheck and the permanent registry insert. The gate
is transparent to public-signal ordering — it reads and releases the same 32-byte
nullifier already in `signals[1]`. `INFLIGHT_NULLIFIERS` is never stable-persisted
and is cleared on Wasm upgrade; test observability is via `inflight_count_for_test`
(testing-feature-only).

---

## 4. Per-Signal Binding

### 4.1 `anchor` (index 0)

**Semantic meaning:** the Merkle root the input note is proven to be a member of.

**Private inputs bound:** `spend_key`, `in_value`, `in_rho`, `in_rseed`,
`path_elements[0..31]`, `path_indices[0..31]`.

**Binding mechanism (indirect — full chain):** the anchor is the output of a
32-level Merkle proof rooted at the input-note commitment:

```
derived_pk = Poseidon(spend_key, PK_DOMAIN=1)
in_commit.commitment = Poseidon(domain_sep, in_value, derived_pk, in_rho, in_rseed, COMMITMENT_DOMAIN=3)
merkle.leaf <== in_commit.commitment
[32 levels of Poseidon(2) hashing along path_elements / path_indices]
anchor === merkle.root
```

`derived_pk` is wired directly into `in_commit`, closing the ownership gap: the
Merkle leaf is definitionally the input-note commitment derived from the prover's
`spend_key`.

**Pool-side extraction:** `anchor = args.envelope.root_reference` (signal[0]).

**Pre-verification check:** `is_accepted_anchor` — local read of the pool's
`ACCEPTED_SPEND_ROOTS` allow-list (no Merkle-canister call; the Merkle ring buffer
`ROOT_HISTORY` is not an anchor source).
**Post-verification re-check:** anchor re-validated against `ACCEPTED_SPEND_ROOTS`
after the async verifier call.

**Attack prevented:** without this binding a prover could substitute any
historical or foreign-pool root to construct a proof against a different leaf set.
The binding forces the anchor to be the root of the specific tree containing the
input-note commitment derived from the prover's `spend_key`. Cross-deployment
replay is additionally prevented by `domain_sep` (§9).

---

### 4.2 `nullifier_hash` (index 1)

**Semantic meaning:** the unique spend tag for the input note. Once recorded, the
note cannot be spent again.

**Private inputs bound:** `spend_key`, `in_commitment` — and therefore, transitively,
the whole note: `in_value`, `derived_pk`, `in_rho`, `in_rseed`.

**Binding mechanism (direct equality):**

```
nullifier_hash === Poseidon(4)[domain_sep, spend_key, in_commitment, NULLIFIER_DOMAIN=2]
```

**DEF-109-A (full-note binding):** the third Poseidon input is the input note's
COMMITMENT (`in_commit.commitment`, which already binds `in_value`, `derived_pk`,
`in_rho`, `in_rseed`), not the bare `in_rho`. This closes DEF-109: two otherwise-valid
notes sharing `(spend_key, in_rho)` but differing in `in_value`/`in_rseed` have distinct
commitments and therefore distinct nullifiers, so spending one no longer bricks the
other. Because `in_commitment` transitively includes `in_rho`, substituting a different
nullifier still breaks the commitment binding and the Merkle membership proof at once.

**Domain separation:**
- `NULLIFIER_DOMAIN = 2` (within-deployment purpose separation — prevents a
  nullifier colliding with a commitment (`COMMITMENT_DOMAIN = 3`) or a
  `derived_pk` (`PK_DOMAIN = 1`)).
- **DEF-035 cross-deployment prefix:** `domain_sep` is prepended as the **first**
  Poseidon input, binding the nullifier to **one tuple of compiled domain constants**.
  `domain_sep` is a circuit constant, not a public signal — the signal schema is
  unchanged. See §9 and `POSEIDON_PARAMS.md` §Domain Separation (DEF-035).
  **AR1-12 — the retracted claim.** This bullet previously said a proof "cannot be
  replayed on another deployment sharing the same VK". That is withdrawn as
  self-defeating: sharing a VK means sharing the compiled circuit and therefore the
  same baked `domain_sep`, so the constant cannot separate those two deployments —
  and deployments whose constants differ have different VKs, already separated by the
  pool's `verifying_key_hash` envelope check. What it does separate is deployments or
  version bumps **whose compiled tuple differs**; it gives no separation across a
  reinstall under the same principal, asset, circuit version and network. See
  `PUBLIC_SIGNALS_SCHEMA.md` §Signal 1, which carries the full statement — this
  bullet is the twin of that text and moves with it (ARCHITECTURE.md law #6).

**Pool-side extraction:** `nullifier = args.nullifiers[0]` (signal[1]).
**Pre-verification:** intra-batch duplicate check + `contains_nullifiers_batch` on the
registry. **Post-verification re-check:** nullifiers re-checked after the await.

**Mutation (A2 stage-before-finalize):** after successful verification and
rechecks, nullifiers are first reserved in the heap-only INFLIGHT gate, then
reserved locally (`NullifierReserved`). Outputs are STAGED in `PENDING_OUTPUTS`
(`OutputsStaged`) — NOT yet in the Merkle tree. The nullifier is then permanently
inserted into the registry; only AFTER that finality are the staged outputs
promoted to the active Merkle tree. See §6.5.

**Attack prevented:** without this binding a prover could substitute a different
nullifier to double-spend a note (two nullifiers for one note) or spend without
invalidating the correct note.

---

### 4.3 `output_merkle_leaf_1` (index 2)  — DEF-111 (was `output_commitment_1`)

**Semantic meaning:** the **value-bound outer Merkle leaf** of the first output note.
DEF-111 / B-prime changed this signal from the inner note commitment to
`MerkleLeaf(out_value_1, inner_commitment_1)` so Merkle membership binds the note's
spendable value. Promoted to the Merkle tree (as the leaf) after nullifier finality.

**Private inputs bound:** `out_value_1`, `out_recipient_pk_1`, `out_rho_1`,
`out_rseed_1` (via the inner commitment) **plus `out_value_1` directly in the leaf**.

**Binding mechanism (direct equality):**

```
output_merkle_leaf_1 === Poseidon(3)[out_value_1, inner_commitment_1, MERKLE_LEAF_DOMAIN=4]
  where inner_commitment_1 = Poseidon(6)[domain_sep, out_value_1, out_recipient_pk_1,
                                         out_rho_1, out_rseed_1, COMMITMENT_DOMAIN=3]
```
The inner commitment is a private circuit intermediate. `domain_sep` is omitted from
the outer leaf (Poseidon(3), tag last) because the inner commitment already binds it
(DEF-111 0b ruling). The leaf hash MUST byte-match `stsh_field_utils::merkle_leaf`
(pool) and `wallet notes.ts` (leaf-agreement checkpoint).

**DEF-035 cross-deployment prefix:** every note commitment (the input note and
both outputs, via the shared `NoteCommitment` template) prepends `domain_sep` as
the **first** Poseidon input, so a commitment from one deployment is not valid in
another's Merkle tree. Applies identically to `output_commitment_2`. `domain_sep`
is a circuit constant, not a public signal. See §9 and `POSEIDON_PARAMS.md`.

**Recipient-pk note:** `out_recipient_pk_1` is prover-supplied (the sender chooses
who receives the output note). The circuit does not verify it is a valid public
key for any identity — a note sent to a wrong/random pk is unspendable. Recipient
pk correctness is a wallet-layer concern.

**Pool-side extraction:** `oc1 = args.output_commitments[0]` (signal[2]).

**Pool staging + promotion (A2):** `output_commitment_1` is first STAGED in
`PENDING_OUTPUTS`, and is appended to the active Merkle tree (via the atomic
`append_commitments` call) ONLY AFTER the parent nullifier is permanently inserted
into the registry (promotion). Under this stage-before-finalize ordering a failed
nullifier insert leaves no orphan output in the tree (closes QA-DEF-034). See §6.5.

**Attack prevented:** without this binding a prover could submit a valid proof but
substitute a different output commitment — redirecting note value or inflating an
embedded value. The direct equality constraint forces the commitment to be exactly
the Poseidon hash of the private values used in the proof.

---

### 4.4 `output_merkle_leaf_2` (index 3)  — DEF-111 (was `output_commitment_2`)

**Semantic meaning:** the value-bound outer Merkle leaf of the second output note.
May encode a zero value (empty change note).

**Private inputs bound:** `out_value_2`, `out_recipient_pk_2`, `out_rho_2`,
`out_rseed_2` (via the inner commitment) plus `out_value_2` directly in the leaf.

**Binding mechanism (direct equality):**

```
output_merkle_leaf_2 === Poseidon(3)[out_value_2, inner_commitment_2, MERKLE_LEAF_DOMAIN=4]
  where inner_commitment_2 = Poseidon(6)[domain_sep, out_value_2, out_recipient_pk_2,
                                         out_rho_2, out_rseed_2, COMMITMENT_DOMAIN=3]
```

**Zero-value notes:** `out_value_2 = 0` is explicitly permitted (valid empty
change note); the leaf is still a nonzero domain-separated hash. All pool checks,
staging, and promotion are identical to `output_merkle_leaf_1`; both leaves are
promoted together.

**Attack prevented:** substituting a leaf, or (DEF-111) committing a note whose
spendable value exceeds the escrowed amount — the value is now bound into membership.

---

### 4.5 `public_amount` (index 4)

**Semantic meaning:** the net public STSH value leaving the shielded pool. `0`
for a pure private transfer; `> 0` for a specific-amount public payout.

**Private inputs bound:** all value signals indirectly — via the balance equation.

**Binding mechanism (indirect — linear R1CS constraint):**

```
Range check:   public_amount ∈ [0, MAX_NOTE_VALUE]   (LessThan(37), MAX_NOTE_VALUE = 10^11)
Value balance: in_value === out_value_1 + out_value_2 + fee + public_amount
```

Linear constraints are enforced by Groth16 with the same soundness as Poseidon
gates. The balance equation prevents `public_amount` substitution because
`in_value` is fixed by the input-note commitment, and the output values are
committed via signals 2–3. `LessThan(37)` (internally `Num2Bits(38)`) also
prevents Fr-wraparound attacks on near-modulus values.

**Pool assembly:** `pub_amount = u128_to_fr_le(private_spend_public_amount(args))`.
For a public payout the pool checks `public_amount` against the `icrc1_transfer`
amount to the recipient; for a pure transfer it is `0`.

> **DEF-045 — `public_amount` is intentionally NOT denomination-constrained.** The
> fixed `DENOMINATIONS = [1_000, 10_000, 100_000, 1_000_000, 10_000_000] STSH` set (ARCHITECTURE.md Law #1) is
> enforced only for `shield_deposit` (`withdraw` takes a custom `gross_withdraw_amount`;
> fixed-denomination withdraw is a design option, not implemented — ARCHITECTURE.md law 1). A `private_spend`'s
> `public_amount` is deliberately flexible — any value ≤ the spender's shielded
> balance — to support a "specific-amount exit." A non-standard payout amount is a
> unique on-chain fingerprint; this is a documented design choice, not a defect.

**Attack prevented:** without the balance constraint a prover could claim a
`public_amount` larger than the input note value, inflating the exit amount.

---

### 4.6 `fee` (index 5)

**Semantic meaning:** protocol fee paid by the spend, in base STSH units. `fee`
must equal the governance-quoted `protocol_private_spend_fee_stsh`
(`PrivateSpendFeeMismatch` otherwise); the launch value is the
`MAINNET_LAUNCH_SPEND_FEE_E8S` constant, applied by the scripted bootstrap
(MAINNET_DEPLOYMENT.md) — nonzero, not restated here. `SpendFeeNotSupported` is a
deprecated Candid variant.

**Private inputs bound:** same as `public_amount` — indirectly, via the balance
equation (`LessThan(37)` range check + value balance).

**Fee governance interaction:** the circuit-level binding works with pool-side fee
policy. Pre-verification: `args.fee` must equal `fee_preview.total_fee` from the
current `GovernanceFeeParams`. Post-verification: the fee quote is re-validated
after the async verifier await in case governance updated parameters during the
call. See `docs/STSH_FEE_POLICY.md`.

**Pool assembly:** `fee = u128_to_fr_le(args.fee)` — the u128 occupies the low 16
bytes of a 32-byte LE Fr element; `u128::MAX ≪` the BN254 scalar prime, so no
modular reduction occurs.

**Attack prevented:** without the balance constraint a prover could underpay the
fee by substituting a lower `fee` signal. Pool-side checks additionally prevent a
caller from reaching the verifier with a mismatched fee.

---

### 4.7 `recipient_principal` (index 6, DEF-026)

**Semantic meaning:** the destination principal of the optional public payout.

**Encoding (DEF-108):** principal raw bytes (≤29) into `bytes[0..len]`, with
`byte[31] = len` committing the principal length and the rest zero, interpreted as a
little-endian field element. The length byte makes the encoding **injective** — principals
differing only by trailing zero bytes (`[0x04]` vs `[0x04, 0x00]`) no longer collide.
`len ≤ 29` (`0x1D`) as the top byte keeps it canonical (`< p`, top byte `0x30`).
`public_payout = None` ⇒ this signal is `0` (and `public_amount` is also `0`).

**Binding mechanism (membership + explicit DEF-112 constraint):** signals 6–8
are declared in `component main { public [...] }`, so they enter the verifying
key's `gamma_abc_g1` (IC) vector and are bound by the pairing. **DEF-112** additionally
adds an explicit in-circuit constraint (`spend.circom` "Constraint 5c": each recipient
signal is squared into an internal `*_bind` signal — a non-vacuous quadratic that forces
the signal into the R1CS, +3 non-linear constraints at `--O2`), so the binding no longer
rests only on the implicit membership property. The signals remain FREE public inputs
(the all-zero no-payout encoding is unchanged; they are not constrained to any value).
Substituting the principal invalidates the proof under either mechanism.

**Pool-side enforcement:** the pool re-derives signals 6–8 from
`args.public_payout` via `encode_recipient_signals` (None → all zeros), passes
them to the verifier, and **re-checks `signals[6..8]` against the call's payout
after a successful verification** (defence in depth) — before any irreversible
spend effect (nullifier finality, active Merkle promotion, accounting, public
payout). See §5 and §6.

**Attack prevented:** the substitution vector confirmed in DEF-026 — a privileged
actor replaying a valid proof with a different payout recipient. Both the pairing
and the post-verify recheck block it.

---

### 4.8 `recipient_subaccount_lo` (index 7, DEF-026)

**Semantic meaning:** the low 16 bytes of the 32-byte ICRC subaccount of the
payout destination.

**Encoding:** `destination_subaccount[0..16]` interpreted as a little-endian
u128, encoded as that u128 in a 32-byte little-endian field element. `None`
subaccount / `None` payout ⇒ `0`. Canonical by construction (128 bits `< p`).

**Binding mechanism:** membership in the proof (VK IC vector) **+ explicit DEF-112
in-circuit constraint**, as for §4.7. **Pool-side enforcement:** re-derived via
`encode_recipient_signals`; post-verify recheck.

---

### 4.9 `recipient_subaccount_hi` (index 8, DEF-026)

**Semantic meaning:** the high 16 bytes of the 32-byte ICRC subaccount.

**Encoding:** `destination_subaccount[16..32]` interpreted as a little-endian
u128, encoded as that u128 in a 32-byte little-endian field element. `None` ⇒ `0`.
Canonical by construction.

**Binding mechanism:** membership in the proof (VK IC vector) **+ explicit DEF-112
in-circuit constraint**. **Pool-side enforcement:** re-derived via
`encode_recipient_signals`; post-verify recheck.

The 32-byte ICRC subaccount is split into two 128-bit halves so the **full**
subaccount space round-trips with no single-field truncation. Together signals
6–8 bind the exact `(owner, subaccount)` of the payout.

---

## 5. Value Conservation, Range Constraints, and Recipient Re-check

**Range check (per value signal):** `in_value`, `out_value_1`, `out_value_2`,
`fee`, `public_amount` each pass `LessThan(37)` against `MAX_NOTE_VALUE + 1`
(`MAX_NOTE_VALUE = 10^11 = 1000 STSH`). `LessThan(37)` uses `Num2Bits(38)` on the
difference, which enforces the business bound, prevents Fr-wraparound, and allows
zero (change/dummy notes). After range-checking, the sum of value terms is at most
`4 × 10^11 ≪ 2^37 ≪` the Fr modulus, so the balance arithmetic cannot overflow.

**Balance equation (single linear R1CS constraint):**
`in_value === out_value_1 + out_value_2 + fee + public_amount`. Linear constraints
are enforced by Groth16 at the same soundness as any non-linear gate.

**Recipient binding re-check (post-verification, DEF-026):** as defense-in-depth
(independent of the DEF-112 in-circuit binding), the pool re-derives the
`recipient_principal` and the two subaccount halves from `args.public_payout` and
asserts equality with
`signals[6..8]` after a successful verification and **before** any irreversible
spend effect. A verifier that ever accepted a mismatch still cannot redirect the
payout.

---

## 6. Pool-Side Signal Extraction and Validation

### 6.1 Signal assembly

`build_spend_public_signals` (`shielded-pool/src/lib.rs`) assembles all **9**
signals from `PrivateSpendArgs` before the verifier is called:

```rust
fn build_spend_public_signals(args: &PrivateSpendArgs) -> Result<[[u8; 32]; 9], PoolError> {
    // Shape enforcement — 1 nullifier, 2 output commitments
    if args.nullifiers.len() != 1 || args.output_commitments.len() != 2 {
        return Err(PoolError::MalformedSpendArgs);
    }

    let anchor     = args.envelope.root_reference;                    // signal[0]
    let nullifier  = args.nullifiers[0];                              // signal[1]
    let oc1        = args.output_commitments[0];                      // signal[2]
    let oc2        = args.output_commitments[1];                      // signal[3]
    let pub_amount = u128_to_fr_le(private_spend_public_amount(args)?); // signal[4]
    let fee        = u128_to_fr_le(args.fee);                         // signal[5]

    // #116: reject any caller-supplied signal whose bytes are >= the BN254 Fr modulus.
    for (sig, label) in [(&anchor,"anchor"), (&nullifier,"nullifier_hash"),
                         (&oc1,"output_commitment_1"), (&oc2,"output_commitment_2")] {
        if !is_canonical_fr_le(sig) {
            return Err(PoolError::ProofRejected(format!("NonCanonicalSignal: {label}")));
        }
    }

    // DEF-026: signals [6],[7],[8] bind the public-payout recipient (None -> zeros).
    let (recipient_principal, recipient_subaccount_lo, recipient_subaccount_hi) =
        encode_recipient_signals(args.public_payout.as_ref());

    Ok([anchor, nullifier, oc1, oc2, pub_amount, fee,
        recipient_principal, recipient_subaccount_lo, recipient_subaccount_hi])
}
```

Each signal is a `[u8; 32]` little-endian BN254 Fr element. `public_amount` and
`fee` are encoded by `u128_to_fr_le` (u128 in the low 16 bytes, 16 zero bytes of
padding). The recipient signals are produced by `encode_recipient_signals` and are
canonical by construction, so they are not added to the #116 loop.

### 6.2 VK and envelope pin check

`verify_proof_envelope` checks the `ProofEnvelope` before signals are sent:
- `env.circuit_version == PINNED_CIRCUIT_VERSION` → else `CircuitVersionMismatch`
- `env.verifying_key_hash == PINNED_VK_HASH` → else `VerifyingKeyMismatch`
- `env.pool_version == PINNED_POOL_VERSION` → else `PoolVersionMismatch`

This prevents a caller directing a proof at a different VK — one compiled for a
circuit with different or absent signal constraints.

### 6.3 Pre-verification checks

`precheck_private_spend_before_verify`:

| Check | Signal | Pool error |
|---|---|---|
| `is_accepted_anchor` — root in `ACCEPTED_SPEND_ROOTS` | `anchor` (0) | `AnchorNotFound` |
| Intra-batch duplicate nullifier | `nullifier_hash` (1) | `NullifierAlreadySpent` |
| `contains_nullifier` / `contains_nullifiers_batch` — nullifier registry | `nullifier_hash` (1) | `NullifierAlreadySpent` |
| `PRIVATE_LIABILITY >= fee` | `fee` (5) | `InsufficientPrivateLiability` |

### 6.4 Post-verification re-checks

`recheck_private_spend_after_verify`. The verifier call is an async await; other
update calls may have mutated shared state in the interval, so all pre-checks are
re-run: anchor still in `ACCEPTED_SPEND_ROOTS`; nullifiers still unspent; fee quote unchanged;
`PRIVATE_LIABILITY >= fee`; spend record still `VerificationPending`; and the
**recipient signals 6–8 re-check** against `args.public_payout` (§5).

### 6.5 Mutation sequence (A2 stage-before-finalize, QA-DEF-034/036)

`commit_private_spend`:

1. **15-pre** — Reserve nullifiers in the heap-only `INFLIGHT_NULLIFIERS` gate;
   `FailedBeforeStateChange` on conflict (concurrent spend, same nullifier).
2. **15a** — Reserve nullifiers locally (`NullifierReserved`) — first irreversible
   mutation.
3. **15a′** — **Stage** `output_commitment_1` and `output_commitment_2` durably in
   `PENDING_OUTPUTS` (`OutputsStaged`). They are **NOT** in the active Merkle tree,
   not spendable, and no accepted root references them.
4. **15d** — Permanently insert nullifiers into the registry. On success
   (`NullifierFinalizedOutputsPending`) the heap reservation is released — the
   registry is now the source of truth.
5. **Promotion** — `promote_finalized_outputs`: write `ActiveAppendInFlight`, then
   a single atomic `append_commitments` call promotes the staged outputs to the
   active Merkle tree. On success: accept the resulting root into
   `ACCEPTED_SPEND_ROOTS` (`ActiveRootPending → RootAccepted`), apply accounting
   (debit `fee` from `PRIVATE_LIABILITY`, credit reserves), then any public payout,
   then `Finalized`.

**A2 inversion:** the parent nullifier is finalized **before** any Merkle append,
so the active tree only ever contains finalized commitments. A definite append
rejection discards the staged outputs (`FailedAfterOutputsStaged`) — there are
**no orphan output leaves** (closes QA-DEF-034). Recovery from a transport-unknown
nullifier insert (`NullifierInsertUnknown`) or a transport-unknown / rejected
append (`ActiveAppendUnknown` / `ActiveAppendRejected`) is roll-forward only via
`reconcile_nullifier_insert` / `reconcile_pending_spend`; the finalized nullifier
is never rolled back (closes QA-DEF-036).

> This flow is **stage-then-promote** (stage-before-finalize): output commitments
> are staged before finality and promoted to the active tree only after the
> nullifier is finalized. (ARCHITECTURE.md Law #3 names this "stage-before-finalize".)
> The older ordering — appending outputs to the active Merkle tree *before* the
> nullifier is inserted — created orphan, independently spendable outputs on insert
> failure (the closed QA-DEF-034 defect) and must not be reintroduced.

---

## 7. Verifier-Side Signal Count Enforcement

`canisters/verifier/src/lib.rs`:

**Candid interface** (`verify_spend_canister`):
- Input: `proof_bytes: Vec<u8>` (exactly 256 bytes), `signals: Vec<Vec<u8>>`.
- `signals.len() != 9` → `Err("expected 9 public signals, got N")`.
- Each `signals[i].len() != 32` → `Err("signal[i] must be 32 bytes, got N")`.
- `proof_bytes.len() != 256` → `Err("proof_bytes must be 256 bytes, got N")`.

**`gamma_abc_g1.len() == 10` check:**

```rust
let n_ic = pvk.vk.gamma_abc_g1.len();
if n_ic != 10 {
    return Err(VerifierError::ParseError(format!(
        "VK binding mismatch: expected gamma_abc_g1.len()==10 (9 public signals + 1), got {}",
        n_ic,
    )));
}
```

`gamma_abc_g1.len() == number_of_public_inputs + 1` by the Groth16 construction
(the `+1` is the constant/base term). A VK compiled for a different public-signal
count is rejected before any pairing computation, preventing silent signal
mis-mapping.

**Signal encoding** (`parse_public_inputs`):

```rust
pub fn parse_public_inputs(signals: &[[u8; 32]; 9]) -> Result<[Fr; 9], VerifierError> {
    let mut out = [Fr::default(); 9];
    for (i, s) in signals.iter().enumerate() {
        if !is_canonical_fr_le(s) {
            return Err(VerifierError::ParseError(format!(
                "signal[{i}]: non-canonical Fr bytes (value >= BN254 Fr modulus)")));
        }
        out[i] = Fr::from_le_bytes_mod_order(s);
    }
    Ok(out)
}
```

Each 32-byte signal is first checked for canonical encoding via `is_canonical_fr_le`
(#116) — defence in depth, since non-canonical signals are also rejected earlier by
`build_spend_public_signals` at the pool layer (§3, #116 note).

**Proof byte layout** (256 bytes — see `SNARKJS_TO_CANDID_ENCODING.md`):

```
[  0.. 64)  G1 pi_a:  x_LE(32) || y_LE(32)
[ 64..192)  G2 pi_b:  x.c0_LE(32) || x.c1_LE(32) || y.c0_LE(32) || y.c1_LE(32)
[192..256)  G1 pi_c:  x_LE(32) || y_LE(32)
```

All coordinates are 32-byte little-endian Fq (base field). G2 uses c0-first
coefficient ordering.

**Relationship between Groth16 verification and circuit binding:** the verification
equation is a pairing check `e(pi_a, pi_b) == e(alpha, beta) · e(L, gamma) · e(pi_c, delta)`,
where `L` is a linear combination of the `gamma_abc_g1` points weighted by the
public-input field elements. Changing any public signal changes `L`, changing the
left-hand side, failing the equation — unless the prover can re-forge the proof
(requires the trusted-setup toxic waste: computationally infeasible).

---

## 8. Attack Model

| Signal | Attack without binding | Preventing constraint(s) | Additional pool check |
|---|---|---|---|
| `anchor` (0) | Substitute a historical / foreign-pool root to include a note not in current state | `anchor === merkle.root` through spend_key → derived_pk → in_commit → Merkle path; `domain_sep` for cross-deployment | `is_accepted_anchor` (`ACCEPTED_SPEND_ROOTS`); post-await re-check |
| `nullifier_hash` (1) | Substitute a different nullifier to double-spend | `nullifier_hash === Poseidon(4)[domain_sep, spend_key, in_commitment, NULLIFIER_DOMAIN]` (DEF-109-A); `in_commitment` binds the whole note | nullifier-not-spent; post-await re-check |
| `output_commitment_1` (2) | Substitute a commitment for a different recipient pk / value | `=== Poseidon(6)[domain_sep, out_value_1, pk_1, rho_1, rseed_1, COMMITMENT_DOMAIN]` | staged then promoted after nullifier finality (§6.5) |
| `output_commitment_2` (3) | Same as above for the second output | `=== Poseidon(6)[domain_sep, out_value_2, ...]` | §6.5 |
| `public_amount` (4) | Inflate the exit amount beyond the input note value | Balance equation + `LessThan(37)` range | Matched against the `icrc1_transfer` payout amount |
| `fee` (5) | Underpay the protocol fee | Balance equation + range check | `args.fee == fee_preview.total_fee` (pre + post) |
| `recipient_principal` (6) | Replay a proof with a substituted payout principal | Membership in proof (VK IC vector) | Post-verify recheck of `signals[6]` vs `args.public_payout` (DEF-026) |
| `recipient_subaccount_lo` (7) | Substitute the low half of the payout subaccount | Membership in proof (VK IC vector) | Post-verify recheck of `signals[7]` (DEF-026) |
| `recipient_subaccount_hi` (8) | Substitute the high half of the payout subaccount | Membership in proof (VK IC vector) | Post-verify recheck of `signals[8]` (DEF-026) |
| Proof replay | Reuse a valid proof with different public signals | Groth16 `gamma_abc_g1` pairing — any signal change invalidates the equation | VK pin: `env.verifying_key_hash == PINNED_VK_HASH` |
| VK substitution | Supply a proof valid for a weaker circuit with fewer/absent signal constraints | `gamma_abc_g1.len() == 10` check (verifier) | VK governance: timelock + quorum on activation |

---

## 9. Domain Separation Constants

**Within-deployment purpose separation** (hard-coded in the R1CS; changing them
requires recompilation and a new trusted setup):

| Constant | Value | Used in | Prevents |
|---|---|---|---|
| `PK_DOMAIN` | 1 | `Poseidon(spend_key, PK_DOMAIN)` → `derived_pk` | `derived_pk` colliding with nullifiers/commitments |
| `NULLIFIER_DOMAIN` | 2 | nullifier preimage (last input) | nullifier colliding with commitments/pks |
| `COMMITMENT_DOMAIN` | 3 | commitment preimage (last input) | commitments colliding with nullifiers/pks |

**Cross-deployment domain separation (DEF-035)** — layered on top of the above. A
deployment-binding domain hash is prepended as the **first** Poseidon input of the
nullifier and every note commitment:

```
domain_sep = Poseidon(4)[DOMAIN_POOL_CANISTER_ID, DOMAIN_ASSET_ID,
                         DOMAIN_CIRCUIT_VERSION, DOMAIN_NETWORK_ID]
```

Current values (A1 mainnet principal injection, PR #32, 2026-07-07 — this is the
ceremony circuit):

```
DOMAIN_POOL_CANISTER_ID = 4523128485832663883733241601901871400518358776001584537534818377974931259392
                              (ohspu-zqaaa-aaaad-qmasq-cai, mainnet shielded_pool,
                               encoded per the DEF-108 principal→Fr rule — final)
DOMAIN_ASSET_ID         = 0   (STSH native token — final)
DOMAIN_CIRCUIT_VERSION  = 3   (circuit-finalization revision — bumped 2->3 at A6.6)
DOMAIN_NETWORK_ID       = 1   (ICP mainnet — final)
```

The resulting mainnet `domainHash` — the domain separator the production VK **will**
commit to (**A-4, 2026-09-12**: the VK shipped today IS the launch VK
`84dba305…c6914`, produced by the mainnet-v2 ceremony — public Hermez phase 1, beacon-finalized
phase 2; the superseded AR1-13 "single-participant DEV VK" reading no longer holds; see
`POSEIDON_PARAMS.md` §Domain Separation) — is recorded canonically in `POSEIDON_PARAMS.md` §Domain Separation
(decimal `17076800395491555068286473339039486071114029588881949545487634475758427007736`,
LE-32 `f86a7fd6a66d358ddbe7d8fa7b303f5da7e63d41b7ee207c6a31359c6220c125`),
independently re-derived and confirmed by the ceremony R1CS structural review
(2026-07-07). The former staging sentinel `2` is historical (pre-A1 dev circuit;
the dev VK built on it is disposable). `domain_sep` is a circuit constant,
**not** a public signal — the public-signal count stays 9 and no Candid envelope
change is needed. See `POSEIDON_PARAMS.md` §Domain Separation (DEF-035).

PK derivation (`Poseidon(spend_key, PK_DOMAIN)`) is **not** cross-deployment
domain-separated — only the nullifier and commitments are. Wallet software **must**
use the same domain constants and `domain_sep` when computing note commitments for
deposits; a wallet using a stale scheme (no `domain_sep`, or the old non-separated
Poseidon arity) produces incompatible commitments that cannot be proven as Merkle
leaves under this circuit.

---

## 10. Status Notes and Known Limitations

- `public_amount` is `0` for pure private spends; for specific-amount public
  payouts it can be any value ≤ the sender's shielded balance — not
  denomination-constrained (DEF-045, §4.5).
- `fee` must equal the governance-quoted `protocol_private_spend_fee_stsh`
  (`PrivateSpendFeeMismatch` otherwise); the launch value is the
  `MAINNET_LAUNCH_SPEND_FEE_E8S` constant, applied by the scripted bootstrap
  (MAINNET_DEPLOYMENT.md) — nonzero, not restated here. `SpendFeeNotSupported` is a
  deprecated Candid variant (`docs/STSH_FEE_POLICY.md`).
- Only single-input spends are supported; multi-input is an M5 extension.

**Not enforced at the circuit level (enforced at the canister layer instead):**

- `asset_id` / `token_canister_id` — not a circuit signal; enforced by the pool's
  VK pin and token-canister reference.
- `circuit_version` — not a circuit signal; enforced by
  `ProofEnvelope.circuit_version` and `PINNED_CIRCUIT_VERSION`.
- `pool_canister_id` — not a circuit signal; cross-deployment binding is provided
  by `domain_sep` (§9) inside the nullifier/commitment preimages.

**Commitment uniqueness model (DEF-092):** Commitments in the STSH Merkle tree
are transaction-scoped, not globally unique by design. A duplicate commitment
produced by two separate deposits of identical parameters would result in an
unspendable "stuck note" — the nullifier is marked spent on first use, and the
second instance of the note cannot be spent (no double-spend, no fund theft).
Global Merkle uniqueness is NOT required for fund safety; the nullifier
mechanism provides the double-spend guarantee independently.

**Trusted setup:** see the warning at the top. This binding analysis is based on
the R1CS constraints as written in `spend.circom`; it is not a substitute for a ZK
engineer audit of the compiled R1CS, the ptau ceremony, or the final
`verification_key.json`.

---

## 11. Test Vectors

- `circuits/poseidon_test.js` — Poseidon hash cross-check.
- `circuits/tests/adversarial.test.js` — invalid-proof rejection vectors.
- `integration-tests/tests/security_tests.rs` — end-to-end spend with a real proof,
  including the DEF-026 recipient-signal tamper vectors (signals 6–8).

The zero-input anchor (all-zeros commitment leaf) is explicitly tested and
confirmed NOT to be a valid anchor post-Poseidon migration.

> Post-DEF-035 canonical Poseidon vectors for the domain hash, nullifier, and
> commitment derivation paths are published by the ZK engineer at **M5** (the
> pre-DEF-035 protocol vectors in `POSEIDON_PARAMS.md` are superseded). Merkle node
> `Poseidon(2)` vectors are unchanged (DEF-039 published vectors).

---

## Appendix A: Constraint Reference

Constraint numbers reference the comment headers in `circuits/spend.circom`:

| Constraint | Description | Public signal(s) |
|---|---|---|
| 1 | Spend key → `derived_pk` derivation | (internal) |
| 2 | Nullifier derivation (`Poseidon(4)` with `domain_sep`) | `nullifier_hash` (1) |
| 3 | Input note commitment (`Poseidon(6)` with `domain_sep`) | (internal, feeds input Merkle leaf) |
| 4 | Merkle membership over `MerkleLeaf(in_value, in_commitment)` (DEF-111 value-bound leaf, `Poseidon(3)`) | `anchor` (0) |
| 5a | Output note 1: inner commitment (`Poseidon(6)`) → `MerkleLeaf(out_value_1, ·)` (`Poseidon(3)`, DEF-111) | `output_merkle_leaf_1` (2) |
| 5b | Output note 2: inner commitment (`Poseidon(6)`) → `MerkleLeaf(out_value_2, ·)` (`Poseidon(3)`, DEF-111) | `output_merkle_leaf_2` (3) |
| 5c | Recipient binding (DEF-112: squaring, +3 non-linear) | `recipient_principal` (6), `recipient_subaccount_lo` (7), `recipient_subaccount_hi` (8) |
| 6 | Range checks on all value signals | `public_amount` (4), `fee` (5) |
| 7 | Value balance equation | `public_amount` (4), `fee` (5) |

Recipient signals 6–8 are bound by membership in the verifying key's IC vector
**and** an explicit DEF-112 in-circuit constraint (Constraint 5c), and are additionally
re-checked by the pool after verification (§4.7–§4.9, §5).
