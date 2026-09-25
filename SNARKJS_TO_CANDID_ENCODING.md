# snarkjs → Candid Proof Encoding

> **Audience:** Anyone integrating snarkjs-generated proofs into the STSH
> ICP canister. Contains the critical G2 coordinate reversal warning.
>
> Circuit: `circuits/spend.circom` (v0.3.0-a0, Groth16/BN254)

---

## TL;DR — G2 Ordering (Verified 2026-06-09)

**snarkjs G2 coefficient ordering matches arkworks. No swap is needed for JSON parsing.**

In snarkjs JSON: `pi_b[0] = [x_c0, x_c1]` — **c0 at index 0**, c1 at index 1.
In arkworks: `Fq2::new(c0, c1)` — c0 first.

Map directly: `Fq2::new(parse_fq(arr[0][0]), parse_fq(arr[0][1]))`.

**Correction from previous version of this document:** an earlier revision stated
snarkjs uses c1-first (`[c1, c0]`). This was wrong. On-curve diagnostics run
2026-06-09 confirmed ordering B (`arr[i][0] = c0`) is correct for all four G2 points
(vk_beta_2 and pi_b both verified). The parser and binary encoding have been corrected.

---

## snarkjs Proof Format

`groth16.fullProve()` returns a `proof` object:

```json
{
  "pi_a": ["x_decimal", "y_decimal", "1"],
  "pi_b": [
    ["x_c0_decimal", "x_c1_decimal"],
    ["y_c0_decimal", "y_c1_decimal"],
    ["1", "0"]
  ],
  "pi_c": ["x_decimal", "y_decimal", "1"],
  "protocol": "groth16",
  "curve": "bn128"
}
```

And a `publicSignals` array (9 entries since DEF-026):
```json
["anchor", "nullifier", "out_commit_1", "out_commit_2", "pub_amount", "fee",
 "recipient_principal", "recipient_subaccount_lo", "recipient_subaccount_hi"]
```

All numeric values are **decimal strings** (BN254 Fr / Fq field elements as base-10 integers).

### Recipient signals 6/7/8 (DEF-026)

The optional public-payout recipient is encoded into the last three signals,
EXACTLY as `shielded_pool::encode_recipient_signals`:

```
signal[6] recipient_principal     = destination.as_slice() (≤29 bytes) into bytes[0..len],
                                    byte[31] = len (DEF-108), rest zero; LE → Fr
signal[7] recipient_subaccount_lo = destination_subaccount[0..16]  as a 128-bit LE field element
signal[8] recipient_subaccount_hi = destination_subaccount[16..32] as a 128-bit LE field element
```

`public_payout = None` ⇒ all three are `"0"` and `public_amount` (signal 4) is `"0"`.
**DEF-108:** `byte[31]` of `recipient_principal` commits the principal length so principals
differing only by trailing zero bytes (e.g. `[0x04]` vs `[0x04, 0x00]`) no longer collide to
the same field element. `len ≤ 29` (`0x1D`) as the most-significant byte keeps the element
canonical (`< p`, whose top byte is `0x30`); each subaccount half is 128 bits, also canonical.
The wallet MUST reproduce this encoding bit-for-bit **including the length byte**; a mismatch
fails verification.

---

## Coordinate Conventions

### G1 points (pi_a, pi_c, and IC entries in verification key)

```
snarkjs: [x_decimal, y_decimal, z_decimal]
  z is always "1" for affine points (projective with Z=1)

arkworks: G1Affine { x: Fq, y: Fq }
  Directly parse x and y; ignore z.
```

**No coordinate swap needed for G1.**

### G2 points (pi_b, vk_beta_2, vk_gamma_2, vk_delta_2)

```
snarkjs (verified 2026-06-09): [[x_c0, x_c1], [y_c0, y_c1], ["1", "0"]]
  c0 at index 0, c1 at index 1.
  z is always ["1", "0"] for affine.

arkworks: G2Affine { x: Fq2::new(c0, c1), y: Fq2::new(c0, c1) }
  c0 comes FIRST in the Fq2 constructor — matches snarkjs index 0.
```

**No swap needed. Map directly:**
```rust
// snarkjs g2_arr = [[x_c0, x_c1], [y_c0, y_c1], ...]
let x = Fq2::new(
    parse_fq(&g2_arr[0][0]),   // c0 = snarkjs index 0  ← direct
    parse_fq(&g2_arr[0][1]),   // c1 = snarkjs index 1  ← direct
);
let y = Fq2::new(
    parse_fq(&g2_arr[1][0]),   // c0 = snarkjs index 0  ← direct
    parse_fq(&g2_arr[1][1]),   // c1 = snarkjs index 1  ← direct
);
// Use new_unchecked + is_on_curve() check to avoid panic — see lib.rs g2_checked()
```

**Verification method used:** On-curve diagnostic (2026-06-09). Both orderings
were tried for vk_beta_2 and pi_b using `G2Affine::new_unchecked` and then
`.is_on_curve()`. Only c0-first (arr[i][0]=c0) produced points on the BN254 G2 curve.

---

## Fr Field Element Encoding

snarkjs public signals are decimal strings. The STSH canister uses 32-byte
little-endian arrays (matching the Rust `merkle_tree` canister).

### Decimal string → little-endian 32-byte array (Rust)

```rust
use num_bigint::BigUint;

fn decimal_str_to_fr_bytes(s: &str) -> [u8; 32] {
    let big = BigUint::parse_bytes(s.as_bytes(), 10)
        .expect("invalid decimal string");
    let mut bytes = big.to_bytes_le();
    // Pad to 32 bytes
    bytes.resize(32, 0);
    bytes.try_into().expect("should be 32 bytes")
}
```

Or using arkworks Fr directly:
```rust
use ark_ff::PrimeField;
use ark_bn254::Fr;

fn decimal_str_to_fr(s: &str) -> Fr {
    let big = BigUint::parse_bytes(s.as_bytes(), 10).unwrap();
    let bytes = big.to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes)
}
```

### Little-endian 32-byte → decimal string (JavaScript wallet side)

```javascript
const { Scalar } = require("ffjavascript");

function leBytesToDecimal(bytes) {
  // bytes is Uint8Array or Buffer, little-endian
  let n = BigInt(0);
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  return n.toString(10);
}
```

---

## Fq Field Element (for G1/G2 coordinates)

G1 and G2 coordinates are Fq (base field) elements, NOT Fr (scalar field).
The BN254 Fq modulus is different from Fr:
```
Fq modulus q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
Fr modulus p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

For G1/G2 coordinate parsing in Rust:
```rust
use ark_bn254::Fq;
use ark_ff::PrimeField;

fn decimal_str_to_fq(s: &str) -> Fq {
    let big = BigUint::parse_bytes(s.as_bytes(), 10).unwrap();
    let bytes = big.to_bytes_le();
    Fq::from_le_bytes_mod_order(&bytes)
}
```

---

## Verification Key Format (snarkjs)

`snarkjs zkey export verificationkey` produces `verification_key.json`:

```json
{
  "protocol": "groth16",
  "curve": "bn128",
  "nPublic": 9,
  "vk_alpha_1": ["x", "y", "1"],
  "vk_beta_2":  [["x_c0", "x_c1"], ["y_c0", "y_c1"], ["1", "0"]],
  "vk_gamma_2": [["x_c0", "x_c1"], ["y_c0", "y_c1"], ["1", "0"]],
  "vk_delta_2": [["x_c0", "x_c1"], ["y_c0", "y_c1"], ["1", "0"]],
  "vk_alphabeta_12": [[["a00","a01"],["a10","a11"],["a20","a21"]], [...]],
  "IC": [["x0","y0","1"], ["x1","y1","1"], ..., ["x9","y9","1"]]
}
```

`nPublic = 9` for the STSH spend circuit (anchor, nullifier_hash,
output_merkle_leaf_1, output_merkle_leaf_2, public_amount, fee, recipient_principal,
recipient_subaccount_lo, recipient_subaccount_hi — the last three added by DEF-026).
Signals 2/3 are the DEF-111 value-bound outer Merkle leaves
(`Poseidon(3)[out_value_i, inner_commitment_i, MERKLE_LEAF_DOMAIN=4]`), NOT the inner
note commitments; the pool appends them to the tree verbatim (proof-verified). The
9-signal order and per-signal encoding (decimal string → 32-byte LE) are unchanged.

> `public_amount` and `fee` are free `u128` amount fields (decimal string → 32-byte LE → `u128`),
> not codes or enums. In particular `public_amount` is **not** denomination-constrained: the fixed
> `DENOMINATIONS = [1_000, 10_000, 100_000, 1_000_000, 10_000_000] STSH` set applies only to `shield_deposit` (`withdraw` takes a
> custom `gross_withdraw_amount` — ARCHITECTURE.md law 1),
> whereas a `private_spend`'s `public_amount` is a flexible specific-amount payout (DEF-045 — see
> `PUBLIC_SIGNALS_SCHEMA.md` Signal 4 and `PUBLIC_SIGNALS_BINDING.md`).

`IC` has `nPublic + 1 = 10` entries (IC[0] is the offset point). The verifier asserts
`gamma_abc_g1.len() == 10`.

**G2 parsing required for:** `vk_beta_2`, `vk_gamma_2`, `vk_delta_2` and `pi_b`.
**G1 parsing (simpler, single Fq pair):** `vk_alpha_1`, each `IC[i]`, `pi_a`, `pi_c`.
Note: "G2 parsing" means the Fq2 coordinate handling described above — there is NO c0/c1 swap.

---

## ProofEnvelope Candid Type

The STSH canister receives proofs as a `ProofEnvelope`:

```candid
type ProofEnvelope = record {
    circuit_version    : nat32;  // matches active VK circuit version; nat32 not text
    proof_system_id    : text;
    verifying_key_hash : blob;   // 32-byte SHA-256 of canonical VK JSON
    root_reference     : blob;   // 32-byte LE anchor (= public signal 0)
    pool_version       : nat32;
    proof_bytes        : blob;   // serialized proof (see below)
};
```

### proof_bytes Serialization

`proof_bytes` is a compact binary encoding of the snarkjs proof.
Recommended format (little-endian, no length prefixes):

```
[  64 bytes ] G1 pi_a  : x (32 LE) || y (32 LE)
[ 128 bytes ] G2 pi_b  : x_c0 (32 LE) || x_c1 (32 LE) || y_c0 (32 LE) || y_c1 (32 LE)
[  64 bytes ] G1 pi_c  : x (32 LE) || y (32 LE)
[ 256 bytes total ]
```

**Note for pi_b:** Store `x_c0` before `x_c1` in the binary encoding (canonical arkworks
order). snarkjs JSON already has c0 at index 0, so copy order directly — no reordering needed.

Public signals are NOT included in `proof_bytes` — they are carried by
`PrivateSpendArgs` (nullifiers, output commitments, fee, public payout) for
`private_spend`; `withdraw` cannot bind the nine signals and is fail-closed
(`reject_unbound_withdrawal_proof`) until the proof-bound withdraw lane.

### Rust: Parsing proof_bytes

```rust
use ark_bn254::{Bn254, G1Affine, G2Affine, Fq, Fq2};
use ark_groth16::Proof;
use ark_serialize::CanonicalDeserialize;

fn parse_g1(bytes: &[u8]) -> G1Affine {
    assert_eq!(bytes.len(), 64);
    let x = Fq::from_le_bytes_mod_order(&bytes[0..32]);
    let y = Fq::from_le_bytes_mod_order(&bytes[32..64]);
    G1Affine::new(x, y)
}

fn parse_g2(bytes: &[u8]) -> G2Affine {
    assert_eq!(bytes.len(), 128);
    // Stored as: x_c0 || x_c1 || y_c0 || y_c1 (canonical order)
    let x_c0 = Fq::from_le_bytes_mod_order(&bytes[0..32]);
    let x_c1 = Fq::from_le_bytes_mod_order(&bytes[32..64]);
    let y_c0 = Fq::from_le_bytes_mod_order(&bytes[64..96]);
    let y_c1 = Fq::from_le_bytes_mod_order(&bytes[96..128]);
    G2Affine::new(Fq2::new(x_c0, x_c1), Fq2::new(y_c0, y_c1))
}

fn parse_proof(proof_bytes: &[u8]) -> Proof<Bn254> {
    assert_eq!(proof_bytes.len(), 256);
    // BN254 Groth16 proof byte layout (256 bytes total):
    //   pi_a: bytes [0..64)    G1  (x: 0..32,   y: 32..64)
    //   pi_b: bytes [64..192)  G2  (x.c0: 64..96,  x.c1: 96..128,
    //                               y.c0: 128..160, y.c1: 160..192)  — c0-first
    //   pi_c: bytes [192..256) G1  (x: 192..224, y: 224..256)
    Proof {
        a: parse_g1(&proof_bytes[0..64]),
        b: parse_g2(&proof_bytes[64..192]),   // 128 bytes, G2 c0-first
        c: parse_g1(&proof_bytes[192..256]),
    }
    // Illustrative: production code must subgroup-check all three elements
    // (new_unchecked + is_on_curve / correct-subgroup) and return Err, not assert.
    // ENFORCED IN CODE (DEF-113): canisters/verifier g1_checked / g2_checked run
    // is_on_curve() AND is_in_correct_subgroup_assuming_on_curve(), returning
    // VerifierError::ParseError("... not in prime-order subgroup") on failure — so
    // pi_a/pi_b/pi_c are all subgroup-checked at parse time, not merely required.
}
```

For reference — `proof_bytes` layout (**256 bytes** total):
```
[ 64 bytes ] G1 pi_a  : bytes [0..64]
[128 bytes ] G2 pi_b  : bytes [64..192]
[ 64 bytes ] G1 pi_c  : bytes [192..256]
[256 bytes total]
```

---

## JavaScript Wallet: snarkjs → proof_bytes

```javascript
function encodeProofBytes(proof) {
  // proof is the object returned by groth16.fullProve()
  function frToLE(decimal_str) {
    let n = BigInt(decimal_str);
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = Number(n & 0xFFn);
      n >>= 8n;
    }
    return bytes;
  }

  // G1: parse [x, y, "1"] → 64 bytes (x LE || y LE)
  function encodeG1(arr) {
    return Buffer.concat([frToLE(arr[0]), frToLE(arr[1])]);
  }

  // G2: parse [[x_c0, x_c1], [y_c0, y_c1], ...] → 128 bytes
  // snarkjs arr[i][0]=c0, arr[i][1]=c1 — matches binary layout directly, no swap.
  function encodeG2(arr) {
    return Buffer.concat([
      frToLE(arr[0][0]),   // x_c0 (snarkjs index 0)
      frToLE(arr[0][1]),   // x_c1 (snarkjs index 1)
      frToLE(arr[1][0]),   // y_c0 (snarkjs index 0)
      frToLE(arr[1][1]),   // y_c1 (snarkjs index 1)
    ]);
  }

  return Buffer.concat([
    encodeG1(proof.pi_a),   // 64 bytes
    encodeG2(proof.pi_b),   // 128 bytes
    encodeG1(proof.pi_c),   // 64 bytes
  ]);  // 256 bytes total
}
```

---

## Common Mistakes

| Mistake | Symptom | Fix |
|---------|---------|-----|
| Applying G2 c0/c1 swap (old doc said to) | Proof always fails verification silently | Do NOT swap — snarkjs arr[i][0]=c0 already |
| Using checked `G1Affine::new()` in parser | Panic instead of Err on malformed input | Use `new_unchecked` + explicit `is_on_curve()` check returning Err |
| Using Fq modulus for Fr elements | Incorrect field arithmetic | Use Fr for scalars, Fq for coordinates |
| Big-endian byte order | Wrong field element | Use `from_le_bytes_mod_order` |
| Including public signals in proof_bytes | Extra bytes, parse failure | Public signals are separate |
| Hardcoding signal indices without .sym check | Wrong signal mapped to wrong semantic | Always verify from .sym |
| Using VK from JSON dynamically in canister | Insecure — VK substitution attack | Compile VK into canister binary |

---

*Last updated: 2026-06-26 (DEF-026 — recipient/subaccount signals 6/7/8; nPublic 6 → 9, IC 7 → 10)*
