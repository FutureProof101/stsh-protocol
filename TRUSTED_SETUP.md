# Trusted setup

STSH spend proofs are Groth16 proofs over BN254. Groth16 needs a circuit-specific
trusted setup. This page states exactly how that setup was produced, and what
its soundness depends on.

## 1. Circuit

- Source: `circuits/spend.circom`, compiled with circom 2.1.9.
- Size: 10,593 constraints and 9 public inputs.
- R1CS `circuits/build/spend.r1cs`, sha256
  `6ee4350674d0c21dca0a4f2344208ba3547977d48ee10edb5bf408d813aeaa34`.
- Witness wasm `circuits/build/spend_js/spend.wasm`, sha256
  `3e910987203d8e3b42e1b656d21aa4dffce23cad0f1dd84f6f093fce6fbf4585`.

## 2. Phase 1

Phase 1 is the public Hermez powers of tau file
`powersOfTau28_hez_final_15.ptau` (power 15). Its publisher lists 54 named
contributions plus a beacon.

- blake2b-512:
  `982372c867d229c236091f767e703253249a9b432c1710b4f326306bfa2428a17b06240359606cfe4d580b10a5a1f63fbed499527069c18ae17060472969ae6e`
- sha256: `3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f`

The file is not stored in this repository. `just download-ptau` fetches it from
a mirror and deletes it unless both digests match. The canonical hosts were
returning HTTP 403 when the file was retrieved.

## 3. Phase 2: exactly two contributions

1. `FutureProof operator 2026-09-12`: the project operator's human
   contribution.
2. The public drand mainnet beacon, round 6460200, applied last with
   `snarkjs zkey beacon`. Beacon value
   `e45908ee8d0b15714eb1eb75f2f65a95864d1d3236b258b112f2bbd483c65194`,
   iterationsExp 10.

**There was no independent second human contributor.**

## 4. Soundness assumption

Proofs are sound only if the operator host that made contribution #1 destroyed
its secret randomness. The drand beacon adds public randomness but hides
nothing, so it does not reduce this assumption.

Anyone who kept contribution #1's randomness could forge proofs for any public
inputs. With forged proofs they could:

- create notes of any value;
- drain the pool's escrowed STSH through public payouts;
- spend any input whose nullifier has not been spent.

There is no way to verify that the randomness was destroyed.

The ledger supply stays capped, because the pool cannot mint ledger STSH and
payouts are limited by the escrow. But all escrowed STSH is at risk under this
assumption.

A multi-party re-ceremony is planned. It is not yet scheduled.

## 5. Artifacts

- Proving key `circuits/build/spend_1.zkey`, sha256
  `4898655e8b3c3de9517f649f7caf8366ff4f9c95190ac274d5859de58f21e80c`.
- Verification key `circuits/verification_key.json`, sha256
  `84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914`.

This verification-key hash is the `vk_hash` in the pool's
`get_deployment_attestation` and the `vk_hash` the verifier canister reports
about itself. The verifier compiles the key in with `include_str!`
(`canisters/verifier/src/lib.rs`).

## 6. Reproduce

```bash
# circuit: compile, then compare with the tracked R1CS
(cd circuits && circom spend.circom --r1cs --output "$(mktemp -d)")   # then cmp <out>/spend.r1cs circuits/build/spend.r1cs
just download-ptau
npm ci --prefix circuits
cd circuits
npx snarkjs zkey verify build/spend.r1cs ptau/powersOfTau28_hez_final_15.ptau build/spend_1.zkey
# expect "ZKey Ok!", listing exactly the two phase-2 contributions above
npx snarkjs zkey export verificationkey build/spend_1.zkey /tmp/vk.json && cmp /tmp/vk.json verification_key.json
npm run verify:ceremony:next
```

## 7. Record

`docs/ceremony/CEREMONY_RECORD_v3.md` is the public ceremony record. It is a
redacted revision of the private v2 record, and it supersedes v2 under the
record's own revision rule.

- Redactions: the contributor's personal name and country, operator-host paths,
  and internal file names. No measured value changed.
- The private v2 record's sha256 is
  `bb608ebac2d07df6ac5ac47be457fd7e140ecbf319c499e5b0d0c5c137cb1aaf`.
- The v3 record's sha256 is pinned in `scripts/verify_genesis_manifest/VK_PIN.toml`
  (`record_transcript`).
