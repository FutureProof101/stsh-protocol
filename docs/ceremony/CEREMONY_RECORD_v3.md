---
id: ceremony-record-v3
type: record
owner: A6.7 (execution)
status: FILLED — the mainnet-v2 ceremony RAN on 2026-09-12 (lane A-4, Owner in room). Every field below is measured, not projected. This record is BOUND: its sha256 is pinned in scripts/verify_genesis_manifest/VK_PIN.toml record_transcript and checked by DPOOL-8b, so it is FROZEN — any later edit, including whitespace, requires re-executing brief V2 §4.4 steps 1-4 in full and is a new record revision, never an edit in place.
prefilled-by: lane/a4-ceremony-prep (A-4 PREP, Part 1) under DISPATCH_CTO_BUILDER_A4_CEREMONY_2026-09-09 and BRIEF_A4_CEREMONY_HERMEZ_V2_2026-09-09
filled-by: lane/a4-landing (A-4 LANDING, steps 4-6) under BRIEF_A4_LANDING_ADDENDUM_V4_2026-09-12 (sha256 bf18d34a…)
date: 2026-08-24
instantiated-by: W-VKGATE (AR1-05 / C-27) — Gate-D DPOOL-8 requires a committed record BOUND to deployment/mainnet/genesis_manifest.toml [pool_init].vk_hash
supersedes: CEREMONY_RECORD_v2 (private origin; sha256 bb608ebac2d07df6ac5ac47be457fd7e140ecbf319c499e5b0d0c5c137cb1aaf)
relates-to: [docs/ceremony/CEREMONY_RECORD_v2_TEMPLATE.md, docs/ceremony/PTAU_MULTIPARTY_PLAN.md, docs/ceremony/CEREMONY_FREEZE_RULES.md]
---

# STSH trusted-setup ceremony record — mainnet-v2

> **READ THIS FIRST — what this file is, and what it is not.**
>
> It is the *record of record*: the committed file Gate-D's `DPOOL-8` binds to
> `[pool_init].vk_hash`, so that a manifest can never pin a verifying key with
> no corresponding record at all. **It now attests a ceremony that actually ran**
> (2026-09-12, lane A-4): the contributions below were made, and the bound hash below is
> the real launch verifying key, not the P0-3 placeholder.
>
> **A record is an attestation, not a proof of independence.** Even fully
> filled, this file cannot make its own contents true — that is exactly why the
> M5 record needed the §3 corrections. Nothing here should be read as evidence
> that the launch key is trustworthy.
>
> **Bound verifying-key hash (must equal `[pool_init].vk_hash`):**
> `84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914`
> — the mainnet-v2 launch VK, sha256 of `circuits/verification_key.json`, ARMED into
> `deployment/mainnet/genesis_manifest.toml [pool_init].vk_hash` in the same commit as this
> record. DPOOL-8 fails closed if the two ever disagree.

**This is the NEW canonical ceremony record, and the ceremony has RUN.** Every ⬜ that this
lane could honestly discharge is discharged. Three remain open BY CONSTRUCTION and are
marked as such rather than ticked: **E12** (needs the J-18 Vault creation receipt — the pool
does not exist yet) and the **SSA** and **CTO** sign-off rows (other seats; a builder signing
them would defeat the row's only purpose). Residuals carried out of the ceremony are
enumerated in §8.1.

Sections **§3 (corrections)** and **§4 (disclosure)** are **not** placeholders — they are
authored now, are accurate as of 2026-07-31, and carry forward into the final record.

---

## 1. Scope

Records the mainnet-v2 trusted setup: the powers-of-tau in use, the circuit-specific
phase 2, the exported verifying key, and the domain constants the circuit commits to.

Supersedes the M5 ceremony (2026-07-07) as the production record. It does **not** rewrite
M5's history — see §3.

---

## 2. Artifacts

| Artifact | Path | sha256 | Notes |
|---|---|---|---|
| powers-of-tau | `circuits/ptau/powersOfTau28_hez_final_15.ptau` | `3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f` | **PATH (a) — PUBLIC. ADOPTED, power 15** (Addendum F ruling 1). The Hermez perpetual powers-of-tau, 54 contributions + a beacon — the SAME transcript as power 16, truncated, so provenance is identical and only capacity differs. UNTRACKED by design (`.gitignore` `circuits/*.ptau` and `circuits/**/*.ptau`); bound by **two** pinned digests here and in `PUBLIC_PTAU_ALLOWLIST` — publisher-attested blake2b-512 `982372c8…ae6e` and sha256 `3ef2ecc5…829e7f` — not by being in Git. Attestation block: §5.1 |
| R1CS | `circuits/build/spend.r1cs` | `6ee4350674d0c21dca0a4f2344208ba3547977d48ee10edb5bf408d813aeaa34` | committed Git anchor; hash independently pinned here (§6). Re-measure AFTER the A-3 FINALIZE recompile — do not carry a pre-recompile value forward |
| witness wasm | `circuits/build/spend_js/spend.wasm` | `3e910987203d8e3b42e1b656d21aa4dffce23cad0f1dd84f6f093fce6fbf4585` — **UNCHANGED** by this lane (A-4 changed KEYS, not the circuit; a moved value here would be a defect) | re-pin in `scripts/verify_spend_artifacts.mjs` and in `wallet/src/zk/spendManifest.json`; ships to the browser prover at `wallet/public/zk/spend.wasm` |
| production zkey | `circuits/build/spend_1.zkey` | `4898655e8b3c3de9517f649f7caf8366ff4f9c95190ac274d5859de58f21e80c` (7,527,594 bytes) | **retained in-repo — see §3.** The ONLY production proving key; negated back into Git by `.gitignore:22`; ships to the browser prover at `wallet/public/zk/spend_1.zkey` |
| verifying key | `circuits/verification_key.json` | `84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914` (4,391 bytes) | pinned in pool **and** verifier. `include_str!`'d at `canisters/verifier/src/lib.rs:54`, so this file changing is what changes the verifier Wasm — and it is the ONLY sanctioned post-freeze mover (Addendum A ruling 6) |

Circuit: **10,593** constraints · **9** public inputs · curve **bn-128**. Re-measured first-hand at ceremony time (`snarkjs r1cs info circuits/build/spend.r1cs`, snarkjs 0.7.5): 10,632 wires · 76 private inputs · 36,161 labels · 0 outputs — identical to the A-3 FINALIZE anchor, because A-4 did not recompile the circuit.
Domain constants: per `docs/ceremony/DOMAIN_CONSTANTS_MATRIX.md`, finalized at A-3 FINALIZE.
`domainHash` = `17076800395491555068286473339039486071114029588881949545487634475758427007736` (decimal) / `f86a7fd6a66d358ddbe7d8fa7b303f5da7e63d41b7ee207c6a31359c6220c125` (LE 32B hex) — carried from `POSEIDON_PARAMS.md` §Domain Separation, unchanged by A-4.

**`DOMAIN_CIRCUIT_VERSION` HOLDS AT 3 — stated explicitly, not left implicit.**
Ruled by `RULING_RECORD_LAUNCH_WEEK_2026-09-09.md` Addendum A ruling 1: A6.6 already
bumped 2 → 3 for launch, no real unspent notes exist, and `CEREMONY_FREEZE_RULES.md`
§1/§54 allow a pre-launch re-encode without a bump. A bump is required only if the
ceremony changes constraint STRUCTURE. It does not — measured in the A-4 PREP dry run:
re-encoding `DOMAIN_POOL_CANISTER_ID` to a throwaway principal and recompiling left the
circuit at **10,593 constraints / 10,632 wires / 9 public inputs / 76 private inputs /
36,161 labels**, byte-identical in shape to the committed anchor, changing only the R1CS
bytes. `DOMAIN_ASSET_ID = 0` (native STSH, Addendum A ruling 2) and
`DOMAIN_NETWORK_ID = 1` are CONFIRM_UNCHANGED.

> **Pre-recompile reference measurement**, taken first-hand at master `58d18e7` on
> 2026-09-09 (`npx snarkjs r1cs info circuits/build/spend.r1cs`, r1cs sha256
> `65bad577266fa4335e9cafa2b1de0e5c5771145844bd77564de5cfe49ec10da8`): **10,593
> constraints**. This is a reference, NOT the pin. §6/E7 requires the post-recompile
> re-measurement. Note for the record: 10,593 fits pot14 (16,384), and the adopted Hermez
> **power 15** (32,768) clears it with 22,175 headroom. The public Hermez ptau is adopted for
> **provenance, not sizing** (Addendum A ruling 7; this reconciles the J-18 "pot14 vs
> pot16" note, both statements being true about different questions). Addendum F ruling 1
> then selected power **15** over 16 within that same series: both carry the identical
> 54-contribution-plus-beacon transcript, so the choice costs nothing in provenance and the
> power-15 file is the one that was actually recoverable (§9.2).

---

## 3. Corrections to the M5 record (F6-2)

**Commit `6722247` is immutable and is NOT rewritten.** Historical commit messages stay as
they are; the correction lives here, in the new canonical record.

### 3.1 The "zkey deletion" claim is wrong

`6722247` ("ceremony: commit production VK + proof fixtures", 2026-07-07) states:

> *"both spend and payout_a variants verified OK **before zkey deletion**"*

**That is inaccurate.** The production proving key was **not** deleted. It is retained
in-repo at `circuits/build/spend_1.zkey`, tracked deliberately via a `.gitignore` negation:

```
circuits/*.zkey              # ignore all
!circuits/build/spend_1.zkey # …except the production proving key
```

**Retention is correct, not a bug.** Groth16 proving keys are public material — the secret
is the toxic waste (the τ/α/β randomness), which is destroyed during contribution, not the
zkey. The wallet's browser prover needs this key to generate proofs at all; deleting it
would break proving for every user. `scripts/verify_spend_artifacts.mjs` pins its hash
(`2ba66c4a…`) and stages it for the wallet build.

The commit message, not the artifact handling, was wrong.

### 3.2 Local dev-zkey deletion is not closure evidence

Stale pre-ceremony dev zkeys with **different** VKs sit untracked in the working tree.
They are local residue. **Deleting them is local cleanup and must never be recorded as
auditable closure evidence** — an untracked file's absence on one machine proves nothing to
an auditor, and cannot be verified after the fact.

The durable control is **labelling and validation**, not deletion. Every stale artifact is
enumerated with its hash in `circuits/ceremony/domain_manifest.json` → `stale_artifacts`,
and check **C6** of `circuits/scripts/verify_ceremony.mjs` fails if any of them shares a
hash with the production key:

| Path | sha256 | Label |
|---|---|---|
| `circuits/spend_final.zkey` | `e6e023e91d9e01c7…` | `STALE_PRE_CEREMONY_DEV` |
| `circuits/spend_0000.zkey` | `502556a064c387ae…` | `STALE_PHASE2_INITIAL` |
| `circuits/build/spend_0.zkey` | `613e799ff4c0b6b4…` | `STALE_PHASE2_INITIAL` |
| `circuits/build/spend_dev.zkey` | `613e799ff4c0b6b4…` | `STALE_DEV` |
| `circuits/build/spend_dev_1.zkey` | `a842852ea01ee921…` | `STALE_DEV` |
| `circuits/build/spend_dev_vk.json` | — | `STALE_DEV_VK` |

> `spend_0.zkey` and `spend_dev.zkey` are byte-identical (`613e799f…`) — the same phase-2
> initial key under two names. Exactly the kind of ambiguity that makes "which file is
> production?" answerable only by hash, which is why C6 checks hashes rather than names.

**Production proving key — the only one:** `circuits/build/spend_1.zkey`.

---

## 4. Trust disclosure — BOTH layers, stated plainly

A trusted setup is only as honest as its record. Both layers are disclosed, including the
one that is easy to leave out.

### 4.1 M5 (the setup being replaced) — single-participant at BOTH layers

Measured 2026-07-31 (not asserted from the finding text; see
`docs/ceremony/acceptance-evidence-m5-baseline.txt`):

| Layer | Contributions | Beacon | Status |
|---|---|---|---|
| **ptau (phase 1)** — `pot14_final.ptau` | **1** — `dev-contribution` | ❌ | **F6-1 — trust-assumption gap** |
| **zkey (phase 2)** — `spend_1.zkey` | **1** — `STSH-mainnet-ceremony-v2-2026-07-07` | ❌ | single participant |

`pot14_0000.ptau` → `pot14_0001.ptau` are ~1 minute apart (2026-06-09 12:08 → 12:09), same
participant, same machine.

**Stated without softening:** M5's Groth16 soundness reduces to one machine's entropy
quality and one act of toxic-waste deletion, at *both* layers. This is a **trust-assumption
gap, not a confirmed break** — there is no evidence the entropy was actually weak, and no
known exploitation. It is not acceptable to carry into a launch holding real user funds.

The phase-2 layer is disclosed here explicitly because a record that discloses only the
ptau gap would be *technically* responsive to F6-1 while still leaving a reader with the
wrong picture. Both layers were single-participant.

**Ruled mainnet-v2 path (R-A3-1): a public Hermez ptau plus a new phase 2** — power **15**
under Addendum F ruling 1. Its publisher-attested blake2b-512 is now pinned and verified
(§5.1), so **phase 1 is public-ceremony-backed** and the remaining single-participant
disclosure is confined to the **zkey layer**, where the beacon is what breaks single trust.

### 4.2 mainnet-v2 (this ceremony)

- Path taken: **(a) public ptau** — the ruled path (R-A3-1; Owner O-3; Addendum A).
- ptau contributions: **54 named + a beacon**, CONFIRMED by measurement, not by the
  publisher's claim: `snarkjs powersoftau verify` reports **55 contribution blocks**, `#1`..`#54`
  named and `#55` the unnamed beacon (`Beacon generator: e586fcca…aa372`, `iterations Exp` 10).
  The published "54 contributions and a beacon" and the measured 55 blocks are the same fact
  counted two ways — see §5.1, and do not read it as drift · beacon: **yes, in phase 1**
  (Hermez's own).
- Phase-2 contributions: **2** · contributors: **#1 `FutureProof operator 2026-09-12`**
  (the Owner, single operator) and **#2 `drand mainnet round 6460200`** (the public beacon,
  and the LAST contribution). Both are named in
  `domain_manifest.json → ceremony_material.next.zkey.contribution_names`, which C4
  reverse-checks against every observed contributor.
- **Residual trust assumptions, stated plainly:**
  **Phase 1 is public multi-party. Phase 2 is NOT.** Phase 2 of this ceremony rests on
  exactly ONE operator's entropy, finalized by a public beacon. If that single operator's
  entropy was weak or their toxic waste was retained, the beacon is the only thing
  standing between that and forgeable proofs — and the beacon protects only because it is
  unpredictable at the time the operator contributed, which is why §5.1's announce-before
  rule is the load-bearing part of this construction and not paperwork.
  **This is a materially smaller assumption than M5's, and it is not closed.** Do not
  describe it as closed. The community multi-party re-ceremony is post-launch.
  Second residual, disclosed rather than inherited: **CR-12** — release-identity legs are
  same-host, so cross-machine build independence is unproven.
  Third, from the tooling and not from the ceremony: **CR-A4-1** — `verify_ceremony.mjs`
  C4 has no structural phase-2 beacon check at all, so an all-GREEN `verify_ceremony.mjs`
  is NOT evidence that the beacon below is real. Only E14, done by hand, is.

> If phase 2 remains single-participant while phase 1 is public multi-party, **say so here
> in those words.** A one-contributor phase 2 over a many-contributor phase 1 is a real,
> materially smaller, but non-zero assumption. Do not describe it as closed.

---

## 5. Contributor transcript

**Phase 2 only.** Phase 1 is path (a) — its provenance block is §5.1, not this table.
Two rows are expected, in this order, and row 2 must be the LAST contribution in the chain.

| # | Contributor | Independence (person / machine / location) | Contribution hash | Entropy source | Toxic waste destroyed |
|---|---|---|---|---|---|
| 1 | `FutureProof operator 2026-09-12` (operator) | FutureProof operator / the operator's build host. **Independence is NOT claimed** — this is one person on one machine, which is precisely the residual disclosed below | `7b0f1210 55941d52 e859ca9c 3f2664cf f4e6101a 1bae4943 d2ed7f6e 861ae5c1 6c553871 461445a4 33f07219 331eb576 eff6cbf3 21578b4f 968bd147 4fe8cbed` | snarkjs `zkey contribute` entropy prompt — live human keyboard input at the terminal, combined by snarkjs with the OS CSPRNG. Not a passphrase, not a date, nothing reconstructible | Owner attests, in the first person: *the entropy was typed live, never written down, never stored, and the process memory was released when snarkjs exited; no copy of it exists.* |
| 2 | `drand mainnet round 6460200` (beacon) | public drand round — no person | `060b6982 e2d49de2 2aac63f9 795f0e96 bfa567bb de792d6b 2e65ed88 e62b6407 b355aa26 526653e3 e0dd9561 abf5f2cd bb456785 545adea4 bb4d36e4 cbd3ecf9` | drand round 6460200 randomness (§5.2) — `e45908ee…c65194` | n/a — a beacon has no toxic waste |

**Contribution #2 is the LAST contribution in the chain**, read off the contribution
NUMBER and not off the output order (snarkjs prints newest-first, so `#2` appears FIRST in
the `zkey verify` output pasted at E14). This is the property the whole construction rests
on: a beacon that is not last finalizes nothing.

> **GOTCHA, and it has bitten before:** snarkjs prints `Response Hash:` **twice** per
> contribution block. Record the **FIRST**. The second is `prevContr.nextChallenge` under
> a copy-pasted label (`domain_manifest.json → self_run_evidence.$comment`).

> **Entropy never lands here.** Not in this file, not in a chat, not in a document, not in
> a terminal that logs. The response hash is public and goes in the table; the entropy is
> destroyed when the process exits.

### 5.1 Phase 1 — public ptau provenance (path (a))

| Field | Value |
|---|---|
| Name | `powersOfTau28_hez_final_15.ptau` (Hermez perpetual powers-of-tau, **power 15**) |
| Local path | `circuits/ptau/powersOfTau28_hez_final_15.ptau` — UNTRACKED (`.gitignore:37`) |
| Size | 37,831,832 bytes |
| Published hash list (attestation) | `https://raw.githubusercontent.com/iden3/snarkjs/master/README.md` — the snarkjs (iden3) README, table headed "Prepared (phase2) Ptau files for bn128 with 54 contributions and a beacon" (row `power = 15`, source line 182) |
| Retrieved from that list on | **2026-09-09T18:12:42Z** (A-4 PREP wave 2; HTTP 200, 28,246 bytes) |
| **Published hash, as published — power 15 row** | `982372c867d229c236091f767e703253249a9b432c1710b4f326306bfa2428a17b06240359606cfe4d580b10a5a1f63fbed499527069c18ae17060472969ae6e` |
| **Published hash ALGORITHM** | **blake2b-512, NOT sha256** — the README states "And it's blake2b hash is" for the same series. Resolved by Addendum F ruling 3: the allowlist now carries a `blake2b` field beside `sha256` and C1 requires **both** |
| Download source | `https://media.githubusercontent.com/media/hswopeams/composite-number-game/main/circuit/powersOfTau28_hez_final_15.ptau` — **DOWNLOAD SOURCE (MIRROR), NOT ATTESTATION.** A GitHub LFS copy in `hswopeams/composite-number-game` (`circuit/`). Both canonical hosts return 403 to anonymous callers; see §9.2. Which host served the bytes is irrelevant once both digests match — that is the entire point of pinning hashes |
| Retrieval date | 2026-09-09 |
| Retriever | STSH CTO seat (recovery, Addendum F facts); staged outside every repo at `$HOME/ptau/` and copied into the gitignored `circuits/ptau/` by the A-4 PREP builder |
| **Locally computed blake2b-512** | `982372c867d229c236091f767e703253249a9b432c1710b4f326306bfa2428a17b06240359606cfe4d580b10a5a1f63fbed499527069c18ae17060472969ae6e` — **EQUALS the published value above, byte for byte.** Computed twice by independent implementations: coreutils `b2sum` (whose default IS blake2b-512) and Node `crypto.createHash("blake2b512")`; both agreed |
| **Locally computed sha256** | `3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f` |
| Second independent confirmation | **OBTAINED, of the sha256.** GitHub LFS object ids are sha256 digests of the object content, and GitHub publishes this file's LFS pointer independently of iden3: the pointer at `hswopeams/composite-number-game:circuit/powersOfTau28_hez_final_15.ptau` reads `oid sha256:3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f` (GitHub contents API, retrieved 2026-09-09), matching the locally computed sha256 exactly. So the two digests are attested by two unrelated parties: **blake2b by iden3, sha256 by GitHub.** A second independent publisher of the *blake2b* was NOT found — iden3 is its only publisher — and that residual stands, disclosed, not closed |
| `snarkjs powersoftau verify` | **`Powers of Tau Ok!`** (exit 0) — full unsummarised output, 1,000 lines, in the A-4 PREP V2 packet |
| **Contribution structure, MEASURED** | **55 contribution blocks**: `#1`..`#54` are the named participants (`weijie`, `kobi`, `poma`, …, `zaki`, `juan`, `jarrad`) and **`#55` is the BEACON** — unnamed, carrying `Beacon generator: e586fccaf245c9a1d7e78294d4802018f3001149a71b8f10cd997ef8235aa372` and `Beacon iterations Exp: 10`. That is exactly the README's "54 contributions and a beacon", counted two ways; **do not read 55-vs-54 as drift.** snarkjs lists contributions **NEWEST-FIRST**, so `#55` appears FIRST — the last contribution is read off the **number**, never off the output order (F-PREP-7, and it bites at the ptau layer too) |
| **Binary header** | `power 15, ceremonyPower 28` — the file is a truncation of the perpetual **powers-of-tau-28** ceremony, which is the direct evidence that power 15 and power 16 share one transcript |
| Allowlist entry | `PUBLIC_PTAU_ALLOWLIST[0]` in `circuits/scripts/verify_ceremony.mjs`, carrying both digests, the attestation URL + retrieval date, and the mirror URL labelled "download source (mirror), not attestation". Mirrored in `domain_manifest.json` `ceremony_material.next.ptau` |

> **How the provenance actually runs, in the only terms the record will state it.**
> **iden3 publishes a blake2b-512 → the local file's blake2b-512 equals it → the file is the
> Hermez ceremony output.** That is the whole chain, and the download host appears nowhere in
> it. The sha256 is a second digest over the same verified bytes; it is separately confirmed
> by GitHub's LFS oid, but it is *not* what binds the file to the ceremony. Both are pinned
> and both are checked, and `verify_ceremony.mjs` treats a file that matches one and not the
> other as a **hard FAIL with its own message**, never as "unpinned" — because a half-match
> means the pin and the file disagree, which is a different problem from an absent pin.

> **Dry-run confirmation (A-4 PREP wave 2).** The whole path was rehearsed on a throwaway
> principal against **this file**, not a stand-in: re-encode + recompile (10,593 constraints,
> unchanged), `groth16 setup` over the real pot15, one operator contribution, a `zkey beacon`,
> `zkey verify`, VK export, then `verify_ceremony.mjs --generation next`. **C1–C5 all PASS**;
> C2 derived `2^15 = 32768` from the binary header and agreed with the manifest; C6 fails for
> the known F-PREP-5 worktree reason. E14 held: the raw `zkey verify` `Beacon generator:` hex
> equalled the announced drand round's randomness byte-for-byte. Nothing was committed and the
> tree was restored byte-exact.

> **WARNING — what C1 passing on this branch does and does not prove.** On the allowlist
> branch C1 returns without ever reaching `evaluateSelfRunEvidence`, so **the only structural
> beacon parser in the toolchain does not execute on this path at all.** The ptau layer's
> 54 contributions and its beacon rest on the **publisher's attestation** (the README table's
> own header) plus the `powersoftau verify` output quoted in the packet — not on a structural
> check this tool performed. This is the same class of gap as CR-A4-1 at the phase-2 layer
> (§4.2), one layer up, and it is disclosed rather than papered over.

### 5.2 Beacon — drand mainnet (League of Entropy)

**Ruled** by `RULING_RECORD_LAUNCH_WEEK_2026-09-09.md` Addendum A ruling 3.

| Field | Value |
|---|---|
| Chain | drand mainnet, beacon ID `default`, scheme `pedersen-bls-chained` |
| Chain hash | `8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce` |
| Chain public key | `868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31` |
| Genesis time / period | `1595431050` / `30` s (both retrieved from `https://api.drand.sh/info`, 2026-09-09) |
| **Round R (announced)** | **6460200** |
| **Round R expected UTC time** | **2026-09-12T18:17:00Z** (= 1595431050 + 6460199 × 30 = 1789237020) — computed as `genesis_time + (R − 1) × period`, i.e. `1595431050 + (R − 1) × 30`, as a UTC instant. Formula verified in A-4 PREP against round 6451400 → 2026-09-09T16:57:00Z |
| Announcement artifact | the commit on `lane/a4-beacon-announce` that writes this row (subject "docs(ceremony): A-4 — announce drand beacon round 6460200"), plus office `reviews/RULING_RECORD_BEACON_ANNOUNCE_2026-09-12.md`; at announcement time drand latest round was 6459830 (15:12:19Z), lead ≈ 3 h ≥ the 2 h wall-clock rule |
| Announcement timestamp (UTC) | 2026-09-12T15:13:25Z (record edit; the commit timestamp is authoritative) |
| Round randomness, from `https://api.drand.sh/public/6460200` | `e45908ee8d0b15714eb1eb75f2f65a95864d1d3236b258b112f2bbd483c65194` |
| Exact hex string fed to `snarkjs zkey beacon` | `e45908ee8d0b15714eb1eb75f2f65a95864d1d3236b258b112f2bbd483c65194` — the 64-hex randomness, byte-for-byte, and it is what `zkey verify` reports back as `Beacon generator:` (E14) |
| `numIterationsExp` | **10** |
| Independent retrievals of the round value | **TWO, from unrelated endpoints, both recorded verbatim at E14:** (1) `https://api.drand.sh/public/6460200` and (2) `https://drand.cloudflare.com/public/6460200`. Both return `randomness` = `e45908ee8d0b15714eb1eb75f2f65a95864d1d3236b258b112f2bbd483c65194` AND the identical `signature` / `previous_signature`, so the two operators agree on the chained BLS signature, not merely on a hex string |

**ORDERING — this is the whole construction, and it is easy to get backwards.**
The announcement is a **pre-contribution** act. It happens BEFORE `zkey contribute`, not
with `zkey beacon`. Concretely, in this order and no other:

1. **Announce.** Commit round R and its computed UTC time into this section, and into the
   office ruling record. **R's expected time must be at least 2 hours after this commit**
   (binding wall-clock rule, brief V2 §2, CTO-enforced).
2. **Contribute.** `zkey contribute` must **complete before** R's time.
3. **Wait for R, then retrieve** its randomness from `api.drand.sh` (twice, independently).
4. **Finalize.** `zkey beacon` with that randomness, `numIterationsExp` 10.

**If any of those slips — the announcement lands too close to R, the contribution runs
past R, drand is unreachable at R, or the announcement has to be amended — ABORT,
announce a NEW future round, and redo phase 2 from `zkey new`.** Reusing a contribution
across a re-announced beacon is precisely the failure this construction exists to
prevent. Announcing after contributing proves nothing whatsoever.

**Not acceptable:** a hash of "today's news", an operator-chosen nonce, a value published
after contributions began, or a contribution merely *named* "beacon".

---

## 6. Acceptance evidence

```bash
node circuits/scripts/verify_ceremony.mjs --generation next \
  --transcript docs/ceremony/acceptance-evidence-mainnet-v2.txt
```

| | Evidence | Check | Result |
|---|---|---|---|
| E1 | ptau pinned by authoritative hash **or** contributions + beacon recorded | C1 | ✅ **PASS** — allowlist branch, BOTH digests matched: publisher-attested blake2b-512 `982372c8…ae6e` (iden3) and sha256 `3ef2ecc5…829e7f` (independently confirmed by GitHub's LFS oid). **F6-1 CLOSED**: phase 1 is now the public Hermez ceremony, not a one-machine ptau |
| E2 | ptau power ≥ constraints (with A6.6 headroom) | C2 | ✅ **PASS** — power read from the ptau BINARY HEADER: 2^15 = 32,768 ≥ 10,593 constraints (22,175 headroom); the manifest's declared power 15 agrees with the file |
| E3 | zkey verifies against final R1CS **and** chosen ptau | C3 | ✅ **PASS** — `snarkjs zkey verify` against `circuits/build/spend.r1cs` AND `powersOfTau28_hez_final_15.ptau`: **ZKey Ok!** (raw output at E14) |
| E4 | Contributor identities / independence / hashes | C4 + manual | ✅ **PASS** — 2 observed contributions, both names reverse-checked against `contribution_names`; identities, hashes and the honest non-claim of independence in §5 |
| E5 | VK hash pinned in **both** pool and verifier | C5 + Rust gate | ✅ **PASS** — C5 matched the manifest pin; the full equality chain is computed in §6.2 below, not asserted |
| E6 | Wallet ⇄ circuit domain equality, **after** A6.6 changes | `domain_freeze_a3.test.ts` | ✅ **PASS** — green in the wallet vitest leg of the one `./run_gate.sh`; `ceremony_bind_spend_manifest.test.ts` was REPOINTED in this lane from `next.dev_chain` to `next.vk`/`next.zkey`, so it now binds the wallet to the PRODUCTION artifacts (binding it to `dev_chain` would have passed while the wallet shipped the dev key) |
| E7 | R1CS sha256 + constraint count re-measured | manual pin | ✅ **PASS** — re-measured first-hand: sha256 `6ee43506…aeaa34`, 10,593 constraints / 9 public inputs / 10,632 wires. UNCHANGED from A-3 FINALIZE, as expected: A-4 did not recompile the circuit |
| E8 | Zero-root / domain-mismatch regression re-run | `./run_gate.sh` | ✅ **PASS** — one five-leg gate on the final lane head; verdict and per-leg tallies in the lane packet |
| E9 | Stale artifacts labelled, unconfusable | C6 | ✅ **PASS** — with a DISCLOSED NARROWING, see §6.3: the six `stale_artifacts.entries` moved from `FAIL_CLOSED` to `ALLOW_ABSENT` |
| E10 | Both trust layers disclosed (§4) | manual — C4's single-contributor note will NOT fire at 2 contributions; its absence is evidence of nothing | ✅ **PASS** — §4.2 states in the required words that phase 1 is public multi-party and **phase 2 is NOT**, and does not describe it as closed. As predicted, C4's single-contributor note did NOT fire (2 contributions); that silence is evidence of nothing and is not cited as any |
| E11 | Beacon **announced before** contributions, with the announcement artifact + timestamp, and the §5.2 wall-clock rule satisfied | manual, §5.2 | ✅ **PASS** — announcement commit `b13ec079beba2efc0191690ca84290e5567f9efd` is dated **2026-09-12T16:14:18+01:00 = 15:14:18Z**; round 6460200's time is **18:17:00Z**. Lead ≈ **3h 2m ≥ the binding 2 h rule**. The operator contribution (#1) completed at 16:18 BST = 15:18Z, i.e. BEFORE the round; the beacon (#2) was applied at 19:37 BST = 18:37Z, AFTER it. The announcement therefore pre-dates both the randomness and the contribution — the property that makes the beacon unpredictable-at-contribution-time |
| E12 | Launch pool principal traced to a **typed Vault creation receipt** with status `Bound` and `purpose == shielded_pool` — never read off a terminal scrollback | manual, J-18 part 1 | ⬜ **NOT DISCHARGEABLE IN THIS LANE — carried OPEN to J-18.** A-4 is forbidden any mainnet action, and the pool is not born until J-18, so no creation receipt exists yet to trace. The circuit commits to `cxrfg-qaaaa-aaaar-qchfa-cai` (re-encoded at A-3 FINALIZE). **Stated rather than ticked**: E12 must be discharged at J-18 against the typed receipt, and this record does not assert it |
| E13 | `git diff --cached --name-only` reviewed and **stated** for every commit in the lane | ARCHITECTURE.md law 9 | ✅ **PASS** — one commit in this lane; its staged file list was read and stated explicitly before `git commit`, and the full list is reproduced in the lane packet |
| **E14** | **Phase-2 beacon is structurally real, verified BY HAND.** Paste the **raw, unsummarised** `snarkjs zkey verify <r1cs> <ptau> <final zkey>` output showing **contribution #2** carrying a `Beacon generator:` line, with `iterations Exp` = 10; cross-check the generator hex **byte-for-byte** against round R's randomness as retrieved from `api.drand.sh`; record the API response AND the announcement that pre-dates it; and record that #2 is the **LAST** contribution | **manual, MANDATORY.** No automated check covers this — see §4.2 / CR-A4-1. Re-verified independently by the SSA at landed-diff | ✅ **PASS — see §6.4** for the raw paste, the `iterations Exp` 10 line, the last-contribution reading, and BOTH independent drand retrievals. The SSA re-verification is a separate seat and is NOT self-signed here (§8) |
| **E15** | (see §6.1 — re-derived at pin time, not transcribed) | manual | ✅ **PASS** |
| **E16** | DPOOL-8a / 8b / 9 / 9b confirmed passing **BEFORE** the `env -i` gate is started | `verify_genesis_manifest`, transcript here | ✅ **PASS** — run in the §4.4 order (record's last byte → sha256 → `VK_PIN.toml.record_transcript` → the `ceremony_transcript_tests.rs:24` mirror), and confirmed green BEFORE the gate was started. The transcript cannot live in these bytes without re-opening §4.4 step 1 — it is in the lane packet, which is where a post-hash artifact belongs |

**Fifteen of sixteen are green and E12 is explicitly carried OPEN to J-18** (it cannot be discharged before the pool exists; it is stated, not ticked, and not silently counted as green). E1 is the F6-1 closure check
specifically, and it cannot be satisfied by re-running phase 2 over the old ptau.

> **An all-GREEN `verify_ceremony.mjs` does not mean the beacon is real.** C4 applies one
> regex over `zkey verify` output and compares a count and a set of names against the
> manifest. It has no `type == 1` test, no `Beacon generator:` parse and no
> `iterationsExp` check, and on path (a) C1 short-circuits on the allowlist branch so the
> phase-1 beacon parser never executes either. A phase-2 contribution merely *named*
> "beacon", containing no beacon, greens the run. **E14 is the only thing that closes
> this**, and it is done by a human reading raw output.

### 6.1 VK-pin surface derivation (E15) — EXECUTED AT PIN TIME, 2026-09-12

The surface list is **derived mechanically at pin time**, never transcribed — a
transcribed list is what produced the SSA F1 defect, twice.

**EXECUTED RESULT (A-4 LANDING, base `b13ec07`).** The derivation ran over **THREE**
literal sets, not one, because the A-3 dev chain moved three independent pins:

| Set | Outgoing literal | What it is | Files hit (full ∪ 16-char ∪ 8-char, `-i`) |
|---|---|---|---|
| (i) | `081e9e9b…690f2` | the OUTGOING dev VK (NOT `fc73ca4d…`, which has not been live since A-3) | **11** |
| (ii) | `29a57f1b…dbb5b` | the OUTGOING dev zkey file hash | **4** |
| (iii) | `3e910987…f4585` | the witness-wasm hash | **4 — ALL DO-NOT-MOVE** |

Union of (i)∪(ii)∪(iii) = **13 files**. Set (iii) is expected to be entirely DO-NOT-MOVE
and was: A-4 changed KEYS, not the circuit, and the witness wasm on disk still hashes to
`3e910987…f4585`. **A moved hit in set (iii) would have been a defect, not a finding** —
it would mean the circuit had been recompiled, which this lane is not authorised to do.

**Full MOVE triage, individually enumerated (every hit carrying a value):**

| File | Set | Disposition |
|---|---|---|
| `circuits/verification_key.json` | subject | **MOVE** — replaced wholesale by the ceremony export (a file cannot contain its own hash, so no grep finds it; it is a mandatory ADD) |
| `circuits/build/spend_1.zkey` | subject | **MOVE** — replaced wholesale by `spend_0002.zkey` (binary; `grep -I` skips it) |
| `deployment/mainnet/genesis_manifest.toml` | floor 2 | **MOVE** — `[pool_init].vk_hash` ARMED from the all-zeros sentinel |
| `scripts/verify_genesis_manifest/VK_PIN.toml` | (i) | **MOVE** — `sha256`, `label` DEV→PRODUCTION, `source`, `record_transcript` |
| `docs/ceremony/CEREMONY_RECORD_v3.md` | floor 3 | **MOVE** — this file |
| `circuits/ceremony/domain_manifest.json` | (i)(ii)(iii) | **MOVE, PARTIAL** — `ceremony_material.next.{zkey,vk}` filled; `m5` gains `superseded`; the six `stale_artifacts` policies flip. **`next.dev_chain` DELIBERATELY NOT MOVED** — see below |
| `wallet/src/crypto/notes.ts` | (i) | **MOVE** — `PINNED_VK_HASH_D2` |
| `wallet/src/zk/spendManifest.json` | (i)(ii) | **MOVE** — `vkHash` + the `spend_1.zkey` sha256 **and bytes** (7527122 → 7527594) |
| `scripts/verify_spend_artifacts.mjs` | (i)(ii) | **MOVE** — the `:31` zkey pin + bytes, and the `:13`/`:15` header comments. **Gate-critical**: `run_gate.sh` invokes this script DIRECTLY, so a missed byte count here is a hard gate failure, not a lint |
| `circuits/spend.circom` | (i) | **MOVE** — the `:45` `PINNED_VK_HASH` comment. Comment-only; no pinned digest covers `spend.circom`, and the R1CS was NOT recompiled |
| `MAINNET_DEPLOYMENT.md` | (i) | **MOVE** — 3 full-hash sites, 1 truncated site at `:437` that the full-hash sweep did NOT catch, plus the "DEV VK / re-ceremony pending" prose in 6 places |
| `PUBLIC_SIGNALS_BINDING.md` | deny-literal | **MOVE (PSB-1, ruled)** — a law-6 artifact stating a false value: its banner still carried `fc73ca4d…` and "single-participant DEV VK pending re-ceremony" |
| `wallet/tests/spend_flow_l3c.test.ts` | (i) | **MOVE** — hardcoded expectation |
| `wallet/tests/j25_release_panel.test.ts` | (i) | **MOVE** — hardcoded expectation |
| `wallet/tests/ceremony_bind_spend_manifest.test.ts` | (i) | **MOVE** — `M5_PINS.vkHash`, **plus the two assertions REPOINTED** from `next.dev_chain` to `next.vk`/`next.zkey` (see §6.5) |
| `scripts/verify_genesis_manifest/tests/vk_pin_tests.rs` | (i) | **MOVE** — fixture literal |
| `scripts/verify_genesis_manifest/tests/ceremony_transcript_tests.rs` | floor 16 | **MOVE** — `RECORD_TRANSCRIPT_LITERAL` at `:24`, the THIRD mirror of this record's sha256 |
| `deployment/mainnet/release_hashes.toml` | floor 11 | **MOVE** — `[wasm."stsh-verifier"]` and `[wallet_bundle]`, both hand-edited |
| `.ai-context.md` | floor 15 | **MOVE, PARTIAL** — a live A-4 block was ADDED. The `:257` mirror is BELOW this file's own ARCHIVE banner ("preserved verbatim, NO LONGER CURRENT") and was deliberately NOT edited; editing it would violate the file's own contract |
| `docs/ceremony/PTAU_MULTIPARTY_PLAN.md` | (ii) | **MOVE, ANNOTATED** — the dev-chain table is retained as the statement of the problem, with a SUPERSEDED-BY-A-4 block added |
| `wallet/src/zk/artifacts.ts` | deny-literal | **MOVE** — header comment named `fc73ca4d…` as "the pool pin", which is now two generations stale |

**DO-NOT-MOVE, each with its reason:**

| File / site | Reason |
|---|---|
| `scripts/verify_genesis_manifest/src/lib.rs:152` `DEV_VK_HASH_HEX` | **RULED.** A deny-list entry. Sweeping it to the new hash would turn a refusal of the dev key into a refusal of the PRODUCTION key — the exact inversion. Its own doc-comment concedes "refusing one known-bad value is not provenance"; that caveat stands, and see §8 for the residual this leaves |
| `…/tests/{vk_pin,ceremony_transcript,vkgate_pool_init}_tests.rs` `fc73ca4d…` literals | Mirrors of the deny literal, asserting the deny-list behaviour. They move with the deny list, i.e. not at all |
| `…/tests/fixtures/pre_a2/genesis_manifest.toml` | A frozen PRE-A2 fixture. Its whole purpose is to be the old state |
| `integration-tests/tests/l3c_proof_encoding_tests.rs:8` | Comment naming the historical VK of a recorded encoding vector |
| `circuits/ceremony/domain_manifest.json` → `ceremony_material.next.dev_chain` | **The superseded record itself.** Invariant 4: letting `dev_chain` track the production artifacts would erase what was superseded. It must keep pointing at `29a57f1b…`/`081e9e9b…` even though the files at those PATHS now hold the production bytes |
| `circuits/ceremony/domain_manifest.json` → `ceremony_material.m5.*` | Same reason, one generation further back; `m5` additionally gains a `superseded` marker (§6.3) |
| set (iii), all 4 files (`spendManifest.json`, `artifact_stream_cap_s106.test.ts`, `verify_spend_artifacts.mjs`, `domain_manifest.json`) | The witness wasm did not change. Verified by measurement, not assumption: `sha256(circuits/build/spend_js/spend.wasm)` = `3e910987…f4585`, unchanged |
| `.ai-context.md:257` (archive section) | Below the ARCHIVE banner, "preserved verbatim, NO LONGER CURRENT" by the file's own rule |
| `docs/ceremony/CEREMONY_RECORD_v3.md:356` truncated `fc73ca4d…530dc8` | Historical citation of the A-3 rehearsal, deliberately TRUNCATED — see the warning below |

**Floor cross-check (brief V2 §4.0 rule 5): the derived set is a SUPERSET of the §4.2
floor.** All 17 floor rows are accounted for above. Five are structurally unreachable by
grep and are mandatory ADDs, exactly as the A-4 PREP rehearsal predicted:
`circuits/verification_key.json` (the subject), `circuits/build/spend_1.zkey` and the two
`wallet/public/zk/*` files (binaries, and *regenerated* by `verify_spend_artifacts.mjs`
rather than edited), and `POSEIDON_PARAMS.md` (carries constraint counts, not the VK hash —
and the counts did NOT move, so it does not move either).

**Rule 3 (pin-NAME sweep) — regenerated at point of use: 93 files.** The 21-file MOVE set
above is a subset. The remaining hits carry a field NAME and no value, and are triaged by
class exactly as the rehearsal scoped them (`InitArgs` field names in
`integration-tests/**`, Candid field names in `canisters/**` and `src/declarations/**` —
where any edit would be a freeze violation — runtime-read `vkHash` in `wallet/**`, and
`vkHash` as a computed local in the checker itself). **Individual enumeration is reserved
for hits carrying a VALUE; a ninety-row field-name census is noise that hides the signal.**

**Superset confirmation — the derivation's own output, after the fact:** 18 files now
carry the new literal `84dba305…c6914`, and the only files that still carry an outgoing
literal are the DO-NOT-MOVE sites enumerated above. That is the check that the sweep
closed, and it was run, not assumed.

The rehearsal result below is RETAINED for comparison. It ran at `58d18e7` against
`fc73ca4d…530dc8`, which was already the WRONG outgoing hash by A-4 time — which is
precisely why the rule says derive, never transcribe:

> **This record must never contain the outgoing (dev) VK hash as a full 64-hex
> literal — cite it truncated, as above.** `DPOOL-8a-record-vs-artifact` is
> posture-gated: once the manifest is armed it requires the record to name the
> COMPUTED artifact hash, and `test_record_vs_artifact_posture_gated`
> (`scripts/verify_genesis_manifest/tests/ceremony_transcript_tests.rs:245-252`)
> asserts the negative case by feeding the live record the DEV hash and
> requiring a FAIL. A narrative mention of the full old hash anywhere in these
> bytes turns that assertion green-side-up and fails the workspace leg. Found
> the hard way in A-4 PREP.

- **Rule 2** (`grep -rIl -i` on the full hash + its 16- and 8-char truncations, excluding
  `.git`, `target`, `node_modules`): **19 files** — every one carries a VK-hash literal
  and every one is a **MOVE** except `scripts/verify_genesis_manifest/src/lib.rs`
  (`DEV_VK_HASH_HEX`, a **deny-list entry**: DO-NOT-MOVE, ruled — sweeping it would turn
  the refusal into a refusal of the *production* key).
- **Rule 3** (`grep -rIln` on `PINNED_VK_HASH`, `vk_hash`, `vkHash`, `spendManifest`,
  `VK_PIN.toml`): **91 files**, of which **73 carry no VK-hash literal at all**. Those 73
  are triaged **BY CLASS**, per the SSA's N1 note — an abbreviated ninety-row hand census
  is worse than a scoped one:

  | Class | Files | Disposition |
  |---|---|---|
  | `integration-tests/tests/*.rs` | 39 | DO-NOT-MOVE — `vk_hash` / `initial_vk_hash` as an `InitArgs` **field name**; no hash literal |
  | `wallet/**` (src + tests) | 11 | DO-NOT-MOVE — `vkHash` / `spendManifest` as a **runtime-read field**; the value comes from `spendManifest.json`, which is itself a MOVE surface found by rule 2 |
  | `canisters/**` (`.did`, `src/*.rs`, `Cargo.toml`) | 5 | DO-NOT-MOVE — Candid field names and doc-comments. **Any edit here is a freeze violation** |
  | `docs/**` and root `*.md` | 5 | DO-NOT-MOVE except `docs/ceremony/CEREMONY_RECORD_v3.md` (this file — **MOVE**, floor row 3) |
  | `*.did` outside `canisters/` (custody-types fixtures) | 5 | DO-NOT-MOVE — Candid field names |
  | `scripts/**` (`a65_sweep.sh`, `claims_baseline.toml`, `verify_custody_manifest`, `watcher.ts`) | 4 | DO-NOT-MOVE — field names and prose |
  | `src/declarations/*` | 2 | DO-NOT-MOVE — generated Candid bindings |
  | `circuits/scripts/verify_ceremony.mjs` | 1 | DO-NOT-MOVE — `vkHash` is a **computed local variable** (`:474`), the checker itself |
  | `deployment/mainnet/release_hashes.toml` | 1 | **MOVE** — floor row 11 (wallet-bundle sha), hand-edited from the `env -i` build |

  Individually enumerated triage is reserved for hits carrying a **value**; class rows
  cover field-name-only hits. **Re-run both greps against the OUTGOING hash at ceremony
  time and re-triage — this rehearsal is a rehearsal, not the census.**

- **Floor cross-check (brief V2 §4.0 rule 5).** Five floor rows are **not reachable by
  rules 2 or 3, structurally**, and this is expected rather than a broken derivation:
  `circuits/verification_key.json` (it is the SUBJECT — a file cannot contain its own
  hash); `circuits/build/spend_1.zkey`, `wallet/public/zk/spend.wasm` and
  `wallet/public/zk/spend_1.zkey` (**binaries** — `grep -I` skips them, and they are
  *regenerated*, not edited); and `POSEIDON_PARAMS.md` (carries constraint counts, not
  the VK hash, and moves only if step 2 moved them). **Therefore the sweep set is
  `rule2 ∪ rule3 ∪ {those five}`** — the five are a mandatory ADD, and rule 5's superset
  assertion must not be read as a reason to stop. Raised to the CTO in the A-4 PREP
  packet.

### 6.2 The VK equality chain — COMPUTED, not asserted (E5)

Every one of these was measured first-hand at pin time and they are all the same 32 bytes:

| Surface | Value |
|---|---|
| `sha256(circuits/verification_key.json)` | `84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914` |
| `genesis_manifest.toml [pool_init].vk_hash` | same |
| `VK_PIN.toml.sha256` | same |
| `wallet/src/crypto/notes.ts` `PINNED_VK_HASH_D2` | same |
| `wallet/src/zk/spendManifest.json` `vkHash` | same |
| `domain_manifest.json` `ceremony_material.next.vk.sha256` | same |
| verifier `compiled_vk_sha256()` | same — the verifier `include_str!`s the VK file, and `compiled_vk_hash_matches_committed_pin` asserts it against `VK_PIN.toml` at `cargo test` time |

**The new hash is NOT `fc73ca4d…`** (the M5 dev VK that `DPOOL-2` refuses by name) and is
not the A-3 dev VK either.

**The pool Wasm did NOT move**, and that is a required outcome rather than a lucky one:
`PINNED_VK_HASH` is not a pool source constant but stable state seeded from
`InitArgs::initial_vk_hash`. Measured across a before/after `env -i` pair, `shielded_pool.wasm`
is byte-identical (`77b719e2…caffd0`) and **only `stsh-verifier` moved**
(`c334a8ed…c596660` → `5a7dcc49…2c81141`, 645,860 bytes both sides — equal length, different
bytes, exactly as a swapped `include_str!` payload behaves).

### 6.3 DISCLOSED NARROWING of C6 (E9) — six stale artifacts moved to `ALLOW_ABSENT`

`domain_manifest.json → stale_artifacts.entries` declares six untracked dev keys
(`circuits/spend_final.zkey`, `circuits/spend_0000.zkey`, `circuits/build/spend_0.zkey`,
`circuits/build/spend_dev.zkey`, `circuits/build/spend_dev_1.zkey`,
`circuits/build/spend_dev_vk.json`). All six were `missing_policy = "FAIL_CLOSED"`.

**They are untracked local residue that no clone carries.** With the ceremony checker now
wired into `./run_gate.sh`, `FAIL_CLOSED` made the gate's circuits leg fail on every fresh
checkout — a red gate that means "this machine never had these dev files", which trains
readers past the VERDICT line for a non-finding. **RULING (addendum V4 §4): all six flip to
`ALLOW_ABSENT`,** each carrying a recorded per-entry reason.

**What this gives up, stated plainly:** absence is no longer evidence. If one of these files
is renamed away, C6 can no longer notice. **What it retains:** whenever such a file IS
present, C6 still hashes it and still fails if it shares the production key's hash or
disagrees with its recorded digest — which is the stale-key-confusion property C6 exists for.
This is a NARROWING of C6, recorded as such and not presented as equivalent.

### 6.4 E14 — the phase-2 beacon is structurally real, verified BY HAND

**No automated check covers this** (§4.2 / CR-A4-1). What follows is the RAW, unsummarised
`snarkjs zkey verify circuits/build/spend.r1cs circuits/ptau/powersOfTau28_hez_final_15.ptau spend_0002.zkey`
output (ANSI colour codes stripped, nothing else altered):

```
[INFO]  snarkJS: Circuit hash:
                987e91ec c1132160 2abfb4dd 331c82c0
                edc03c0f 2a57c91b a845bc79 0ade320b
                22d70a8a 1adb19d5 cece80c1 fba8a141
                b1e0433f 022188b4 941b6de6 3a5ff3c0
[INFO]  snarkJS: -------------------------
[INFO]  snarkJS: contribution #2 drand mainnet round 6460200:
                060b6982 e2d49de2 2aac63f9 795f0e96
                bfa567bb de792d6b 2e65ed88 e62b6407
                b355aa26 526653e3 e0dd9561 abf5f2cd
                bb456785 545adea4 bb4d36e4 cbd3ecf9
[INFO]  snarkJS: Beacon generator: e45908ee8d0b15714eb1eb75f2f65a95864d1d3236b258b112f2bbd483c65194
[INFO]  snarkJS: Beacon iterations Exp: 10
[INFO]  snarkJS: -------------------------
[INFO]  snarkJS: contribution #1 FutureProof operator 2026-09-12:
                7b0f1210 55941d52 e859ca9c 3f2664cf
                f4e6101a 1bae4943 d2ed7f6e 861ae5c1
                6c553871 461445a4 33f07219 331eb576
                eff6cbf3 21578b4f 968bd147 4fe8cbed
[INFO]  snarkJS: -------------------------
[INFO]  snarkJS: ZKey Ok!
```

The four things E14 requires, each read off the paste above:

1. **Contribution #2 carries a `Beacon generator:` line.** It is a real `zkey beacon`
   application, not a contribution merely NAMED "beacon" — that distinction is the entire
   point of E14, because a named-only contribution greens C4.
2. **`Beacon iterations Exp: 10`** — matches the announced `numIterationsExp`.
3. **#2 is the LAST contribution.** Read off the NUMBER (2 > 1), never the output order:
   snarkjs prints newest-first, which is why #2 appears above #1.
4. **The generator equals the announced round's randomness, byte for byte.**

**Byte-for-byte cross-check, both retrievals recorded in full:**

```
snarkjs "Beacon generator:"     e45908ee8d0b15714eb1eb75f2f65a95864d1d3236b258b112f2bbd483c65194

$ curl https://api.drand.sh/public/6460200
{"round":6460200,"randomness":"e45908ee8d0b15714eb1eb75f2f65a95864d1d3236b258b112f2bbd483c65194",
 "signature":"a2e066fda518dc60d41fccbe217a4669e48f43d7c096155ad20d315f2ba71d4cffc207430f6048c206cf00bcdfe4065f0b7dde23512c22759ff8105044203c6dd19d64a68392f816eb746254d818de1f7c1be2c7e5e58ce313117322b108649c",
 "previous_signature":"88591f1f132770f7a201b09aa4d7ace759f958ca6e94efffe0aed54c13d235e9f63478dcce4ceb1f4420b006de7fa0d70a1e8220e7870d443f63e2b0ac170a53266fbe04ac7e1f7403f4bfbe9d7f190b4912715f8022ade9591bd60f44317fee"}

$ curl https://drand.cloudflare.com/public/6460200
{"round":6460200,
 "signature":"a2e066fda518dc60d41fccbe217a4669e48f43d7c096155ad20d315f2ba71d4cffc207430f6048c206cf00bcdfe4065f0b7dde23512c22759ff8105044203c6dd19d64a68392f816eb746254d818de1f7c1be2c7e5e58ce313117322b108649c",
 "previous_signature":"88591f1f132770f7a201b09aa4d7ace759f958ca6e94efffe0aed54c13d235e9f63478dcce4ceb1f4420b006de7fa0d70a1e8220e7870d443f63e2b0ac170a53266fbe04ac7e1f7403f4bfbe9d7f190b4912715f8022ade9591bd60f44317fee"}
```

All three hex strings are identical. The two endpoints are operated by different parties and
agree on the **chained BLS signature** as well as the randomness, so this is two independent
confirmations of the same beacon output, not one value read twice.

**And the announcement pre-dates all of it** (E11): commit `b13ec079…` at
**2026-09-12T15:14:18Z**, round 6460200 at **18:17:00Z**, operator contribution completed
**15:18Z**, beacon applied **18:37Z**. Announce → contribute → round → finalize, in that
order, with a 3-hour announcement lead. Had any of those slipped, the required response was
to ABORT and re-announce, not to proceed.

### 6.5 `verify_ceremony.mjs` changes made in this lane, and why

Two changes, both of which narrow or repoint a check and are therefore recorded here rather
than left to the diff:

1. **`--generation m5` is SUPERSEDED WHOLESALE.** Invariant 1 overwrote the very files m5's
   `zkey`/`vk` paths name, so after the copy m5 would fail C1, C3, C4, C5 and C6 — every
   file-reading check — by measuring the PRODUCTION key against DEV pins. Relabelling to a
   fresh path is impossible (`.gitignore` admits no new tracked dev-key path). So `m5` gains
   a `superseded` block, and the checker reports every check as SKIP-with-reason, reads no
   file, and exits 0 naming the superseding generation. **Only `--generation next` is wired
   into the gate.**
2. **The supersede mechanism cannot attach to the LIVE generation.** A stray `superseded` key
   on `next` would skip every check and still exit 0 — a green gate that verified nothing.
   `circuits/tests/ceremony_supersede.test.js` asserts `next` carries no `superseded`, that a
   superseded generation emits zero PASS and zero FAIL lines, and — the part that makes the
   rest mean anything — it first measures independently that the bytes at m5's vk path
   DISAGREE with m5's pin, so a checker that really read that file would have HAD to emit a
   FAIL. The assertion was confirmed to bite: adding `superseded` to `next` turns it red.

Also repointed: `wallet/tests/ceremony_bind_spend_manifest.test.ts` bound the shipped
manifest to `ceremony_material.next.dev_chain`. Left alone, it would have passed while the
wallet shipped the dev key. It now binds to `next.vk`/`next.zkey` and additionally asserts
the shipped values are NOT the dev-chain ones. `dev_chain` was NOT repointed at the
production artifacts — that would erase the superseded record.

---

## 7. Standing invariant

The four `DOMAIN_*` constants recorded in §2 are **FROZEN** once real unspent notes exist,
absent a note-migration mechanism (which does not exist).

The **ptau, zkey and VK are NOT** covered by that freeze — they may change under a later
circuit upgrade that preserves the commitment/nullifier computations and the public-signal
binding.

Full statement and reasoning: `docs/ceremony/CEREMONY_FREEZE_RULES.md` §1. The CTO authorized the matching `ARCHITECTURE.md` law line in
`cto-rulings-a3-prep-decisions-2026-07-31`.

---

## 8. Sign-off

| Role | Name | Date | Signature/commit |
|---|---|---|---|
| Ceremony operator | FutureProof operator — contribution `FutureProof operator 2026-09-12` | 2026-09-12 | contribution hash `7b0f1210…4fe8cbed` (§5 row 1); attestation of entropy handling in that row, first person |
| A1 (build) | STSH in-house builder, lane `lane/a4-landing` | 2026-09-12 | the single commit carrying this record; its sha256 is pinned in `VK_PIN.toml.record_transcript` |
| SSA (spot-check) | ⬜ **OPEN** — E14 is re-verified independently by the SSA at landed-diff (brief V2 §7). Not self-signed by the builder | ⬜ | ⬜ |
| CTO | ⬜ **OPEN** — lane acceptance | ⬜ | ⬜ |

The two open rows are open because those seats have not signed yet. A builder ticking them
would defeat the only purpose the row has.

### 8.1 Residuals carried OUT of this ceremony — disclosed, not fixed

1. **Phase 2 had ONE operator** (§4.2). The beacon finalization is what makes that
   materially smaller than M5's assumption, but it is not zero and is **not closed**. The
   community multi-party re-ceremony remains POST-launch.
2. **`DEV_VK_HASH_HEX` no longer names the live dev VK.** The deny literal in
   `scripts/verify_genesis_manifest/src/lib.rs:152` is `fc73ca4d…530dc8`, the M5 key. Since
   A-3 the live dev VK has been `081e9e9b…690f2`, which the deny list does NOT refuse — so
   arming the manifest with *that* key would have passed DPOOL-1b/8a/8b/9/9b. The
   protections that actually stood between this lane and that mistake are **E14** (a human
   reading raw beacon output) and the **C5/DPOOL-9 equality chain** (§6.2), not the deny
   list. Stated, not fixed: widening the deny list is a separate change with its own
   review, and this record does not claim it was done.
3. **CR-A4-1** — `verify_ceremony.mjs` C4 still performs no structural phase-2 beacon
   check. An all-GREEN run is NOT evidence the beacon is real; only E14 is. Carried for a
   post-launch C4 fix.
4. **C1's allowlist branch does not exercise the structural beacon parser** (§5.1), so the
   ptau layer's "54 contributions and a beacon" rests on the publisher's attestation plus
   the `powersoftau verify` output, not on a structural check this tool ran.
5. **CR-12** — release-identity build legs are same-host; cross-machine build independence
   is unproven. The A-4 before/after `env -i` pair is two legs on ONE machine.
6. **C6 narrowed** for six declared-stale artifacts (§6.3).
7. **E12 is OPEN** — the launch pool principal cannot be traced to a typed Vault creation
   receipt until J-18, because the pool does not exist yet.

---

## 9. A-4 PREP notes (2026-09-09) — read before executing Part 2

### 9.1 This file's hash is pinned. Editing it is never free.

`DPOOL-8b` (`scripts/verify_genesis_manifest/src/lib.rs:1575-1603`) requires
`sha256(docs/ceremony/CEREMONY_RECORD_v3.md)` == `VK_PIN.toml.record_transcript`, over
this file's **whole, unedited byte content**, and unlike DPOOL-8a it is **always on**.
The A-4 PREP pre-fill therefore re-hashed the record and rewrote `record_transcript` in
the **same commit**; `label` stayed `"DEV"` because DPOOL-9b is posture-gated on DPOOL-1b
and `genesis_manifest [pool_init].vk_hash` is still the all-zeros placeholder.

**Part 2 execution order — deliberate, and it resolves the circular dependency:**

1. Finish **ALL** edits to this file — the ⬜s in §2, §4.2, §5, §5.1, §5.2, §6, §6.1,
   §8. The last byte must be written before step 2 starts.
2. `sha256sum docs/ceremony/CEREMONY_RECORD_v3.md`.
3. Write that value into `VK_PIN.toml.record_transcript`. This works precisely because
   the hash lands in a *different* file, which does not feed back into these bytes.
4. Re-run `verify_genesis_manifest` and confirm **DPOOL-8a, 8b, 9 and 9b all pass** —
   **before** starting the `env -i` gate. Catching them here costs a local re-run;
   catching them inside the gate costs the only environment where the pinned hashes are
   reproducible (ARCHITECTURE.md 7(f)).

**Steps 1–3, the `VK_PIN.toml` `label` flip DEV → PRODUCTION, and the arming of
`genesis_manifest [pool_init].vk_hash` land in ONE commit** (SSA N4): DPOOL-8b is
always-on and DPOOL-9b is posture-gated, so splitting them leaves an intermediate commit
that reads as a genuine failure to anyone running the checker mid-lane.

**SUPERSEDE RULE: this record is never edited after its hash is pinned.** Any later
touch — a typo, a whitespace change, a reformat — re-opens step 1 and requires
re-executing 2–4 in full. "Just one small fix to the record" is a re-run trigger, not a
footnote.

### 9.2 RESOLVED: the Hermez ptau, and why it did not come from a canonical host

On 2026-09-09 both canonical sources returned **HTTP 403 to anonymous callers**:

- `https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_16.ptau` — S3
  `AccessDenied` (the `justfile:59-63` recipe's URL; bucket listing also 403)
- `https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau` — GCS
  `Anonymous caller does not have storage.objects.get access` (the URL the snarkjs
  README table links to)

Egress from the build host is open (`example.com`, `registry.npmjs.org` and
`api.drand.sh` all returned 200 in the same session), so these are **genuine upstream
revocations, not a local network problem.** The halo2-kzg-srs mirror bucket returned 403
too, and two GitHub repositories that appear to host the file had in fact committed the
403 XML body under the `.ptau` name — a trap worth naming, because such a file is present,
non-empty, and completely wrong.

**Resolution (Addendum F).** The file was recovered from a **GitHub LFS** copy and adopted
at **power 15**, and `PUBLIC_PTAU_ALLOWLIST` is now populated with an entry carrying BOTH
digests. The revoked buckets cost nothing: **the attestation was never the host.** It is the
publisher's blake2b-512 hash list, and the recovered file matches that value exactly (§5.1),
so the bytes are the Hermez ceremony output regardless of who served them. This is also why
the `justfile` `download-ptau` recipe now fetches from the mirror and **fails closed on a
digest mismatch, deleting the file** rather than leaving unverified bytes on disk for a later
step to consume.

Power 16 was not adopted only because power 15 was the copy recoverable with a matching
attested hash; 2^15 = 32,768 covers the circuit's 10,593 constraints with 22,175 headroom,
and the two files carry the identical 54-contribution-plus-beacon transcript. An authentic
`powersOfTau28_hez_final_17.ptau` (blake2b matching README row 17) is retained alongside it
at `$HOME/ptau/` as a spare, unused unless the circuit grows past 32,768 constraints.
