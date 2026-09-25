# STSH Development Task Runner
# Install: cargo install just
# Usage:   just <recipe>

# ── Local development ─────────────────────────────────────────────────────────

# Start local ICP replica in background
start:
    dfx start --background --clean

# Stop local replica
stop:
    dfx stop

# Deploy all canisters to local replica
deploy:
    dfx deploy

# Deploy a single canister (e.g.: just deploy-one stsh_token)
deploy-one canister:
    dfx deploy {{canister}}

# ── Build ─────────────────────────────────────────────────────────────────────

# Build all Rust canisters
build:
    cargo build --target wasm32-unknown-unknown --release

# Optimise SIX canisters (shrinks Wasm size) — NOT all of them.
#
# The loop names six of the crates the workspace builds. DIRECTORY NAME AND
# PACKAGE NAME ARE NOT THE SAME THING and `token` is where they diverge: the
# directory is `canisters/token`, the package is `stsh_token`, so the artifact
# is `stsh_token.wasm`. `${canister//-/_}` alone yielded `token.wasm`, which no
# build ever produces — the loop's first iteration always failed. `$canister`
# is the DIRECTORY, `$pkg` is the ARTIFACT STEM; every use below picks the one
# it actually means. Widening the loop to the whole fleet is still a separate
# change owned by whoever owns this justfile.
build-opt:
    cargo build --target wasm32-unknown-unknown --release
    for canister in token shielded-pool nullifier-registry merkle-tree vesting treasury; do \
        pkg=$canister; if [ "$canister" = "token" ]; then pkg=stsh_token; else pkg=${canister//-/_}; fi; \
        ic-wasm target/wasm32-unknown-unknown/release/$pkg.wasm -o target/wasm32-unknown-unknown/release/${pkg}_opt.wasm shrink; \
    done

# Build browser WASM prover (M3)
build-prover:
    cd circuits/prover && wasm-pack build --target web --out-dir ../../wallet/src/wasm

# ── ZK circuit toolchain ──────────────────────────────────────────────────────

# Compile the spend circuit (generates R1CS + WASM + symbols)
compile-circuit:
    mkdir -p circuits/build
    circom circuits/spend.circom \
        --r1cs --wasm --sym --json \
        --output circuits/build

# Download the launch phase-1 powers of tau (Hermez, power 15 — 2^15 = 32768 constraints max).
#
# A-4 (CTO ruling: RULING_RECORD_LAUNCH_WEEK_2026-09-09.md Addendum F). This recipe used to
# fetch power 16 from hermez.s3-eu-west-1.amazonaws.com. BOTH canonical hosts — that S3 bucket
# AND storage.googleapis.com/zkevm/ptau/, the URL the snarkjs README links to — return
# 403 AccessDenied to anonymous callers as of 2026-09-09, so this now fetches from a GitHub LFS
# mirror. The URL is a DOWNLOAD SOURCE, NOT AN ATTESTATION.
#
# The ATTESTATION is the publisher's blake2b-512, published in the snarkjs (iden3) README
# powers-of-tau table (row power=15), retrieved 2026-09-09:
#   https://raw.githubusercontent.com/iden3/snarkjs/master/README.md
# Which host serves the bytes does not matter once the hashes match — which is why this recipe
# FAILS CLOSED on a hash mismatch and deletes the file rather than leaving unverified bytes on
# disk for a later step to pick up. The same two digests are pinned in
# circuits/scripts/verify_ceremony.mjs PUBLIC_PTAU_ALLOWLIST and in
# circuits/ceremony/domain_manifest.json ceremony_material.next.ptau; all three must agree.
download-ptau:
    mkdir -p circuits/ptau
    wget -O circuits/ptau/powersOfTau28_hez_final_15.ptau \
        https://media.githubusercontent.com/media/hswopeams/composite-number-game/main/circuit/powersOfTau28_hez_final_15.ptau
    #
    # Verify BOTH digests before the file is usable. b2sum's default IS blake2b-512.
    echo "982372c867d229c236091f767e703253249a9b432c1710b4f326306bfa2428a17b06240359606cfe4d580b10a5a1f63fbed499527069c18ae17060472969ae6e  circuits/ptau/powersOfTau28_hez_final_15.ptau" \
        | b2sum -c - || (rm -f circuits/ptau/powersOfTau28_hez_final_15.ptau; \
                         echo "BLAKE2B MISMATCH — not the attested Hermez ptau; file deleted"; exit 1)
    echo "3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f  circuits/ptau/powersOfTau28_hez_final_15.ptau" \
        | sha256sum -c - || (rm -f circuits/ptau/powersOfTau28_hez_final_15.ptau; \
                             echo "SHA256 MISMATCH — file deleted"; exit 1)

# Run Groth16 setup (generates proving key + verifying key)
# Run once after circuit is finalised; output is committed to repo
setup-groth16: compile-circuit
    snarkjs groth16 setup \
        circuits/build/spend.r1cs \
        circuits/ptau/powersOfTau28_hez_final_15.ptau \
        circuits/build/spend_0000.zkey
    # TODO: run a contribution ceremony before mainnet — this is a dev-only key
    snarkjs zkey contribute \
        circuits/build/spend_0000.zkey \
        circuits/build/spend_final.zkey \
        --name "dev contribution" -v -e "$(openssl rand -hex 32)"
    snarkjs zkey export verificationkey \
        circuits/build/spend_final.zkey \
        circuits/build/verification_key.json

# Export Solidity verifier (reference — actual verifier is in Rust for ICP)
export-verifier:
    snarkjs zkey export solidityverifier \
        circuits/build/spend_final.zkey \
        circuits/build/verifier_reference.sol

# Generate a test proof (for dev/testing only)
test-proof:
    snarkjs groth16 prove \
        circuits/build/spend_final.zkey \
        circuits/build/spend_js/witness.wtns \
        circuits/build/proof.json \
        circuits/build/public.json
    snarkjs groth16 verify \
        circuits/build/verification_key.json \
        circuits/build/public.json \
        circuits/build/proof.json

# ── Candid ────────────────────────────────────────────────────────────────────

# Re-generate .did files for the SIX canisters named below — not for every
# canister in the workspace.
#
# The DESTINATION is what made the old `token` entry worse than a no-op. dfx
# reads `canisters/token/stsh_token.did` (`dfx.json`), so writing
# `canisters/token/token.did` created an ORPHAN beside the file dfx actually
# loads, and left that file to go stale unnoticed. Same `$canister`/`$pkg`
# split as `build-opt`: directory vs. artifact stem.
gen-did:
    for canister in token shielded-pool nullifier-registry merkle-tree vesting treasury; do \
        pkg=$canister; if [ "$canister" = "token" ]; then pkg=stsh_token; else pkg=${canister//-/_}; fi; \
        candid-extractor target/wasm32-unknown-unknown/release/$pkg.wasm \
            > canisters/$canister/$pkg.did; \
    done

# ── Testing ───────────────────────────────────────────────────────────────────

# Fails loud on any missing prerequisite; see ARCHITECTURE.md law #7.
# THE GATE: two-phase build (the test-Wasms named by run_gate.sh's own
# TEST_CANISTERS array — the count is NOT restated here, see the R-10 lint in
# run_gate.sh) + workspace + vetkeys + wallet + solvency-status, one verdict
gate:
    ./run_gate.sh

# Continues when environment prerequisites are absent; exits non-zero.
# Gate WITHOUT prerequisites — reports PARTIAL, never a pass
gate-partial:
    ./run_gate.sh --partial

# O-12. PREPARATION, NOT A GATE LEG — it asserts presence, never a verdict.
# Derives the required artifact set from the tree (run_gate.sh's own
# TEST_CANISTERS/PROD_PACKAGES, integration-tests/build.rs, the test sources and
# run_gate.sh's prerequisite checks), prints the derived count, and names the
# exact producing command for anything missing. Report-only by default.
# Prepare a FRESH worktree so ./run_gate.sh can run — report only
prepare-worktree:
    ./scripts/prepare_fresh_worktree.sh

# Builds the two cargo phases, the excluded vetkeys crate and the three npm
# trees, then re-derives. Predecessor fixtures are NEVER synthesised from
# current source — rebuilding one would make the test that consumes it vacuous.
# Prepare a fresh worktree AND build what this tree can produce
prepare-worktree-run:
    ./scripts/prepare_fresh_worktree.sh --prepare

# Skips the two-phase Wasm build (integration tests may run against stale or
# missing artifacts) and cannot see canisters/vetkeys, which is workspace-
# EXCLUDED. Run `just gate` before claiming anything is green.
# Quick unit-test loop — NOT THE GATE
test:
    cargo test

# Run integration tests against local replica
test-integration:
    dfx start --background --clean
    dfx deploy
    cargo test --test integration
    dfx stop

# Run pool solvency invariant check
test-solvency:
    cargo test solvency -- --nocapture

# ── Mainnet ───────────────────────────────────────────────────────────────────

# B-2: the `deploy-mainnet` recipe was DELETED 2026-09-14 — raw `dfx deploy --network ic` bypassed the Vault, the only sanctioned install route. Mainnet installs go through docs/A7_INSTALL_RUNBOOK.md.

# Check canister Wasm hash matches source build
verify-wasm canister:
    @echo "On-chain hash:"
    dfx canister --network ic info {{canister}}
    @echo "Local build hash:"
    sha256sum target/wasm32-unknown-unknown/release/{{canister}}.wasm
