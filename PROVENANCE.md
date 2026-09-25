# Provenance of this export

This repository's single commit is an export of the project's private
development repository at head `213bd19eddc29f663fbe0f40f05c6db2009f2a78`
("chore(release): TOKEN-APPROVE-TTL …"). It was made on 2026-09-24.

## Input

- `git archive --format=tar 213bd19eddc29f663fbe0f40f05c6db2009f2a78`
- sha256 of that tarball: `3d155fd6ae9eadc047980bf7f4d16098f4ac5db3b443252d2755b483e721af8a`
  (produced with git 2.34.1)

A file cannot contain its own hash. The public commit's tree hash and the
sha256 of `git archive --format=tar HEAD` of the public commit are therefore
published in the release notes, not here.

## Changes against the input tree

1. **Excluded paths.** These are internal process documents, plus one binary:
   - two internal agent-context files at the repository root;
   - `DOC_TRIAGE.md`, `QA_DEFECT_LEDGER.md`, `QA_FEATURE_LEDGER.md`,
     `CIRCUIT_AUDIT_NOTES.md`, `REPRODUCIBLE_BUILD_REVIEW.md`,
     `TOKENOMICS_PROPOSAL.md`;
   - `docs/L4_AUTHORITY_PIN_HANDOFF.md`, `docs/L4_CUSTODY_FINALIZATION_DESIGN.md`,
     `docs/archive/` (3 files), `docs/DOC_STALENESS_REGISTER.md`,
     `docs/STSH_A2_Full_Active_Root_Finality_Proposal.md`;
   - `docs/ceremony/PTAU_MULTIPARTY_PLAN.md`,
     `docs/ceremony/CEREMONY_FREEZE_RULES.md`,
     `docs/ceremony/CEREMONY_RECORD_v2_TEMPLATE.md`,
     `docs/ceremony/acceptance-evidence-m5-baseline.txt`;
   - `docs/repro-build-2026-06-21/` (2 files);
   - `canisters/treasury/CUSTODY_DECISION.md`, `wallet/BUILD_PLAN.md`;
   - `deployment/mainnet/stsh_token_init.bin` (see "Owner-name redaction"
     below).

   The previous `README.md` was replaced. Some code comments and records still
   name excluded documents. Those references dangle by design.
2. **In-line rewrites of comments and text.** These remove third-party, partner
   and model names, and internal machine paths. Line numbers are preserved in
   every rewritten file.
3. **Wording fixes** in `canisters/smoke-alarm-monitor/OPERATIONS.md` and
   `docs/SOLVENCY_ATTESTATION_SPEC.md`, which removed wording that overstated
   audit and external-review status.
4. **Renames.** Two regression test files were renamed to
   `integration-tests/tests/ext_regression_*.rs`, and one test function to
   `residual_ext_dbr001_supported_standards_pinned`.
5. **Gate-lint data.** `scripts/gate_lints/CORPUS.toml` and
   `scripts/gate_lints/claims_baseline.toml` now follow the excluded and renamed
   files.
6. **ICRC reference ledger.** Its default path in
   `integration-tests/tests/token_icrc_conformance_tests.rs` is now
   `target/icrc-ref/ic-icrc1-ledger.wasm.gz`.
7. **Release record.** `asserts_identity_at` in `release_hashes.toml` was
   rebound, record-only, as the release-identity rule requires after a change
   under `canisters/`.
8. **Ceremony record.** It is published as a redacted revision, and its
   `record_transcript` pin is rebound (see below).
9. **New files.** `README.md`, `ARCHITECTURE.md`, `SECURITY.md`,
   `TRUSTED_SETUP.md`, `PROVENANCE.md` and `LICENSE`, plus `.gitignore`
   additions.

## Owner-name redaction

The Owner's personal name and country were removed from every file.

- The genesis allocation label `"Founder (single, <name>)"` is now `"founder"`
  in:
  - `deployment/mainnet/genesis_manifest.toml`;
  - `deployment/mainnet/stsh_token_init.did`;
  - the approved-schema checker (`scripts/verify_genesis_manifest`), together
    with its pin test.
- The pinned sha256 of `deployment/mainnet/genesis_principals.toml` was rebound,
  because one of its comments was redacted.
- `deployment/mainnet/stsh_token_init.bin` is not included.

**The genesis manifest's contributor label is redacted in this export. The
recorded install-arg hashes (`deployment/mainnet/a7_install_kit.toml`
`arg_sha256` / `arg_text_sha256`) are the true on-chain values, and they cannot
be reproduced from the public tree alone.** The same applies to the vesting
init-arg text hash, because comments in `vesting_init.did` were redacted. The
vesting `.bin` is unchanged and still re-encodes byte-identically.

The A-7 install-kit checker runs in a disclosed redacted mode for these two
entries and prints one `REDACTED (public export)` line per skipped check.
`--emit` refuses both entries.

## Ceremony record

The record is published as `docs/ceremony/CEREMONY_RECORD_v3.md`, a redacted
revision of the private v2 record. The v2 sha256 is
`bb608ebac2d07df6ac5ac47be457fd7e140ecbf319c499e5b0d0c5c137cb1aaf`. The
`record_transcript` pin in `scripts/verify_genesis_manifest/VK_PIN.toml` and its
test mirror are rebound to v3. See `TRUSTED_SETUP.md`.

## Content left unchanged on purpose

Six lines keep the original builder's home path. The release Wasms embed that
path, and byte-for-byte reproduction needs it:

- `deployment/mainnet/release_hashes.toml`: three lines;
- the d068 fixture recipe (`canisters/vault/tests/fixtures/d068_canonical_v1.PROVENANCE.md`):
  two lines;
- `README.md`: one line.

The comments in `canisters/vetkeys/src` are byte-identical to the private
source, and some of them still carry internal review-round ids and
internal-document names. Rewriting them was measured to change the vetkeys Wasm
away from its pin, so they are left unchanged. Only the
manifest comment in `canisters/vetkeys/Cargo.toml` and the comments in
`canisters/vetkeys/tests/` were reworded. Both changes were measured to leave
the Wasm byte-identical.

## Wallet package

The `description` in `wallet/package.json` and some wallet source comments were
reworded. The wallet bundle built from this tree (`cd wallet && npm run build`,
Node 22.23.1) is byte-identical to the one built from the unredacted private head,
and equals the recorded `[wallet_bundle]` pin: sha256
`9d4b4af9076868ff4c6c6c513723337c3da23db3f0301ee29455ce1b9dbfad6d` by the
record's manifest procedure, 15 files, 14,337,769 bytes.

## Invariants

- In `deployment/mainnet/release_hashes.toml`, no `sha256`, `bytes`,
  `source_sha` or `[build]` value changed. Only `asserts_identity_at` and
  comment text changed.
- A clean `env -i` build of this tree reproduced the ten pinned release Wasms
  and vetkeys `4ea38e5f…` byte-identically.
- The full gate (`./run_gate.sh`) was run once on 2026-09-25 and returned
  `GATE PASSED`: workspace 2480 passed, vetkeys 292 passed, wallet 1376 passed,
  website 97 passed, circuits 26 passed, 0 failed in every leg. It ran on a
  private tree (git tree hash `685c47e2235d7cf07786a39beeccdedee72a64d9`) that
  differs from this commit only in `README.md` and `PROVENANCE.md`, where
  pending markers were replaced with these results. It asserted all ten release
  pins with release identity armed, and vetkeys `4ea38e5f…`. The A-7 install-kit
  stage ran in the redacted mode described above.

Commit SHAs cited in comments and records refer to the private history. They are
provenance, and they cannot be resolved in this repository.
