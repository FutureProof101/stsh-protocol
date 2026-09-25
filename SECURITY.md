# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository: open the
**Security** tab and choose **Report a vulnerability**. This creates a private
advisory visible only to the maintainers. There is no email channel.

Please do **not** open a public issue, discussion or pull request for a
vulnerability.

We handle reports on a best-effort basis. There is no guaranteed response time.

## Bug bounty

There is no bug bounty programme.

## Scope

In scope:

- `canisters/`: every deployed canister listed in the README.
- `circuits/`: the spend circuit, the proving key and the verification key.
- `wallet/`: the app.stsh.fi wallet bundle.
- `website/solvency-status/`: the reserves.stsh.fi page.
- Release and verification tooling under `scripts/`.

Out of scope:

- The stsh.fi marketing site, which is not in this repository.
- Third-party dependencies. Please report those upstream.
- Volumetric denial-of-service against Internet Computer boundary nodes.

## Known, disclosed limitations

These are already public and do not need to be reported:

- The trusted setup has a single phase-2 human contributor (see
  `TRUSTED_SETUP.md`).
- The submitting account is public on every spend, and a single deposit can be
  linked to its payout.
- Withdraw (unshield) is not built.
- The founder still holds direct controller keys, and two of the three
  multisig keys.
- No external audit has been done. One is planned.
- The solvency monitor detects a drain. It does not prevent one.

## Supported version

The supported version is the commit in this repository. It matches the deployed
release, as described in `PROVENANCE.md`.
