/**
 * Shield fee math (Campaign B / L3a) — a byte-exact mirror of the Rust
 * fee-policy crate's deposit preview (canisters/fee-policy/src/lib.rs,
 * `value_fee` + `compute_deposit_preview`), which the pool applies inside
 * `shield_deposit`:
 *
 *   protocol_shielding_fee = max(shield_flat_minimum_fee_e8s,
 *                                gross * shield_fee_bps / 10_000)   [floor]
 *   pool_transfer_in       = gross + protocol_shielding_fee         [fee-ON-TOP]
 *   total_public_debit     = pool_transfer_in + ledger_fee
 *
 * Fee-ON-TOP is LOCKED (fee-build lane §2): the note is credited the FULL
 * denomination, so the fixed-denomination invariant (anti-drift law #1) holds
 * at any fee. All math is bigint — no floats, floor division (rounds in the
 * user's favour), and JS bigints cannot wrap.
 *
 * Fail-closed versioning (B3 §0.4): the wallet computes fees ONLY for
 * fee-model version 1. A pool reporting any other version means the formula
 * changed shape — the wallet must ABORT, never guess.
 */

import type { ShieldFeeParams } from "../actors/pool";

/** The one fee-model version this wallet's formula implements. */
export const WALLET_FEE_MODEL_VERSION = 1;

/** The pool's fee configuration is outside what this wallet can price. */
export class FeeModelUnsupportedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FeeModelUnsupportedError";
  }
}

/** The denomination violates a pool-side fee precheck — would fail on-chain. */
export class ShieldPrecheckError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ShieldPrecheckError";
  }
}

/** `max(flat_minimum, amount * bps / 10_000)` — mirrors fee-policy `value_fee`. */
export function shieldProtocolFee(denom: bigint, params: ShieldFeeParams): bigint {
  const byBps = (denom * BigInt(params.shieldFeeBps)) / 10_000n;
  return params.shieldFlatMinimumFeeE8s > byBps ? params.shieldFlatMinimumFeeE8s : byBps;
}

/**
 * `max(unshield_flat_minimum, public_amount * unshield_bps / 10_000)` — the EXIT
 * fee, mirroring fee-policy's `unshield_protocol_fee` (lane A-7).
 *
 * The basis is `public_amount`: the gross leaving the shielded set, i.e. the
 * recipient's net plus the live ledger fee — exactly the number the pool checks
 * and the number bound into public signal[5]. Integer arithmetic throughout, and
 * floor division, so the wallet and the canister round identically; a `number`
 * or a float here would diverge from the canister at the last e8s.
 *
 * Cross-checked against the CANISTER's own answers (not against the Rust source)
 * in `wallet/tests/a7_exit_fee_mirror.test.ts`, over the table the pool produced
 * by call in `integration-tests/tests/a7_exit_fee_symmetry_tests.rs`.
 */
export function unshieldProtocolFee(publicAmount: bigint, params: ShieldFeeParams): bigint {
  const byBps = (publicAmount * BigInt(params.unshieldFeeBps)) / 10_000n;
  return params.unshieldFlatMinimumFeeE8s > byBps ? params.unshieldFlatMinimumFeeE8s : byBps;
}

/**
 * The fee a `private_spend` must carry (lane A-7). With a public payout it is the
 * unshield value fee on the payout's gross; without one it is the flat protocol
 * spend fee, unchanged.
 *
 * One function so the two call sites in `spendFlow` — the basis and the
 * pre-dispatch drift re-check — cannot drift apart from each other.
 */
export function privateSpendFee(
  publicAmount: bigint | undefined,
  params: ShieldFeeParams,
): bigint {
  return publicAmount === undefined
    ? params.protocolPrivateSpendFeeStsh
    : unshieldProtocolFee(publicAmount, params);
}

export interface ShieldDepositPreview {
  /** The denomination (gross). With fee-on-top this is also the credited amount. */
  denom: bigint;
  protocolFee: bigint;
  /** `denom + protocolFee` — the ICRC-2 transfer_from amount the pool pulls. */
  poolTransferIn: bigint;
  /** `poolTransferIn + ledgerFee` — what the allowance must cover for this note. */
  totalPublicDebit: bigint;
}

/**
 * Per-note deposit preview, mirroring the pool's `compute_deposit_preview`
 * prechecks that depend only on amount + params (the live balance/allowance
 * checks happen at approve/deposit time).
 */
export function shieldDepositPreview(
  denom: bigint,
  ledgerFee: bigint,
  params: ShieldFeeParams,
): ShieldDepositPreview {
  if (params.feeModelVersion !== WALLET_FEE_MODEL_VERSION) {
    throw new FeeModelUnsupportedError(
      `the pool reports fee-model version ${params.feeModelVersion}; this wallet prices ` +
        `version ${WALLET_FEE_MODEL_VERSION} only — refusing to shield (never guess a fee)`,
    );
  }
  // Fee-on-top: private_balance_credit == denom; mirror the pool's
  // minimum_private_credit precheck so the failure is local and typed.
  if (denom < params.minimumPrivateCredit) {
    throw new ShieldPrecheckError(
      `denomination ${denom} is below the pool's minimum private credit ${params.minimumPrivateCredit}`,
    );
  }
  const protocolFee = shieldProtocolFee(denom, params);
  const poolTransferIn = denom + protocolFee;
  return { denom, protocolFee, poolTransferIn, totalPublicDebit: poolTransferIn + ledgerFee };
}

/**
 * Whether two fee snapshots price shields identically. Used for the L3a
 * staleness re-check: the snapshot taken before approval must still hold
 * before the deposits submit — any drift ABORTS (fail closed, never guess).
 */
export function sameShieldFeeBasis(a: ShieldFeeParams, b: ShieldFeeParams): boolean {
  return (
    a.shieldFeeBps === b.shieldFeeBps &&
    a.shieldFlatMinimumFeeE8s === b.shieldFlatMinimumFeeE8s &&
    a.minimumPrivateCredit === b.minimumPrivateCredit &&
    a.feeModelVersion === b.feeModelVersion &&
    a.paramsEpoch === b.paramsEpoch
  );
}

/**
 * WL-3 — the largest PUBLIC amount a note of value `noteValue` can actually
 * exit with, once the exit protocol fee is funded FROM THE NOTE.
 *
 * The defect this closes: the spend page bounded the payout by the raw note
 * value, so a 1,000-STSH note appeared able to exit 1,000 STSH. It cannot —
 * `runSpendFlow` requires `note.value >= public_amount + unshieldProtocolFee
 * (public_amount)`, so the true ceiling is strictly smaller. Showing the raw
 * value is a disclosure defect (the user is told a number the protocol will
 * not honour), not a fund-loss one: `spendFlow.ts` already fails closed.
 *
 * Defined as the largest `p` in `[0, noteValue]` with
 *
 *     p + unshieldProtocolFee(p, params) <= noteValue
 *
 * `g(p) = p + unshieldProtocolFee(p, params)` is non-decreasing in `p` (both
 * terms are), so the feasible set is a prefix and a binary search returns the
 * exact maximum — no closed form that has to case-split the flat arm against
 * the bps arm, and no rounding step that could disagree with the canister at
 * the last e8s. All bigint, floor division, same as the fee itself.
 *
 * NOTHING here is precomputed. The maximum a given note exits with is an
 * OUTPUT of this function at the live governance params; the wallet must never
 * carry that figure — for a 1,000-STSH note or any other — as a constant, in
 * code or in a comment. The number lives in the A-7 fixture, which is the
 * canister's own answer, and in the test that reads it.
 *
 * Fail-closed versioning, same contract as `shieldDepositPreview`: an unknown
 * fee-model version means the formula changed shape, so the wallet refuses to
 * quote a maximum rather than guessing one. It never falls back to
 * `noteValue`.
 */
export function maxPublicAmount(noteValue: bigint, params: ShieldFeeParams): bigint {
  if (params.feeModelVersion !== WALLET_FEE_MODEL_VERSION) {
    throw new FeeModelUnsupportedError(
      `the pool reports fee-model version ${params.feeModelVersion}; this wallet prices ` +
        `version ${WALLET_FEE_MODEL_VERSION} only — refusing to quote a maximum exit ` +
        `(never guess a fee, and never fall back to the note value)`,
    );
  }
  if (noteValue <= 0n) return 0n;
  const fits = (p: bigint): boolean => p + unshieldProtocolFee(p, params) <= noteValue;
  if (!fits(0n)) return 0n; // the flat minimum alone already exceeds the note
  let lo = 0n; // always feasible
  let hi = noteValue; // may or may not be feasible
  while (lo < hi) {
    const mid = (lo + hi + 1n) / 2n;
    if (fits(mid)) lo = mid;
    else hi = mid - 1n;
  }
  return lo;
}

/**
 * The largest RECIPIENT NET a note can pay out — display only.
 *
 * The gross (`public_amount`) is what the pool checks and what signal[5]
 * binds; the recipient sees the gross MINUS the live ledger fee. These are
 * two different numbers and the UI must never label one as the other, so the
 * conversion lives here once rather than at each call site.
 */
export function maxRecipientNet(noteValue: bigint, ledgerFee: bigint, params: ShieldFeeParams): bigint {
  const gross = maxPublicAmount(noteValue, params);
  return gross > ledgerFee ? gross - ledgerFee : 0n;
}
