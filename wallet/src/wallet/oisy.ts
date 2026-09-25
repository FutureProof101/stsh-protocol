/**
 * OISY wallet-signer integration (wallet-build Commit 6, BUILD_PLAN §1.6;
 * corrective lane AC-2 — @dfinity/oisy-wallet-signer 0.4 / ledger-icrc 3).
 *
 * The shield flow's icrc2_approve runs through the user's wallet so THEY see and
 * confirm the consent (spender = shielded pool, amount, ledger) — the wallet
 * front-end never holds the user's ledger key. Uses @dfinity/oisy-wallet-signer
 * IcrcWallet (an ICRC-25/27/49 relying party).
 *
 * AC-2 typing contract (verified against the installed 0.4.0 types):
 * `ApproveParams` comes from @dfinity/ledger-icrc@3, whose `spender` is a
 * ledger `Account` with `owner: Principal` — a typed conversion, not a text
 * passthrough. The TOP-LEVEL `owner` stays `PrincipalText` (string) per
 * `IcrcAccount`. All principal texts are validated BEFORE the signer popup
 * opens: a malformed principal fails fast here, never mid-consent.
 *
 * Structural, like the workers: it drives real popup/signature flows that
 * can't run headless; the payload shape is covered by tests/oisy_approve.
 */

import { IcrcWallet } from "@dfinity/oisy-wallet-signer/icrc-wallet";
import { Principal } from "@dfinity/principal";

import { approvalExpiresAt } from "../actors/token";

export interface ShieldApprovalRequest {
  /** Relying-party (wallet) URL, e.g. https://oisy.com/sign. */
  walletUrl: string;
  /** IC host the wallet should target. */
  host: string;
  /** The connected account owner (principal text) approving the allowance. */
  owner: string;
  /** STSH ledger canister id (principal text). */
  ledgerCanisterId: string;
  /** The spender to approve — the shielded pool principal (text). */
  spender: string;
  /** Allowance amount in base units (sum of the shield denominations + fee headroom). */
  amount: bigint;
  /**
   * WT-1 — REQUIRED compare-and-set guard, the same non-negotiable the
   * in-app path has carried all along (`actors/token.ts` `ApproveRequest`).
   * The allowance the caller observed immediately before approving; the ledger
   * rejects with `AllowanceChanged` if the live value differs.
   *
   * It was ABSENT on this path, which made the two paths disagree on a safety
   * property — and a guard present on one of two approve routes is not a guard,
   * it is a route an attacker picks. Required rather than optional for the same
   * reason it is required there: a blind approve must be unrepresentable, not
   * merely discouraged.
   */
  expectedAllowance: bigint;
  /**
   * WT-1 — REQUIRED stable dedup timestamp (ns). The expiry is derived from it
   * (see `approvalExpiresAt`), so a retry reproduces the same absolute bound
   * rather than sliding it forward on every attempt.
   */
  createdAtTime: bigint;
}

/**
 * Connect the wallet, request an icrc2_approve for the shielded pool as spender,
 * and return the approval block index. The user confirms the consent message in
 * their wallet.
 */
export async function approveForShield(req: ShieldApprovalRequest): Promise<bigint> {
  // Validate every principal BEFORE opening the signer popup (AC-2 fail-fast):
  // the spender needs a typed Principal for the ledger-icrc Account; owner and
  // ledger id stay PrincipalText on the wire but must still parse.
  const spender = Principal.fromText(req.spender);
  Principal.fromText(req.owner);
  Principal.fromText(req.ledgerCanisterId);

  const wallet = await IcrcWallet.connect({ url: req.walletUrl, host: req.host });
  try {
    return await wallet.approve({
      owner: req.owner,
      ledgerCanisterId: req.ledgerCanisterId,
      params: {
        spender: { owner: spender, subaccount: [] },
        amount: req.amount,
        // WT-1 — both paths must agree; a bound on one of them is a hole.
        // `@dfinity/ledger-icrc@3` takes these as plain optionals and does the
        // candid `opt` wrapping itself, unlike the raw actor in `actors/token.ts`.
        expected_allowance: req.expectedAllowance,
        expires_at: approvalExpiresAt(req.createdAtTime),
      },
    });
  } finally {
    await wallet.disconnect();
  }
}
