/**
 * Display + amount formatting for the Campaign-B (shielded) pages.
 *
 * The pure STSH <-> base-unit helpers moved to ui/tokenFormat.ts in the A1
 * isolation split (H-A3): this module imports crypto/notes + storage/noteCache
 * (both Campaign B), so Wave-1 code must import tokenFormat directly, never
 * this file. The re-exports below keep a single amount-format implementation
 * for the Campaign-B pages and existing tests.
 */

import { DENOMINATIONS, decomposeAmount } from "../crypto/notes";
import type { ScannedNote } from "../storage/noteCache";

import { formatStsh } from "./tokenFormat";

export { STSH_DECIMALS, formatStsh, parseStsh } from "./tokenFormat";

export interface DenomBucket {
  denom: bigint;
  count: number;
  subtotal: bigint;
}

export interface BalanceSummary {
  buckets: DenomBucket[];
  total: bigint;
  noteCount: number;
}

/** Summarise a recovered note set into per-denomination buckets + total. */
export function summarizeBalance(notes: ScannedNote[]): BalanceSummary {
  const counts = new Map<bigint, number>();
  let total = 0n;
  for (const n of notes) {
    counts.set(n.value, (counts.get(n.value) ?? 0) + 1);
    total += n.value;
  }
  const buckets: DenomBucket[] = [...counts.entries()]
    .map(([denom, count]) => ({ denom, count, subtotal: denom * BigInt(count) }))
    .sort((a, b) => (a.denom < b.denom ? -1 : a.denom > b.denom ? 1 : 0));
  return { buckets, total, noteCount: notes.length };
}

export interface ShieldPlan {
  /** The denomination notes the amount decomposes into (ascending grouped). */
  buckets: DenomBucket[];
  /** Flat list of note denominations to shield, largest first. */
  notes: bigint[];
  total: bigint;
}

/**
 * Preview how a shield amount decomposes into fixed-denomination notes
 * (deposit is fixed-denomination only — anti-drift law #1). Throws if the
 * amount is not exactly decomposable.
 */
export function planShield(amountBaseUnits: bigint): ShieldPlan {
  const notes = decomposeAmount(amountBaseUnits);
  const counts = new Map<bigint, number>();
  for (const d of notes) counts.set(d, (counts.get(d) ?? 0) + 1);
  const buckets: DenomBucket[] = [...counts.entries()]
    .map(([denom, count]) => ({ denom, count, subtotal: denom * BigInt(count) }))
    .sort((a, b) => (a.denom < b.denom ? -1 : a.denom > b.denom ? 1 : 0));
  return { buckets, notes, total: amountBaseUnits };
}

/** The five fixed denominations, for rendering the shield denomination chips. */
export const SHIELD_DENOMINATIONS: readonly bigint[] = DENOMINATIONS;

/**
 * WALLET-UI Addendum 2 item 6: the decomposition refusal from
 * `decomposeAmount` carries the amount in raw base units ("Amount
 * 150000000000 is not decomposable…"). Say it in STSH, one idea per line, and
 * name what WOULD fit: the ladder and the nearest shieldable amount below.
 * Returns null for any other message.
 */
export function shieldAmountErrorLines(message: string): string[] | null {
  const m = /^Amount (\d+) is not decomposable/.exec(message);
  if (m === null) return null;
  const amount = BigInt(m[1]!);
  const step = DENOMINATIONS[0];
  const lower = (amount / step) * step;
  const lines = [
    `${formatStsh(amount)} STSH can't be split into notes.`,
    `Notes come in ${DENOMINATIONS.map((d) => formatStsh(d)).join(" / ")} STSH.`,
  ];
  if (lower === 0n) {
    lines.push(`Smallest amount: ${formatStsh(step)} STSH.`);
  } else {
    let shape = "";
    try {
      shape = planShield(lower)
        .buckets.slice()
        .reverse()
        .map((b) => `${b.count} × ${formatStsh(b.denom)}`)
        .join(" + ");
    } catch {
      shape = "";
    }
    lines.push(`Nearest that fits: ${formatStsh(lower)} STSH${shape !== "" ? ` (${shape})` : ""}.`);
  }
  return lines;
}

/** One-line form of `shieldAmountErrorLines` (status bar); other messages unchanged. */
export function describeShieldAmountError(message: string): string {
  return shieldAmountErrorLines(message)?.join(" ") ?? message;
}
