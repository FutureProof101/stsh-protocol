/**
 * Campaign-A-only token amount formatting (brief A1.5, A-S16).
 *
 * Pure STSH <-> base-unit helpers with NO Campaign-B imports. ui/format.ts
 * imports crypto/notes + storage/noteCache (both Campaign B), so Wave-1
 * account/staking/vesting code imports THIS module instead; format.ts
 * re-exports these helpers for the Campaign-B pages so there is a single
 * implementation. tests/isolation.test.ts enforces the import-graph split.
 */

export const STSH_DECIMALS = 8;

/** Insert thousands separators into a non-negative integer string. */
function groupThousands(intStr: string): string {
  return intStr.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/**
 * Format base units as a human STSH string, e.g. 150_000_000n -> "1.5",
 * 1_234_500_000_000n -> "12,345". Trailing fractional zeros are trimmed.
 */
export function formatStsh(baseUnits: bigint, decimals: number = STSH_DECIMALS): string {
  if (baseUnits < 0n) return `-${formatStsh(-baseUnits, decimals)}`;
  const scale = 10n ** BigInt(decimals);
  const whole = baseUnits / scale;
  const frac = baseUnits % scale;
  const wholeStr = groupThousands(whole.toString(10));
  if (frac === 0n) return wholeStr;
  const fracStr = frac.toString(10).padStart(decimals, "0").replace(/0+$/, "");
  return `${wholeStr}.${fracStr}`;
}

/**
 * Parse a user-entered STSH amount ("12,345.5") into base units. Throws on a
 * malformed value or more than `decimals` fractional digits (which would
 * silently truncate the user's amount). The digits-only grammar rejects
 * signs, exponents ("1e18") and hex — adversarial inputs surface as errors,
 * never as a coerced amount.
 */
export function parseStsh(input: string, decimals: number = STSH_DECIMALS): bigint {
  const cleaned = input.trim().replace(/,/g, "");
  if (!/^\d+(\.\d+)?$/.test(cleaned)) {
    throw new Error(`invalid STSH amount: "${input}"`);
  }
  const [whole, frac = ""] = cleaned.split(".");
  if (frac.length > decimals) {
    throw new Error(`too many decimal places (max ${decimals}) in "${input}"`);
  }
  const scale = 10n ** BigInt(decimals);
  return BigInt(whole) * scale + BigInt(frac.padEnd(decimals, "0"));
}
