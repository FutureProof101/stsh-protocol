// @vitest-environment node
//
// NODE, not jsdom: arm 41 reads the canister's pins source from disk, and the
// jsdom environment rewrites `import.meta.url` into a scheme `fileURLToPath`
// refuses. Every arm in this file is pure, so it needs no DOM. Arm 43, which
// drives the real app shell, lives in its own jsdom file.
/**
 * A1 fix brief V5 §6.6 — the wallet half of held-balance-age admission.
 *
 * A first-ever derive is now refused until the required balance has been held
 * for T. From the user's side that is a WAIT, not a fault: they are already
 * funded and there is nothing for them to fix. These arms cover the typed wait,
 * the ruled copy, the level mapping through the REAL render path, the copy's
 * binding to the canister's own pin, and — the load-bearing one — the retry
 * discipline through the real fetch path.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  describeVetkeysError,
  retryAfterSeconds,
  WALLET_ELIGIBILITY_MIN_BALANCE_E8S,
} from "../src/crypto/vetkeys";
import { humanizeWait, quotaRefusalNotice } from "../src/ui/quotaCopy";
import type { VetkeysError } from "../../src/declarations/vetkeys/vetkeys.did";

const age = (ns: bigint): VetkeysError =>
  ({ EligibilityAgeNotMet: { retry_after_ns: ns } }) as VetkeysError;
const capacity = (ns: bigint): VetkeysError =>
  ({ GlobalDerivationBudgetExceeded: { retry_after_ns: ns } }) as VetkeysError;
const ownQuota = (ns: bigint): VetkeysError =>
  ({ DerivationQuotaExceeded: { retry_after_ns: ns } }) as VetkeysError;

// ── Arm 38 — the shared ceiling-rounding idiom ───────────────────────────────

describe("§6.6 arm 38 — retryAfterSeconds handles EligibilityAgeNotMet", () => {
  it("rounds UP, with expectations written out rather than derived", () => {
    expect(retryAfterSeconds(age(1_000_000_000n))).toBe(1);
    // One nanosecond over a second still shows the NEXT whole second.
    expect(retryAfterSeconds(age(1_000_000_001n))).toBe(2);
    expect(retryAfterSeconds(age(900_000_000_000n))).toBe(900);
  });

  it("agrees with the other rate limits at the same nanosecond value", () => {
    for (const ns of [1n, 999_999_999n, 1_000_000_000n, 1_000_000_001n, 899_999_999_999n]) {
      expect(retryAfterSeconds(age(ns))).toBe(retryAfterSeconds(capacity(ns)));
      expect(retryAfterSeconds(age(ns))).toBe(retryAfterSeconds(ownQuota(ns)));
    }
  });
});

// ── Arms 39 and 40 — the copy, and its variant binding ───────────────────────

describe("§6.6 arms 39/40 — the preparation copy is its own, and INFO", () => {
  it("is an INFO notice — the user did nothing wrong", () => {
    const notice = quotaRefusalNotice(age(900_000_000_000n));
    expect(notice).not.toBeNull();
    expect(notice?.level).toBe("info");
  });

  it("states the ruled preparation message (C-4 Option 1 — the returned wait, no fixed anchor)", () => {
    expect(quotaRefusalNotice(age(120_000_000_000n))?.message).toBe(
      "Your wallet is being prepared — first use unlocks in 2 minutes.",
    );
    // Ground truth, not a promise: a SHORTER returned wait reads shorter, and a
    // saturation-stretched one reads longer. No sign-in anchor, no fixed ceiling.
    expect(quotaRefusalNotice(age(45_000_000_000n))?.message).toBe(
      "Your wallet is being prepared — first use unlocks in 45 seconds.",
    );
    expect(quotaRefusalNotice(age(900_000_000_000n))?.message).toBe(
      "Your wallet is being prepared — first use unlocks in 15 minutes.",
    );
  });

  /**
   * THE TWO COPIES ARE DISTINCT AND EACH IS REACHABLE ONLY FROM ITS OWN VARIANT.
   *
   * The launch-capacity waitlist copy stays exclusive to
   * `GlobalDerivationBudgetExceeded`. If the two ever converged, an operator
   * reading a support ticket could not tell which control the user hit — a
   * fleet wall and a personal first-time wait have different remedies.
   */
  it("differs from the launch-capacity copy, and neither leaks into the other", () => {
    const prep = quotaRefusalNotice(age(900_000_000_000n))?.message ?? "";
    const fleet = quotaRefusalNotice(capacity(900_000_000_000n))?.message ?? "";
    expect(prep).not.toBe(fleet);
    expect(prep).not.toContain("Launch capacity");
    expect(fleet).not.toContain("being prepared");
    // And the user's OWN allowance message is a third, distinct string.
    const own = quotaRefusalNotice(ownQuota(900_000_000_000n))?.message ?? "";
    expect(new Set([prep, fleet, own]).size).toBe(3);
  });

  it("arm 40 — describeVetkeysError returns a SPECIFIC string, not the fallback", () => {
    const described = describeVetkeysError(age(900_000_000_000n));
    expect(described).not.toBe("the key service refused the request");
    expect(described).toContain("prepared");
    // And it is not the "not eligible" text: the user IS funded.
    expect(described).not.toContain("balance");
  });
});

// ── Arm 41 — the copy's duration is BOUND to the canister's pin ──────────────

describe("§6.6 arm 41 — the stated wait covers ELIGIBILITY_MIN_AGE_NS", () => {
  /**
   * A DRIFT LOCK, and it is UNCONDITIONAL (D-2). The canister pin is read from
   * its SOURCE at test time — `canisters/vetkeys` is workspace-excluded and the
   * wallet cannot import from it, and a hand-copied number here would be
   * exactly the drift this arm exists to catch.
   *
   * C-4 Option 1 (VETKEYS-AGE-2MIN): the copy states the wait the canister
   * RETURNED, humanized. For a full-T refusal (a first sighting) the stated
   * wait must equal `humanizeWait` of the pin, re-derived here independently
   * from the SOURCE literal, and must never read SHORTER than the pin — a
   * short one sends the user back early, to a refusal.
   */
  const pinLiteral = (name: string): bigint => {
    const src = readFileSync(
      fileURLToPath(new URL("../../canisters/vetkeys/src/pins.rs", import.meta.url)),
      "utf8",
    );
    const line = src.split("\n").find((l) => l.trimStart().startsWith(`pub const ${name}`));
    if (line === undefined) {
      throw new Error(
        `canisters/vetkeys/src/pins.rs no longer declares ${name} — this drift ` +
          "lock cannot verify the wallet side and must be REPAIRED, not deleted",
      );
    }
    const literal = line.split("=").at(-1)?.trim().replace(/;$/, "").replace(/_/g, "");
    if (literal === undefined || !/^\d+$/.test(literal)) {
      throw new Error(`${name} is no longer a plain integer literal: ${line}`);
    }
    return BigInt(literal);
  };
  const pinNs = (): bigint => pinLiteral("ELIGIBILITY_MIN_AGE_NS");

  it("a full-T refusal states exactly humanizeWait(pin), never shorter than the pin", () => {
    const message = quotaRefusalNotice(age(pinNs()))?.message ?? "";
    const stated = message.match(/unlocks in (.+)\./);
    expect(stated, `the copy must state the returned wait: ${message}`).not.toBeNull();
    const pinSeconds = Number((pinNs() + 999_999_999n) / 1_000_000_000n);
    expect(stated![1]).toBe(humanizeWait(pinSeconds));
    // The relation, explicitly: parse the humanized minutes back and compare.
    const minutes = stated![1].match(/^(\d+) minutes?$/);
    expect(minutes, `a 2-minute pin humanizes to minutes: ${stated![1]}`).not.toBeNull();
    expect(BigInt(minutes![1]) * 60n * 1_000_000_000n).toBeGreaterThanOrEqual(pinNs());
  });

  it("the drift lock actually reads the pin — non-vacuity", () => {
    // 2 minutes (559b411e…), written out here as its own arithmetic. If this
    // ever fails, the pin moved and the copy must be re-ruled, not re-derived.
    expect(pinNs()).toBe(2n * 60n * 1_000_000_000n);
  });

  it("VETKEYS-AGE-2MIN — WALLET_ELIGIBILITY_MIN_BALANCE_E8S mirrors the canister's §D floor", () => {
    // The login-time priming gate reads this constant; if the canister floor
    // moved alone the wallet would prime below it (wasted meter charge) or
    // skip priming for users the canister would sight.
    expect(WALLET_ELIGIBILITY_MIN_BALANCE_E8S).toBe(pinLiteral("ELIGIBILITY_MIN_BALANCE_E8S"));
    // Non-vacuity: 0.1 STSH, as its own arithmetic.
    expect(pinLiteral("ELIGIBILITY_MIN_BALANCE_E8S")).toBe(10_000_000n);
  });
});
