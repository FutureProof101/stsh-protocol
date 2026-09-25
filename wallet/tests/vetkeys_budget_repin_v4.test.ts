/**
 * Brief V4 §9.3 — the wallet half of the launch on-ramp re-pin.
 *
 * The fleet-capacity refusal is a WAITLIST, not a fault: the user did nothing
 * wrong, has nothing to fix, and is in a queue that moves on its own. These
 * arms cover the whole path — the typed wait, the copy, the level mapping
 * through the REAL render path, and the countdown on an injected clock.
 */

import { describe, expect, it } from "vitest";

import { describeVetkeysError, retryAfterSeconds } from "../src/crypto/vetkeys";
import { quotaRefusalNotice } from "../src/ui/quotaCopy";
import type { VetkeysError } from "../../src/declarations/vetkeys/vetkeys.did";

const capacity = (ns: bigint): VetkeysError =>
  ({ GlobalDerivationBudgetExceeded: { retry_after_ns: ns } }) as VetkeysError;
const ownQuota = (ns: bigint): VetkeysError =>
  ({ DerivationQuotaExceeded: { retry_after_ns: ns } }) as VetkeysError;

describe("§9.3(11) — retryAfterSeconds handles the fleet variant", () => {
  it("rounds UP with the shared idiom, at both edges", () => {
    // Expected values written out, not derived from the implementation.
    expect(retryAfterSeconds(capacity(1_000_000_000n))).toBe(1);
    // One nanosecond over a second still shows the NEXT whole second — the
    // same boundary the other two rate limits use, so a wait never reads as
    // shorter than it is.
    expect(retryAfterSeconds(capacity(1_000_000_001n))).toBe(2);
    expect(retryAfterSeconds(capacity(3_600_000_000_000n))).toBe(3_600);
  });

  it("agrees with the other rate limits at the same nanosecond value", () => {
    for (const ns of [1n, 999_999_999n, 1_000_000_000n, 1_000_000_001n, 59_999_999_999n]) {
      expect(retryAfterSeconds(capacity(ns))).toBe(retryAfterSeconds(ownQuota(ns)));
    }
  });
});

describe("§9.3(12) — the capacity notice is non-null, info, and its own text", () => {
  it("returns an INFO notice, not an error", () => {
    const notice = quotaRefusalNotice(capacity(1_800_000_000_000n));
    expect(notice).not.toBeNull();
    // The user is queued, not at fault. This is the level the render arm maps.
    expect(notice?.level).toBe("info");
  });

  it("differs from the user's OWN allowance message", () => {
    const fleet = quotaRefusalNotice(capacity(1_800_000_000_000n));
    const own = quotaRefusalNotice(ownQuota(1_800_000_000_000n));
    expect(fleet?.message).not.toBe(own?.message);
    // And they carry different levels: one is about the fleet, one about you.
    expect(own?.level).toBe("error");
  });

  it("carries the countdown in the text", () => {
    expect(quotaRefusalNotice(capacity(1_800_000_000_000n))?.message).toMatch(/30 minutes/);
  });
});

describe("§9.3(15) — the copy claims no daily bucket (RULED: hourly)", () => {
  /**
   * Asserted against MEANING, not a fixed string: the wording may change, the
   * semantics may not. Owner ruled "use the hourly copy — no 'today'"
   * (eb847fd1…), and 480/day may never appear as a quota in a refusal.
   */
  it("says nothing about days, today, or a daily allowance", () => {
    for (const ns of [1_000_000_000n, 1_800_000_000_000n, 3_600_000_000_000n]) {
      const message = quotaRefusalNotice(capacity(ns))?.message ?? "";
      expect(message).not.toMatch(/today/i);
      expect(message).not.toMatch(/\bper day\b|\bdaily\b/i);
      expect(message).not.toMatch(/\b480\b/);
    }
  });

  it("no in-wallet refusal text uses daily-bucket language", () => {
    // The ruling is about EVERY refusal, not only the fleet one.
    for (const err of [capacity(60_000_000_000n), ownQuota(60_000_000_000n)]) {
      expect(quotaRefusalNotice(err)?.message ?? "").not.toMatch(/today/i);
    }
  });

  it("frames it as capacity/a spot, not as the user's fault", () => {
    const message = quotaRefusalNotice(capacity(60_000_000_000n))?.message ?? "";
    expect(message).toMatch(/capacity/i);
    expect(message).toMatch(/spot/i);
    // Never accuses the user of exceeding anything.
    expect(message).not.toMatch(/you have used|your limit/i);
  });
});

describe("§9.3(13) — describeVetkeysError covers BOTH new variants", () => {
  const GENERIC = "the key service refused the request";

  it("gives the fleet refusal its own specific string", () => {
    const text = describeVetkeysError(capacity(60_000_000_000n));
    expect(text).not.toBe(GENERIC);
    expect(text).toMatch(/capacity/i);
  });

  it("gives CycleFloorReached its own string, with NO cycle figures", () => {
    // The variant genuinely CARRIES the two balances, which is exactly why the
    // no-leak assertion below matters: the numbers are right there to be
    // rendered by accident.
    const text = describeVetkeysError({
      CycleFloorReached: {
        liquid_cycles: 499_000_000_000n,
        required_cycles: 526_000_000_000n,
      },
    } as VetkeysError);
    expect(text).not.toBe(GENERIC);
    // A balance number tells an attacker how close a drain is, and tells a user
    // nothing they can act on.
    expect(text).not.toMatch(/\d{4,}/);
    expect(text).not.toMatch(/cycle/i);
    // It must still say the useful thing: existing devices keep working.
    expect(text).toMatch(/existing devices keep working/i);
  });
});
