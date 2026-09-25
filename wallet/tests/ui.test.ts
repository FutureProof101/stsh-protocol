/**
 * UI logic tests (wallet-build Commit 6).
 *
 * The pure, framework-free logic behind the pages: hash routing, STSH amount
 * formatting/parsing, balance summary, shield decomposition preview, the
 * privacy warnings (incl. the specific-amount fingerprint warning), the config
 * resolver, and the token actor adapter. The DOM rendering itself is structural.
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";

import { DEFAULT_ROUTE, parseRoute, routeHref } from "../src/ui/router";
import { formatStsh, parseStsh, planShield, summarizeBalance } from "../src/ui/format";
import { privacyWarnings } from "../src/ui/privacyWarnings";
import { resolveConfig, DEFAULT_POOL_CANISTER_ID } from "../src/session/config";
import { wrapTokenActor } from "../src/actors/token";
import { DENOMINATIONS } from "../src/crypto/notes";
import type { ScannedNote } from "../src/storage/noteCache";

const asService = <T>(mock: Record<string, unknown>): T => mock as unknown as T;
const note = (value: bigint, leafIndex = 0n): ScannedNote => ({
  leafIndex,
  value,
  rho: new Uint8Array(32),
  rseed: new Uint8Array(32),
  recipientPk: new Uint8Array(32),
});

describe("router.parseRoute (L3a)", () => {
  it("maps the account/staking/vesting/shield routes and falls back to the default", () => {
    expect(parseRoute("#/account")).toBe("account");
    expect(parseRoute("#/staking")).toBe("staking");
    expect(parseRoute("#/vesting")).toBe("vesting");
    expect(parseRoute("#/shield")).toBe("shield");
    expect(parseRoute("")).toBe(DEFAULT_ROUTE);
    expect(parseRoute("#/")).toBe(DEFAULT_ROUTE);
    expect(parseRoute("#/nonsense")).toBe(DEFAULT_ROUTE);
    expect(DEFAULT_ROUTE).toBe("account");
    expect(routeHref("staking")).toBe("#/staking");
  });

  it("resolves all shielded routes (L3b scan/balance, L3c spend); unknown segments fall back", () => {
    expect(parseRoute("#/scan")).toBe("scan");
    expect(parseRoute("#/balance")).toBe("balance");
    expect(parseRoute("#/spend")).toBe("spend");
    expect(parseRoute("#/nonsense")).toBe("account");
  });
});

describe("format.formatStsh / parseStsh", () => {
  it("formats base units, trimming fractional zeros and grouping thousands", () => {
    expect(formatStsh(100_000_000n)).toBe("1");
    expect(formatStsh(150_000_000n)).toBe("1.5");
    expect(formatStsh(0n)).toBe("0");
    expect(formatStsh(1_234_500_000_000n)).toBe("12,345");
    expect(formatStsh(100_000_001n)).toBe("1.00000001");
  });

  it("parses amounts and rejects malformed / over-precise input", () => {
    expect(parseStsh("1")).toBe(100_000_000n);
    expect(parseStsh("1.5")).toBe(150_000_000n);
    expect(parseStsh("12,345")).toBe(1_234_500_000_000n);
    expect(parseStsh(" 12,345 ")).toBe(1_234_500_000_000n);
    expect(() => parseStsh("1.234567890")).toThrow(/too many decimal/);
    expect(() => parseStsh("abc")).toThrow(/invalid/);
  });

  it("round-trips format <-> parse", () => {
    expect(formatStsh(parseStsh("12,345"))).toBe("12,345");
  });
});

describe("format.summarizeBalance", () => {
  it("buckets by denomination and totals", () => {
    const s = summarizeBalance([note(DENOMINATIONS[0]), note(DENOMINATIONS[0]), note(DENOMINATIONS[2])]);
    expect(s.noteCount).toBe(3);
    expect(s.total).toBe(DENOMINATIONS[0] * 2n + DENOMINATIONS[2]);
    expect(s.buckets.map((b) => [b.denom, b.count])).toEqual([
      [DENOMINATIONS[0], 2],
      [DENOMINATIONS[2], 1],
    ]);
  });
});

describe("format.planShield", () => {
  it("decomposes into fixed denominations (largest first), grouped", () => {
    const plan = planShield(parseStsh("123000")); // 100k + 10k + 10k + 1k + 1k + 1k
    expect(plan.notes).toEqual([
      DENOMINATIONS[2],
      DENOMINATIONS[1],
      DENOMINATIONS[1],
      DENOMINATIONS[0],
      DENOMINATIONS[0],
      DENOMINATIONS[0],
    ]);
    expect(plan.buckets.map((b) => [b.denom, b.count])).toEqual([
      [DENOMINATIONS[0], 3],
      [DENOMINATIONS[1], 2],
      [DENOMINATIONS[2], 1],
    ]);
    expect(plan.total).toBe(parseStsh("123000"));
  });

  it("throws for an amount not expressible in fixed denominations", () => {
    expect(() => planShield(parseStsh("1.5"))).toThrow(/not decomposable/);
  });
});

describe("privacyWarnings", () => {
  it("flags a specific-amount spend as a traceable fingerprint (high)", () => {
    const w = privacyWarnings({ amountKind: "specific-amount" });
    expect(w[0].level).toBe("high");
    expect(w[0].msg).toMatch(/fingerprint/i);
    expect(w[0].msg).toMatch(/anonymity set/i);
  });

  it("is empty for a fixed-denomination spend in an aged, private setup", () => {
    expect(
      privacyWarnings({
        amountKind: "fixed-denomination",
        msSinceDeposit: 5 * 24 * 60 * 60 * 1000,
        publicPayout: false,
      }),
    ).toEqual([]);
  });

  it("warns on a fresh deposit and public payout — and NEVER on an anonymity-set estimate (K3-007)", () => {
    const w = privacyWarnings({
      amountKind: "fixed-denomination",
      msSinceDeposit: 60_000,
      publicPayout: true,
    });
    expect(w.some((x) => /timing correlation/i.test(x.msg) && x.level === "high")).toBe(true);
    // AR2-P2-01 moved this row from `medium` to `high`, and the assertion moves
    // with it deliberately rather than being loosened: the warning no longer
    // says only that the recipient and amount are public — it says the account
    // that submits the spend is public and permanently recorded. That is a
    // different, larger claim about the user's own identity, so it is not a
    // `medium`. The severity is pinned here so a later silent downgrade fails.
    expect(w.some((x) => /public payout/i.test(x.msg) && x.level === "high")).toBe(true);
    // The old small-anonymity-set warning was removed: the own-note count is
    // inverted and the pool leaf_count is not an anonymity-set estimate.
    expect(w.some((x) => /anonymity set is small/i.test(x.msg))).toBe(false);
  });
});

describe("session.resolveConfig", () => {
  it("defaults the pool id and honours env overrides", () => {
    const def = resolveConfig({});
    expect(def.poolCanisterId).toBe(DEFAULT_POOL_CANISTER_ID);
    expect(def.fetchRootKey).toBe(false);
    expect(def.host).toMatch(/^https:\/\//);

    const local = resolveConfig({
      VITE_IC_HOST: "http://127.0.0.1:8080",
      VITE_FETCH_ROOT_KEY: "true",
      VITE_MERKLE_CANISTER_ID: "aaaaa-aa",
    });
    expect(local.fetchRootKey).toBe(true);
    expect(local.merkleCanisterId).toBe("aaaaa-aa");
  });
});

describe("actors.wrapTokenActor", () => {
  it("maps balanceOf to an ICRC Account and combines metadata", async () => {
    let captured: unknown;
    const token = wrapTokenActor(
      asService({
        icrc1_balance_of: async (acc: unknown) => {
          captured = acc;
          return 777n;
        },
        icrc1_symbol: async () => "STSH",
        icrc1_decimals: async () => 8,
        icrc1_fee: async () => 10n,
      }),
    );
    const owner = Principal.fromText(DEFAULT_POOL_CANISTER_ID);
    expect(await token.balanceOf(owner)).toBe(777n);
    expect(captured).toEqual({ owner, subaccount: [] });
    expect(await token.metadata()).toEqual({ symbol: "STSH", decimals: 8, fee: 10n });
  });
});
