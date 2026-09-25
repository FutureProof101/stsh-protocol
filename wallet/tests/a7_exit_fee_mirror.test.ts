/**
 * A-7 (T6): the wallet's exit-fee mirror against the CANISTER's own answers.
 *
 * Two implementations that happen to agree are not evidence. Every row below is
 * a number the pool itself produced, obtained by call in
 * `integration-tests/tests/a7_exit_fee_symmetry_tests.rs` (`t6a`): the canister
 * is handed a deliberately wrong fee and states the one it wanted in
 * `PrivateSpendFeeMismatch.expected`. That Rust test asserts the same fixture,
 * so the two surfaces are pinned to ONE table and a divergence REDs on both
 * sides rather than quietly cancelling out.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

import { privateSpendFee, unshieldProtocolFee } from "../src/crypto/fees";
import { MAX_SPEND_OUTPUT_VALUE } from "../src/crypto/notes";
import type { ShieldFeeParams } from "../src/actors/pool";

interface FeeTable {
  unshield_fee_bps: number;
  flat_minimum_e8s: string;
  crossover_e8s: string;
  rows: Array<{ public_amount_e8s: string; fee_e8s: string }>;
}

const here = dirname(fileURLToPath(import.meta.url));
const table = JSON.parse(
  readFileSync(join(here, "fixtures/a7_exit_fee_table.json"), "utf8"),
) as FeeTable;

const params: ShieldFeeParams = {
  shieldFeeBps: table.unshield_fee_bps,
  shieldFlatMinimumFeeE8s: BigInt(table.flat_minimum_e8s),
  minimumPrivateCredit: 0n,
  feeModelVersion: 1,
  paramsEpoch: 0n,
  protocolPrivateSpendFeeStsh: 250_000_000n, // 2.5 STSH (A6.6, OWNER_RULING_FEE_FLOOR_2_5_STSH)
  unshieldFeeBps: table.unshield_fee_bps,
  unshieldFlatMinimumFeeE8s: BigInt(table.flat_minimum_e8s),
};

describe("A-7 T6 — the wallet mirror equals the canister's own answers", () => {
  it("has a table to check against (an empty fixture must not pass vacuously)", () => {
    expect(table.rows.length).toBeGreaterThanOrEqual(6);
    expect(table.unshield_fee_bps).toBe(25);
    expect(BigInt(table.flat_minimum_e8s)).toBe(250_000_000n); // 2.5 STSH (A6.6)
  });

  it.each(table.rows)(
    "public_amount %s e8s -> the canister said %s e8s",
    ({ public_amount_e8s, fee_e8s }) => {
      const amount = BigInt(public_amount_e8s);
      expect(unshieldProtocolFee(amount, params)).toBe(BigInt(fee_e8s));
      // ...and through the branch the spend flow actually calls.
      expect(privateSpendFee(amount, params)).toBe(BigInt(fee_e8s));
    },
  );

  it("both arms of max() are represented, so neither can be silently unexercised", () => {
    const flat = BigInt(table.flat_minimum_e8s);
    const fees = table.rows.map((r) => BigInt(r.fee_e8s));
    expect(fees.some((f) => f === flat), "no floor-arm row").toBe(true);
    expect(fees.some((f) => f > flat), "no bps-arm row").toBe(true);
  });

  it("the crossover behaves as measured on-chain, floor division included", () => {
    const crossover = BigInt(table.crossover_e8s);
    const flat = BigInt(table.flat_minimum_e8s);
    expect(unshieldProtocolFee(crossover, params)).toBe(flat);
    expect(unshieldProtocolFee(crossover - 1n, params)).toBe(flat);
    // One e8s above the crossover the floor STILL binds: the bps arm is integer
    // floor division, so 400 e8s of amount buys 1 e8s of fee.
    expect(unshieldProtocolFee(crossover + 1n, params)).toBe(flat);
    expect(unshieldProtocolFee(crossover + 400n, params)).toBe(flat + 1n);
  });

  it("without a payout the flat protocol spend fee is used, unchanged", () => {
    expect(privateSpendFee(undefined, params)).toBe(params.protocolPrivateSpendFeeStsh);
  });
});

/**
 * The wallet's SECOND copy of the circuit value bound — granted into this lane
 * as a test-only pin by `SUPERVISOR_RULING_A-7_eighth_site_V3` §3, found by the
 * Supervisor's independent sweep. `wallet/src/crypto/notes.ts` stays at ZERO
 * diff; only this assertion is added.
 *
 * The authority is the circuit source itself, parsed here exactly as
 * `shielded_pool::tests::circuit_max_value_matches_spend_circom` parses it in
 * Rust — so the wallet constant, the pool constant and `spend.circom` are three
 * copies pinned to ONE source rather than to each other.
 */
describe("A-7 — the wallet's copy of the circuit bound is pinned to spend.circom", () => {
  it("MAX_SPEND_OUTPUT_VALUE equals MAX_NOTE_VALUE in the circuit source", () => {
    const circom = readFileSync(join(here, "../../circuits/spend.circom"), "utf8");
    const matches = circom
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.startsWith("var MAX_NOTE_VALUE"));
    expect(matches.length, "spend.circom must declare MAX_NOTE_VALUE exactly once").toBe(1);
    const literal = matches[0].split("=")[1].trim().match(/^\d+/)?.[0];
    expect(literal, "MAX_NOTE_VALUE must be a plain literal").toBeDefined();
    expect(MAX_SPEND_OUTPUT_VALUE).toBe(BigInt(literal as string));
  });

  it("the largest exit in the canister table fits under that bound, fee included", () => {
    // The boundary row: public_amount + fee == the bound, exactly.
    const last = table.rows[table.rows.length - 1];
    const amount = BigInt(last.public_amount_e8s);
    const fee = BigInt(last.fee_e8s);
    expect(amount + fee).toBe(MAX_SPEND_OUTPUT_VALUE);
    // ...and one e8s more does not fit, so this really is the boundary.
    const over = amount + 1n;
    expect(over + unshieldProtocolFee(over, params)).toBeGreaterThan(MAX_SPEND_OUTPUT_VALUE);
  });
});
