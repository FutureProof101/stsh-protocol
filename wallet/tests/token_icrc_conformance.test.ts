// =============================================================================
// STSH — ICRC-1/2 JS client conformance (BRIEF_ICRC_COMPATIBILITY_AUDIT §7.1)
// Lane 4 deliverable — @dfinity/agent BigInt/shape checks (JS-01 .. JS-09).
// =============================================================================
//
// EXECUTION IS DEFERRED-LIVE: dfx 0.32 is GLIBC-broken on the WSL validation
// box, so there is no local replica to point an HttpAgent at. This suite is
// therefore gated on env vars and auto-skips when they are absent, keeping
// `vitest run` green locally. Run it at the mainnet smoke test (or any live
// replica) with:
//
//   STSH_TOKEN_CANISTER_ID=<principal> IC_HOST=https://ic0.app npx vitest run \
//       tests/token_icrc_conformance.test.ts
//
// FINDING-001 is FIXED (ICRC remediation lane): icrc1_supported_standards now
// returns the spec-shaped vec record { name:text; url:text }, so the standard
// idlFactory decode below asserts SUCCESS (regression guard).
// =============================================================================

import { describe, expect, test } from "vitest";
import { Actor, HttpAgent } from "@dfinity/agent";
import { IDL } from "@dfinity/candid";
import { Principal } from "@dfinity/principal";

const TOKEN_ID = process.env.STSH_TOKEN_CANISTER_ID ?? "";
const HOST = process.env.IC_HOST ?? "";
const LIVE = TOKEN_ID !== "" && HOST !== "";

// ── SPEC-shaped ICRC-1/2 idlFactory (what standard tooling generates) ─────────
const Account = IDL.Record({
  owner: IDL.Principal,
  subaccount: IDL.Opt(IDL.Vec(IDL.Nat8)),
});
const TransferArgs = IDL.Record({
  from_subaccount: IDL.Opt(IDL.Vec(IDL.Nat8)),
  to: Account,
  amount: IDL.Nat,
  fee: IDL.Opt(IDL.Nat),
  memo: IDL.Opt(IDL.Vec(IDL.Nat8)),
  created_at_time: IDL.Opt(IDL.Nat64),
});
const TransferError = IDL.Variant({
  BadFee: IDL.Record({ expected_fee: IDL.Nat }),
  BadBurn: IDL.Record({ min_burn_amount: IDL.Nat }),
  InsufficientFunds: IDL.Record({ balance: IDL.Nat }),
  TooOld: IDL.Null,
  CreatedInFuture: IDL.Record({ ledger_time: IDL.Nat64 }),
  Duplicate: IDL.Record({ duplicate_of: IDL.Nat }),
  TemporarilyUnavailable: IDL.Null,
  GenericError: IDL.Record({ error_code: IDL.Nat, message: IDL.Text }),
});
const Value = IDL.Variant({
  Nat: IDL.Nat,
  Int: IDL.Int,
  Text: IDL.Text,
  Blob: IDL.Vec(IDL.Nat8),
});
const ApproveArgs = IDL.Record({
  from_subaccount: IDL.Opt(IDL.Vec(IDL.Nat8)),
  spender: Account,
  amount: IDL.Nat,
  expected_allowance: IDL.Opt(IDL.Nat),
  expires_at: IDL.Opt(IDL.Nat64),
  fee: IDL.Opt(IDL.Nat),
  memo: IDL.Opt(IDL.Vec(IDL.Nat8)),
  created_at_time: IDL.Opt(IDL.Nat64),
});
const ApproveError = IDL.Variant({
  BadFee: IDL.Record({ expected_fee: IDL.Nat }),
  InsufficientFunds: IDL.Record({ balance: IDL.Nat }),
  AllowanceChanged: IDL.Record({ current_allowance: IDL.Nat }),
  Expired: IDL.Record({ ledger_time: IDL.Nat64 }),
  TooOld: IDL.Null,
  CreatedInFuture: IDL.Record({ ledger_time: IDL.Nat64 }),
  Duplicate: IDL.Record({ duplicate_of: IDL.Nat }),
  TemporarilyUnavailable: IDL.Null,
  GenericError: IDL.Record({ error_code: IDL.Nat, message: IDL.Text }),
});
const AllowanceArgs = IDL.Record({ account: Account, spender: Account });

// SPEC shape — STSH serves exactly this since the F-001 fix:
const StandardRecordSpec = IDL.Record({ name: IDL.Text, url: IDL.Text });

const idlFactorySpec = ({ IDL: _ }: { IDL: typeof IDL }) =>
  IDL.Service({
    icrc1_name: IDL.Func([], [IDL.Text], ["query"]),
    icrc1_symbol: IDL.Func([], [IDL.Text], ["query"]),
    icrc1_decimals: IDL.Func([], [IDL.Nat8], ["query"]),
    icrc1_fee: IDL.Func([], [IDL.Nat], ["query"]),
    icrc1_total_supply: IDL.Func([], [IDL.Nat], ["query"]),
    icrc1_minting_account: IDL.Func([], [IDL.Opt(Account)], ["query"]),
    icrc1_metadata: IDL.Func([], [IDL.Vec(IDL.Tuple(IDL.Text, Value))], ["query"]),
    icrc1_balance_of: IDL.Func([Account], [IDL.Nat], ["query"]),
    icrc1_supported_standards: IDL.Func([], [IDL.Vec(StandardRecordSpec)], ["query"]),
    icrc1_transfer: IDL.Func(
      [TransferArgs],
      [IDL.Variant({ Ok: IDL.Nat, Err: TransferError })],
      [],
    ),
    icrc2_approve: IDL.Func(
      [ApproveArgs],
      [IDL.Variant({ Ok: IDL.Nat, Err: ApproveError })],
      [],
    ),
    icrc2_allowance: IDL.Func(
      [AllowanceArgs],
      [IDL.Record({ allowance: IDL.Nat, expires_at: IDL.Opt(IDL.Nat64) })],
      ["query"],
    ),
  });

async function actor(factory: (a: { IDL: typeof IDL }) => IDL.ServiceClass) {
  const agent = await HttpAgent.create({ host: HOST, shouldFetchRootKey: !HOST.includes("ic0.app") });
  return Actor.createActor(factory, { agent, canisterId: TOKEN_ID });
}

describe.skipIf(!LIVE)("ICRC-1/2 JS client conformance (live)", () => {
  test("JS-01: icrc1_name returns string", async () => {
    const t = await actor(idlFactorySpec);
    expect(typeof (await t.icrc1_name())).toBe("string");
  });

  test("JS-02: icrc1_fee returns BigInt", async () => {
    const t = await actor(idlFactorySpec);
    expect(typeof (await t.icrc1_fee())).toBe("bigint");
  });

  test("JS-03/JS-04: balance_of default vs zero subaccount", async () => {
    const t = await actor(idlFactorySpec);
    const owner = Principal.anonymous();
    const b1 = await t.icrc1_balance_of({ owner, subaccount: [] });
    const b2 = await t.icrc1_balance_of({ owner, subaccount: [new Uint8Array(32)] });
    expect(typeof b1).toBe("bigint");
    expect(b1).toBe(b2);
  });

  test("JS-09: total supply round-trips as BigInt > MAX_SAFE_INTEGER", async () => {
    const t = await actor(idlFactorySpec);
    const s = (await t.icrc1_total_supply()) as bigint;
    expect(typeof s).toBe("bigint");
    // 1e17 base units > Number.MAX_SAFE_INTEGER (9_007_199_254_740_991)
    expect(s > BigInt(Number.MAX_SAFE_INTEGER)).toBe(true);
  });

  test("M-07: metadata keys + Value variants (decimals must be Nat)", async () => {
    const t = await actor(idlFactorySpec);
    const md = (await t.icrc1_metadata()) as Array<[string, Record<string, unknown>]>;
    const map = Object.fromEntries(md);
    expect(map["icrc1:symbol"]).toHaveProperty("Text");
    expect(map["icrc1:name"]).toHaveProperty("Text");
    expect(map["icrc1:decimals"]).toHaveProperty("Nat"); // NOT Int
    expect(map["icrc1:fee"]).toHaveProperty("Nat");
  });

  test("FINDING-001 fixed: spec-shaped supported_standards decodes against STSH", async () => {
    const t = await actor(idlFactorySpec);
    // Standard tooling (@dfinity/ledger-icrc et al.) uses the named-record
    // shape — this must now decode cleanly (regression guard for F-001).
    const std = (await t.icrc1_supported_standards()) as Array<{ name: string; url: string }>;
    const names = std.map((s) => s.name);
    expect(names).toContain("ICRC-1");
    expect(names).toContain("ICRC-2");
    expect(names).toContain("ICRC-10");
    expect(names).toContain("ICRC-21");
  });

  test("JS-08: BadFee error shape via spec idlFactory", async () => {
    const t = await actor(idlFactorySpec);
    const fee = (await t.icrc1_fee()) as bigint;
    const res = (await t.icrc1_transfer({
      to: { owner: Principal.anonymous(), subaccount: [] },
      amount: 1n,
      fee: [fee + 1n],
      memo: [],
      created_at_time: [],
      from_subaccount: [],
    })) as { Err?: { BadFee?: { expected_fee: bigint } } };
    expect(res.Err?.BadFee?.expected_fee).toBe(fee);
  });
});

describe("ICRC idlFactory static self-check (always runs)", () => {
  test("spec idlFactory constructs without error", () => {
    expect(() => idlFactorySpec({ IDL })).not.toThrow();
  });
});
