/**
 * AC-2 gate test — OISY approve payload/interaction contract
 * (connect -> approve payload shape with a REAL Principal spender -> disconnect).
 *
 * With @dfinity/oisy-wallet-signer 0.4 + @dfinity/ledger-icrc@3 actually
 * installed, `ApproveParams.spender` is a ledger `Account` whose `owner` is a
 * typed `Principal` — the old string passthrough no longer typechecks. This
 * test pins the wire shape and the fail-fast principal validation (a bad
 * principal must fail BEFORE the signer popup opens).
 */

import { describe, expect, it, vi } from "vitest";
import { Principal } from "@dfinity/principal";

const signer = vi.hoisted(() => ({
  connectCalls: [] as Array<Record<string, unknown>>,
  approveCalls: [] as Array<Record<string, unknown>>,
  disconnects: { count: 0 },
  approveShouldThrow: { value: false },
}));

vi.mock("@dfinity/oisy-wallet-signer/icrc-wallet", () => ({
  IcrcWallet: {
    connect: async (opts: Record<string, unknown>) => {
      signer.connectCalls.push(opts);
      return {
        approve: async (args: Record<string, unknown>) => {
          signer.approveCalls.push(args);
          if (signer.approveShouldThrow.value) throw new Error("user rejected consent");
          return 42n;
        },
        disconnect: async () => {
          signer.disconnects.count += 1;
        },
      };
    },
  },
}));

import { approveForShield } from "../src/wallet/oisy";

const OWNER = "ohspu-zqaaa-aaaad-qmasq-cai";
const LEDGER = "aaaaa-aa";
const POOL = "pyeop-7yaaa-aaaam-ajfja-cai";
/** A fixed dedup timestamp, so the derived expiry is deterministic. */
const CREATED_AT = 1_700_000_000_000_000_000n;

function request(overrides: Partial<Parameters<typeof approveForShield>[0]> = {}) {
  return {
    walletUrl: "https://oisy.com/sign",
    host: "https://icp-api.io",
    owner: OWNER,
    ledgerCanisterId: LEDGER,
    spender: POOL,
    amount: 123_000_000n,
    expectedAllowance: 7n,
    createdAtTime: CREATED_AT,
    ...overrides,
  };
}

describe("oisy.approveForShield (0.4 payload contract)", () => {
  it("connect -> approve with a typed Principal spender -> disconnect", async () => {
    const before = signer.approveCalls.length;
    const block = await approveForShield(request());
    expect(block).toBe(42n);

    const connectOpts = signer.connectCalls.at(-1);
    expect(connectOpts?.url).toBe("https://oisy.com/sign");
    expect(connectOpts?.host).toBe("https://icp-api.io");

    expect(signer.approveCalls.length).toBe(before + 1);
    const call = signer.approveCalls.at(-1) as {
      owner: unknown;
      ledgerCanisterId: unknown;
      params: {
        spender: { owner: unknown; subaccount: unknown };
        amount: unknown;
        expected_allowance: unknown;
        expires_at: unknown;
      };
    };
    // Top-level owner + ledger id stay PrincipalText (verified 0.4 IcrcAccount).
    expect(call.owner).toBe(OWNER);
    expect(call.ledgerCanisterId).toBe(LEDGER);
    // The ledger-icrc Account spender carries a REAL Principal.
    expect(call.params.spender.owner).toBeInstanceOf(Principal);
    expect((call.params.spender.owner as Principal).toText()).toBe(POOL);
    expect(call.params.spender.subaccount).toEqual([]);
    expect(call.params.amount).toBe(123_000_000n);

    // WT-1 — the two fields this path was MISSING. `actors/token.ts` has always
    // sent a CAS guard; this path sent none, so the safety property depended on
    // which of the two approve routes the user happened to take. The expiry is
    // the bound the in-app path also now carries.
    //
    // Both expectations are LITERALS written here, not `APPROVAL_TTL_NS`
    // imported from the code under test: importing the constant would assert
    // only that it equals itself, and the 15-minute bound is exactly the kind of
    // value that could be widened to hours without any arm noticing.
    expect(call.params.expected_allowance).toBe(7n);
    expect(call.params.expires_at).toBe(CREATED_AT + 900_000_000_000n);

    expect(signer.disconnects.count).toBeGreaterThan(0);
  });

  it("disconnects even when the approval fails mid-consent", async () => {
    signer.approveShouldThrow.value = true;
    const disconnectsBefore = signer.disconnects.count;
    await expect(approveForShield(request())).rejects.toThrow(/user rejected consent/);
    expect(signer.disconnects.count).toBe(disconnectsBefore + 1);
    signer.approveShouldThrow.value = false;
  });

  it("fails fast on a malformed principal BEFORE the signer popup opens", async () => {
    for (const bad of [
      request({ spender: "not-a-principal" }),
      request({ owner: "also-bad" }),
      request({ ledgerCanisterId: "nope" }),
    ]) {
      const connectsBefore = signer.connectCalls.length;
      await expect(approveForShield(bad)).rejects.toThrow();
      expect(signer.connectCalls.length).toBe(connectsBefore); // popup never opened
    }
  });
});
