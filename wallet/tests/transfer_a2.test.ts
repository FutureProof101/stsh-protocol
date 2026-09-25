/**
 * Lane A2 gate tests — the idempotent transfer contract (C-A3, brief §3).
 *
 * Covers: dropped-response retry -> Duplicate (confirmed success, no second
 * debit, byte-for-byte envelope reuse) · logout-as-A / login-as-B envelope
 * non-recovery · two-tab collision -> one atomic slot · TooOld frozen (not
 * re-minted) with the manual-abandon (confirm + archive) workflow · malformed
 * principal / adversarial amount parsing · mutation refusal while anonymous ·
 * balance refresh only after a definite result.
 */

import { describe, expect, it } from "vitest";

import { unusedIcrc2 } from "./helpers/tokenStubs";
import { Principal } from "@dfinity/principal";
import { Ed25519KeyIdentity } from "@dfinity/identity";

import {
  wrapTokenMutationActor,
  type TokenCanister,
  type TokenMutationCanister,
  type TransferOutcome,
  type TransferRequest,
} from "../src/actors/token";
import type { AuthSession, DelegationIdentityLike } from "../src/session/auth";
import { PRODUCTION_ORIGIN } from "../src/session/config";
import {
  IntentSlotBusyError,
  TransferJournal,
  scopeKey,
  type TransferScope,
} from "../src/storage/transferJournal";
import { mountApp, type AppDeps } from "../src/ui/app";
import { memoryJournalStore, type MemoryJournalStore } from "./helpers/memoryJournalStore";

const asService = <T>(mock: Record<string, unknown>): T => mock as unknown as T;

const RECIPIENT = "ohspu-zqaaa-aaaad-qmasq-cai";

function principalOf(seed: number): Principal {
  return Ed25519KeyIdentity.generate(new Uint8Array(32).fill(seed)).getPrincipal();
}

function sessionFor(principal: Principal): AuthSession {
  return { identity: {} as DelegationIdentityLike, principal };
}

function scope(owner: string, ledger = "", network = "https://icp-api.io"): TransferScope {
  return { ownerPrincipal: owner, ledgerCanisterId: ledger, network };
}

// ---------------------------------------------------------------------------
// mutation actor adapter
// ---------------------------------------------------------------------------

describe("actors.wrapTokenMutationActor", () => {
  const req: TransferRequest = {
    to: { owner: Principal.fromText(RECIPIENT) },
    amount: 500n,
    fee: 10n,
    createdAtTime: 123_456_789n,
  };

  it("always sends created_at_time (never []) and maps Ok", async () => {
    const captured: Record<string, unknown>[] = [];
    const actor = wrapTokenMutationActor(
      asService({
        icrc1_transfer: async (args: Record<string, unknown>) => {
          captured.push(args);
          return { Ok: 7n };
        },
      }),
    );
    expect(await actor.transfer(req)).toEqual({ kind: "ok", blockIndex: 7n });
    expect(captured[0].created_at_time).toEqual([123_456_789n]);
    expect(captured[0].fee).toEqual([10n]);
    expect(captured[0].memo).toEqual([]);
    expect(captured[0].from_subaccount).toEqual([]);
  });

  it("maps Duplicate to a confirmed-success outcome", async () => {
    const actor = wrapTokenMutationActor(
      asService({ icrc1_transfer: async () => ({ Err: { Duplicate: { duplicate_of: 3n } } }) }),
    );
    expect(await actor.transfer(req)).toEqual({ kind: "duplicate", duplicateOf: 3n });
  });

  it("maps TooOld to its own outcome (journal decides freeze vs reject)", async () => {
    const actor = wrapTokenMutationActor(
      asService({ icrc1_transfer: async () => ({ Err: { TooOld: null } }) }),
    );
    expect(await actor.transfer(req)).toEqual({ kind: "too-old" });
  });

  it("maps other ledger errors to definite rejections", async () => {
    const actor = wrapTokenMutationActor(
      asService({
        icrc1_transfer: async () => ({ Err: { BadFee: { expected_fee: 10n } } }),
      }),
    );
    const outcome = await actor.transfer(req);
    expect(outcome.kind).toBe("rejected");
    if (outcome.kind === "rejected") expect(outcome.reason).toMatch(/BadFee/);
  });

  it("propagates transport failures (unknown outcome) as throws", async () => {
    const actor = wrapTokenMutationActor(
      asService({
        icrc1_transfer: async () => {
          throw new Error("connection reset");
        },
      }),
    );
    await expect(actor.transfer(req)).rejects.toThrow(/connection reset/);
  });
});

// ---------------------------------------------------------------------------
// transfer journal
// ---------------------------------------------------------------------------

describe("storage.TransferJournal", () => {
  const OWNER_A = principalOf(1).toText();
  const OWNER_B = principalOf(2).toText();

  function fields(overrides: Partial<Parameters<TransferJournal["beginIntent"]>[0]> = {}) {
    return {
      toOwner: RECIPIENT,
      toSubaccountHex: null,
      amount: 100n,
      fee: 10n,
      memoHex: null,
      fromSubaccountHex: null,
      createdAtTimeNs: 1_700_000_000_000_000_000n,
      ...overrides,
    };
  }

  it("persists a fully-bound envelope before any submit", async () => {
    const store = memoryJournalStore();
    const journal = new TransferJournal(store, scope(OWNER_A, "ledger-1"));
    const intent = await journal.beginIntent(fields());
    const stored = store.intents.get(scopeKey(scope(OWNER_A, "ledger-1")));
    expect(stored).toEqual(intent);
    expect(stored?.state).toBe("pending");
    expect(stored?.ownerPrincipal).toBe(OWNER_A);
    expect(stored?.ledgerCanisterId).toBe("ledger-1");
    expect(stored?.network).toBe("https://icp-api.io");
    expect(stored?.createdAtTimeNs).toBe("1700000000000000000");
    expect(stored?.attempts).toBe(0);
  });

  it("two concurrent claims (two tabs) resolve exactly one winner", async () => {
    const store = memoryJournalStore();
    const tab1 = new TransferJournal(store, scope(OWNER_A));
    const tab2 = new TransferJournal(store, scope(OWNER_A));
    const results = await Promise.allSettled([
      tab1.beginIntent(fields()),
      tab2.beginIntent(fields({ amount: 999n })),
    ]);
    const wins = results.filter((r) => r.status === "fulfilled");
    const losses = results.filter((r) => r.status === "rejected");
    expect(wins).toHaveLength(1);
    expect(losses).toHaveLength(1);
    const loss = losses[0] as PromiseRejectedResult;
    expect(loss.reason).toBeInstanceOf(IntentSlotBusyError);
    expect(store.intents.size).toBe(1);
  });

  it("never recovers an envelope across principal, ledger, or network (A-S14)", async () => {
    const store = memoryJournalStore();
    const journalA = new TransferJournal(store, scope(OWNER_A, "ledger-1", "https://icp-api.io"));
    await journalA.beginIntent(fields());

    expect(
      await new TransferJournal(store, scope(OWNER_B, "ledger-1", "https://icp-api.io")).loadUnresolved(),
    ).toBeNull();
    expect(
      await new TransferJournal(store, scope(OWNER_A, "ledger-2", "https://icp-api.io")).loadUnresolved(),
    ).toBeNull();
    expect(
      await new TransferJournal(store, scope(OWNER_A, "ledger-1", "http://127.0.0.1:8080")).loadUnresolved(),
    ).toBeNull();
    // The rightful scope still sees it.
    expect(await journalA.loadUnresolved()).not.toBeNull();
  });

  it("markUnknown persists the attempt count; resolve clears the slot", async () => {
    const store = memoryJournalStore();
    const journal = new TransferJournal(store, scope(OWNER_A));
    const intent = await journal.beginIntent(fields());
    const marked = await journal.markUnknown(intent);
    expect(marked.state).toBe("unknown");
    expect(marked.attempts).toBe(1);
    expect(store.intents.get(scopeKey(scope(OWNER_A)))?.attempts).toBe(1);
    await journal.resolve(marked);
    expect(store.intents.size).toBe(0);
  });

  it("abandon requires frozen state AND explicit confirmation, then archives", async () => {
    const store = memoryJournalStore();
    const journal = new TransferJournal(store, scope(OWNER_A));
    const intent = await journal.beginIntent(fields());
    const marked = await journal.markUnknown(intent);

    // Not frozen: cannot abandon at all.
    await expect(
      journal.abandonFrozen(marked, { confirmedExternalReconcile: true }),
    ).rejects.toThrow(/only a frozen/);

    const frozen = await journal.freeze(marked);
    expect(store.intents.get(scopeKey(scope(OWNER_A)))?.state).toBe("frozen");

    // No confirmation: refused, record kept, nothing archived.
    await expect(
      journal.abandonFrozen(frozen, { confirmedExternalReconcile: false }),
    ).rejects.toThrow(/explicit confirmation/);
    expect(store.intents.size).toBe(1);
    expect(store.archive).toHaveLength(0);

    // Confirmed after external reconcile: archived (not erased), slot freed.
    await journal.abandonFrozen(frozen, { confirmedExternalReconcile: true });
    expect(store.intents.size).toBe(0);
    expect(store.archive).toHaveLength(1);
    expect(store.archive[0].record.createdAtTimeNs).toBe(frozen.createdAtTimeNs);
    expect(store.archive[0].resolution).toBe("abandoned-after-external-reconcile");
  });
});

// ---------------------------------------------------------------------------
// app-level flows
// ---------------------------------------------------------------------------

/** A dedup-aware fake ledger: same envelope (created_at_time+args) never debits twice. */
function fakeLedger(script?: { outcomes?: Array<"transport-error" | "transport-error-executed" | "too-old"> }) {
  const executed = new Map<string, bigint>();
  const argsSeen: TransferRequest[] = [];
  let debits = 0;
  let nextBlock = 1n;
  const outcomes = [...(script?.outcomes ?? [])];

  const token: TokenMutationCanister = {
    ...unusedIcrc2,
    async transfer(req: TransferRequest): Promise<TransferOutcome> {
      argsSeen.push(req);
      const key = `${req.createdAtTime}|${req.to.owner.toText()}|${req.amount}|${req.fee}`;
      const scripted = outcomes.shift();
      if (scripted === "transport-error") {
        throw new Error("connection reset (nothing executed)");
      }
      if (scripted === "transport-error-executed") {
        // The ledger EXECUTED the transfer but the response was lost.
        if (!executed.has(key)) {
          executed.set(key, nextBlock++);
          debits += 1;
        }
        throw new Error("connection reset (response lost)");
      }
      if (scripted === "too-old") return { kind: "too-old" };
      const prior = executed.get(key);
      if (prior !== undefined) return { kind: "duplicate", duplicateOf: prior };
      executed.set(key, nextBlock++);
      debits += 1;
      return { kind: "ok", blockIndex: executed.get(key) as bigint };
    },
  };
  return { token, argsSeen, debits: () => debits };
}

interface FlowHarness {
  deps: AppDeps;
  store: MemoryJournalStore;
  setLoginSession(session: AuthSession): void;
}

function flowHarness(opts: {
  store?: MemoryJournalStore;
  restore?: AuthSession | null;
  mutationToken: TokenMutationCanister;
  balanceOf?: TokenCanister["balanceOf"];
  fee?: bigint;
}): FlowHarness {
  const store = opts.store ?? memoryJournalStore();
  let loginSession: AuthSession | null = null;
  const readToken: TokenCanister = {
    balanceOf: opts.balanceOf ?? (async () => 0n),
    metadata: async () => ({ symbol: "STSH", decimals: 8, fee: opts.fee ?? 10_000n }),
    fee: async () => opts.fee ?? 10_000n,
  };
  const emptyStaking = { getStakePositions: async () => [], getPendingRewards: async () => 0n };
  const emptyVesting = { getSchedule: async () => null, claimableAmount: async () => 0n };
  const deps: AppDeps = {
    origin: PRODUCTION_ORIGIN,
    // S1-02: the launch origin is runtime-loaded; this harness supplies the ruled
    // value so the policy sees the same origin it is evaluated against.
    loadLaunchOrigin: async () => PRODUCTION_ORIGIN,
    buildReadActors: async () => ({
      token: readToken,
      staking: emptyStaking,
      vesting: emptyVesting,
    }),
    buildMutationActors: async () => ({ token: opts.mutationToken }),
    createAuth: async () => ({
      restore: async () => opts.restore ?? null,
      login: async () => {
        if (loginSession === null) throw new Error("login not scripted");
        return loginSession;
      },
      logout: async () => undefined,
      verify: () => "valid",
    }),
    createJournalStore: async () => store,
  };
  return { deps, store, setLoginSession: (s) => (loginSession = s) };
}

function mountContainer(): HTMLElement {
  const node = document.createElement("div");
  document.body.append(node);
  return node;
}

describe("transfer flow (mountApp)", () => {
  const ownerA = principalOf(11);
  const ownerB = principalOf(12);

  it("executes a clean transfer, clears the slot, refreshes balance after the definite result", async () => {
    window.location.hash = "";
    const ledger = fakeLedger();
    let balance = 5_000_000_000n;
    const h = flowHarness({
      restore: sessionFor(ownerA),
      mutationToken: ledger.token,
      balanceOf: async () => balance,
    });
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    balance = 4_000_000_000n; // post-transfer ledger view
    await ctx.transfer({ toText: RECIPIENT, amountText: "10" });
    expect(ctx.state.status?.kind).toBe("success");
    expect(ledger.debits()).toBe(1);
    expect(ctx.pendingIntent).toBeNull();
    expect(h.store.intents.size).toBe(0);
    expect(ctx.state.balance).toBe(4_000_000_000n); // refreshed after definite result
  });

  it("dropped response -> byte-for-byte retry -> Duplicate, exactly one debit (C-A3)", async () => {
    window.location.hash = "";
    const ledger = fakeLedger({ outcomes: ["transport-error-executed"] });
    const container = mountContainer();
    const h = flowHarness({ restore: sessionFor(ownerA), mutationToken: ledger.token });
    const ctx = await mountApp(container, {}, h.deps);

    await ctx.transfer({ toText: RECIPIENT, amountText: "10" });
    // Outcome unknown: envelope persisted, slot occupied, ONE debit so far.
    expect(ctx.state.status?.msg).toMatch(/outcome unknown/i);
    expect(ctx.pendingIntent?.state).toBe("unknown");
    expect(ctx.pendingIntent?.attempts).toBe(1);
    expect(ledger.debits()).toBe(1);
    // The account page offers the byte-for-byte retry, not a new form.
    expect(container.querySelector('[data-testid="retry-intent"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="send"]')).toBeNull();

    await ctx.retryPendingIntent();
    expect(ctx.state.status?.kind).toBe("success");
    expect(ctx.state.status?.msg).toMatch(/no second debit/i);
    expect(ledger.debits()).toBe(1); // STILL exactly one debit
    expect(ctx.pendingIntent).toBeNull();
    expect(h.store.intents.size).toBe(0);

    // Byte-for-byte: identical envelope on the wire both times.
    expect(ledger.argsSeen).toHaveLength(2);
    const [first, second] = ledger.argsSeen;
    expect(second.createdAtTime).toBe(first.createdAtTime);
    expect(second.amount).toBe(first.amount);
    expect(second.fee).toBe(first.fee);
    expect(second.to.owner.toText()).toBe(first.to.owner.toText());
  });

  it("refuses mutations while anonymous", async () => {
    window.location.hash = "";
    const ledger = fakeLedger();
    const h = flowHarness({ restore: null, mutationToken: ledger.token });
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    await ctx.transfer({ toText: RECIPIENT, amountText: "1" });
    expect(ctx.state.status?.kind).toBe("error");
    expect(ctx.state.status?.msg).toMatch(/log in to transfer/i);
    expect(ledger.argsSeen).toHaveLength(0);
    expect(h.store.intents.size).toBe(0);
  });

  it("rejects a malformed principal and adversarial amounts without minting an intent", async () => {
    window.location.hash = "";
    const ledger = fakeLedger();
    const h = flowHarness({ restore: sessionFor(ownerA), mutationToken: ledger.token });
    const ctx = await mountApp(mountContainer(), {}, h.deps);

    for (const [toText, amountText] of [
      ["not-a-principal", "1"],
      [RECIPIENT, "1e18"],
      [RECIPIENT, "-5"],
      [RECIPIENT, "0"],
      [RECIPIENT, "0.000000001"], // > 8 decimals
      [RECIPIENT, "0x10"],
      [RECIPIENT, ""],
    ] as const) {
      await ctx.transfer({ toText, amountText });
      expect(ctx.state.status?.kind, `${toText} / ${amountText}`).toBe("error");
    }
    expect(ledger.argsSeen).toHaveLength(0);
    expect(h.store.intents.size).toBe(0);
  });

  it("TooOld on the FIRST direct attempt is a definite non-execution (slot cleared)", async () => {
    window.location.hash = "";
    const ledger = fakeLedger({ outcomes: ["too-old"] });
    const h = flowHarness({ restore: sessionFor(ownerA), mutationToken: ledger.token });
    const ctx = await mountApp(mountContainer(), {}, h.deps);
    await ctx.transfer({ toText: RECIPIENT, amountText: "10" });
    expect(ctx.state.status?.kind).toBe("error");
    expect(ctx.state.status?.msg).toMatch(/nothing was debited/i);
    expect(ctx.pendingIntent).toBeNull();
    expect(h.store.intents.size).toBe(0);
  });

  it("ambiguous TooOld freezes the intent (never re-mints) and abandon needs confirm + archive", async () => {
    window.location.hash = "";
    const ledger = fakeLedger({ outcomes: ["transport-error", "too-old"] });
    const container = mountContainer();
    const h = flowHarness({ restore: sessionFor(ownerA), mutationToken: ledger.token });
    const ctx = await mountApp(container, {}, h.deps);

    await ctx.transfer({ toText: RECIPIENT, amountText: "10" });
    expect(ctx.pendingIntent?.state).toBe("unknown");
    const mintedCreatedAt = ctx.pendingIntent?.createdAtTimeNs;

    await ctx.retryPendingIntent(); // ledger: TooOld after a prior unknown attempt
    expect(ctx.pendingIntent?.state).toBe("frozen");
    expect(ctx.pendingIntent?.createdAtTimeNs).toBe(mintedCreatedAt); // never re-minted
    expect(ctx.state.status?.msg).toMatch(/frozen/i);

    // A new transfer is refused while the frozen intent occupies the slot.
    await ctx.transfer({ toText: RECIPIENT, amountText: "5" });
    expect(ctx.state.status?.msg).toMatch(/unresolved transfer intent/i);
    expect(h.store.intents.size).toBe(1);
    expect(h.store.intents.values().next().value?.createdAtTimeNs).toBe(mintedCreatedAt);

    // The frozen panel is shown; retry is not offered for frozen intents.
    expect(container.querySelector('[data-testid="frozen-intent"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="retry-intent"]')).toBeNull();

    // Abandon without confirmation: refused, record kept, no archive entry.
    await ctx.abandonFrozenIntent({ confirmedExternalReconcile: false });
    expect(ctx.state.status?.kind).toBe("error");
    expect(ctx.pendingIntent?.state).toBe("frozen");
    expect(h.store.archive).toHaveLength(0);

    // Abandon after confirmed external reconcile: archived, slot freed.
    await ctx.abandonFrozenIntent({ confirmedExternalReconcile: true });
    expect(ctx.pendingIntent).toBeNull();
    expect(h.store.intents.size).toBe(0);
    expect(h.store.archive).toHaveLength(1);
    expect(h.store.archive[0].record.createdAtTimeNs).toBe(mintedCreatedAt);
  });

  it("logout as A -> login as B: B cannot see or submit A's envelope; A recovers it later", async () => {
    window.location.hash = "";
    const ledger = fakeLedger({ outcomes: ["transport-error-executed"] });
    const h = flowHarness({ restore: sessionFor(ownerA), mutationToken: ledger.token });
    const ctx = await mountApp(mountContainer(), {}, h.deps);

    // A's transfer ends transport-unknown -> durable envelope for A.
    await ctx.transfer({ toText: RECIPIENT, amountText: "10" });
    expect(ctx.pendingIntent?.state).toBe("unknown");
    const aKey = [...h.store.intents.keys()][0];
    expect(aKey).toContain(ownerA.toText());

    await ctx.logout();
    expect(ctx.pendingIntent).toBeNull();

    // B logs in on the same device: A's envelope is invisible to B.
    h.setLoginSession(sessionFor(ownerB));
    await ctx.login();
    expect(ctx.state.principal?.toText()).toBe(ownerB.toText());
    expect(ctx.pendingIntent).toBeNull();

    // B transacts normally in B's OWN slot; A's record is untouched.
    await ctx.transfer({ toText: RECIPIENT, amountText: "3" });
    expect(ctx.state.status?.kind).toBe("success");
    expect(h.store.intents.size).toBe(1); // only A's unresolved envelope remains
    expect(h.store.intents.get(aKey)?.ownerPrincipal).toBe(ownerA.toText());
    expect(h.store.intents.get(aKey)?.state).toBe("unknown");

    // A logs back in and recovers the SAME envelope; retry -> Duplicate, one debit.
    await ctx.logout();
    h.setLoginSession(sessionFor(ownerA));
    await ctx.login();
    expect(ctx.pendingIntent?.state).toBe("unknown");
    expect(ctx.pendingIntent?.createdAtTimeNs).toBe(h.store.intents.get(aKey)?.createdAtTimeNs);
    const debitsBefore = ledger.debits();
    await ctx.retryPendingIntent();
    expect(ctx.state.status?.msg).toMatch(/no second debit/i);
    expect(ledger.debits()).toBe(debitsBefore); // A's original debit already counted
    expect(h.store.intents.size).toBe(0);
  });
});
