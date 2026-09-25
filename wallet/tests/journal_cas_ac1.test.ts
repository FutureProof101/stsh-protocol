/**
 * AC-1 gate tests — CAS-guarded journal writes, lossless v1->v2 migration,
 * and caller-side stale recovery (corrective lane, brief §1).
 *
 * The core races run against BOTH the in-memory store and the REAL IndexedDB
 * implementation (fake-indexeddb): a stale tab's resolve/freeze/markUnknown/
 * abandon must fail closed with StaleIntentError and never destroy a newer
 * intent — the double-debit class the SSA found.
 */

import "fake-indexeddb/auto";

import { unusedIcrc2 } from "./helpers/tokenStubs";
import { describe, expect, it, vi } from "vitest";
import { openDB } from "idb";
import { Principal } from "@dfinity/principal";
import { Ed25519KeyIdentity } from "@dfinity/identity";

import {
  IntentSlotBusyError,
  StaleIntentError,
  TransferJournal,
  openIndexedDbJournalStore,
  scopeKey,
  type BeginIntentFields,
  type JournalStore,
  type TransferIntentRecord,
  type TransferScope,
} from "../src/storage/transferJournal";
import type { AuthSession, DelegationIdentityLike } from "../src/session/auth";
import { PRODUCTION_ORIGIN } from "../src/session/config";
import type { TokenCanister, TokenMutationCanister } from "../src/actors/token";
import { mountApp, type AppDeps } from "../src/ui/app";
import { memoryJournalStore } from "./helpers/memoryJournalStore";

const RECIPIENT = "ohspu-zqaaa-aaaad-qmasq-cai";
const OWNER = Ed25519KeyIdentity.generate(new Uint8Array(32).fill(31)).getPrincipal().toText();
/**
 * The journal scope keys on the LEDGER canister id, which `resolveConfig({})`
 * now supplies from a hardcoded default (WT-1 Addendum A) rather than leaving
 * `""`. Written as a literal here — importing `DEFAULT_TOKEN_CANISTER_ID` would
 * make the scope agree with the code under test by construction, and a scope
 * mismatch is exactly the bug these CAS arms exist to catch.
 */
const LIVE_TOKEN_ID = "clv7x-haaaa-aaaar-qchha-cai";

function scope(owner = OWNER, ledger = "ledger-1", network = "https://icp-api.io"): TransferScope {
  return { ownerPrincipal: owner, ledgerCanisterId: ledger, network };
}

function fields(overrides: Partial<BeginIntentFields> = {}): BeginIntentFields {
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

function uniqueDbName(): string {
  return `stsh-test-${crypto.randomUUID()}`;
}

const STORE_FACTORIES: Array<[string, () => Promise<JournalStore>]> = [
  ["in-memory", async () => memoryJournalStore()],
  ["real IndexedDB", () => openIndexedDbJournalStore(uniqueDbName())],
];

describe.each(STORE_FACTORIES)("AC-1 CAS journal (%s store)", (_label, makeStore) => {
  const KEY = scopeKey(scope());

  it("minted intents carry a CSPRNG intentId and revision 0", async () => {
    const store = await makeStore();
    const journal = new TransferJournal(store, scope());
    const intent = await journal.beginIntent(fields());
    expect(intent.intentId).toMatch(/^[0-9a-f]{32}$/);
    expect(intent.revision).toBe(0);
    const second = await journal
      .beginIntent(fields())
      .catch((e: unknown) => e as IntentSlotBusyError);
    expect(second).toBeInstanceOf(IntentSlotBusyError);
  });

  it("a stale resolve cannot delete a newer intent (J intact)", async () => {
    const store = await makeStore();
    const journal = new TransferJournal(store, scope());
    const intentI = await journal.beginIntent(fields());
    const markedI = await journal.markUnknown(intentI);
    await journal.resolve(markedI); // definite outcome frees the slot
    const intentJ = await journal.beginIntent(fields({ amount: 999n }));

    const err = await journal.resolve(markedI).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(StaleIntentError);
    expect((err as StaleIntentError).current).toEqual(intentJ);
    expect(await store.get(KEY)).toEqual(intentJ); // J survived the stale delete
  });

  it("a stale freeze or markUnknown cannot overwrite a newer intent", async () => {
    const store = await makeStore();
    const journal = new TransferJournal(store, scope());
    const intentI = await journal.beginIntent(fields());
    const markedI = await journal.markUnknown(intentI);
    await journal.resolve(markedI);
    const intentJ = await journal.beginIntent(fields({ amount: 999n }));

    await expect(journal.freeze(markedI)).rejects.toThrow(StaleIntentError);
    await expect(journal.markUnknown(markedI)).rejects.toThrow(StaleIntentError);
    const slot = await store.get(KEY);
    expect(slot).toEqual(intentJ); // untouched: same id, revision 0, attempts 0
  });

  it("a newer transport-unknown intent survives every stale op, byte-for-byte", async () => {
    const store = await makeStore();
    const journal = new TransferJournal(store, scope());
    const intentI = await journal.beginIntent(fields());
    const markedI = await journal.markUnknown(intentI);
    await journal.resolve(markedI);
    const intentJ = await journal.beginIntent(
      fields({ amount: 777n, createdAtTimeNs: 1_800_000_000_000_000_000n }),
    );
    const markedJ = await journal.markUnknown(intentJ); // J is now transport-unknown

    await expect(journal.resolve(markedI)).rejects.toThrow(StaleIntentError);
    await expect(journal.freeze(markedI)).rejects.toThrow(StaleIntentError);

    const recovered = await journal.loadUnresolved();
    expect(recovered).toEqual(markedJ);
    expect(recovered?.createdAtTimeNs).toBe("1800000000000000000");
    expect(recovered?.state).toBe("unknown");
    expect(recovered?.attempts).toBe(1);
  });

  it("an outdated revision of the SAME intent is also stale", async () => {
    const store = await makeStore();
    const journal = new TransferJournal(store, scope());
    const intent = await journal.beginIntent(fields());
    await journal.markUnknown(intent); // slot now at revision 1
    await expect(journal.markUnknown(intent)).rejects.toThrow(StaleIntentError); // rev-0 replay
    const slot = await store.get(KEY);
    expect(slot?.revision).toBe(1);
    expect(slot?.attempts).toBe(1); // the replay did not double-count the attempt
  });

  it("abandon is atomic and unrepeatable: one archive entry, stale retry archives nothing", async () => {
    const store = await makeStore();
    const journal = new TransferJournal(store, scope());
    const intent = await journal.beginIntent(fields());
    const marked = await journal.markUnknown(intent);
    const frozen = await journal.freeze(marked);

    await journal.abandonFrozen(frozen, { confirmedExternalReconcile: true });
    expect(await store.get(KEY)).toBeNull();
    expect(await store.listArchive()).toHaveLength(1);

    // Retry of the same abandon: CAS fails, NO duplicate archive entry.
    await expect(
      journal.abandonFrozen(frozen, { confirmedExternalReconcile: true }),
    ).rejects.toThrow(StaleIntentError);
    expect(await store.listArchive()).toHaveLength(1);

    // A stale abandon against a NEWER occupant archives nothing and keeps it.
    const intentJ = await journal.beginIntent(fields({ amount: 55n }));
    await expect(
      journal.abandonFrozen(frozen, { confirmedExternalReconcile: true }),
    ).rejects.toThrow(StaleIntentError);
    expect(await store.listArchive()).toHaveLength(1);
    expect(await store.get(KEY)).toEqual(intentJ);
  });
});

// ---------------------------------------------------------------------------
// AC-1c: lossless v1 -> v2 migration (real IndexedDB)
// ---------------------------------------------------------------------------

interface V1Record {
  schema: 1;
  state: "pending" | "unknown" | "frozen";
  ownerPrincipal: string;
  ledgerCanisterId: string;
  network: string;
  fromSubaccountHex: string | null;
  toOwner: string;
  toSubaccountHex: string | null;
  amount: string;
  fee: string;
  memoHex: string | null;
  createdAtTimeNs: string;
  createdAtMs: number;
  attempts: number;
}

function v1Record(overrides: Partial<V1Record> = {}): V1Record {
  return {
    schema: 1,
    state: "unknown",
    ownerPrincipal: OWNER,
    ledgerCanisterId: "ledger-1",
    network: "https://icp-api.io",
    fromSubaccountHex: null,
    toOwner: RECIPIENT,
    toSubaccountHex: null,
    amount: "1000000000",
    fee: "10000",
    memoHex: "deadbeef",
    createdAtTimeNs: "1700000000000000000",
    createdAtMs: 123_456,
    attempts: 3,
    ...overrides,
  };
}

async function seedV1Database(name: string): Promise<void> {
  const db = await openDB(name, 1, {
    upgrade(database) {
      database.createObjectStore("transfer-intents");
      database.createObjectStore("transfer-archive", { autoIncrement: true });
    },
  });
  await db.put("transfer-intents", v1Record(), `v1|https://icp-api.io|ledger-1|${OWNER}`);
  await db.add("transfer-archive", {
    record: v1Record({ state: "frozen", amount: "42", attempts: 2 }),
    archivedAtMs: 456_789,
    resolution: "abandoned-after-external-reconcile",
  });
  db.close();
}

describe("AC-1c journal v1 -> v2 migration", () => {
  it("migrates active + archived v1 records losslessly (re-keyed, nothing invisible)", async () => {
    const name = uniqueDbName();
    await seedV1Database(name);

    const store = await openIndexedDbJournalStore(name);
    const journal = new TransferJournal(store, scope());
    const migrated = await journal.loadUnresolved();

    // The active record is visible under the v2 key with EVERY field intact.
    expect(migrated).not.toBeNull();
    expect(migrated?.schema).toBe(2);
    expect(migrated?.intentId).toMatch(/^[0-9a-f]{32}$/);
    expect(migrated?.revision).toBe(0);
    expect(migrated?.state).toBe("unknown");
    expect(migrated?.attempts).toBe(3);
    expect(migrated?.amount).toBe("1000000000");
    expect(migrated?.fee).toBe("10000");
    expect(migrated?.memoHex).toBe("deadbeef");
    expect(migrated?.createdAtTimeNs).toBe("1700000000000000000");
    expect(migrated?.createdAtMs).toBe(123_456);
    expect(migrated?.toOwner).toBe(RECIPIENT);
    expect(migrated?.ownerPrincipal).toBe(OWNER);

    // The v1 key is gone (re-keyed, not duplicated, not silently retained).
    expect(await store.get(`v1|https://icp-api.io|ledger-1|${OWNER}`)).toBeNull();

    // The archive migrated too and stays readable.
    const archive = await store.listArchive();
    expect(archive).toHaveLength(1);
    expect(archive[0].archivedAtMs).toBe(456_789);
    expect(archive[0].record.schema).toBe(2);
    expect(archive[0].record.state).toBe("frozen");
    expect(archive[0].record.amount).toBe("42");
    expect(archive[0].record.attempts).toBe(2);

    // The migrated record is fully CAS-operable (retry byte-for-byte works).
    const marked = await journal.markUnknown(migrated as TransferIntentRecord);
    expect(marked.attempts).toBe(4);
    expect(marked.revision).toBe(1);
    expect(marked.createdAtTimeNs).toBe("1700000000000000000");
  });

  it("surfaces a blocked migration via onBlocked, then completes once the old tab closes", async () => {
    const name = uniqueDbName();
    await seedV1Database(name);

    // An "old tab" holds a v1 connection open.
    const oldTab = await openDB(name, 1);
    let blockedCalls = 0;
    const opening = openIndexedDbJournalStore(name, {
      onBlocked: () => {
        blockedCalls += 1;
      },
    });
    await vi.waitFor(() => expect(blockedCalls).toBeGreaterThan(0));

    oldTab.close();
    const store = await opening; // resolves once the blocker is gone
    expect(await new TransferJournal(store, scope()).loadUnresolved()).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// AC-1b: caller-side stale recovery (app level)
// ---------------------------------------------------------------------------

function sessionFor(principalText: string): AuthSession {
  return {
    identity: {} as DelegationIdentityLike,
    principal: Principal.fromText(principalText),
  };
}

describe("AC-1b caller-side stale recovery (mountApp)", () => {
  it("stale CAS -> no wire call, slot reloaded under the epoch, UI does not loop on the dead intent", async () => {
    window.location.hash = "";
    const store = memoryJournalStore();
    let wireCalls = 0;
    const mutationToken: TokenMutationCanister = {
      ...unusedIcrc2,
      transfer: async () => {
        wireCalls += 1;
        throw new Error("connection reset (response lost)"); // transport-unknown
      },
    };
    const readToken: TokenCanister = {
      balanceOf: async () => 0n,
      metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 10_000n }),
      fee: async () => 10_000n,
    };
    const deps: AppDeps = {
      origin: PRODUCTION_ORIGIN,
      // S1-02: the launch origin is runtime-loaded; this harness supplies the ruled
      // value so the policy sees the same origin it is evaluated against.
      loadLaunchOrigin: async () => PRODUCTION_ORIGIN,
      buildReadActors: async () => ({
        token: readToken,
        staking: { getStakePositions: async () => [], getPendingRewards: async () => 0n },
        vesting: { getSchedule: async () => null, claimableAmount: async () => 0n },
      }),
      buildMutationActors: async () => ({ token: mutationToken }),
      createAuth: async () => ({
        restore: async () => sessionFor(OWNER),
        login: async () => {
          throw new Error("not scripted");
        },
        logout: async () => undefined,
        verify: () => "valid",
      }),
      createJournalStore: async () => store,
    };

    const container = document.createElement("div");
    document.body.append(container);
    const ctx = await mountApp(container, {}, deps);

    // A's transfer ends transport-unknown -> durable intent I (rev 1).
    await ctx.transfer({ toText: RECIPIENT, amountText: "10" });
    expect(ctx.pendingIntent?.state).toBe("unknown");
    expect(wireCalls).toBe(1);
    const staleId = ctx.pendingIntent?.intentId;

    // "Another tab": settles I and claims a NEW intent K in the same scope.
    const appScope = scope(OWNER, LIVE_TOKEN_ID, "https://icp-api.io"); // default env: the pinned ledger id, mainnet host
    const otherTab = new TransferJournal(store, appScope);
    const currentSlot = await otherTab.loadUnresolved();
    expect(currentSlot?.intentId).toBe(staleId);
    await otherTab.resolve(currentSlot as TransferIntentRecord);
    const intentK = await otherTab.beginIntent(fields({ amount: 12_345n }));

    // This tab retries its STALE pendingIntent: the CAS must fail BEFORE any
    // wire call, and the UI must resynchronize to K — not loop on I.
    await ctx.retryPendingIntent();
    expect(wireCalls).toBe(1); // no wire call happened
    expect(ctx.pendingIntent?.intentId).toBe(intentK.intentId);
    expect(ctx.pendingIntent?.amount).toBe("12345");
    expect(ctx.state.status?.msg).toMatch(/updated by another tab/i);

    // The rendered account page now shows K's pending panel, not I's.
    expect(container.textContent).toMatch(/Unresolved transfer/);
  });
});

// ---------------------------------------------------------------------------
// AC-1b POST-WIRE stale recovery (SSA correction): the real outcome survives
// ---------------------------------------------------------------------------

describe("AC-1b post-wire stale recovery preserves the REAL outcome (SSA correction)", () => {
  const APP_SCOPE = scope(OWNER, LIVE_TOKEN_ID, "https://icp-api.io"); // default env: the pinned ledger id, mainnet host

  /**
   * Boots a session whose FIRST transfer executes but loses its response
   * (durable unknown intent), and whose byte-for-byte RETRY lets "tab B"
   * interleave via `onRetryWire` BEFORE this tab's settle runs — the
   * deterministic version of the two-tab race the SSA reproduced.
   */
  async function mountRetryRace(onRetryWire: (store: ReturnType<typeof memoryJournalStore>) => Promise<void>) {
    window.location.hash = "";
    const store = memoryJournalStore();
    let wireCalls = 0;
    const executed = new Map<string, bigint>();
    const mutationToken: TokenMutationCanister = {
      ...unusedIcrc2,
      transfer: async (req) => {
        wireCalls += 1;
        const key = `${req.createdAtTime}|${req.amount}|${req.fee}`;
        if (wireCalls === 1) {
          executed.set(key, 1n); // the ledger EXECUTED; the response was lost
          throw new Error("connection reset (response lost)");
        }
        await onRetryWire(store); // tab B settles/supersedes the slot NOW
        const block = executed.get(key);
        if (block !== undefined) return { kind: "duplicate", duplicateOf: block };
        executed.set(key, 2n);
        return { kind: "ok", blockIndex: 2n };
      },
    };
    const deps: AppDeps = {
      origin: PRODUCTION_ORIGIN,
      // S1-02: the launch origin is runtime-loaded; this harness supplies the ruled
      // value so the policy sees the same origin it is evaluated against.
      loadLaunchOrigin: async () => PRODUCTION_ORIGIN,
      buildReadActors: async () => ({
        token: {
          balanceOf: async () => 777n,
          metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 10_000n }),
          fee: async () => 10_000n,
        },
        staking: { getStakePositions: async () => [], getPendingRewards: async () => 0n },
        vesting: { getSchedule: async () => null, claimableAmount: async () => 0n },
      }),
      buildMutationActors: async () => ({ token: mutationToken }),
      createAuth: async () => ({
        restore: async () => sessionFor(OWNER),
        login: async () => {
          throw new Error("not scripted");
        },
        logout: async () => undefined,
        verify: () => "valid",
      }),
      createJournalStore: async () => store,
    };
    const container = document.createElement("div");
    document.body.append(container);
    const ctx = await mountApp(container, {}, deps);
    await ctx.transfer({ toText: RECIPIENT, amountText: "10" });
    expect(ctx.pendingIntent?.state).toBe("unknown");
    expect(wireCalls).toBe(1);
    return { ctx, container, store, executedCount: () => executed.size, wireCalls: () => wireCalls };
  }

  it("tab B clears I before A settles its confirmed duplicate: A reports CONFIRMED success, never 'nothing submitted'", async () => {
    const race = await mountRetryRace(async (store) => {
      const otherTab = new TransferJournal(store, APP_SCOPE);
      const current = await otherTab.loadUnresolved();
      if (current !== null) await otherTab.resolve(current);
    });

    await race.ctx.retryPendingIntent();

    // The REAL outcome is preserved and reported (SSA Critical): confirmed
    // execution, balance refreshed — no false "nothing submitted" that would
    // invite a fresh intent and a second debit.
    expect(race.ctx.state.status?.kind).toBe("success");
    expect(race.ctx.state.status?.msg).toMatch(/no second debit/i);
    expect(race.ctx.state.status?.msg).toMatch(/already executed/i);
    expect(race.ctx.state.status?.msg).not.toMatch(/nothing was submitted|nothing went to the ledger/i);
    expect(race.ctx.state.balance).toBe(777n); // refreshed after the confirmed result
    // The slot is genuinely settled — and the UI says CONFIRMED, not clean-slate.
    expect(race.ctx.pendingIntent).toBeNull();
    expect(race.executedCount()).toBe(1); // exactly one debit, ever
    expect(race.wireCalls()).toBe(2);
  });

  it("tab B clears I AND claims successor K: A reports its confirmed outcome and displays K separately", async () => {
    let successorId = "";
    const race = await mountRetryRace(async (store) => {
      const otherTab = new TransferJournal(store, APP_SCOPE);
      const current = await otherTab.loadUnresolved();
      if (current !== null) await otherTab.resolve(current);
      const successor = await otherTab.beginIntent(fields({ amount: 5_555n }));
      successorId = successor.intentId;
    });

    await race.ctx.retryPendingIntent();

    // Outcome reported in the status bar...
    expect(race.ctx.state.status?.kind).toBe("success");
    expect(race.ctx.state.status?.msg).toMatch(/no second debit/i);
    expect(race.ctx.state.status?.msg).not.toMatch(/nothing was submitted|nothing went to the ledger/i);
    // ...and the successor slot shown SEPARATELY via the pending panel.
    expect(race.ctx.pendingIntent?.intentId).toBe(successorId);
    expect(race.ctx.pendingIntent?.amount).toBe("5555");
    expect(race.container.textContent).toMatch(/Unresolved transfer/);
    expect(race.executedCount()).toBe(1);
  });
});
