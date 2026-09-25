/**
 * VAULT-LIST-PAGING — the operator page must show EVERY Vault proposal.
 *
 * WHY THIS FILE EXISTS. On 2026-09-22 Vault proposal #26 (the launch fee
 * activation) was proposed and given its first approval by the machine dfx
 * identity. The second approval has to come from an Internet Identity signer,
 * and II can only sign through this page. The page never showed #26: it made
 * ONE `list_proposals(null, 25)` call, the Vault returns ids ASCENDING and
 * strictly after the cursor with `take(limit)`, and terminal proposals are
 * never removed — so the page was a fixed window of ids 1..25, forever. From
 * id 26 on, the Vault plane had no II-reachable approval surface at all.
 *
 * Every arm below is about that class of failure, so each one says which:
 *
 *  - PAGING WALK (AC-1, 1b, 2, 3, 4): the exact cursor arguments, not just the
 *    rendered result. A page that happened to render the right rows from the
 *    wrong cursors would pass a rows-only assertion and still be broken at the
 *    next boundary. AC-1 is the arm that exercises the >25 boundary: both
 *    visible ids (28, 26) are above the old single window.
 *  - FAIL CLOSED (AC-7): a walk is atomic. A thrown read or a `null` page
 *    invalidates the WHOLE walk — including after a previously successful
 *    list, which is the case that leaves a stale list on screen if you only
 *    accumulate locally. `null` is unauthorized, never "an empty page".
 *  - BY ID (AC-5, AC-6): CUST-SSA-001 is preserved on the by-id path because
 *    it IS the list path — the same `proposalCard`, the same `bindApproval`.
 *    The negative is asserted at the real submission seam, twice: once through
 *    the page's connected recorder, and once through `wrapVaultActor` over a
 *    raw `_SERVICE` double, so "the adapter would have swallowed it" is not an
 *    available explanation for a green result.
 *  - POST-PROPOSE REFRESH (AC-11): a newly created id becomes visible without
 *    a manual reload, and an UNSUCCESSFUL propose neither re-walks nor clears.
 *  - O-3 LOCAL RESULT: the raw outcome renders beneath the control that caused
 *    it, across repaint, and is not misattributed to another form.
 *
 * KNOWN, DISCLOSED, AND NOT FIXED HERE: `actionSummary` has no `Application`
 * branch, so #26 renders as the bare word "Application". The commitment hash
 * still binds what was proposed; a matching hash proves BINDING, not informed
 * payload review. Reading #26's payload via dfx before pasting is an operator
 * step, not something this page currently shows.
 */

import { Principal } from "@dfinity/principal";
import { describe, expect, it } from "vitest";

import type {
  ActionOutcome,
  ProposalView,
  _SERVICE,
} from "../../src/declarations/vault/vault.did";
import { wrapVaultActor, type VaultCanister, type VaultResult } from "../src/actors/vault";
import type { UpgraderCanister } from "../src/actors/upgrader";
import { bytesToHex } from "../src/operator/proposals";
import committedPins from "../src/generated/releasePins.json";
import type { WasmPins } from "../src/release/wasmPins";
import { evaluateSessionPolicy, resolveConfig, type WalletConfig } from "../src/session/config";
import { renderOperator, type OperatorDeps } from "../src/ui/pages/operator";
import type { AppContext } from "../src/ui/context";

const PINS = committedPins as WasmPins;
const SIGNER = Principal.fromText("aaaaa-aa");
const PEER = Principal.fromText("2vxsx-fae");
const PRODUCTION_ORIGIN = "https://app.stsh.fi";
const PAGE_LIMIT = 25;

// ── Fixtures ────────────────────────────────────────────────────────────────

const COMMITMENT = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const COMMITMENT_HEX = bytesToHex(COMMITMENT);

const PENDING: ActionOutcome = { Pending: null };
const EXECUTING: ActionOutcome = { Executing: null };
const UNKNOWN: ActionOutcome = { OutcomeUnknown: null };
const EXECUTED: ActionOutcome = { Executed: null };
const FAILED: ActionOutcome = { Failed: null };
const CANCELLED: ActionOutcome = { Cancelled: null };
const EXPIRED: ActionOutcome = { Expired: null };

/** `#26`'s real shape: a Pending `Application` action, as the Vault returns it. */
function viewOf(id: bigint, outcome: ActionOutcome, proposer: Principal = PEER): ProposalView {
  return {
    result: [],
    action: { Application: "PoolSetGovernanceFeeParams" },
    commitment_hash: COMMITMENT,
    epoch: 1n,
    created_at_ns: 1_700_000_000_000_000_000n,
    proposal_id: id,
    proposer,
    outcome,
    snapshot_id: [],
    approvals: [],
  };
}

/**
 * A fake with the Vault's REAL listing semantics
 * (`canisters/vault/src/lib.rs:6268-6294`): ascending `proposal_id`, strictly
 * after `cursor`, `take(limit)`. Building the fake this way rather than
 * hand-writing pages is what makes the cursor assertions meaningful — a page
 * that sent the wrong cursor gets wrong ROWS here, not just a wrong argument
 * log.
 */
function listingFrom(rows: () => ProposalView[]) {
  return async (cursor: bigint | null, limit: number): Promise<ProposalView[]> => {
    const sorted = [...rows()].sort((a, b) => (a.proposal_id < b.proposal_id ? -1 : 1));
    return sorted.filter((v) => cursor === null || v.proposal_id > cursor).slice(0, limit);
  };
}

interface ListCall {
  cursor: bigint | null;
  limit: number;
}

/**
 * A spy Vault that RECORDS the listing reads.
 *
 * The J-17b fixture's `listProposals` records nothing, so inspecting its call
 * log for listing behaviour would be inspecting an empty log. This one is
 * connected: `listCalls` is the evidence for every cursor assertion, and
 * `calls` is the evidence for "nothing was sent".
 */
function recordingVault(overrides: Partial<VaultCanister> = {}): {
  vault: VaultCanister;
  calls: { method: string; args: unknown[] }[];
  listCalls: ListCall[];
  getProposalCalls: bigint[];
} {
  const calls: { method: string; args: unknown[] }[] = [];
  const listCalls: ListCall[] = [];
  const getProposalCalls: bigint[] = [];
  const record = (method: string, ...args: unknown[]) => calls.push({ method, args });
  const base: VaultCanister = {
    async propose(kind) {
      record("propose", kind);
      return { ok: 7n } as VaultResult<bigint>;
    },
    async approve(id, hash) {
      record("approve", id, hash);
      return { ok: { Approved: { approvals: 2, threshold: 2 } } };
    },
    async cancelProposal(id) {
      record("cancel_proposal", id);
      return { ok: null };
    },
    async sweepExpiredProposals(limit) {
      record("sweep_expired_proposals", limit);
      return { ok: [] };
    },
    async listProposals() {
      return [];
    },
    async getProposal() {
      return null;
    },
    async getSigners() {
      return [SIGNER];
    },
    async getGovernedTargets() {
      return null;
    },
    async getCreationReceipts() {
      return null;
    },
    async getAuditEvents() {
      return null;
    },
    async getGovernanceSummary() {
      return { threshold: 2, signer_count: 3, governance_epoch: 1n };
    },
    async getActionCatalogue() {
      return [];
    },
    async getBuildInfo() {
      return "test";
    },
    ...overrides,
  };
  // Wrap the two reads this lane is about so EVERY invocation is recorded,
  // including the ones supplied through `overrides`.
  const vault: VaultCanister = {
    ...base,
    async listProposals(cursor, limit) {
      listCalls.push({ cursor, limit });
      return base.listProposals(cursor, limit);
    },
    async getProposal(id) {
      getProposalCalls.push(id);
      return base.getProposal(id);
    },
  };
  return { vault, calls, listCalls, getProposalCalls };
}

const upgrader: UpgraderCanister = {
  async getControllerInvariantProof() {
    return {
      upgrader_controllers_ok: true,
      freshness: { Fresh: null } as never,
      observed_at_ns: 0n,
      age_ns: [],
      max_age_ns: 0n,
      vault_controllers_ok: true,
      current_proof_ok: true,
    };
  },
  async getRecoverySummary() {
    return { threshold: 2, member_count: 3 };
  },
  async getBuildInfo() {
    return "test";
  },
  // The rotation plane stays OFF in this file: a null membership read is the
  // fail-closed answer, and every arm here is about the VAULT plane. The two
  // rosters are independent and this file must not blur them.
  async getRecoveryMembership() {
    return null;
  },
  async getAuditEvents() {
    return null;
  },
  async proposeMembershipRotation() {
    throw new Error("paging fixture: propose_membership_rotation is not exercised here");
  },
  async approveRecovery() {
    throw new Error("paging fixture: approve_recovery is not exercised here");
  },
  async getRotationProposal() {
    return null;
  },
};

function ctxFor(input: { vault: VaultCanister; principal?: Principal }): AppContext {
  const noop = async (): Promise<void> => undefined;
  const config: WalletConfig = { ...resolveConfig({}), launchOrigin: PRODUCTION_ORIGIN };
  const policy = evaluateSessionPolicy(config, PRODUCTION_ORIGIN);
  return {
    config,
    policy,
    state: {
      principal: input.principal ?? SIGNER,
      balance: null,
      busy: false,
      spendLocallyCancellable: false,
      status: null,
      cacheUnlocked: false,
      shieldEntries: null,
      notes: [],
      scanning: false,
      lastScanOk: null,
      scanProgress: null,
      mirrorHead: null,
      quarantineTotal: 0,
      verifiedScan: null,
      verifiedRollback: null,
      verifiedScanning: false,
      wipeReport: null,
      submissionDelayEnabled: false,
      pendingDelay: null,
      quotaNotice: null,
      capacityCountdownSeconds: null,
      spendFeeBasis: null,
      pendingRecovery: [],
    },
    readActors: {
      token: {
        balanceOf: async () => 0n,
        metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
        fee: async () => 0n,
      },
      staking: { getStakePositions: async () => [], getPendingRewards: async () => 0n },
      vesting: { getSchedule: async () => null, claimableAmount: async () => 0n },
    },
    mutationActors: null,
    journalAvailable: true,
    operatorActors: { vault: input.vault, upgrader },
    shieldedActors: null,
    pendingIntent: null,
    navigate: () => undefined,
    refresh: () => undefined,
    login: noop,
    logout: noop,
    refreshBalance: noop,
    transfer: noop,
    retryPendingIntent: noop,
    abandonFrozenIntent: noop,
    unlockNoteCache: noop,
    shield: noop,
    reconcileShieldJournal: noop,
    revokeShieldAllowance: noop,
    cancelPlannedShield: noop,
    abandonAmbiguousShieldEntry: noop,
    scan: noop,
    spend: noop,
    recoverSpends: noop,
    panicWipe: async () => {
      const none = { kind: "ok" as const, items: [] };
      const inv = { indexedDb: none, localStorage: none, sessionStorage: none, cacheStorage: none };
      return { complete: true, surfaces: [], before: inv, after: inv };
    },
    setSubmissionDelayEnabled: () => undefined,
    loadSpendFeeBasis: noop,
    applySpendRecovery: noop,
  };
}

function deps(): OperatorDeps {
  return { pins: PINS, sha256Hex: async () => "0".repeat(64), nowMs: () => 1_700_000_000_000 };
}

/**
 * Let the page's microtask chains settle. A 40-window walk is 40 sequential
 * awaits, so the J-17b `settle()` (8 ticks) is not enough here — this is a
 * generous, cheap bound rather than a guess.
 */
async function settle(): Promise<void> {
  for (let i = 0; i < 600; i += 1) await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
  for (let i = 0; i < 200; i += 1) await Promise.resolve();
}

function q(root: HTMLElement, testid: string): HTMLElement | null {
  return root.querySelector<HTMLElement>(`[data-testid="${testid}"]`);
}

/** The ids of the cards currently rendered OUTSIDE the completed section. */
function visibleIds(root: HTMLElement): bigint[] {
  const completed = q(root, "operator-completed");
  return Array.from(root.querySelectorAll<HTMLElement>('[data-testid^="operator-commitment-"]'))
    .filter((node) => completed === null || !completed.contains(node))
    .map((node) => BigInt(node.getAttribute("data-testid")!.replace("operator-commitment-", "")));
}

function completedIds(root: HTMLElement): bigint[] {
  const completed = q(root, "operator-completed");
  if (completed === null) return [];
  return Array.from(
    completed.querySelectorAll<HTMLElement>('[data-testid^="operator-commitment-"]'),
  ).map((node) => BigInt(node.getAttribute("data-testid")!.replace("operator-commitment-", "")));
}

async function mount(vault: VaultCanister, principal?: Principal): Promise<HTMLElement> {
  const container = document.createElement("main");
  renderOperator(container, ctxFor({ vault, principal }), deps());
  await settle();
  return container;
}

// ── AC-1 / AC-1b / AC-2 / AC-3 — the walk ───────────────────────────────────

describe("VAULT-LIST-PAGING walks the whole listing, newest first", () => {
  /**
   * AC-1 — THE >25 BOUNDARY ARM. ids 1..30, with 26 and 28 Pending and the
   * other 28 terminal. Both visible ids are above 25, i.e. exactly the ids the
   * single-window page could never render — #26 among them.
   */
  it("AC-1 renders [28, 26] visible, collapses 28 completed, and uses cursors [null, 25]", async () => {
    const rows = Array.from({ length: 30 }, (_, i) => {
      const id = BigInt(i + 1);
      if (id === 26n || id === 28n) return viewOf(id, PENDING);
      return viewOf(id, EXECUTED);
    });
    const { vault, listCalls } = recordingVault({ listProposals: listingFrom(() => rows) });
    const root = await mount(vault);

    expect(listCalls).toEqual([
      { cursor: null, limit: PAGE_LIMIT },
      { cursor: 25n, limit: PAGE_LIMIT },
    ]);
    expect(visibleIds(root)).toEqual([28n, 26n]);

    const toggle = q(root, "operator-toggle-completed")!;
    expect(toggle.textContent).toBe("Show 28 completed");
    expect(q(root, "operator-completed")).toBeNull();

    (toggle as HTMLButtonElement).click();
    await settle();
    const expected = [30n, 29n, 27n, ...Array.from({ length: 25 }, (_, i) => BigInt(25 - i))];
    expect(completedIds(root)).toEqual(expected);
    expect(q(root, "operator-toggle-completed")!.textContent).toBe("Hide 28 completed");
  });

  it("AC-1b every proposal terminal: the empty-state text plus a toggle whose count is the fetched count", async () => {
    const rows = Array.from({ length: 30 }, (_, i) => viewOf(BigInt(i + 1), EXECUTED));
    const { vault } = recordingVault({ listProposals: listingFrom(() => rows) });
    const root = await mount(vault);
    expect(visibleIds(root)).toEqual([]);
    expect(root.textContent).toContain("No proposals.");
    // Nothing is hidden silently: the toggle count equals every fetched row.
    expect(q(root, "operator-toggle-completed")!.textContent).toBe("Show 30 completed");
    (q(root, "operator-toggle-completed") as HTMLButtonElement).click();
    await settle();
    expect(completedIds(root)).toHaveLength(30);
  });

  it("AC-2 exactly 25 proposals: two calls, the second returning the empty page, 25 rows", async () => {
    const rows = Array.from({ length: 25 }, (_, i) => viewOf(BigInt(i + 1), PENDING));
    const { vault, listCalls } = recordingVault({ listProposals: listingFrom(() => rows) });
    const root = await mount(vault);
    // The exact-25 edge: a full page is indistinguishable from "more to come",
    // so the walk MUST make the final empty read rather than guessing.
    expect(listCalls).toEqual([
      { cursor: null, limit: PAGE_LIMIT },
      { cursor: 25n, limit: PAGE_LIMIT },
    ]);
    expect(visibleIds(root)).toHaveLength(25);
    expect(visibleIds(root)[0]).toBe(25n);
  });

  it("AC-3 zero proposals: ONE call and the unchanged empty-state text", async () => {
    const { vault, listCalls } = recordingVault({ listProposals: listingFrom(() => []) });
    const root = await mount(vault);
    expect(listCalls).toEqual([{ cursor: null, limit: PAGE_LIMIT }]);
    expect(root.textContent).toContain("No proposals.");
    expect(q(root, "operator-toggle-completed")).toBeNull();
    expect(q(root, "operator-listing-truncated")).toBeNull();
  });

  it("covers all three non-terminal and all four terminal outcomes on the split", async () => {
    const rows = [
      viewOf(1n, PENDING),
      viewOf(2n, EXECUTING),
      viewOf(3n, UNKNOWN),
      viewOf(4n, EXECUTED),
      viewOf(5n, FAILED),
      viewOf(6n, CANCELLED),
      viewOf(7n, EXPIRED),
    ];
    const { vault } = recordingVault({ listProposals: listingFrom(() => rows) });
    const root = await mount(vault);
    expect(visibleIds(root)).toEqual([3n, 2n, 1n]);
    expect(q(root, "operator-toggle-completed")!.textContent).toBe("Show 4 completed");
    (q(root, "operator-toggle-completed") as HTMLButtonElement).click();
    await settle();
    expect(completedIds(root)).toEqual([7n, 6n, 5n, 4n]);
  });

  /**
   * SSA C-4. The previous fixture had four rows and one window, so no cursor
   * was ever advanced and a COUNT-derived cursor (`cursor = rowsSoFar`) would
   * have survived it; its two "colliding" ids did not in fact collide. This
   * one is decisive:
   *
   *  - a FULL 25-row first page, so the walk must take a second window;
   *  - ascending and NON-CONTIGUOUS, so `cursor = 25` (a count) fetches the
   *    wrong rows and the assertion below fails;
   *  - a last id ABOVE Number.MAX_SAFE_INTEGER, carried back as the cursor
   *    EXACTLY — a round trip through Number would send 9007199254740992;
   *  - two ids that genuinely collapse to the same f64, so a per-id Number
   *    comparator cannot order them.
   */
  it("AC-1b sends the exact bigint last id as the cursor across a 25-row non-contiguous page above 2^53", async () => {
    const collideA = 9_007_199_254_740_992n; // MAX_SAFE_INTEGER + 1
    const collideB = 9_007_199_254_740_993n; // MAX_SAFE_INTEGER + 2
    // The collision is REAL, not assumed: both are the same f64.
    expect(Number(collideA)).toBe(Number(collideB));
    expect(Number(collideA)).toBe(Number.MAX_SAFE_INTEGER + 1);

    // 23 non-contiguous ids, then the two colliding ones: 25 rows exactly.
    const firstPage = [
      ...Array.from({ length: 23 }, (_, i) => BigInt((i + 1) * 7)),
      collideA,
      collideB,
    ];
    const tail = 9_007_199_254_740_999n;
    const rows = [...firstPage, tail].map((id) => viewOf(id, PENDING));
    expect(firstPage).toHaveLength(PAGE_LIMIT);

    const { vault, listCalls } = recordingVault({ listProposals: listingFrom(() => rows) });
    const root = await mount(vault);

    // (i) EXACTLY two windows, the second carrying the unchanged bigint last
    //     id of the first page — not a count, not a Number round trip.
    expect(listCalls).toEqual([
      { cursor: null, limit: PAGE_LIMIT },
      { cursor: collideB, limit: PAGE_LIMIT },
    ]);
    expect(listCalls[1].cursor).toBe(9_007_199_254_740_993n);
    expect(typeof listCalls[1].cursor).toBe("bigint");

    // (ii) the EXACT final descending order, including the colliding pair.
    expect(visibleIds(root)).toEqual([
      tail,
      collideB,
      collideA,
      ...Array.from({ length: 23 }, (_, i) => BigInt((23 - i) * 7)),
    ]);
    expect(visibleIds(root)).toHaveLength(26);
  });

});

// ── AC-4 — the 40-window cap ────────────────────────────────────────────────

describe("VAULT-LIST-PAGING bounds the walk and SAYS SO", () => {
  it("AC-4 stops after exactly 40 reads, last cursor 975, last id 1000, and renders the notice", async () => {
    // Ascending, distinct, cursor-consistent FULL pages forever: the runaway
    // case. The cap must bite, and the operator must be told it bit.
    const { vault, listCalls } = recordingVault({
      listProposals: async (cursor, limit) => {
        const start = (cursor ?? 0n) + 1n;
        return Array.from({ length: limit }, (_, i) => viewOf(start + BigInt(i), PENDING));
      },
    });
    const root = await mount(vault);
    expect(listCalls).toHaveLength(40);
    expect(q(root, "operator-listing-truncated")!.textContent).toContain(
      "listing truncated at id 1000",
    );
    // The truncation notice is NOT buried inside the collapsed completed
    // section: it is the one thing the operator must not have to open a
    // disclosure to find.
    const completed = q(root, "operator-completed");
    expect(completed === null || !completed.contains(q(root, "operator-listing-truncated")!)).toBe(true);
    expect(visibleIds(root)[0]).toBe(1000n);
    // The derived quota is labelled as a lower bound over fetched rows only.
    expect(q(root, "operator-quota")!.textContent).toContain("DERIVED FROM THE FETCHED ROWS ONLY");
  });

  it("AC-4 (cursors) makes exactly 40 calls, the last with cursor 975, and no 41st", async () => {
    const { vault, listCalls } = recordingVault({
      listProposals: async (cursor, limit) => {
        const start = (cursor ?? 0n) + 1n;
        return Array.from({ length: limit }, (_, i) => viewOf(start + BigInt(i), EXECUTED));
      },
    });
    await mount(vault);
    expect(listCalls).toHaveLength(40);
    expect(listCalls[0]).toEqual({ cursor: null, limit: PAGE_LIMIT });
    expect(listCalls[39]).toEqual({ cursor: 975n, limit: PAGE_LIMIT });
  });

  /**
   * SSA C-4. The arm above checked CALLS only. When every fetched row is
   * TERMINAL the live list is empty and the completed section is collapsed —
   * the one shape in which a truncation notice rendered inside that section
   * would be invisible to the operator who most needs it.
   */
  it("AC-4 all-terminal + capped: the truncation notice is visible OUTSIDE the collapsed section", async () => {
    const { vault } = recordingVault({
      listProposals: async (cursor, limit) => {
        const start = (cursor ?? 0n) + 1n;
        return Array.from({ length: limit }, (_, i) => viewOf(start + BigInt(i), EXECUTED));
      },
    });
    const root = await mount(vault);
    // Nothing is expanded: the 1000 completed rows are behind the toggle.
    expect(q(root, "operator-completed")).toBeNull();
    // SSA C-4: the COUNT ITSELF is qualified as fetched-only, independently of
    // the quota wording and of the panel-level truncation notice asserted below.
    const toggle = q(root, "operator-toggle-completed")!;
    expect(toggle.textContent).toBe("Show 1000 completed (fetched rows only)");
    expect(toggle.closest('[data-testid="operator-completed"]')).toBeNull();
    toggle.click();
    await settle();
    expect(q(root, "operator-toggle-completed")!.textContent).toBe(
      "Hide 1000 completed (fetched rows only)",
    );
    expect(q(root, "operator-completed")).not.toBeNull();
    q(root, "operator-toggle-completed")!.click();
    await settle();
    expect(visibleIds(root)).toEqual([]);
    // …and the notice is nevertheless on screen, at panel level.
    const notice = q(root, "operator-listing-truncated")!;
    expect(notice.textContent).toContain("listing truncated at id 1000");
    expect(q(root, "operator-completed")).toBeNull();
    expect(
      notice.closest('[data-testid="operator-completed"]'),
    ).toBeNull();
    // The derived quota is explicitly fetched-row-only in this same shape.
    expect(q(root, "operator-quota")!.textContent).toContain("DERIVED FROM THE FETCHED ROWS ONLY");
    expect(q(root, "operator-quota")!.textContent).toContain("lower bound, not your whole in-flight total");
  });
});

// ── AC-7 — the walk is ATOMIC and fails closed ──────────────────────────────

describe("VAULT-LIST-PAGING fails closed: a partial walk is never presented as a list", () => {
  it("AC-7 window 2 throws: exactly two reads, no retry, NO partial rows, the no-list text and the error", async () => {
    const { vault, listCalls } = recordingVault({
      listProposals: async (cursor, limit) => {
        if (cursor === null) {
          return Array.from({ length: limit }, (_, i) => viewOf(BigInt(i + 1), PENDING));
        }
        throw new Error("subnet said no");
      },
    });
    const root = await mount(vault);
    expect(listCalls).toEqual([
      { cursor: null, limit: PAGE_LIMIT },
      { cursor: 25n, limit: PAGE_LIMIT },
    ]);
    // Not 25 rows, not 1 row: none. A prefix of a listing is not a listing.
    expect(visibleIds(root)).toEqual([]);
    expect(completedIds(root)).toEqual([]);
    expect(root.textContent).toContain("No proposal list (unauthorized, or not loaded yet).");
    expect(q(root, "operator-notice")!.textContent).toContain("Could not read the Vault");
    expect(q(root, "operator-notice")!.textContent).toContain("subnet said no");
  });

  it("AC-7 window 2 returns NULL: null is unauthorized, not an empty successful page", async () => {
    const { vault, listCalls } = recordingVault({
      listProposals: async (cursor, limit) => {
        if (cursor === null) {
          return Array.from({ length: limit }, (_, i) => viewOf(BigInt(i + 1), PENDING));
        }
        return null;
      },
    });
    const root = await mount(vault);
    expect(listCalls).toHaveLength(2);
    expect(visibleIds(root)).toEqual([]);
    expect(root.textContent).toContain("No proposal list (unauthorized, or not loaded yet).");
    expect(q(root, "operator-notice")!.textContent).toContain("Could not read the Vault");
    expect(q(root, "operator-notice")!.textContent).toContain("not an empty list");
  });

  it("AC-7 a failed RELOAD after a successful list CLEARS the old rows — the case local accumulation misses", async () => {
    let fail = false;
    const rows = Array.from({ length: 30 }, (_, i) => viewOf(BigInt(i + 1), PENDING));
    const listing = listingFrom(() => rows);
    const { vault } = recordingVault({
      listProposals: async (cursor, limit) => {
        if (fail && cursor !== null) throw new Error("reload blew up");
        return listing(cursor, limit);
      },
    });
    const root = await mount(vault);
    expect(visibleIds(root)).toHaveLength(30);

    fail = true;
    (q(root, "operator-reload") as HTMLButtonElement).click();
    await settle();
    // The previous successful list must NOT survive a later failed walk.
    expect(visibleIds(root)).toEqual([]);
    expect(root.textContent).toContain("No proposal list (unauthorized, or not loaded yet).");
    expect(q(root, "operator-notice")!.textContent).toContain("Could not read the Vault");
  });

  it("AC-7 the truncation state is cleared by a later failed walk too", async () => {
    let fail = false;
    const { vault } = recordingVault({
      listProposals: async (cursor, limit) => {
        if (fail && cursor !== null) throw new Error("gone");
        const start = (cursor ?? 0n) + 1n;
        return Array.from({ length: limit }, (_, i) => viewOf(start + BigInt(i), PENDING));
      },
    });
    const root = await mount(vault);
    expect(q(root, "operator-listing-truncated")).not.toBeNull();
    fail = true;
    (q(root, "operator-reload") as HTMLButtonElement).click();
    await settle();
    expect(q(root, "operator-listing-truncated")).toBeNull();
    expect(visibleIds(root)).toEqual([]);
  });

  it("AC-7 a FAILED signer read fails closed for the Vault plane and reads no listing at all", async () => {
    const { vault, listCalls } = recordingVault({
      getSigners: async () => {
        throw new Error("signer read blew up");
      },
      listProposals: listingFrom(() => [viewOf(1n, PENDING)]),
    });
    const root = await mount(vault);
    expect(listCalls).toEqual([]);
    expect(q(root, "operator-notice")!.textContent).toContain("Could not read the Vault");
    expect(q(root, "operator-proposal-load")).toBeNull();
  });
});

// ── AC-8 — the non-signer reads nothing ─────────────────────────────────────

describe("VAULT-LIST-PAGING keeps the non-signer surface at zero calls", () => {
  it("AC-8 a null signer set makes NO listing calls and offers no by-id control", async () => {
    const { vault, listCalls, getProposalCalls } = recordingVault({
      getSigners: async () => null,
      listProposals: listingFrom(() => [viewOf(26n, PENDING)]),
      getProposal: async () => viewOf(26n, PENDING),
    });
    const root = await mount(vault);
    expect(listCalls).toEqual([]);
    expect(getProposalCalls).toEqual([]);
    expect(q(root, "operator-proposal-load")).toBeNull();
    expect(q(root, "operator-approve-26")).toBeNull();
  });
});

// ── AC-5 / AC-6 — load by id, and CUST-SSA-001 on that path ─────────────────

describe("VAULT-LIST-PAGING loads a proposal by id through the SAME card", () => {
  async function loadById(
    root: HTMLElement,
    id: string,
  ): Promise<void> {
    (q(root, "operator-proposal-id") as HTMLInputElement).value = id;
    (q(root, "operator-proposal-load") as HTMLButtonElement).click();
    await settle();
  }

  it("AC-5 renders Pending Application #26 with its approve control", async () => {
    const { vault } = recordingVault({
      listProposals: listingFrom(() => []),
      getProposal: async (id) => (id === 26n ? viewOf(26n, PENDING) : null),
    });
    const root = await mount(vault);
    await loadById(root, "26");
    expect(q(root, "operator-commitment-26")!.textContent).toBe(COMMITMENT_HEX);
    expect(q(root, "operator-approve-26")).not.toBeNull();
    // DISCLOSED LIMITATION, asserted so it cannot change unnoticed: an
    // `Application` action renders as the bare variant name.
    expect(root.textContent).toContain("Application");
  });

  it("AC-5 NEGATIVE: a one-hex-char mismatch sends NOTHING through the page's own seam", async () => {
    const { vault, calls } = recordingVault({
      listProposals: listingFrom(() => []),
      getProposal: async (id) => (id === 26n ? viewOf(26n, PENDING) : null),
    });
    const root = await mount(vault);
    await loadById(root, "26");
    const off = `${COMMITMENT_HEX.slice(0, 63)}${COMMITMENT_HEX[63] === "0" ? "1" : "0"}`;
    expect(off).toMatch(/^[0-9a-f]{64}$/); // a WELL-FORMED but wrong hash
    (q(root, "operator-approve-input-26") as HTMLInputElement).value = off;
    (q(root, "operator-approve-26") as HTMLButtonElement).click();
    await settle();
    expect(calls.filter((c) => c.method === "approve")).toHaveLength(0);
    expect(q(root, "operator-approve-refused-26")!.textContent).toContain("does not match");
  });

  it("AC-5 POSITIVE: the matching paste sends exactly one approve(26n, the VIEW's bytes)", async () => {
    const { vault, calls } = recordingVault({
      listProposals: listingFrom(() => []),
      getProposal: async (id) => (id === 26n ? viewOf(26n, PENDING) : null),
    });
    const root = await mount(vault);
    await loadById(root, "26");
    (q(root, "operator-approve-input-26") as HTMLInputElement).value = COMMITMENT_HEX;
    (q(root, "operator-approve-26") as HTMLButtonElement).click();
    await settle();
    const approve = calls.filter((c) => c.method === "approve");
    expect(approve).toHaveLength(1);
    expect(approve[0].args[0]).toBe(26n);
    expect(bytesToHex(approve[0].args[1] as Uint8Array)).toBe(COMMITMENT_HEX);
  });

  it("AC-5 through wrapVaultActor over a RAW _SERVICE double: raw.approve untouched on mismatch", async () => {
    const { raw, rawCalls } = rawVaultDouble();
    const root = await mount(wrapVaultActor(raw));
    await loadById(root, "26");
    const off = `${COMMITMENT_HEX.slice(0, 63)}${COMMITMENT_HEX[63] === "0" ? "1" : "0"}`;
    (q(root, "operator-approve-input-26") as HTMLInputElement).value = off;
    (q(root, "operator-approve-26") as HTMLButtonElement).click();
    await settle();
    // Asserted on the RAW service, below the adapter: "the wrapper refused it"
    // is not an available explanation for this green.
    expect(rawCalls.approve).toHaveLength(0);
  });

  it("AC-5 through wrapVaultActor over a RAW _SERVICE double: raw.approve called once with 26n and the stored bytes", async () => {
    const { raw, rawCalls } = rawVaultDouble();
    const root = await mount(wrapVaultActor(raw));
    await loadById(root, "26");
    (q(root, "operator-approve-input-26") as HTMLInputElement).value = COMMITMENT_HEX;
    (q(root, "operator-approve-26") as HTMLButtonElement).click();
    await settle();
    expect(rawCalls.approve).toHaveLength(1);
    expect(rawCalls.approve[0][0]).toBe(26n);
    expect(bytesToHex(rawCalls.approve[0][1])).toBe(COMMITMENT_HEX);
  });

  it("AC-5 preserves the malformed-hash and stored-length refusals on a by-id row", async () => {
    const { vault, calls } = recordingVault({
      listProposals: listingFrom(() => []),
      getProposal: async () => viewOf(26n, PENDING),
    });
    const root = await mount(vault);
    await loadById(root, "26");
    for (const bad of ["", `0x${COMMITMENT_HEX}`, COMMITMENT_HEX.slice(0, 32)]) {
      (q(root, "operator-approve-input-26") as HTMLInputElement).value = bad;
      (q(root, "operator-approve-26") as HTMLButtonElement).click();
      await settle();
    }
    expect(calls.filter((c) => c.method === "approve")).toHaveLength(0);
  });

  it("AC-5 keeps cancel-my-proposal on a by-id row the caller proposed", async () => {
    const { vault, calls } = recordingVault({
      listProposals: listingFrom(() => []),
      getProposal: async () => viewOf(26n, PENDING, SIGNER),
    });
    const root = await mount(vault);
    await loadById(root, "26");
    expect(q(root, "operator-cancel-26")).not.toBeNull();
    (q(root, "operator-cancel-26") as HTMLButtonElement).click();
    await settle();
    expect(calls.filter((c) => c.method === "cancel_proposal")[0]?.args[0]).toBe(26n);
  });

  it("AC-6 a null answer renders the 'no proposal #N' notice and leaves the list untouched", async () => {
    const rows = Array.from({ length: 30 }, (_, i) => viewOf(BigInt(i + 1), PENDING));
    const { vault } = recordingVault({
      listProposals: listingFrom(() => rows),
      getProposal: async () => null,
    });
    const root = await mount(vault);
    const before = visibleIds(root);
    await loadById(root, "999");
    const note = q(root, "operator-proposal-lookup-note")!.textContent ?? "";
    expect(note).toContain("no proposal #999");
    // It must NOT claim to distinguish "absent" from "unauthorized".
    expect(note).toContain("indistinguishable");
    expect(visibleIds(root)).toEqual(before);
  });

  it("AC-6 a success followed by a null leaves NO stale approve control beside the new id", async () => {
    let answer: ProposalView | null = viewOf(26n, PENDING);
    const { vault } = recordingVault({
      listProposals: listingFrom(() => []),
      getProposal: async () => answer,
    });
    const root = await mount(vault);
    await loadById(root, "26");
    expect(q(root, "operator-approve-26")).not.toBeNull();
    answer = null;
    await loadById(root, "27");
    expect(q(root, "operator-approve-26")).toBeNull();
    expect(q(root, "operator-commitment-26")).toBeNull();
  });

  it("AC-6 a success followed by a THROW also clears the card and reports the failure", async () => {
    let blow = false;
    const { vault } = recordingVault({
      listProposals: listingFrom(() => []),
      getProposal: async () => {
        if (blow) throw new Error("read blew up");
        return viewOf(26n, PENDING);
      },
    });
    const root = await mount(vault);
    await loadById(root, "26");
    expect(q(root, "operator-approve-26")).not.toBeNull();
    blow = true;
    await loadById(root, "27");
    expect(q(root, "operator-approve-26")).toBeNull();
    expect(q(root, "operator-proposal-lookup-note")!.textContent).toContain("Could not read the Vault");
  });

  it("AC-6 malformed and out-of-nat64-range ids make ZERO getProposal calls", async () => {
    const { vault, getProposalCalls } = recordingVault({
      listProposals: listingFrom(() => []),
      getProposal: async () => viewOf(26n, PENDING),
    });
    const root = await mount(vault);
    for (const bad of ["", "  ", "26.0", "-1", "0x1a", "twenty-six", "18446744073709551616"]) {
      await loadById(root, bad);
      expect(getProposalCalls).toEqual([]);
      expect(q(root, "operator-proposal-lookup-note")).not.toBeNull();
    }
    // …and the well-formed id still works, so the guard is not a blanket block.
    await loadById(root, "26");
    expect(getProposalCalls).toEqual([26n]);
  });

  it("AC-6 an older in-flight lookup cannot overwrite a newer one", async () => {
    const gate: Record<string, (value: ProposalView | null) => void> = {};
    const { vault } = recordingVault({
      listProposals: listingFrom(() => []),
      getProposal: (id) =>
        new Promise<ProposalView | null>((resolve) => {
          gate[id.toString(10)] = resolve;
        }),
    });
    const root = await mount(vault);
    (q(root, "operator-proposal-id") as HTMLInputElement).value = "26";
    (q(root, "operator-proposal-load") as HTMLButtonElement).click();
    (q(root, "operator-proposal-id") as HTMLInputElement).value = "27";
    (q(root, "operator-proposal-load") as HTMLButtonElement).click();
    await settle();
    // The NEWER request answers first; the older one then loses the race.
    gate["27"](viewOf(27n, PENDING));
    await settle();
    gate["26"](viewOf(26n, PENDING));
    await settle();
    expect(q(root, "operator-commitment-27")).not.toBeNull();
    expect(q(root, "operator-commitment-26")).toBeNull();
  });

  it("AC-6 an id already in the list is NOT rendered a second time", async () => {
    const rows = [viewOf(26n, PENDING)];
    const { vault } = recordingVault({
      listProposals: listingFrom(() => rows),
      getProposal: async () => viewOf(26n, PENDING),
    });
    const root = await mount(vault);
    await loadById(root, "26");
    // Exactly one card, so no operator (and no test) can act on the wrong copy.
    expect(root.querySelectorAll('[data-testid="operator-approve-26"]')).toHaveLength(1);
    expect(q(root, "operator-proposal-already-listed")!.textContent).toContain("already shown");
  });

  it("by-id remains available when the listing was truncated at the cap", async () => {
    const { vault, getProposalCalls } = recordingVault({
      listProposals: async (cursor, limit) => {
        const start = (cursor ?? 0n) + 1n;
        return Array.from({ length: limit }, (_, i) => viewOf(start + BigInt(i), EXECUTED));
      },
      getProposal: async () => viewOf(5000n, PENDING),
    });
    const root = await mount(vault);
    expect(q(root, "operator-listing-truncated")).not.toBeNull();
    await loadById(root, "5000");
    expect(getProposalCalls).toEqual([5000n]);
    expect(q(root, "operator-approve-5000")).not.toBeNull();
  });
});

/** A raw candid `_SERVICE` double — no agent, no network (vault.ts:82-101). */
function rawVaultDouble(): {
  raw: _SERVICE;
  rawCalls: { approve: [bigint, Uint8Array][]; list: (bigint | null)[] };
} {
  const rawCalls: { approve: [bigint, Uint8Array][]; list: (bigint | null)[] } = {
    approve: [],
    list: [],
  };
  const unused = (name: string) => () => {
    throw new Error(`raw double: ${name} is not exercised here`);
  };
  const raw = {
    async approve(id: bigint, hash: Uint8Array) {
      rawCalls.approve.push([id, hash]);
      return { Ok: { Approved: { approvals: 2, threshold: 2 } } };
    },
    async list_proposals(cursor: [] | [bigint]) {
      rawCalls.list.push(cursor.length === 1 ? cursor[0] : null);
      return [[]];
    },
    async get_proposal(id: bigint) {
      return id === 26n ? [viewOf(26n, PENDING)] : [];
    },
    async get_signers() {
      return [[SIGNER]];
    },
    async get_governance_summary() {
      return { threshold: 2, signer_count: 3, governance_epoch: 1n };
    },
    async get_action_catalogue() {
      return [];
    },
    async get_build_info() {
      return "raw double";
    },
    propose: unused("propose"),
    cancel_proposal: unused("cancel_proposal"),
    sweep_expired_proposals: unused("sweep_expired_proposals"),
    get_governed_targets: unused("get_governed_targets"),
    get_creation_receipts: unused("get_creation_receipts"),
    get_audit_events: unused("get_audit_events"),
  } as unknown as _SERVICE;
  return { raw, rawCalls };
}

// ── AC-11 — the post-propose refresh ────────────────────────────────────────

describe("VAULT-LIST-PAGING re-walks after a SUCCESSFUL propose, and only then", () => {
  it("AC-11 POSITIVE: a full second walk from cursor null makes the new id 31 visible with no reload click", async () => {
    const rows = Array.from({ length: 30 }, (_, i) => viewOf(BigInt(i + 1), EXECUTED));
    const listing = listingFrom(() => rows);
    const { vault, listCalls } = recordingVault({
      listProposals: listing,
      propose: async () => {
        rows.push(viewOf(31n, PENDING));
        return { ok: 31n };
      },
    });
    const root = await mount(vault);
    expect(listCalls).toEqual([
      { cursor: null, limit: PAGE_LIMIT },
      { cursor: 25n, limit: PAGE_LIMIT },
    ]);
    expect(q(root, "operator-commitment-31")).toBeNull();

    (q(root, "operator-create-submit") as HTMLButtonElement).click();
    await settle();

    // (i) a SECOND walk, starting at null — a full re-walk, not a tail fetch.
    expect(listCalls).toEqual([
      { cursor: null, limit: PAGE_LIMIT },
      { cursor: 25n, limit: PAGE_LIMIT },
      { cursor: null, limit: PAGE_LIMIT },
      { cursor: 25n, limit: PAGE_LIMIT },
    ]);
    // (ii) the new Pending id is on screen with its approve control.
    expect(q(root, "operator-commitment-31")).not.toBeNull();
    expect(q(root, "operator-approve-31")).not.toBeNull();
    expect(visibleIds(root)).toEqual([31n]);
    // (iv) exactly the two walks' windows — no duplicate refresh.
    expect(listCalls).toHaveLength(4);
  });

  it("AC-11 POSITIVE: the reload button is never clicked — the refresh is the page's own", async () => {
    const rows = Array.from({ length: 30 }, (_, i) => viewOf(BigInt(i + 1), EXECUTED));
    let reloadClicks = 0;
    const { vault } = recordingVault({
      listProposals: listingFrom(() => rows),
      propose: async () => {
        rows.push(viewOf(31n, PENDING));
        return { ok: 31n };
      },
    });
    const root = await mount(vault);
    q(root, "operator-reload")!.addEventListener("click", () => {
      reloadClicks += 1;
    });
    (q(root, "operator-create-submit") as HTMLButtonElement).click();
    await settle();
    expect(reloadClicks).toBe(0);
    expect(q(root, "operator-commitment-31")).not.toBeNull();
  });

  it("AC-11 NEGATIVE (typed refusal): no second walk, the list is untouched, the result is under the control", async () => {
    const rows = Array.from({ length: 30 }, (_, i) => viewOf(BigInt(i + 1), PENDING));
    let attempts = 0;
    const { vault, listCalls } = recordingVault({
      listProposals: listingFrom(() => rows),
      propose: async () => {
        attempts += 1;
        return { err: { NotAuthorized: null } } as VaultResult<bigint>;
      },
    });
    const root = await mount(vault);
    const before = visibleIds(root);
    expect(listCalls).toHaveLength(2);

    (q(root, "operator-create-submit") as HTMLButtonElement).click();
    await settle();

    expect(listCalls).toHaveLength(2); // (i) unchanged
    expect(visibleIds(root)).toEqual(before); // (ii) untouched
    expect(attempts).toBe(1); // exactly one attempted update
    // (iii) reported through the O-3 local result, beneath the propose control.
    const local = q(root, "operator-local-result-propose-create")!;
    expect(local.textContent).toContain("The Vault refused the call");
    expect(local.textContent).toContain("Err =");
  });

  it("AC-11 NEGATIVE (transport throw): no second walk, the list survives, the uncertainty wording is preserved", async () => {
    const rows = Array.from({ length: 30 }, (_, i) => viewOf(BigInt(i + 1), PENDING));
    let attempts = 0;
    const { vault, listCalls } = recordingVault({
      listProposals: listingFrom(() => rows),
      propose: async () => {
        attempts += 1;
        throw new Error("transport blew up");
      },
    });
    const root = await mount(vault);
    const before = visibleIds(root);

    (q(root, "operator-create-submit") as HTMLButtonElement).click();
    await settle();

    expect(attempts).toBe(1); // exactly one attempted update; no auto-retry
    expect(listCalls).toHaveLength(2);
    expect(visibleIds(root)).toEqual(before);
    const local = q(root, "operator-local-result-propose-create")!;
    expect(local.textContent).toContain("may or may not have reached the Vault");
  });

  it("AC-11 FAIL-CLOSED COMPOSITION: propose Ok but the second walk's window 2 throws", async () => {
    const rows = Array.from({ length: 30 }, (_, i) => viewOf(BigInt(i + 1), PENDING));
    const listing = listingFrom(() => rows);
    let proposed = false;
    const { vault, listCalls } = recordingVault({
      listProposals: async (cursor, limit) => {
        if (proposed && cursor !== null) throw new Error("post-propose read blew up");
        return listing(cursor, limit);
      },
      propose: async () => {
        proposed = true;
        return { ok: 31n };
      },
    });
    const root = await mount(vault);
    expect(visibleIds(root)).toHaveLength(30);

    (q(root, "operator-create-submit") as HTMLButtonElement).click();
    await settle();

    expect(listCalls).toHaveLength(4);
    expect(visibleIds(root)).toEqual([]);
    expect(root.textContent).toContain("No proposal list (unauthorized, or not loaded yet).");
    expect(q(root, "operator-notice")!.textContent).toContain("Could not read the Vault");
    expect(q(root, "operator-listing-truncated")).toBeNull();
  });
});

// ── O-3 — the result belongs to the control that caused it ──────────────────

describe("VAULT-LIST-PAGING renders the raw outcome beneath the triggering control", () => {
  it("an ACCEPTED call reports beneath the form that sent it, and nowhere else", async () => {
    const { vault } = recordingVault({ listProposals: listingFrom(() => []) });
    const root = await mount(vault);
    (q(root, "operator-create-submit") as HTMLButtonElement).click();
    await settle();
    expect(q(root, "operator-local-result-propose-create")!.textContent).toContain(
      "The Vault accepted the call",
    );
    expect(q(root, "operator-local-result-propose-create")!.textContent).toContain("proposal_id = 7");
    // Not misattributed to one of the four near-identical sibling forms.
    for (const other of ["propose-InstallCode", "propose-Upgrade", "propose-settings", "propose-signerset"]) {
      expect(q(root, `operator-local-result-${other}`)).toBeNull();
    }
  });

  it("the local result SURVIVES the repaint that the refresh triggers", async () => {
    const rows: ProposalView[] = [];
    const { vault } = recordingVault({
      listProposals: listingFrom(() => rows),
      propose: async () => {
        rows.push(viewOf(7n, PENDING));
        return { ok: 7n };
      },
    });
    const root = await mount(vault);
    (q(root, "operator-create-submit") as HTMLButtonElement).click();
    await settle();
    // The successful path repaints twice (refresh, then `.then(paint)`), so a
    // result held on the element rather than in state would be gone by now.
    expect(q(root, "operator-commitment-7")).not.toBeNull();
    expect(q(root, "operator-local-result-propose-create")).not.toBeNull();
  });

  it("an approve reports beneath THAT proposal's approve control", async () => {
    const { vault } = recordingVault({ listProposals: listingFrom(() => [viewOf(26n, PENDING)]) });
    const root = await mount(vault);
    (q(root, "operator-approve-input-26") as HTMLInputElement).value = COMMITMENT_HEX;
    (q(root, "operator-approve-26") as HTMLButtonElement).click();
    await settle();
    expect(q(root, "operator-local-result-approve-26")!.textContent).toContain(
      "The Vault accepted the call",
    );
    expect(q(root, "operator-local-result-propose-create")).toBeNull();
  });

  it("a CLIENT-SIDE refusal (a malformed form) also reports under its own form", async () => {
    const { vault, calls } = recordingVault({ listProposals: listingFrom(() => []) });
    const root = await mount(vault);
    (q(root, "operator-settings-target") as HTMLInputElement).value = "not-a-principal";
    (q(root, "operator-settings-submit") as HTMLButtonElement).click();
    await settle();
    expect(calls.filter((c) => c.method === "propose")).toHaveLength(0);
    expect(q(root, "operator-local-result-propose-settings")).not.toBeNull();
    expect(q(root, "operator-local-result-propose-create")).toBeNull();
  });
});

// ── SSA C-5 — the stale card is gone BEFORE the new request is awaited ───────

/**
 * The prior round cleared `state.vaultLookup` before the read, but for a VALID
 * id the next paint happened only AFTER `await getProposal(id)` resolved. The
 * previously rendered card — with its approve and cancel controls — stayed
 * live in the DOM for the whole duration of the in-flight read, next to an
 * input naming a DIFFERENT id. Not an approve-by-id bypass (the old card still
 * binds its own stored commitment), but exactly the stale-control window the
 * by-id safety requirement forbids.
 */
describe("VAULT-LIST-PAGING invalidates the previous by-id card before awaiting the new read", () => {
  /** A Vault whose #26 answers immediately and whose #27 is held open. */
  function deferredVault(listRows: ProposalView[]) {
    let resolve27: ((v: ProposalView | null) => void) | null = null;
    let reject27: ((e: unknown) => void) | null = null;
    const { vault, getProposalCalls } = recordingVault({
      listProposals: listingFrom(() => listRows),
      getProposal: (id) => {
        if (id === 26n) return Promise.resolve(viewOf(26n, PENDING, SIGNER));
        return new Promise<ProposalView | null>((res, rej) => {
          resolve27 = res;
          reject27 = rej;
        });
      },
    });
    return {
      vault,
      getProposalCalls,
      resolve27: (v: ProposalView | null) => resolve27!(v),
      reject27: (e: unknown) => reject27!(e),
    };
  }

  async function loadById(root: HTMLElement, id: string): Promise<void> {
    (q(root, "operator-proposal-id") as HTMLInputElement).value = id;
    (q(root, "operator-proposal-load") as HTMLButtonElement).click();
    await settle();
  }

  async function startDeferredLookup(root: HTMLElement, id: string): Promise<void> {
    (q(root, "operator-proposal-id") as HTMLInputElement).value = id;
    (q(root, "operator-proposal-load") as HTMLButtonElement).click();
    await settle();
  }

  it("C-5 while the #27 read is UNRESOLVED, #26's commitment, approve and cancel are already gone (null case)", async () => {
    const listRows = [viewOf(3n, PENDING)];
    const { vault, resolve27 } = deferredVault(listRows);
    const root = await mount(vault);

    await loadById(root, "26");
    // The card we are about to invalidate really is there, controls and all.
    expect(q(root, "operator-commitment-26")).not.toBeNull();
    expect(q(root, "operator-approve-26")).not.toBeNull();
    expect(q(root, "operator-cancel-26")).not.toBeNull();

    await startDeferredLookup(root, "27");

    // THE ASSERTION. The #27 read has not resolved; the input says 27; and
    // there is no #26 control left for an operator to act on.
    expect(q(root, "operator-commitment-26")).toBeNull();
    expect(q(root, "operator-approve-26")).toBeNull();
    expect(q(root, "operator-approve-input-26")).toBeNull();
    expect(q(root, "operator-cancel-26")).toBeNull();
    // Nor has a #27 card appeared out of an unresolved read.
    expect(q(root, "operator-commitment-27")).toBeNull();
    // The INDEPENDENTLY loaded list is untouched by any of this.
    expect(visibleIds(root)).toEqual([3n]);

    resolve27(null);
    await settle();
    expect(q(root, "operator-proposal-lookup-note")!.textContent).toContain("no proposal #27");
    expect(q(root, "operator-approve-26")).toBeNull();
    expect(visibleIds(root)).toEqual([3n]);
  });

  it("C-5 the same holds when the #27 read ultimately FAILS (error case)", async () => {
    const listRows = [viewOf(3n, PENDING)];
    const { vault, reject27 } = deferredVault(listRows);
    const root = await mount(vault);

    await loadById(root, "26");
    expect(q(root, "operator-approve-26")).not.toBeNull();

    await startDeferredLookup(root, "27");
    expect(q(root, "operator-commitment-26")).toBeNull();
    expect(q(root, "operator-approve-26")).toBeNull();
    expect(q(root, "operator-cancel-26")).toBeNull();
    expect(visibleIds(root)).toEqual([3n]);

    reject27(new Error("read blew up"));
    await settle();
    expect(q(root, "operator-proposal-lookup-note")!.textContent).toContain(
      "Could not read the Vault: read blew up",
    );
    expect(q(root, "operator-approve-26")).toBeNull();
    expect(visibleIds(root)).toEqual([3n]);
  });

  it("C-5 latest-request-wins is preserved: an older in-flight answer cannot repaint its card", async () => {
    const gate: Record<string, (value: ProposalView | null) => void> = {};
    const { vault } = recordingVault({
      listProposals: listingFrom(() => []),
      getProposal: (id) =>
        new Promise<ProposalView | null>((resolve) => {
          gate[id.toString(10)] = resolve;
        }),
    });
    const root = await mount(vault);
    (q(root, "operator-proposal-id") as HTMLInputElement).value = "26";
    (q(root, "operator-proposal-load") as HTMLButtonElement).click();
    (q(root, "operator-proposal-id") as HTMLInputElement).value = "27";
    (q(root, "operator-proposal-load") as HTMLButtonElement).click();
    await settle();
    // Neither card exists while both are in flight — the paint-first fix must
    // not have introduced an intermediate render of the superseded request.
    expect(q(root, "operator-commitment-26")).toBeNull();
    expect(q(root, "operator-commitment-27")).toBeNull();
    gate["27"](viewOf(27n, PENDING));
    await settle();
    gate["26"](viewOf(26n, PENDING));
    await settle();
    expect(q(root, "operator-commitment-27")).not.toBeNull();
    expect(q(root, "operator-commitment-26")).toBeNull();
  });
});

// ── SSA C-8 — the local result survives the transition IT caused ─────────────

/**
 * O-3 renders the raw result beneath the control that caused it. But a
 * quorum-completing approve EXECUTES the proposal, and a cancel CANCELS it —
 * so the very next refresh moves that row out of the Pending branch (which is
 * where the local result used to be rendered) and into the default-COLLAPSED
 * completed section. The operator was left with only the global notice: the
 * exact raw outcome of the call they had just made was gone, and gone from
 * beside the proposal it belonged to.
 */
describe("VAULT-LIST-PAGING keeps a raw result beside its proposal after the state transition", () => {
  /** The rendered node holding the retained result, via its own anchor. */
  function retained(root: HTMLElement, id: string) {
    const anchor = q(root, `operator-retained-result-anchor-${id}`);
    return { anchor, result: anchor?.nextElementSibling as HTMLElement | null };
  }

  it("C-8 an ACCEPTED approval that executes the proposal keeps its Ok result on that row", async () => {
    const rows = [viewOf(26n, PENDING), viewOf(30n, PENDING)];
    let approveCalls = 0;
    const { vault } = recordingVault({
      listProposals: listingFrom(() => rows),
      approve: async () => {
        // The REAL transition: quorum is reached and the Vault executes it.
        approveCalls += 1;
        rows[0] = { ...rows[0], outcome: EXECUTED };
        return { ok: { Approved: { approvals: 2, threshold: 2 } } };
      },
    });
    const root = await mount(vault);
    (q(root, "operator-approve-input-26") as HTMLInputElement).value = COMMITMENT_HEX;
    (q(root, "operator-approve-26") as HTMLButtonElement).click();
    await settle();

    // (i) the transition really happened: 26 is terminal and out of the live list.
    expect(visibleIds(root)).toEqual([30n]);
    expect(completedIds(root)).toEqual([26n]);
    // …and the section holding it is OPEN, so the result is actually visible.
    expect(q(root, "operator-completed")).not.toBeNull();

    // (ii) the raw result is DOM-adjacent to its own anchor, on #26's card.
    const { anchor, result } = retained(root, "26");
    expect(anchor).not.toBeNull();
    expect(result).not.toBeNull();
    expect(result!.getAttribute("data-testid")).toBe("operator-local-result-approve-26");
    expect(q(root, "operator-completed")!.contains(result!)).toBe(true);
    expect(result!.closest(".proposal")).toBe(q(root, "operator-commitment-26")!.closest(".proposal"));

    // (iii) the EXACT text, not a prefix match.
    expect(result!.textContent).toBe(
      'The Vault accepted the call. Ok = {"Approved":{"approvals":2,"threshold":2}}',
    );
    expect(anchor!.textContent).toBe(
      "Result of the approve call you sent for #26. Current proposal status: Executed.",
    );
    // SSA C-8: the anchor states WHAT was sent and the status seen NOW. It must
    // never claim the call produced that status.
    expect(anchor!.textContent).not.toContain("moved this proposal");

    // (iv) exactly one attempted update, and no misattribution.
    expect(approveCalls).toBe(1);
    expect(q(root, "operator-local-result-approve-30")).toBeNull();
    expect(q(root, "operator-retained-result-anchor-30")).toBeNull();
    for (const other of ["propose-create", "propose-InstallCode", "propose-settings"]) {
      expect(q(root, `operator-local-result-${other}`)).toBeNull();
    }
  });

  it("C-8 an ACCEPTED cancel keeps its Ok result on the now-Cancelled row", async () => {
    const rows = [viewOf(26n, PENDING, SIGNER), viewOf(30n, PENDING)];
    let cancelCalls = 0;
    const { vault } = recordingVault({
      listProposals: listingFrom(() => rows),
      cancelProposal: async () => {
        cancelCalls += 1;
        rows[0] = { ...rows[0], outcome: CANCELLED };
        return { ok: null };
      },
    });
    const root = await mount(vault);
    (q(root, "operator-cancel-26") as HTMLButtonElement).click();
    await settle();

    expect(visibleIds(root)).toEqual([30n]);
    expect(completedIds(root)).toEqual([26n]);
    const { anchor, result } = retained(root, "26");
    expect(result!.getAttribute("data-testid")).toBe("operator-local-result-cancel-26");
    expect(result!.textContent).toBe("The Vault accepted the call. Ok = null");
    expect(anchor!.textContent).toBe(
      "Result of the cancel call you sent for #26. Current proposal status: Cancelled.",
    );
    expect(anchor!.textContent).not.toContain("moved this proposal");
    expect(result!.closest(".proposal")).toBe(q(root, "operator-commitment-26")!.closest(".proposal"));
    expect(cancelCalls).toBe(1);
    expect(q(root, "operator-local-result-cancel-30")).toBeNull();
  });

  it("C-8 a TYPED REFUSAL reports the exact Err detail beneath that proposal's own approve control", async () => {
    const rows = [viewOf(26n, PENDING), viewOf(30n, PENDING)];
    let attempts = 0;
    const { vault, listCalls } = recordingVault({
      listProposals: listingFrom(() => rows),
      approve: async () => {
        attempts += 1;
        return { err: { NotAuthorized: null } } as VaultResult<never>;
      },
    });
    const root = await mount(vault);
    const walksBefore = listCalls.length;
    (q(root, "operator-approve-input-26") as HTMLInputElement).value = COMMITMENT_HEX;
    (q(root, "operator-approve-26") as HTMLButtonElement).click();
    await settle();

    // A refusal changed nothing, so the row is still Pending and the result
    // renders beneath the approve control that caused it.
    const result = q(root, "operator-local-result-approve-26")!;
    expect(result.textContent).toBe(
      "The Vault refused the call. Nothing was created or changed. Err = NotAuthorized",
    );
    expect(result.closest(".proposal")).toBe(q(root, "operator-commitment-26")!.closest(".proposal"));
    // SSA C-8: EXPLICIT adjacency — the result is the immediate next sibling of
    // the row holding the approve control that sent it. Sharing the card is not
    // enough: moving the node elsewhere on the same card must fail here.
    expect(q(root, "operator-approve-26")!.closest(".row")!.nextElementSibling).toBe(result);
    expect(attempts).toBe(1); // one attempted update; never retried
    expect(listCalls).toHaveLength(walksBefore); // no re-walk after a refusal
    expect(visibleIds(root)).toEqual([30n, 26n]);
    expect(q(root, "operator-local-result-approve-30")).toBeNull();
    expect(q(root, "operator-local-result-propose-create")).toBeNull();
  });

  it("C-8 a TRANSPORT failure reports the exact '(no result)' text and the uncertainty wording", async () => {
    const rows = [viewOf(26n, PENDING), viewOf(30n, PENDING)];
    let attempts = 0;
    const { vault, listCalls } = recordingVault({
      listProposals: listingFrom(() => rows),
      approve: async () => {
        attempts += 1;
        throw new Error("transport blew up");
      },
    });
    const root = await mount(vault);
    const walksBefore = listCalls.length;
    (q(root, "operator-approve-input-26") as HTMLInputElement).value = COMMITMENT_HEX;
    (q(root, "operator-approve-26") as HTMLButtonElement).click();
    await settle();

    const result = q(root, "operator-local-result-approve-26")!;
    expect(result.textContent).toBe(
      "The call did not return a result. It may or may not have reached the Vault — RELOAD the " +
        "proposal list and check before sending anything again. Nothing is retried automatically. " +
        "(no result) transport blew up",
    );
    expect(result.closest(".proposal")).toBe(q(root, "operator-commitment-26")!.closest(".proposal"));
    expect(q(root, "operator-approve-26")!.closest(".row")!.nextElementSibling).toBe(result);
    expect(attempts).toBe(1);
    expect(listCalls).toHaveLength(walksBefore);
    expect(visibleIds(root)).toEqual([30n, 26n]);
    expect(q(root, "operator-local-result-approve-30")).toBeNull();
  });

  /**
   * SSA C-8 false-causality regression. A transport failure leaves the operator
   * with NO idea whether the call reached the Vault. If a manual reload then
   * shows the row Executed, the page must keep the uncertain result beside that
   * row and say only what the status IS. Asserting that THIS call executed the
   * proposal would be an unsupported causal claim — the execution may have come
   * from another signer entirely.
   */
  it("C-8 transport failure → manual reload → terminal row: the uncertain result is retained with NO causal claim", async () => {
    const rows = [viewOf(26n, PENDING), viewOf(30n, PENDING)];
    let attempts = 0;
    const { vault } = recordingVault({
      listProposals: listingFrom(() => rows),
      approve: async () => {
        attempts += 1;
        throw new Error("transport blew up");
      },
    });
    const root = await mount(vault);
    (q(root, "operator-approve-input-26") as HTMLInputElement).value = COMMITMENT_HEX;
    (q(root, "operator-approve-26") as HTMLButtonElement).click();
    await settle();
    expect(visibleIds(root)).toEqual([30n, 26n]); // still Pending: nothing observed yet

    // Someone else's approval executes it; the operator reloads by hand.
    rows[0] = { ...rows[0], outcome: EXECUTED };
    (q(root, "operator-reload") as HTMLButtonElement).click();
    await settle();

    expect(completedIds(root)).toEqual([26n]);
    const { anchor, result } = retained(root, "26");
    expect(anchor).not.toBeNull();
    expect(result!.getAttribute("data-testid")).toBe("operator-local-result-approve-26");
    // The uncertainty wording survives VERBATIM…
    expect(result!.textContent).toBe(
      "The call did not return a result. It may or may not have reached the Vault — RELOAD the " +
        "proposal list and check before sending anything again. Nothing is retried automatically. " +
        "(no result) transport blew up",
    );
    // …and the anchor is neutral: what was sent, and the status as observed now.
    expect(anchor!.textContent).toBe(
      "Result of the approve call you sent for #26. Current proposal status: Executed.",
    );
    expect(anchor!.textContent).not.toContain("moved this proposal");
    expect(anchor!.textContent).not.toContain("That call is what");
    // Still ONE attempted update, and never attributed to an unrelated row/form.
    expect(attempts).toBe(1);
    expect(q(root, "operator-retained-result-anchor-30")).toBeNull();
    expect(q(root, "operator-local-result-approve-30")).toBeNull();
    for (const other of ["propose-create", "propose-InstallCode", "propose-settings"]) {
      expect(q(root, `operator-local-result-${other}`)).toBeNull();
    }
  });

  /** The same false-causality shape from a TYPED REFUSAL: this call provably
   *  changed nothing, so the later Executed status cannot be attributed to it. */
  it("C-8 typed refusal → manual reload → terminal row: the Err is retained with NO causal claim", async () => {
    const rows = [viewOf(26n, PENDING), viewOf(30n, PENDING)];
    let attempts = 0;
    const { vault } = recordingVault({
      listProposals: listingFrom(() => rows),
      approve: async () => {
        attempts += 1;
        return { err: { NotAuthorized: null } } as VaultResult<never>;
      },
    });
    const root = await mount(vault);
    (q(root, "operator-approve-input-26") as HTMLInputElement).value = COMMITMENT_HEX;
    (q(root, "operator-approve-26") as HTMLButtonElement).click();
    await settle();

    rows[0] = { ...rows[0], outcome: EXECUTED };
    (q(root, "operator-reload") as HTMLButtonElement).click();
    await settle();

    expect(completedIds(root)).toEqual([26n]);
    const { anchor, result } = retained(root, "26");
    expect(result!.textContent).toBe(
      "The Vault refused the call. Nothing was created or changed. Err = NotAuthorized",
    );
    expect(anchor!.textContent).toBe(
      "Result of the approve call you sent for #26. Current proposal status: Executed.",
    );
    expect(anchor!.textContent).not.toContain("moved this proposal");
    expect(attempts).toBe(1);
    expect(q(root, "operator-retained-result-anchor-30")).toBeNull();
    for (const other of ["propose-create", "propose-InstallCode", "propose-settings"]) {
      expect(q(root, `operator-local-result-${other}`)).toBeNull();
    }
  });
});
