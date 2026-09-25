/**
 * UPG-ROT-UI — the Upgrader membership-rotation surface on `#/operator`.
 *
 * WHAT THESE ARMS ARE FOR, one line each. The lane's whole risk is a green
 * suite that proves a helper and not the page, so every negative below is
 * driven through the PRODUCTION submission path — `renderOperator` -> the
 * button's own `onclick` -> the injected `UpgraderCanister` — with a
 * call-counting double attached to that path. "It showed an error" and "it sent
 * nothing" are different claims and both are asserted, on the spy, every time.
 *
 *  - MEMBERSHIP GATE (SSA C-3): the controls are gated on the UPGRADER's
 *    `get_recovery_membership`, INDEPENDENTLY of the Vault signer set. A
 *    recovery-only member gets them; a Vault-only signer does not; unloaded,
 *    null and thrown reads all fail closed. The anti-vacuous half is asserted
 *    too — a gate that hides everything from everyone passes the first half.
 *  - PROPOSE (AC-1): exactly three principals, count confirmation, duplicates,
 *    anonymous, malformed — each refusal with its own reason and ZERO wire
 *    calls; the positive control sends exactly one call through the same seam.
 *  - VIEW (AC-2): every `RotationProposalView` field renders, `new_members` in
 *    full and in order, `expires_at_ns` read from the canister (SSA C-5).
 *  - APPROVE (AC-3): the binding is byte-for-byte against the STORED hash; the
 *    bytes SENT are the view's. Wrong-length, same-length-unequal and a
 *    malformed stored commitment all refuse without touching the wire.
 *  - ROTATION-ONLY (SSA C-3): approval exists only on a FETCHED rotation view.
 *    A null lookup leaves nothing approvable.
 *  - EXPIRY (SSA C-5): the server's `ProposalExpired` is rendered distinctly,
 *    with both timestamps, through the real seam — and nothing is retried.
 *  - ACTOR SURFACE (AC-4): exactly the five J-17b reads plus the three named
 *    methods, and the anonymous replicated allowlist is untouched.
 *
 * No arm asserts a literal II principal: an II principal is a function of the
 * origin and of the identity, and pinning one here would bind the suite to a
 * fact the test cannot legitimately know.
 */

import { Principal } from "@dfinity/principal";
import { describe, expect, it } from "vitest";

import type {
  RecoveryError,
  RotationProposalView,
} from "../../src/declarations/upgrader/upgrader.did";
import { REPLICATED_METHODS } from "../src/actors/replicated";
import type { UpgraderCanister, UpgraderResult } from "../src/actors/upgrader";
import { wrapUpgraderActor } from "../src/actors/upgrader";
import type { VaultCanister, VaultResult } from "../src/actors/vault";
import {
  bindApproval,
  buildRotationRoster,
  bytesToHex,
  describeRecoveryError,
  describeRotationExpiry,
  rotationApprovePreview,
  rotationCandidPreview,
  ROTATION_ROSTER_SIZE,
} from "../src/operator/proposals";
import committedPins from "../src/generated/releasePins.json";
import type { WasmPins } from "../src/release/wasmPins";
import { evaluateSessionPolicy, resolveConfig, type WalletConfig } from "../src/session/config";
import { renderOperator, type OperatorDeps } from "../src/ui/pages/operator";
import type { AppContext } from "../src/ui/context";

const PINS = committedPins as WasmPins;
const PRODUCTION_ORIGIN = "https://app.stsh.fi";

/** Three distinct, valid, non-anonymous principals. Values are not load-bearing. */
const M1 = Principal.fromText("aaaaa-aa");
const M2 = Principal.fromText("rrkah-fqaaa-aaaaa-aaaaq-cai");
const M3 = Principal.fromText("ryjl3-tyaaa-aaaaa-aaaba-cai");
const M4 = Principal.fromText("r7inp-6aaaa-aaaaa-aaabq-cai");
const OUTSIDER = Principal.fromText("renrk-eyaaa-aaaaa-aaada-cai");
const ANON = Principal.anonymous();

const COMMITMENT = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const COMMITMENT_HEX = bytesToHex(COMMITMENT);

// ── Harness ─────────────────────────────────────────────────────────────────

interface Call {
  method: string;
  args: unknown[];
}

/**
 * A counting Upgrader double, attached to the page's real actor seam.
 *
 * Every method records itself, so "zero update calls" is a statement about the
 * spy and not about a rendered message. `getRecoveryMembership` is a function
 * so an arm can make it throw.
 */
function spyUpgrader(
  overrides: Partial<UpgraderCanister> = {},
): { upgrader: UpgraderCanister; calls: Call[] } {
  const calls: Call[] = [];
  const record = (method: string, ...args: unknown[]) => calls.push({ method, args });
  const upgrader: UpgraderCanister = {
    async getControllerInvariantProof() {
      record("get_controller_invariant_proof");
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
      record("get_recovery_summary");
      return { threshold: 2, member_count: 3 };
    },
    async getBuildInfo() {
      record("get_build_info");
      return "test";
    },
    async getRecoveryMembership() {
      record("get_recovery_membership");
      return [M1, M2, M3];
    },
    async getAuditEvents() {
      record("get_upgrader_audit_events");
      return null;
    },
    async proposeMembershipRotation(members) {
      record("propose_membership_rotation", members);
      return { ok: 42n };
    },
    async approveRecovery(id, hash) {
      record("approve_recovery", id, hash);
      return { ok: null };
    },
    async getRotationProposal(id) {
      record("get_rotation_proposal", id);
      return rotationView();
    },
    ...overrides,
  };
  return { upgrader, calls };
}

/** Updates only — the "zero wire calls" assertions are about these two. */
function updateCalls(calls: Call[]): Call[] {
  return calls.filter(
    (c) => c.method === "propose_membership_rotation" || c.method === "approve_recovery",
  );
}

/** A minimal Vault double. The rotation plane must not depend on it. */
function spyVault(signers: Principal[] | null): { vault: VaultCanister; calls: Call[] } {
  const calls: Call[] = [];
  const vault: VaultCanister = {
    async propose(kind) {
      calls.push({ method: "propose", args: [kind] });
      return { ok: 7n } as VaultResult<bigint>;
    },
    async approve(id, hash) {
      calls.push({ method: "approve", args: [id, hash] });
      return { ok: { Approved: { approvals: 1, threshold: 2 } } };
    },
    async cancelProposal() {
      return { ok: null };
    },
    async sweepExpiredProposals() {
      return { ok: [] };
    },
    async listProposals() {
      return [];
    },
    async getProposal() {
      return null;
    },
    async getSigners() {
      return signers;
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
  };
  return { vault, calls };
}

function rotationView(over: Partial<RotationProposalView> = {}): RotationProposalView {
  return {
    threshold: 2,
    commitment_hash: COMMITMENT,
    epoch: 0n,
    created_at_ns: 1_700_000_000_000_000_000n,
    new_members: [M2, M3, M4],
    proposal_id: 42n,
    proposer: M1,
    outcome: { Pending: null },
    expires_at_ns: [1_700_000_000_000_000_000n + 2_592_000_000_000_000n],
    approvals: [],
    ...over,
  };
}

function ctxFor(input: {
  principal?: Principal | null;
  vault?: VaultCanister;
  upgrader?: UpgraderCanister;
  operatorActorsNull?: boolean;
}): AppContext {
  const noop = async (): Promise<void> => undefined;
  const config: WalletConfig = { ...resolveConfig({}), launchOrigin: PRODUCTION_ORIGIN };
  const policy = evaluateSessionPolicy(config, PRODUCTION_ORIGIN);
  return {
    config,
    policy,
    state: {
      principal: input.principal === undefined ? M1 : input.principal,
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
    operatorActors:
      input.operatorActorsNull === true
        ? null
        : {
            vault: input.vault ?? spyVault([M1]).vault,
            upgrader: input.upgrader ?? spyUpgrader().upgrader,
          },
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

async function settle(): Promise<void> {
  for (let i = 0; i < 12; i += 1) await Promise.resolve();
}

/** Render the page and return the container. */
async function page(input: Parameters<typeof ctxFor>[0]): Promise<HTMLElement> {
  const container = document.createElement("main");
  renderOperator(container, ctxFor(input), deps());
  await settle();
  return container;
}

function q<T extends HTMLElement>(root: HTMLElement, testid: string): T | null {
  return root.querySelector<T>(`[data-testid="${testid}"]`);
}

/** Fill the propose form and click. Returns the container for assertions. */
async function propose(
  root: HTMLElement,
  membersText: string,
  countText: string,
): Promise<void> {
  q<HTMLTextAreaElement>(root, "operator-rotation-members")!.value = membersText;
  q<HTMLInputElement>(root, "operator-rotation-count")!.value = countText;
  q<HTMLButtonElement>(root, "operator-rotation-propose")!.click();
  await settle();
}

/** Load proposal `id`, then paste `typed` and click approve. */
async function loadAndApprove(root: HTMLElement, id: string, typed: string): Promise<void> {
  q<HTMLInputElement>(root, "operator-rotation-id")!.value = id;
  q<HTMLButtonElement>(root, "operator-rotation-load")!.click();
  await settle();
  const input = q<HTMLInputElement>(root, "operator-rotation-approve-input");
  if (input === null) return;
  input.value = typed;
  q<HTMLButtonElement>(root, "operator-rotation-approve")!.click();
  await settle();
}

const THREE = [M2, M3, M4].map((p) => p.toText()).join("\n");

// ── AC-4: the actor surface ─────────────────────────────────────────────────

describe("UPG-ROT-UI AC-4 — the wrapper adds exactly three methods", () => {
  it("exports the five J-17b reads plus proposeMembershipRotation/approveRecovery/getRotationProposal", () => {
    // A snapshot of Object.keys: a NEW method appearing here is a widened
    // recovery-plane surface and must fail this arm, not slip through.
    const raw = {} as never;
    expect(Object.keys(wrapUpgraderActor(raw)).sort()).toEqual([
      "approveRecovery",
      "getAuditEvents",
      "getBuildInfo",
      "getControllerInvariantProof",
      "getRecoveryMembership",
      "getRecoverySummary",
      "getRotationProposal",
      "proposeMembershipRotation",
    ]);
  });

  it("wraps NONE of the other recovery-plane updates", () => {
    const names = Object.keys(wrapUpgraderActor({} as never));
    for (const forbidden of [
      "proposeRecovery",
      "cancelRecoveryProposal",
      "sweepExpiredRecoveryProposals",
      "triggerVaultUpgrade",
      "reconcileVaultUpgrade",
      "refreshControllerInvariantNow",
      "getControllerInvariant",
      "getRecoveryProposal",
    ]) {
      expect(names).not.toContain(forbidden);
    }
  });

  it("leaves the anonymous replicated allowlist exactly as WALLET-AUTH G1 left it", () => {
    // I-2: the anonymous replicated actor is NOT extended by this lane. The
    // fixture file itself is byte-unchanged; this asserts the value it guards.
    expect(REPLICATED_METHODS).toEqual({
      merkle_tree: ["get_scan_head", "get_scan_page"],
      nullifier_registry: ["count", "get_nullifiers_page"],
      shielded_pool: [
        "get_accepted_root_head",
        "get_security_epoch",
        "get_deployment_attestation",
      ],
    });
    expect(Object.keys(REPLICATED_METHODS)).not.toContain("upgrader");
  });

  it("sends the RULED-DEFAULT lifetime as candid null, and forwards the stored bytes", async () => {
    // At the raw-candid boundary, which is where `[]` vs `[x]` is decidable.
    const seen: unknown[][] = [];
    const raw = {
      async propose_membership_rotation(members: Principal[], lifetime: [] | [bigint]) {
        seen.push([members, lifetime]);
        return { Ok: 42n };
      },
      async approve_recovery(id: bigint, hash: Uint8Array) {
        seen.push([id, hash]);
        return { Ok: null };
      },
      async get_rotation_proposal() {
        return [] as [];
      },
    } as never;
    const actor = wrapUpgraderActor(raw);
    expect(await actor.proposeMembershipRotation([M2, M3, M4])).toEqual({ ok: 42n });
    expect(seen[0]).toEqual([[M2, M3, M4], []]);
    expect(await actor.approveRecovery(42n, COMMITMENT)).toEqual({ ok: null });
    expect(seen[1]).toEqual([42n, COMMITMENT]);
    // `opt` -> null, which is what "no rotation proposal with that id" means.
    expect(await actor.getRotationProposal(9n)).toBeNull();
  });

  it("flattens Err rather than throwing it away", async () => {
    const raw = {
      async propose_membership_rotation() {
        return { Err: { ThresholdViolation: null } as RecoveryError };
      },
    } as never;
    const out = await wrapUpgraderActor(raw).proposeMembershipRotation([M2, M3, M4]);
    expect(out).toEqual({ err: { ThresholdViolation: null } });
  });
});

// ── SSA C-3: the membership gate, independent of the Vault ──────────────────

describe("UPG-ROT-UI membership gate (SSA C-3) — the UPGRADER's roster, not the Vault's", () => {
  it("SHOWS the controls to a recovery-only member who is NOT a Vault signer (anti-vacuous)", async () => {
    const { vault } = spyVault([OUTSIDER]); // M1 is NOT a Vault signer
    const root = await page({ vault });
    expect(q(root, "operator-rotation-not-member")).toBeNull();
    expect(q(root, "operator-rotation-propose")).not.toBeNull();
    expect(q(root, "operator-rotation-load")).not.toBeNull();
    // ...and the VAULT signing controls are correctly absent for that same user.
    expect(q(root, "operator-create-submit")).toBeNull();
    expect(q(root, "operator-signerset-submit")).toBeNull();
  });

  it("HIDES them from a Vault-only signer who is not a recovery member", async () => {
    const { vault } = spyVault([M1]);
    const { upgrader, calls } = spyUpgrader({
      async getRecoveryMembership() {
        return [M2, M3, M4]; // M1 removed
      },
    });
    const root = await page({ vault, upgrader });
    expect(q(root, "operator-rotation-not-member")!.textContent).toContain(
      "not in the Upgrader recovery membership",
    );
    expect(q(root, "operator-rotation-propose")).toBeNull();
    expect(q(root, "operator-rotation-approve")).toBeNull();
    // The Vault half is unaffected — the two gates are genuinely separate.
    expect(q(root, "operator-create-submit")).not.toBeNull();
    expect(updateCalls(calls)).toHaveLength(0);
  });

  it("fails CLOSED on the indistinguishable null membership answer", async () => {
    const { upgrader, calls } = spyUpgrader({
      async getRecoveryMembership() {
        return null;
      },
    });
    const root = await page({ upgrader });
    expect(q(root, "operator-rotation-not-member")!.textContent).toContain(
      "did not answer the recovery-membership query",
    );
    expect(q(root, "operator-rotation-propose")).toBeNull();
    expect(updateCalls(calls)).toHaveLength(0);
  });

  it("fails CLOSED when the membership read THROWS", async () => {
    const { upgrader, calls } = spyUpgrader({
      async getRecoveryMembership() {
        throw new Error("boom");
      },
    });
    const root = await page({ upgrader });
    expect(q(root, "operator-rotation-not-member")).not.toBeNull();
    expect(q(root, "operator-rotation-propose")).toBeNull();
    expect(root.querySelector('[data-testid="operator-notice"]')?.textContent).toContain(
      "Could not read the Upgrader recovery membership",
    );
    expect(updateCalls(calls)).toHaveLength(0);
  });

  it("AC-5 — an ended session: the SPECIFIC refusal, zero updates, and no read either", async () => {
    // SSA landed-diff C-4(a). The double is ATTACHED to this render, so "no
    // update was constructible" is a statement about a counter that the same
    // double proves can be incremented — the positive control below drives
    // the very same `upgrader` object through the very same seam and sees a
    // call. Without that pairing this arm would be an assertion about an
    // object nothing could ever have reached.
    const { upgrader, calls } = spyUpgrader();
    const root = await page({ principal: null, upgrader });

    // The specific refusal, not merely "some refusal rendered".
    expect(q(root, "operator-session-required")!.textContent).toBe(
      "Your Internet Identity session has ended or was never started. Log in to sign Vault actions.",
    );
    expect(q(root, "operator-rotation")).toBeNull();
    expect(q(root, "operator-rotation-propose")).toBeNull();
    expect(q(root, "operator-rotation-approve")).toBeNull();
    expect(q(root, "operator-rotation-approve-input")).toBeNull();
    expect(root.textContent).toContain("Log in");

    // Zero UPDATES, and zero calls of ANY kind: the page returns at Gate 2
    // before `refresh()`, so not even the membership query is issued.
    expect(updateCalls(calls)).toHaveLength(0);
    expect(calls).toHaveLength(0);

    // POSITIVE CONTROL, on the SAME double: a live session reaches it.
    const live = await page({ upgrader });
    expect(q(live, "operator-rotation-propose")).not.toBeNull();
    await propose(live, THREE, "3");
    expect(updateCalls(calls)).toHaveLength(1);
    expect(calls.some((c) => c.method === "get_recovery_membership")).toBe(true);
  });

  it("AC-5 — a session that dropped the operator actors is refused the same way", async () => {
    // Same shape: its own attached counting double, its own specific wording.
    const { upgrader, calls } = spyUpgrader();
    const root = await page({ operatorActorsNull: true, upgrader });
    expect(q(root, "operator-session-required")!.textContent).toBe(
      "The operator surface is unavailable for this session (the Vault/Upgrader canister ids are not configured).",
    );
    expect(q(root, "operator-rotation")).toBeNull();
    expect(q(root, "operator-rotation-propose")).toBeNull();
    expect(updateCalls(calls)).toHaveLength(0);
    expect(calls).toHaveLength(0);

    // POSITIVE CONTROL on the same double.
    const live = await page({ upgrader });
    await propose(live, THREE, "3");
    expect(updateCalls(calls)).toHaveLength(1);
  });
});

// ── AC-1: propose, through the page ─────────────────────────────────────────

describe("UPG-ROT-UI AC-1 — propose_membership_rotation", () => {
  it("POSITIVE CONTROL — sends exactly ONE call, with exactly the three principals entered", async () => {
    const { upgrader, calls } = spyUpgrader();
    const root = await page({ upgrader });
    await propose(root, THREE, "3");
    const sent = updateCalls(calls);
    expect(sent).toHaveLength(1);
    expect(sent[0].method).toBe("propose_membership_rotation");
    expect((sent[0].args[0] as Principal[]).map((p) => p.toText())).toEqual([
      M2.toText(),
      M3.toText(),
      M4.toText(),
    ]);
    // The exact Candid is shown BEFORE the call and the raw result after.
    expect(q(root, "operator-preview")!.textContent).toContain(`principal "${M2.toText()}";`);
    expect(q(root, "operator-preview")!.textContent).toContain("null,");
    expect(q(root, "operator-raw-result")!.textContent).toContain("proposal_id = 42");
  });

  const negatives: { name: string; members: string; count: string; reason: string }[] = [
    {
      name: "fewer than three",
      members: [M2, M3].map((p) => p.toText()).join("\n"),
      count: "3",
      reason: "roster of exactly 3 members; you entered 2",
    },
    {
      name: "more than three",
      members: [M1, M2, M3, M4].map((p) => p.toText()).join("\n"),
      count: "3",
      reason: "roster of exactly 3 members; you entered 4",
    },
    {
      name: "a duplicate",
      members: [M2, M3, M3].map((p) => p.toText()).join("\n"),
      count: "3",
      reason: "Duplicate principal in the list",
    },
    {
      name: "the anonymous principal",
      members: [M2, M3, ANON].map((p) => p.toText()).join("\n"),
      count: "3",
      reason: "anonymous principal (2vxsx-fae) cannot be a recovery member",
    },
    {
      name: "malformed text",
      members: `${M2.toText()}\nnot-a-principal\n${M4.toText()}`,
      count: "3",
      reason: "Not a valid principal",
    },
    {
      name: "an empty roster",
      members: "   \n  ",
      count: "3",
      reason: "At least one principal is required",
    },
    {
      name: "a count confirmation that does not match",
      members: THREE,
      count: "2",
      reason: 'Type the member count (3) to confirm',
    },
    {
      name: "an empty count confirmation",
      members: THREE,
      count: "",
      reason: "Type the member count (3) to confirm",
    },
  ];

  for (const n of negatives) {
    it(`REFUSES ${n.name} with its own reason, and sends NOTHING`, async () => {
      const { upgrader, calls } = spyUpgrader();
      const root = await page({ upgrader });
      await propose(root, n.members, n.count);
      expect(q(root, "operator-notice")!.textContent).toContain(n.reason);
      // The claim that matters, asserted on the spy and not on the message.
      expect(updateCalls(calls)).toHaveLength(0);
      expect(q(root, "operator-preview")).toBeNull();
    });
  }

  it("a transport failure is ONE attempt, reported with its OWN error text, and never retried", async () => {
    // SSA landed-diff C-4(b). The previous form asserted an EMPTY call log
    // after an override that never recorded — true by construction, and it
    // could not have failed. The override now RECORDS FIRST and throws
    // second, so the counter carries the real evidence: exactly one attempted
    // update reached the seam, and no second one followed it.
    const { upgrader, calls } = spyUpgrader({
      async proposeMembershipRotation(members) {
        calls.push({ method: "propose_membership_rotation", args: [members] });
        throw new Error("transport blew up");
      },
    });
    const root = await page({ upgrader });
    await propose(root, THREE, "3");

    const sent = updateCalls(calls);
    expect(sent).toHaveLength(1);
    expect((sent[0].args[0] as Principal[]).map((p) => p.toText())).toEqual([
      M2.toText(),
      M3.toText(),
      M4.toText(),
    ]);

    // The ACTUAL thrown text, surfaced verbatim — not merely the generic
    // unknown-outcome notice. An error swallowed into a house string would
    // fail here.
    expect(q(root, "operator-raw-result")!.textContent).toBe(
      "(no result) transport blew up",
    );
    expect(q(root, "operator-notice")!.textContent).toContain(
      "may or may not have reached the Upgrader",
    );
    expect(q(root, "operator-notice")!.textContent).toContain(
      "Nothing is retried automatically",
    );
  });

  it("renders a typed Err verbatim and creates nothing", async () => {
    const { upgrader } = spyUpgrader({
      async proposeMembershipRotation() {
        return { err: { ThresholdViolation: null } } as UpgraderResult<bigint>;
      },
    });
    const root = await page({ upgrader });
    await propose(root, THREE, "3");
    expect(q(root, "operator-raw-result")!.textContent).toContain("ThresholdViolation");
    expect(q(root, "operator-raw-result")!.textContent).toContain("MembershipRotationRejected");
    expect(q(root, "operator-notice")!.textContent).toContain("The Upgrader refused the call");
  });
});

// ── AC-2: the view ──────────────────────────────────────────────────────────

describe("UPG-ROT-UI AC-2 — the rotation view renders in full", () => {
  it("shows every field, and new_members IN ORDER rather than as a count", async () => {
    const root = await page({});
    q<HTMLInputElement>(root, "operator-rotation-id")!.value = "42";
    q<HTMLButtonElement>(root, "operator-rotation-load")!.click();
    await settle();
    const items = Array.from(
      root.querySelectorAll('[data-testid="operator-rotation-new-members"] li'),
    );
    expect(items.map((li) => li.textContent)).toEqual([M2.toText(), M3.toText(), M4.toText()]);
    const meta = q(root, "operator-rotation-meta")!.textContent ?? "";
    expect(meta).toContain(`proposer ${M1.toText()}`);
    expect(meta).toContain("epoch 0");
    expect(meta).toContain("threshold 2");
    expect(meta).toContain("approvals 0");
    expect(meta).toContain("created_at_ns 1700000000000000000");
    expect(root.textContent).toContain("rotation #42 — Pending");
    expect(q(root, "operator-rotation-commitment-42")!.textContent).toBe(COMMITMENT_HEX);
    expect(q(root, "operator-rotation-expiry")!.textContent).toContain("expires_at_ns = 17");
  });

  it("SSA C-5 — the expiry is READ from the canister, and `[]` is said in words", () => {
    const withExpiry = describeRotationExpiry(rotationView());
    expect(withExpiry).toContain("Read from the canister, not derived");
    expect(withExpiry).toContain("RULED DEFAULT, not 'no expiry'");
    expect(describeRotationExpiry(rotationView({ expires_at_ns: [] }))).toContain(
      "NO stored expiry",
    );
  });

  it("renders a terminal proposal WITHOUT an approval control", async () => {
    const { upgrader } = spyUpgrader({
      async getRotationProposal() {
        return rotationView({ outcome: { Executed: null } });
      },
    });
    const root = await page({ upgrader });
    q<HTMLInputElement>(root, "operator-rotation-id")!.value = "42";
    q<HTMLButtonElement>(root, "operator-rotation-load")!.click();
    await settle();
    expect(q(root, "operator-rotation-terminal")).not.toBeNull();
    expect(q(root, "operator-rotation-approve")).toBeNull();
  });
});

// ── AC-3 + SSA C-3: approve is reachable ONLY from a fetched view ───────────

describe("UPG-ROT-UI AC-3 — approve binds to the STORED commitment", () => {
  it("POSITIVE CONTROL — the exact hash sends ONE call carrying the STORED bytes", async () => {
    const { upgrader, calls } = spyUpgrader();
    const root = await page({ upgrader });
    await loadAndApprove(root, "42", COMMITMENT_HEX);
    const sent = updateCalls(calls);
    expect(sent).toHaveLength(1);
    expect(sent[0].method).toBe("approve_recovery");
    expect(sent[0].args[0]).toBe(42n);
    // The bytes are the VIEW's, byte for byte — never re-derived from the text.
    expect(bytesToHex(sent[0].args[1] as Uint8Array)).toBe(COMMITMENT_HEX);
    expect(q(root, "operator-preview")!.textContent).toContain("42 : nat64");
    expect(q(root, "operator-preview")!.textContent).toContain('blob "\\01\\02');
  });

  const refusals: { name: string; typed: string; reason: string }[] = [
    {
      name: "a one-nibble difference (same length, unequal)",
      typed: `${COMMITMENT_HEX.slice(0, 63)}${COMMITMENT_HEX[63] === "0" ? "1" : "0"}`,
      reason: "does not match this proposal's stored commitment hash",
    },
    {
      name: "a truncated prefix",
      typed: COMMITMENT_HEX.slice(0, 40),
      reason: "Paste the FULL 64-character commitment hash",
    },
    {
      name: "an over-long hash",
      typed: `${COMMITMENT_HEX}ab`,
      reason: "Paste the FULL 64-character commitment hash",
    },
    {
      name: "non-hex text",
      typed: "z".repeat(64),
      reason: "Paste the FULL 64-character commitment hash",
    },
    { name: "nothing at all", typed: "", reason: "Paste the FULL 64-character commitment hash" },
  ];

  for (const r of refusals) {
    it(`REFUSES ${r.name} and sends NOTHING`, async () => {
      const { upgrader, calls } = spyUpgrader();
      const root = await page({ upgrader });
      await loadAndApprove(root, "42", r.typed);
      expect(q(root, "operator-notice")!.textContent).toContain(r.reason);
      expect(updateCalls(calls)).toHaveLength(0);
    });
  }

  it("REFUSES a malformed STORED commitment before anything is sent", async () => {
    const { upgrader, calls } = spyUpgrader({
      async getRotationProposal() {
        return rotationView({ commitment_hash: COMMITMENT.slice(0, 31) });
      },
    });
    const root = await page({ upgrader });
    await loadAndApprove(root, "42", COMMITMENT_HEX);
    expect(q(root, "operator-notice")!.textContent).toContain(
      "stored commitment hash is 31 bytes, not 32",
    );
    expect(updateCalls(calls)).toHaveLength(0);
  });

  it("SSA C-3 — a null lookup leaves NOTHING approvable, and no arbitrary-hash form exists", async () => {
    const { upgrader, calls } = spyUpgrader({
      async getRotationProposal() {
        return null;
      },
    });
    const root = await page({ upgrader });
    q<HTMLInputElement>(root, "operator-rotation-id")!.value = "99";
    q<HTMLButtonElement>(root, "operator-rotation-load")!.click();
    await settle();
    expect(q(root, "operator-rotation-lookup-note")!.textContent).toContain(
      "no ROTATION proposal for id 99",
    );
    expect(q(root, "operator-rotation-approve")).toBeNull();
    expect(q(root, "operator-rotation-approve-input")).toBeNull();
    expect(updateCalls(calls)).toHaveLength(0);
  });

  it("a FAILED lookup fails closed the same way", async () => {
    const { upgrader, calls } = spyUpgrader({
      async getRotationProposal() {
        throw new Error("read blew up");
      },
    });
    const root = await page({ upgrader });
    q<HTMLInputElement>(root, "operator-rotation-id")!.value = "42";
    q<HTMLButtonElement>(root, "operator-rotation-load")!.click();
    await settle();
    expect(q(root, "operator-rotation-lookup-note")!.textContent).toContain(
      "Could not read the Upgrader",
    );
    expect(q(root, "operator-rotation-approve")).toBeNull();
    expect(updateCalls(calls)).toHaveLength(0);
  });

  it("a non-numeric id reads NOTHING", async () => {
    const { upgrader, calls } = spyUpgrader();
    const root = await page({ upgrader });
    q<HTMLInputElement>(root, "operator-rotation-id")!.value = "4 2";
    q<HTMLButtonElement>(root, "operator-rotation-load")!.click();
    await settle();
    expect(q(root, "operator-rotation-lookup-note")!.textContent).toContain("Not a proposal id");
    expect(calls.filter((c) => c.method === "get_rotation_proposal")).toHaveLength(0);
  });
});

// ── SSA C-5 + C-1: the server's own variants, through the real seam ─────────

describe("UPG-ROT-UI — server error variants render distinctly and change nothing", () => {
  it("ProposalExpired keeps BOTH timestamps and does not claim the proposal is gone", async () => {
    let attempts = 0;
    const { upgrader } = spyUpgrader({
      async approveRecovery() {
        attempts += 1;
        return {
          err: {
            ProposalExpired: { expires_at_ns: 111n, now_ns: 222n },
          },
        } as UpgraderResult<null>;
      },
    });
    const root = await page({ upgrader });
    await loadAndApprove(root, "42", COMMITMENT_HEX);
    const raw = q(root, "operator-raw-result")!.textContent ?? "";
    // SSA landed-diff C-4(c): the VARIANT NAME itself, through the page seam.
    // Timestamps alone do not distinguish ProposalExpired from any other
    // error that happens to carry two numbers.
    expect(raw).toContain("ProposalExpired");
    expect(raw.startsWith("Err = ProposalExpired:")).toBe(true);
    expect(raw).not.toContain("StaleEpoch");
    expect(raw).not.toContain("AlreadyTerminal");
    expect(raw).toContain("expires_at_ns = 111");
    expect(raw).toContain("now_ns = 222");
    expect(raw).toContain("NOTHING was mutated");
    expect(raw).toContain("did NOT free its capacity");
    // Exactly one attempt: no retry, automatic or otherwise.
    expect(attempts).toBe(1);
    // And no sweep/cancel control was added anywhere on this plane.
    expect(q(root, "operator-rotation-sweep")).toBeNull();
    expect(q(root, "operator-rotation-cancel")).toBeNull();
  });

  it("StaleEpoch carries both epochs — the evidence that a rotation executed", () => {
    const text = describeRecoveryError({ StaleEpoch: { proposal: 0n, current: 1n } });
    expect(text).toContain("proposal = 0");
    expect(text).toContain("current = 1");
    expect(text).toContain("a rotation has already executed");
  });

  it("NotAuthorized says why a REMOVED member sees it instead of StaleEpoch", () => {
    const text = describeRecoveryError({ NotAuthorized: null });
    expect(text).toContain("not a CURRENT recovery member");
    expect(text).toContain("precedes the epoch check");
  });

  it("distinguishes the two CommitmentMismatch limbs", () => {
    expect(
      describeRecoveryError({ CommitmentMismatch: { StoredVsRecomputed: null } as never }),
    ).toContain("Stop and escalate");
    expect(
      describeRecoveryError({ CommitmentMismatch: { CallerMismatch: null } as never }),
    ).toContain("Zero writes");
  });
});

// ── Pure halves, kept because they are cheap and name the rule ──────────────

describe("UPG-ROT-UI — roster + preview helpers", () => {
  it("ROTATION_ROSTER_SIZE is three and the preview shows the ruled-default lifetime", () => {
    expect(ROTATION_ROSTER_SIZE).toBe(3);
    const preview = rotationCandidPreview([M2, M3, M4]);
    expect(preview.split("\n")).toEqual([
      "(",
      "  vec {",
      `    principal "${M2.toText()}";`,
      `    principal "${M3.toText()}";`,
      `    principal "${M4.toText()}";`,
      "  },",
      "  null,",
      ")",
    ]);
  });

  it("buildRotationRoster tolerates commas and surrounding whitespace", () => {
    const out = buildRotationRoster(` ${M2.toText()}, ${M3.toText()} , ${M4.toText()} `, " 3 ");
    expect("ok" in out).toBe(true);
  });

  it("bindApproval is the SAME code for both planes (generalised, not copied)", () => {
    const bound = bindApproval(rotationView(), COMMITMENT_HEX);
    expect(bound.kind).toBe("bound");
    if (bound.kind === "bound") expect(bound.proposalId).toBe(42n);
  });

  it("the approve preview escapes the stored bytes as a candid blob", () => {
    expect(rotationApprovePreview(42n, COMMITMENT)).toBe(
      `(\n  42 : nat64,\n  blob "${COMMITMENT_HEX.replace(/../g, (h) => `\\${h}`)}",\n)`,
    );
  });
});
