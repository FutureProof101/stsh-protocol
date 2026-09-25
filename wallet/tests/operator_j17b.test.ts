/**
 * J-17b — the Vault operator page.
 *
 * What these arms are actually for, one line each, because a green suite that
 * checks the wrong thing is the failure mode this lane is most exposed to:
 *
 *  - SIGNER GATING: the signing controls are absent for a non-signer, and
 *    PRESENT for a signer (the anti-vacuous half — a gate that hides everything
 *    from everyone also passes a "hidden for non-signers" assertion).
 *  - APPROVE BINDING (CUST-SSA-001): a mismatched hash must NEVER reach the
 *    agent. Asserted on the agent spy, not on a rendered message: "it showed an
 *    error" and "it sent nothing" are different claims.
 *  - CANDID ENCODING: the four proposal shapes this page may build, compared
 *    against the generated candid types and the exact preview text.
 *  - ORIGIN: the hard block fires for the `*.icp0.io` asset alias and does NOT
 *    fire for the production origin. Both directions, since a block that fires
 *    everywhere would pass the first assertion alone.
 *  - SESSION REVOCATION: an operator action after the session ends is refused.
 *  - VETKEYS: the unpinned role is buildable ONLY behind the acknowledgement.
 *
 * No arm asserts a literal II principal: an II principal is a function of the
 * origin and of the identity, and pinning one here would bind the suite to a
 * fact the test cannot legitimately know.
 */

import { Principal } from "@dfinity/principal";
import { describe, expect, it } from "vitest";

import type {
  ActionView,
  ProposalView,
  VaultActionKind,
} from "../../src/declarations/vault/vault.did";
import type { VaultCanister, VaultResult } from "../src/actors/vault";
import type { UpgraderCanister } from "../src/actors/upgrader";
import {
  bindApproval,
  buildCreateCanister,
  buildInstallCode,
  buildUpdateSettings,
  buildUpgrade,
  buildUpdateSignerSet,
  bytesToHex,
  candidPreview,
  describeVaultError,
  inFlightRetainedBytes,
  PER_SIGNER_RETAINED_BYTES,
} from "../src/operator/proposals";
import committedPins from "../src/generated/releasePins.json";
import { pinForRole, ROLE_PACKAGE_ALIAS, UNPINNED_ROLES, type WasmPins } from "../src/release/wasmPins";
import { evaluateSessionPolicy, resolveConfig, type WalletConfig } from "../src/session/config";
import { parseRoute, routeHref } from "../src/ui/router";
import { renderOperator, type OperatorDeps } from "../src/ui/pages/operator";
import type { AppContext } from "../src/ui/context";

const PINS = committedPins as WasmPins;
const SIGNER = Principal.fromText("aaaaa-aa");
const PEER = Principal.fromText("2vxsx-fae");
const TARGET = Principal.fromText("rrkah-fqaaa-aaaaa-aaaaq-cai");
const PRODUCTION_ORIGIN = "https://app.stsh.fi";
const ASSET_ALIAS_ORIGIN = "https://s3tyu-aaaaa-aaaab-qhdjq-cai.icp0.io";

// ── Harness ─────────────────────────────────────────────────────────────────

/** A spy Vault: every call is recorded so "nothing was sent" is checkable. */
function spyVault(overrides: Partial<VaultCanister> = {}): {
  vault: VaultCanister;
  calls: { method: string; args: unknown[] }[];
} {
  const calls: { method: string; args: unknown[] }[] = [];
  const record = (method: string, ...args: unknown[]) => calls.push({ method, args });
  const vault: VaultCanister = {
    async propose(kind) {
      record("propose", kind);
      return { ok: 7n } as VaultResult<bigint>;
    },
    async approve(id, hash) {
      record("approve", id, hash);
      return { ok: { Approved: { approvals: 1, threshold: 2 } } };
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
  return { vault, calls };
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
  async getRecoveryMembership() {
    return null;
  },
  async getAuditEvents() {
    return null;
  },
  // UPG-ROT-UI (SSA C-6): the THREE newly required interface methods, as
  // stubs, so this fixture is a complete `UpgraderCanister` again. No arm in
  // this file exercises them — the rotation plane's arms live in
  // `operator_upgrader_rotation.test.ts`. `getRecoveryMembership` above still
  // returns `null`, so every J-17b arm runs with the rotation controls OFF and
  // the behaviour this file asserts is unchanged.
  async proposeMembershipRotation() {
    throw new Error("J-17b fixture: propose_membership_rotation is not exercised here");
  },
  async approveRecovery() {
    throw new Error("J-17b fixture: approve_recovery is not exercised here");
  },
  async getRotationProposal() {
    return null;
  },
};

function ctxFor(input: {
  origin?: string;
  principal?: Principal | null;
  vault?: VaultCanister;
  operatorActorsNull?: boolean;
}): AppContext {
  const noop = async (): Promise<void> => undefined;
  const config: WalletConfig = { ...resolveConfig({}), launchOrigin: PRODUCTION_ORIGIN };
  const policy = evaluateSessionPolicy(config, input.origin ?? PRODUCTION_ORIGIN);
  return {
    config,
    policy,
    state: {
      principal: input.principal === undefined ? SIGNER : input.principal,
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
        : { vault: input.vault ?? spyVault().vault, upgrader },
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

function deps(pins: WasmPins = PINS): OperatorDeps {
  return { pins, sha256Hex: async () => "0".repeat(64), nowMs: () => 1_700_000_000_000 };
}

/** Let the page's one refresh() microtask chain settle before asserting. */
async function settle(): Promise<void> {
  for (let i = 0; i < 8; i += 1) await Promise.resolve();
}

function pendingView(action: ActionView, commitment: Uint8Array): ProposalView {
  return {
    result: [],
    action,
    commitment_hash: commitment,
    epoch: 1n,
    created_at_ns: 1_700_000_000_000_000_000n,
    proposal_id: 7n,
    proposer: PEER,
    outcome: { Pending: null },
    snapshot_id: [],
    approvals: [],
  };
}

const COMMITMENT = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const COMMITMENT_HEX = bytesToHex(COMMITMENT);

// ── Routing ─────────────────────────────────────────────────────────────────

describe("J-17b routing", () => {
  it("resolves #/operator without putting it in the nav", () => {
    expect(parseRoute("#/operator")).toBe("operator");
    expect(routeHref("operator")).toBe("#/operator");
  });

  it("is reach-only: an unknown segment still falls back to the default route", () => {
    expect(parseRoute("#/operators")).toBe("account");
  });
});

// ── Origin (SSA F-06) ───────────────────────────────────────────────────────

describe("J-17b origin hard block (WT-1: the canister origin is now PERMITTED)", () => {
  // SUPERSEDED ASSERTION, kept visible. SSA F-06 blocked the `*.icp0.io` alias
  // because an II login there derived DIFFERENT principals from the pinned ones,
  // so an operator who wandered onto it would sign as an unauthorized caller.
  // WT-1 removes the premise rather than the check: principals are now rooted at
  // that very canister origin, so it is the CANONICAL place to sign, not a trap.
  // `app.stsh.fi` remains permitted as an alias, vouched for by the certified
  // alternative-origins asset. A third origin is still blocked — asserted below.
  it("PERMITS the asset canister's *.icp0.io alias — it is the derivation root", () => {
    const config: WalletConfig = { ...resolveConfig({}), launchOrigin: PRODUCTION_ORIGIN };
    const policy = evaluateSessionPolicy(config, ASSET_ALIAS_ORIGIN);
    expect(policy.kind).toBe("production");
  });

  it("does NOT block the production wallet origin", () => {
    const config: WalletConfig = { ...resolveConfig({}), launchOrigin: PRODUCTION_ORIGIN };
    expect(evaluateSessionPolicy(config, PRODUCTION_ORIGIN).kind).toBe("production");
  });

  it("still BLOCKS a third origin — the guard narrowed, it did not disappear", () => {
    const config: WalletConfig = { ...resolveConfig({}), launchOrigin: PRODUCTION_ORIGIN };
    for (const rogue of [
      "https://s3tyu-aaaaa-aaaab-qhdjq-cai.icp0.io.evil.example",
      "https://staging.stsh.fi",
      "https://app.stsh.fi.evil.example",
    ]) {
      expect(evaluateSessionPolicy(config, rogue).kind).toBe("blocked");
    }
  });

  it("renders the block — not a banner — on the operator route, and calls nothing", async () => {
    // WT-1: the blocked origin is now a THIRD origin, not the canister alias.
    // The behaviour under test — a hard block with no signing surface and no
    // canister traffic at all — is unchanged; only the origin that triggers it
    // moved, because the alias is now legitimate.
    const { vault, calls } = spyVault();
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ origin: "https://staging.stsh.fi", vault }), deps());
    await settle();
    expect(container.querySelector('[data-testid="operator-blocked"]')).not.toBeNull();
    // No signing surface at all, and nothing was read or sent.
    expect(container.querySelector('[data-testid="operator-signer-list"]')).toBeNull();
    expect(calls).toHaveLength(0);
  });
});

// ── Session revocation ──────────────────────────────────────────────────────

describe("J-17b session revocation", () => {
  it("refuses when the principal is gone", async () => {
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ principal: null }), deps());
    await settle();
    expect(container.querySelector('[data-testid="operator-session-required"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="operator-create-submit"]')).toBeNull();
  });

  it("refuses when the session dropped the operator actors, even with a principal", async () => {
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ operatorActorsNull: true }), deps());
    await settle();
    expect(container.querySelector('[data-testid="operator-session-required"]')).not.toBeNull();
  });
});

// ── Signer gating ───────────────────────────────────────────────────────────

describe("J-17b signer gating", () => {
  it("hides the signing controls when the principal is not a signer", async () => {
    const { vault } = spyVault({ getSigners: async () => [PEER] });
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ vault }), deps());
    await settle();
    expect(container.querySelector('[data-testid="operator-not-signer"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="operator-create-submit"]')).toBeNull();
    expect(container.querySelector('[data-testid="operator-signerset-submit"]')).toBeNull();
  });

  it("hides them on the indistinguishable unauthorized None", async () => {
    const { vault } = spyVault({ getSigners: async () => null });
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ vault }), deps());
    await settle();
    expect(container.querySelector('[data-testid="operator-not-signer"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="operator-create-submit"]')).toBeNull();
  });

  it("SHOWS them for a signer (anti-vacuous)", async () => {
    const { vault } = spyVault();
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ vault }), deps());
    await settle();
    expect(container.querySelector('[data-testid="operator-create-submit"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="operator-InstallCode-submit"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="operator-settings-submit"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="operator-signerset-submit"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="operator-sweep"]')).not.toBeNull();
  });

  it("always shows this principal, so the Owner can copy it into the re-pin", async () => {
    const container = document.createElement("main");
    renderOperator(container, ctxFor({}), deps());
    await settle();
    const shown = container.querySelector('[data-testid="operator-principal"]')?.textContent;
    // The VALUE is not pinned — an II principal is a function of the origin.
    expect(shown).toBe(SIGNER.toText());
  });
});

// ── Approve binding (CUST-SSA-001) ──────────────────────────────────────────

describe("J-17b approve binds to the stored commitment hash", () => {
  const view = pendingView({ Application: "noop" }, COMMITMENT);

  it("accepts the exact full hash", () => {
    const bound = bindApproval(view, COMMITMENT_HEX);
    expect(bound.kind).toBe("bound");
    if (bound.kind === "bound") {
      expect(bytesToHex(bound.commitmentHash)).toBe(COMMITMENT_HEX);
      expect(bound.proposalId).toBe(7n);
    }
  });

  it("tolerates surrounding whitespace and case, which is transcription, not a different hash", () => {
    expect(bindApproval(view, `  ${COMMITMENT_HEX.toUpperCase()}\n`).kind).toBe("bound");
  });

  it("REFUSES a one-nibble difference", () => {
    const off = `${COMMITMENT_HEX.slice(0, 63)}${COMMITMENT_HEX[63] === "0" ? "1" : "0"}`;
    expect(bindApproval(view, off).kind).toBe("refused");
  });

  it("REFUSES a correct PREFIX — a prefix match is not a comparison", () => {
    expect(bindApproval(view, COMMITMENT_HEX.slice(0, 32)).kind).toBe("refused");
  });

  it("REFUSES an empty or non-hex value", () => {
    expect(bindApproval(view, "").kind).toBe("refused");
    expect(bindApproval(view, "0x" + COMMITMENT_HEX).kind).toBe("refused");
  });

  it("a mismatched hash NEVER reaches the agent", async () => {
    const { vault, calls } = spyVault({ listProposals: async () => [view] });
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ vault }), deps());
    await settle();
    const input = container.querySelector<HTMLInputElement>('[data-testid="operator-approve-input-7"]');
    const button = container.querySelector<HTMLButtonElement>('[data-testid="operator-approve-7"]');
    expect(input).not.toBeNull();
    expect(button).not.toBeNull();
    // A well-formed 64-hex hash that is simply the WRONG one — so this arm
    // exercises the mismatch branch, not the "that is not a hash at all" branch.
    input!.value = "de".repeat(32);
    button!.click();
    await settle();
    expect(calls.filter((c) => c.method === "approve")).toHaveLength(0);
    expect(
      container.querySelector('[data-testid="operator-approve-refused-7"]')?.textContent,
    ).toContain("does not match");
  });

  it("the matching hash DOES reach the agent, with the VIEW's bytes", async () => {
    const { vault, calls } = spyVault({ listProposals: async () => [view] });
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ vault }), deps());
    await settle();
    const input = container.querySelector<HTMLInputElement>('[data-testid="operator-approve-input-7"]');
    input!.value = COMMITMENT_HEX;
    container.querySelector<HTMLButtonElement>('[data-testid="operator-approve-7"]')!.click();
    await settle();
    const approve = calls.filter((c) => c.method === "approve");
    expect(approve).toHaveLength(1);
    expect(approve[0].args[0]).toBe(7n);
    expect(bytesToHex(approve[0].args[1] as Uint8Array)).toBe(COMMITMENT_HEX);
  });
});

// ── Pin comparison on an InstallCode view (SSA F-02) ─────────────────────────

describe("J-17b shows expected_wasm_hash against the pin before approval", () => {
  function installView(hash: string): ProposalView {
    const bytes = Uint8Array.from(
      hash.match(/../g)!.map((h) => Number.parseInt(h, 16)),
    );
    return pendingView(
      {
        Management: {
          InstallCode: {
            expected_wasm_hash: bytes,
            wasm_bytes_len: 1000n,
            bytes_retained: true,
            expected_arg_hash: new Uint8Array(32),
            arg_bytes_len: 4n,
            target: TARGET,
          },
        },
      },
      COMMITMENT,
    );
  }

  it("marks a pinned build as matching", async () => {
    const { vault } = spyVault({ listProposals: async () => [installView(PINS.shielded_pool)] });
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ vault }), deps());
    await settle();
    const mark = container.querySelector('[data-testid="operator-pin-match-7"]');
    expect(mark?.textContent).toContain("MATCHES");
    expect(mark?.className).not.toBe("error");
  });

  it("marks an unpinned build as NOT matching", async () => {
    const { vault } = spyVault({ listProposals: async () => [installView("ab".repeat(32))] });
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ vault }), deps());
    await settle();
    const mark = container.querySelector('[data-testid="operator-pin-match-7"]');
    expect(mark?.textContent).toContain("does NOT match");
    expect(mark?.className).toBe("error");
  });
});

// ── Candid encoding ─────────────────────────────────────────────────────────

describe("WALLET-V12 AC-1 — Management.Upgrade against the HARDEN-04 pins (Vault #29 pool / #30 vesting)", () => {
  // Literals from the HARDEN-04 record, not read back from the pins under test.
  const HARDEN04 = {
    shielded_pool: "dca03f68fbf3ddf4c1bb1c4c36689d9a3dcf124fb5aab2bff50d88cca51afd69",
    vesting: "8b9c58600198ed83d426430b55cdac38f61a612773628a82f778c95622225a2e",
  } as const;
  const ARG = "ab".repeat(32);

  for (const role of ["shielded_pool", "vesting"] as const) {
    it(`${role}: the Upgrade proposal is built with expected_wasm_hash = the HARDEN-04 pin, under the COMMITTED pins`, () => {
      const wasm = new Uint8Array([0, 97, 115, 109]);
      const built = buildUpgrade({
        target: TARGET,
        role,
        typedWasmHash: HARDEN04[role],
        localWasmHash: HARDEN04[role],
        wasmBytes: wasm,
        argHash: ARG,
        argBytes: new Uint8Array([1]),
        pins: PINS, // the committed releasePins.json — what the page defaults to
        unpinnedRoleAcknowledged: false,
      });
      expect("ok" in built, JSON.stringify(built)).toBe(true);
      if (!("ok" in built)) return;
      const body = (built.ok as { Management: { Upgrade: Record<string, unknown> } }).Management.Upgrade;
      expect(body.target).toBe(TARGET);
      expect(bytesToHex(body.expected_wasm_hash as Uint8Array)).toBe(HARDEN04[role]);
      expect(bytesToHex(body.expected_arg_hash as Uint8Array)).toBe(ARG);
      expect(body.wasm_bytes).toBe(wasm);
      expect(candidPreview(built.ok, { wasmSha256: HARDEN04[role] })).toContain("Upgrade = record {");
    });

    it(`${role}: a final-v11-era (pre-HARDEN-04) artifact is REFUSED — not the reviewed build`, () => {
      const stale = role === "shielded_pool"
        ? "5fa7176e15548db1740fa184842db279b10f5621e1d9400a641caccc82910dc5"
        : "760488eb60d9b23bd3b612b122fb183ea5f9c1525208709e580956cf1ee59b27";
      const built = buildUpgrade({
        target: TARGET,
        role,
        typedWasmHash: stale,
        localWasmHash: stale,
        wasmBytes: new Uint8Array([1]),
        argHash: ARG,
        argBytes: new Uint8Array([1]),
        pins: PINS,
        unpinnedRoleAcknowledged: false,
      });
      expect(built).toEqual({ refused: expect.stringContaining("does not equal the pinned") });
    });
  }
});

describe("J-17b Candid encoding", () => {
  it("CreateCanister encodes purpose + BornUnderVault, for each of the nine roles", () => {
    for (const role of Object.keys(ROLE_PACKAGE_ALIAS)) {
      const built = buildCreateCanister(role);
      expect("ok" in built).toBe(true);
      if (!("ok" in built)) continue;
      const kind: VaultActionKind = built.ok;
      expect(kind).toEqual({
        Management: { CreateCanister: { manifest_purpose: role, disposition: { BornUnderVault: null } } },
      });
      const preview = candidPreview(kind);
      expect(preview).toContain(`manifest_purpose = "${role}";`);
      expect(preview).toContain("disposition = variant { BornUnderVault };");
      // The lifetime argument is ALWAYS null (SSA F-04) and always visible.
      expect(preview.trimEnd().endsWith("null,\n)")).toBe(true);
    }
  });

  it("refuses a role that is not a BORN_UNDER_VAULT role", () => {
    expect(buildCreateCanister("staking")).toEqual({
      refused: expect.stringContaining("not a BORN_UNDER_VAULT role"),
    });
  });

  it("InstallCode encodes the target, both hashes and the bytes", () => {
    const wasm = new Uint8Array([1, 2, 3]);
    const built = buildInstallCode({
      target: TARGET,
      role: "shielded_pool",
      typedWasmHash: PINS.shielded_pool,
      localWasmHash: PINS.shielded_pool,
      wasmBytes: wasm,
      argHash: "0".repeat(64),
      argBytes: new Uint8Array([9]),
      pins: PINS,
      unpinnedRoleAcknowledged: false,
    });
    expect("ok" in built).toBe(true);
    if (!("ok" in built)) return;
    const body = (built.ok as { Management: { InstallCode: Record<string, unknown> } }).Management
      .InstallCode;
    expect(body.target).toBe(TARGET);
    expect(bytesToHex(body.expected_wasm_hash as Uint8Array)).toBe(PINS.shielded_pool);
    expect(bytesToHex(body.expected_arg_hash as Uint8Array)).toBe("0".repeat(64));
    expect(body.wasm_bytes).toBe(wasm);
    const preview = candidPreview(built.ok, { wasmSha256: PINS.shielded_pool });
    expect(preview).toContain("InstallCode = record {");
    expect(preview).toContain(`target = principal "${TARGET.toText()}";`);
  });

  it("InstallCode REFUSES when the local hash differs from the typed hash", () => {
    const built = buildInstallCode({
      target: TARGET,
      role: "shielded_pool",
      typedWasmHash: PINS.shielded_pool,
      localWasmHash: "ab".repeat(32),
      wasmBytes: new Uint8Array([1]),
      argHash: "0".repeat(64),
      argBytes: new Uint8Array(),
      pins: PINS,
      unpinnedRoleAcknowledged: false,
    });
    expect(built).toEqual({ refused: expect.stringContaining("does not equal the hash you typed") });
  });

  it("InstallCode REFUSES when the file matches the typed hash but not the PIN", () => {
    const rogue = "ab".repeat(32);
    const built = buildInstallCode({
      target: TARGET,
      role: "shielded_pool",
      typedWasmHash: rogue,
      localWasmHash: rogue,
      wasmBytes: new Uint8Array([1]),
      argHash: "0".repeat(64),
      argBytes: new Uint8Array(),
      pins: PINS,
      unpinnedRoleAcknowledged: false,
    });
    expect(built).toEqual({ refused: expect.stringContaining("not the reviewed artifact") });
  });

  it("UpdateSettings encodes the controller set in full", () => {
    const built = buildUpdateSettings({ target: TARGET, controllers: [SIGNER, PEER] });
    expect("ok" in built).toBe(true);
    if (!("ok" in built)) return;
    expect(built.ok).toEqual({
      Management: { UpdateSettings: { target: TARGET, controllers: [SIGNER, PEER] } },
    });
    const preview = candidPreview(built.ok);
    expect(preview).toContain("UpdateSettings = record {");
    expect(preview).toContain(`principal "${SIGNER.toText()}";`);
    expect(preview).toContain(`principal "${PEER.toText()}";`);
  });

  it("UpdateSettings REFUSES an empty controller set", () => {
    expect(buildUpdateSettings({ target: TARGET, controllers: [] })).toEqual({
      refused: expect.stringContaining("no controller at all"),
    });
  });

  it("UpdateSignerSet is a TOP-LEVEL variant, not a Management one (SSA F-05)", () => {
    const built = buildUpdateSignerSet({ signers: [SIGNER, PEER], threshold: 2 });
    expect("ok" in built).toBe(true);
    if (!("ok" in built)) return;
    expect(built.ok).toEqual({ UpdateSignerSet: { signers: [SIGNER, PEER], threshold: 2 } });
    expect(Object.keys(built.ok)).toEqual(["UpdateSignerSet"]);
    const preview = candidPreview(built.ok);
    expect(preview).toContain("UpdateSignerSet = record {");
    expect(preview).toContain("threshold = 2 : nat32;");
  });

  it("UpdateSignerSet REFUSES an unmeetable threshold", () => {
    expect(buildUpdateSignerSet({ signers: [SIGNER], threshold: 2 })).toEqual({
      refused: expect.stringContaining("cannot be met"),
    });
  });
});

// ── vetkeys: the unpinned role needs the acknowledgement (SSA G-02/H-01) ────

describe("J-17b vetkeys unpinned-role path", () => {
  const base = {
    target: TARGET,
    role: "vetkeys",
    typedWasmHash: "cd".repeat(32),
    localWasmHash: "cd".repeat(32),
    wasmBytes: new Uint8Array([1, 2]),
    argHash: "0".repeat(64),
    argBytes: new Uint8Array(),
    pins: PINS,
  };

  it("the record really does carry no vetkeys pin", () => {
    expect(PINS.vetkeys).toBeUndefined();
    expect(UNPINNED_ROLES).toContain("vetkeys");
    expect(pinForRole("vetkeys", PINS)).toEqual({ kind: "unpinned-by-ruling", pkg: "vetkeys" });
  });

  it("REFUSES without the acknowledgement", () => {
    expect(buildInstallCode({ ...base, unpinnedRoleAcknowledged: false })).toEqual({
      refused: expect.stringContaining("unpinned-role acknowledgement"),
    });
  });

  it("builds WITH the acknowledgement", () => {
    const built = buildInstallCode({ ...base, unpinnedRoleAcknowledged: true });
    expect("ok" in built).toBe(true);
  });

  it("the acknowledgement does NOT unlock a pinned role's mismatch", () => {
    // The escape hatch is scoped to roles that have no pin. A ticked checkbox
    // must not become a general "skip the pin check" control.
    const built = buildInstallCode({
      ...base,
      role: "shielded_pool",
      unpinnedRoleAcknowledged: true,
    });
    expect(built).toEqual({ refused: expect.stringContaining("not the reviewed artifact") });
  });
});

// ── Quota + typed errors (SSA G-05) ─────────────────────────────────────────

describe("J-17b in-flight quota and typed errors", () => {
  it("counts only MY retained code-bearing proposals", () => {
    const mine = (retained: boolean, proposer: Principal): ProposalView => ({
      ...pendingView(
        {
          Management: {
            InstallCode: {
              expected_wasm_hash: new Uint8Array(32),
              wasm_bytes_len: 1000n,
              bytes_retained: retained,
              expected_arg_hash: new Uint8Array(32),
              arg_bytes_len: 24n,
              target: TARGET,
            },
          },
        },
        COMMITMENT,
      ),
      proposer,
    });
    expect(inFlightRetainedBytes([mine(true, SIGNER)], SIGNER)).toBe(1024n);
    expect(inFlightRetainedBytes([mine(false, SIGNER)], SIGNER)).toBe(0n);
    expect(inFlightRetainedBytes([mine(true, PEER)], SIGNER)).toBe(0n);
    expect(PER_SIGNER_RETAINED_BYTES).toBe(2 * 1024 * 1024);
  });

  it("renders SizeLimitExceeded VERBATIM, with both numbers", () => {
    const text = describeVaultError({
      SizeLimitExceeded: { encoded_bytes: 2_100_000n, limit_bytes: 2_097_152n },
    });
    expect(text).toContain("encoded_bytes = 2100000");
    expect(text).toContain("limit_bytes = 2097152");
  });

  it("renders ProposalExpired with its zero-mutation meaning", () => {
    const text = describeVaultError({ ProposalExpired: { expires_at_ns: 1n, now_ns: 2n } });
    expect(text).toContain("NOTHING was mutated");
  });
});

// ── No caching / no auto-retry ──────────────────────────────────────────────

describe("J-17b call discipline", () => {
  it("does not retry a failed update", async () => {
    let attempts = 0;
    const { vault, calls } = spyVault({
      listProposals: async () => [],
      propose: async () => {
        attempts += 1;
        throw new Error("transport blew up");
      },
    });
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ vault }), deps());
    await settle();
    container.querySelector<HTMLButtonElement>('[data-testid="operator-create-submit"]')!.click();
    await settle();
    expect(attempts).toBe(1);
    expect(calls.filter((c) => c.method === "propose")).toHaveLength(0);
    expect(container.querySelector('[data-testid="operator-notice"]')?.textContent).toContain(
      "may or may not have reached the Vault",
    );
  });

  it("shows the exact Candid BEFORE the call and the raw result after", async () => {
    const { vault } = spyVault({ listProposals: async () => [] });
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ vault }), deps());
    await settle();
    container.querySelector<HTMLButtonElement>('[data-testid="operator-create-submit"]')!.click();
    await settle();
    const preview = container.querySelector('[data-testid="operator-preview"]')?.textContent ?? "";
    expect(preview).toContain("CreateCanister = record {");
    expect(preview).toContain("null,");
    expect(container.querySelector('[data-testid="operator-raw-result"]')?.textContent).toContain(
      "proposal_id = 7",
    );
  });

  it("re-reads the proposal list from the canister rather than caching it", async () => {
    let reads = 0;
    const { vault } = spyVault({
      listProposals: async () => {
        reads += 1;
        return [];
      },
    });
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ vault }), deps());
    await settle();
    const before = reads;
    container.querySelector<HTMLButtonElement>('[data-testid="operator-reload"]')!.click();
    await settle();
    expect(reads).toBeGreaterThan(before);
  });

  it("sends 12 to the bounded sweep (SSA G-07)", async () => {
    const { vault, calls } = spyVault({ listProposals: async () => [] });
    const container = document.createElement("main");
    renderOperator(container, ctxFor({ vault }), deps());
    await settle();
    container.querySelector<HTMLButtonElement>('[data-testid="operator-sweep"]')!.click();
    await settle();
    expect(calls.filter((c) => c.method === "sweep_expired_proposals")[0]?.args[0]).toBe(12);
  });
});
