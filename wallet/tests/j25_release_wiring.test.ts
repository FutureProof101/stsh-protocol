/**
 * J-25 D-5 / D-6 — the PRODUCTION wiring of the wallet release panel.
 *
 * SSA addendum D and AMBER-4: a component supplied convenient props can pass
 * while the real page renders a constant or never mounts it. These tests drive
 * `mountApp` — the function `main.ts` calls — and assert on what lands in the
 * container. Deleting the `mountReleaseFooter(...)` call from `app.ts`, or
 * replacing the panel's source with a constant, fails here.
 *
 * They also bind two things a unit test cannot: that `defaultAppDeps()` (the
 * production dependency set) actually supplies the anonymous reader, and that
 * the fresh per-spend deployment validation in `spendFlow.ts` still runs on its
 * own path regardless of the display query (addendum E).
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";

import { defaultAppDeps, mountApp, type AppDeps } from "../src/ui/app";
import { REPO_ROOT, RELEASE_RECORD_PATH } from "../src/release/loadRecord";
import { selectBuildSourceSha } from "../src/release/record";
import type { PoolIdentityReader } from "../src/release/poolIdentity";
import { resetProverAssetVerification } from "../src/release/proverVerification";
import { spendManifest } from "../src/zk/artifacts";
import { memoryJournalStore } from "./helpers/memoryJournalStore";

const RECORDED_SOURCE = selectBuildSourceSha(readFileSync(RELEASE_RECORD_PATH, "utf8"));
const PRODUCTION_ORIGIN = "https://app.stsh.fi";
const MANIFEST_VK = spendManifest.vkHash;

function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const emptyToken = {
  balanceOf: async () => 0n,
  metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
  fee: async () => 0n,
};

function deps(reader?: PoolIdentityReader | null, counters = { readerBuilt: 0 }): AppDeps {
  return {
    origin: PRODUCTION_ORIGIN,
    loadLaunchOrigin: async () => PRODUCTION_ORIGIN,
    buildReadActors: async () =>
      ({
        token: emptyToken,
        staking: { getStakePositions: async () => [], getPendingRewards: async () => 0n },
        vesting: { getSchedule: async () => null, claimableAmount: async () => 0n },
      }) as never,
    buildMutationActors: async () => ({}) as never,
    createJournalStore: async () => memoryJournalStore(),
    createAuth: async () => ({
      restore: async () => null,
      login: async () => {
        throw new Error("not scripted");
      },
      logout: async () => {},
      verify: () => "valid" as const,
    }),
    buildPoolIdentityReader:
      reader === undefined
        ? undefined
        : async () => {
            counters.readerBuilt += 1;
            return reader;
          },
  } as AppDeps;
}

function container(): HTMLElement {
  const node = document.createElement("div");
  document.body.append(node);
  return node;
}

function panelRows(root: HTMLElement): Map<string, string> {
  const panel = root.querySelector('[data-release-panel="wallet"]');
  if (panel === null) throw new Error("the wallet shell mounted NO release panel");
  const out = new Map<string, string>();
  for (const li of Array.from(panel.querySelectorAll("li"))) {
    out.set(li.getAttribute("data-release-row") ?? "", li.textContent ?? "");
  }
  return out;
}

const agreeingReader: PoolIdentityReader = {
  getCircuitVersion: async () => spendManifest.circuitVersion,
  getPinnedVkHash: async () => hexBytes(MANIFEST_VK),
};

beforeEach(() => {
  window.location.hash = "";
  resetProverAssetVerification();
});

describe("J-25 D-5 — the shell mounts the release panel", () => {
  it("mounts exactly ONE panel, with all five rows", async () => {
    const root = container();
    await mountApp(root, {}, deps(null));
    expect(root.querySelectorAll('[data-release-panel="wallet"]')).toHaveLength(1);
    expect([...panelRows(root).keys()]).toEqual([
      "Canister build source",
      "Circuit version",
      "Verifying-key hash",
      "Prover-asset verification",
      "Attestation schema",
    ]);
  });

  // THE BUILD-INJECTION TEST ON THE PRODUCTION PATH. The rendered value is the
  // record's, read here independently from the file rather than from anything
  // the wallet emitted.
  it("renders the RECORD's build source, and calls it the canister build source", async () => {
    const root = container();
    await mountApp(root, {}, deps(null));
    const text = panelRows(root).get("Canister build source") ?? "";
    expect(text).toContain(RECORDED_SOURCE);
    expect(text).toContain("committed release record");
    expect(text).toContain("this is the canister build source, not the UI commit");
    expect(text).not.toMatch(/signed/i);
  });

  it("boots OFFLINE (no reader) showing manifest-declared values, never a match", async () => {
    const root = container();
    await mountApp(root, {}, deps(null));
    const rows = panelRows(root);
    expect(rows.get("Circuit version")).toContain(String(spendManifest.circuitVersion));
    expect(rows.get("Circuit version")).toContain("unverified against pool");
    expect(rows.get("Verifying-key hash")).toContain(MANIFEST_VK);
    expect(rows.get("Verifying-key hash")).not.toMatch(/agrees/);
    expect(rows.get("Prover-asset verification")).toContain("not yet verified this session");
  });

  it("repaints to 'agrees with pool' once the anonymous observation settles", async () => {
    const root = container();
    await mountApp(root, {}, deps(agreeingReader));
    // Let the observation's promise chain flush.
    await new Promise((r) => setTimeout(r, 0));
    const rows = panelRows(root);
    expect(rows.get("Circuit version")).toContain("agrees with pool");
    expect(rows.get("Verifying-key hash")).toContain("agrees with pool");
  });

  it("shows BOTH values on a disagreement, through the production path", async () => {
    const root = container();
    const disagreeing: PoolIdentityReader = {
      getCircuitVersion: async () => spendManifest.circuitVersion + 1,
      getPinnedVkHash: async () => new Uint8Array(32).fill(0xab),
    };
    await mountApp(root, {}, deps(disagreeing));
    await new Promise((r) => setTimeout(r, 0));
    const rows = panelRows(root);
    expect(rows.get("Circuit version")).toContain("DISAGREES");
    expect(rows.get("Circuit version")).toContain(String(spendManifest.circuitVersion));
    expect(rows.get("Circuit version")).toContain(String(spendManifest.circuitVersion + 1));
    expect(rows.get("Verifying-key hash")).toContain(MANIFEST_VK);
    expect(rows.get("Verifying-key hash")).toContain("ab".repeat(32));
  });

  it("a rejected query renders 'unverified against pool', not an error page", async () => {
    const root = container();
    const failing: PoolIdentityReader = {
      getCircuitVersion: async () => {
        throw new Error("Canister rejected the call");
      },
      getPinnedVkHash: async () => hexBytes(MANIFEST_VK),
    };
    await mountApp(root, {}, deps(failing));
    await new Promise((r) => setTimeout(r, 0));
    expect(panelRows(root).get("Circuit version")).toContain("unverified against pool");
  });

  // D-6 on the production path: the panel is mounted once and the observation
  // is made once, however many times the app rerenders afterwards.
  it("mounting makes ONE reader build and ONE pair of queries", async () => {
    const counters = { readerBuilt: 0 };
    let versionCalls = 0;
    const counting: PoolIdentityReader = {
      getCircuitVersion: async () => {
        versionCalls += 1;
        return spendManifest.circuitVersion;
      },
      getPinnedVkHash: async () => hexBytes(MANIFEST_VK),
    };
    const root = container();
    const ctx = await mountApp(root, {}, deps(counting, counters));
    await new Promise((r) => setTimeout(r, 0));
    ctx.refresh();
    ctx.refresh();
    ctx.navigate("staking");
    await new Promise((r) => setTimeout(r, 0));
    expect(counters.readerBuilt).toBe(1);
    expect(versionCalls).toBe(1);
    expect(root.querySelectorAll('[data-release-panel="wallet"]')).toHaveLength(1);
  });
});

describe("J-25 D-5 — the production dependency set really supplies the reader", () => {
  it("defaultAppDeps() carries buildPoolIdentityReader", () => {
    // Without this, `mountApp` would take the harness branch in production and
    // the panel would permanently read "no pool configured".
    expect(typeof defaultAppDeps().buildPoolIdentityReader).toBe("function");
  });

  it("the anonymous reader is built over the READ agent, never a mutation one", () => {
    const src = readFileSync(resolve(REPO_ROOT, "wallet/src/ui/app.ts"), "utf8");
    const wiring = /buildPoolIdentityReader:[\s\S]{0,400}?createReadAgent\(config\)/.exec(src);
    expect(wiring, "buildPoolIdentityReader must use createReadAgent").not.toBeNull();
    expect(wiring?.[0]).not.toMatch(/createMutationAgent|identity/);
  });

  it("the identity read actor exposes NO update method", () => {
    const src = readFileSync(resolve(REPO_ROOT, "wallet/src/actors/pool.ts"), "utf8");
    const block = src.slice(src.indexOf("export function createPoolIdentityReadActor"));
    expect(block).toContain("get_circuit_version");
    expect(block).toContain("get_pinned_vk_hash");
    for (const update of ["shield_deposit", "private_spend", "withdraw", "retry_deposit_commitment"]) {
      expect(block, `${update} must not be reachable from the display actor`).not.toContain(update);
    }
  });
});

describe("J-25 I3 — the display path does not weaken the fail-closed controls", () => {
  it("spendFlow still runs its own fresh deployment validation", () => {
    const src = readFileSync(resolve(REPO_ROOT, "wallet/src/ui/spendFlow.ts"), "utf8");
    expect(src).toContain("assertManifestAttestation");
    // Nothing in the spend path may consult the presentation cache.
    expect(src).not.toContain("PoolIdentityCache");
    expect(src).not.toContain("proverAssetVerificationAt");
  });

  it("the verification event is recorded only AFTER both artifacts hash-match", () => {
    const src = readFileSync(resolve(REPO_ROOT, "wallet/src/zk/artifacts.ts"), "utf8");
    const zkeyAt = src.indexOf("const zkeyUrl = await loadVerifiedArtifact(zkey, signal);");
    const recordAt = src.indexOf("recordProverAssetVerification()");
    expect(zkeyAt).toBeGreaterThan(0);
    expect(recordAt).toBeGreaterThan(zkeyAt);
    // and it is NOT recorded at import or at function entry.
    expect(src.split("recordProverAssetVerification()")).toHaveLength(2);
  });
});
