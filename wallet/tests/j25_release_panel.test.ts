/**
 * J-25 D-3 / D-6 — the wallet release panel's trust states and its ONE
 * anonymous session-cached observation.
 *
 * D-3 asserts the RENDERED source, value and status text for every state the
 * source matrix names: agreement, disagreement on the circuit version only, on
 * the VK hash only, on both, a rejected query, an absent configuration, a
 * malformed/partial result, and offline startup.
 * D-6 asserts the query discipline of addendum E: concurrent renders share one
 * request, a configuration change invalidates, and an obsolete late response is
 * discarded.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  PoolIdentityCache,
  poolIdentityKey,
  toHex,
  type PoolIdentityObservation,
  type PoolIdentityReader,
} from "../src/release/poolIdentity";
import {
  proverAssetVerificationAt,
  recordProverAssetVerification,
  resetProverAssetVerification,
} from "../src/release/proverVerification";
import { mountReleaseFooter } from "../src/ui/releaseFooter";
import { REPO_ROOT } from "../src/release/loadRecord";
import { buildWalletReleaseRows, type ReleaseRow } from "../src/release/walletPanel";
import { renderReleaseRows } from "../src/ui/releaseFooter";

// The VK hash the shipped wallet spend manifest carries, transcribed
// independently (never read back from spendManifest.json — that would make the
// agreement assertion a tautology). MOVED at lane A-3 FINALIZE (2026-09-12):
// the re-encode regenerated the dev chain, so the manifest pin moved and this
// fixture's "pool agrees with manifest" arm moved with it. NOT synthetic,
// despite the A-3 brief's follow-up (b) classification — see the packet.
const MANIFEST_VK = "84dba3059c1fb15080cd2d1c5b9a1eefbfea7f3b0321e1297d83ad56acbc6914";
const OTHER_VK = "0011223344556677889900112233445566778899001122334455667788990011";
const BUILD_SOURCE = "5ae6b0ff5708aec4492a210f6d78805678404151";

function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function rows(observation: PoolIdentityObservation | null, proverAt: number | null = null): ReleaseRow[] {
  return buildWalletReleaseRows({
    buildSource: BUILD_SOURCE,
    manifest: { circuitVersion: 3, vkHash: MANIFEST_VK },
    observation,
    proverVerifiedAtMs: proverAt,
    formatTime: () => "2026-09-08 12:00:00Z",
  });
}

function row(rs: ReleaseRow[], label: string): ReleaseRow {
  const r = rs.find((x) => x.label === label);
  if (!r) throw new Error(`no row labelled ${label}`);
  return r;
}

/** Render into a real DOM node and read back what the user would see. */
function rendered(rs: ReleaseRow[]): Map<string, { text: string; cls: string }> {
  const panel = document.createElement("footer");
  renderReleaseRows(panel, rs);
  const out = new Map<string, { text: string; cls: string }>();
  for (const li of Array.from(panel.querySelectorAll("li"))) {
    out.set(li.getAttribute("data-release-row") ?? "", {
      text: li.textContent ?? "",
      cls: li.className,
    });
  }
  return out;
}

const ok = (circuitVersion: number, vkHex: string): PoolIdentityObservation => ({
  kind: "ok",
  circuitVersion,
  vkHash: vkHex,
});

describe("J-25 D-3 — build source row", () => {
  it("names the committed release record and says it is the CANISTER build source", () => {
    const r = row(rows(null), "Canister build source");
    expect(r.value).toBe(BUILD_SOURCE);
    expect(r.source).toBe("committed release record");
    expect(r.trust).toBe(
      "from the committed release record; this is the canister build source, not the UI commit",
    );
  });

  it("never says 'signed' anywhere in the panel, in any state", () => {
    for (const o of [
      null,
      { kind: "unconfigured" } as const,
      { kind: "failed", detail: "rejected" } as const,
      ok(3, MANIFEST_VK),
      ok(9, OTHER_VK),
    ]) {
      expect(JSON.stringify(rows(o, 1_757_000_000_000))).not.toMatch(/signed/i);
    }
  });

  it("shows the row as unavailable — never blank — when no value was injected", () => {
    const r = row(
      buildWalletReleaseRows({
        buildSource: null,
        manifest: { circuitVersion: 3, vkHash: MANIFEST_VK },
        observation: null,
        proverVerifiedAtMs: null,
      }),
      "Canister build source",
    );
    expect(r.value).toBeNull();
    expect(r.state).toBe("unavailable");
    expect(r.trust).toBe("not available from this build");
  });
});

describe("J-25 D-3 — circuit version and VK hash agree/disagree INDEPENDENTLY", () => {
  it("both agree", () => {
    const rs = rows(ok(3, MANIFEST_VK));
    expect(row(rs, "Circuit version").trust).toBe("manifest-declared — agrees with pool");
    expect(row(rs, "Verifying-key hash").trust).toBe("manifest-declared — agrees with pool");
    expect(row(rs, "Circuit version").state).toBe("agrees");
  });

  it("circuit version disagrees, VK hash agrees", () => {
    const rs = rows(ok(4, MANIFEST_VK));
    expect(row(rs, "Circuit version").trust).toBe("DISAGREES: manifest 3, pool 4");
    expect(row(rs, "Circuit version").poolValue).toBe("4");
    expect(row(rs, "Verifying-key hash").state).toBe("agrees");
  });

  it("VK hash disagrees, circuit version agrees", () => {
    const rs = rows(ok(3, OTHER_VK));
    expect(row(rs, "Verifying-key hash").trust).toBe(
      `DISAGREES: manifest ${MANIFEST_VK}, pool ${OTHER_VK}`,
    );
    expect(row(rs, "Circuit version").state).toBe("agrees");
  });

  it("both disagree, and BOTH values are shown for each", () => {
    const rs = rows(ok(4, OTHER_VK));
    const view = rendered(rs);
    expect(view.get("Circuit version")?.text).toContain("3");
    expect(view.get("Circuit version")?.text).toContain("4");
    expect(view.get("Verifying-key hash")?.text).toContain(MANIFEST_VK);
    expect(view.get("Verifying-key hash")?.text).toContain(OTHER_VK);
    expect(view.get("Verifying-key hash")?.cls).toContain("release-disagrees");
  });

  it("the FULL 64-hex VK hash is shown, monospace, never truncated", () => {
    const r = row(rows(ok(3, MANIFEST_VK)), "Verifying-key hash");
    expect(r.value).toBe(MANIFEST_VK);
    expect(r.value).toHaveLength(64);
    expect(r.monospace).toBe(true);
    const panel = document.createElement("footer");
    renderReleaseRows(panel, rows(ok(3, MANIFEST_VK)));
    const value = panel.querySelector('[data-release-row="Verifying-key hash"] .release-value');
    expect(value?.textContent).toBe(MANIFEST_VK);
    expect(value?.className).toContain("mono");
  });
});

describe("J-25 D-3 — every unverified state says so, and never claims a match", () => {
  const cases: Array<[string, PoolIdentityObservation | null, RegExp]> = [
    ["offline startup / query in flight", null, /unverified against pool \(query in progress\)/],
    ["absent configuration", { kind: "unconfigured" }, /unverified against pool \(no pool configured\)/],
    [
      "rejected query",
      { kind: "failed", detail: "Canister rejected the call" },
      /unverified against pool \(Canister rejected the call\)/,
    ],
    [
      "malformed partial result",
      { kind: "failed", detail: "pool returned a malformed verifying-key hash" },
      /unverified against pool \(pool returned a malformed verifying-key hash\)/,
    ],
  ];

  for (const [name, observation, expected] of cases) {
    it(`${name}: both manifest rows read manifest-declared + unverified`, () => {
      const rs = rows(observation);
      for (const label of ["Circuit version", "Verifying-key hash"]) {
        const r = row(rs, label);
        expect(r.source).toBe("wallet spend manifest");
        expect(r.state).toBe("unverified");
        expect(r.trust).toMatch(/^manifest-declared — /);
        expect(r.trust).toMatch(expected);
        // The value is still shown — it is a declared value, not a claim.
        expect(r.value).not.toBeNull();
      }
      const view = rendered(rs);
      expect(view.get("Circuit version")?.text).not.toMatch(/agrees/);
    });
  }
});

describe("J-25 D-3 — prover-asset verification is an EVENT, never an import", () => {
  beforeEach(() => resetProverAssetVerification());

  it("says not yet verified when nothing was verified this session", () => {
    expect(proverAssetVerificationAt()).toBeNull();
    const r = row(rows(ok(3, MANIFEST_VK)), "Prover-asset verification");
    expect(r.trust).toBe("not yet verified this session");
    expect(r.state).toBe("unverified");
  });

  it("says verified — with the time — only after an event was recorded", () => {
    recordProverAssetVerification(1_757_000_000_000);
    expect(proverAssetVerificationAt()).toBe(1_757_000_000_000);
    const r = row(rows(ok(3, MANIFEST_VK), 1_757_000_000_000), "Prover-asset verification");
    expect(r.trust).toBe("verified this session at 2026-09-08 12:00:00Z");
  });
});

describe("J-25 D-3 — the attestation-schema row is PRESENT and explicitly n/a", () => {
  it("is rendered, with no value and the n/a wording", () => {
    const r = row(rows(ok(3, MANIFEST_VK)), "Attestation schema");
    expect(r.value).toBeNull();
    expect(r.trust).toBe("not available from this source");
    expect(rendered(rows(ok(3, MANIFEST_VK))).has("Attestation schema")).toBe(true);
  });

  it("the panel always renders exactly the five rows of the source matrix", () => {
    expect(rows(null).map((r) => r.label)).toEqual([
      "Canister build source",
      "Circuit version",
      "Verifying-key hash",
      "Prover-asset verification",
      "Attestation schema",
    ]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// D-6 — query discipline (addendum E)
// ─────────────────────────────────────────────────────────────────────────────

interface Scripted {
  reader: PoolIdentityReader;
  calls: number;
  release: () => void;
}

function scriptedReader(circuitVersion = 3, vkHex = MANIFEST_VK): Scripted {
  let releaseFn: () => void = () => {};
  const gate = new Promise<void>((res) => {
    releaseFn = res;
  });
  const s: Scripted = {
    calls: 0,
    release: () => releaseFn(),
    reader: {
      async getCircuitVersion() {
        s.calls += 1;
        await gate;
        return circuitVersion;
      },
      async getPinnedVkHash() {
        await gate;
        return hexBytes(vkHex);
      },
    },
  };
  return s;
}

const KEY_A = poolIdentityKey({ poolCanisterId: "aaaaa-aa", host: "https://icp-api.io" });
const KEY_B = poolIdentityKey({ poolCanisterId: "bbbbb-bb", host: "https://icp-api.io" });

describe("J-25 D-6 — one shared observation per session and configuration", () => {
  it("concurrent renders share ONE request", async () => {
    const s = scriptedReader();
    const cache = new PoolIdentityCache();
    const all = [cache.observe(KEY_A, s.reader), cache.observe(KEY_A, s.reader), cache.observe(KEY_A, s.reader)];
    s.release();
    const results = await Promise.all(all);
    expect(s.calls).toBe(1);
    for (const r of results) expect(r).toEqual(ok(3, MANIFEST_VK));
  });

  it("a settled result is reused — a rerender makes NO new request", async () => {
    const s = scriptedReader();
    const cache = new PoolIdentityCache();
    s.release();
    await cache.observe(KEY_A, s.reader);
    await cache.observe(KEY_A, s.reader);
    await cache.observe(KEY_A, s.reader);
    expect(s.calls).toBe(1);
    expect(cache.peek(KEY_A)).toEqual(ok(3, MANIFEST_VK));
  });

  it("a configuration change INVALIDATES the observation", async () => {
    const a = scriptedReader(3, MANIFEST_VK);
    const b = scriptedReader(9, OTHER_VK);
    const cache = new PoolIdentityCache();
    a.release();
    b.release();
    expect(await cache.observe(KEY_A, a.reader)).toEqual(ok(3, MANIFEST_VK));
    expect(cache.peek(KEY_A)).not.toBeNull();
    expect(await cache.observe(KEY_B, b.reader)).toEqual(ok(9, OTHER_VK));
    // The old key's cached value is gone, not merely shadowed.
    expect(cache.peek(KEY_A)).toBeNull();
    expect(a.calls).toBe(1);
    expect(b.calls).toBe(1);
  });

  it("an OBSOLETE late response never overwrites current state", async () => {
    const slowA = scriptedReader(3, MANIFEST_VK);
    const fastB = scriptedReader(9, OTHER_VK);
    const cache = new PoolIdentityCache();

    const pendingA = cache.observe(KEY_A, slowA.reader); // in flight, not released
    fastB.release();
    const b = await cache.observe(KEY_B, fastB.reader);
    expect(cache.peek(KEY_B)).toEqual(b);

    slowA.release();
    await pendingA; // resolves LATE, under the obsolete key
    expect(cache.peek(KEY_B), "the late A response overwrote B").toEqual(ok(9, OTHER_VK));
    expect(cache.peek(KEY_A)).toBeNull();
  });

  it("no reader (unconfigured) settles without any request", async () => {
    const cache = new PoolIdentityCache();
    expect(await cache.observe(KEY_A, null)).toEqual({ kind: "unconfigured" });
  });

  it("a rejected query becomes a FAILED observation, not a thrown error", async () => {
    const cache = new PoolIdentityCache();
    const reader: PoolIdentityReader = {
      getCircuitVersion: async () => {
        throw new Error("Canister rejected the call");
      },
      getPinnedVkHash: async () => hexBytes(MANIFEST_VK),
    };
    expect(await cache.observe(KEY_A, reader)).toEqual({
      kind: "failed",
      detail: "Canister rejected the call",
    });
  });

  it("a malformed or partial result is a FAILURE, never a value", async () => {
    const cache = new PoolIdentityCache();
    const bad: PoolIdentityReader = {
      getCircuitVersion: async () => 3,
      getPinnedVkHash: async () => new Uint8Array(31),
    };
    expect(await cache.observe(KEY_A, bad)).toEqual({
      kind: "failed",
      detail: "pool returned a malformed verifying-key hash",
    });

    const cache2 = new PoolIdentityCache();
    const bad2: PoolIdentityReader = {
      getCircuitVersion: async () => undefined as unknown as number,
      getPinnedVkHash: async () => hexBytes(MANIFEST_VK),
    };
    expect(await cache2.observe(KEY_A, bad2)).toEqual({
      kind: "failed",
      detail: "pool returned a malformed circuit version",
    });
  });

  it("toHex renders the full lowercase hash", () => {
    expect(toHex(hexBytes(MANIFEST_VK))).toBe(MANIFEST_VK);
  });
});


// ─────────────────────────────────────────────────────────────────────────────
// RED-1 (SSA landed-diff 2026-09-09) — the MOUNTED footer must repaint when the
// real verification event fires, after the pool observation has already
// settled. The event test above builds rows with a timestamp already supplied;
// the wiring test reads source order. Neither binds this live transition, and
// on the unfixed footer the row keeps saying "not yet verified this session"
// for the whole session because nothing notifies it.
// ─────────────────────────────────────────────────────────────────────────────

const MOUNT_CONFIG = { poolCanisterId: "aaaaa-aa", host: "https://icp-api.io" };

function proverRowText(footer: HTMLElement): string {
  const li = footer.querySelector('[data-release-row="Prover-asset verification"]');
  expect(li, "the prover-asset verification row must be rendered").not.toBeNull();
  return li?.textContent ?? "";
}

describe("J-25 RED-1 — a completed prover verification repaints the mounted footer", () => {
  beforeEach(() => resetProverAssetVerification());

  it("transitions from 'not yet verified' to the timestamped text after the observation settled", async () => {
    const s = scriptedReader(3, MANIFEST_VK);
    const cache = new PoolIdentityCache();
    const container = document.createElement("div");

    // The REAL production path: no `proverVerifiedAt` override, so the footer
    // reads and subscribes to the same module `withVerifiedProverAssets` calls.
    const handle = mountReleaseFooter(container, {
      config: MOUNT_CONFIG,
      reader: s.reader,
      cache,
      formatTime: (atMs) => `t=${atMs}`,
    });

    s.release();
    const observation = await handle.observed;
    expect(observation).toEqual(ok(3, MANIFEST_VK));
    // Paint 2 has happened; the pool rows agree and the prover row does not yet
    // claim anything.
    expect(proverRowText(handle.footer)).toContain("not yet verified this session");

    // The real recorder — the one artifacts.ts calls once both hashes match.
    recordProverAssetVerification(1_757_000_000_000);
    await Promise.resolve();

    const after = proverRowText(handle.footer);
    expect(after, "the stale 'not yet verified' text survived a real verification").not.toContain(
      "not yet verified this session",
    );
    expect(after).toContain("verified this session at t=1757000000000");

    // The repaint must not regress the settled pool rows back to "in progress".
    const vk = handle.footer.querySelector('[data-release-row="Verifying-key hash"]');
    expect(vk?.textContent).toContain("agrees with pool");
    expect(vk?.className).toContain("release-agrees");

    handle.dispose();
  });

  it("a disposed panel stops repainting — one mount's listener cannot paint another", async () => {
    const s = scriptedReader(3, MANIFEST_VK);
    const cache = new PoolIdentityCache();
    const container = document.createElement("div");
    const handle = mountReleaseFooter(container, { config: MOUNT_CONFIG, reader: s.reader, cache });
    s.release();
    await handle.observed;

    handle.dispose();
    recordProverAssetVerification(1_757_000_000_000);
    await Promise.resolve();
    expect(proverRowText(handle.footer)).toContain("not yet verified this session");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RED-2 — key equality is NOT identity. Both constructions below reuse key A,
// so `this.key === forKey` passes for the obsolete request and its stale value
// overwrites the newer settled one. Both fail on the pre-fix cache.
// ─────────────────────────────────────────────────────────────────────────────

describe("J-25 RED-2 — an obsolete response for a REUSED key is discarded", () => {
  it("a request that spanned reset() never overwrites the session that followed", async () => {
    const oldA = scriptedReader(3, MANIFEST_VK);
    const cache = new PoolIdentityCache();
    const pendingOldA = cache.observe(KEY_A, oldA.reader); // in flight

    cache.reset();

    const newA = scriptedReader(9, OTHER_VK);
    newA.release();
    expect(await cache.observe(KEY_A, newA.reader)).toEqual(ok(9, OTHER_VK));

    oldA.release();
    await pendingOldA; // resolves LATE, for the pre-reset generation
    expect(cache.peek(KEY_A), "the pre-reset A response overwrote the new one").toEqual(
      ok(9, OTHER_VK),
    );
  });

  it("after A -> B -> A the FIRST A's late response is discarded", async () => {
    const firstA = scriptedReader(3, MANIFEST_VK);
    const b = scriptedReader(5, OTHER_VK);
    const cache = new PoolIdentityCache();
    const pendingFirstA = cache.observe(KEY_A, firstA.reader); // in flight

    b.release();
    await cache.observe(KEY_B, b.reader);

    const secondA = scriptedReader(9, OTHER_VK);
    secondA.release();
    expect(await cache.observe(KEY_A, secondA.reader)).toEqual(ok(9, OTHER_VK));

    firstA.release();
    await pendingFirstA;
    expect(cache.peek(KEY_A), "the first A response overwrote the second").toEqual(
      ok(9, OTHER_VK),
    );
  });

  it("the generation advances on key change, on reset and on every new request", async () => {
    const cache = new PoolIdentityCache();
    const g0 = cache.generation();
    const a = scriptedReader();
    a.release();
    await cache.observe(KEY_A, a.reader);
    const g1 = cache.generation();
    expect(g1).toBeGreaterThan(g0);
    // A cache HIT starts no request, so it must not advance the generation:
    // that is what keeps concurrent renders sharing one observation.
    await cache.observe(KEY_A, a.reader);
    expect(cache.generation()).toBe(g1);
    cache.reset();
    expect(cache.generation()).toBeGreaterThan(g1);
  });

  it("the mounted footer does not paint an observation from an obsolete generation", async () => {
    const slowA = scriptedReader(3, MANIFEST_VK);
    const cache = new PoolIdentityCache();
    const container = document.createElement("div");
    const handle = mountReleaseFooter(container, {
      config: MOUNT_CONFIG,
      reader: slowA.reader,
      cache,
      proverVerifiedAt: () => null,
    });

    // The session moves on, and a NEW request for the same key settles first.
    cache.reset();
    const newA = scriptedReader(9, OTHER_VK);
    newA.release();
    await cache.observe(KEY_A, newA.reader);

    slowA.release();
    await handle.observed;

    // The footer's late callback must have painted nothing: its rows still show
    // the mount paint, not the obsolete version 3.
    const cv = handle.footer.querySelector('[data-release-row="Circuit version"]');
    expect(cv?.textContent).toContain("unverified against pool (query in progress)");
    handle.dispose();
  });
});


// ─────────────────────────────────────────────────────────────────────────────
// AMBER-1 — the classes the footer emits must actually STYLE something. Before
// this, `.mono` inherited the :root system-ui family (so the full hash was
// monospace in the data and proportional on screen) and `release-disagrees`
// carried no visual emphasis at all: the disagreement was discoverable only by
// reading the sentence.
// ─────────────────────────────────────────────────────────────────────────────

const STYLESHEET = readFileSync(resolve(REPO_ROOT, "wallet/src/styles.css"), "utf8");

/** The declaration block of a single-selector rule, or null. */
function ruleBody(selector: string): string | null {
  const re = new RegExp(
    `(?:^|[},])\\s*${selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*\\{([^}]*)\\}`,
    "m",
  );
  const m = re.exec(STYLESHEET);
  return m === null ? null : m[1];
}

describe("J-25 AMBER-1 — the release typography and state classes are styled", () => {
  let styleEl: HTMLStyleElement | null = null;

  beforeEach(() => {
    styleEl = document.createElement("style");
    styleEl.textContent = STYLESHEET;
    document.head.append(styleEl);
  });
  afterEach(() => {
    styleEl?.remove();
    styleEl = null;
  });

  it("the stylesheet main.ts imports actually defines .mono and every release-* state", () => {
    for (const selector of [
      ".mono",
      ".release-panel",
      ".release-row",
      ".release-label",
      ".release-value",
      ".release-pool-value",
      ".release-source",
      ".release-trust",
      ".release-informational",
      ".release-agrees",
      ".release-unverified",
      ".release-unavailable",
      ".release-disagrees",
    ]) {
      expect(ruleBody(selector), `${selector} has no stylesheet rule`).not.toBeNull();
    }
  });

  it("the full 64-hex hash renders MONOSPACE and wraps rather than overflowing", () => {
    const panel = document.createElement("footer");
    document.body.append(panel);
    renderReleaseRows(panel, rows(ok(3, MANIFEST_VK)));
    const value = panel.querySelector(
      '[data-release-row="Verifying-key hash"] .release-value',
    ) as HTMLElement;
    expect(value.textContent).toHaveLength(64);

    const family = getComputedStyle(value).fontFamily;
    expect(family, "the applied family is still the inherited sans-serif").toMatch(/monospace/);
    expect(family).not.toMatch(/system-ui/);

    // A 64-character unbroken token must be allowed to break; jsdom's cssstyle
    // drops `overflow-wrap: anywhere`, so the rule text is the binding check.
    const mono = ruleBody(".mono") ?? "";
    expect(mono).toMatch(/overflow-wrap:\s*anywhere/);
    expect(mono).toMatch(/word-break:\s*break-all/);
    // and nothing may clip or ellipsise it.
    expect(mono).not.toMatch(/text-overflow|white-space:\s*nowrap|overflow:\s*hidden/);
    panel.remove();
  });

  it("a DISAGREES row carries visible emphasis, not only a sentence", () => {
    const panel = document.createElement("footer");
    document.body.append(panel);
    renderReleaseRows(panel, rows(ok(4, OTHER_VK)));
    const li = panel.querySelector('[data-release-row="Circuit version"]') as HTMLElement;
    expect(li.className).toContain("release-disagrees");

    const emphasis = ruleBody(".release-disagrees") ?? "";
    expect(emphasis).toMatch(/border-left-color:\s*var\(--high\)/);
    // The disagreeing values and the trust sentence are emphasised too.
    expect(STYLESHEET).toMatch(/\.release-disagrees \.release-trust\s*\{[^}]*var\(--high\)/);
    expect(STYLESHEET).toMatch(
      /\.release-disagrees \.release-value,\s*\n?\s*\.release-disagrees \.release-pool-value\s*\{[^}]*var\(--high\)/,
    );
    // An AGREES row must NOT get the alarm colour.
    expect(ruleBody(".release-agrees") ?? "").toMatch(/var\(--success\)/);
    panel.remove();
  });

  it("the stylesheet is the one the production entrypoint imports", () => {
    const main = readFileSync(resolve(REPO_ROOT, "wallet/src/main.ts"), "utf8");
    expect(main).toMatch(/import\s+"\.\/styles\.css"/);
  });
});
