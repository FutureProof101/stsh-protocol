// @vitest-environment node
/**
 * W-WALLET-ORIGIN. Originally the SINGLE branch (C-19(b) ruled: one wallet
 * domain, app.stsh.fi).
 *
 * ── C-19(b) IS REVERSED (WT-1, 2026-09-14) ─────────────────────────────────
 * Ruling record: `reviews/RULING_RECORD_SSOT_V91_AND_D1_D5_2026-09-14.md`;
 * brief `BRIEF_WT1_CANISTER_ROOTED_IDENTITY_V3_2026-09-14.md`.
 *
 * This file is SUPERSEDED IN PLACE rather than deleted, because the history is
 * the point. C-19(b) ruled one wallet domain, and two of the assertions below
 * followed from it: O-4 refused any `derivationOrigin`, and O-10 asserted
 * positively that NO `.well-known/ii-alternative-origins` asset ships. Both were
 * correct under that ruling and both are now INVERTED — silently deleting them
 * would erase the evidence that the old behaviour was deliberate and tested,
 * leaving a future reader unable to tell a reversal from a regression.
 *
 * WHY IT REVERSED: an II principal derived from `https://app.stsh.fi` is only as
 * durable as that DNS name. Whoever holds the domain can mint or move every
 * user's identity, and an expiry, a registrar mistake or a hijack silently
 * destroys access to shielded notes. Principals are therefore re-rooted at the
 * wallet CANISTER's own origin (`s3tyu-…icp0.io`), which no registrar can take
 * away, and `app.stsh.fi` is demoted to an alias vouched for by a certified
 * alternative-origins asset that the canister itself serves.
 *
 * WHAT DID NOT CHANGE, and is still asserted below: a third origin is refused
 * (O-2), an absent or malformed launch config fails closed with no compiled-in
 * fallback (O-3/O-8), and a derivation origin nobody authorised is refused —
 * O-4 now asserts the POSITIVE form of that same guard.
 *
 * The new-policy arms (permitted serving set, pinned derivation origin,
 * alt-origins asset body, `.ic-assets.json5` rule, CSP) live in
 * `tests/wt1_canister_rooted_identity.test.ts`.
 * ────────────────────────────────────────────────────────────────────────────
 *
 * S1-02 — the launch origin moves from a compile-time constant to a value loaded
 * at runtime from a same-origin asset.
 *
 * INDEPENDENT EXPECTED SIDE: every expected origin below is a literal written in
 * this file. `PRODUCTION_ORIGIN` is deliberately NOT imported as the oracle —
 * importing the value under test would make O-9 assert only that a constant
 * equals itself, which is precisely how the ruled value could drift unnoticed.
 */

import { describe, expect, it } from "vitest";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluateSessionPolicy, resolveConfig } from "../src/session/config";
import { loadLaunchOrigin, normaliseLaunchOrigin } from "../src/session/launchConfig";

/** The C-19(b) ruled value, written here, not read from the code under test. */
const RULED_ORIGIN = "https://app.stsh.fi";

const configWith = (launchOrigin: string | undefined, env: Record<string, string> = {}) => ({
  ...resolveConfig(env),
  launchOrigin,
});

const here = dirname(fileURLToPath(import.meta.url));
const walletRoot = resolve(here, "..");

/** A fetch stub serving one body from the same-origin relative path. */
const serving = (body: string, ok = true): typeof fetch =>
  (async (input: RequestInfo | URL) => {
    // The request must be RELATIVE — a config fetched from a named host would let
    // that host decide which origin may hold funds.
    expect(String(input).startsWith("http")).toBe(false);
    return new Response(body, { status: ok ? 200 : 404 });
  }) as unknown as typeof fetch;

describe("O-1 — the wallet runs where the launch config says it may", () => {
  it("enables login and transfers on the configured origin", () => {
    const policy = evaluateSessionPolicy(configWith(RULED_ORIGIN), RULED_ORIGIN);
    expect(policy.kind).toBe("production");
  });
});

describe("O-2 — any other origin is refused, exactly as before", () => {
  for (const origin of [
    "https://app.stsh.fi.evil.example",
    "https://stsh.fi",
    "https://app-stsh.fi",
    "http://app.stsh.fi",
    "https://app.stsh.fi:8443",
  ]) {
    it(`refuses ${origin}`, () => {
      const policy = evaluateSessionPolicy(configWith(RULED_ORIGIN), origin);
      expect(policy.kind).toBe("blocked");
      if (policy.kind === "blocked") {
        // The reason must name the ORIGIN mismatch, not the missing config —
        // otherwise this arm could pass on a refusal it did not test for.
        expect(policy.reason).toMatch(/is not the production wallet origin/i);
      }
    });
  }
});

describe("O-3 / O-8 — absent, empty or malformed config FAILS CLOSED", () => {
  // The whole point of S1-02's fail-closed rule: a missing config must never
  // fall back to a compiled-in value, because that is exactly what would mask a
  // config that was never deployed or was tampered with.
  for (const [label, value] of [
    ["undefined (fetch failed / asset absent)", undefined],
    ["empty string", ""],
  ] as const) {
    it(`refuses when the launch origin is ${label}, naming the config`, () => {
      const policy = evaluateSessionPolicy(configWith(value), RULED_ORIGIN);
      expect(policy.kind).toBe("blocked");
      if (policy.kind === "blocked") {
        expect(policy.reason).toMatch(/wallet-config\.json/i);
        expect(policy.reason).toMatch(/missing or unreadable/i);
      }
    });
  }

  it("refuses even when the RUNNING origin is the ruled one — no fallback exists", () => {
    // If anyone reintroduces `PRODUCTION_ORIGIN` as a default, this arm fails.
    const policy = evaluateSessionPolicy(configWith(undefined), RULED_ORIGIN);
    expect(policy.kind).not.toBe("production");
  });

  it("rejects every malformed config shape at the loader", async () => {
    const bad = [
      '{"launchOrigin": ""}',
      '{"launchOrigin": null}',
      '{"launchOrigin": 42}',
      '{"launchOrigin": "app.stsh.fi"}', // no scheme
      '{"launchOrigin": "http://app.stsh.fi"}', // not https
      '{"launchOrigin": "https://app.stsh.fi/wallet"}', // path-bearing: rejected, not repaired
      '{"notTheField": "https://app.stsh.fi"}',
      "[]",
      "null",
      "not json at all",
    ];
    for (const body of bad) {
      expect(await loadLaunchOrigin(serving(body))).toBeUndefined();
    }
    // ...and a non-2xx response.
    expect(await loadLaunchOrigin(serving('{"launchOrigin":"https://app.stsh.fi"}', false))).toBeUndefined();
  });

  it("accepts a well-formed BARE origin", async () => {
    expect(await loadLaunchOrigin(serving('{"launchOrigin":"https://app.stsh.fi"}'))).toBe(RULED_ORIGIN);
    // A trailing slash is the same origin spelled differently, not extra input.
    expect(normaliseLaunchOrigin("https://app.stsh.fi/")).toBe(RULED_ORIGIN);
  });

  it("REJECTS anything that is not a bare origin — the boundary, both sides", () => {
    // SSA-B RED-1: this contract is REJECTION, not canonicalisation. Repairing
    // an operator's value in flight would let the deployed config and the
    // enforced value differ silently, in a security-control asset.
    for (const accepted of ["https://app.stsh.fi", "https://app.stsh.fi/"]) {
      expect(normaliseLaunchOrigin(accepted)).toBe(RULED_ORIGIN);
    }
    for (const rejected of [
      "https://app.stsh.fi/wallet", // non-root path
      "https://app.stsh.fi/?x=1", // query
      "https://app.stsh.fi/#frag", // fragment
      "https://app.stsh.fi/wallet?x=1#y", // the value V1 silently accepted
      "https://user:pw@app.stsh.fi", // embedded credentials
      " https://app.stsh.fi", // leading whitespace
      "https://app.stsh.fi ", // trailing whitespace
      "http://app.stsh.fi",
      "app.stsh.fi",
      "",
    ]) {
      expect(normaliseLaunchOrigin(rejected)).toBeUndefined();
    }
  });

  it("a path-bearing config REFUSES end to end, not just at the validator", async () => {
    // The boundary must hold through the loader and the policy, or the
    // validator could be correct while the wallet still ran.
    const loaded = await loadLaunchOrigin(serving('{"launchOrigin":"https://app.stsh.fi/wallet"}'));
    expect(loaded).toBeUndefined();
    const policy = evaluateSessionPolicy(configWith(loaded), RULED_ORIGIN);
    expect(policy.kind).toBe("blocked");
    if (policy.kind === "blocked") expect(policy.reason).toMatch(/wallet-config\.json/i);
  });
});

describe("O-4 (SUPERSEDED BY WT-1) — an UNAUTHORISED derivationOrigin is still refused", () => {
  // WAS: "derivationOrigin stays REFUSED under the single-origin ruling" —
  // any configured value was blocked, and a source-level lock asserted the auth
  // layer never passed one to the client. C-19(b) is reversed, so both halves
  // are inverted here. The SUBSTANCE of the old guard is retained: the refusal
  // of an origin nobody authorised. Only the authorised value changed, from
  // "none at all" to "exactly the pinned wallet-canister origin".
  it("refuses a configured derivationOrigin that is NOT the pinned native origin", () => {
    const policy = evaluateSessionPolicy(
      { ...configWith(RULED_ORIGIN), derivationOrigin: "https://other.stsh.fi" },
      RULED_ORIGIN,
    );
    expect(policy.kind).toBe("blocked");
    if (policy.kind === "blocked") expect(policy.reason).toMatch(/derivationOrigin override/i);
  });

  it("the auth layer passes derivationOrigin ONLY from the policy — never from env or a caller", () => {
    // The old arm asserted `derivationOrigin` appears in NO login call. It now
    // must appear, so the source-level lock is re-aimed at the property that
    // actually protects users: the forwarded value has exactly one provenance,
    // the vetted policy object. If anyone ever wires `config.`, `env.` or
    // `import.meta` into that spread, this fails.
    const auth = readFileSync(resolve(walletRoot, "src/session/auth.ts"), "utf8");
    const createCalls = auth.match(/AuthClient\.create\([\s\S]*?\)/g) ?? [];
    expect(createCalls.length).toBeGreaterThan(0);
    for (const call of createCalls) expect(call).not.toMatch(/derivationOrigin/);
    // Exactly one assignment of the forwarded local, and it reads the policy.
    const assignments = auth.match(/const derivationOrigin = [^;]+;/g) ?? [];
    expect(assignments).toHaveLength(1);
    expect(assignments[0]).toBe("const derivationOrigin = policy.derivationOrigin;");
    expect(auth).not.toMatch(/derivationOrigin[^\n]*import\.meta/);
    expect(auth).not.toMatch(/derivationOrigin: *(?:config|env)\./);
  });
});

describe("O-9 — the shipped config carries exactly the ruled value", () => {
  it("wallet-config.json names https://app.stsh.fi", () => {
    const shipped = JSON.parse(readFileSync(resolve(walletRoot, "public/wallet-config.json"), "utf8"));
    expect(shipped.launchOrigin).toBe(RULED_ORIGIN);
  });

  it("a wallet served from any other origin refuses, using the shipped value", () => {
    const shipped = JSON.parse(readFileSync(resolve(walletRoot, "public/wallet-config.json"), "utf8"));
    const policy = evaluateSessionPolicy(configWith(shipped.launchOrigin), "https://staging.stsh.fi");
    expect(policy.kind).toBe("blocked");
  });
});

describe("O-10 (SUPERSEDED BY WT-1) — the alternative-origins asset MUST now ship", () => {
  // WAS: "S1-01 closes N/A-WITH-EVIDENCE: no alternative-origins asset ships" —
  // a positive assertion that `dist` contained no `.well-known/ii-alternative-origins`
  // and nothing named like one anywhere in the tree. Correct under C-19(b),
  // which ruled a single wallet domain; wrong under WT-1, where that asset is
  // the mechanism by which `app.stsh.fi` is permitted to derive principals from
  // the wallet canister's own origin. Inverted rather than deleted so the
  // reversal is legible as a decision.
  //
  // Still asserted over the BUILT output, for the original reason: the asset
  // canister serves `dist`, and presence in `public/` proves nothing about what
  // ships. The BODY and the header rules are asserted in
  // `tests/wt1_canister_rooted_identity.test.ts`.
  const dist = resolve(walletRoot, "dist");

  it("the built output exists (else this arm proves nothing — provision it)", () => {
    // Fail-on-absence by design, the R14-1 pattern: an arm that silently skips
    // when `dist` is missing would report N/A-with-evidence with no evidence.
    expect(existsSync(dist)).toBe(true);
  });

  it("ships the ii-alternative-origins well-known asset, at exactly one path", () => {
    expect(existsSync(join(dist, ".well-known/ii-alternative-origins"))).toBe(true);

    // The inverted form of the old sweep. The old arm required NOTHING in the
    // tree matching the name; this one requires exactly ONE thing matching it.
    // A second copy — say a stray `.json` twin — is still a defect: II fetches
    // one path, and a near-miss file that nobody serves is how a stale origin
    // list survives a change to the real one.
    const walk = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)],
      );
    const matches = walk(dist).filter((f) => /alternative-origins/i.test(f));
    expect(matches).toEqual([join(dist, ".well-known/ii-alternative-origins")]);
  });

  it("ships the launch config the policy needs", () => {
    // The other half of the same evidence: the asset that MUST ship, does.
    const cfg = join(dist, "wallet-config.json");
    expect(existsSync(cfg)).toBe(true);
    expect(JSON.parse(readFileSync(cfg, "utf8")).launchOrigin).toBe(RULED_ORIGIN);
  });
});
