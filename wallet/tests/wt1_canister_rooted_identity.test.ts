// @vitest-environment node
/**
 * WT-1 — canister-rooted identity, and the wallet-rebuild fold (Addendum A).
 *
 * Brief `BRIEF_WT1_CANISTER_ROOTED_IDENTITY_V3_2026-09-14.md` (sha256
 * `0a80d32a…`) and `BRIEF_WT1_ADDENDUM_A_WALLET_REBUILD_FOLD_V2_2026-09-14.md`
 * (`5f1e8730…`); spec `reviews/ICP_FRONTEND_IDENTITY_TRUST_MODEL_V3_2026-09-14.md`;
 * C-19(b) reversal recorded in
 * `reviews/RULING_RECORD_SSOT_V91_AND_D1_D5_2026-09-14.md`.
 *
 * WHAT THIS LANE IS FOR, in one line: an II principal must not be a function of
 * a DNS name somebody could lose, let expire, or take. It is re-rooted at the
 * wallet canister's own origin, and `app.stsh.fi` becomes an alias the canister
 * itself vouches for.
 *
 * INDEPENDENT EXPECTED SIDE — the discipline stated at
 * `origin_policy_s102.test.ts:10-13`, carried here deliberately. EVERY expected
 * value below is a literal written in THIS file: the origins, the nine canister
 * ids, the CSP header string, the approval bound. Nothing is imported from the
 * module under test, and nothing is read from `a7_install_kit.toml` or
 * `.ic-assets.json5` at test time. An oracle taken from the artifact it checks
 * asserts only that the artifact equals itself — which is exactly how a wrong
 * canister id or a widened CSP would ship green.
 */

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluateSessionPolicy, permittedServingOrigins, resolveConfig } from "../src/session/config";
import { wrapTokenMutationActor } from "../src/actors/token";
import { createWalletAuth } from "../src/session/auth";

const here = dirname(fileURLToPath(import.meta.url));
const walletRoot = resolve(here, "..");
const dist = resolve(walletRoot, "dist");

/**
 * The pinned wallet-canister origin: `s3tyu-aaaaa-aaaab-qhdjq-cai`
 * (`deployment/mainnet/custody_manifest.toml:241`, `vault_init.did:75`,
 * `purpose = "wallet_frontend"`) under the boundary-node domain. Written here,
 * never imported.
 */
const NATIVE_ORIGIN = "https://s3tyu-aaaaa-aaaab-qhdjq-cai.icp0.io";
/** The DNS alias, demoted from identity root to serving alias. */
const ALIAS_ORIGIN = "https://app.stsh.fi";

const configWith = (over: Record<string, unknown> = {}) => ({
  ...resolveConfig({}),
  launchOrigin: ALIAS_ORIGIN,
  ...over,
});

// ───────────────────────────────────────────────────────────────────────────
// AC-1 / AC-2 — the split: a permitted SERVING set, one pinned DERIVATION origin
// ───────────────────────────────────────────────────────────────────────────

describe("AC-1 — the production policy accepts the pinned native derivation origin, and nothing else", () => {
  it("accepts exactly the native wallet-canister origin", () => {
    const policy = evaluateSessionPolicy(configWith({ derivationOrigin: NATIVE_ORIGIN }), ALIAS_ORIGIN);
    expect(policy.kind).toBe("production");
    // It is not merely accepted — it is CARRIED, because a value the policy
    // approves but drops would leave the auth layer with nothing to forward and
    // the whole lane inert while every arm stayed green.
    if (policy.kind === "production") expect(policy.derivationOrigin).toBe(NATIVE_ORIGIN);
  });

  it("rejects every other configured value, including near-misses", () => {
    for (const rogue of [
      "https://s3tyu-aaaaa-aaaab-qhdjq-cai.icp0.io.evil.example",
      "https://s3tyu-aaaaa-aaaab-qhdjq-cai.raw.icp0.io",
      "https://s3tyu-aaaaa-aaaab-qhdjq-cai.ic0.app",
      "http://s3tyu-aaaaa-aaaab-qhdjq-cai.icp0.io",
      ALIAS_ORIGIN,
      "https://other.stsh.fi",
    ]) {
      const policy = evaluateSessionPolicy(configWith({ derivationOrigin: rogue }), ALIAS_ORIGIN);
      expect(policy.kind).toBe("blocked");
      if (policy.kind === "blocked") expect(policy.reason).toMatch(/derivationOrigin override/i);
    }
  });

  it("permits an ABSENT derivation origin — the transitional (Phase B.1) deployment", () => {
    // Not a hole: absent means nothing is forwarded and II derives from the
    // serving origin, i.e. the wallet's exact pre-WT-1 behaviour. The rotation
    // is executed under this bundle, with the OLD principals, by design.
    const policy = evaluateSessionPolicy(configWith({ derivationOrigin: undefined }), ALIAS_ORIGIN);
    expect(policy.kind).toBe("production");
    if (policy.kind === "production") expect(policy.derivationOrigin).toBeUndefined();
  });
});

describe("AC-2 — the permitted serving-origin set is exactly two, and closed", () => {
  it("accepts the native origin and the alias", () => {
    for (const origin of [NATIVE_ORIGIN, ALIAS_ORIGIN]) {
      expect(evaluateSessionPolicy(configWith({ derivationOrigin: NATIVE_ORIGIN }), origin).kind).toBe(
        "production",
      );
    }
    expect([...permittedServingOrigins(configWith())].sort()).toEqual([ALIAS_ORIGIN, NATIVE_ORIGIN].sort());
  });

  it("rejects a third origin", () => {
    for (const rogue of [
      "https://staging.stsh.fi",
      "https://app.stsh.fi.evil.example",
      "https://s3tyu-aaaaa-aaaab-qhdjq-cai.icp0.io.evil.example",
      "https://stsh.fi",
    ]) {
      const policy = evaluateSessionPolicy(configWith({ derivationOrigin: NATIVE_ORIGIN }), rogue);
      expect(policy.kind).toBe("blocked");
      if (policy.kind === "blocked") expect(policy.reason).toMatch(/not the production wallet origin/i);
    }
  });

  it("an absent launch config still fails closed — the set never degrades to 'native only'", () => {
    // The serving set is built from the launch config PLUS the native origin, so
    // a missing config could plausibly have left a still-usable one-element set.
    // It must not: S1-02's fail-closed rule comes first, and is unweakened.
    const policy = evaluateSessionPolicy(configWith({ launchOrigin: undefined }), NATIVE_ORIGIN);
    expect(policy.kind).toBe("blocked");
    if (policy.kind === "blocked") expect(policy.reason).toMatch(/wallet-config\.json/i);
  });
});

describe("AC-1 (forwarding) — the policy's value actually reaches AuthClient.login", () => {
  /**
   * The half of this lane that cannot be proved by inspecting the policy: a
   * derivation origin that is validated and then never sent produces a green
   * suite and a wallet that still derives from the DNS name. Asserted on the
   * wire arguments.
   *
   * The login is allowed to REJECT — the stub identity is anonymous, so the
   * auth layer refuses the session afterwards. That is irrelevant here: the
   * options object was already handed to the client, which is the fact under
   * test.
   */
  async function capturedLoginOptions(derivationOrigin: string | undefined) {
    let options: Record<string, unknown> | undefined;
    const anonymous = {
      getPrincipal: () => ({ isAnonymous: () => true, toText: () => "2vxsx-fae" }),
      getDelegation: () => ({ delegations: [] }),
    };
    const auth = await createWalletAuth(
      { kind: "production", iiUrl: undefined, derivationOrigin },
      () => {},
      {
        createClient: async () => ({
          isAuthenticated: async () => false,
          getIdentity: () => anonymous as never,
          login: async (opts: Record<string, unknown>) => {
            options = opts;
            (opts.onSuccess as () => void)?.();
          },
          logout: async () => {},
        }),
      },
    );
    await auth.login().catch(() => {});
    return options ?? {};
  }

  it("forwards the pinned native origin when the policy carries it", async () => {
    expect((await capturedLoginOptions(NATIVE_ORIGIN)).derivationOrigin).toBe(NATIVE_ORIGIN);
  });

  it("OMITS the key entirely under the transitional policy — not `undefined`", async () => {
    // `derivationOrigin: undefined` and an absent key are not the same request
    // to every client version. The transitional bundle must be byte-identical on
    // the wire to the pre-WT-1 one, or Phase B.1 is not the no-op it is relied
    // on to be.
    expect("derivationOrigin" in (await capturedLoginOptions(undefined))).toBe(false);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// AC-4 — the alternative-origins asset, over the BUILT output
// ───────────────────────────────────────────────────────────────────────────

describe("AC-4 — the shipped .well-known/ii-alternative-origins body", () => {
  const assetPath = join(dist, ".well-known/ii-alternative-origins");

  it("the built output exists (else this arm proves nothing — provision it)", () => {
    expect(existsSync(dist)).toBe(true);
    expect(existsSync(assetPath)).toBe(true);
  });

  it("parses as JSON and lists exactly the alias origin", () => {
    // JSON-PARSED equality, not a byte match (brief N-4): whitespace, key order
    // and trailing newline are not part of the contract with II, and pinning
    // them would make an innocuous formatting change look like a security
    // regression — which trains people to wave the real one through.
    const body = JSON.parse(readFileSync(assetPath, "utf8")) as { alternativeOrigins: string[] };
    expect(body.alternativeOrigins).toEqual([ALIAS_ORIGIN]);
  });

  it("carries at most the 100 entries II accepts", () => {
    const body = JSON.parse(readFileSync(assetPath, "utf8")) as { alternativeOrigins: string[] };
    expect(body.alternativeOrigins.length).toBeGreaterThan(0);
    expect(body.alternativeOrigins.length).toBeLessThanOrEqual(100);
  });

  it("the shipped launch config names the native origin as the derivation root", () => {
    // The FINAL (Phase D.8) shape. The transitional install ships this same
    // bundle with the field removed from the asset — a deployment difference,
    // not a source difference.
    const cfg = JSON.parse(readFileSync(join(dist, "wallet-config.json"), "utf8"));
    expect(cfg.launchOrigin).toBe(ALIAS_ORIGIN);
    expect(cfg.derivationOrigin).toBe(NATIVE_ORIGIN);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// AC-5 / AC-6 — the asset-canister header rules
// ───────────────────────────────────────────────────────────────────────────

/**
 * Parse `.ic-assets.json5` as JSON after dropping WHOLE-LINE `//` comments.
 * Deliberately not a general JSON5 parser and deliberately not regex-scraping
 * the raw text: if the file ever grows a construct this cannot parse, the test
 * fails loudly rather than matching a substring inside a comment and reporting
 * a policy that is not the deployed one.
 */
function readAssetRules(): Array<Record<string, unknown>> {
  const raw = readFileSync(resolve(walletRoot, "public/.ic-assets.json5"), "utf8");
  const stripped = raw
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("//"))
    .join("\n");
  return JSON.parse(stripped);
}

describe("AC-5 — the .well-known rule II needs in order to honour the alias", () => {
  it("has a rule matching the exact path, with the JSON content type and a CORS header", () => {
    const rule = readAssetRules().find((r) => r.match === ".well-known/ii-alternative-origins");
    expect(rule).toBeDefined();
    const headers = (rule as { headers: Record<string, string> }).headers;
    // Literals, written here. The file has no extension, so the asset canister
    // cannot infer a type, and II rejects a wrong one.
    expect(headers["Content-Type"]).toBe("application/json");
    // II fetches this cross-origin; without the header the browser discards the
    // response and the alias silently falls back to alias-derived principals —
    // the wrong identity, not a visible error.
    expect(headers["Access-Control-Allow-Origin"]).toBe("*");
  });

  it("disables dfx's dotfile skip on BOTH the directory and the file", () => {
    // The trap this arm exists for, and the one that got past its first version
    // (SSA landed-diff F-1): `dfx` ignores dot-prefixed paths by default, and
    // that applies to the DIRECTORY as well as the file inside it. A file rule
    // alone is not enough — dfx never descends into `.well-known/` to reach the
    // entry, so the asset is present in `dist`, passes AC-4, satisfies the file
    // rule, and still never exists on chain. Both rules, asserted separately,
    // because the earlier single-rule version of this arm was green while the
    // deployment was broken.
    const rules = readAssetRules();

    const dirRule = rules.find((r) => r.match === ".well-known");
    expect(dirRule, "a directory rule for .well-known must exist").toBeDefined();
    expect((dirRule as { ignore: unknown }).ignore).toBe(false);

    const fileRule = rules.find((r) => r.match === ".well-known/ii-alternative-origins");
    expect(fileRule).toBeDefined();
    expect((fileRule as { ignore: unknown }).ignore).toBe(false);
  });

  it("orders the rules so the file's headers are not shadowed by the catch-all", () => {
    // dfx applies every matching rule and the LAST one wins for a given header,
    // so the specific `.well-known/ii-alternative-origins` rule must come after
    // `**/*`. Asserted on index, because the Content-Type and CORS header that
    // AC-5 checks above are worthless if the catch-all overwrites them.
    const matches = readAssetRules().map((r) => r.match);
    expect(matches.indexOf(".well-known/ii-alternative-origins")).toBeGreaterThan(
      matches.indexOf("**/*"),
    );
    // The directory rule carries no headers, so its position is free; it is
    // pinned to the head only to mirror the in-repo precedent.
    expect(matches[0]).toBe(".well-known");
  });
});

describe("AC-6 — the Content-Security-Policy, asserted as an exact literal", () => {
  /**
   * The WHOLE expected header, written out here rather than read from the file.
   * Reading it would assert only that the policy equals itself. Spelled in full
   * so that widening ANY directive — not just the three this lane narrowed —
   * fails this arm and has to be argued for.
   */
  const EXPECTED_CSP =
    "default-src 'self';" +
    "script-src 'self' 'wasm-unsafe-eval';" +
    "connect-src 'self' https://icp0.io https://*.icp0.io https://icp-api.io blob:;" +
    "worker-src 'self' blob:;" +
    "img-src 'self' data:;" +
    "style-src 'self' 'unsafe-inline';" +
    "style-src-elem 'self' 'unsafe-inline';" +
    "font-src 'self';" +
    "object-src 'none';" +
    "base-uri 'self';" +
    "frame-ancestors 'none';" +
    "form-action 'self';" +
    "upgrade-insecure-requests;";

  it("matches the shipped policy byte for byte", () => {
    const rule = readAssetRules().find((r) => r.match === "**/*");
    expect(rule).toBeDefined();
    const csp = (rule as { headers: Record<string, string> }).headers["Content-Security-Policy"];
    expect(csp).toBe(EXPECTED_CSP);
  });

  it("no wildcard survives on style-src, style-src-elem or font-src", () => {
    // The same fact from the other side, so a future edit that satisfies the
    // literal by accident (say, by reordering) cannot also reintroduce a `*`.
    const rule = readAssetRules().find((r) => r.match === "**/*");
    const csp = (rule as { headers: Record<string, string> }).headers["Content-Security-Policy"];
    for (const directive of ["style-src", "style-src-elem", "font-src"]) {
      const found = csp.split(";").find((d) => d.trim().startsWith(`${directive} `));
      expect(found).toBeDefined();
      expect(found).not.toMatch(/\*/);
      expect(found).toMatch(/'self'/);
    }
    // `'unsafe-eval'` must never appear; `'wasm-unsafe-eval'` is the narrower
    // token the WASM prover genuinely needs, and is checked not to be a prefix
    // match for the dangerous one.
    expect(csp).not.toMatch(/(^|[ ;'])'unsafe-eval'/);
  });

  it("WALLET-CSP-BLOB: blob: is granted to connect-src and worker-src ONLY", () => {
    // Deviations (4) and (5): the prover worker fetches its hash-verified
    // artifact object URLs (connect-src), and ffjavascript spawns its proving
    // thread pool from a blob URL (worker-src). Parsed to exact token lists so
    // `blob:` cannot drift into script-src / default-src — where it would let a
    // blob URL load as a page script — without failing here.
    const rule = readAssetRules().find((r) => r.match === "**/*");
    const csp = (rule as { headers: Record<string, string> }).headers["Content-Security-Policy"];
    const d = new Map<string, string[]>();
    for (const part of csp.split(";")) {
      const tokens = part.trim().split(/\s+/).filter(Boolean);
      if (tokens.length === 0) continue;
      expect(d.has(tokens[0])).toBe(false); // no shadowing duplicate directive
      d.set(tokens[0], tokens.slice(1));
    }
    expect(d.get("connect-src")).toContain("blob:");
    expect(d.get("worker-src")).toEqual(["'self'", "blob:"]);
    expect(d.get("script-src")).toEqual(["'self'", "'wasm-unsafe-eval'"]);
    expect(d.get("script-src")).not.toContain("blob:");
    expect(d.get("default-src")).toEqual(["'self'"]);
    expect(d.get("default-src")).not.toContain("blob:");
    expect(d.has("child-src")).toBe(false);
  });

  it("the production policy no longer reaches the user's own machine", () => {
    // dfx's standard policy ships `http://localhost:*` in connect-src so a local
    // build can reach a local replica. A mainnet page that may open connections
    // to arbitrary ports on the visitor's machine has no legitimate use.
    const rule = readAssetRules().find((r) => r.match === "**/*");
    const csp = (rule as { headers: Record<string, string> }).headers["Content-Security-Policy"];
    expect(csp).not.toMatch(/localhost/);
    expect(csp).not.toMatch(/127\.0\.0\.1/);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// AC-7 — the approval bound, in-app path (the oisy path is in oisy_approve)
// ───────────────────────────────────────────────────────────────────────────

describe("AC-7 — icrc2_approve carries a bounded expiry AND keeps the CAS guard", () => {
  const CREATED_AT = 1_700_000_000_000_000_000n;
  /** 15 minutes in ns, written here — never imported from the code under test. */
  const EXPECTED_TTL_NS = 900_000_000_000n;

  function captureApprove() {
    const seen: Array<Record<string, unknown>> = [];
    const actor = wrapTokenMutationActor({
      icrc2_approve: async (arg: Record<string, unknown>) => {
        seen.push(arg);
        return { Ok: 1n };
      },
    } as never);
    return { actor, seen };
  }

  it("sends expires_at = createdAtTime + 15 minutes, with expected_allowance retained", async () => {
    const { actor, seen } = captureApprove();
    await actor.approve({
      spender: { toText: () => "aaaaa-aa" } as never,
      amount: 100n,
      expectedAllowance: 0n,
      createdAtTime: CREATED_AT,
      fee: 10n,
    });
    const arg = seen.at(-1) as { expires_at: bigint[]; expected_allowance: bigint[]; created_at_time: bigint[] };
    // Previously `[]` — a PERMANENT allowance left behind by every abandoned or
    // failed shield, invisible to the user and live for the life of the account.
    expect(arg.expires_at).toEqual([CREATED_AT + EXPECTED_TTL_NS]);
    // The CAS guard is not traded away for the bound: they defend different
    // things (stacking vs lingering) and both are required.
    expect(arg.expected_allowance).toEqual([0n]);
    expect(arg.created_at_time).toEqual([CREATED_AT]);
  });

  it("derives the expiry from the DEDUP timestamp, so a retry reproduces it exactly", async () => {
    // C-A3: a lost-response retry must reproduce the approve argument
    // byte-for-byte or the ledger sees a second, different approve instead of a
    // `Duplicate`. An expiry read from a wall clock per attempt would break
    // dedup on precisely the path it protects.
    const { actor, seen } = captureApprove();
    const req = {
      spender: { toText: () => "aaaaa-aa" } as never,
      amount: 100n,
      expectedAllowance: 0n,
      createdAtTime: CREATED_AT,
      fee: 10n,
    };
    await actor.approve(req);
    await actor.approve(req);
    const [first, second] = seen.slice(-2) as Array<{ expires_at: bigint[] }>;
    expect(second.expires_at).toEqual(first.expires_at);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Addendum A — AC-14 / AC-15 / AC-15a: the ids the pinned build actually carries
// ───────────────────────────────────────────────────────────────────────────

describe("AC-14/AC-15 — resolveConfig({}) yields every live canister id", () => {
  /**
   * The nine live principals, each written here as a literal and each equal to
   * the `target` row of its install record in
   * `deployment/mainnet/a7_install_kit.toml` at this lane's head:
   *   verifier  :95    merkle  :115   nullifier :133   vetkeys :184
   *   token     :216   vesting :247   pool      :277
   * Vault and Upgrader come from `deployment/mainnet/custody_manifest.toml`.
   *
   * Read from the records, never hand-copied. NOT imported from `config.ts` and
   * NOT read from the kit at test time: an oracle that inherits the artifact's
   * own value cannot detect a wrong one.
   */
  const LIVE_IDS = {
    poolCanisterId: "cxrfg-qaaaa-aaaar-qchfa-cai",
    frozenPoolCanisterId: "cxrfg-qaaaa-aaaar-qchfa-cai",
    merkleCanisterId: "cmuzd-kyaaa-aaaar-qchhq-cai",
    nullifierCanisterId: "ccwul-riaaa-aaaar-qchgq-cai",
    vetkeysCanisterId: "a7l2d-caaaa-aaaar-qchja-cai",
    tokenCanisterId: "clv7x-haaaa-aaaar-qchha-cai",
    vestingCanisterId: "cfxs7-4qaaa-aaaar-qchga-cai",
    verifierCanisterId: "arjxl-zqaaa-aaaar-qchia-cai",
    vaultCanisterId: "cpdab-saaaa-aaaar-qca2q-cai",
    upgraderCanisterId: "cgal5-eiaaa-aaaar-qca3a-cai",
  } as const;

  it("the EMPTY-env path — the one the pinned build takes — is fully configured", () => {
    // `resolveConfig({})` is not a convenience here, it is the exact production
    // path: `[wallet_bundle].command` is a bare `npm run build`, `run_gate.sh`
    // sets no `VITE_*`, and `vite.config.ts` injects only `[build].source_sha`.
    // Six of these ids used to resolve to `""`, and nothing anywhere caught it —
    // the wallet degraded silently at the action site, with the user believing
    // it was configured.
    const config = resolveConfig({}) as unknown as Record<string, string>;
    for (const [field, expected] of Object.entries(LIVE_IDS)) {
      expect(config[field], `${field} must be the live mainnet principal`).toBe(expected);
      expect(config[field]).not.toBe("");
    }
  });

  it("staking alone stays empty — it is NOT INSTALLED at launch (D1)", () => {
    // The one deliberate exception, asserted so it reads as a decision rather
    // than as the bug the other eight were.
    expect(resolveConfig({}).stakingCanisterId).toBe("");
  });

  it("an explicit env value still overrides, for a local replica dry run", () => {
    expect(resolveConfig({ VITE_TOKEN_CANISTER_ID: "aaaaa-aa" }).tokenCanisterId).toBe("aaaaa-aa");
  });
});

describe("AC-15a — no untracked .env may have altered the measured bundle", () => {
  it("wallet/.env, .env.local and .env.production do not exist", () => {
    // Vite AUTO-LOADS these. An operator-local file would silently change the
    // bundle whose sha256 is pinned in `[wallet_bundle]`, and the record would
    // be reproducible only on that one machine. `.env.example` is tracked,
    // loaded by nothing, and stays.
    for (const name of [".env", ".env.local", ".env.production"]) {
      expect(existsSync(resolve(walletRoot, name)), `wallet/${name} must not exist`).toBe(false);
    }
    expect(existsSync(resolve(walletRoot, ".env.example"))).toBe(true);
  });
});
