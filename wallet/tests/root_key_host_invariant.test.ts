/**
 * DL-1 — the S-12 drift-lock (HARDEN-03-WALLET-AUTH, brief V2 §6 gotcha 3, §7).
 *
 * **S-12, "root key by local host only"** (`Briefs/Complete/BRIEF_WALLET_B_PHASE2_FINISH_R4.md`
 * §12 register, listed there as a closed BLOCKER and as an L1 red-team angle
 * "mainnet root-key reachable incl. scanner worker (S-12/S-25)").
 *
 * The wallet builds agents in TWO places, and they gate the root key in two
 * syntactically different ways:
 *
 *     wallet/src/workers/scanner.worker.ts:51   if (isLocalHost(host)) await agent.fetchRootKey();
 *     wallet/src/session/session.ts:86          return config.fetchRootKey && isLocalHost(config.host);
 *
 * **That asymmetry is deliberate and this suite does not touch it.** It is one
 * invariant plus one narrowing, and each form is correct for its own trust
 * boundary:
 *
 *   - `session.ts` runs on the main thread, where the extra condition's input
 *     (`VITE_FETCH_ROOT_KEY`, `session/config.ts:203`) is a Vite BUILD-TIME
 *     constant baked into the bundle — free defence in depth, nothing an
 *     attacker can influence at runtime. That narrowing is A-S9.
 *   - `scanner.worker.ts` runs in a worker, where the equivalent flag would have
 *     to arrive over **postMessage** — runtime, caller-supplied. A boolean of
 *     exactly that shape once existed on that path and **S-25 deliberately
 *     removed it**. The worker's decision is the host classifier ALONE.
 *
 * Harmonising the two is ESC-4, a CTO item; SSA's ruling (`reviews/SSA_HARDEN03_WALLET_AUTH_V2_2026-09-17.md`
 * §4) is that what is owed there is DOCUMENTATION, not a code change. Brief §8
 * forbids this lane from altering either policy. So this suite asserts only the
 * property BOTH paths share and that the verified transport now leans on:
 *
 *     the root key is NEVER fetched when `!isLocalHost(host)`.
 *
 * A change to either path that breaks that shared invariant fails here.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { shouldFetchRootKey, createReadAgent, createMutationAgent } from "../src/session/session";
import { isLocalHost, type WalletConfig } from "../src/session/config";

const here = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Shared host corpus
// ---------------------------------------------------------------------------

const LOOPBACK_HOSTS = [
  "http://127.0.0.1:4943",
  "http://127.0.0.2:4943",
  "http://localhost:4943",
  "http://sub.localhost:4943",
  "http://[::1]:4943",
];

/**
 * Non-loopback hosts, including the shapes an attacker would reach for: a
 * hostname that merely CONTAINS a loopback string, and one that ends in a
 * lookalike suffix.
 */
const PRODUCTION_HOSTS = [
  "https://icp-api.io",
  "https://ic0.app",
  "https://app.stsh.fi",
  "https://127.0.0.1.evil.example",
  "https://localhost.evil.example",
  "https://notlocalhost",
  "https://192.168.1.10:4943",
];

// The corpus is only meaningful if the classifier agrees about it.
describe("DL-1 corpus sanity — isLocalHost agrees with the two host sets", () => {
  it("every loopback host classifies local", () => {
    for (const h of LOOPBACK_HOSTS) expect(isLocalHost(h), h).toBe(true);
  });
  it("every production host classifies non-local", () => {
    for (const h of PRODUCTION_HOSTS) expect(isLocalHost(h), h).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Mocked HttpAgent — shared by both path suites
// ---------------------------------------------------------------------------

const fetchRootKey = vi.fn(async () => new Uint8Array(133));
const createAgent = vi.fn(async (_opts: unknown) => ({ fetchRootKey }));

vi.mock("@dfinity/agent", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@dfinity/agent")>();
  return {
    ...actual,
    HttpAgent: { ...actual.HttpAgent, create: (opts: unknown) => createAgent(opts) },
  };
});

vi.mock("@dfinity/vetkeys", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, VetKey: { deserialize: () => ({ mocked: true }) } };
});

vi.mock("../src/actors/merkle", () => ({ createMerkleActor: () => ({}) }));
vi.mock("../src/actors/nullifierRegistry", () => ({ createNullifierRegistryActor: () => ({}) }));
vi.mock("../src/crypto/vetkeys", () => ({ tryDecryptNotePayload: () => null }));
vi.mock("../src/crypto/scanner", () => ({
  scanAndValidate: async () => ({ notes: [], scannedUpTo: 0n }),
}));

beforeEach(() => {
  fetchRootKey.mockClear();
  createAgent.mockClear();
});

afterEach(() => {
  vi.resetModules();
});

// ---------------------------------------------------------------------------
// PATH 1 — session.ts (main thread). READ AND ASSERT ONLY; policy untouched.
// ---------------------------------------------------------------------------

const configFor = (host: string, fetchRootKeyFlag: boolean): WalletConfig =>
  ({ host, fetchRootKey: fetchRootKeyFlag }) as unknown as WalletConfig;

describe("DL-1 path 1 — session.ts never fetches the root key off loopback", () => {
  it("shouldFetchRootKey is false on every production host, whatever the env flag says", () => {
    for (const host of PRODUCTION_HOSTS) {
      expect(shouldFetchRootKey(configFor(host, true)), `${host} / flag=true`).toBe(false);
      expect(shouldFetchRootKey(configFor(host, false)), `${host} / flag=false`).toBe(false);
    }
  });

  it("A-S9's narrowing still applies on loopback — the flag can only SUBTRACT", () => {
    for (const host of LOOPBACK_HOSTS) {
      expect(shouldFetchRootKey(configFor(host, true)), `${host} / flag=true`).toBe(true);
      expect(shouldFetchRootKey(configFor(host, false)), `${host} / flag=false`).toBe(false);
    }
  });

  it("createReadAgent does not call fetchRootKey on a production host", async () => {
    for (const host of PRODUCTION_HOSTS) {
      fetchRootKey.mockClear();
      await createReadAgent(configFor(host, true));
      expect(fetchRootKey, host).not.toHaveBeenCalled();
    }
  });

  it("createMutationAgent does not call fetchRootKey on a production host", async () => {
    for (const host of PRODUCTION_HOSTS) {
      fetchRootKey.mockClear();
      await createMutationAgent(configFor(host, true), {} as never);
      expect(fetchRootKey, host).not.toHaveBeenCalled();
    }
  });

  it("createReadAgent DOES fetch on loopback with the flag set (local dev still works)", async () => {
    await createReadAgent(configFor("http://127.0.0.1:4943", true));
    expect(fetchRootKey).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// PATH 2 — scanner.worker.ts (worker). Behavioural, through the real module.
// ---------------------------------------------------------------------------

type WorkerMessage = (e: MessageEvent<unknown>) => Promise<void> | void;

async function loadWorkerHandler(): Promise<WorkerMessage> {
  vi.resetModules();
  // The worker posts its outcome through `self.postMessage`; jsdom's window
  // form wants a targetOrigin, so stub it for the duration.
  (globalThis as unknown as { postMessage: unknown }).postMessage = vi.fn();
  await import("../src/workers/scanner.worker");
  const handler = (globalThis as unknown as { onmessage: WorkerMessage | null }).onmessage;
  expect(handler, "scanner.worker.ts must install a self.onmessage handler").toBeTruthy();
  return handler as WorkerMessage;
}

const scanRequest = (host: string) => ({
  data: {
    merkleCanisterId: "aaaaa-aa",
    nullifierCanisterId: "aaaaa-aa",
    host,
    vetKeySerialized: new Uint8Array(48),
    masterNoteSecret: new Uint8Array(32),
    fromIndex: 0n,
  },
});

describe("DL-1 path 2 — scanner.worker.ts never fetches the root key off loopback", () => {
  it("does not call fetchRootKey for any production host", async () => {
    const handler = await loadWorkerHandler();
    for (const host of PRODUCTION_HOSTS) {
      fetchRootKey.mockClear();
      await handler(scanRequest(host) as unknown as MessageEvent<unknown>);
      expect(fetchRootKey, host).not.toHaveBeenCalled();
    }
  });

  it("DOES call fetchRootKey for a loopback host — the classifier is the sole authority", async () => {
    const handler = await loadWorkerHandler();
    for (const host of LOOPBACK_HOSTS) {
      fetchRootKey.mockClear();
      await handler(scanRequest(host) as unknown as MessageEvent<unknown>);
      expect(fetchRootKey, host).toHaveBeenCalledTimes(1);
    }
  });
});

// ---------------------------------------------------------------------------
// S-25 — no root-key input may cross the worker's postMessage boundary
// ---------------------------------------------------------------------------

/** Extract the body of `export interface <name> { ... }` from a source file. */
function interfaceBody(src: string, name: string): string {
  const start = src.indexOf(`export interface ${name} {`);
  expect(start, `interface ${name} not found`).toBeGreaterThan(-1);
  const open = src.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < src.length; i += 1) {
    if (src[i] === "{") depth += 1;
    else if (src[i] === "}") {
      depth -= 1;
      if (depth === 0) return src.slice(open + 1, i);
    }
  }
  throw new Error(`unterminated interface ${name}`);
}

describe("S-25 — the removed root-key boolean stays removed", () => {
  const worker = readFileSync(resolve(here, "../src/workers/scanner.worker.ts"), "utf8");
  const app = readFileSync(resolve(here, "../src/ui/app.ts"), "utf8");

  it("ScannerRequest carries no root-key field", () => {
    expect(interfaceBody(worker, "ScannerRequest")).not.toMatch(/root\s*_?key/i);
  });

  it("ScanWorkerInput carries no root-key field", () => {
    expect(interfaceBody(app, "ScanWorkerInput")).not.toMatch(/root\s*_?key/i);
  });

  it("the worker's ONLY fetchRootKey call is guarded by the host classifier", () => {
    const calls = worker.match(/^.*\bfetchRootKey\(\).*$/gm) ?? [];
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatch(/if \(isLocalHost\(host\)\) await agent\.fetchRootKey\(\);/);
  });

  it("the worker derives the host from the request, never a boolean", () => {
    // `host` is the one field that decides both where requests go and whether
    // the root key is fetched — the coherence property S-25 protects.
    expect(interfaceBody(worker, "ScannerRequest")).toMatch(/\bhost\s*:\s*string;/);
  });
});
