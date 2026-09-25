/**
 * HARDEN-03-WALLET-AUTH — Gate 0 acceptance for the Route A replicated-read
 * transport (`src/actors/replicated.ts`).
 *
 * Rows covered here (brief V2 §7):
 *
 *   G0-3  a method NOT on the closed allowlist is unreachable — a type error at
 *         compile time and absent from the actor at runtime; a name that is not
 *         declared at all throws. Never silently promoted.
 *   G0-5  DL-2, SSA's ESC-1 condition — the runtime copy's method set and
 *         signatures versus the generated declarations. A drift in EITHER
 *         direction fails: a copy that names something the declarations do not
 *         have, and a declaration change the copy does not track.
 *   AC-8b the verified transport gates on the host classifier AT THE POINT OF
 *         USE and does not inherit trust from whoever constructed the agent it
 *         was handed. No new boolean is introduced to achieve it (S-25).
 *
 * NOT covered here, and deliberately: G0-1 (replicated invocation actually takes
 * the agent's update path), G0-2 (a wrong root key makes verification fail) and
 * G0-4 (measured sweep cost). Those three are the brief's `replica` harness —
 * they need a real local `dfx` replica, because the property under test is the
 * AGENT's own certificate validation against a root key. A mock cannot fail them
 * honestly, so they are not simulated here; see the lane packet.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { IC_ROOT_KEY, type HttpAgent } from "@dfinity/agent";
import { IDL } from "@dfinity/candid";

import {
  GENERATED_IDL_FACTORIES,
  REPLICATED_METHODS,
  ReplicatedMethodNotDeclared,
  ReplicatedTransportRefused,
  assertReplicatedTransportAllowed,
  createReplicatedMerkleActor,
  createReplicatedNullifierActor,
  createReplicatedPoolActor,
  replicatedInterfaceFactory,
} from "../src/actors/replicated";

const here = dirname(fileURLToPath(import.meta.url));

const MAINNET_ROOT_KEY = Uint8Array.from(
  (IC_ROOT_KEY.match(/../g) ?? []).map((b) => parseInt(b, 16)),
);
/** A "fetched" key — any key that is not the pinned one. Contents irrelevant. */
const FETCHED_ROOT_KEY = Uint8Array.from({ length: 133 }, (_, i) => (i * 7) % 251);

const agentAt = (host: string, rootKey: Uint8Array | null): HttpAgent =>
  ({ host: new URL(host), rootKey, _isAgent: true }) as unknown as HttpAgent;

const MERKLE_ID = "aaaaa-aa";

/** Invoke a factory and read back its service fields as a name -> Func map. */
function fields(factory: IDL.InterfaceFactory): Map<string, IDL.FuncClass> {
  const service = factory({ IDL }) as unknown as IDL.ServiceClass;
  return new Map(service._fields);
}

const CANISTERS = ["merkle_tree", "nullifier_registry", "shielded_pool"] as const;

// ---------------------------------------------------------------------------
// G0-5 / DL-2 — the runtime copy is GENERATED FROM the declarations
// ---------------------------------------------------------------------------

describe("DL-2 / G0-5 — replicated.ts vs the generated declarations", () => {
  it("names exactly the allowlist, and every name is a real declared method", () => {
    for (const canister of CANISTERS) {
      const allowlist = REPLICATED_METHODS[canister] as readonly string[];
      const generated = fields(GENERATED_IDL_FACTORIES[canister]);
      const copy = fields(replicatedInterfaceFactory(GENERATED_IDL_FACTORIES[canister], allowlist));

      expect([...copy.keys()].sort()).toEqual([...allowlist].sort());
      for (const name of allowlist) {
        expect(generated.has(name), `${canister}.${name} must be declared`).toBe(true);
      }
    }
  });

  it("is SEVEN methods in total — the brief's G0-1 target set", () => {
    const total = CANISTERS.reduce((n, c) => n + REPLICATED_METHODS[c].length, 0);
    expect(total).toBe(7);
  });

  it("reuses the generated argument and return types BY REFERENCE (no transcription)", () => {
    for (const canister of CANISTERS) {
      const allowlist = REPLICATED_METHODS[canister] as readonly string[];
      const factory = GENERATED_IDL_FACTORIES[canister];
      // One invocation of the generated factory, reused for both sides, so the
      // identity comparison is meaningful (the factory builds fresh objects).
      const shared: IDL.InterfaceFactory = (idl) => factory(idl);
      const service = shared({ IDL }) as unknown as IDL.ServiceClass;
      const generated = new Map(service._fields);
      const copy = fields(() => service);

      for (const name of allowlist) {
        const g = generated.get(name)!;
        const c = copy.get(name)!;
        expect(c.argTypes.length).toBe(g.argTypes.length);
        expect(c.retTypes.length).toBe(g.retTypes.length);
        g.argTypes.forEach((t, i) => expect(c.argTypes[i]).toBe(t));
        g.retTypes.forEach((t, i) => expect(c.retTypes[i]).toBe(t));
        // Textual Candid signature is the human-readable half of the same claim.
        expect(c.argTypes.map((t) => t.name)).toEqual(g.argTypes.map((t) => t.name));
        expect(c.retTypes.map((t) => t.name)).toEqual(g.retTypes.map((t) => t.name));
      }
    }
  });

  it("drops the query dispatch annotation and NOTHING else", () => {
    for (const canister of CANISTERS) {
      const allowlist = REPLICATED_METHODS[canister] as readonly string[];
      const generated = fields(GENERATED_IDL_FACTORIES[canister]);
      const copy = fields(replicatedInterfaceFactory(GENERATED_IDL_FACTORIES[canister], allowlist));

      for (const name of allowlist) {
        const g = generated.get(name)!;
        const c = copy.get(name)!;
        // The premise: every allowlisted method IS a query today. If a
        // regeneration ever made one an update, this fires and the lane is told.
        expect(g.annotations, `${canister}.${name} annotations`).toContain("query");
        expect(g.annotations).not.toContain("composite_query");
        expect(c.annotations).toEqual(
          g.annotations.filter((a) => a !== "query" && a !== "composite_query"),
        );
        expect(c.annotations).not.toContain("query");
      }
    }
  });

  it("never mutates the generated declarations' own objects", () => {
    const factory = GENERATED_IDL_FACTORIES.merkle_tree;
    const before = fields(factory).get("get_scan_head")!.annotations.slice();
    replicatedInterfaceFactory(factory, REPLICATED_METHODS.merkle_tree)({ IDL });
    const after = fields(factory).get("get_scan_head")!.annotations;
    expect(after).toEqual(before);
    expect(after).toContain("query");
  });

  it("DRIFT DIRECTION 1 — an allowlist name the declarations lack THROWS", () => {
    const factory = replicatedInterfaceFactory(GENERATED_IDL_FACTORIES.merkle_tree, [
      "get_scan_head",
      "get_scan_head_v2_that_does_not_exist",
    ]);
    expect(() => factory({ IDL })).toThrow(ReplicatedMethodNotDeclared);
  });

  it("DRIFT DIRECTION 2 — a declaration signature change propagates into the copy", () => {
    // A stand-in "regenerated" declaration: get_scan_head grows an argument.
    const mutated: IDL.InterfaceFactory = (idl) =>
      idl.IDL.Service({
        get_scan_head: idl.IDL.Func([idl.IDL.Nat64], [idl.IDL.Nat64], ["query"]),
      }) as never;
    const copy = fields(replicatedInterfaceFactory(mutated, ["get_scan_head"]));
    const f = copy.get("get_scan_head")!;
    // The copy tracked the change rather than preserving a stale local signature.
    expect(f.argTypes.map((t) => t.name)).toEqual(["nat64"]);
    expect(f.annotations).not.toContain("query");
    // And it now differs from the real declarations, which is the drift this
    // lock exists to surface.
    const real = fields(GENERATED_IDL_FACTORIES.merkle_tree).get("get_scan_head")!;
    expect(f.argTypes.map((t) => t.name)).not.toEqual(real.argTypes.map((t) => t.name));
  });

  it("does not edit any checked-in generated declaration file (guardrail 1)", () => {
    const src = readFileSync(resolve(here, "../src/actors/replicated.ts"), "utf8");
    // Only `import` statements may name the declarations; nothing writes there.
    for (const line of src.split("\n")) {
      if (line.includes("src/declarations")) {
        expect(line.trimStart().startsWith("import")).toBe(true);
      }
    }
    expect(src).not.toMatch(/writeFileSync|\.did\.js['"]\s*,\s*['"]w/);
  });
});

// ---------------------------------------------------------------------------
// G0-3 — the closed allowlist
// ---------------------------------------------------------------------------

describe("G0-3 — a method off the allowlist is never silently promoted", () => {
  const prodAgent = () => agentAt("https://icp-api.io", MAINNET_ROOT_KEY);

  it("a declared-but-not-allowlisted merkle method is absent from the actor", () => {
    const actor = createReplicatedMerkleActor(MERKLE_ID, prodAgent());
    // `get_root`, `get_payloads`, `leaf_count`, `append_commitment` are all real
    // merkle methods and all deliberately off the allowlist.
    for (const name of ["get_root", "get_payloads", "leaf_count", "append_commitment"]) {
      expect((actor as unknown as Record<string, unknown>)[name]).toBeUndefined();
    }
    // ...and a type error, not merely absent at runtime:
    // @ts-expect-error `append_commitment` is not on the replicated allowlist
    expect(actor.append_commitment).toBeUndefined();
  });

  it("the allowlisted methods ARE present on all three actors", () => {
    const merkle = createReplicatedMerkleActor(MERKLE_ID, prodAgent());
    const nullifier = createReplicatedNullifierActor(MERKLE_ID, prodAgent());
    const pool = createReplicatedPoolActor(MERKLE_ID, prodAgent());
    const present = (a: unknown, names: readonly string[]) => {
      for (const n of names) {
        expect(typeof (a as Record<string, unknown>)[n]).toBe("function");
      }
    };
    present(merkle, REPLICATED_METHODS.merkle_tree);
    present(nullifier, REPLICATED_METHODS.nullifier_registry);
    present(pool, REPLICATED_METHODS.shielded_pool);
  });

  it("an undeclared name throws at actor construction, not at first call", () => {
    expect(() =>
      replicatedInterfaceFactory(GENERATED_IDL_FACTORIES.shielded_pool, ["withdraw_everything"])({
        IDL,
      }),
    ).toThrow(ReplicatedMethodNotDeclared);
  });
});

// ---------------------------------------------------------------------------
// AC-8b — the transport's own host-classifier gate
// ---------------------------------------------------------------------------

describe("AC-8b — the verified transport gates at the point of use", () => {
  it("allows a production host carrying the PINNED IC root key", () => {
    expect(() =>
      assertReplicatedTransportAllowed(agentAt("https://icp-api.io", MAINNET_ROOT_KEY)),
    ).not.toThrow();
  });

  it("REFUSES a production host whose agent fetched a root key", () => {
    for (const host of ["https://icp-api.io", "https://ic0.app", "https://app.stsh.fi"]) {
      expect(() =>
        assertReplicatedTransportAllowed(agentAt(host, FETCHED_ROOT_KEY)),
      ).toThrow(ReplicatedTransportRefused);
    }
  });

  it("REFUSES a production host whose agent has no root key yet (lazy fetch)", () => {
    expect(() =>
      assertReplicatedTransportAllowed(agentAt("https://ic0.app", null)),
    ).toThrow(ReplicatedTransportRefused);
  });

  it("allows loopback with a fetched replica root key — the intended local case", () => {
    for (const host of ["http://127.0.0.1:4943", "http://localhost:4943", "http://[::1]:4943"]) {
      expect(() =>
        assertReplicatedTransportAllowed(agentAt(host, FETCHED_ROOT_KEY)),
      ).not.toThrow();
    }
  });

  it("refuses at CONSTRUCTION, so a bad agent never yields an actor", () => {
    expect(() =>
      createReplicatedMerkleActor(MERKLE_ID, agentAt("https://ic0.app", FETCHED_ROOT_KEY)),
    ).toThrow(ReplicatedTransportRefused);
  });

  it("re-derives the decision on EVERY CALL — trust is not inherited from construction", async () => {
    // Construct while the agent is well-formed...
    const agent = agentAt("https://icp-api.io", MAINNET_ROOT_KEY);
    const actor = createReplicatedMerkleActor(MERKLE_ID, agent);
    // ...then the agent fetches a root key on the production host afterwards.
    (agent as { rootKey: Uint8Array | null }).rootKey = FETCHED_ROOT_KEY;
    await expect(actor.get_scan_head()).rejects.toThrow(ReplicatedTransportRefused);
    await expect(actor.get_scan_page(0n, 1n)).rejects.toThrow(ReplicatedTransportRefused);
  });

  it("classifies on the AGENT's OWN destination, not on a caller-supplied host", () => {
    // The gate takes exactly one argument: the agent. There is no `host`
    // parameter and no boolean for a caller to supply (S-25).
    expect(assertReplicatedTransportAllowed.length).toBe(1);
    const src = readFileSync(resolve(here, "../src/actors/replicated.ts"), "utf8");
    expect(src).toMatch(/isLocalHost\(destination\)/);
    expect(src).toMatch(/agent\.host\?\.toString\(\)/);
  });

  it("introduces NO root-key boolean anywhere in the module (S-25)", () => {
    const src = readFileSync(resolve(here, "../src/actors/replicated.ts"), "utf8");
    // Prose cites S-12/S-25 by name, so strip comments and judge the CODE.
    const code = src
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .split("\n")
      .filter((l) => !l.trimStart().startsWith("//"))
      .join("\n");
    // No declared parameter, field or const whose name is a root-key flag.
    expect(code).not.toMatch(/\b(fetchRootKey|shouldFetchRootKey|allowRootKey|rootKeyOk)\s*[?:]/);
    // And the module never fetches a root key itself.
    expect(code).not.toMatch(/\bfetchRootKey\s*\(/);
  });
});
