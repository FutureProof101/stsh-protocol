/**
 * J-17d — the II delegation-chain ceiling.
 *
 * Internet Identity 2.0 returns a THREE-delegation chain: the leaf honours the
 * 8h `maxTimeToLive` this app requests, while the two upstream delegations are
 * II's own 30-day internal ones. The old per-link ceiling rejected every real
 * mainnet login. These arms hold the corrected policy: the ceiling applies to
 * the chain's MINIMUM expiration (the effective session lifetime), the SDK's
 * own `isDelegationValid` is still required, an empty chain is "anonymous"
 * before any reduce (SSA B-1), and a scoped delegation is refused (SSA B-2).
 *
 * Chains here are REAL Ed25519 chains built with `DelegationChain.create`
 * ({ previous }), not mocks — same discipline as session_a1.
 */
import { describe, expect, it } from "vitest";

import { Principal } from "@dfinity/principal";
import {
  DelegationChain,
  DelegationIdentity,
  Ed25519KeyIdentity,
} from "@dfinity/identity";
import type { Identity, SignIdentity } from "@dfinity/agent";

import {
  createWalletAuth,
  hasScopedDelegation,
  verifyIdentity,
  SCOPED_DELEGATION_REFUSAL,
  type AuthClientLike,
  type DelegationIdentityLike,
} from "../src/session/auth";

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/**
 * Build a real delegation chain of `expiriesMs.length` links. The LAST entry is
 * the leaf (the session key this app holds); earlier entries are upstream
 * delegations, exactly the shape II 2.0 returns.
 */
async function makeChain(
  expiriesMs: number[],
  targets?: Principal[],
): Promise<{ identity: DelegationIdentity; chain: DelegationChain }> {
  const session = Ed25519KeyIdentity.generate();
  let signer: SignIdentity = Ed25519KeyIdentity.generate();
  let chain: DelegationChain | undefined;
  for (let i = 0; i < expiriesMs.length; i += 1) {
    const last = i === expiriesMs.length - 1;
    const next = last ? session : Ed25519KeyIdentity.generate();
    chain = await DelegationChain.create(
      signer,
      next.getPublicKey(),
      new Date(Date.now() + expiriesMs[i]),
      { previous: chain, targets },
    );
    signer = next;
  }
  return { identity: DelegationIdentity.fromDelegation(session, chain!), chain: chain! };
}

/** The realistic II 2.0 shape: two 30-day upstream links, an 8h leaf. */
function ii2Chain(
  leafMs: number,
): Promise<{ identity: DelegationIdentity; chain: DelegationChain }> {
  return makeChain([30 * DAY_MS, 30 * DAY_MS, leafMs]);
}

/** Force `targets` to a literal value the SDK API cannot produce (e.g. null). */
function setTargets(chain: DelegationChain, index: number, value: unknown): void {
  (chain.delegations[index].delegation as unknown as { targets: unknown }).targets = value;
}

describe("J-17d: the ceiling applies to the effective session lifetime", () => {
  it("accepts the realistic II 2.0 chain — 8h leaf under two 30-day upstream links", async () => {
    const { identity } = await ii2Chain(8 * HOUR_MS - 60_000);
    expect(identity.getDelegation().delegations).toHaveLength(3);
    expect(verifyIdentity(identity)).toBe("valid");
  });

  it("refuses the same chain when the LEAF itself exceeds the ceiling (9h)", async () => {
    const { identity } = await ii2Chain(9 * HOUR_MS);
    expect(verifyIdentity(identity)).toBe("expired");
  });

  it("still refuses a chain whose minimum is expired (isDelegationValid is not bypassed)", async () => {
    const { identity } = await makeChain([30 * DAY_MS, 30 * DAY_MS, -1000]);
    expect(verifyIdentity(identity)).toBe("expired");
  });

  it("takes the MINIMUM, not the leaf: a long leaf behind a short upstream link is valid", async () => {
    // Upstream expires in 1h, leaf in 30 days: the session is usable for 1h.
    const { identity } = await makeChain([HOUR_MS, 30 * DAY_MS]);
    expect(verifyIdentity(identity)).toBe("valid");
  });
});

describe("J-17d: empty chain (SSA B-1)", () => {
  it("verdicts an EMPTY delegation chain as anonymous, not valid", async () => {
    const { identity, chain } = await ii2Chain(4 * HOUR_MS);
    (chain as unknown as { _delegations: unknown[] })._delegations = [];
    Object.defineProperty(chain, "delegations", { value: [], configurable: true });
    expect(identity.getDelegation().delegations).toHaveLength(0);
    expect(verifyIdentity(identity)).toBe("anonymous");
  });
});

describe("J-17d: scoped delegations (SSA B-2)", () => {
  it("targets absent (undefined) is valid", async () => {
    const { identity, chain } = await ii2Chain(4 * HOUR_MS);
    expect(chain.delegations.every((d) => d.delegation.targets === undefined)).toBe(true);
    expect(verifyIdentity(identity)).toBe("valid");
    expect(hasScopedDelegation(identity)).toBe(false);
  });

  it("targets explicitly null is valid (null == undefined under the != null test)", async () => {
    const { identity, chain } = await ii2Chain(4 * HOUR_MS);
    setTargets(chain, 2, null);
    expect(verifyIdentity(identity)).toBe("valid");
    expect(hasScopedDelegation(identity)).toBe(false);
  });

  it("targets [] is REFUSED — scoped to nothing is still scoped", async () => {
    const { identity, chain } = await ii2Chain(4 * HOUR_MS);
    setTargets(chain, 2, []);
    expect(verifyIdentity(identity)).toBe("expired");
    expect(hasScopedDelegation(identity)).toBe(true);
  });

  it("targets [principal] is REFUSED", async () => {
    const { identity, chain } = await ii2Chain(4 * HOUR_MS);
    setTargets(chain, 2, [Principal.fromText("aaaaa-aa")]);
    expect(verifyIdentity(identity)).toBe("expired");
    expect(hasScopedDelegation(identity)).toBe(true);
  });

  it("a scoped UPSTREAM link is refused too, not just the leaf", async () => {
    const { identity, chain } = await ii2Chain(4 * HOUR_MS);
    setTargets(chain, 0, [Principal.fromText("aaaaa-aa")]);
    expect(verifyIdentity(identity)).toBe("expired");
  });

  it("login() surfaces the scoped-delegation refusal copy where login errors are shown", async () => {
    const { identity, chain } = await ii2Chain(4 * HOUR_MS);
    setTargets(chain, 2, [Principal.fromText("aaaaa-aa")]);
    let loggedOut = false;
    const client: AuthClientLike = {
      isAuthenticated: async () => true,
      getIdentity: () => identity as unknown as Identity,
      login: async (options) => {
        options.onSuccess?.();
      },
      logout: async () => {
        loggedOut = true;
      },
    };
    const auth = await createWalletAuth({ kind: "production" } as never, () => {}, {
      createClient: async () => client,
    });
    await expect(auth.login()).rejects.toThrow(SCOPED_DELEGATION_REFUSAL);
    expect(SCOPED_DELEGATION_REFUSAL).toMatch(/scoped delegation not supported/);
    expect(loggedOut).toBe(true);
  });
});

describe("J-17d: legacy single-delegation chains are unchanged", () => {
  it("single 4h delegation valid, single 9h refused, single expired refused", async () => {
    expect(verifyIdentity((await makeChain([4 * HOUR_MS])).identity)).toBe("valid");
    expect(verifyIdentity((await makeChain([9 * HOUR_MS])).identity)).toBe("expired");
    expect(verifyIdentity((await makeChain([-1000])).identity)).toBe("expired");
  });

  it("a delegation-less identity is still anonymous", () => {
    const plain = { getPrincipal: () => Principal.fromText("aaaaa-aa") } as unknown as Identity;
    expect(verifyIdentity(plain)).toBe("anonymous");
    expect(hasScopedDelegation(plain)).toBe(false);
    const typed: DelegationIdentityLike | null = null;
    expect(typed).toBeNull();
  });
});
