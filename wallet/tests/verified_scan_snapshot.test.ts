// @vitest-environment node
/**
 * WALLET-AUTH Gate 1 — the verified sweep's anchor, bounds and refusals.
 *
 * WHAT THIS SUITE PROVES, AND WHAT IT CANNOT. Every case here is a MOCK
 * (parent brief §7): a plain object satisfying `ScanActors`, with no agent and
 * no replica. It exercises the wallet's own logic — which head bounds the
 * sweep, what the mirror is compared against, what is refused and what is
 * persisted. It exercises NOTHING about certificate verification; that is the
 * agent's job and Gate 0's replica evidence
 * (`reviews/PACKET_HARDEN03_WALLET_AUTH_GATE0_563f8a4_2026-09-17.md`, G0-1/G0-2).
 *
 * THE RESIDUAL, stated here because a test file is where an over-claim does
 * the most damage: authenticating a reply closes the TRANSPORT-level attack —
 * a boundary node or a network position cannot strip, swap or shorten what the
 * canister signed. It does NOT close the dishonest-canister case. A lying pool
 * signs a fabricated accepted root as readily as a true one, and a pool that
 * rotates its `config_hash` or bumps its `security_epoch` mints a floor with
 * no history to contradict it. A test written as though these cases defeat a
 * malicious canister is a test that cannot fail honestly. That residual is
 * PROT-8 / H-02, deferred with a trigger.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { initPoseidon } from "../src/crypto/poseidon";
import {
  DeploymentAttestationUnavailableError,
  MAX_VERIFIED_SWEEP_LEAVES,
  MerkleBehindAcceptedRootError,
  SPENT_SET_DIGEST_DOMAIN,
  StaleSnapshotError,
  VerifiedAnchorMismatchError,
  VerifiedPathUnavailableError,
  VerifiedSweepTooLargeError,
  WrongDeploymentError,
  assertVerifiedActors,
  missingVerifiedActors,
  scanAndValidateVerified,
  spentSetDigest,
  syncMirror,
  type ScanActors,
} from "../src/crypto/scanner";
import {
  PER_PAGE_BUDGET_MS,
  VERIFIED_SWEEP_DEADLINE_MS,
  LEASE_DEADLINE_MS,
  createAuthorizationAuthority,
  leaseDeadlineFor,
  ActionNotAuthorizedError,
} from "../src/actors/authorization";
import { runVerifiedSweepViaWorker } from "../src/ui/app";
import {
  BINDING,
  DENOMINATIONS,
  MASTER,
  OTHER_MASTER,
  attestationFor,
  entryOf,
  hex,
  makeCandidate,
  rootOf,
  verifiedChain,
} from "./helpers/verifiedScanHarness";

const here = dirname(fileURLToPath(import.meta.url));
beforeAll(async () => {
  const wasmBytes = readFileSync(resolve(here, "../src/wasm/poseidon/stsh_poseidon_wasm_bg.wasm"));
  await initPoseidon(wasmBytes);
});

/**
 * The harness stores note plaintext directly as `encrypted_payload` and this is
 * the identity "decryptor" — the same convention `new5_forged_scan_head.test.ts`
 * uses. Ownership is still decided by the real crypto: the per-candidate loop
 * re-derives (rho, rseed, recipientPk) from MASTER and the note's nonce and
 * compares in constant time, so another wallet's note is rejected on its
 * fields, not on an inability to decrypt it.
 */
const decryptSelf = (bytes: Uint8Array): Uint8Array | null => bytes;

// ── The anchor ───────────────────────────────────────────────────────────────

describe("the anchor is the POOL's accepted root, not the merkle head", () => {
  it("control: an honest deployment verifies, and the evidence names every §5.2 source", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 40);
    const c1 = await makeCandidate(DENOMINATIONS[1], 41);
    const entries = [entryOf(c0), entryOf(c1)];
    const actors = await verifiedChain({ acceptedEntries: entries, securityEpoch: 9n });

    const result = await scanAndValidateVerified(actors, BINDING, decryptSelf, MASTER, {
      nowMs: () => 1_700_000_000_000,
    });

    expect(result.status).toBe("verified");
    if (result.status !== "verified") return;
    expect(result.outcome.notes).toHaveLength(2);
    expect(result.outcome.notes.every((n) => n.verified === true)).toBe(true);
    expect(result.metadata.config_hash).toBe(hex(new Uint8Array(32).fill(0x01)));
    expect(result.metadata.accepted_root).toBe(hex(await rootOf(entries)));
    expect(result.metadata.accepted_leaf_count).toBe("2");
    expect(result.metadata.security_epoch).toBe("9");
    expect(result.metadata.spent_count).toBe("0");
    expect(result.metadata.evidence_kind).toBe("replicated-replies");
    expect(result.metadata.validated_at_ms).toBe(1_700_000_000_000);
    expect(result.metadata.freshness_budget_ms).toBeGreaterThan(0);
  });

  it("sweeps [0, n_a) ONLY — leaves past the accepted head are not scanned", async () => {
    // The merkle tree is AHEAD of the accepted root, which is the normal case.
    // `[n_a, n_m)` is not spend authority and must not enter the mirror.
    const c0 = await makeCandidate(DENOMINATIONS[0], 42);
    const c1 = await makeCandidate(DENOMINATIONS[1], 43);
    const accepted = [entryOf(c0)];
    const full = [entryOf(c0), entryOf(c1)];
    const actors = await verifiedChain({
      acceptedEntries: accepted,
      headEntries: full,
      pageEntries: full,
    });

    const result = await scanAndValidateVerified(actors, BINDING, decryptSelf, MASTER);
    expect(result.status).toBe("verified");
    if (result.status !== "verified") return;
    expect(result.outcome.notes.map((n) => n.leafIndex)).toEqual([0n]);
    expect(result.outcome.mirrorHead.leafCount).toBe(1n);
    expect(result.metadata.accepted_leaf_count).toBe("1");
  });

  it("AC-2: n_m < n_a fails closed with MerkleBehindAcceptedRootError, nothing returned", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 44);
    const c1 = await makeCandidate(DENOMINATIONS[1], 45);
    const full = [entryOf(c0), entryOf(c1)];
    // The pool has accepted two leaves; the merkle canister only claims one.
    const actors = await verifiedChain({
      acceptedEntries: full,
      headEntries: [entryOf(c0)],
      pageEntries: full,
    });

    await expect(
      scanAndValidateVerified(actors, BINDING, decryptSelf, MASTER),
    ).rejects.toBeInstanceOf(MerkleBehindAcceptedRootError);
  });

  it("the anchor is root_a: pages that satisfy the MERKLE head but not the accepted root are refused", async () => {
    // This is the case that makes the anchor choice observable. The merkle
    // canister is internally consistent with itself — head root == mirror root
    // over its own pages — and the ORDINARY path accepts it. Only the pool's
    // accepted root disagrees, so only the verified path sees anything wrong.
    const mine = [entryOf(await makeCandidate(DENOMINATIONS[0], 46))];
    const theirs = [entryOf(await makeCandidate(DENOMINATIONS[0], 47, OTHER_MASTER))];
    const actors = await verifiedChain({
      acceptedEntries: mine, // the pool accepted MY history
      headEntries: theirs, // the merkle canister is self-consistent about ANOTHER
      pageEntries: theirs,
    });

    await expect(
      scanAndValidateVerified(actors, BINDING, decryptSelf, MASTER),
    ).rejects.toBeInstanceOf(VerifiedAnchorMismatchError);
  });

  it("n_a = 0 and an absent accepted head are both the pre-genesis state, not errors", async () => {
    const empty = await verifiedChain({ acceptedEntries: [], acceptedLeafCount: 0n });
    await expect(scanAndValidateVerified(empty, BINDING, decryptSelf, MASTER)).resolves.toEqual({
      status: "no-accepted-root",
    });

    const none = await verifiedChain({ acceptedEntries: [], acceptedLeafCount: null });
    await expect(scanAndValidateVerified(none, BINDING, decryptSelf, MASTER)).resolves.toEqual({
      status: "no-accepted-root",
    });
  });

  it("syncMirror refuses a bound above the head rather than clamping it", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 48);
    const actors = await verifiedChain({ acceptedEntries: [entryOf(c0)] });
    await expect(syncMirror(actors, { bound: 5n })).rejects.toBeInstanceOf(
      MerkleBehindAcceptedRootError,
    );
  });
});

// ── AC-3: no pool id means no verified path ──────────────────────────────────

describe("AC-3 — the verified path is unreachable without the pool reads", () => {
  it("names every missing read and refuses with VerifiedPathUnavailableError", async () => {
    const ordinary: ScanActors = {
      getScanHead: async () => ({ leafCount: 0n, root: new Uint8Array(32) }),
      getScanPage: async () => [],
      getNullifiersPage: async () => [],
      count: async () => 0n,
    };
    expect(missingVerifiedActors(ordinary)).toEqual([
      "getAcceptedRootHead",
      "getSecurityEpoch",
      "getDeploymentAttestation",
    ]);
    expect(() => assertVerifiedActors(ordinary)).toThrow(VerifiedPathUnavailableError);

    await expect(
      scanAndValidateVerified(ordinary, BINDING, decryptSelf, MASTER),
    ).rejects.toBeInstanceOf(VerifiedPathUnavailableError);
  });

  it("a PARTIAL set is still a refusal — there is no best-effort verified scan", async () => {
    const full = await verifiedChain({ acceptedEntries: [] });
    const partial = { ...full, getSecurityEpoch: undefined } as unknown as ScanActors;
    expect(missingVerifiedActors(partial)).toEqual(["getSecurityEpoch"]);
    expect(() => assertVerifiedActors(partial)).toThrow(VerifiedPathUnavailableError);
  });
});

// ── The attestation, the wiring and the ceiling ──────────────────────────────

describe("attestation, wiring and ceiling", () => {
  it("SSA C-10: an attestation failure is fail-closed, and NO other read is attempted", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 49);
    const actors = await verifiedChain({ acceptedEntries: [entryOf(c0)], attestationFails: true });

    await expect(
      scanAndValidateVerified(actors, BINDING, decryptSelf, MASTER),
    ).rejects.toBeInstanceOf(DeploymentAttestationUnavailableError);
    // Fail closed means the sweep never starts: the attestation is the FIRST
    // read, and nothing after it ran.
    expect(actors.log.calls).toEqual(["getDeploymentAttestation"]);
  });

  it("AC-11: an attestation naming other canisters aborts, naming every mismatch", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 50);
    const wrong = attestationFor(new Uint8Array(32).fill(0x01), {
      poolCanisterId: "aaaaa-aa",
      merkleCanisterId: BINDING.merkleCanisterId,
      nullifierCanisterId: BINDING.nullifierCanisterId,
    });
    const actors = await verifiedChain({ acceptedEntries: [entryOf(c0)], attestation: wrong });

    const err = await scanAndValidateVerified(actors, BINDING, decryptSelf, MASTER).catch((e) => e);
    expect(err).toBeInstanceOf(WrongDeploymentError);
    expect((err as WrongDeploymentError).mismatches).toHaveLength(1);
    expect((err as WrongDeploymentError).mismatches[0]).toContain("pool");
    // No sweep, no spent-set download: the abort is before any of it.
    expect(actors.log.calls).toEqual(["getDeploymentAttestation"]);
  });

  it("AC-14: a tree above MAX_VERIFIED_SWEEP_LEAVES refuses — no merkle-only fallback", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 51);
    const entries = [entryOf(c0)];
    const actors = await verifiedChain({ acceptedEntries: entries });

    const err = await scanAndValidateVerified(actors, BINDING, decryptSelf, MASTER, {
      maxLeaves: 0n, // ceiling of zero: one leaf is already above it
    }).catch((e) => e);

    expect(err).toBeInstanceOf(VerifiedSweepTooLargeError);
    expect((err as VerifiedSweepTooLargeError).acceptedLeafCount).toBe(1n);
    expect((err as VerifiedSweepTooLargeError).ceiling).toBe(0n);
    // Nothing was swept and nothing was downloaded. A fallback would show up
    // here as a getScanPage the refusal did not prevent.
    expect(actors.log.calls).not.toContain("getScanPage");
    expect(actors.log.calls).not.toContain("getNullifiersPage");
  });

  it("AC-14 / SSA F-2: the ceiling comparison is SCALE-SENSITIVE, not just zero-sensitive", async () => {
    // WHY THIS CASE EXISTS. The test above drives the seam with `maxLeaves: 0n`,
    // and zero is ABSORBING under multiplication: mutating the comparison to
    // `acceptedLeafCount > ceiling * 1000n` leaves `0 * 1000 = 0` and the test
    // still passes. SSA's M7 survived all 57 tests in the three new suites for
    // exactly that reason. A NON-ZERO ceiling that the tree exceeds by a
    // finite, small margin is what makes any scaling of the comparison visible.
    const c0 = await makeCandidate(DENOMINATIONS[0], 86);
    const c1 = await makeCandidate(DENOMINATIONS[1], 87);
    const entries = [entryOf(c0), entryOf(c1)];
    const actors = await verifiedChain({ acceptedEntries: entries });

    // Two accepted leaves against a ceiling of one: over by exactly one leaf.
    const err = await scanAndValidateVerified(actors, BINDING, decryptSelf, MASTER, {
      maxLeaves: 1n,
    }).catch((e) => e);
    expect(err).toBeInstanceOf(VerifiedSweepTooLargeError);
    expect((err as VerifiedSweepTooLargeError).acceptedLeafCount).toBe(2n);
    expect((err as VerifiedSweepTooLargeError).ceiling).toBe(1n);
    expect(actors.log.calls).not.toContain("getScanPage");
    expect(actors.log.calls).not.toContain("getNullifiersPage");
  });

  it("AC-14: the ceiling is an inclusive bound — exactly at it passes, one above refuses", async () => {
    // The comparison is `>`, so `n_a === ceiling` is allowed. Asserted rather
    // than assumed, because an off-by-one here silently refuses an honest tree.
    const c0 = await makeCandidate(DENOMINATIONS[0], 88);
    const c1 = await makeCandidate(DENOMINATIONS[1], 89);
    const actors = await verifiedChain({ acceptedEntries: [entryOf(c0), entryOf(c1)] });
    const atBound = await scanAndValidateVerified(actors, BINDING, decryptSelf, MASTER, {
      maxLeaves: 2n,
    });
    expect(atBound.status).toBe("verified");
  });

  it("SSA F-3: the ceiling is a DERIVED EXPRESSION in the source, and a literal fails this test", () => {
    // WHAT THE OLD VERSION OF THIS TEST ACTUALLY CHECKED. It said in its own
    // body "if someone edits the ceiling to a literal, this fails", and it did
    // not: SSA replaced the expression with `export const
    // MAX_VERIFIED_SWEEP_LEAVES = 92_500n;` and the suite stayed green,
    // because value equality cannot distinguish a derivation from its result.
    //
    // So this test now has two halves that check two different things:
    //
    //   (a) the INPUTS still produce the pinned value — the drift lock, which
    //       bites when Gate 0's measurement or the deadline moves;
    //   (b) the SOURCE still expresses the derivation — the lock the comment
    //       claimed, which can only be checked by reading the declaration.
    //
    // (b) is a source scan and is named as one. It is the weaker kind of
    // evidence, and it is here because it is the only kind that can catch the
    // thing (a) structurally cannot.
    const pagesInBudget = Math.floor(VERIFIED_SWEEP_DEADLINE_MS / PER_PAGE_BUDGET_MS);
    expect(PER_PAGE_BUDGET_MS).toBe(Math.ceil((1_244 * 26) / 10));
    expect(MAX_VERIFIED_SWEEP_LEAVES).toBe(BigInt(pagesInBudget) * 500n);
    expect(MAX_VERIFIED_SWEEP_LEAVES).toBe(92_500n);

    const src = readFileSync(resolve(here, "../src/crypto/scanner.ts"), "utf8");
    const decl = /export const MAX_VERIFIED_SWEEP_LEAVES\s*=\s*([^;]+);/.exec(src);
    expect(decl).not.toBeNull();
    const rhs = decl![1].replace(/\s+/g, " ").trim();
    // A bare bigint literal — `92_500n`, `92500n` — is exactly what C-3 forbade.
    expect(rhs).not.toMatch(/^[0-9_]+n$/);
    expect(rhs).toContain("VERIFIED_SWEEP_DEADLINE_MS");
    expect(rhs).toContain("PER_PAGE_BUDGET_MS");
    expect(rhs).toContain("DEFAULT_PAGE_SIZE");
  });
});

// ── Payload substitution / omission / spent-set stability ────────────────────

describe("page-level attacks under the verified anchor", () => {
  it("AC-5: a payload swapped for another wallet's does not yield a complete verified sweep", async () => {
    // The merkle leaf is a Poseidon commitment over NOTE FIELDS. It is NOT a
    // commitment to the encrypted payload bytes, so a swapped payload beside a
    // correct leaf is not caught by the leaf itself — it is caught because the
    // recomputed leaf for the swapped note does not match, and the note is
    // quarantined instead of entering the balance.
    const mine = await makeCandidate(DENOMINATIONS[0], 52);
    const theirs = await makeCandidate(DENOMINATIONS[1], 53, OTHER_MASTER);
    const spliced = { payload: theirs.plaintext, leaf: mine.leaf };
    const actors = await verifiedChain({
      acceptedEntries: [spliced],
      acceptedRoot: await rootOf([spliced]),
    });

    const result = await scanAndValidateVerified(actors, BINDING, decryptSelf, MASTER);
    expect(result.status).toBe("verified");
    if (result.status !== "verified") return;
    // Nothing spendable was minted out of the substitution.
    expect(result.outcome.notes).toHaveLength(0);
  });

  it("AC-6: a truncated encrypted_payload is quarantined, never silently dropped", async () => {
    const mine = await makeCandidate(DENOMINATIONS[0], 54);
    const truncated = { payload: mine.plaintext.slice(0, 8), leaf: mine.leaf };
    const actors = await verifiedChain({
      acceptedEntries: [truncated],
      acceptedRoot: await rootOf([truncated]),
    });

    const result = await scanAndValidateVerified(actors, BINDING, decryptSelf, MASTER);
    expect(result.status).toBe("verified");
    if (result.status !== "verified") return;
    expect(result.outcome.notes).toHaveLength(0);
  });

  it("AC-7: a spent set that changes across the sweep fails closed with StaleSnapshotError", async () => {
    const c0 = await makeCandidate(DENOMINATIONS[0], 55);
    const entries = [entryOf(c0)];
    let served = 0;
    const base = await verifiedChain({ acceptedEntries: entries });
    // `count` answers a different number every time it is asked, so the
    // before/after check can never stabilise. The bound is
    // MAX_FULL_SCAN_ATTEMPTS, not an unbounded retry.
    const unstable: ScanActors = { ...base, count: async () => BigInt(served++) };

    await expect(
      scanAndValidateVerified(unstable, BINDING, decryptSelf, MASTER),
    ).rejects.toBeInstanceOf(StaleSnapshotError);
  });

  it("AC-12: decrypting a note causes no extra wire call and does not alter the page plan", async () => {
    const mine = [entryOf(await makeCandidate(DENOMINATIONS[0], 56))];
    const theirs = [entryOf(await makeCandidate(DENOMINATIONS[0], 57, OTHER_MASTER))];

    const a = await verifiedChain({ acceptedEntries: mine });
    const b = await verifiedChain({ acceptedEntries: theirs });
    const ra = await scanAndValidateVerified(a, BINDING, decryptSelf, MASTER);
    const rb = await scanAndValidateVerified(b, BINDING, decryptSelf, MASTER);

    expect(ra.status).toBe("verified");
    expect(rb.status).toBe("verified");
    if (ra.status !== "verified" || rb.status !== "verified") return;
    // One run decrypts everything, the other decrypts nothing.
    expect(ra.outcome.notes).toHaveLength(1);
    expect(rb.outcome.notes).toHaveLength(0);
    // The wire traffic is IDENTICAL in count and in order.
    expect(a.log.calls).toEqual(b.log.calls);
  });
});

// ── The spent-set digest ─────────────────────────────────────────────────────

describe("the spent-set digest is a local summary, with a stated preimage", () => {
  it("is a function of the SET, not of the order the elements arrived in", async () => {
    const a = new Uint8Array(32).fill(0x02);
    const b = new Uint8Array(32).fill(0x05);
    const forward = await spentSetDigest(new Set([hex(a), hex(b)]));
    const backward = await spentSetDigest(new Set([hex(b), hex(a)]));
    expect(hex(forward)).toBe(hex(backward));
  });

  it("binds the count, so a truncated set cannot collide with a shorter honest one", async () => {
    const a = new Uint8Array(32).fill(0x02);
    const b = new Uint8Array(32).fill(0x05);
    const two = await spentSetDigest(new Set([hex(a), hex(b)]));
    const one = await spentSetDigest(new Set([hex(a)]));
    expect(hex(two)).not.toBe(hex(one));
  });

  it("reproduces its own documented preimage, byte for byte", async () => {
    const a = new Uint8Array(32).fill(0x02);
    const b = new Uint8Array(32).fill(0x05);
    const domain = new TextEncoder().encode(SPENT_SET_DIGEST_DOMAIN);
    const preimage = new Uint8Array(domain.length + 8 + 64);
    preimage.set(domain, 0);
    new DataView(preimage.buffer, domain.length, 8).setBigUint64(0, 2n, true);
    preimage.set(a, domain.length + 8);
    preimage.set(b, domain.length + 8 + 32);
    const expected = new Uint8Array(await crypto.subtle.digest("SHA-256", preimage));

    expect(hex(await spentSetDigest(new Set([hex(a), hex(b)])))).toBe(hex(expected));
  });
});

// ── R-1: the read lease ──────────────────────────────────────────────────────

describe("R-1 — the verifiedScan read lease", () => {
  it("SSA C-4 / AC-18: an unauthorised sweep is refused by identity, before any wire call", async () => {
    const authority = createAuthorizationAuthority({ now: () => 0 });
    const c0 = await makeCandidate(DENOMINATIONS[0], 58);
    const actors = await verifiedChain({ acceptedEntries: [entryOf(c0)] });

    // No token at all.
    const missing = (() => {
      try {
        authority.consume(undefined, "verifiedScan");
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(missing).toBeInstanceOf(ActionNotAuthorizedError);
    expect((missing as ActionNotAuthorizedError).action).toBe("verifiedScan");

    // A token for a DIFFERENT action is not a verified-scan token.
    const spendLease = authority.mintLease(["privateSpend"]);
    expect(() => spendLease.draw("verifiedScan")).toThrow(ActionNotAuthorizedError);

    // SSA F-4: the zero-wire-call claim, ACTUALLY DRIVEN. The previous version
    // of this line asserted `actors.log.calls` was empty after constructing
    // `actors` and never handing them to anything — true by construction, and
    // therefore worth nothing. The harness is now handed to the real UI route
    // with a lease that does not name the action: the route must refuse at the
    // draw, before the seam it was given is ever called.
    let seamCalls = 0;
    const refused = await runVerifiedSweepViaWorker({
      scanNotes: async () => {
        seamCalls += 1;
        throw new Error("the seam must not be reached");
      },
      cache: { update: async () => { throw new Error("the cache must not be touched"); } } as never,
      lease: spendLease,
      merkleCanisterId: BINDING.merkleCanisterId,
      nullifierCanisterId: BINDING.nullifierCanisterId,
      poolCanisterId: BINDING.poolCanisterId,
      host: "http://127.0.0.1:4943",
      vetKeySerialized: new Uint8Array(48),
      masterNoteSecret: MASTER,
    }).catch((e) => e);
    expect(refused).toBeInstanceOf(ActionNotAuthorizedError);
    expect((refused as ActionNotAuthorizedError).action).toBe("verifiedScan");
    expect(seamCalls).toBe(0);
    expect(actors.log.calls).toEqual([]);
  });

  it("a verifiedScan lease draws and consumes exactly one single-use token", () => {
    const authority = createAuthorizationAuthority({ now: () => 0 });
    const lease = authority.mintLease(["verifiedScan"]);
    const token = lease.draw("verifiedScan");
    authority.consume(token, "verifiedScan");
    expect(() => authority.consume(token, "verifiedScan")).toThrow(ActionNotAuthorizedError);
  });

  it("SSA C-3: the read lease runs on its OWN deadline, not the spend-derived one", () => {
    expect(leaseDeadlineFor(["verifiedScan"])).toBe(VERIFIED_SWEEP_DEADLINE_MS);
    expect(VERIFIED_SWEEP_DEADLINE_MS).not.toBe(LEASE_DEADLINE_MS);
    // The six state-changing actions are untouched by the table's existence.
    for (const action of [
      "shieldDeposit",
      "retryDepositCommitment",
      "privateSpend",
      "retryPrivateSpendPayout",
      "transfer",
      "approve",
    ] as const) {
      expect(leaseDeadlineFor([action])).toBe(LEASE_DEADLINE_MS);
    }
    // A mixed lease gets the TIGHTEST deadline of the actions it names.
    expect(leaseDeadlineFor(["privateSpend", "verifiedScan"])).toBe(
      Math.min(LEASE_DEADLINE_MS, VERIFIED_SWEEP_DEADLINE_MS),
    );
  });

  it("expiry is enforced on a verifiedScan lease exactly as on a spend lease", () => {
    let now = 0;
    const authority = createAuthorizationAuthority({ now: () => now });
    const lease = authority.mintLease(["verifiedScan"]);
    now = VERIFIED_SWEEP_DEADLINE_MS; // inclusive boundary
    expect(() => lease.draw("verifiedScan")).toThrow(/expired/);
  });
});

// ── AC-19: the verified path stays ANONYMOUS ─────────────────────────────────

describe("AC-19 / SSA C-5 — the scan agent carries no identity", () => {
  it("the injected agent factory is handed { host } and nothing else", async () => {
    (globalThis as unknown as { self: unknown }).self = globalThis;
    const worker = await import("../src/workers/scanner.worker");

    const captured: Record<string, unknown>[] = [];
    let fetched = false;
    const fake = async (opts: { host: string }) => {
      captured.push(opts as Record<string, unknown>);
      return {
        host: new URL(opts.host),
        rootKey: null,
        fetchRootKey: async () => {
          fetched = true;
        },
      } as unknown as Awaited<ReturnType<typeof worker.defaultScanAgentFactory>>;
    };

    await worker.buildScanAgent("https://icp-api.io", fake);
    expect(captured).toHaveLength(1);
    // The assertion is on the KEYS, not on `identity === undefined`: an option
    // object that merely happens to hold `undefined` today is one refactor away
    // from holding a session identity.
    expect(Object.keys(captured[0])).toEqual(["host"]);
    // S-12: no root key on a production host.
    expect(fetched).toBe(false);

    await worker.buildScanAgent("http://127.0.0.1:4943", fake);
    expect(Object.keys(captured[1])).toEqual(["host"]);
    // Loopback: the host classifier — and only it — authorises the fetch.
    expect(fetched).toBe(true);
  });

  it("STATIC: the worker source contains no identity and no root-key input", () => {
    const raw = readFileSync(resolve(here, "../src/workers/scanner.worker.ts"), "utf8");
    // Comments are stripped first: the module's own prose EXPLAINS why there is
    // no identity here, and a scan that tripped on the explanation would push
    // the next author to delete the explanation rather than keep the property.
    const source = raw.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    // S-25: nothing caller-supplied decides the root key, and nothing on the
    // postMessage boundary is named for one.
    expect(source).not.toMatch(/\bidentity\b/);
    expect(source).not.toMatch(/fetchRootKey\s*[:?]/); // a FIELD named fetchRootKey
    // The only fetchRootKey call is the one the host classifier guards.
    const calls = source.match(/fetchRootKey\(\)/g) ?? [];
    expect(calls).toHaveLength(1);
    expect(source).toMatch(/if \(isLocalHost\(host\)\) await agent\.fetchRootKey\(\);/);
  });

  it("STATIC: ScannerRequest gained a pool id and NO boolean", () => {
    const source = readFileSync(resolve(here, "../src/workers/scanner.worker.ts"), "utf8");
    const iface = source.slice(
      source.indexOf("export interface ScannerRequest"),
      source.indexOf("export type ScannerResponse"),
    );
    expect(iface).toContain("poolCanisterId?: string;");
    expect(iface).not.toMatch(/:\s*boolean/);
  });
});

// ── AC-18: the lease is consumed before the worker exists ────────────────────

describe("AC-18 — runScannerWorker refuses an unauthorised verified sweep first", () => {
  it("throws by identity before constructing a Worker or posting a message", async () => {
    const app = await import("../src/ui/app");
    const authority = createAuthorizationAuthority({ now: () => 0 });

    const input = {
      merkleCanisterId: BINDING.merkleCanisterId,
      nullifierCanisterId: BINDING.nullifierCanisterId,
      poolCanisterId: BINDING.poolCanisterId,
      host: "https://icp-api.io",
      vetKeySerialized: new Uint8Array(48),
      masterNoteSecret: MASTER,
      fromIndex: 0n,
    };

    // No token: this must throw BEFORE `new Worker(...)`, which is why the
    // assertion is that it throws at all — a `Worker` constructor in this
    // harness would fail with something else entirely.
    let thrown: unknown = null;
    try {
      app.runScannerWorker(input, authority);
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(ActionNotAuthorizedError);
    expect((thrown as ActionNotAuthorizedError).action).toBe("verifiedScan");
  });

  it("the six existing AuthorizedActions are unchanged, and verifiedScan is the only addition", async () => {
    const source = readFileSync(resolve(here, "../src/actors/authorization.ts"), "utf8");
    const block = source.slice(
      source.indexOf("export type StateChangingAction"),
      source.indexOf("export type ReadLeaseAction"),
    );
    expect(block).toContain('| "shieldDeposit"');
    expect(block).toContain('| "retryDepositCommitment"');
    expect(block).toContain('| "privateSpend"');
    expect(block).toContain('| "retryPrivateSpendPayout"');
    expect(block).toContain('| "transfer"');
    expect(block).toContain('| "approve"');
    expect(source).toContain('export type ReadLeaseAction = "verifiedScan";');
  });
});

// ── The registered UI copy ───────────────────────────────────────────────────

describe("the registered verified-scan strings", () => {
  it("name the residual wherever they use the word verified (SSA C-9)", async () => {
    const app = await import("../src/ui/app");
    const s = app.VERIFIED_SCAN_STRINGS;
    expect(s.observation).toContain("observation, not a guarantee");
    expect(s.observation).toContain("dishonest pool");
    // The lease copy says what the user is agreeing to, and says the wallet is
    // still anonymous — the one privacy property R-1 must not be read to weaken.
    expect(s.lease).toContain("anonymously");
    expect(s.lease).toContain("no identity is attached");
    // The ceiling is the PROT-8 trigger, and the copy does not offer a bigger one.
    expect(s.treeTooLarge).toContain("different design");
    // The rollback copy warns about what the reset costs the user.
    expect(s.rollbackRefused).toContain("would stop being visible");
  });

  it("maps each typed failure onto its own string", async () => {
    const app = await import("../src/ui/app");
    const { NoAcceptedRootYetError } = await import("../src/crypto/scanner");
    const { VerifiedFloorRollbackError } = await import("../src/storage/noteCache");
    expect(app.verifiedScanMessage(new NoAcceptedRootYetError())).toBe(
      app.VERIFIED_SCAN_STRINGS.noAcceptedRoot,
    );
    expect(app.verifiedScanMessage(new VerifiedFloorRollbackError("k", 1n, 2n, false))).toBe(
      app.VERIFIED_SCAN_STRINGS.rollbackRefused,
    );
    expect(app.verifiedScanMessage(new VerifiedSweepTooLargeError(1n, 0n))).toBe(
      app.VERIFIED_SCAN_STRINGS.treeTooLarge,
    );
    expect(app.verifiedScanMessage(new Error("network"))).toBe(
      app.VERIFIED_SCAN_STRINGS.unavailable,
    );
    expect(app.VERIFIED_SCAN_LEAF_CEILING).toBe(MAX_VERIFIED_SWEEP_LEAVES);
  });
});
