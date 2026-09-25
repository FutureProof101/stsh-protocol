// @vitest-environment jsdom
/**
 * WALLET-SHIELD-LAYER1 (AD-8) — shield acquires the vetKey through the SESSION's
 * Layer-1 provider, like scan and spend: zero derives on an enrolled device, and
 * on a new device exactly one derive that enrols it, then zero.
 *
 * APP-LEVEL ON PURPOSE. `w_vetkeys_layer1_d1b` proves the Layer-1 provider in
 * isolation; AD-8 slipped because nothing proved the APP hands that provider to
 * shield. So these arms mount the real app with NO `deps.fetchKeys` seam — the
 * only way shield can reach Layer 1 is `sessionFetchKeys` from login. Derives
 * are counted where they become canister calls (`getEncryptedVetkey`).
 *
 * Balance stays 0 in every arm, so the VETKEYS-AGE-2MIN login-time priming
 * (gated on a funded balance) never contributes to the count.
 */

import { describe, expect, it, vi } from "vitest";
import { Principal } from "@dfinity/principal";

// The Layer-2 derive, as a PASS-THROUGH: it makes the same canister calls the
// real one does (so every derive is counted at the canister) and returns a real
// fixture VetKey, because real BLS decryption needs a real vetKD reply. Both
// the shield flow's own fallback and Layer 1's internal fallback import this.
vi.mock("../src/crypto/vetkeys", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/crypto/vetkeys")>();
  const { VetKey } = await import("@dfinity/vetkeys");
  return {
    ...real,
    fetchUserVetKey: async (canister: import("../src/crypto/vetkeys").VetkeysCanister) => {
      await canister.getVetkeyVerificationKey();
      const derived = await canister.getEncryptedVetkey(new Uint8Array(48).fill(2));
      const hex =
        "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
      const bytes = new Uint8Array((hex.match(/../g) ?? []).map((b) => parseInt(b, 16)));
      return { vetKey: VetKey.deserialize(bytes), verificationKey: {} as never, remaining: derived.remaining };
    },
  };
});
// jsdom has no IndexedDB: an in-memory device store the arms can pre-seed.
const deviceStore = vi.hoisted(() => new Map<string, unknown>());
vi.mock("../src/storage/deviceStore", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/storage/deviceStore")>();
  return {
    ...real,
    loadDeviceIdentity: async (principalText: string) => deviceStore.get(principalText) ?? null,
    saveDeviceIdentity: async (principalText: string, identity: unknown) => {
      deviceStore.set(principalText, identity);
    },
  };
});
vi.mock("../src/session/domainGuard", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/session/domainGuard")>();
  return {
    ...real,
    assertDeploymentBinding: async () => ({ hash: new Uint8Array(32), wiring: {} as never }),
  };
});

import { VetKey } from "@dfinity/vetkeys";

import { mountApp, type AppDeps } from "../src/ui/app";
import { VetkeysCallError, type VetkeysCanister } from "../src/crypto/vetkeys";
import { exportDevicePublicKeys, generateDeviceKeys } from "../src/crypto/devices";
import { wrapVetKeyForDevice } from "../src/crypto/layer1";
import { DEFAULT_VETKEYS_CANISTER_ID, PRODUCTION_ORIGIN } from "../src/session/config";
import type { AuthSession, WalletAuth } from "../src/session/auth";
import type { MutationActors, ReadActors, ShieldedActors } from "../src/session/session";
import type { TokenCanister } from "../src/actors/token";
import type { ScanOutcome } from "../src/crypto/scanner";
import type { AppContext } from "../src/ui/context";
import { memoryJournalStore } from "./helpers/memoryJournalStore";
import { memoryHarness } from "./helpers/cacheL4";
import { unusedIcrc2 } from "./helpers/tokenStubs";

const USER = Principal.fromUint8Array(new Uint8Array(10).fill(0x33));
const VETKEYS_ID = Principal.fromText(DEFAULT_VETKEYS_CANISTER_ID);
const CONFIG: [string, string] = ["stsh.wallet.notes.v1", "key_1"];
/** 1_000 STSH — the smallest fixed denomination (anti-drift law 1), in e8s. */
const SHIELD_AMOUNT = 100_000_000_000n;

const fromHex = (s: string): Uint8Array =>
  new Uint8Array((s.match(/../g) ?? []).map((b) => parseInt(b, 16)));
const FIXTURE_VETKEY = () =>
  VetKey.deserialize(
    fromHex(
      "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    ),
  );
/** BLS12-381 G2 generator, compressed — a valid `DerivedPublicKey`. */
const G2_GENERATOR_HEX =
  "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e" +
  "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

const EMPTY_OUTCOME: ScanOutcome = {
  notes: [],
  scannedUpTo: 0n,
  mirrorHead: { leafCount: 0n, root: new Uint8Array(32) },
  quarantine: { total: 0, ring: [] },
  spentSet: new Set(),
};

/** Balance 0: the funded-login priming path stays shut (see header). */
const token: TokenCanister = {
  balanceOf: async () => 0n,
  metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
  fee: async () => 0n,
};

function fakeSession(): AuthSession {
  return {
    identity: { getPrincipal: () => USER } as unknown as AuthSession["identity"],
    principal: USER,
  };
}

/** A vetkeys canister that COUNTS derives and registrations and stores one envelope. */
function countingVetkeys(initial: Uint8Array | null) {
  let stored = initial;
  const calls = { derives: 0, registrations: 0, envelopeReads: 0 };
  const canister: VetkeysCanister = {
    async getConfig() {
      return CONFIG;
    },
    async getVetkeyVerificationKey() {
      // FREE, not a derivation — and a real G2 point so the Layer-1 path's
      // `DerivedPublicKey.deserialize` succeeds for the right reason.
      return fromHex(G2_GENERATOR_HEX);
    },
    async getEncryptedVetkey() {
      calls.derives += 1;
      return { encryptedKey: new Uint8Array(192).fill(1), remaining: 4 };
    },
    async registerDevice(_id, _enc, _sign, envelope) {
      calls.registrations += 1;
      stored = envelope;
    },
    async getWrappedSecret() {
      calls.envelopeReads += 1;
      if (stored === null) {
        throw new VetkeysCallError("get_wrapped_secret", { UnknownDevice: null });
      }
      return stored;
    },
    async revokeDevice(): Promise<never> {
      throw new Error("revokeDevice not scripted");
    },
    async replaceEnvelope(): Promise<never> {
      throw new Error("replaceEnvelope not scripted");
    },
    async listDevices() {
      return [];
    },
  };
  return { canister, calls };
}

/**
 * The app harness. NO `fetchKeys` — deliberately: the arms must prove shield
 * reaches Layer 1 through the session, with no seam propping it up. The flow
 * aborts at the fee snapshot, the first call AFTER key acquisition, so a
 * counted fee-params call proves the key was obtained.
 */
function harness(vetkeys: VetkeysCanister): { deps: AppDeps; feeParamsCalls: () => number } {
  let feeParamsCalls = 0;
  const deps: AppDeps = {
    origin: PRODUCTION_ORIGIN,
    loadLaunchOrigin: async () => PRODUCTION_ORIGIN,
    buildReadActors: async () =>
      ({
        token,
        staking: { getStakePositions: async () => [], getPendingRewards: async () => 0n },
        vesting: { getSchedule: async () => null, claimableAmount: async () => 0n },
      }) satisfies ReadActors,
    buildMutationActors: async () =>
      ({
        token: {
          transfer: async () => {
            throw new Error("not scripted");
          },
          ...unusedIcrc2,
        },
      }) satisfies MutationActors,
    buildShieldedActors: async () =>
      ({
        pool: {
          getGovernanceFeeParams: async () => {
            feeParamsCalls += 1;
            throw new Error("fee params reached (counted)");
          },
        } as unknown as ShieldedActors["pool"],
        vetkeys,
      }) satisfies ShieldedActors,
    createJournalStore: async () => memoryJournalStore(),
    createAuth: async () => {
      const auth: WalletAuth = {
        restore: async () => null,
        login: async () => fakeSession(),
        logout: async () => undefined,
        verify: () => "valid",
      };
      return auth;
    },
    createCacheStore: async () => (await memoryHarness()).store,
    scanNotes: async () => EMPTY_OUTCOME,
    sleep: async () => undefined,
  };
  expect("fetchKeys" in deps, "the harness must not stub the key fetch").toBe(false);
  return { deps, feeParamsCalls: () => feeParamsCalls };
}

async function settle(): Promise<void> {
  for (let i = 0; i < 25; i += 1) await new Promise((r) => setTimeout(r, 0));
}

async function loggedIn(deps: AppDeps): Promise<AppContext> {
  window.location.hash = "#/account";
  const node = document.createElement("div");
  document.body.append(node);
  const ctx = await mountApp(node, {}, deps);
  await ctx.login();
  await settle();
  await ctx.unlockNoteCache("pw");
  return ctx;
}

describe("WALLET-SHIELD-LAYER1 — shield uses the session's Layer-1 envelope", () => {
  it("(a) ENROLLED device: a shield makes ZERO derives and opens the stored envelope", async () => {
    deviceStore.clear();
    // Pre-seed this browser as an enrolled device for USER, and the canister
    // with the envelope sealed to it — the steady state after enrolment.
    const keys = await generateDeviceKeys();
    const pub = await exportDevicePublicKeys(keys);
    deviceStore.set(USER.toText(), {
      deviceId: "dev-enrolled",
      encSpki: pub.encSpki,
      signSpki: pub.signSpki,
      encPrivate: keys.encryption.privateKey,
      encPublic: keys.encryption.publicKey,
      signPrivate: keys.signing.privateKey,
      signPublic: keys.signing.publicKey,
    });
    const envelope = await wrapVetKeyForDevice(
      { canisterId: VETKEYS_ID, owner: USER, deviceId: "dev-enrolled", encSpki: pub.encSpki },
      FIXTURE_VETKEY(),
    );
    const { canister, calls } = countingVetkeys(envelope);
    const h = harness(canister);
    const ctx = await loggedIn(h.deps);
    expect(calls.derives, "login makes no derive (balance 0: no priming)").toBe(0);
    // WALLET-CACHE-II-ONLY (O-1, Addendum 3): sign-in now opens the private
    // balance from this same envelope — one read, zero derives.
    const readsAtSignIn = calls.envelopeReads;
    expect(readsAtSignIn, "the sign-in open read the envelope once").toBe(1);

    await ctx.shield(SHIELD_AMOUNT);
    expect(h.feeParamsCalls(), "shield went past key acquisition").toBe(1);
    expect(calls.derives, "an enrolled device must never derive on shield").toBe(0);
    expect(calls.envelopeReads - readsAtSignIn, "the key came from this device's envelope").toBe(1);
    expect(calls.registrations).toBe(0);
  }, 120_000);

  it("(b) NEW device: the first shield derives ONCE and enrols; the second derives ZERO", async () => {
    deviceStore.clear();
    const { canister, calls } = countingVetkeys(null);
    const h = harness(canister);
    const ctx = await loggedIn(h.deps);
    expect(calls.derives, "login makes no derive (balance 0: no priming)").toBe(0);

    await ctx.shield(SHIELD_AMOUNT);
    expect(h.feeParamsCalls(), "first shield went past key acquisition").toBe(1);
    expect(calls.derives, "the first-ever action on a device derives once").toBe(1);
    expect(calls.registrations, "…and enrols this device").toBe(1);
    expect(deviceStore.has(USER.toText()), "the device identity was saved").toBe(true);

    await ctx.shield(SHIELD_AMOUNT);
    expect(h.feeParamsCalls(), "second shield went past key acquisition").toBe(2);
    expect(calls.derives, "an enrolled device never derives again").toBe(1);
    expect(calls.registrations, "no second enrolment").toBe(1);
  }, 120_000);
});
