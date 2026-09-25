// @vitest-environment jsdom
/**
 * WALLET-CACHE-II-ONLY — Internet Identity sign-in opens the note cache; the
 * passcode is opt-in; old passphrase records move once (brief V1 + Addenda
 * 1-3, SSA conditions C1-C3).
 *
 * APP-LEVEL, like `shield_layer1_app`: the real `mountApp`, the real Layer-1
 * crypto (device RSA keys, sealed envelopes, Argon2id passcode envelopes), the
 * real L4 cache over the in-memory store — and NO `deps.fetchKeys` seam, so the
 * only way a key reaches the cache is the session's own path.
 *
 * EVERY DERIVE IS COUNTED AT THE CANISTER (`getEncryptedVetkey`). The Layer-2
 * `fetchUserVetKey` is a pass-through that makes the same two canister calls
 * the real one makes and returns a fixture vetKey (real BLS decryption needs a
 * real vetKD reply); the dispatch — the thing under test — is untouched.
 *
 * C2: wherever an arm asserts "zero derives at sign-in" for a device with no
 * envelope, the public balance is BELOW the §D floor, so the VETKEYS-AGE-2MIN
 * priming derive (sanctioned, pre-existing) is shut by its own gate. The
 * invariant under test is zero CACHE-attributable derives, not "zero ever".
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { Principal } from "@dfinity/principal";

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

import { VetKey } from "@dfinity/vetkeys";

import { mountApp, type AppDeps } from "../src/ui/app";
import { VetkeysCallError, type VetkeysCanister } from "../src/crypto/vetkeys";
import type { VetkeysError } from "../../src/declarations/vetkeys/vetkeys.did";
import {
  encodeSetDeviceApprovalPolicyV1,
  exportDevicePublicKeys,
  generateDeviceKeys,
} from "../src/crypto/devices";
import {
  DEVICE_APPROVAL_NO_HANDOFF_LINE,
  DEVICE_APPROVAL_OFF_LINE,
  DEVICE_APPROVAL_ON_LINE,
  DEVICE_APPROVAL_REFUSAL_LINES,
  DEVICE_APPROVAL_ZERO_DEVICES_LINE,
} from "../src/ui/deviceApprovalCopy";
import type { DeviceApprovalPolicyView, SignedApproval } from "../../src/declarations/vetkeys/vetkeys.did";
import { cacheUnlockKeyIiOnly, envelopeIsPasscodeProtected, wrapVetKeyForDevice } from "../src/crypto/layer1";
import { DEFAULT_VETKEYS_CANISTER_ID, PRODUCTION_ORIGIN } from "../src/session/config";
import type { AuthSession, WalletAuth } from "../src/session/auth";
import type { MutationActors, ReadActors, ShieldedActors } from "../src/session/session";
import type { ScanOutcome } from "../src/crypto/scanner";
import type { AppContext } from "../src/ui/context";
import {
  CacheIntegrityError,
  KDF_VERSION_ARGON2ID,
  KDF_VERSION_VETKEY_UNLOCK,
  KDF_VERSION_WALLET_PASSCODE,
  PrincipalNoteCache,
  importCacheKey,
  type CachedScanState,
  type PrincipalCacheStore,
} from "../src/storage/noteCache";
import { memoryJournalStore } from "./helpers/memoryJournalStore";
import { addNote, memoryHarness, note, testBinding, type CacheHarness } from "./helpers/cacheL4";
import { unusedIcrc2 } from "./helpers/tokenStubs";

const USER = Principal.fromUint8Array(new Uint8Array(10).fill(0x44));
const VETKEYS_ID = Principal.fromText(DEFAULT_VETKEYS_CANISTER_ID);
const CONFIG: [string, string] = ["stsh.wallet.notes.v1", "key_1"];
/** Funded: comfortably above the §D floor (literal, as in the priming suite). */
const FUNDED = 5_000_000_000n;
const T_NS = 120_000_000_000n;
const OLD_PASSPHRASE = "old passphrase 2026-09-22";
const PASSCODE = "device passcode 1";

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

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

async function settle(): Promise<void> {
  for (let i = 0; i < 40; i += 1) await new Promise((r) => setTimeout(r, 0));
}

/** Wait for an async app step that crosses real WebCrypto/Argon2id work. */
async function until(check: () => boolean, what: string): Promise<void> {
  await vi.waitFor(
    () => {
      if (!check()) throw new Error(`still waiting: ${what}`);
    },
    { timeout: 60_000, interval: 20 },
  );
}

type DeriveStep = "succeed" | "age-refuse" | Promise<void>;

/**
 * A vetkeys canister that COUNTS every derive, envelope read, registration and
 * replacement, and stores ONE envelope for the device.
 */
function countingVetkeys(opts: { envelope?: Uint8Array | null; derive?: (n: number) => DeriveStep; revoked?: boolean }) {
  let stored = opts.envelope ?? null;
  const calls = { derives: 0, envelopeReads: 0, registrations: 0, replacements: 0, lists: 0 };
  const canister: VetkeysCanister = {
    async getConfig() {
      return CONFIG;
    },
    async getVetkeyVerificationKey() {
      return fromHex(G2_GENERATOR_HEX);
    },
    async getEncryptedVetkey() {
      calls.derives += 1;
      const step = (opts.derive ?? (() => "succeed"))(calls.derives);
      if (step === "age-refuse") {
        throw new VetkeysCallError("get_encrypted_vetkey", {
          EligibilityAgeNotMet: { retry_after_ns: T_NS },
        } as VetkeysError);
      }
      if (step !== "succeed") await step;
      return { encryptedKey: new Uint8Array(192).fill(1), remaining: 4 };
    },
    async registerDevice(_id, _enc, _sign, envelope) {
      calls.registrations += 1;
      stored = envelope;
    },
    async getWrappedSecret() {
      calls.envelopeReads += 1;
      if (opts.revoked === true) throw new VetkeysCallError("get_wrapped_secret", { DeviceRevoked: null });
      if (stored === null) throw new VetkeysCallError("get_wrapped_secret", { UnknownDevice: null });
      return stored;
    },
    async replaceEnvelope(_id, next) {
      calls.replacements += 1;
      stored = next;
    },
    async revokeDevice(): Promise<never> {
      throw new Error("revokeDevice not scripted");
    },
    async listDevices() {
      calls.lists += 1;
      return stored === null ? [] : ([{ device_id: "dev" }] as never);
    },
  } as VetkeysCanister;
  return { canister, calls, current: () => stored };
}

/** Pre-seed THIS browser as an enrolled device, returning its envelope. */
async function enrolThisBrowser(passcode?: string): Promise<Uint8Array> {
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
  return wrapVetKeyForDevice(
    { canisterId: VETKEYS_ID, owner: USER, deviceId: "dev-enrolled", encSpki: pub.encSpki },
    FIXTURE_VETKEY(),
    passcode,
  );
}

/** A v2 (Argon2id passphrase) record for USER holding `notes` notes. */
async function seedPassphraseRecord(h: CacheHarness, notes: number): Promise<void> {
  const cache = await PrincipalNoteCache.open(h.store, OLD_PASSPHRASE, testBinding(USER.toText()));
  for (let i = 0; i < notes; i += 1) await cache.update(addNote(note(BigInt(i), 10 + i)));
  cache.lock();
}

function harness(opts: {
  vetkeys: VetkeysCanister;
  store: PrincipalCacheStore;
  balance?: () => bigint;
  restored?: boolean;
}): { deps: AppDeps; clock: { advance(ms: number): void } } {
  let nowMs = 1_000_000;
  const deps: AppDeps = {
    origin: PRODUCTION_ORIGIN,
    loadLaunchOrigin: async () => PRODUCTION_ORIGIN,
    buildReadActors: async () =>
      ({
        token: {
          balanceOf: async () => (opts.balance ?? (() => 0n))(),
          metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }),
          fee: async () => 0n,
        },
        staking: null,
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
      ({ pool: {} as ShieldedActors["pool"], vetkeys: opts.vetkeys }) satisfies ShieldedActors,
    createJournalStore: async () => memoryJournalStore(),
    createAuth: async () => {
      const session: AuthSession = {
        identity: { getPrincipal: () => USER } as unknown as AuthSession["identity"],
        principal: USER,
      };
      const auth: WalletAuth = {
        restore: async () => (opts.restored === true ? session : null),
        login: async () => session,
        logout: async () => undefined,
        verify: () => "valid",
      };
      return auth;
    },
    createCacheStore: async () => opts.store,
    scanNotes: async () => EMPTY_OUTCOME,
    sleep: async () => undefined,
    now: () => nowMs,
    scheduleTick: () => () => undefined,
  };
  expect("fetchKeys" in deps, "the harness must not stub the key fetch").toBe(false);
  return {
    deps,
    clock: {
      advance(ms: number) {
        nowMs += ms;
      },
    },
  };
}

let container: HTMLElement;
async function mount(deps: AppDeps, hash = "#/account"): Promise<AppContext> {
  window.location.hash = hash;
  container = document.createElement("div");
  document.body.append(container);
  return mountApp(container, {}, deps);
}

/** Route to `hash` and let the hashchange render land. */
async function show(ctx: AppContext, hash: string): Promise<void> {
  if (window.location.hash === hash) {
    ctx.refresh();
    return;
  }
  window.location.hash = hash;
  await vi.waitFor(() => {
    if (container.querySelector(`main[data-route="${hash.slice(2)}"]`) === null) throw new Error("route not rendered");
  });
}

const passwordInputs = () => container.querySelectorAll('input[type="password"]').length;

afterEach(() => {
  deviceStore.clear();
  window.location.hash = "";
  document.body.innerHTML = "";
});

describe("AC-1 — sign-in opens the private balance", () => {
  it("(a) ENROLLED device, fresh principal: login opens the cache with NO passphrase UI and ZERO derives", async () => {
    const envelope = await enrolThisBrowser();
    const { canister, calls } = countingVetkeys({ envelope });
    const h = await memoryHarness();
    const { deps } = harness({ vetkeys: canister, store: h.store });
    const ctx = await mount(deps);
    await ctx.login();
    await until(() => ctx.state.cacheUnlocked, "sign-in open");

    expect(ctx.state.cacheGate).toBe("open");
    expect(calls.derives, "sign-in never derives").toBe(0);
    expect(calls.envelopeReads, "one envelope read opened it").toBe(1);
    // A NEW record, sealed at the II-only version under the sign-in key.
    const slot = await h.readSlot(USER.toText());
    expect(slot?.record.kdfVersion).toBe(KDF_VERSION_VETKEY_UNLOCK);
    const key = await importCacheKey(cacheUnlockKeyIiOnly(FIXTURE_VETKEY()));
    await expect(PrincipalNoteCache.openWithKey(h.store, key, testBinding(USER.toText()))).resolves.toBeTruthy();

    await show(ctx, "#/shield");
    expect(passwordInputs(), "no passphrase input anywhere on #/shield").toBe(0);
    expect(container.querySelector('input[aria-label="Amount in STSH (e.g. 123)"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="cache-gate-preparing"]')).toBeNull();
  }, 120_000);

  it("(a′) the same on a restored session — and a SECOND sign-in re-opens the same record, still zero derives", async () => {
    const envelope = await enrolThisBrowser();
    const { canister, calls } = countingVetkeys({ envelope });
    const h = await memoryHarness();
    const { deps } = harness({ vetkeys: canister, store: h.store, restored: true });
    const ctx = await mount(deps);
    await until(() => ctx.state.cacheUnlocked, "restore open");
    const first = await h.readSlot(USER.toText());

    await ctx.logout();
    expect(ctx.state.cacheUnlocked).toBe(false);
    await ctx.login();
    await until(() => ctx.state.cacheUnlocked, "second sign-in open");
    const second = await h.readSlot(USER.toText());
    expect(second?.revision, "opened, not re-created").toBe(first?.revision);
    expect(calls.derives).toBe(0);
  }, 120_000);

  it("(b) NO device (C2: balance below the floor, priming shut): gated, ZERO derives at sign-in, opens on the first sync", async () => {
    const { canister, calls } = countingVetkeys({ envelope: null });
    const h = await memoryHarness();
    const { deps } = harness({ vetkeys: canister, store: h.store, balance: () => 0n });
    const ctx = await mount(deps);
    await ctx.login();
    await settle();

    expect(ctx.state.balance, "C2: below the floor — the priming gate is closed").toBe(0n);
    expect(ctx.state.cacheUnlocked).toBe(false);
    expect(ctx.state.cacheGate).toBe("preparing");
    expect(calls.derives, "ZERO cache-attributable derives at sign-in").toBe(0);
    expect(calls.envelopeReads, "no envelope to read — nothing was called").toBe(0);

    for (const route of ["#/shield", "#/scan", "#/balance", "#/spend"]) {
      await show(ctx, route);
      expect(passwordInputs(), `no passphrase input on ${route}`).toBe(0);
      expect(container.querySelector('[data-testid="cache-gate-preparing"]')?.textContent).toBe(
        "Your wallet is getting ready. First shield or sync opens it.",
      );
    }

    await show(ctx, "#/scan");
    (container.querySelector('[data-testid="gate-sync"]') as HTMLButtonElement).click();
    await until(() => ctx.state.cacheUnlocked && !ctx.state.busy && !ctx.state.scanning, "first sync");
    expect(calls.derives, "the first genuine action derives exactly once").toBe(1);
    expect(calls.registrations, "…and enrols this device").toBe(1);
    expect((await h.readSlot(USER.toText()))?.record.kdfVersion).toBe(KDF_VERSION_VETKEY_UNLOCK);
    expect(ctx.state.lastScanOk, "and the sync itself ran").toBe(true);

    // The sync's own key acquisition came from the envelope just enrolled.
    await ctx.scan();
    expect(calls.derives, "an enrolled device never derives again").toBe(1);
  }, 120_000);

  it("(b′) SSA B1: 'About N s' appears only while a preparation deadline is live", async () => {
    const { canister, calls } = countingVetkeys({ envelope: null, derive: () => "age-refuse" });
    const h = await memoryHarness();
    const { deps } = harness({ vetkeys: canister, store: h.store, balance: () => 0n });
    const ctx = await mount(deps);
    await ctx.login();
    await settle();
    await ctx.scan(); // the first action is age-refused
    expect(calls.derives).toBe(1);
    expect(ctx.state.cacheUnlocked).toBe(false);
    await show(ctx, "#/shield");
    expect(container.querySelector('[data-testid="cache-gate-preparing"]')?.textContent).toBe(
      "Your wallet is getting ready. First shield or sync opens it. About 120 s.",
    );
    // While the deadline is live a second click makes NO call at all.
    await ctx.scan();
    expect(calls.derives).toBe(1);
    expect(passwordInputs()).toBe(0);
  }, 120_000);
});

describe("session hygiene — a stale sign-in open never stands in for the next session's", () => {
  it("logout while the first open is parked, then login: the new session opens", async () => {
    const envelope = await enrolThisBrowser();
    const vk = countingVetkeys({ envelope });
    const parked = deferred<void>();
    let reads = 0;
    const canister: VetkeysCanister = {
      ...vk.canister,
      async getWrappedSecret(id: string) {
        reads += 1;
        if (reads === 1) await parked.promise; // the FIRST session's read hangs
        return vk.canister.getWrappedSecret(id);
      },
    } as VetkeysCanister;
    const h = await memoryHarness();
    const { deps } = harness({ vetkeys: canister, store: h.store });
    const ctx = await mount(deps);
    await ctx.login();
    await until(() => reads === 1, "first open parked");
    await ctx.logout();
    await ctx.login();
    await until(() => ctx.state.cacheUnlocked, "second session's own open");
    expect(ctx.state.cacheGate).toBe("open");
    parked.resolve(); // the stale run wakes up and must commit nothing
    await settle();
    expect(ctx.state.cacheUnlocked).toBe(true);
    expect(vk.calls.derives).toBe(0);
  }, 120_000);
});

describe("SSA C1 — priming and the first action share ONE derive", () => {
  it("priming in flight, THEN the first sync: total derives === 1", async () => {
    const gate = deferred<void>();
    const { canister, calls } = countingVetkeys({ envelope: null, derive: () => gate.promise });
    const h = await memoryHarness();
    const { deps } = harness({ vetkeys: canister, store: h.store, balance: () => FUNDED });
    const ctx = await mount(deps);
    await ctx.login();
    await until(() => calls.derives === 1, "priming parked in its derive");

    const sync = ctx.scan(); // the user's first genuine action, concurrently
    await settle();
    expect(calls.derives, "the first action joined the in-flight derive").toBe(1);
    gate.resolve();
    await sync;
    await until(() => ctx.state.cacheUnlocked && !ctx.state.busy && !ctx.state.scanning, "both settle");
    await settle();

    expect(calls.derives, "priming + first action = ONE derive, never two").toBe(1);
    expect(calls.registrations, "one enrolment").toBe(1);
    expect(ctx.state.cacheGate).toBe("open");
  }, 120_000);

  it("the first sync in flight, THEN priming fires: total derives === 1", async () => {
    const gate = deferred<void>();
    const { canister, calls } = countingVetkeys({ envelope: null, derive: () => gate.promise });
    const h = await memoryHarness();
    let balance = 0n; // unfunded at login: priming stays shut until the refresh below
    const { deps } = harness({ vetkeys: canister, store: h.store, balance: () => balance });
    const ctx = await mount(deps);
    await ctx.login();
    await settle();
    expect(calls.derives).toBe(0);

    const sync = ctx.scan();
    await until(() => calls.derives === 1, "the first action parked in its derive");
    balance = FUNDED;
    await ctx.refreshBalance(); // the observation that opens the priming gate
    await settle();
    expect(calls.lists, "priming ran its gate while the derive was in flight").toBe(1);
    gate.resolve();
    await sync;
    await until(() => ctx.state.cacheUnlocked && !ctx.state.busy && !ctx.state.scanning, "both settle");
    await settle();

    expect(calls.derives, "first action + priming = ONE derive, never two").toBe(1);
    expect(calls.registrations).toBe(1);
  }, 120_000);

  it("priming that completes on its own opens the cache through the no-derive path", async () => {
    const { canister, calls } = countingVetkeys({ envelope: null });
    const h = await memoryHarness();
    const { deps } = harness({ vetkeys: canister, store: h.store, balance: () => FUNDED });
    const ctx = await mount(deps);
    await ctx.login();
    await until(() => ctx.state.cacheUnlocked, "post-priming open");
    expect(calls.derives, "the priming derive, and nothing else").toBe(1);
    expect(calls.envelopeReads, "the open read the envelope priming enrolled").toBe(1);
  }, 120_000);
});

describe("AC-2 / C3 — the one-time move of an old passphrase record", () => {
  async function migrating(opts: { notes: number; store?: (h: CacheHarness) => PrincipalCacheStore }) {
    const envelope = await enrolThisBrowser();
    const vk = countingVetkeys({ envelope });
    const h = await memoryHarness();
    await seedPassphraseRecord(h, opts.notes);
    const { deps } = harness({ vetkeys: vk.canister, store: opts.store ? opts.store(h) : h.store });
    const ctx = await mount(deps);
    await ctx.login();
    await until(() => ctx.state.cacheGate === "migrate", "migration gate");
    return { ctx, h, vk };
  }

  it("the prompt renders, routes stay gated, and a WRONG passphrase leaves the record untouched", async () => {
    const { ctx, h, vk } = await migrating({ notes: 2 });
    expect(ctx.state.cacheUnlocked).toBe(false);
    await show(ctx, "#/shield");
    expect(container.querySelector('[data-testid="cache-migrate"]')).not.toBeNull();
    expect(container.querySelector('input[aria-label="Amount in STSH (e.g. 123)"]')).toBeNull();

    const before = await h.readSlot(USER.toText());
    await ctx.migrateNoteCache!({ passphrase: "WRONG", keepAsPasscode: false });
    expect(ctx.state.status?.kind).toBe("error");
    expect(ctx.state.status?.msg).toMatch(/didn't match/i);
    const after = await h.readSlot(USER.toText());
    expect(after?.record.kdfVersion, "kdfVersion unchanged").toBe(KDF_VERSION_ARGON2ID);
    expect(after?.revision).toBe(before?.revision);
    expect(ctx.state.cacheUnlocked).toBe(false);
    expect(ctx.state.cacheGate).toBe("migrate");
    expect(vk.calls.derives).toBe(0);
  }, 180_000);

  it("the RIGHT passphrase moves every note to sign-in unlock; the prompt is gone", async () => {
    const { ctx, h, vk } = await migrating({ notes: 3 });
    await show(ctx, "#/balance");
    const input = container.querySelector('[data-testid="migrate-passphrase"]') as HTMLInputElement;
    input.value = OLD_PASSPHRASE;
    (container.querySelector('[data-testid="migrate-submit"]') as HTMLButtonElement).click();
    await until(() => ctx.state.cacheUnlocked && !ctx.state.busy, "migration");

    const slot = await h.readSlot(USER.toText());
    expect(slot?.record.kdfVersion).toBe(KDF_VERSION_VETKEY_UNLOCK);
    const key = await importCacheKey(cacheUnlockKeyIiOnly(FIXTURE_VETKEY()));
    const reopened = await PrincipalNoteCache.openWithKey(h.store, key, testBinding(USER.toText()));
    expect((await reopened.load()).notes.length, "lossless").toBe(3);
    expect(ctx.state.notes.length).toBe(3);
    expect(ctx.state.cacheGate).toBe("open");
    expect(container.querySelector('[data-testid="cache-migrate"]')).toBeNull();
    expect(vk.calls.derives, "the target key came from the envelope — no derive").toBe(0);
    expect(vk.calls.replacements).toBe(0);
  }, 180_000);

  it("keep-as-passcode: the envelope gains the passcode, the record moves to v4, next sign-in asks for it", async () => {
    const { ctx, h, vk } = await migrating({ notes: 1 });
    await ctx.migrateNoteCache!({ passphrase: OLD_PASSPHRASE, keepAsPasscode: true });
    await until(() => ctx.state.cacheUnlocked && !ctx.state.busy, "migration (keep)");
    expect((await h.readSlot(USER.toText()))?.record.kdfVersion).toBe(KDF_VERSION_WALLET_PASSCODE);
    expect(vk.calls.replacements, "the canister envelope was replaced once").toBe(1);
    expect(envelopeIsPasscodeProtected(vk.current()!)).toBe(true);
    expect(ctx.state.passcodeRequired).toBe(true);

    await ctx.logout();
    await ctx.login();
    await until(() => ctx.state.cacheGate === "passcode", "passcode gate");
    expect(ctx.state.cacheUnlocked).toBe(false);
    expect(vk.calls.derives).toBe(0);
  }, 240_000);

  it("C3: the move COMMITTED but its read-back failed — the new key opens it, the old passphrase is NOT re-asked", async () => {
    let failReadBack = false;
    let armed = false;
    const { ctx, h } = await migrating({
      notes: 2,
      store: (inner) => ({
        ...inner.store,
        async get(p) {
          if (failReadBack) {
            failReadBack = false;
            return null; // one transient miss right after the committed CAS
          }
          return inner.store.get(p);
        },
        async compareAndPut(p, expected, slot) {
          const out = await inner.store.compareAndPut(p, expected, slot);
          if (armed && out.ok && slot.record.kdfVersion === KDF_VERSION_VETKEY_UNLOCK) {
            armed = false;
            failReadBack = true;
          }
          return out;
        },
      }),
    });
    armed = true;
    await ctx.migrateNoteCache!({ passphrase: OLD_PASSPHRASE, keepAsPasscode: false });
    expect(failReadBack, "the injected read-back miss was consumed").toBe(false);
    expect(ctx.state.cacheUnlocked, "opened with the target key despite the read-back error").toBe(true);
    expect(ctx.state.cacheGate).toBe("open");
    expect(ctx.state.status?.kind).toBe("success");
    expect(ctx.state.notes.length).toBe(2);
    expect((await h.readSlot(USER.toText()))?.record.kdfVersion).toBe(KDF_VERSION_VETKEY_UNLOCK);
    await show(ctx, "#/balance");
    expect(container.querySelector('[data-testid="migrate-passphrase"]'), "never re-prompted").toBeNull();
  }, 180_000);

  it("C3 control: the storage layer really does throw CacheIntegrityError in that window", async () => {
    // Proves the arm above exercises the post-CAS failure, not an easier one.
    const { migratePassphraseRecord } = await import("../src/storage/noteCache");
    const h = await memoryHarness();
    await seedPassphraseRecord(h, 1);
    let miss = false;
    const store: PrincipalCacheStore = {
      ...h.store,
      async get(p) {
        if (miss) {
          miss = false;
          return null;
        }
        return h.store.get(p);
      },
      async compareAndPut(p, e, s) {
        const out = await h.store.compareAndPut(p, e, s);
        if (out.ok) miss = true;
        return out;
      },
    };
    const key = await importCacheKey(cacheUnlockKeyIiOnly(FIXTURE_VETKEY()));
    await expect(
      migratePassphraseRecord(store, testBinding(USER.toText()), OLD_PASSPHRASE, { mode: "ii-only", key }),
    ).rejects.toBeInstanceOf(CacheIntegrityError);
    expect((await h.readSlot(USER.toText()))?.record.kdfVersion, "yet the record DID move").toBe(
      KDF_VERSION_VETKEY_UNLOCK,
    );
  }, 120_000);
});

describe("AC-3 — the opt-in passcode, and Addendum 1's Settings tick box", () => {
  it("toggle ON → envelope replaced once, record v4, next sign-in asks; toggle OFF → back to AC-1", async () => {
    const envelope = await enrolThisBrowser();
    const vk = countingVetkeys({ envelope });
    const h = await memoryHarness();
    const { deps } = harness({ vetkeys: vk.canister, store: h.store });
    const ctx = await mount(deps);
    await ctx.login();
    await until(() => ctx.state.cacheUnlocked, "sign-in open");

    await show(ctx, "#/settings");
    const box = () => container.querySelector('[data-testid="passcode-toggle"]') as HTMLInputElement;
    expect(box().checked, "Addendum 1: shows the REAL setting — off").toBe(false);
    expect(box().disabled, "and is a working control").toBe(false);

    await ctx.passcode!.enable(PASSCODE);
    expect(vk.calls.replacements, "the passcode-enable mechanism ran once").toBe(1);
    expect(envelopeIsPasscodeProtected(vk.current()!)).toBe(true);
    expect((await h.readSlot(USER.toText()))?.record.kdfVersion).toBe(KDF_VERSION_WALLET_PASSCODE);
    expect(ctx.state.cacheUnlocked, "still open under the new key").toBe(true);
    await show(ctx, "#/settings");
    expect(box().checked, "now ticked").toBe(true);

    await ctx.logout();
    await ctx.login();
    await until(() => ctx.state.cacheGate === "passcode", "passcode gate");
    await show(ctx, "#/balance");
    expect(container.querySelector('[data-testid="cache-passcode"]')).not.toBeNull();
    await show(ctx, "#/settings");
    expect(box().checked, "locked, but still shows the real setting").toBe(true);
    expect(box().disabled).toBe(true);

    await ctx.unlockWithPasscode!("not it");
    expect(ctx.state.cacheUnlocked).toBe(false);
    expect(ctx.state.status?.msg).toMatch(/didn't match/i);
    await ctx.unlockWithPasscode!(PASSCODE);
    await until(() => ctx.state.cacheUnlocked && !ctx.state.busy, "passcode unlock");

    await ctx.passcode!.disable(PASSCODE);
    expect(vk.calls.replacements).toBe(2);
    expect(envelopeIsPasscodeProtected(vk.current()!)).toBe(false);
    expect((await h.readSlot(USER.toText()))?.record.kdfVersion).toBe(KDF_VERSION_VETKEY_UNLOCK);

    await ctx.logout();
    await ctx.login();
    await until(() => ctx.state.cacheUnlocked, "AC-1 behaviour again");
    expect(vk.calls.derives, "the whole cycle made zero derives").toBe(0);
  }, 300_000);
});

describe("AC-4 — Layer 1 unavailable fails CLOSED", () => {
  it("a revoked envelope: gated, no derive, no passphrase input anywhere", async () => {
    await enrolThisBrowser();
    const { canister, calls } = countingVetkeys({ envelope: null, revoked: true });
    const h = await memoryHarness();
    const { deps } = harness({ vetkeys: canister, store: h.store, balance: () => 0n });
    const ctx = await mount(deps);
    await ctx.login();
    await settle();
    expect(calls.envelopeReads).toBe(1);
    expect(calls.derives, "no fall-through to Layer 2 at sign-in").toBe(0);
    expect(ctx.state.cacheUnlocked).toBe(false);
    expect(ctx.state.cacheGate).toBe("preparing");
    for (const route of ["#/account", "#/shield", "#/scan", "#/balance", "#/spend", "#/activity"]) {
      await show(ctx, route);
      expect(passwordInputs(), `no passphrase fallback on ${route}`).toBe(0);
    }
    expect(await h.readSlot(USER.toText()), "no record was created").toBeNull();
  }, 120_000);

  it("EligibilityAgeNotMet on the first action: gated with the countdown copy, cache NOT opened", async () => {
    const { canister, calls } = countingVetkeys({ envelope: null, derive: () => "age-refuse" });
    const h = await memoryHarness();
    const { deps } = harness({ vetkeys: canister, store: h.store, balance: () => 0n });
    const ctx = await mount(deps);
    await ctx.login();
    await settle();
    await ctx.shield(100_000_000_000n);
    expect(calls.derives).toBe(1);
    expect(ctx.state.cacheUnlocked).toBe(false);
    expect(ctx.state.status?.kind).toBe("info");
    expect(await h.readSlot(USER.toText())).toBeNull();
    await show(ctx, "#/shield");
    expect(container.querySelector('[data-testid="cache-gate-preparing"]')?.textContent).toMatch(/About 120 s\.$/);
    expect(passwordInputs()).toBe(0);
  }, 120_000);
});

describe("AC-5 — cacheUnlocked is never true without a successful open", () => {
  it("a store that throws: the gate reads error, the cache stays closed", async () => {
    const envelope = await enrolThisBrowser();
    const { canister } = countingVetkeys({ envelope });
    const h = await memoryHarness();
    const broken: PrincipalCacheStore = {
      ...h.store,
      async get() {
        throw new Error("IndexedDB is unavailable (scripted)");
      },
    };
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const { deps } = harness({ vetkeys: canister, store: broken });
      const ctx = await mount(deps);
      await ctx.login();
      await until(() => ctx.state.cacheGate === "error", "error gate");
      expect(ctx.state.cacheUnlocked).toBe(false);
      expect(ctx.state.status?.kind, "no error toast over 'Logged in.'").not.toBe("error");
    } finally {
      errors.mockRestore();
    }
  }, 120_000);

  it("a record sealed under ANOTHER key: authentication fails, the cache stays closed", async () => {
    const envelope = await enrolThisBrowser();
    const { canister } = countingVetkeys({ envelope });
    const h = await memoryHarness();
    const other = await importCacheKey(new Uint8Array(32).fill(7));
    const planted = await PrincipalNoteCache.openOrCreateWithKey(h.store, other, testBinding(USER.toText()));
    planted.lock();
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const { deps } = harness({ vetkeys: canister, store: h.store });
      const ctx = await mount(deps);
      await ctx.login();
      await until(() => ctx.state.cacheGate === "error", "error gate");
      expect(ctx.state.cacheUnlocked).toBe(false);
    } finally {
      errors.mockRestore();
    }
  }, 120_000);
});

describe("storage — the create-with-key path keeps the HARD RULE", () => {
  it("creates at v3 (or v4) under the supplied non-extractable key, never at a passphrase version", async () => {
    const h = await memoryHarness();
    const key = await importCacheKey(cacheUnlockKeyIiOnly(FIXTURE_VETKEY()));
    expect(key.extractable).toBe(false);
    const cache = await PrincipalNoteCache.openOrCreateWithKey(h.store, key, testBinding("aaaaa-aa"));
    const empty: CachedScanState = await cache.load();
    expect(empty.notes).toEqual([]);
    expect((await h.readSlot("aaaaa-aa"))?.record.kdfVersion).toBe(KDF_VERSION_VETKEY_UNLOCK);

    const h4 = await memoryHarness();
    await PrincipalNoteCache.openOrCreateWithKey(h4.store, key, testBinding("aaaaa-aa"), KDF_VERSION_WALLET_PASSCODE);
    expect((await h4.readSlot("aaaaa-aa"))?.record.kdfVersion).toBe(KDF_VERSION_WALLET_PASSCODE);

    await expect(
      PrincipalNoteCache.openOrCreateWithKey(h.store, key, testBinding("aaaaa-aa"), KDF_VERSION_ARGON2ID),
    ).rejects.toThrow(/key-based cache record/);
    // Nothing but ciphertext and non-secret metadata was stored.
    const values = JSON.stringify(await h.allValues(), (_k, v) => (v instanceof Uint8Array ? [...v] : v));
    expect(values).not.toContain(JSON.stringify([...cacheUnlockKeyIiOnly(FIXTURE_VETKEY())]).slice(1, -1));
  }, 60_000);

  it("an existing PASSPHRASE record is refused before any crypto — never re-sealed by the key path", async () => {
    const h = await memoryHarness();
    await seedPassphraseRecord(h, 1);
    const key = await importCacheKey(cacheUnlockKeyIiOnly(FIXTURE_VETKEY()));
    await expect(PrincipalNoteCache.openOrCreateWithKey(h.store, key, testBinding(USER.toText()))).rejects.toThrow(
      /not a key-based/,
    );
    expect((await h.readSlot(USER.toText()))?.record.kdfVersion).toBe(KDF_VERSION_ARGON2ID);
  }, 60_000);
});

// ── WALLET-V12 AC-3 — "Approve new devices" (O-4; Owner O-8; SSA F-3) ─────────

describe("WALLET-V12 AC-3 — Settings → Extra security → Approve new devices", () => {
  const HOUR_NS = 3_600_000_000_000n;
  const nowNs = () => BigInt(Date.now()) * 1_000_000n;

  /**
   * `countingVetkeys` plus the four HARDEN-04 O-8 methods, scripted over ONE
   * canister-side policy row with the canister's semantics: device-signed
   * false DELETES the row (immediate); the II-only request sets
   * `pending_clear_effective_at_ns = now + 24 h` and never deletes it.
   */
  function policyVetkeys(opts: {
    envelope: Uint8Array | null;
    policy: DeviceApprovalPolicyView | null;
    activeDevices: string[];
    enrolRefusal?: boolean;
  }) {
    const base = countingVetkeys({ envelope: opts.envelope });
    let row = opts.policy;
    const policyCalls = {
      set: [] as { require: boolean; approval: SignedApproval }[],
      clear: 0,
      reads: 0,
    };
    const canister: VetkeysCanister = {
      ...base.canister,
      async listDevices() {
        return opts.activeDevices.map((id) => ({ device_id: id, active: true })) as never;
      },
      async registerDevice(...args) {
        if (opts.enrolRefusal === true) {
          throw new VetkeysCallError("register_device", {
            BootstrapNotAuthorized: { reason: "DEVICE_APPROVAL_REQUIRED (prose never parsed)" },
          } as VetkeysError);
        }
        return base.canister.registerDevice(...args);
      },
      async setDeviceApprovalPolicy(require, approval) {
        policyCalls.set.push({ require, approval });
        row = require
          ? { require_device_approval: true, set_at_ns: nowNs(), pending_clear_effective_at_ns: [] }
          : null; // immediate: the row is deleted
      },
      async requestDeviceApprovalPolicyClear() {
        policyCalls.clear += 1;
        if (row === null) throw new VetkeysCallError("request_device_approval_policy_clear", { InvalidRequest: "no device-approval policy is set" });
        const t = row.pending_clear_effective_at_ns[0] ?? nowNs() + 24n * HOUR_NS;
        row = { ...row, pending_clear_effective_at_ns: [t] };
        return t;
      },
      async deviceApprovalPolicy() {
        policyCalls.reads += 1;
        return row;
      },
      async getDeviceCheckCaller() {
        return null;
      },
    };
    return { canister, policyCalls, base };
  }

  const toggle = () => container.querySelector('[data-testid="device-approval-toggle"]') as HTMLInputElement;
  const stateLines = () =>
    Array.from(container.querySelectorAll('[data-testid="device-approval-state"]')).map((p) => p.textContent);

  async function openSettings(vk: VetkeysCanister): Promise<AppContext> {
    const h = await memoryHarness();
    const { deps } = harness({ vetkeys: vk, store: h.store });
    const ctx = await mount(deps);
    await ctx.login();
    await settle();
    await show(ctx, "#/settings");
    await until(() => ctx.state.deviceApproval !== undefined && ctx.state.deviceApproval !== null, "setting read");
    return ctx;
  }

  it("default OFF; ON from this enrolled device calls set_device_approval_policy ONCE, signed by the existing device key", async () => {
    const envelope = await enrolThisBrowser();
    const { canister, policyCalls } = policyVetkeys({ envelope, policy: null, activeDevices: ["dev-enrolled"] });
    const ctx = await openSettings(canister);
    expect(container.querySelector('[data-testid="settings-extra-security"] h3')?.textContent).toBe("Extra security");
    expect(toggle().checked, "default OFF").toBe(false);
    expect(toggle().disabled).toBe(false);
    expect(stateLines()).toEqual([DEVICE_APPROVAL_OFF_LINE]);

    toggle().checked = true;
    toggle().dispatchEvent(new Event("change"));
    await until(() => policyCalls.set.length === 1 && !ctx.state.busy, "set(true)");
    await until(() => ctx.state.deviceApproval?.state.kind === "on", "re-read");
    expect(policyCalls.set).toHaveLength(1);
    expect(policyCalls.clear).toBe(0);
    const { require, approval } = policyCalls.set[0];
    expect(require).toBe(true);
    expect(approval.issuer_device_id).toBe("dev-enrolled");
    // The signature verifies over the canonical SetDeviceApprovalPolicyV1
    // transcript under THIS device's stored signing key (no new key path).
    const stored = deviceStore.get(USER.toText()) as { signPublic: CryptoKey };
    const transcript = encodeSetDeviceApprovalPolicyV1({
      canisterId: VETKEYS_ID,
      owner: USER,
      issuerDeviceId: "dev-enrolled",
      requireDeviceApproval: true,
      nonce: new Uint8Array(approval.nonce as Uint8Array),
      expiryNs: approval.expiry_ns,
    });
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      stored.signPublic,
      new Uint8Array(approval.signature as Uint8Array),
      new Uint8Array(transcript),
    );
    expect(ok, "device-signed transcript verifies").toBe(true);
    await show(ctx, "#/settings");
    expect(toggle().checked).toBe(true);
    expect(stateLines()).toEqual([DEVICE_APPROVAL_ON_LINE, DEVICE_APPROVAL_NO_HANDOFF_LINE]);
  }, 120_000);

  it("OFF from an ENROLLED device is set_device_approval_policy(false) — immediate, no pending state, no II-only request", async () => {
    const envelope = await enrolThisBrowser();
    const { canister, policyCalls } = policyVetkeys({
      envelope,
      policy: { require_device_approval: true, set_at_ns: 1n, pending_clear_effective_at_ns: [] },
      activeDevices: ["dev-enrolled"],
    });
    const ctx = await openSettings(canister);
    expect(toggle().checked).toBe(true);
    toggle().checked = false;
    toggle().dispatchEvent(new Event("change"));
    await until(() => policyCalls.set.length === 1 && !ctx.state.busy, "set(false)");
    await until(() => ctx.state.deviceApproval?.state.kind === "off", "re-read");
    expect(policyCalls.set[0].require).toBe(false);
    expect(policyCalls.clear, "never the 24 h path from an enrolled device").toBe(0);
    await show(ctx, "#/settings");
    expect(toggle().checked).toBe(false);
    expect(stateLines()).toEqual([DEVICE_APPROVAL_OFF_LINE]);
  }, 120_000);

  it("OFF from an II-only session (this browser not enrolled) is request_device_approval_policy_clear — renders the 24 h pending state", async () => {
    // No deviceStore entry: this browser holds no device key; another device is active.
    const { canister, policyCalls } = policyVetkeys({
      envelope: null,
      policy: { require_device_approval: true, set_at_ns: 1n, pending_clear_effective_at_ns: [] },
      activeDevices: ["dev-other"],
    });
    const ctx = await openSettings(canister);
    expect(ctx.state.deviceApproval?.thisDeviceActive).toBe(false);
    expect(toggle().checked).toBe(true);
    expect(toggle().disabled, "the II-only request is available").toBe(false);
    toggle().checked = false;
    toggle().dispatchEvent(new Event("change"));
    await until(() => policyCalls.clear === 1 && !ctx.state.busy, "request clear");
    await until(() => ctx.state.deviceApproval?.state.kind === "pending-clear", "re-read");
    expect(policyCalls.set, "no device signature from an II-only session").toHaveLength(0);
    await show(ctx, "#/settings");
    expect(toggle().checked, "still on until the canister's instant").toBe(true);
    expect(toggle().disabled, "an II-only clear cannot be sped up").toBe(true);
    expect(stateLines()[0]).toMatch(/^Turns off at .+ \(24h\)\.$/);
    expect(stateLines()[1]).toBe(DEVICE_APPROVAL_NO_HANDOFF_LINE);
  }, 120_000);

  it("a MATURED II-only clear (row not deleted, instant passed) renders as OFF", async () => {
    const envelope = await enrolThisBrowser();
    const { canister } = policyVetkeys({
      envelope,
      policy: {
        require_device_approval: true,
        set_at_ns: 1n,
        pending_clear_effective_at_ns: [nowNs() - 2n * HOUR_NS],
      },
      activeDevices: ["dev-enrolled"],
    });
    const ctx = await openSettings(canister);
    expect(ctx.state.deviceApproval?.state.kind).toBe("off");
    expect(toggle().checked).toBe(false);
    expect(stateLines()).toEqual([DEVICE_APPROVAL_OFF_LINE]);
  }, 120_000);

  it("zero active devices: the toggle is disabled with a one-line reason (the canister refuses set)", async () => {
    const { canister, policyCalls } = policyVetkeys({ envelope: null, policy: null, activeDevices: [] });
    await openSettings(canister);
    expect(toggle().disabled).toBe(true);
    expect(toggle().checked).toBe(false);
    expect(stateLines()).toEqual([DEVICE_APPROVAL_ZERO_DEVICES_LINE]);
    expect(policyCalls.set).toHaveLength(0);
  }, 120_000);

  it("new-device enrolment refused under ON: the three-fact advisory, discriminated by device_approval_policy() — not the reason text", async () => {
    const { canister, policyCalls } = policyVetkeys({
      envelope: null,
      policy: { require_device_approval: true, set_at_ns: 1n, pending_clear_effective_at_ns: [] },
      activeDevices: ["dev-other"],
      enrolRefusal: true,
    });
    const h = await memoryHarness();
    const { deps } = harness({ vetkeys: canister, store: h.store, balance: () => 0n });
    const ctx = await mount(deps);
    await ctx.login();
    await settle();
    await ctx.shield(100_000_000_000n);
    await until(() => ctx.state.status?.kind === "advisory", "advisory refusal");
    expect(ctx.state.status?.lines).toEqual([...DEVICE_APPROVAL_REFUSAL_LINES]);
    for (const line of DEVICE_APPROVAL_REFUSAL_LINES) {
      expect(line.split(/\s+/).filter(Boolean).length, line).toBeLessThanOrEqual(15);
    }
    expect(policyCalls.reads).toBeGreaterThanOrEqual(1);
    // "Or request turn-off here": the offered action is the II-only request.
    ctx.state.status?.action?.run();
    await until(() => policyCalls.clear === 1, "request clear from the refusal");
    expect(policyCalls.set).toHaveLength(0);
  }, 120_000);

  it("the SAME refusal with the flag OFF (L04-07 re-bootstrap) keeps the existing error copy", async () => {
    const { canister } = policyVetkeys({
      envelope: null,
      policy: null,
      activeDevices: [],
      enrolRefusal: true,
    });
    const h = await memoryHarness();
    const { deps } = harness({ vetkeys: canister, store: h.store, balance: () => 0n });
    const ctx = await mount(deps);
    await ctx.login();
    await settle();
    await ctx.shield(100_000_000_000n);
    await until(() => ctx.state.status?.kind === "error", "error");
    expect(ctx.state.status?.lines).toBeUndefined();
  }, 120_000);
});
