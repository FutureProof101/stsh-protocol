/**
 * W-VETKEYS D-1b — the ZERO-DERIVE fast path, the passcode toggle, the cache
 * migration matrix, and the binding compromise wording.
 *
 * The headline arm here is the zero-derive one: it is the property the entire
 * two-layer design exists for, and before D-1b it was FALSE (every shield,
 * spend and scan derived).
 */

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";
import { VetKey } from "@dfinity/vetkeys";

import { exportDevicePublicKeys, generateDeviceKeys } from "../src/crypto/devices";
import { envelopeIsPasscodeProtected, cacheUnlockKeyIiOnly, wrapVetKeyForDevice } from "../src/crypto/layer1";
import {
  createLayer1FirstFetchKeys,
  enrollDevice,
  Layer1Unavailable,
  openThisDevicesVetKey,
  setEnvelopePasscode,
  type DeviceIdentity,
  type Layer1Config,
} from "../src/crypto/vetkeyAccess";
import { VetkeysCallError, type VetkeysCanister } from "../src/crypto/vetkeys";
import {
  COMPROMISE_MIGRATION_STEPS,
  COMPROMISE_NO_IN_PRODUCT_CUTOFF,
  COMPROMISE_SELF_SPEND_IS_NOT_A_REMEDY,
  migrationIsComplete,
  migrationStatusLine,
  REVOCATION_NOT_CRYPTOGRAPHIC_RECOVERY,
  REVOCATION_SERVICE_CUTOFF,
} from "../src/ui/recoveryCopy";
import {
  CacheFormatError,
  CacheWriteConflictError,
  importCacheKey,
  KDF_VERSION_ARGON2ID,
  KDF_VERSION_VETKEY_UNLOCK,
  KDF_VERSION_WALLET_PASSCODE,
  migratePassphraseRecord,
  PrincipalNoteCache,
} from "../src/storage/noteCache";
import { memoryHarness, testBinding } from "./helpers/cacheL4";

const hex = (b: Uint8Array): string =>
  [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (s: string): Uint8Array =>
  new Uint8Array((s.match(/../g) ?? []).map((b) => parseInt(b, 16)));

const FIXTURE_VETKEY = () =>
  VetKey.deserialize(
    fromHex(
      "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    ),
  );

/** BLS12-381 G2 generator, compressed — a valid `DerivedPublicKey` for stubs. */
const G2_GENERATOR_HEX =
  "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e" +
  "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

const CANISTER = Principal.fromUint8Array(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 1, 1]));
const OWNER = Principal.fromUint8Array(new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0x02, 0x01]));

/**
 * A canister stub that COUNTS derives and stores one envelope. The count is the
 * whole point: the fast path must never reach `getEncryptedVetkey`.
 */
function countingCanister(initial: Uint8Array | null) {
  let stored = initial;
  const calls = { derives: 0, replacements: 0, verificationKeys: 0 };
  const canister: VetkeysCanister = {
    async getVetkeyVerificationKey() {
      calls.verificationKeys += 1;
      // `vetkd_public_key` is FREE and is not a derivation — fetching it does
      // not spend quota, which is why the fast path may still call it.
      //
      // It must be a REAL G2 point: `DerivedPublicKey.deserialize` rejects
      // zeros, and a stub that threw there would make the derive counter below
      // read 0 for the wrong reason. This is the BLS12-381 G2 generator.
      return fromHex(G2_GENERATOR_HEX);
    },
    async getEncryptedVetkey() {
      calls.derives += 1;
      return { encryptedKey: new Uint8Array(192), remaining: 4 };
    },
    async getConfig() {
      return ["stsh.wallet.notes.v1", "key_1"];
    },
    async registerDevice(_id, _enc, _sign, envelope) {
      stored = envelope;
    },
    async revokeDevice() {
      stored = null;
    },
    async replaceEnvelope(_id, envelope, approval) {
      calls.replacements += 1;
      // The stub verifies SHAPE only — the canister suite proves the crypto.
      expect(approval.signature.length).toBe(64);
      expect(approval.nonce.length).toBe(16);
      stored = envelope;
    },
    async getWrappedSecret() {
      if (stored === null) {
        throw new VetkeysCallError("get_wrapped_secret", { UnknownDevice: null });
      }
      return stored;
    },
    async listDevices() {
      return [];
    },
  };
  return { canister, calls, current: () => stored };
}

async function makeConfig(): Promise<{ config: Layer1Config; identity: DeviceIdentity }> {
  const keys = await generateDeviceKeys();
  const pub = await exportDevicePublicKeys(keys);
  const identity: DeviceIdentity = {
    deviceId: "dev-1",
    keys,
    encSpki: pub.encSpki,
    signSpki: pub.signSpki,
  };
  return { config: { canisterId: CANISTER, owner: OWNER, device: identity }, identity };
}

describe("D-1b — the zero-derive fast path", () => {
  it("a registered device's login/scan/shield/spend cycle performs ZERO derives", async () => {
    const { config } = await makeConfig();
    const vetKey = FIXTURE_VETKEY();
    const envelope = await wrapVetKeyForDevice(
      { canisterId: CANISTER, owner: OWNER, deviceId: "dev-1", encSpki: config.device.encSpki },
      vetKey,
    );
    const { canister, calls } = countingCanister(envelope);
    const fetchKeys = createLayer1FirstFetchKeys(config);

    // Four acquisitions, standing in for the four flows that each used to
    // derive: login, scan, shield, spend.
    for (const flow of ["login", "scan", "shield", "spend"]) {
      const keys = await fetchKeys(canister, OWNER);
      expect(hex(keys.vetKey.serialize()), `${flow} must recover the same key`).toBe(
        hex(vetKey.serialize()),
      );
      // `remaining` is null on this path: no derive happened, so there is no
      // §H′ allowance to report.
      expect(keys.remaining).toBeNull();
    }

    expect(calls.derives).toBe(0);
  }, 120_000);

  it("falls back to Layer 2 ONLY when this device has no envelope, and exactly once", async () => {
    const { config } = await makeConfig();
    const { canister, calls } = countingCanister(null);
    const fetchKeys = createLayer1FirstFetchKeys(config);

    // No envelope: `getWrappedSecret` answers UnknownDevice, so the fallback
    // runs. It will fail on the stub's fake key material — what matters is that
    // exactly one derive was attempted.
    await expect(fetchKeys(canister, OWNER)).rejects.toBeTruthy();
    expect(calls.derives).toBe(1);
  }, 60_000);

  it("does NOT fall back when the envelope exists but cannot be opened", async () => {
    const { config } = await makeConfig();
    const other = await makeConfig();
    // An envelope belonging to a DIFFERENT device — a substitution.
    const foreign = await wrapVetKeyForDevice(
      {
        canisterId: CANISTER,
        owner: OWNER,
        deviceId: other.identity.deviceId,
        encSpki: other.identity.encSpki,
      },
      FIXTURE_VETKEY(),
    );
    const { canister, calls } = countingCanister(foreign);
    const fetchKeys = createLayer1FirstFetchKeys(config);

    await expect(fetchKeys(canister, OWNER)).rejects.toThrow(/does not match/);
    expect(
      calls.derives,
      "a failed unwrap must SURFACE, not silently spend quota on a derive",
    ).toBe(0);
  }, 120_000);

  it("enrolling a device stores the envelope the fast path then opens", async () => {
    const { config } = await makeConfig();
    const { canister, calls, current } = countingCanister(null);
    const vetKey = FIXTURE_VETKEY();

    await enrollDevice(canister, config, vetKey, { Bootstrap: null });
    expect(current()).not.toBeNull();

    const recovered = await openThisDevicesVetKey(canister, config);
    expect(hex(recovered.serialize())).toBe(hex(vetKey.serialize()));
    expect(calls.derives).toBe(0);
  }, 120_000);

  it("surfaces a revoked device as Layer1Unavailable rather than an opaque failure", async () => {
    const { config } = await makeConfig();
    const canister: VetkeysCanister = {
      ...countingCanister(null).canister,
      async getWrappedSecret() {
        throw new VetkeysCallError("get_wrapped_secret", { DeviceRevoked: null });
      },
    };
    await expect(openThisDevicesVetKey(canister, config)).rejects.toBeInstanceOf(Layer1Unavailable);
  }, 60_000);
});

describe("D-1b §2 — the passcode toggle goes THROUGH the canister", () => {
  it("enabling a passcode REPLACES the stored II-only blob", async () => {
    const { config } = await makeConfig();
    const vetKey = FIXTURE_VETKEY();
    const binding = {
      canisterId: CANISTER,
      owner: OWNER,
      deviceId: "dev-1",
      encSpki: config.device.encSpki,
    };
    const iiOnly = await wrapVetKeyForDevice(binding, vetKey);
    const { canister, calls, current } = countingCanister(iiOnly);

    await setEnvelopePasscode(canister, config, vetKey, "my passcode", 1_700_000_000_000_000_000n);

    expect(calls.replacements).toBe(1);
    const after = current()!;
    // THE RULED PROPERTY: the II-only blob is GONE. A wallet-local wrapper that
    // left it in place would fail right here.
    expect(hex(after)).not.toBe(hex(iiOnly));
    expect(envelopeIsPasscodeProtected(after)).toBe(true);

    // And the new envelope really does need the passcode to open.
    const reopened = await openThisDevicesVetKey(
      { ...canister, async getWrappedSecret() { return after; } },
      { ...config, requestPasscode: async () => "my passcode" },
    );
    expect(hex(reopened.serialize())).toBe(hex(vetKey.serialize()));
  }, 180_000);

  it("disabling the passcode replaces it again with an II-only envelope", async () => {
    const { config } = await makeConfig();
    const vetKey = FIXTURE_VETKEY();
    const binding = {
      canisterId: CANISTER,
      owner: OWNER,
      deviceId: "dev-1",
      encSpki: config.device.encSpki,
    };
    const passcoded = await wrapVetKeyForDevice(binding, vetKey, "old passcode");
    const { canister, current } = countingCanister(passcoded);

    await setEnvelopePasscode(canister, config, vetKey, undefined, 1_700_000_000_000_000_000n);
    const after = current()!;
    expect(envelopeIsPasscodeProtected(after)).toBe(false);
    expect(hex(after)).not.toBe(hex(passcoded));
  }, 180_000);

  it("the replacement is signed over the CURRENT stored envelope, freshly fetched", async () => {
    const { config } = await makeConfig();
    const vetKey = FIXTURE_VETKEY();
    const binding = {
      canisterId: CANISTER,
      owner: OWNER,
      deviceId: "dev-1",
      encSpki: config.device.encSpki,
    };
    const stored = await wrapVetKeyForDevice(binding, vetKey);
    let fetched = 0;
    const base = countingCanister(stored);
    const canister: VetkeysCanister = {
      ...base.canister,
      async getWrappedSecret() {
        fetched += 1;
        return stored;
      },
    };
    await setEnvelopePasscode(canister, config, vetKey, "pw", 1_700_000_000_000_000_000n);
    expect(
      fetched,
      "the old envelope must be READ, not remembered — that is what makes a concurrent " +
        "toggle from another tab fail loudly instead of losing an update",
    ).toBeGreaterThanOrEqual(1);
  }, 180_000);
});

describe("D-1b v4 §1 — the binding compromise wording", () => {
  it("names service cutoff and cryptographic recovery SEPARATELY", () => {
    expect(REVOCATION_SERVICE_CUTOFF).toMatch(/service cutoff/i);
    expect(REVOCATION_NOT_CRYPTOGRAPHIC_RECOVERY).toMatch(/not cryptographic recovery/i);
    // The honest half must say what survives revocation, including future notes.
    expect(REVOCATION_NOT_CRYPTOGRAPHIC_RECOVERY).toMatch(/in future/i);
  });

  it("never offers same-principal self-spend as a remedy", () => {
    const corpus = [
      REVOCATION_SERVICE_CUTOFF,
      REVOCATION_NOT_CRYPTOGRAPHIC_RECOVERY,
      COMPROMISE_SELF_SPEND_IS_NOT_A_REMEDY,
      COMPROMISE_NO_IN_PRODUCT_CUTOFF,
      ...COMPROMISE_MIGRATION_STEPS,
    ].join("\n");
    // The only mention of sending to yourself must be the one that says it does
    // NOT help.
    expect(COMPROMISE_SELF_SPEND_IS_NOT_A_REMEDY).toMatch(/does not help/i);
    expect(corpus).not.toMatch(/send(ing)? (funds )?to yourself (is|will) (a )?(safe|fix|remedy)/i);
    // And the ruled remedy IS named: a new identity.
    expect(corpus).toMatch(/new identity/i);
  });

  it("migration completes only after BOTH the spend and the new-identity recovery", () => {
    // Expected outcomes are written out here, not read back from the function.
    expect(migrationIsComplete({ oldValueSpent: false, newIdentityRecoveryVerified: false })).toBe(false);
    expect(migrationIsComplete({ oldValueSpent: true, newIdentityRecoveryVerified: false })).toBe(false);
    expect(migrationIsComplete({ oldValueSpent: false, newIdentityRecoveryVerified: true })).toBe(false);
    expect(migrationIsComplete({ oldValueSpent: true, newIdentityRecoveryVerified: true })).toBe(true);

    // The half-done status must not read as success.
    const halfway = migrationStatusLine({ oldValueSpent: true, newIdentityRecoveryVerified: false });
    expect(halfway).toMatch(/not complete/i);
    expect(halfway).not.toMatch(/^Migration complete/);
  });

  it("the ceremony's steps are ordered: verify BEFORE retiring the old identity", () => {
    const verifyAt = COMPROMISE_MIGRATION_STEPS.findIndex((s) => /confirm the notes/i.test(s));
    const revokeAt = COMPROMISE_MIGRATION_STEPS.findIndex((s) => /revoke every device/i.test(s));
    expect(verifyAt).toBeGreaterThanOrEqual(0);
    expect(revokeAt).toBeGreaterThan(verifyAt);
  });
});

describe("D-1b §3 — legacy passphrase cache migration", () => {
  const PRINCIPAL = "aaaaa-aa";

  async function seedPassphraseRecord(notes: number) {
    const h = await memoryHarness();
    const binding = testBinding(PRINCIPAL);
    const cache = await PrincipalNoteCache.open(h.store, "old passphrase", binding);
    await cache.update((state) => ({
      ...state,
      notes: Array.from({ length: notes }, (_, i) => ({
        leafIndex: BigInt(i),
        value: 100n,
        rho: new Uint8Array(32).fill(i + 1),
        rseed: new Uint8Array(32).fill(i + 2),
        recipientPk: new Uint8Array(32).fill(i + 3),
        commitment: new Uint8Array(32).fill(i + 4),
      })) as typeof state.notes,
      // The scan cursor: a migration that silently reset it would still look
      // successful and would cost the user a full rescan.
      lastScannedIndex: 42n,
    }));
    return { h, binding };
  }

  it("migrates to II-only losslessly, and the record carries the new version", async () => {
    const { h, binding } = await seedPassphraseRecord(3);
    const key = await importCacheKey(cacheUnlockKeyIiOnly(FIXTURE_VETKEY()));

    const outcome = await migratePassphraseRecord(h.store, binding, "old passphrase", {
      mode: "ii-only",
      key,
    });
    expect(outcome.kdfVersion).toBe(KDF_VERSION_VETKEY_UNLOCK);
    expect(outcome.noteCount).toBe(3);

    const slot = await h.readSlot(PRINCIPAL);
    expect(slot?.record.kdfVersion).toBe(KDF_VERSION_VETKEY_UNLOCK);
  }, 120_000);

  it("migrates to the wallet-passcode mode under its own version", async () => {
    const { h, binding } = await seedPassphraseRecord(1);
    const key = await importCacheKey(new Uint8Array(32).fill(9));
    const outcome = await migratePassphraseRecord(h.store, binding, "old passphrase", {
      mode: "wallet-passcode",
      key,
    });
    expect(outcome.kdfVersion).toBe(KDF_VERSION_WALLET_PASSCODE);
  }, 120_000);

  it("a WRONG passphrase migrates nothing and leaves the record untouched", async () => {
    const { h, binding } = await seedPassphraseRecord(2);
    const before = await h.readSlot(PRINCIPAL);
    const key = await importCacheKey(new Uint8Array(32).fill(1));

    await expect(
      migratePassphraseRecord(h.store, binding, "WRONG", { mode: "ii-only", key }),
    ).rejects.toBeTruthy();

    const after = await h.readSlot(PRINCIPAL);
    expect(after?.record.kdfVersion).toBe(KDF_VERSION_ARGON2ID);
    expect(hex(after!.record.ciphertext)).toBe(hex(before!.record.ciphertext));
    expect(after!.revision).toBe(before!.revision);
  }, 120_000);

  it("an ALREADY-migrated record is refused before any decryption is attempted", async () => {
    const { h, binding } = await seedPassphraseRecord(1);
    const key = await importCacheKey(cacheUnlockKeyIiOnly(FIXTURE_VETKEY()));
    await migratePassphraseRecord(h.store, binding, "old passphrase", { mode: "ii-only", key });

    await expect(
      migratePassphraseRecord(h.store, binding, "old passphrase", { mode: "ii-only", key }),
    ).rejects.toBeInstanceOf(CacheFormatError);
  }, 120_000);

  it("a CAS collision aborts the migration and leaves the old record openable", async () => {
    const { h, binding } = await seedPassphraseRecord(2);
    const before = await h.readSlot(PRINCIPAL);
    const key = await importCacheKey(cacheUnlockKeyIiOnly(FIXTURE_VETKEY()));

    // Another tab bumps the revision between our read and our write.
    const original = h.store.compareAndPut.bind(h.store);
    let bumped = false;
    h.store.compareAndPut = async (principalText, expected, slot) => {
      if (!bumped) {
        bumped = true;
        await original(principalText, expected, {
          revision: (before!.revision ?? 0) + 1,
          record: before!.record,
        });
        return { ok: false, current: await h.readSlot(principalText) };
      }
      return original(principalText, expected, slot);
    };

    await expect(
      migratePassphraseRecord(h.store, binding, "old passphrase", { mode: "ii-only", key }),
    ).rejects.toBeInstanceOf(CacheWriteConflictError);

    const after = await h.readSlot(PRINCIPAL);
    expect(after?.record.kdfVersion).toBe(KDF_VERSION_ARGON2ID);
  }, 120_000);

  it("preserves the FULL state, not just the notes", async () => {
    const { h, binding } = await seedPassphraseRecord(2);
    const key = await importCacheKey(cacheUnlockKeyIiOnly(FIXTURE_VETKEY()));
    await migratePassphraseRecord(h.store, binding, "old passphrase", { mode: "ii-only", key });

    // Re-open under the NEW key and compare the fields that matter — scan head
    // included, because a migration that silently reset the cursor would look
    // successful and cost the user a full rescan.
    const slot = await h.readSlot(PRINCIPAL);
    expect(slot).not.toBeNull();
    const cache = await PrincipalNoteCache.openWithKey(h.store, key, binding);
    const state = await cache.load();
    expect(state.notes.length).toBe(2);
    expect(state.lastScannedIndex).toBe(42n);
  }, 120_000);
});
