/**
 * W-VETKEYS — the three ruled UX/transport obligations:
 *   1. the key-recovery quota is SURFACED (D-1 clause 4, brief V1 §6);
 *   2. envelope traffic is never cacheable (brief V1 §6, prior published no-cache discipline);
 *   3. the device-approval flow is drivable end to end (brief V2 §C).
 */

import { describe, expect, it, vi } from "vitest";
import { Principal } from "@dfinity/principal";
import { VetKey } from "@dfinity/vetkeys";

import {
  assertNoServiceWorkerIntercept,
  NEVER_CACHED_METHODS,
  noStoreFetch,
} from "../src/net/noStore";
import { humanizeWait, quotaNotice, quotaRefusalNotice } from "../src/ui/quotaCopy";
import { QUOTA_WARN_REMAINING, VetkeysCallError, type VetkeysCanister } from "../src/crypto/vetkeys";
import {
  approveNewDevice,
  openThisDevicesVetKey,
  revokeDeviceWithHonestCopy,
  type DeviceIdentity,
  type Layer1Config,
} from "../src/crypto/vetkeyAccess";
import { exportDevicePublicKeys, generateDeviceKeys, randomDeviceId } from "../src/crypto/devices";
import { wrapVetKeyForDevice, envelopeIsPasscodeProtected } from "../src/crypto/layer1";

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
const CANISTER = Principal.fromUint8Array(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 1, 1]));
const OWNER = Principal.fromUint8Array(new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0x02, 0x01]));
const EXPIRY = 1_900_000_000_000_000_000n;

async function makeDevice(id: string): Promise<DeviceIdentity> {
  const keys = await generateDeviceKeys();
  const pub = await exportDevicePublicKeys(keys);
  return { deviceId: id, keys, encSpki: pub.encSpki, signSpki: pub.signSpki };
}

// ── 1. Quota UX ───────────────────────────────────────────────────────────────

describe("D-1 clause 4 — the key-recovery quota is surfaced", () => {
  it("warns at the pinned threshold and not before", () => {
    // Expected behaviour is written out per value rather than derived from the
    // constant, so moving the constant moves this test to RED.
    expect(quotaNotice(5)).toBeNull();
    expect(quotaNotice(4)).toBeNull();
    expect(quotaNotice(3)?.level).toBe("warning");
    expect(quotaNotice(2)?.level).toBe("warning");
    expect(quotaNotice(1)?.level).toBe("warning");
    expect(QUOTA_WARN_REMAINING).toBe(3);
  });

  it("says the count, and says what uses one", () => {
    const notice = quotaNotice(2);
    expect(notice?.message).toMatch(/2 key recoveries left today/);
    expect(notice?.message).toMatch(/new-device setup|all-devices-lost/i);
  });

  it("uses the singular at one remaining", () => {
    expect(quotaNotice(1)?.message).toMatch(/1 key recovery left/);
  });

  it("escalates at zero, and says the existing device still works", () => {
    const notice = quotaNotice(0);
    expect(notice?.level).toBe("error");
    expect(notice?.message).toMatch(/still works/i);
  });

  it("shows NOTHING on the fast path — the canister reported no allowance", () => {
    // `null` is the Layer-1 path. Rendering "5 of 5" here would be the wallet
    // asserting a number the canister never said.
    expect(quotaNotice(null)).toBeNull();
  });

  it("renders the wait on an exhausted quota", () => {
    const notice = quotaRefusalNotice({
      DerivationQuotaExceeded: { retry_after_ns: 3_600_000_000_000n },
    } as never);
    expect(notice?.level).toBe("error");
    expect(notice?.message).toMatch(/try again in 1 hour/);
    expect(notice?.message).toMatch(/already set up keep working/i);
  });

  it("renders the registration limit's wait separately from the derive quota", () => {
    const notice = quotaRefusalNotice({
      RegistrationRateExceeded: { retry_after_ns: 120_000_000_000n },
    } as never);
    expect(notice?.message).toMatch(/device changes/i);
    expect(notice?.message).toMatch(/2 minutes/);
  });

  it("returns nothing for errors that carry no wait", () => {
    expect(quotaRefusalNotice({ AdmissionLapsed: null } as never)).toBeNull();
    expect(quotaRefusalNotice({ UnknownDevice: null } as never)).toBeNull();
  });

  it("rounds waits UP — sending a user back early is worse than a pessimistic number", () => {
    expect(humanizeWait(0)).toBe("a moment");
    expect(humanizeWait(1)).toBe("1 seconds");
    expect(humanizeWait(59)).toBe("59 seconds");
    expect(humanizeWait(60)).toBe("1 minute");
    expect(humanizeWait(61)).toBe("2 minutes");
    expect(humanizeWait(3600)).toBe("1 hour");
    expect(humanizeWait(3601)).toBe("2 hours");
    expect(humanizeWait(86_400)).toBe("1 day");
    expect(humanizeWait(86_401)).toBe("2 days");
  });
});

// ── 2. No-store ───────────────────────────────────────────────────────────────

describe("brief V1 §6 — envelope traffic is never cacheable", () => {
  it("sets BOTH the cache mode and the Cache-Control header", async () => {
    const seen: RequestInit[] = [];
    const base = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      seen.push(init ?? {});
      return new Response("{}");
    }) as unknown as typeof fetch;

    await noStoreFetch(base)("https://ic0.app/api/v2/canister/x/query", {
      method: "POST",
      body: "payload",
    });

    expect(seen).toHaveLength(1);
    // The RequestInit mode governs the browser's HTTP cache…
    expect(seen[0].cache).toBe("no-store");
    // …and the header is what an intermediary sees. Both, because they are
    // different layers.
    expect(new Headers(seen[0].headers).get("Cache-Control")).toBe("no-store");
    // The caller's own fields survive.
    expect(seen[0].method).toBe("POST");
    expect(seen[0].body).toBe("payload");
  });

  it("does not clobber a caller's other headers", async () => {
    const seen: RequestInit[] = [];
    const base = (async (_i: RequestInfo | URL, init?: RequestInit) => {
      seen.push(init ?? {});
      return new Response("{}");
    }) as unknown as typeof fetch;
    await noStoreFetch(base)("https://ic0.app/", {
      headers: { "Content-Type": "application/cbor" },
    });
    const headers = new Headers(seen[0].headers);
    expect(headers.get("Content-Type")).toBe("application/cbor");
    expect(headers.get("Cache-Control")).toBe("no-store");
  });

  it("names every envelope-carrying method, so the set is reviewable against the .did", () => {
    expect([...NEVER_CACHED_METHODS].sort()).toEqual([
      "get_encrypted_vetkey",
      "get_wrapped_secret",
      "register_device",
      "replace_envelope",
    ]);
  });

  it("passes when no service worker is registered, and REFUSES when one is", async () => {
    await expect(
      assertNoServiceWorkerIntercept({
        navigator: { serviceWorker: { getRegistrations: async () => [] } as never },
      }),
    ).resolves.toBeUndefined();

    await expect(
      assertNoServiceWorkerIntercept({
        navigator: { serviceWorker: { getRegistrations: async () => [{}] } as never },
      }),
    ).rejects.toThrow(/must be excluded/);

    // An environment without service workers at all is fine, not an error.
    await expect(assertNoServiceWorkerIntercept({})).resolves.toBeUndefined();
  });

  it("the wallet registers no service worker today (source census)", async () => {
    // A grep-style census rather than a runtime check: the point is that
    // NOTHING in the app registers one, which a runtime probe in jsdom cannot
    // show. If a service worker is added later, this fails and its author has
    // to exclude the envelope methods first.
    const files = import.meta.glob("../src/**/*.ts", { query: "?raw", import: "default" });
    const sources = await Promise.all(Object.values(files).map((load) => load() as Promise<string>));
    const offenders = sources.filter((src) => /serviceWorker\s*\.\s*register\s*\(/.test(src));
    expect(offenders).toHaveLength(0);
  });
});

// ── 3. Device approval ────────────────────────────────────────────────────────

describe("brief V2 §C — the device-approval flow, end to end", () => {
  /** A stub that records the registration the existing device submits. */
  function registryCanister(existingEnvelope: Uint8Array) {
    const stored = new Map<string, Uint8Array>([["existing", existingEnvelope]]);
    const registrations: Array<{ deviceId: string; approval: unknown }> = [];
    const revocations: string[] = [];
    const canister: VetkeysCanister = {
      async getVetkeyVerificationKey() {
        return new Uint8Array(96);
      },
      async getEncryptedVetkey() {
        throw new Error("the approval flow must not derive");
      },
      async getConfig() {
        return ["stsh.wallet.notes.v1", "key_1"];
      },
      async registerDevice(deviceId, _enc, _sign, envelope, approval) {
        registrations.push({ deviceId, approval });
        stored.set(deviceId, envelope);
      },
      async revokeDevice(deviceId) {
        revocations.push(deviceId);
        stored.delete(deviceId);
      },
      async replaceEnvelope(deviceId, envelope) {
        stored.set(deviceId, envelope);
      },
      async getWrappedSecret(deviceId) {
        const found = stored.get(deviceId);
        if (found === undefined) {
          throw new VetkeysCallError("get_wrapped_secret", { UnknownDevice: null });
        }
        return found;
      },
      async listDevices() {
        return [];
      },
    };
    return { canister, registrations, revocations, stored };
  }

  it("an existing device approves a new one, which can then open its OWN envelope", async () => {
    const existing = await makeDevice("existing");
    const incoming = await makeDevice(randomDeviceId());
    const vetKey = FIXTURE_VETKEY();
    const existingEnvelope = await wrapVetKeyForDevice(
      { canisterId: CANISTER, owner: OWNER, deviceId: "existing", encSpki: existing.encSpki },
      vetKey,
    );
    const { canister, registrations } = registryCanister(existingEnvelope);
    const config: Layer1Config = { canisterId: CANISTER, owner: OWNER, device: existing };

    // The new device hands over PUBLIC material only — nothing secret crosses
    // the gap, so the transfer channel carries no secret to protect.
    await approveNewDevice(
      canister,
      config,
      vetKey,
      { deviceId: incoming.deviceId, encSpki: incoming.encSpki, signSpki: incoming.signSpki },
      EXPIRY,
    );

    expect(registrations).toHaveLength(1);
    expect(registrations[0].deviceId).toBe(incoming.deviceId);
    expect(registrations[0].approval).toHaveProperty("Device");

    // THE END-TO-END PROPERTY: the new device now opens its own envelope and
    // recovers the SAME vetKey — with no derive anywhere in the flow.
    const recovered = await openThisDevicesVetKey(canister, {
      canisterId: CANISTER,
      owner: OWNER,
      device: incoming,
    });
    expect(hex(recovered.serialize())).toBe(hex(vetKey.serialize()));
  }, 180_000);

  it("can approve a new device straight into passcode mode", async () => {
    const existing = await makeDevice("existing");
    const incoming = await makeDevice("incoming");
    const vetKey = FIXTURE_VETKEY();
    const existingEnvelope = await wrapVetKeyForDevice(
      { canisterId: CANISTER, owner: OWNER, deviceId: "existing", encSpki: existing.encSpki },
      vetKey,
    );
    const { canister, stored } = registryCanister(existingEnvelope);

    await approveNewDevice(
      canister,
      { canisterId: CANISTER, owner: OWNER, device: existing },
      vetKey,
      { deviceId: "incoming", encSpki: incoming.encSpki, signSpki: incoming.signSpki },
      EXPIRY,
      "the new device's passcode",
    );

    expect(envelopeIsPasscodeProtected(stored.get("incoming")!)).toBe(true);
    const recovered = await openThisDevicesVetKey(canister, {
      canisterId: CANISTER,
      owner: OWNER,
      device: incoming,
      requestPasscode: async () => "the new device's passcode",
    });
    expect(hex(recovered.serialize())).toBe(hex(vetKey.serialize()));
  }, 240_000);

  it("refuses to approve a device onto itself", async () => {
    const existing = await makeDevice("existing");
    const vetKey = FIXTURE_VETKEY();
    const { canister } = registryCanister(new Uint8Array(1));
    await expect(
      approveNewDevice(
        canister,
        { canisterId: CANISTER, owner: OWNER, device: existing },
        vetKey,
        { deviceId: "existing", encSpki: existing.encSpki, signSpki: existing.signSpki },
        EXPIRY,
      ),
    ).rejects.toThrow(/must be different/);
  }, 60_000);

  it("revocation returns BOTH halves of the honest wording, and the read path closes", async () => {
    const existing = await makeDevice("existing");
    const doomed = await makeDevice("doomed");
    const vetKey = FIXTURE_VETKEY();
    const existingEnvelope = await wrapVetKeyForDevice(
      { canisterId: CANISTER, owner: OWNER, deviceId: "existing", encSpki: existing.encSpki },
      vetKey,
    );
    const { canister, revocations } = registryCanister(existingEnvelope);
    const config: Layer1Config = { canisterId: CANISTER, owner: OWNER, device: existing };

    await approveNewDevice(
      canister,
      config,
      vetKey,
      { deviceId: "doomed", encSpki: doomed.encSpki, signSpki: doomed.signSpki },
      EXPIRY,
    );

    const copy = await revokeDeviceWithHonestCopy(canister, config, "doomed", EXPIRY);
    expect(revocations).toEqual(["doomed"]);
    expect(copy.serviceCutoff).toMatch(/service cutoff/i);
    // The UI cannot ship the reassuring half alone: the flow HANDS BACK both.
    expect(copy.notCryptographicRecovery).toMatch(/not cryptographic recovery/i);

    // The revoked device gets neither the blob nor a working read path.
    await expect(
      openThisDevicesVetKey(canister, { canisterId: CANISTER, owner: OWNER, device: doomed }),
    ).rejects.toBeTruthy();
  }, 240_000);
});
