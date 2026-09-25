/**
 * STSH W-VETKEYS — the Layer-1-first key path (brief V4 §6, D-1b v3/v4)
 *
 * This is where "ordinary logins cost ZERO derives" actually happens. Every
 * flow that needs the user's vetKey — login, scan, shield, spend — goes through
 * a `FetchKeys` function, and in production that function is the one built
 * here: it opens this device's stored envelope and returns the vetKey without
 * ever calling `get_encrypted_vetkey`.
 *
 * LAYER 2 IS THE FALLBACK, NOT THE PATH: a derive happens only when this device
 * has no usable envelope — first-ever bootstrap, or genuine all-devices-lost
 * recovery. Those are quota-bound and metered; the fast path is neither,
 * because it never reaches the canister's derive endpoint at all.
 *
 * WHAT THIS MODULE WILL NOT DO: it will not silently fall back to Layer 2 when
 * a passcode is wrong, or when an envelope fails to open. A failed unwrap is an
 * error the user must see — quietly deriving instead would spend quota, teach
 * the user nothing, and hide a tampered or substituted envelope.
 */

import type { DerivedPublicKey } from "@dfinity/vetkeys";
import { DerivedPublicKey as DerivedPublicKeyImpl, VetKey } from "@dfinity/vetkeys";
import { Principal } from "@dfinity/principal";

import type { EnvelopeBinding } from "./envelope";
import { EnvelopeFormatError } from "./envelope";
import {
  envelopeIsPasscodeProtected,
  openVetKeyEnvelope,
  wrapVetKeyForDevice,
} from "./layer1";
import type { DeviceKeyPair } from "./devices";
import {
  encodeApprovalV1,
  encodeReplaceV1,
  encodeRevokeV1,
  encodeSetDeviceApprovalPolicyV1,
  randomNonce,
  sha256,
  signTranscript,
} from "./devices";
import {
  REVOCATION_NOT_CRYPTOGRAPHIC_RECOVERY,
  REVOCATION_SERVICE_CUTOFF,
} from "../ui/recoveryCopy";
import type { FetchKeys, VetkeysCanister } from "./vetkeys";
import { fetchUserVetKey, VetkeysCallError } from "./vetkeys";

/** This device's registered identity: its id and its non-extractable keys. */
export interface DeviceIdentity {
  deviceId: string;
  keys: DeviceKeyPair;
  /** SPKI of the encryption public key — part of the envelope's binding. */
  encSpki: Uint8Array;
  /** SPKI of the signing public key. */
  signSpki: Uint8Array;
}

export interface Layer1Config {
  /** The vetkeys canister's own principal — bound into every envelope. */
  canisterId: Principal;
  owner: Principal;
  device: DeviceIdentity;
  /**
   * Asked for ONLY when the stored envelope is passcode-protected. Returning
   * `null` means the user declined, and the operation fails — it does not fall
   * through to a derive.
   */
  requestPasscode?: () => Promise<string | null>;
}

/** Why the Layer-1 path could not serve this device. */
export class Layer1Unavailable extends Error {
  constructor(
    message: string,
    readonly cause?: unknown,
  ) {
    super(message);
    this.name = "Layer1Unavailable";
  }
}

function bindingFor(config: Layer1Config): EnvelopeBinding {
  return {
    canisterId: config.canisterId,
    owner: config.owner,
    deviceId: config.device.deviceId,
    encSpki: config.device.encSpki,
  };
}

/**
 * Open this device's envelope and return the vetKey. ZERO derives.
 *
 * Throws `Layer1Unavailable` when the canister has no envelope for this device
 * (never registered, or revoked) — the one case where the caller may sensibly
 * fall back to Layer 2. Every other failure (wrong passcode, tampered
 * envelope, wrong binding) throws as itself, because falling back would hide it.
 */
export async function openThisDevicesVetKey(
  canister: VetkeysCanister,
  config: Layer1Config,
): Promise<VetKey> {
  return (await openThisDevicesEnvelope(canister, config)).vetKey;
}

/**
 * `openThisDevicesVetKey`, also returning the envelope bytes it opened.
 *
 * WALLET-CACHE-II-ONLY: the passcode-mode cache key is HKDF over the ENVELOPE's
 * Argon2id output (`cacheUnlockKeyFromPasscode(passcode, envelopeSalt)`), so the
 * caller needs the salt of the very envelope that was opened — not a second
 * read that another tab could have replaced in between. Same single query, same
 * zero derives, same error contract as `openThisDevicesVetKey` (which is this
 * function with the envelope dropped).
 */
export async function openThisDevicesEnvelope(
  canister: VetkeysCanister,
  config: Layer1Config,
): Promise<{ vetKey: VetKey; envelope: Uint8Array }> {
  let envelope: Uint8Array;
  try {
    envelope = await canister.getWrappedSecret(config.device.deviceId);
  } catch (err) {
    if (err instanceof VetkeysCallError) {
      // UnknownDevice / DeviceRevoked are the "this device cannot serve you"
      // answers; anything else is a real failure and is re-thrown as itself.
      if ("UnknownDevice" in err.error || "DeviceRevoked" in err.error) {
        throw new Layer1Unavailable(err.message, err);
      }
    }
    throw err;
  }

  let passcode: string | undefined;
  const { needsPasscode } = describeEnvelope(envelope);
  if (needsPasscode) {
    const supplied = await config.requestPasscode?.();
    if (supplied === null || supplied === undefined) {
      throw new EnvelopeFormatError(
        "this device's key envelope is protected by your wallet passcode, and it was not " +
          "provided",
      );
    }
    passcode = supplied;
  }
  const vetKey = await openVetKeyEnvelope(
    envelope,
    bindingFor(config),
    config.device.keys.encryption.privateKey,
    passcode,
  );
  return { vetKey, envelope };
}

/**
 * Whether a stored envelope needs a passcode, without opening it.
 *
 * The parse is FAIL-CLOSED: a malformed or unknown-version envelope throws here
 * rather than being read as "II-only, no passcode needed", which would turn a
 * tampered envelope into a silent downgrade.
 */
export function describeEnvelope(envelope: Uint8Array): { needsPasscode: boolean } {
  return { needsPasscode: envelopeIsPasscodeProtected(envelope) };
}

/**
 * The production `FetchKeys`: Layer 1 first, Layer 2 only if this device has no
 * usable envelope.
 *
 * The verification key is still fetched — `vetkd_public_key` is FREE and is not
 * a derivation, so this costs no quota and no cycles of consequence.
 */
export function createLayer1FirstFetchKeys(config: Layer1Config): FetchKeys {
  return async (canister, principal) => {
    try {
      const vetKey = await openThisDevicesVetKey(canister, config);
      const verificationKey: DerivedPublicKey = DerivedPublicKeyImpl.deserialize(
        await canister.getVetkeyVerificationKey(),
      );
      // `remaining` is null on this path, and that is the honest value: no
      // derive was performed, so there is no §H′ allowance to report. Reporting
      // a full quota here would tell the user something the canister did not say.
      return { vetKey, verificationKey, remaining: null };
    } catch (err) {
      if (err instanceof Layer1Unavailable) {
        // The ONLY fallback: this device has no envelope to open.
        return fetchUserVetKey(canister, principal);
      }
      throw err;
    }
  };
}

/**
 * Everything the session needs to run Layer 1, with the storage and key
 * generation injected so this is testable without IndexedDB or real RSA.
 */
export interface SessionKeyDeps {
  canisterId: Principal;
  owner: Principal;
  /** This browser's device identity for this principal, or null if new here. */
  loadDevice: () => Promise<DeviceIdentity | null>;
  /** Persist a newly enrolled device identity. */
  saveDevice: (identity: DeviceIdentity) => Promise<void>;
  /** Generate a fresh device identity (non-extractable keys + a fresh id). */
  createDevice: () => Promise<DeviceIdentity>;
  requestPasscode?: () => Promise<string | null>;
  /** Reports whether this acquisition took the fast path — for UX and tests. */
  onPath?: (path: "layer1" | "layer2-bootstrap") => void;
}

/**
 * The session's `FetchKeys`: Layer 1 when this browser is a registered device,
 * and otherwise ONE Layer-2 ceremony that immediately enrolls this device so
 * that no later call derives again.
 *
 * ENROLMENT IS PART OF THE SAME ACQUISITION, deliberately. The §B bootstrap
 * ticket exists only in the window right after a successful derive, so a design
 * that derived now and registered "later" would routinely find the ticket
 * expired and derive again — turning the fallback into the normal path, which
 * is the failure this whole lane exists to end.
 */
export function createSessionFetchKeys(deps: SessionKeyDeps): FetchKeys {
  return async (canister, principal) => {
    const existing = await deps.loadDevice();
    if (existing !== null) {
      const config: Layer1Config = {
        canisterId: deps.canisterId,
        owner: deps.owner,
        device: existing,
        ...(deps.requestPasscode !== undefined ? { requestPasscode: deps.requestPasscode } : {}),
      };
      try {
        const vetKey = await openThisDevicesVetKey(canister, config);
        deps.onPath?.("layer1");
        const verificationKey = DerivedPublicKeyImpl.deserialize(
          await canister.getVetkeyVerificationKey(),
        );
        return { vetKey, verificationKey, remaining: null };
      } catch (err) {
        if (!(err instanceof Layer1Unavailable)) throw err;
        // This device's envelope is gone (revoked, or the canister was
        // reinstalled). Fall through to a fresh ceremony — and forget nothing
        // silently: the new enrolment below replaces the stale identity.
      }
    }

    // ── Layer 2: the rare path ───────────────────────────────────────────────
    const derived = await fetchUserVetKey(canister, principal);
    const device = await deps.createDevice();
    const config: Layer1Config = { canisterId: deps.canisterId, owner: deps.owner, device };
    // Bootstrap consumes the §B ticket this derive just minted. The canister
    // (`bootstrap_path_open`, canisters/vetkeys/src/lib.rs) opens the Bootstrap
    // path when the principal has NEVER enrolled, or has AT LEAST ONE ACTIVE
    // device already — adding a further device this way is allowed. It refuses
    // only a principal that enrolled before and now has ZERO active devices
    // (every device revoked) unless an `authorize_re_bootstrap` approval signed
    // by a previously active device is on file; otherwise whoever holds the II
    // could undo the revocation just by enrolling again. That refusal is an
    // honest failure, not a second derive.
    await enrollDevice(canister, config, derived.vetKey, { Bootstrap: null });
    await deps.saveDevice(device);
    deps.onPath?.("layer2-bootstrap");
    return derived;
  };
}

/**
 * WALLET-CACHE-II-ONLY SSA C1 — ONE key acquisition in flight per principal.
 *
 * THE RACE THIS CLOSES. On a device with no envelope, every caller of the
 * session's `FetchKeys` looks up the device, finds none, and runs its OWN
 * Layer-2 ceremony — a paid vetKD derive against a five-per-day quota. The
 * login-time priming attempt (VETKEYS-AGE-2MIN) and a user's first shield /
 * sync were two such callers with nothing ordering them: priming's latch only
 * ever guarded priming against itself. Fired together they derived TWICE.
 *
 * THE CONSTRUCTION. Wrap the session provider so that a call arriving while
 * another call for the same principal (on the same canister actor) is still in
 * flight does not start a second acquisition — it AWAITS the one already
 * running and receives the same result (or the same refusal). The in-flight
 * entry is dropped only when that acquisition SETTLES, and the ceremony saves
 * the enrolled device BEFORE it settles, so a call arriving afterwards finds
 * the device and takes the zero-derive Layer-1 path. There is therefore no
 * ordering of "priming" and "first action" in which both derive: either they
 * overlap and share one promise, or one follows the other and the follower
 * reads the envelope the leader enrolled.
 *
 * WHAT IT DOES NOT CHANGE: which path a lone call takes, what it costs, or what
 * it reports. A fast-path (Layer-1) call that happens to overlap another simply
 * shares that call's envelope read. Two TABS are two module instances with two
 * wrappers — the cross-tab race is the residual VETKEYS-AGE-2MIN already
 * discloses, unchanged here.
 */
export function singleFlightFetchKeys(inner: FetchKeys): FetchKeys {
  const inFlight = new Map<string, { canister: VetkeysCanister; result: ReturnType<FetchKeys> }>();
  return (canister, principal) => {
    const key = principal.toText();
    const running = inFlight.get(key);
    if (running !== undefined && running.canister === canister) return running.result;
    const result = inner(canister, principal);
    const entry = { canister, result };
    inFlight.set(key, entry);
    const release = () => {
      if (inFlight.get(key) === entry) inFlight.delete(key);
    };
    result.then(release, release);
    return result;
  };
}

/**
 * Seal the vetKey to this device and register it — the last step of a Layer-2
 * ceremony, after which this device never derives again.
 *
 * `approval` is `Bootstrap` for a first device (consuming the §B ticket the
 * ceremony just minted) or a `Device` approval signed by an existing one.
 */
export async function enrollDevice(
  canister: VetkeysCanister,
  config: Layer1Config,
  vetKey: VetKey,
  approval: Parameters<VetkeysCanister["registerDevice"]>[4],
  passcode?: string,
): Promise<Uint8Array> {
  const envelope = await wrapVetKeyForDevice(bindingFor(config), vetKey, passcode);
  await canister.registerDevice(
    config.device.deviceId,
    config.device.encSpki,
    config.device.signSpki,
    envelope,
    approval,
  );
  return envelope;
}

/** The PUBLIC material a new device hands to an existing one (brief V2 §C). */
export interface NewDevicePublicKeys {
  deviceId: string;
  encSpki: Uint8Array;
  signSpki: Uint8Array;
}

/**
 * Approve and register a NEW device from an EXISTING one (brief V2 §C flow).
 *
 * WHO DOES WHAT, AND WHY IT IS THIS WAY ROUND. The existing device is the one
 * that holds the vetKey, so it is the only party that can seal an envelope for
 * the new device. It therefore does all three steps: wrap the vetKey to the new
 * device's encryption key, sign the ApprovalV1 transcript with its own signing
 * key, and submit the registration. The new device only ever hands over PUBLIC
 * material (its id and two SPKI public keys) — nothing secret crosses the gap
 * between devices, so the transfer channel (QR, paste, whatever the UI offers)
 * carries no secret to protect.
 *
 * ZERO DERIVES: the existing device already has the vetKey from its own
 * envelope, so adding a device costs no vetKD call at all.
 *
 * The approval binds the new device's BOTH key hashes and the envelope hash, so
 * a relay that swapped any of them produces a signature that does not verify.
 */
export async function approveNewDevice(
  canister: VetkeysCanister,
  config: Layer1Config,
  vetKey: VetKey,
  newDevice: NewDevicePublicKeys,
  expiryNs: bigint,
  /** Passcode for the NEW device's envelope; omit for the II-only default. */
  passcode?: string,
): Promise<Uint8Array> {
  if (newDevice.deviceId === config.device.deviceId) {
    throw new Error(
      "the approving device and the new device must be different — a device cannot approve " +
        "itself onto the account it is already on",
    );
  }
  const envelope = await wrapVetKeyForDevice(
    {
      canisterId: config.canisterId,
      owner: config.owner,
      deviceId: newDevice.deviceId,
      encSpki: newDevice.encSpki,
    },
    vetKey,
    passcode,
  );
  const nonce = randomNonce();
  const transcript = encodeApprovalV1({
    canisterId: config.canisterId,
    owner: config.owner,
    issuerDeviceId: config.device.deviceId,
    newDeviceId: newDevice.deviceId,
    encPubkeyHash: await sha256(newDevice.encSpki),
    signPubkeyHash: await sha256(newDevice.signSpki),
    wrappedSecretHash: await sha256(envelope),
    nonce,
    expiryNs,
  });
  const signature = await signTranscript(config.device.keys.signing.privateKey, transcript);
  await canister.registerDevice(newDevice.deviceId, newDevice.encSpki, newDevice.signSpki, envelope, {
    Device: {
      issuer_device_id: config.device.deviceId,
      nonce,
      expiry_ns: expiryNs,
      signature,
    },
  });
  return envelope;
}

/**
 * Revoke a device from another one, and say honestly what that did.
 *
 * Returns the wording the UI must show (D-1b v4 §1): revocation is a SERVICE
 * cutoff, not cryptographic recovery. The copy is returned rather than left to
 * the caller so a screen cannot quietly ship the reassuring half alone.
 */
export async function revokeDeviceWithHonestCopy(
  canister: VetkeysCanister,
  config: Layer1Config,
  targetDeviceId: string,
  expiryNs: bigint,
): Promise<{ serviceCutoff: string; notCryptographicRecovery: string }> {
  const nonce = randomNonce();
  const transcript = encodeRevokeV1({
    canisterId: config.canisterId,
    owner: config.owner,
    issuerDeviceId: config.device.deviceId,
    targetDeviceId,
    nonce,
    expiryNs,
  });
  const signature = await signTranscript(config.device.keys.signing.privateKey, transcript);
  await canister.revokeDevice(targetDeviceId, {
    issuer_device_id: config.device.deviceId,
    nonce,
    expiry_ns: expiryNs,
    signature,
  });
  return {
    serviceCutoff: REVOCATION_SERVICE_CUTOFF,
    notCryptographicRecovery: REVOCATION_NOT_CRYPTOGRAPHIC_RECOVERY,
  };
}

/**
 * Turn the wallet passcode ON or OFF — THROUGH THE CANISTER (D-1b v3 §2).
 *
 * `passcode === undefined` restores the II-only envelope. Either way the stored
 * blob is REPLACED: a wallet-local wrapper that left the canister envelope bare
 * is forbidden by the ruling, because it would protect nothing an attacker
 * holding the stored blob could not simply ignore.
 *
 * The old envelope is fetched (not remembered) so `old_envelope_hash` describes
 * what the canister has RIGHT NOW — which is what makes a concurrent toggle
 * from another tab fail loudly instead of silently losing an update.
 */
export async function setEnvelopePasscode(
  canister: VetkeysCanister,
  config: Layer1Config,
  vetKey: VetKey,
  passcode: string | undefined,
  expiryNs: bigint,
): Promise<Uint8Array> {
  const current = await canister.getWrappedSecret(config.device.deviceId);
  const next = await wrapVetKeyForDevice(bindingFor(config), vetKey, passcode);
  const nonce = randomNonce();
  const transcript = encodeReplaceV1({
    canisterId: config.canisterId,
    owner: config.owner,
    deviceId: config.device.deviceId,
    oldEnvelopeHash: await sha256(current),
    newEnvelopeHash: await sha256(next),
    nonce,
    expiryNs,
  });
  const signature = await signTranscript(config.device.keys.signing.privateKey, transcript);
  await canister.replaceEnvelope(config.device.deviceId, next, {
    issuer_device_id: config.device.deviceId,
    nonce,
    expiry_ns: expiryNs,
    signature,
  });
  return next;
}

/**
 * LAUNCH-HARDEN-04 O-8 (WALLET-V12 O-4): set (`true`) or clear (`false`) the
 * principal's "require device approval" flag, signed by THIS device's existing
 * non-extractable signing key (no new key path, no derive). The canister only
 * accepts it from an ACTIVE device. `false` is immediate — the flag row is
 * deleted; `true` also cancels any pending II-only clear.
 */
export async function setDeviceApprovalPolicyFromDevice(
  canister: VetkeysCanister,
  config: Layer1Config,
  requireDeviceApproval: boolean,
  expiryNs: bigint,
): Promise<void> {
  if (canister.setDeviceApprovalPolicy === undefined) {
    throw new Error("this build's key service cannot change the new-device approval setting");
  }
  const nonce = randomNonce();
  const transcript = encodeSetDeviceApprovalPolicyV1({
    canisterId: config.canisterId,
    owner: config.owner,
    issuerDeviceId: config.device.deviceId,
    requireDeviceApproval,
    nonce,
    expiryNs,
  });
  const signature = await signTranscript(config.device.keys.signing.privateKey, transcript);
  await canister.setDeviceApprovalPolicy(requireDeviceApproval, {
    issuer_device_id: config.device.deviceId,
    nonce,
    expiry_ns: expiryNs,
    signature,
  });
}
