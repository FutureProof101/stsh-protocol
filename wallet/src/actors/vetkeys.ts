/**
 * vetKeys canister actor (wallet-build Commit 4).
 *
 * Adapts the dfx-generated vetkeys declarations into the `VetkeysCanister`
 * interface that `crypto/vetkeys.ts` already consumes (that module was written
 * agent-agnostic on purpose — actor wiring was left for this lane). The three
 * methods map 1:1 to `canisters/vetkeys/vetkeys.did`:
 *   get_vetkey_verification_key : () -> (blob)
 *   get_encrypted_vetkey        : (blob) -> (variant { Ok : EncryptedVetKeyReply;
 *                                                        Err : VetkeysError })
 *   get_config                  : () -> (text, text) query
 * plus the W-VETKEYS Layer-1 registry (register/revoke/get_wrapped_secret/
 * list_devices), which perform ZERO vetKD derives, and (WALLET-V12) the
 * LAUNCH-HARDEN-04 O-8 device-approval policy (set / II-only clear / read) and
 * the O-1(b) `get_device_check_caller` readback.
 */

import { Actor, type HttpAgent } from "@dfinity/agent";

import { idlFactory } from "../../../src/declarations/vetkeys/vetkeys.did.js";
import type { _SERVICE } from "../../../src/declarations/vetkeys/vetkeys.did";
import type { Principal } from "@dfinity/principal";
import type {
  DeviceApproval,
  DeviceApprovalPolicyView,
  DeviceView,
  SignedApproval,
  VetkeysError,
} from "../../../src/declarations/vetkeys/vetkeys.did";
import type { DeriveResult, VetkeysCanister } from "../crypto/vetkeys";
import { VetkeysCallError } from "../crypto/vetkeys";
import { toBytes } from "./common";

/**
 * Pure adapter: raw candid actor -> `VetkeysCanister`. Unwraps the
 * `get_encrypted_vetkey` result envelope (throws on `Err`) and normalises blob
 * outputs to `Uint8Array`. Mock-testable with any object satisfying `_SERVICE`.
 */
export function wrapVetkeysActor(raw: _SERVICE): VetkeysCanister {
  return {
    async getVetkeyVerificationKey(): Promise<Uint8Array> {
      return toBytes(await raw.get_vetkey_verification_key());
    },

    async getEncryptedVetkey(transportPublicKey: Uint8Array): Promise<DeriveResult> {
      const res = await raw.get_encrypted_vetkey(transportPublicKey);
      if ("Err" in res) {
        // Typed, not stringly: the wallet must distinguish "out of quota until
        // T" from "your call lapsed, retry now" from "not eligible", and each
        // needs a different thing said to the user.
        throw new VetkeysCallError("get_encrypted_vetkey", res.Err);
      }
      return { encryptedKey: toBytes(res.Ok.encrypted_key), remaining: res.Ok.remaining };
    },

    async registerDevice(
      deviceId: string,
      encPubkeySpki: Uint8Array,
      signPubkeySpki: Uint8Array,
      wrappedSecret: Uint8Array,
      approval: DeviceApproval,
    ): Promise<void> {
      const res = await raw.register_device(
        deviceId,
        encPubkeySpki,
        signPubkeySpki,
        wrappedSecret,
        approval,
      );
      if ("Err" in res) throw new VetkeysCallError("register_device", res.Err);
    },

    async replaceEnvelope(
      deviceId: string,
      newEnvelope: Uint8Array,
      approval: SignedApproval,
    ): Promise<void> {
      const res = await raw.replace_envelope(deviceId, newEnvelope, approval);
      if ("Err" in res) throw new VetkeysCallError("replace_envelope", res.Err);
    },

    async revokeDevice(deviceId: string, approval: SignedApproval): Promise<void> {
      const res = await raw.revoke_device(deviceId, approval);
      if ("Err" in res) throw new VetkeysCallError("revoke_device", res.Err);
    },

    async getWrappedSecret(deviceId: string): Promise<Uint8Array> {
      const res = await raw.get_wrapped_secret(deviceId);
      if ("Err" in res) throw new VetkeysCallError("get_wrapped_secret", res.Err);
      return toBytes(res.Ok);
    },

    async listDevices(): Promise<DeviceView[]> {
      return raw.list_devices();
    },

    async getConfig(): Promise<[string, string]> {
      const [domainSeparator, keyName] = await raw.get_config();
      return [domainSeparator, keyName];
    },

    // ── LAUNCH-HARDEN-04 O-8 / O-1(b) (WALLET-V12 O-1/O-4) ──────────────────

    async setDeviceApprovalPolicy(
      requireDeviceApproval: boolean,
      approval: SignedApproval,
    ): Promise<void> {
      const res = await raw.set_device_approval_policy(requireDeviceApproval, approval);
      if ("Err" in res) throw new VetkeysCallError("set_device_approval_policy", res.Err);
    },

    async requestDeviceApprovalPolicyClear(): Promise<bigint> {
      const res = await raw.request_device_approval_policy_clear();
      if ("Err" in res) throw new VetkeysCallError("request_device_approval_policy_clear", res.Err);
      return res.Ok;
    },

    async deviceApprovalPolicy(): Promise<DeviceApprovalPolicyView | null> {
      const res = await raw.device_approval_policy();
      return res.length === 1 ? res[0] : null;
    },

    async getDeviceCheckCaller(): Promise<Principal | null> {
      const res = await raw.get_device_check_caller();
      return res.length === 1 ? res[0] : null;
    },
  };
}

/** Build a live vetKeys actor bound to `agent` and adapt it. */
export function createVetkeysActor(canisterId: string, agent: HttpAgent): VetkeysCanister {
  const raw = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });
  return wrapVetkeysActor(raw);
}
