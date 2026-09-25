/**
 * STSH vetKeys wallet crypto — II-anchored keys, IBE payloads, cross-device scan
 * BRIEF_VETKEYS_CROSSDEVICE §§2-4
 *
 * One mechanism behind cross-device access, viewing keys, and recovery: the
 * user's vetKey is derived on-chain from their Internet Identity principal
 * (canisters/vetkeys), so any device that authenticates the same II principal
 * re-derives the identical key — and from it, the identical note secrets
 * (./notes.ts `deriveNoteSecrets`) — and rebuilds the wallet's note set from
 * public on-chain data alone (merkle-tree `get_payloads`, DEF-073-public).
 *
 * PINNED CONSTANTS — must byte-match canisters/vetkeys/src/lib.rs. A mismatch
 * silently breaks decryption; `assertCanisterConfig` fails loudly at startup.
 *
 * All keys stay in this module's types (VetKey); nothing here persists secrets.
 * Generate a FRESH transport key per session — never reuse one.
 */

import { Principal } from "@dfinity/principal";
import type {
  DeviceApproval,
  DeviceApprovalPolicyView,
  DeviceView,
  SignedApproval,
  VetkeysError,
} from "../../../src/declarations/vetkeys/vetkeys.did";
import {
  DerivedPublicKey,
  EncryptedVetKey,
  IbeCiphertext,
  IbeIdentity,
  IbeSeed,
  TransportSecretKey,
  VetKey,
} from "@dfinity/vetkeys";

// ── Pinned constants (canister + Rust reference test mirror these) ────────────

/** vetKD context / domain separator — canisters/vetkeys DOMAIN_SEPARATOR. */
export const VETKEYS_CONTEXT = "stsh.wallet.notes.v1";
/** Key name inside the (principal, name) key id — canisters/vetkeys KEY_NAME. */
export const VETKEYS_KEY_NAME = "notes";
/** Domain separator for the master note secret (see ./notes.ts spec block). */
export const MASTER_NOTE_SECRET_DOMAIN_SEP = "stsh-notes-master-v1";
/**
 * merkle-tree payload cap (canisters/merkle-tree/src/lib.rs
 * MAX_ENCRYPTED_PAYLOAD_BYTES) — an IBE ciphertext exceeding this would be
 * rejected on append, so we fail loudly at encryption time instead.
 */
export const MAX_ENCRYPTED_PAYLOAD_BYTES = 1024;

// ── Canister access (actor-agnostic) ──────────────────────────────────────────

/**
 * The two vetkeys-canister methods this module needs, supplied by the caller
 * (agent/actor wiring is the wallet-build lane's concern, not this module's).
 */
export interface VetkeysCanister {
  /** update `get_vetkey_verification_key : () -> (blob)` */
  getVetkeyVerificationKey(): Promise<Uint8Array>;
  /**
   * update `get_encrypted_vetkey` — a LAYER-2 operation. Rare by design: first
   * bootstrap and genuine all-devices-lost recovery only. Every call is
   * metered and quota-bound; the reply carries the caller's remaining §H′
   * allowance.
   */
  getEncryptedVetkey(transportPublicKey: Uint8Array): Promise<DeriveResult>;
  /** query `get_config : () -> (text, text)` — (domain_separator, vetkd_key_name) */
  getConfig(): Promise<[string, string]>;

  // ── Layer 1 — ZERO derives ─────────────────────────────────────────────────
  registerDevice(
    deviceId: string,
    encPubkeySpki: Uint8Array,
    signPubkeySpki: Uint8Array,
    wrappedSecret: Uint8Array,
    approval: DeviceApproval,
  ): Promise<void>;
  revokeDevice(deviceId: string, approval: SignedApproval): Promise<void>;
  /**
   * D-1b v3 §2 — replace THIS device's envelope (the passcode toggle). The
   * toggle is only real through here; a wallet-local wrapper is forbidden.
   */
  replaceEnvelope(
    deviceId: string,
    newEnvelope: Uint8Array,
    approval: SignedApproval,
  ): Promise<void>;
  getWrappedSecret(deviceId: string): Promise<Uint8Array>;
  listDevices(): Promise<DeviceView[]>;

  // ── LAUNCH-HARDEN-04 O-8 / O-1(b) — WALLET-V12 O-4 ─────────────────────────
  // Optional so a narrow test double need not script them; the live actor
  // (`actors/vetkeys.ts`) always provides all four. A caller that finds one
  // absent treats the feature as unavailable (control disabled), never as OFF.
  /** update `set_device_approval_policy` — device-signed; `false` is immediate. */
  setDeviceApprovalPolicy?(requireDeviceApproval: boolean, approval: SignedApproval): Promise<void>;
  /** update `request_device_approval_policy_clear` — II-only; returns the effective instant (ns). */
  requestDeviceApprovalPolicyClear?(): Promise<bigint>;
  /** query `device_approval_policy` — the caller's OWN flag, or null (off). */
  deviceApprovalPolicy?(): Promise<DeviceApprovalPolicyView | null>;
  /** query `get_device_check_caller` — the configured pool principal, or null. */
  getDeviceCheckCaller?(): Promise<Principal | null>;
}

/** A successful derive, plus the §H′ allowance left in the rolling window. */
export interface DeriveResult {
  encryptedKey: Uint8Array;
  remaining: number;
}

/**
 * The key-acquisition seam every flow uses.
 *
 * `remaining` is `null` when NO derive happened — the Layer-1 fast path opened
 * this device's envelope instead. That is the honest value: there is no §H′
 * allowance to report, and reporting a full quota would attribute a number to
 * the canister that it never said.
 */
export type FetchKeys = (
  canister: VetkeysCanister,
  userPrincipal: Principal,
) => Promise<{ vetKey: VetKey; verificationKey: DerivedPublicKey; remaining: number | null }>;

/**
 * The wallet warns the user at this many derives remaining — mirrors the
 * canister's pinned `QUOTA_WARN_REMAINING`.
 */
export const QUOTA_WARN_REMAINING = 3;

/**
 * VETKEYS-AGE-2MIN — the §D balance floor, in e8s (0.1 STSH). Mirrors the
 * canister's pinned `ELIGIBILITY_MIN_BALANCE_E8S` (`canisters/vetkeys/src/pins.rs`);
 * a drift lock in `tests/vetkeys_held_balance_age_v5.test.ts` reads the pin from
 * source. The login-time priming attempt fires only at or above it: below the
 * floor the canister writes no sighting, so an attempt would buy nothing.
 */
export const WALLET_ELIGIBILITY_MIN_BALANCE_E8S = 10_000_000n;

/**
 * A typed canister refusal. The variant is preserved so callers can BRANCH on
 * it (quota vs lapse vs eligibility vs approval), rather than matching on
 * English that may change.
 */
export class VetkeysCallError extends Error {
  constructor(
    readonly method: string,
    readonly error: VetkeysError,
  ) {
    super(`vetkeys.${method} failed: ${describeVetkeysError(error)}`);
    this.name = "VetkeysCallError";
  }
}

/** Seconds, rounded up — what a user-facing "try again in…" should show. */
export function retryAfterSeconds(error: VetkeysError): number | null {
  if ("DerivationQuotaExceeded" in error) {
    return Number((error.DerivationQuotaExceeded.retry_after_ns + 999_999_999n) / 1_000_000_000n);
  }
  if ("RegistrationRateExceeded" in error) {
    return Number((error.RegistrationRateExceeded.retry_after_ns + 999_999_999n) / 1_000_000_000n);
  }
  // C-26 R2 — the FLEET-wide budget. Same ceiling-rounding idiom as the two
  // above, deliberately: a shared idiom means a shared boundary, so "1 ns over
  // a second still shows the next whole second" holds identically everywhere a
  // wait is displayed.
  if ("GlobalDerivationBudgetExceeded" in error) {
    return Number(
      (error.GlobalDerivationBudgetExceeded.retry_after_ns + 999_999_999n) / 1_000_000_000n,
    );
  }
  // V5 §6.6 — held-balance-age. The SAME ceiling-rounding idiom as the three
  // above, deliberately: a shared idiom means a shared boundary, so a wait
  // never reads as shorter than it is, wherever it is displayed.
  if ("EligibilityAgeNotMet" in error) {
    return Number((error.EligibilityAgeNotMet.retry_after_ns + 999_999_999n) / 1_000_000_000n);
  }
  return null;
}

/**
 * Is retrying this refusal immediately reasonable? `AdmissionLapsed` is the one
 * refusal that means "nothing was charged, just call again" — the caller's
 * reservation was pruned or its callback arrived after a stale charge.
 */
export function isImmediatelyRetryable(error: VetkeysError): boolean {
  // `AdmissionLapsed`: nothing was charged, the reservation simply went stale —
  // call again. `EligibilityCheckUnavailable`: the eligibility question could
  // not be ASKED (unconfigured or unreachable token canister), which is
  // infrastructure state, not a verdict about this user — also retryable.
  // `PrincipalNotEligible` is deliberately NOT here: that is an authoritative
  // answer, and retrying it changes nothing until the user is funded.
  return "AdmissionLapsed" in error || "EligibilityCheckUnavailable" in error;
}

/** Human-facing text for a typed refusal. */
export function describeVetkeysError(error: VetkeysError): string {
  if ("AnonymousCaller" in error) return "sign in with Internet Identity first";
  if ("RateLimited" in error) return error.RateLimited;
  if ("DerivationQuotaExceeded" in error) {
    return `key-recovery limit reached — try again in ${retryAfterSeconds(error)} s`;
  }
  if ("AdmissionLapsed" in error) return "the request lapsed before completing — try again";
  if ("InvalidTransportKey" in error) return error.InvalidTransportKey;
  if ("NotAuthorized" in error) return error.NotAuthorized;
  if ("InvalidRequest" in error) return error.InvalidRequest;
  if ("BootstrapNotAuthorized" in error) return error.BootstrapNotAuthorized.reason;
  if ("ApprovalRejected" in error) return error.ApprovalRejected;
  if ("RegistrationRateExceeded" in error) {
    return `too many device registrations — try again in ${retryAfterSeconds(error)} s`;
  }
  if ("DeviceLimitReached" in error) {
    return `this account already has ${error.DeviceLimitReached.active} active devices — revoke one first`;
  }
  if ("UnknownDevice" in error) return "this device is not registered to your account";
  if ("DeviceRevoked" in error) return "this device has been revoked";
  if ("PrincipalNotEligible" in error) return error.PrincipalNotEligible;
  if ("EligibilityCheckUnavailable" in error) {
    return "key recovery is temporarily unavailable — please try again shortly";
  }
  // C-26 R2 — the two fleet-health refusals. Neither is a statement about this
  // user's own allowance, and neither may fall through to the generic text.
  if ("GlobalDerivationBudgetExceeded" in error) {
    return `launch capacity is currently full — the next spot opens in ${retryAfterSeconds(error)} s`;
  }
  // V5 §6.6 — its OWN string, never the generic fallback. This is a WAIT, not
  // a verdict about the user: they are already funded and there is nothing for
  // them to fix, which is exactly why it must not read like PrincipalNotEligible.
  if ("EligibilityAgeNotMet" in error) {
    return `your wallet is being prepared — first use unlocks in ${retryAfterSeconds(error)} s`;
  }
  if ("CycleFloorReached" in error) {
    // NO CYCLE FIGURES IN USER-FACING COPY (brief V4 §5.5): a balance number
    // tells an attacker how close a drain is to its goal, and tells a user
    // nothing they can act on.
    return "new device setup is temporarily paused — your existing devices keep working; please try again later";
  }
  return "the key service refused the request";
}

/**
 * Startup guard: the canister's pinned config must match ours before we derive any key.
 *
 * Asserts BOTH:
 *  - the domain separator equals our `VETKEYS_CONTEXT` (a mismatch silently breaks every
 *    payload encrypt/decrypt); and
 *  - the canister's vetKD key name equals `expectedKeyName`, which the CALLER supplies
 *    (H-2/A3): the production bootstrap passes `"key_1"`; a local/test path passes its
 *    explicitly configured test key (`"test_key_1"` / `"dfx_test_key"`). This is the vetKD
 *    curve key (the SECOND element of `get_config()`), NOT the frozen `"notes"` application
 *    key name. The parameter is REQUIRED and never inferred from a global, so a caller can
 *    never silently skip it — a mainnet canister accidentally left on `"test_key_1"` would
 *    otherwise pass this guard and derive against the wrong key, bricking every note (G1/G4).
 */
export async function assertCanisterConfig(
  canister: VetkeysCanister,
  expectedKeyName: string,
): Promise<void> {
  const [domainSeparator, keyName] = await canister.getConfig();
  if (domainSeparator !== VETKEYS_CONTEXT) {
    throw new Error(
      `vetkeys canister domain separator mismatch: canister="${domainSeparator}" ` +
        `wallet="${VETKEYS_CONTEXT}" — refusing to derive keys (would silently ` +
        `break payload decryption)`,
    );
  }
  if (keyName !== expectedKeyName) {
    throw new Error(
      `vetkeys canister key-name mismatch: canister="${keyName}" ` +
        `expected="${expectedKeyName}" — refusing to derive keys (the canister is on the ` +
        `wrong vetKD key for this network; a production canister must be on "key_1")`,
    );
  }
}

// ── Identity derivation ───────────────────────────────────────────────────────

/**
 * The vetKD derivation input for a user — and therefore the IBE identity their
 * payloads are encrypted to: `len(principal) || principal || key_name`.
 * Mirror of `ic_vetkeys::key_manager::key_id_to_vetkd_input` (Rust) — pinned
 * by the cross-device acceptance test.
 */
export function vetkdInput(principal: Principal, keyName: string = VETKEYS_KEY_NAME): Uint8Array {
  const p = principal.toUint8Array();
  const name = new TextEncoder().encode(keyName);
  const input = new Uint8Array(1 + p.length + name.length);
  input[0] = p.length;
  input.set(p, 1);
  input.set(name, 1 + p.length);
  return input;
}

/** IBE identity for a recipient principal — derived OFFLINE, no canister call. */
export function ibeIdentityFor(principal: Principal): IbeIdentity {
  return IbeIdentity.fromBytes(vetkdInput(principal));
}

// ── Key session ───────────────────────────────────────────────────────────────

/**
 * One device session: generate a FRESH transport key, fetch this user's
 * encrypted vetKey, decrypt and VERIFY it against the canister's verification
 * key. Deterministic: the same II principal receives the identical VetKey on
 * every device/session (the transport key only protects it in flight).
 */
export async function fetchUserVetKey(
  canister: VetkeysCanister,
  userPrincipal: Principal,
): Promise<{ vetKey: VetKey; verificationKey: DerivedPublicKey; remaining: number }> {
  const verificationKey = DerivedPublicKey.deserialize(
    await canister.getVetkeyVerificationKey(),
  );
  const tsk = TransportSecretKey.random(); // fresh per session — never reuse
  const derived = await canister.getEncryptedVetkey(tsk.publicKeyBytes());
  const encrypted = EncryptedVetKey.deserialize(derived.encryptedKey);
  const vetKey = encrypted.decryptAndVerify(
    tsk,
    verificationKey,
    vetkdInput(userPrincipal),
  );
  return { vetKey, verificationKey, remaining: derived.remaining };
}

/**
 * The 32-byte master note secret — the root of the HD note-secret tree
 * (./notes.ts `deriveNoteSecrets`). Same VetKey -> same master, always.
 */
export function masterNoteSecret(vetKey: VetKey): Uint8Array {
  return vetKey.deriveSymmetricKey(MASTER_NOTE_SECRET_DOMAIN_SEP, 32);
}

// ── IBE note payloads ─────────────────────────────────────────────────────────

/**
 * IBE-encrypt a note payload to a recipient's II principal — for a self-shield
 * that is the user themselves; for a private-spend output, the actual
 * recipient. Entirely OFFLINE: the recipient's IBE "public key" is
 * (verificationKey, identity-from-principal); no canister call.
 *
 * The ciphertext goes into the EXISTING `append_commitment(commitment,
 * encrypted_payload)` path — the pool/merkle canisters treat it as opaque
 * bytes (size-checked only), unchanged.
 *
 * Throws if the ciphertext would exceed the merkle-tree's 1024-byte cap
 * (structurally impossible for the 104-byte note layout — IBE overhead is
 * 136 bytes — but fail loudly rather than on-chain, per the brief).
 */
export function encryptNotePayload(
  verificationKey: DerivedPublicKey,
  recipient: Principal,
  payload: Uint8Array,
): Uint8Array {
  const ciphertext = IbeCiphertext.encrypt(
    verificationKey,
    ibeIdentityFor(recipient),
    payload,
    IbeSeed.random(),
  ).serialize();
  if (ciphertext.length > MAX_ENCRYPTED_PAYLOAD_BYTES) {
    throw new Error(
      `IBE ciphertext ${ciphertext.length} bytes exceeds the merkle-tree cap ` +
        `${MAX_ENCRYPTED_PAYLOAD_BYTES} — payload too large`,
    );
  }
  return ciphertext;
}

/**
 * Trial-decrypt one on-chain payload with the user's vetKey. Returns the
 * plaintext if it is ours, null otherwise (not our note / not an IBE payload).
 */
export function tryDecryptNotePayload(vetKey: VetKey, bytes: Uint8Array): Uint8Array | null {
  try {
    return IbeCiphertext.deserialize(bytes).decrypt(vetKey);
  } catch {
    return null;
  }
}

// ── Cross-device scan ─────────────────────────────────────────────────────────

/** One page of `merkle_tree.get_payloads(from_index, limit)`. */
export type PayloadPage = Array<[bigint, Uint8Array]>;

export interface RecoveredPayload {
  leafIndex: bigint;
  plaintext: Uint8Array;
}

/**
 * Rebuild the user's payload set from on-chain data alone: page through the
 * merkle-tree's public `get_payloads` and trial-decrypt each entry. The ones
 * that decrypt are ours (./notes.ts `noteFromBytes` parses them back into
 * notes). Runs identically on ANY device with the same II principal — this is
 * cross-device access, and run on a fresh session it is recovery.
 *
 * `tryDecrypt` is injected so tests can drive the paging/filtering logic
 * without a live chain; production binds `tryDecryptNotePayload(vetKey, ·)`.
 *
 * (Future optimisation, deliberately NOT now: view tags to cheaply skip most
 * payloads — only needed at large note counts. Noted in wallet/BUILD_PLAN.md.)
 */
export async function scanPayloads(
  fetchPage: (fromIndex: bigint, limit: bigint) => Promise<PayloadPage>,
  tryDecrypt: (bytes: Uint8Array) => Uint8Array | null,
  onProgress?: (scanned: bigint) => void,
  pageSize: bigint = 500n,
): Promise<RecoveredPayload[]> {
  const recovered: RecoveredPayload[] = [];
  let from = 0n;
  for (;;) {
    const page = await fetchPage(from, pageSize);
    if (page.length === 0) break;
    for (const [leafIndex, bytes] of page) {
      const plaintext = tryDecrypt(bytes);
      if (plaintext !== null) recovered.push({ leafIndex, plaintext });
    }
    from += BigInt(page.length);
    onProgress?.(from);
    if (BigInt(page.length) < pageSize) break;
  }
  return recovered;
}
