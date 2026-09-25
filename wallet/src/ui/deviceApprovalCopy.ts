/**
 * STSH — "Approve new devices" (WALLET-V12 O-4; LAUNCH-HARDEN-04 O-8; Owner
 * O-8 ruling 2026-09-23; SSA F-3; CTO Addendum 1 E-3).
 *
 * Canister semantics (`canisters/vetkeys/vetkeys.did`, O-8 comments):
 *   - `device_approval_policy()` → null = OFF; a row = ON.
 *   - ON is set only by an ACTIVE device's signature (so never from zero devices).
 *   - OFF from an ACTIVE device (`set_device_approval_policy(false)`) is
 *     IMMEDIATE — the row is deleted, no pending state.
 *   - OFF without a device (`request_device_approval_policy_clear()`, II-only)
 *     takes effect 24 h later; the row keeps `pending_clear_effective_at_ns`
 *     and is NOT deleted when that instant passes (lazy check canister-side).
 *   - The flag blocks NEW-DEVICE ENROLMENT only. It does not stop a live,
 *     hijacked II session — so no copy here claims more than that (I-4).
 *
 * This module is pure: classify the read-back against the local clock, and the
 * ruled copy. The matured-clear check defaults to "pending" inside a clock
 * skew margin — the canister's clock decides, and a local clock running fast
 * must not render a still-armed flag as OFF.
 */

import type { DeviceApprovalPolicyView } from "../../../src/declarations/vetkeys/vetkeys.did";

export type DeviceApprovalState =
  | { kind: "off" }
  | { kind: "on" }
  | { kind: "pending-clear"; effectiveAtNs: bigint };

/** Local-clock margin before a matured II-only clear renders as OFF. */
export const DEVICE_APPROVAL_CLOCK_MARGIN_NS = 5n * 60n * 1_000_000_000n;

export function classifyDeviceApprovalPolicy(
  view: DeviceApprovalPolicyView | null,
  nowNs: bigint,
): DeviceApprovalState {
  if (view === null || !view.require_device_approval) return { kind: "off" };
  if (view.pending_clear_effective_at_ns.length === 1) {
    const t = view.pending_clear_effective_at_ns[0];
    // Matured (lazy row): OFF — but only once clearly past, never on a guess.
    if (nowNs >= t + DEVICE_APPROVAL_CLOCK_MARGIN_NS) return { kind: "off" };
    return { kind: "pending-clear", effectiveAtNs: t };
  }
  return { kind: "on" };
}

/** Whether new-device enrolment is currently gated (ON, or a clear not yet in force). */
export function deviceApprovalBlocksEnrolment(state: DeviceApprovalState): boolean {
  return state.kind !== "off";
}

// ── Copy (O-6: one idea per line, plain words; O-7: advisory is copper) ──────

export const DEVICE_APPROVAL_TOGGLE_LABEL = "Approve new devices from a device I already have";
/** SSA E-3 / A1: the ON line — no stronger claim than the canister makes. */
export const DEVICE_APPROVAL_ON_LINE = "New devices need approval from one you already have.";
/** CTO Addendum 1 E-3: no device-to-device handoff ships in this release. */
export const DEVICE_APPROVAL_NO_HANDOFF_LINE =
  "New devices can't be added while this is on (in this release).";
export const DEVICE_APPROVAL_OFF_LINE = "Off.";
/** S5: the canister refuses to set the flag with zero active devices. */
export const DEVICE_APPROVAL_ZERO_DEVICES_LINE = "Set up this device first to use this.";
/** ON can only be signed by an enrolled device; this browser is not one. */
export const DEVICE_APPROVAL_NOT_THIS_DEVICE_LINE = "Turn this on from a device you already use.";
export const DEVICE_APPROVAL_UNAVAILABLE_LINE = "Open your private balance to change this.";

export function deviceApprovalPendingLine(effectiveAtNs: bigint): string {
  const when = new Date(Number(effectiveAtNs / 1_000_000n)).toLocaleString();
  return `Turns off at ${when} (24h).`;
}

/**
 * SSA E-3: the new-device enrolment refusal under ON — exactly three facts,
 * one line each, ≤ 15 words, advisory. Shown only after `device_approval_policy()`
 * confirms the flag, never by parsing the refusal's reason text.
 */
export const DEVICE_APPROVAL_REFUSAL_LINES: readonly string[] = [
  "This wallet only adds devices approved from a device you already use.",
  "On your other device, turn off “Approve new devices” in Settings. It's instant.",
  "Or request turn-off here. It takes 24 hours.",
];
export const DEVICE_APPROVAL_REQUEST_CLEAR_BUTTON = "Request turn-off";
