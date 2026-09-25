/**
 * J-17b — the operator page's PURE half: hash binding, proposal encoding, the
 * exact-Candid preview, the client-derived in-flight quota, and typed error
 * rendering. No DOM, no agent, no I/O — `ui/pages/operator.ts` is the shell
 * around this, and every rule a signer depends on is unit-testable here.
 *
 * The V1 action surface is CLOSED, on purpose (brief: "do not build a generic
 * dispatcher"): four `Management` variants plus the top-level `UpdateSignerSet`
 * — exactly what J-18 and A-7 need. The 21 `Application` variants, the
 * `ReadModel` plane, both reconcile classes and the two upgrade-via-Upgrader
 * classes are deliberately unreachable from this page.
 */

import { Principal } from "@dfinity/principal";

import type {
  ManifestDisposition,
  ProposalView,
  VaultActionKind,
  VaultError,
} from "../../../src/declarations/vault/vault.did";
import type {
  RecoveryError,
  RotationProposalView,
} from "../../../src/declarations/upgrader/upgrader.did";
import { pinForRole, ROLE_PACKAGE_ALIAS, type RolePin, type WasmPins } from "../release/wasmPins";

// ── Hex ──────────────────────────────────────────────────────────────────────

const HEX64 = /^[0-9a-f]{64}$/;

export function bytesToHex(bytes: Uint8Array | number[]): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Strict 32-byte hex -> bytes. Returns null for ANYTHING else. */
export function hex32ToBytes(hex: string): Uint8Array | null {
  const normalised = hex.trim().toLowerCase();
  if (!HEX64.test(normalised)) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) out[i] = Number.parseInt(normalised.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ── Approve: the CUST-SSA-001 binding ────────────────────────────────────────

export type ApprovalBinding =
  | { kind: "bound"; proposalId: bigint; commitmentHash: Uint8Array }
  | { kind: "refused"; reason: string };

/**
 * Bind an approval to the proposal's STORED commitment hash (R1.5 /
 * CUST-SSA-001).
 *
 * The signer types the full 64-hex hash. This compares it BYTE FOR BYTE against
 * the hash on the view and refuses on any difference — the refusal is the whole
 * point, so it happens here, before an actor exists, and the caller has no way
 * to reach `approve` except through a `bound` result. A truncated or prefix
 * match is a refusal: `startsWith` on a hash is not a comparison.
 *
 * The bytes SENT are the view's, never the typed string's. Typing is the
 * signer's confirmation that they read the hash; it is not the source of the
 * argument, so a hash that passes confirmation cannot then be mis-transcribed
 * into the call.
 *
 * GENERALISED over `{proposal_id, commitment_hash}` (UPG-ROT-UI §5), so the
 * Vault's `ProposalView` and the Upgrader's `RotationProposalView` bind through
 * the SAME code rather than through a second copy of this rule. Widening the
 * parameter changes no existing behaviour: `ProposalView` still satisfies it.
 */
export type CommitmentBearingView = {
  proposal_id: bigint;
  commitment_hash: Uint8Array | number[];
};

export function bindApproval(view: CommitmentBearingView, typed: string): ApprovalBinding {
  const stored = Uint8Array.from(view.commitment_hash);
  if (stored.length !== 32) {
    return {
      kind: "refused",
      reason: `The proposal's stored commitment hash is ${stored.length} bytes, not 32. Refusing to approve.`,
    };
  }
  const typedBytes = hex32ToBytes(typed);
  if (typedBytes === null) {
    return {
      kind: "refused",
      reason:
        "Paste the FULL 64-character commitment hash exactly as shown on the proposal " +
        "(lowercase hex, no 0x, no spaces). Nothing was sent.",
    };
  }
  let equal = typedBytes.length === stored.length;
  for (let i = 0; i < stored.length; i += 1) {
    if (typedBytes[i] !== stored[i]) equal = false;
  }
  if (!equal) {
    return {
      kind: "refused",
      reason:
        "The hash you pasted does not match this proposal's stored commitment hash. " +
        "Nothing was sent, and the proposal is unchanged.",
    };
  }
  return { kind: "bound", proposalId: view.proposal_id, commitmentHash: stored };
}

// ── Proposal construction ────────────────────────────────────────────────────

const BORN_UNDER_VAULT: ManifestDisposition = { BornUnderVault: null };

export type BuildResult<T> = { ok: T } | { refused: string };

/** A parsed principal, or the reason it is not one. */
export function parsePrincipal(text: string): BuildResult<Principal> {
  const trimmed = text.trim();
  if (trimmed === "") return { refused: "A principal is required." };
  try {
    return { ok: Principal.fromText(trimmed) };
  } catch {
    return { refused: `Not a valid principal: ${JSON.stringify(trimmed)}` };
  }
}

/** Parse a whitespace/comma separated principal list, rejecting duplicates. */
export function parsePrincipalList(text: string): BuildResult<Principal[]> {
  const parts = text
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter((p) => p !== "");
  if (parts.length === 0) return { refused: "At least one principal is required." };
  const out: Principal[] = [];
  const seen = new Set<string>();
  for (const part of parts) {
    const parsed = parsePrincipal(part);
    if ("refused" in parsed) return parsed;
    const text2 = parsed.ok.toText();
    if (seen.has(text2)) {
      // Every custody surface rejects duplicates (SSA F-03); catching it here
      // means the signer sees which one, rather than a generic canister reject.
      return { refused: `Duplicate principal in the list: ${text2}` };
    }
    seen.add(text2);
    out.push(parsed.ok);
  }
  return { ok: out };
}

/**
 * `Management.CreateCanister` for one of the nine BORN_UNDER_VAULT roles.
 *
 * The disposition is FIXED at `BornUnderVault` and is not a form field:
 * `SetControllerAtCutover` describes a canister that already exists and is
 * adopted, and `OutOfScope` is a manifest classification, not something to
 * create. Offering the choice here would only ever be a way to get it wrong.
 */
export function buildCreateCanister(role: string): BuildResult<VaultActionKind> {
  if (ROLE_PACKAGE_ALIAS[role] === undefined) {
    return { refused: `Unknown role ${JSON.stringify(role)} — not a BORN_UNDER_VAULT role.` };
  }
  return {
    ok: {
      Management: {
        CreateCanister: { manifest_purpose: role, disposition: BORN_UNDER_VAULT },
      },
    },
  };
}

export interface CodeProposalInput {
  target: Principal;
  /** The role the artifact is FOR — used to select the pin, not sent on chain. */
  role: string;
  /** The sha256 the operator typed, independently of the file. */
  typedWasmHash: string;
  /** sha256 of the bytes actually read from disk, computed locally. */
  localWasmHash: string;
  wasmBytes: Uint8Array;
  /** sha256 of the init/upgrade argument bytes. */
  argHash: string;
  argBytes: Uint8Array;
  pins: WasmPins;
  /** Explicit acknowledgement for a role that HAS no pin (vetkeys, D1/A-7). */
  unpinnedRoleAcknowledged: boolean;
}

/** The three-way artifact check, reported so the page can show each limb. */
export interface ArtifactCheck {
  pin: RolePin;
  localMatchesTyped: boolean;
  localMatchesPin: boolean | null;
}

/**
 * Check the picked file against BOTH the typed hash and the release pin.
 *
 * Two independent statements have to agree before any bytes are proposable:
 * "this is the file I meant" (typed) and "this is the reviewed build" (pin).
 * The typed hash alone proves only that the operator can read a filename; the
 * pin alone proves only that SOME pinned build was picked. `null`
 * `localMatchesPin` means the role carries no pin by ruling — the ONLY case,
 * and it needs the acknowledgement below.
 */
export function checkArtifact(input: CodeProposalInput): ArtifactCheck {
  const pin = pinForRole(input.role, input.pins);
  const local = input.localWasmHash.trim().toLowerCase();
  return {
    pin,
    localMatchesTyped: HEX64.test(local) && local === input.typedWasmHash.trim().toLowerCase(),
    localMatchesPin: pin.kind === "pinned" ? local === pin.sha256 : null,
  };
}

function requireArtifact(input: CodeProposalInput): string | null {
  const check = checkArtifact(input);
  if (check.pin.kind === "unknown-role") {
    return `Unknown role ${JSON.stringify(input.role)} — refusing to build an install proposal.`;
  }
  if (!HEX64.test(input.localWasmHash.trim().toLowerCase())) {
    return "No local sha256 for the selected file — pick the Wasm file again.";
  }
  if (!check.localMatchesTyped) {
    return (
      "The selected file's sha256 does not equal the hash you typed. " +
      "Nothing was sent and no proposal was built."
    );
  }
  if (check.pin.kind === "unpinned-by-ruling") {
    if (!input.unpinnedRoleAcknowledged) {
      return (
        `The ${input.role} role carries NO [wasm.*] pin in the release record (D1 — installed ` +
        "at A-7). Its bytes cannot be checked against a reviewed build here. Tick the " +
        "unpinned-role acknowledgement, and record the Owner ruling id in the operator log, " +
        "to build this proposal anyway."
      );
    }
    return null;
  }
  if (check.localMatchesPin !== true) {
    return (
      `The selected file's sha256 does not equal the pinned ${check.pin.pkg} build in ` +
      "deployment/mainnet/release_hashes.toml. This is not the reviewed artifact. " +
      "Nothing was sent."
    );
  }
  return null;
}

function codePayload(input: CodeProposalInput): BuildResult<{
  target: Principal;
  expected_wasm_hash: Uint8Array;
  expected_arg_hash: Uint8Array;
  wasm_bytes: Uint8Array;
  arg_bytes: Uint8Array;
}> {
  const refusal = requireArtifact(input);
  if (refusal !== null) return { refused: refusal };
  const wasmHash = hex32ToBytes(input.typedWasmHash);
  const argHash = hex32ToBytes(input.argHash);
  if (wasmHash === null) return { refused: "The expected wasm hash must be 64 hex characters." };
  if (argHash === null) return { refused: "The expected arg hash must be 64 hex characters." };
  return {
    ok: {
      target: input.target,
      expected_wasm_hash: wasmHash,
      expected_arg_hash: argHash,
      wasm_bytes: input.wasmBytes,
      arg_bytes: input.argBytes,
    },
  };
}

/** `Management.InstallCode` — install-mode, against an allocated principal. */
export function buildInstallCode(input: CodeProposalInput): BuildResult<VaultActionKind> {
  const payload = codePayload(input);
  if ("refused" in payload) return payload;
  return { ok: { Management: { InstallCode: payload.ok } } };
}

/** `Management.Upgrade` — upgrade-mode, same hash discipline. */
export function buildUpgrade(input: CodeProposalInput): BuildResult<VaultActionKind> {
  const payload = codePayload(input);
  if ("refused" in payload) return payload;
  return { ok: { Management: { Upgrade: payload.ok } } };
}

/**
 * `Management.UpdateSettings` — the controller set, and the ONLY cutover-related
 * Vault action (see the ring-closure order in MAINNET_DEPLOYMENT.md: the Vault
 * must ALREADY be a controller of the target before this proposal can execute).
 */
export function buildUpdateSettings(input: {
  target: Principal;
  controllers: Principal[];
}): BuildResult<VaultActionKind> {
  if (input.controllers.length === 0) {
    return {
      refused:
        "An empty controller set would leave the target with no controller at all. Refusing.",
    };
  }
  return {
    ok: { Management: { UpdateSettings: { target: input.target, controllers: input.controllers } } },
  };
}

/** Top-level `UpdateSignerSet` — NOT a `Management` variant (SSA F-05). */
export function buildUpdateSignerSet(input: {
  signers: Principal[];
  threshold: number;
}): BuildResult<VaultActionKind> {
  if (!Number.isInteger(input.threshold) || input.threshold < 1) {
    return { refused: "The threshold must be a positive whole number." };
  }
  if (input.threshold > input.signers.length) {
    return {
      refused: `A threshold of ${input.threshold} cannot be met by ${input.signers.length} signer(s).`,
    };
  }
  return { ok: { UpdateSignerSet: { signers: input.signers, threshold: input.threshold } } };
}

// ── Exact-Candid preview ─────────────────────────────────────────────────────

/**
 * How a blob is rendered in the preview.
 *
 * A ~1.7 MB `wasm_bytes` cannot be shown as literal Candid, and a preview a
 * human cannot read is not a preview. It is rendered as its LENGTH AND SHA256
 * instead, marked as an abbreviation in the preview itself, which is the same
 * binding the canister enforces — `expected_wasm_hash` is checked against the
 * bytes on execution, so the abbreviation names exactly the property that makes
 * the bytes the right ones. Every OTHER blob (the two 32-byte hashes) is shown
 * in full.
 */
const BLOB_INLINE_MAX = 64;

function blobLiteral(bytes: Uint8Array, sha256: string | null): string {
  if (bytes.length <= BLOB_INLINE_MAX) {
    let escaped = "";
    for (const b of bytes) escaped += `\\${b.toString(16).padStart(2, "0")}`;
    return `blob "${escaped}"`;
  }
  const digest = sha256 === null ? "" : `, sha256 ${sha256}`;
  return `blob /* ABBREVIATED: ${bytes.length} bytes${digest} */`;
}

function principalLiteral(p: Principal): string {
  return `principal "${p.toText()}"`;
}

/**
 * Render the EXACT argument tuple `propose` will be called with.
 *
 * The second element is always `null` — the ruled default lifetime (SSA F-04).
 * It is shown rather than omitted so the signer can see that no custom expiry
 * is being requested.
 */
export function candidPreview(
  kind: VaultActionKind,
  artifactDigests?: { wasmSha256?: string; argSha256?: string },
): string {
  return `(\n${indent(actionLiteral(kind, artifactDigests), 2)},\n  null,\n)`;
}

function indent(text: string, by: number): string {
  const pad = " ".repeat(by);
  return text
    .split("\n")
    .map((line) => (line === "" ? line : pad + line))
    .join("\n");
}

function actionLiteral(
  kind: VaultActionKind,
  digests?: { wasmSha256?: string; argSha256?: string },
): string {
  if ("UpdateSignerSet" in kind) {
    const { signers, threshold } = kind.UpdateSignerSet;
    return [
      "variant {",
      "  UpdateSignerSet = record {",
      `    signers = vec {${signers.length === 0 ? "" : `\n${signers
        .map((s) => `      ${principalLiteral(s)};`)
        .join("\n")}\n    `}};`,
      `    threshold = ${threshold} : nat32;`,
      "  }",
      "}",
    ].join("\n");
  }
  if (!("Management" in kind)) {
    // Unreachable for the V1 surface; rendered rather than thrown so a future
    // variant is visibly unpreviewable instead of silently previewed wrong.
    return `variant { /* UNSUPPORTED BY THIS PAGE: ${Object.keys(kind)[0]} */ }`;
  }
  const m = kind.Management;
  if ("CreateCanister" in m) {
    return [
      "variant {",
      "  Management = variant {",
      "    CreateCanister = record {",
      `      manifest_purpose = "${m.CreateCanister.manifest_purpose}";`,
      `      disposition = variant { ${Object.keys(m.CreateCanister.disposition)[0]} };`,
      "    }",
      "  }",
      "}",
    ].join("\n");
  }
  if ("UpdateSettings" in m) {
    const { target, controllers } = m.UpdateSettings;
    return [
      "variant {",
      "  Management = variant {",
      "    UpdateSettings = record {",
      `      target = ${principalLiteral(target)};`,
      `      controllers = vec {`,
      ...controllers.map((c) => `        ${principalLiteral(c)};`),
      "      };",
      "    }",
      "  }",
      "}",
    ].join("\n");
  }
  const tag = "InstallCode" in m ? "InstallCode" : "Upgrade" in m ? "Upgrade" : null;
  if (tag === null) {
    return `variant { Management = variant { /* UNSUPPORTED BY THIS PAGE: ${
      Object.keys(m)[0]
    } */ } }`;
  }
  const body = (m as Record<string, {
    target: Principal;
    expected_wasm_hash: Uint8Array | number[];
    expected_arg_hash: Uint8Array | number[];
    wasm_bytes: Uint8Array | number[];
    arg_bytes: Uint8Array | number[];
  }>)[tag];
  const wasm = Uint8Array.from(body.wasm_bytes);
  const arg = Uint8Array.from(body.arg_bytes);
  return [
    "variant {",
    "  Management = variant {",
    `    ${tag} = record {`,
    `      target = ${principalLiteral(body.target)};`,
    `      expected_wasm_hash = ${blobLiteral(Uint8Array.from(body.expected_wasm_hash), null)};`,
    `      expected_arg_hash = ${blobLiteral(Uint8Array.from(body.expected_arg_hash), null)};`,
    `      wasm_bytes = ${blobLiteral(wasm, digests?.wasmSha256 ?? null)};`,
    `      arg_bytes = ${blobLiteral(arg, digests?.argSha256 ?? null)};`,
    "    }",
    "  }",
    "}",
  ].join("\n");
}

// ── C6 quota: in-flight install bytes, derived client-side ───────────────────

/** The per-signer retained-payload budget the Vault enforces (2 MiB). */
export const PER_SIGNER_RETAINED_BYTES = 2 * 1024 * 1024;

/**
 * Sum the payload bytes a proposer currently has RETAINED in flight.
 *
 * The Vault exposes no retained-bytes query (SSA G-05), so this is derived from
 * `list_proposals`: the two code-bearing views carry `wasm_bytes_len`,
 * `arg_bytes_len` and `bytes_retained`, and only a proposal whose bytes are
 * still retained occupies the budget. This is an ESTIMATE from the signer's own
 * view of the proposal list — it is shown as a guide, and the authority remains
 * the Vault's typed `SizeLimitExceeded`, which the page renders verbatim.
 */
export function inFlightRetainedBytes(views: ProposalView[], proposer: Principal): bigint {
  const who = proposer.toText();
  let total = 0n;
  for (const view of views) {
    if (view.proposer.toText() !== who) continue;
    const action = view.action;
    if (!("Management" in action)) continue;
    const m = action.Management;
    const body = "InstallCode" in m ? m.InstallCode : "Upgrade" in m ? m.Upgrade : null;
    if (body === null || !body.bytes_retained) continue;
    total += body.wasm_bytes_len + body.arg_bytes_len;
  }
  return total;
}

// ── Typed error rendering ────────────────────────────────────────────────────

/**
 * Render a `VaultError` for the operator.
 *
 * `SizeLimitExceeded` carries the two numbers that make it actionable and they
 * are shown VERBATIM (SSA G-05) rather than collapsed into "too big": the
 * difference between the encoded size and the limit is what tells an operator
 * whether to sweep an expired proposal or to stop.
 */
export function describeVaultError(err: VaultError): string {
  if ("SizeLimitExceeded" in err) {
    const { encoded_bytes, limit_bytes } = err.SizeLimitExceeded;
    return (
      `SizeLimitExceeded: encoded_bytes = ${encoded_bytes}, limit_bytes = ${limit_bytes}. ` +
      "The Vault refused the proposal; nothing was created. Your other in-flight proposals " +
      "hold this budget until they terminalize or are swept."
    );
  }
  if ("ProposalExpired" in err) {
    const { expires_at_ns, now_ns } = err.ProposalExpired;
    return (
      `ProposalExpired: expires_at_ns = ${expires_at_ns}, now_ns = ${now_ns}. ` +
      "The approval was refused at admission and NOTHING was mutated — the proposal is not " +
      "terminalized by this refusal; only the expiry sweep terminalizes."
    );
  }
  if ("CommitmentMismatch" in err) {
    const which = Object.keys(err.CommitmentMismatch)[0];
    return which === "StoredVsRecomputed"
      ? "CommitmentMismatch: StoredVsRecomputed — the Vault's STORED commitment does not equal " +
          "the one recomputed from the retained payload. No honest sequence of operations " +
          "produces this. Stop and escalate."
      : "CommitmentMismatch: CallerMismatch — the hash sent does not equal the stored " +
          "commitment. Zero writes; the proposal is unchanged.";
  }
  if ("StaleEpoch" in err) {
    const { expected, found } = err.StaleEpoch;
    return `StaleEpoch: expected = ${expected}, found = ${found}. The signer set changed under you; reload.`;
  }
  if ("UnknownProposal" in err) {
    return `UnknownProposal: proposal_id = ${err.UnknownProposal.proposal_id}.`;
  }
  if ("LifetimeOutOfBounds" in err) {
    return `LifetimeOutOfBounds: ${JSON.stringify(err.LifetimeOutOfBounds, bigintText)}`;
  }
  if ("GuardRejected" in err) {
    return `GuardRejected: ${JSON.stringify(err.GuardRejected, bigintText)}`;
  }
  if ("ReadLimitExceeded" in err || "ReadBoundExceeded" in err || "AlreadySettled" in err) {
    return JSON.stringify(err, bigintText);
  }
  const tag = Object.keys(err)[0] ?? "(empty)";
  const payload = (err as Record<string, unknown>)[tag];
  return payload === null || payload === undefined
    ? tag
    : `${tag}: ${JSON.stringify(payload, bigintText)}`;
}

function bigintText(_key: string, value: unknown): unknown {
  return typeof value === "bigint" ? value.toString(10) : value;
}

// ── Derived expiry (SSA F-08) ────────────────────────────────────────────────

/**
 * The ruled default proposal lifetime bound, in days. `ProposalView` carries NO
 * expiry field, so the page can only ever show a DERIVED "expires ≈" from
 * `created_at_ns` — and it says so rather than presenting a derivation as a
 * fact read from the canister.
 */
export const RULED_LIFETIME_MIN_DAYS = 1;
export const RULED_LIFETIME_MAX_DAYS = 30;


// ── Upgrader rotation plane (UPG-ROT-UI) ─────────────────────────────────────

/**
 * The roster size this page will propose, and the ONLY one it will propose.
 *
 * The canister accepts 2..=9 distinct non-anonymous members
 * (`validate_bootstrap_quorum` + `check_recovery_roster_size`). This page is
 * narrower ON PURPOSE: step 7 rotates a three-member roster, and a surface that
 * would silently accept two is a surface that can silently drop a signer.
 */
export const ROTATION_ROSTER_SIZE = 3;

/**
 * Parse + validate a proposed rotation roster.
 *
 * `typedCount` is the signer's typed confirmation of the count. It is checked
 * against `ROTATION_ROSTER_SIZE` AND against what was actually parsed, so
 * "I meant three" and "there are three here" are two separate statements that
 * must agree — typing the count cannot rubber-stamp a list of a different size.
 *
 * Anonymous is rejected here as well as by the canister: `2vxsx-fae` parses
 * fine and would be refused on chain as `ThresholdViolation`, a wire code that
 * says nothing about which principal was wrong.
 */
export function buildRotationRoster(text: string, typedCount: string): BuildResult<Principal[]> {
  const parsed = parsePrincipalList(text);
  if ("refused" in parsed) return parsed;
  const members = parsed.ok;
  if (members.length !== ROTATION_ROSTER_SIZE) {
    return {
      refused:
        `This page proposes a roster of exactly ${ROTATION_ROSTER_SIZE} members; you entered ` +
        `${members.length}. Nothing was sent.`,
    };
  }
  const typed = typedCount.trim();
  if (typed !== String(ROTATION_ROSTER_SIZE)) {
    return {
      refused:
        `Type the member count (${ROTATION_ROSTER_SIZE}) to confirm the roster you are about ` +
        `to propose. You typed ${JSON.stringify(typed)}. Nothing was sent.`,
    };
  }
  for (const m of members) {
    if (m.isAnonymous()) {
      return {
        refused:
          "The anonymous principal (2vxsx-fae) cannot be a recovery member. The canister would " +
          "refuse this as ThresholdViolation, which does not say which principal was wrong. " +
          "Nothing was sent.",
      };
    }
  }
  return { ok: members };
}

/** The EXACT Candid tuple `propose_membership_rotation` will be called with. */
export function rotationCandidPreview(members: Principal[]): string {
  return [
    "(",
    "  vec {",
    ...members.map((m) => `    ${principalLiteral(m)};`),
    "  },",
    // Shown rather than omitted, for the same reason as the Vault preview: the
    // signer can see that no custom lifetime is being requested. `null` is the
    // canister's RULED DEFAULT (the 30-day maximum), not "no expiry".
    "  null,",
    ")",
  ].join("\n");
}

/** `approve_recovery(id, blob)` — the stored bytes, rendered in full. */
export function rotationApprovePreview(proposalId: bigint, commitmentHash: Uint8Array): string {
  const escaped = bytesToHex(commitmentHash).replace(/../g, (h) => `\\${h}`);
  return `(\n  ${proposalId} : nat64,\n  blob "${escaped}",\n)`;
}

/**
 * Render a `RecoveryError` for the operator.
 *
 * `ProposalExpired` is preserved DISTINCTLY and with both timestamps (SSA C-5):
 * the rejection mutates nothing, does not terminalize the proposal and does not
 * free its capacity — only the bounded sweep does, and this page has no sweep
 * control. `StaleEpoch` carries the two epochs, which is exactly the evidence
 * that a rotation executed under the caller.
 */
export function describeRecoveryError(err: RecoveryError): string {
  if ("ProposalExpired" in err) {
    const { expires_at_ns, now_ns } = err.ProposalExpired;
    return (
      `ProposalExpired: expires_at_ns = ${expires_at_ns}, now_ns = ${now_ns}. ` +
      "The approval was refused at ADMISSION and NOTHING was mutated. This refusal did NOT " +
      "cancel the proposal, did NOT terminalize it and did NOT free its capacity — only the " +
      "expiry sweep does that, and this page deliberately has no sweep control."
    );
  }
  if ("StaleEpoch" in err) {
    const { proposal, current } = err.StaleEpoch;
    return (
      `StaleEpoch: proposal = ${proposal}, current = ${current}. The recovery membership epoch ` +
      "advanced under this proposal — a rotation has already executed. Nothing was written. " +
      "Reload the membership before doing anything else."
    );
  }
  if ("CommitmentMismatch" in err) {
    const which = Object.keys(err.CommitmentMismatch)[0];
    return which === "StoredVsRecomputed"
      ? "CommitmentMismatch: StoredVsRecomputed — the Upgrader's STORED commitment does not " +
          "equal the one recomputed from the proposal. No honest sequence of operations " +
          "produces this. Stop and escalate."
      : "CommitmentMismatch: CallerMismatch — the hash sent does not equal the stored " +
          "commitment. Zero writes; the proposal is unchanged.";
  }
  if ("NotAuthorized" in err) {
    return (
      "NotAuthorized: this principal is not a CURRENT recovery member. Zero writes. Note that " +
      "the caller check precedes the epoch check, so a REMOVED member sees this rather than " +
      "StaleEpoch."
    );
  }
  if ("AlreadyApproved" in err) {
    return "AlreadyApproved: this principal has already approved this proposal. Zero writes.";
  }
  if ("AlreadyTerminal" in err) {
    return (
      "AlreadyTerminal: the proposal is Executed, Failed, Cancelled or Expired and can never " +
      "collect another approval."
    );
  }
  if ("ThresholdViolation" in err) {
    return (
      "ThresholdViolation: the Upgrader refused the proposed roster. RecoveryError carries no " +
      "membership-validation variant, so this is the wire classification for every roster " +
      "rejection — the precise reason is in the Upgrader audit events " +
      "(MembershipRotationRejected). Nothing was created."
    );
  }
  if ("UnknownProposal" in err) {
    return `UnknownProposal: proposal_id = ${err.UnknownProposal.proposal_id}.`;
  }
  if ("LifetimeOutOfBounds" in err) {
    return `LifetimeOutOfBounds: ${JSON.stringify(err.LifetimeOutOfBounds, bigintText)}`;
  }
  if ("GuardRejected" in err) {
    return `GuardRejected: ${JSON.stringify(err.GuardRejected, bigintText)}`;
  }
  const tag = Object.keys(err)[0] ?? "(empty)";
  const payload = (err as Record<string, unknown>)[tag];
  return payload === null || payload === undefined
    ? tag
    : `${tag}: ${JSON.stringify(payload, bigintText)}`;
}

/**
 * The stored `expires_at_ns`, rendered EXPLICITLY (SSA C-5).
 *
 * Unlike the Vault's `ProposalView`, `RotationProposalView` DOES carry the
 * expiry, so nothing here is derived. An absent `expires_at_ns` is the only
 * case where no expiry exists, and it is said in those words rather than shown
 * as a blank.
 */
export function describeRotationExpiry(view: RotationProposalView): string {
  if (view.expires_at_ns.length === 0) {
    return "expires_at_ns = (none) — this proposal carries NO stored expiry.";
  }
  const ns = view.expires_at_ns[0];
  return (
    `expires_at_ns = ${ns} (${new Date(Number(ns / 1_000_000n)).toISOString()}). ` +
    "Read from the canister, not derived. A rotation proposed from this page requests " +
    "lifetime = null, which is the canister's RULED DEFAULT, not 'no expiry'."
  );
}
