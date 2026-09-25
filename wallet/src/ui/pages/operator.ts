/**
 * J-17b — the Vault operator page (`#/operator`).
 *
 * WHY THIS EXISTS. The Vault's pinned signer set is 2-of-3: two Internet
 * Identity principals plus the machine dfx identity, and "the machine key never
 * acts alone" means every action needs at least one human II signature. An II
 * principal is derived from the ORIGIN it was created at, and dfx cannot sign as
 * II — so without a browser surface served from the wallet's own origin there is
 * no way for a human signer to call `propose`/`approve` at all, and J-18 is
 * blocked. This page is that surface and nothing more.
 *
 * ORIGIN (SSA F-06, REVISED BY WT-1). II principals are a function of the
 * DERIVATION origin. That used to be the serving origin, so `https://app.stsh.fi`
 * was the only origin whose principals were the pinned ones and the
 * `s3tyu-….icp0.io` asset-canister alias derived DIFFERENT principals — an
 * unauthorized caller, silently. WT-1 re-roots derivation at the canister origin
 * itself and vouches for the DNS alias with a certified
 * `.well-known/ii-alternative-origins` asset, so BOTH origins now derive the same
 * pinned principals and both are permitted. A third origin is still hard-blocked.
 *
 * The page still invents no check of its own: it reuses `evaluateSessionPolicy`,
 * which now enforces the permitted serving SET and the single pinned derivation
 * origin (a block, not a banner). Nothing about origins is configurable here.
 *
 * WHAT THE CLIENT GATE IS AND IS NOT. Signer-only controls are hidden when the
 * logged-in principal is not in `get_signers()`. That is UX: the Vault enforces
 * authorization server-side on every single call regardless, and every
 * signer-gated query returns an indistinguishable `None` to an unauthorized
 * caller. Nothing here is a security boundary.
 *
 * DISCIPLINE, all four of which are load-bearing rather than stylistic:
 *   - Every update shows the EXACT Candid argument tuple before it is sent and
 *     the RAW result after.
 *   - NO auto-retry. `propose`/`approve` are not idempotent from the caller's
 *     side; a silent retry of a quorum action is exactly the wrong reflex.
 *   - NO caching of proposals. A stale proposal list is how a signer approves
 *     something that already changed.
 *   - NO payload ever reaches a log. The wallet has no telemetry and this page
 *     adds none; wasm bytes are read, hashed, sent, and dropped.
 */

import type { Principal } from "@dfinity/principal";
import { sha256 } from "hash-wasm";

import type {
  ProposalView,
  VaultActionKind,
} from "../../../../src/declarations/vault/vault.did";
import type { RotationProposalView } from "../../../../src/declarations/upgrader/upgrader.did";
import type { VaultCanister, VaultResult } from "../../actors/vault";
import type { UpgraderCanister, UpgraderResult } from "../../actors/upgrader";
import type { OperatorActors } from "../../session/session";
import {
  bindApproval,
  buildCreateCanister,
  buildRotationRoster,
  buildInstallCode,
  buildUpdateSettings,
  buildUpdateSignerSet,
  buildUpgrade,
  bytesToHex,
  candidPreview,
  describeRecoveryError,
  describeRotationExpiry,
  describeVaultError,
  inFlightRetainedBytes,
  parsePrincipal,
  parsePrincipalList,
  PER_SIGNER_RETAINED_BYTES,
  rotationApprovePreview,
  rotationCandidPreview,
  ROTATION_ROSTER_SIZE,
  RULED_LIFETIME_MAX_DAYS,
  RULED_LIFETIME_MIN_DAYS,
  type BuildResult,
} from "../../operator/proposals";
import committedPins from "../../generated/releasePins.json";
import { BORN_UNDER_VAULT_ROLES, UNPINNED_ROLES, type WasmPins } from "../../release/wasmPins";
import type { AppContext } from "../context";
import { el } from "../dom";

/** The Vault clamps the sweep to 12; sending 12 asks for the whole allowance. */
const SWEEP_LIMIT = 12;
/**
 * One page of proposals / receipts / audit events.
 *
 * DELIBERATE, and deliberately below the ceiling: the custody read bound is
 * `MAX_READ_PAGE_LIMIT = 128` (`canisters/custody-types/src/lib.rs:1138`,
 * drift-locked at `:3923`). 25 is a choice about response size per round trip,
 * not a protocol maximum, and `list_proposals` applies no byte-based
 * short-page rule — its stopping semantics are `take(limit)`
 * (`canisters/vault/src/lib.rs:6268-6294`). Raising it is out of scope here.
 */
const PAGE_LIMIT = 25;

/**
 * VAULT-LIST-PAGING. The Vault returns proposals ASCENDING, strictly after the
 * cursor, `take(limit)` — so a single `list_proposals(null, 25)` is a fixed
 * window of ids 1..25 forever, and terminal proposals are never removed. From
 * id 26 on, no II signer could see (let alone approve) anything. The page now
 * walks the whole listing, and bounds that walk so a hostile or runaway ledger
 * cannot spin it: 40 windows = 1000 ids, after which the truncation is stated
 * ON SCREEN rather than silently dropping the tail.
 */
const MAX_LIST_WINDOWS = 40;

/** `nat64` ceiling — an id above this is rejected before any query is made. */
const NAT64_MAX = 18_446_744_073_709_551_615n;

/** The three non-terminal outcomes. Everything else is done and collapsible. */
function isNonTerminal(view: ProposalView): boolean {
  const o = view.outcome;
  return "Pending" in o || "Executing" in o || "OutcomeUnknown" in o;
}

/** Newest first, on `proposal_id` as bigint — never on `created_at_ns`. */
function byIdDescending(rows: ProposalView[]): ProposalView[] {
  return [...rows].sort((a, b) =>
    a.proposal_id < b.proposal_id ? 1 : a.proposal_id > b.proposal_id ? -1 : 0,
  );
}

export interface OperatorDeps {
  /** The build-time `[wasm.*]` pins. Injected so a test can perturb them. */
  pins: WasmPins;
  /** Local sha256 of picked bytes (hash-wasm — SSA H-05, CSP unchanged). */
  sha256Hex(bytes: Uint8Array): Promise<string>;
  /** Wall clock, injectable so the derived "expires ≈" is testable. */
  nowMs(): number;
}

export function defaultOperatorDeps(): OperatorDeps {
  return {
    pins: committedPins as WasmPins,
    sha256Hex: (bytes) => sha256(bytes),
    nowMs: () => Date.now(),
  };
}

/** Everything the page holds between renders. Never persisted, never cached. */
interface OperatorState {
  signers: Principal[] | null;
  /** false = not read yet; the signer check is never made on a guess. */
  signersLoaded: boolean;
  /**
   * The WHOLE fetched listing, newest first — or `null`, which means "no list",
   * never "an empty Vault". A walk is atomic: rows are published here only
   * after every window of that walk succeeded (or the marked cap was reached).
   * A thrown read or a `null` page invalidates the walk and clears this,
   * INCLUDING after a previously successful list (VAULT-LIST-PAGING AC-7).
   */
  proposals: ProposalView[] | null;
  /** Non-null = the walk hit the 40-window cap; the id it stopped at. */
  proposalsTruncatedAtId: bigint | null;
  /** The completed (terminal) rows are collapsed by default. */
  showCompleted: boolean;
  /** The one Vault proposal fetched BY ID, plus the note for a null/failed read. */
  vaultLookup: { requestedId: string; view: ProposalView | null; note: string | null } | null;
  /**
   * The outcome of the last update, and the id of the control that triggered
   * it, so the result renders immediately beneath THAT control across repaint
   * (O-3) rather than only at the top of the page.
   */
  localResult: { source: string; kind: "error" | "success"; text: string } | null;
  /**
   * The UPGRADER's own recovery membership (SSA C-3). Read separately from the
   * Vault signer set and never inferred from it: the two planes keep
   * independent rosters, and a Vault signer is not thereby a recovery member.
   * `null` = unauthorized, failed or not yet read — all of which FAIL CLOSED.
   */
  recoveryMembers: Principal[] | null;
  recoveryLoaded: boolean;
  /** The one rotation proposal fetched by id. Approval is reachable ONLY here. */
  rotation: RotationProposalView | null;
  rotationNote: string | null;
  /** Raw JSON of the last recovery-plane read, for the evidence file. */
  rotationReadback: string | null;
  receiptsCursor: bigint | null;
  auditCursor: bigint | null;
  /** The last exact-Candid preview and the last raw result, both verbatim. */
  preview: string | null;
  rawResult: string | null;
  notice: { kind: "info" | "error" | "success"; text: string } | null;
  busy: boolean;
}

function newState(): OperatorState {
  return {
    signers: null,
    signersLoaded: false,
    proposals: null,
    proposalsTruncatedAtId: null,
    showCompleted: false,
    vaultLookup: null,
    localResult: null,
    recoveryMembers: null,
    recoveryLoaded: false,
    rotation: null,
    rotationNote: null,
    rotationReadback: null,
    receiptsCursor: null,
    auditCursor: null,
    preview: null,
    rawResult: null,
    notice: null,
    busy: false,
  };
}

/** Render `#/operator` into `container`. */
export function renderOperator(
  container: HTMLElement,
  ctx: AppContext,
  deps: OperatorDeps = defaultOperatorDeps(),
): void {
  const root = el("section", { class: "operator", "data-testid": "operator" });
  container.append(root);

  // ── Gate 1: the ORIGIN hard block, reused verbatim from the session policy.
  // This is the same block that stops login and every mutation — the operator
  // route gets no exemption and no softer treatment, because a principal
  // derived at the wrong origin is not the signer the Vault has pinned.
  if (ctx.policy.kind === "blocked") {
    root.append(
      el("h2", {}, ["Vault operator"]),
      el("p", { class: "error", "data-testid": "operator-blocked" }, [ctx.policy.reason]),
      el("p", { class: "muted" }, [
        "Internet Identity principals are derived per ORIGIN. The pinned Vault signers were " +
          "derived at the production wallet origin; another origin — including the asset " +
          "canister's *.icp0.io alias — produces different principals that the Vault has never " +
          "seen. Open the wallet at its production origin.",
      ]),
    );
    return;
  }

  // ── Gate 2: a live session. A revoked/expired session drops the operator
  // actors, so there is nothing to call with — refused here, explicitly.
  const bound = ctx.operatorActors;
  if (ctx.state.principal === null || bound === null) {
    root.append(
      el("h2", {}, ["Vault operator"]),
      el("p", { class: "muted", "data-testid": "operator-session-required" }, [
        ctx.state.principal === null
          ? "Your Internet Identity session has ended or was never started. Log in to sign Vault actions."
          : "The operator surface is unavailable for this session (the Vault/Upgrader canister ids are not configured).",
      ]),
      el("div", { class: "row" }, [
        el("button", { class: "primary", onclick: () => void ctx.login() }, ["Log in"]),
      ]),
    );
    return;
  }

  const actors: OperatorActors = bound;
  const me = ctx.state.principal;
  const state = newState();
  const body = el("div", {});
  root.append(header(me), body);

  function report(kind: "info" | "error" | "success", text: string): void {
    state.notice = { kind, text };
  }

  /** Re-render the whole body. Cheap, and there is no cache to invalidate. */
  function paint(): void {
    body.replaceChildren();
    body.append(
      noticeBar(state),
      previewPanel(state),
      signerPanel(state, me),
      ...(isSigner(state, me) ? signerSections() : []),
      // OUTSIDE `signerSections()` ON PURPOSE (SSA C-3): the rotation plane is
      // gated by the UPGRADER's membership, not the Vault's signer set. A
      // recovery member who is not a Vault signer must still reach it, and a
      // Vault signer who is not a recovery member must not.
      upgraderRotationPanel(state, actors, me, runRecovery, loadRotation, paint),
      statusPanel(state, ctx, actors, deps, refresh, report, paint),
    );
  }

  function signerSections(): HTMLElement[] {
    return [
      proposalsPanel(state, ctx, actors, me, deps, run, paint, loadVaultProposal),
      proposePanel(state, actors, deps, run, paint),
      maintenancePanel(actors, run),
    ];
  }

  /**
   * Run ONE update call: preview -> send -> raw result. No retry, ever: a
   * failure is reported with its typed reason and the operator decides.
   */
  async function runCall<T, E>(
    previewText: string,
    call: () => Promise<{ ok: T } | { err: E }>,
    describe: (value: T) => string,
    describeErr: (err: E) => string,
    subject: string,
    source: string | null,
  ): Promise<void> {
    if (state.busy) return;
    state.busy = true;
    state.preview = previewText;
    state.rawResult = null;
    state.notice = null;
    state.localResult = null;
    paint();
    // O-3b: only a call that RESOLVED Ok re-walks the listing. A refusal or a
    // transport failure created nothing, so re-reading would be noise; worse,
    // a failed walk after a failed update would clear a list the operator is
    // being told to go and check. The single existing refresh site is kept —
    // no second, duplicate read is added anywhere on the propose path.
    let created = false;
    try {
      const result = await call();
      if ("err" in result) {
        state.rawResult = `Err = ${describeErr(result.err)}`;
        const text = `The ${subject} refused the call. Nothing was created or changed.`;
        report("error", text);
        if (source !== null) state.localResult = { source, kind: "error", text: `${text} ${state.rawResult}` };
      } else {
        created = true;
        state.rawResult = `Ok = ${describe(result.ok)}`;
        const text = `The ${subject} accepted the call.`;
        report("success", text);
        if (source !== null) state.localResult = { source, kind: "success", text: `${text} ${state.rawResult}` };
      }
    } catch (error) {
      // A transport/reject failure is NOT a verdict about whether the call
      // landed. Say exactly that rather than implying it failed.
      state.rawResult = `(no result) ${error instanceof Error ? error.message : String(error)}`;
      const text =
        `The call did not return a result. It may or may not have reached the ${subject} — ` +
        "RELOAD the proposal list and check before sending anything again. Nothing is retried automatically.";
      report("error", text);
      if (source !== null) state.localResult = { source, kind: "error", text: `${text} ${state.rawResult}` };
    } finally {
      state.busy = false;
      if (created) await refresh();
      paint();
    }
  }

  /** The Vault plane. Signature unchanged, so every existing call site is. */
  function run<T>(
    previewText: string,
    call: () => Promise<VaultResult<T>>,
    describe: (value: T) => string,
    source?: string,
  ): Promise<void> {
    return runCall(previewText, call, describe, describeVaultError, "Vault", source ?? null);
  }

  /** The Upgrader rotation plane — same state machine, same no-retry rule. */
  function runRecovery<T>(
    previewText: string,
    call: () => Promise<UpgraderResult<T>>,
    describe: (value: T) => string,
    source?: string,
  ): Promise<void> {
    return runCall(previewText, call, describe, describeRecoveryError, "Upgrader", source ?? null);
  }

  /**
   * Fetch ONE rotation proposal by id (SSA C-3).
   *
   * This is the only way the approve control comes into existence: there is no
   * arbitrary-id/arbitrary-hash approval form. A `null` answer — no such
   * proposal, or a proposal of the RECOVERY-ACTION kind, which the typed query
   * does not view — clears any previously loaded proposal rather than leaving a
   * stale card on screen next to a new id.
   */
  async function loadRotation(idText: string): Promise<void> {
    state.rotation = null;
    const trimmed = idText.trim();
    if (!/^[0-9]+$/.test(trimmed)) {
      state.rotationNote = `Not a proposal id: ${JSON.stringify(trimmed)}. Nothing was read.`;
      paint();
      return;
    }
    try {
      const view = await actors.upgrader.getRotationProposal(BigInt(trimmed));
      if (view === null) {
        state.rotationNote =
          `The Upgrader returned no ROTATION proposal for id ${trimmed}. That single answer ` +
          "covers every case it does not distinguish — no such proposal, or a proposal of the " +
          "recovery-ACTION kind, which this typed query does not view. Nothing to approve.";
        state.rotationReadback = null;
      } else {
        state.rotation = view;
        state.rotationNote = null;
        state.rotationReadback = rawJson(view);
      }
    } catch (error) {
      // Fail closed: a failed read leaves NO approvable proposal on screen.
      state.rotationNote = `Could not read the Upgrader: ${errText(error)}`;
      state.rotationReadback = null;
    }
    paint();
  }

  /**
   * Fetch ONE Vault proposal by id (O-2).
   *
   * Exists because the listing walk is capped, and because #26-class ids are
   * exactly the ones an operator is handed out of band. Mirrors the rotation
   * loader's safety property: the previous card is cleared BEFORE the read, so
   * a null/failed lookup can never leave a stale approvable card sitting next
   * to a different id. A newer request always wins over an older in-flight one.
   */
  let lookupSeq = 0;
  async function loadVaultProposal(idText: string): Promise<void> {
    const seq = (lookupSeq += 1);
    const trimmed = idText.trim();
    state.vaultLookup = { requestedId: trimmed, view: null, note: null };
    // SSA C-5. Invalidating `state.vaultLookup` is not enough on its own: the
    // PREVIOUS card's approve/cancel controls stay live in the DOM until the
    // next paint, and for a VALID id the next paint used to be after the
    // `await` below. An operator could therefore act on #26's card while the
    // input names #27 and the read for #27 is still in flight. Paint HERE, so
    // the stale card is gone before any request is awaited.
    paint();
    if (!/^[0-9]+$/.test(trimmed)) {
      state.vaultLookup.note = `Not a proposal id: ${JSON.stringify(trimmed)}. Nothing was read.`;
      paint();
      return;
    }
    const id = BigInt(trimmed);
    if (id > NAT64_MAX) {
      state.vaultLookup.note = `Proposal id ${trimmed} is above the nat64 maximum. Nothing was read.`;
      paint();
      return;
    }
    try {
      const view = await actors.vault.getProposal(id);
      // A response that lost the race belongs to a superseded request.
      if (seq !== lookupSeq) return;
      if (view === null) {
        state.vaultLookup = {
          requestedId: trimmed,
          view: null,
          note:
            `The Vault returned no proposal #${trimmed}. That single answer is deliberately ` +
            "indistinguishable: no such proposal, and an unauthorized caller, look the same. " +
            "Nothing to approve.",
        };
      } else {
        state.vaultLookup = { requestedId: trimmed, view, note: null };
      }
    } catch (error) {
      if (seq !== lookupSeq) return;
      // Fail closed: a failed read leaves NO approvable card on screen.
      state.vaultLookup = {
        requestedId: trimmed,
        view: null,
        note: `Could not read the Vault: ${errText(error)}`,
      };
    }
    paint();
  }

  /**
   * Walk the WHOLE proposal listing forward, accumulating LOCALLY (AC-7).
   *
   * Nothing is published to `state` from in here. A thrown read or a `null`
   * page — `null` is unauthorized, never "an empty successful page" — aborts
   * the whole walk, and the caller then clears the rendered list rather than
   * presenting a prefix as if it were complete. No retry, ever
   * (`operator.ts` `runCall` doc comment; the same rule covers reads).
   */
  async function walkProposals(): Promise<
    { ok: true; rows: ProposalView[]; truncatedAtId: bigint | null } | { ok: false; error: string }
  > {
    const acc: ProposalView[] = [];
    let cursor: bigint | null = null;
    for (let window = 0; window < MAX_LIST_WINDOWS; window += 1) {
      let page: ProposalView[] | null;
      try {
        page = await actors.vault.listProposals(cursor, PAGE_LIMIT);
      } catch (error) {
        return { ok: false, error: errText(error) };
      }
      if (page === null) {
        return {
          ok: false,
          error:
            "the Vault answered the proposal listing with nothing (unauthorized, or the read " +
            "failed). That is not an empty list.",
        };
      }
      acc.push(...page);
      // A short page is the end of the listing: `list_proposals` is
      // `take(limit)` over ids strictly after the cursor.
      if (page.length < PAGE_LIMIT) return { ok: true, rows: acc, truncatedAtId: null };
      cursor = page[page.length - 1].proposal_id;
      if (window === MAX_LIST_WINDOWS - 1) return { ok: true, rows: acc, truncatedAtId: cursor };
    }
    /* c8 ignore next */
    return { ok: true, rows: acc, truncatedAtId: cursor };
  }

  /** Reload every live view from the canister. Nothing is read from a cache. */
  async function refresh(): Promise<void> {
    try {
      state.signers = await actors.vault.getSigners();
    } catch (error) {
      // Fail closed for the Vault plane: an unread signer set is not a signer.
      state.signers = null;
      report("error", `Could not read the Vault: ${errText(error)}`);
    } finally {
      state.signersLoaded = true;
    }
    if (isSigner(state, me)) {
      const walk = await walkProposals();
      if (walk.ok) {
        state.proposals = byIdDescending(walk.rows);
        state.proposalsTruncatedAtId = walk.truncatedAtId;
      } else {
        state.proposals = null;
        state.proposalsTruncatedAtId = null;
        report("error", `Could not read the Vault: ${walk.error}`);
      }
    } else {
      state.proposals = null;
      state.proposalsTruncatedAtId = null;
    }
    // SSA C-3 — read INDEPENDENTLY of the Vault, and fail closed on any
    // failure: `recoveryMembers` stays null and the rotation controls stay off.
    try {
      state.recoveryMembers = await actors.upgrader.getRecoveryMembership();
    } catch (error) {
      state.recoveryMembers = null;
      report("error", `Could not read the Upgrader recovery membership: ${errText(error)}`);
    } finally {
      state.recoveryLoaded = true;
    }
  }

  paint();
  void refresh().then(paint);
}

// ── Pieces ───────────────────────────────────────────────────────────────────

function isSigner(state: OperatorState, me: Principal): boolean {
  if (state.signers === null) return false;
  return state.signers.some((s) => s.toText() === me.toText());
}

function header(me: Principal): HTMLElement {
  const text = me.toText();
  return el("div", {}, [
    el("h2", {}, ["Vault operator"]),
    el("p", { class: "muted" }, [
      "This page signs custody actions as YOUR Internet Identity principal. It talks to the " +
        "Vault and the Upgrader only. Every update shows the exact Candid it will send before " +
        "sending, and the raw result after. Nothing is retried automatically and no proposal is cached.",
    ]),
    el("h3", {}, ["My principal"]),
    el("p", { class: "muted" }, [
      "This is the principal derived for THIS origin. It is what goes into the pinned signer " +
        "set — copy it exactly, and paste it back from the source rather than retyping it.",
    ]),
    el("code", { class: "principal-large", "data-testid": "operator-principal" }, [text]),
  ]);
}

function noticeBar(state: OperatorState): HTMLElement {
  if (state.notice === null) return el("div", {});
  return el(
    "p",
    { class: state.notice.kind === "error" ? "error" : "muted", "data-testid": "operator-notice" },
    [state.notice.text],
  );
}

function previewPanel(state: OperatorState): HTMLElement {
  if (state.preview === null && state.rawResult === null) return el("div", {});
  const rows: HTMLElement[] = [el("h3", {}, ["Last call"])];
  if (state.preview !== null) {
    rows.push(
      el("p", { class: "muted" }, ["Exact Candid argument tuple sent:"]),
      el("pre", { "data-testid": "operator-preview" }, [state.preview]),
    );
  }
  if (state.rawResult !== null) {
    rows.push(
      el("p", { class: "muted" }, ["Raw result:"]),
      el("pre", { "data-testid": "operator-raw-result" }, [state.rawResult]),
    );
  }
  return el("div", { class: "panel" }, rows);
}

function signerPanel(state: OperatorState, me: Principal): HTMLElement {
  if (!state.signersLoaded) {
    return el("p", { class: "muted", "data-testid": "operator-signers-loading" }, [
      "Reading the signer set…",
    ]);
  }
  if (state.signers === null) {
    // The indistinguishable `None` (vault.did freeze §4): anonymous, removed,
    // stale-epoch and unknown are ONE observable and must be reported as one.
    return el("div", { class: "panel" }, [
      el("p", { class: "muted", "data-testid": "operator-not-signer" }, [
        "The Vault did not answer the signer query for this principal. That single answer covers " +
          "every unauthorized case — not a signer, removed, or a stale governance epoch — and the " +
          "Vault deliberately does not distinguish them. Signing controls are hidden.",
      ]),
    ]);
  }
  return el("div", { class: "panel" }, [
    el("h3", {}, ["Signers"]),
    el("ul", { "data-testid": "operator-signer-list" },
      state.signers.map((s) =>
        el("li", {}, [`${s.toText()}${s.toText() === me.toText() ? "  ← you" : ""}`]),
      ),
    ),
    isSigner(state, me)
      ? el("p", { class: "muted" }, ["You are a signer on this Vault."])
      : el("p", { class: "error", "data-testid": "operator-not-signer" }, [
          "Your principal is not in the signer set. Signing controls are hidden; the Vault would " +
            "refuse them regardless.",
        ]),
  ]);
}

// ── Proposals + approve ──────────────────────────────────────────────────────

type RunFn = <T>(
  preview: string,
  call: () => Promise<VaultResult<T>>,
  describe: (value: T) => string,
  source?: string,
) => Promise<void>;

/** The O-3 local result: the exact raw outcome, beneath the control that caused it. */
/**
 * The proposal id a retained O-3 local result belongs to, or null.
 *
 * SSA C-8: a quorum-completing approval EXECUTES the proposal, so the very
 * next refresh moves that row out of the Pending branch — and into the
 * default-collapsed completed section. The raw result of the call the
 * operator just made must not vanish with it.
 */
function localResultProposalId(state: OperatorState): bigint | null {
  const source = state.localResult?.source;
  if (source === undefined) return null;
  const m = /^(?:approve|cancel)-([0-9]+)$/.exec(source);
  return m === null ? null : BigInt(m[1]);
}

function localResultFor(state: OperatorState, source: string): HTMLElement {
  const result = state.localResult;
  if (result === null || result.source !== source) return el("div", {});
  return el(
    "p",
    {
      class: result.kind === "error" ? "error" : "muted",
      "data-testid": `operator-local-result-${source}`,
    },
    [result.text],
  );
}

function proposalsPanel(
  state: OperatorState,
  ctx: AppContext,
  actors: { vault: VaultCanister; upgrader: UpgraderCanister },
  me: Principal,
  deps: OperatorDeps,
  run: RunFn,
  paint: () => void,
  loadVaultProposal: (idText: string) => Promise<void>,
): HTMLElement {
  const rows: HTMLElement[] = [el("h3", {}, ["Proposals"])];
  const views = state.proposals;
  if (views === null) {
    rows.push(el("p", { class: "muted" }, ["No proposal list (unauthorized, or not loaded yet)."]));
    rows.push(vaultLookupForm(state, ctx, actors, me, deps, run, paint, loadVaultProposal));
    return el("div", { class: "panel" }, rows);
  }
  const truncated = state.proposalsTruncatedAtId;
  const inFlight = inFlightRetainedBytes(views, me);
  rows.push(
    el("p", { class: "muted", "data-testid": "operator-quota" }, [
      `Your in-flight retained payload: ${inFlight} of ${PER_SIGNER_RETAINED_BYTES} bytes ` +
        "(DERIVED from this proposal list — the Vault exposes no retained-bytes query. The " +
        "authority is the Vault's own SizeLimitExceeded, shown verbatim if it refuses)." +
        (truncated === null
          ? ""
          : " DERIVED FROM THE FETCHED ROWS ONLY — the listing was truncated, so this is a " +
            "lower bound, not your whole in-flight total."),
    ]),
  );
  if (truncated !== null) {
    rows.push(
      el("p", { class: "error", "data-testid": "operator-listing-truncated" }, [
        `listing truncated at id ${truncated} — the walk stopped after ${MAX_LIST_WINDOWS} ` +
          `windows of ${PAGE_LIMIT}. Rows beyond that id were NOT fetched, so this list is not ` +
          "all proposals and is not globally newest-first. Load a higher id by number below.",
      ]),
    );
  }
  // Newest first, and split: what still needs a decision is never buried under
  // hundreds of finished rows — which is precisely how #26 became invisible.
  const live = views.filter(isNonTerminal);
  const completed = views.filter((v) => !isNonTerminal(v));
  if (live.length === 0) {
    rows.push(el("p", { class: "muted" }, ["No proposals."]));
  }
  for (const view of live) {
    rows.push(proposalCard(view, ctx, actors, me, deps, run, paint, state));
  }
  if (completed.length > 0) {
    rows.push(
      el("div", { class: "row" }, [
        el(
          "button",
          {
            "data-testid": "operator-toggle-completed",
            onclick: () => {
              state.showCompleted = !state.showCompleted;
              paint();
            },
          },
          [
            // SSA C-4: when the walk was truncated this count covers the FETCHED
            // rows only, so the label says so on the count itself — the panel
            // warning is not the only place that qualification appears.
            `${state.showCompleted ? "Hide" : "Show"} ${completed.length} completed` +
              (truncated === null ? "" : " (fetched rows only)"),
          ],
        ),
      ]),
    );
    // SSA C-8: if the row that triggered the retained local result has just
    // become terminal, the section that now holds it is opened, so the result
    // stays VISIBLE beside its own proposal instead of being collapsed away.
    const retainedId = localResultProposalId(state);
    const holdsRetained =
      retainedId !== null && completed.some((v) => v.proposal_id === retainedId);
    if (state.showCompleted || holdsRetained) {
      const done = el("div", { "data-testid": "operator-completed" }, []);
      for (const view of completed) {
        done.append(proposalCard(view, ctx, actors, me, deps, run, paint, state));
      }
      rows.push(done);
    }
  }
  rows.push(vaultLookupForm(state, ctx, actors, me, deps, run, paint, loadVaultProposal));
  return el("div", { class: "panel" }, rows);
}

/**
 * O-2 — load one Vault proposal by id.
 *
 * The result is rendered through `proposalCard`, the SAME component the list
 * rows use, so the approve/cancel/pin-banner behaviour cannot drift into a
 * second implementation. If the id is already on screen in the list the card
 * is NOT rendered a second time: two cards for one id means two controls with
 * the same identity, and an operator (or a test) acting on the wrong copy.
 */
function vaultLookupForm(
  state: OperatorState,
  ctx: AppContext,
  actors: { vault: VaultCanister; upgrader: UpgraderCanister },
  me: Principal,
  deps: OperatorDeps,
  run: RunFn,
  paint: () => void,
  loadVaultProposal: (idText: string) => Promise<void>,
): HTMLElement {
  const id = el("input", {
    type: "text",
    size: 10,
    placeholder: "proposal id",
    "data-testid": "operator-proposal-id",
  });
  const rows: HTMLElement[] = [
    el("h4", {}, ["Load a Vault proposal by id"]),
    el("p", { class: "muted" }, [
      "The listing above is capped. Any proposal — including one beyond the cap — can be fetched " +
        "here by number, and it approves through exactly the same byte-for-byte commitment check " +
        "as a list row. There is no form that takes an id and a hash and sends them.",
    ]),
    el("div", { class: "row" }, [
      id,
      el(
        "button",
        {
          "data-testid": "operator-proposal-load",
          onclick: () => void loadVaultProposal((id as HTMLInputElement).value),
        },
        ["Load proposal"],
      ),
    ]),
  ];
  const lookup = state.vaultLookup;
  if (lookup !== null && lookup.note !== null) {
    rows.push(
      el("p", { class: "error", "data-testid": "operator-proposal-lookup-note" }, [lookup.note]),
    );
  }
  if (lookup !== null && lookup.view !== null) {
    const alreadyListed =
      state.proposals !== null &&
      state.proposals.some((v) => v.proposal_id === lookup.view!.proposal_id);
    if (alreadyListed) {
      rows.push(
        el("p", { class: "muted", "data-testid": "operator-proposal-already-listed" }, [
          `Proposal #${lookup.view.proposal_id} is already shown in the list above — use the ` +
            "controls there. It is deliberately not rendered twice.",
        ]),
      );
    } else {
      rows.push(proposalCard(lookup.view, ctx, actors, me, deps, run, paint, state));
    }
  }
  return el("div", { class: "form" }, rows);
}

function outcomeTag(view: ProposalView): string {
  return Object.keys(view.outcome)[0] ?? "(unknown)";
}

function actionSummary(view: ProposalView): string {
  const action = view.action;
  if ("Management" in action) {
    const m = action.Management;
    const tag = Object.keys(m)[0];
    if ("CreateCanister" in m) {
      return `Management.CreateCanister purpose=${m.CreateCanister.manifest_purpose} disposition=${
        Object.keys(m.CreateCanister.disposition)[0]
      }`;
    }
    if ("UpdateSettings" in m) {
      return `Management.UpdateSettings target=${m.UpdateSettings.target.toText()} controllers=[${m.UpdateSettings.controllers
        .map((c) => c.toText())
        .join(", ")}]`;
    }
    if ("InstallCode" in m || "Upgrade" in m) {
      const body = "InstallCode" in m ? m.InstallCode : m.Upgrade;
      return `Management.${tag} target=${body.target.toText()} wasm_bytes_len=${
        body.wasm_bytes_len
      } bytes_retained=${body.bytes_retained}`;
    }
    return `Management.${tag}`;
  }
  if ("UpdateSignerSet" in action) {
    return `UpdateSignerSet threshold=${action.UpdateSignerSet.threshold} signers=[${action.UpdateSignerSet.signers
      .map((s) => s.toText())
      .join(", ")}]`;
  }
  return Object.keys(action)[0] ?? "(unknown action)";
}

/** The `expected_wasm_hash` on a code-bearing view, or null. */
function expectedWasmHashOf(view: ProposalView): { tag: string; hash: string } | null {
  const action = view.action;
  if (!("Management" in action)) return null;
  const m = action.Management;
  if ("InstallCode" in m) return { tag: "InstallCode", hash: bytesToHex(m.InstallCode.expected_wasm_hash) };
  if ("Upgrade" in m) return { tag: "Upgrade", hash: bytesToHex(m.Upgrade.expected_wasm_hash) };
  return null;
}

/**
 * ONE renderer for a Vault proposal — used by the list rows AND by the O-2
 * load-by-id result. Not forked, not copied: approve/cancel, the byte-for-byte
 * `bindApproval` binding and the release-pin banner must be the same code on
 * both paths or they drift, and the one that drifts is the one nobody looks at.
 * `state` is here only so the O-3 local result can render beneath this card's
 * own controls across a repaint; nothing else reads it.
 */
function proposalCard(
  view: ProposalView,
  ctx: AppContext,
  actors: { vault: VaultCanister; upgrader: UpgraderCanister },
  me: Principal,
  deps: OperatorDeps,
  run: RunFn,
  paint: () => void,
  state: OperatorState,
): HTMLElement {
  const commitment = bytesToHex(view.commitment_hash);
  const created = Number(view.created_at_ns / 1_000_000n);
  const rows: HTMLElement[] = [
    el("h4", {}, [`#${view.proposal_id} — ${outcomeTag(view)}`]),
    el("p", { class: "muted" }, [
      `proposer ${view.proposer.toText()} · epoch ${view.epoch} · approvals ${view.approvals.length}`,
    ]),
    el("p", {}, [actionSummary(view)]),
    el("p", { class: "muted" }, [
      // SSA F-08: ProposalView carries NO expiry field. This is DERIVED from
      // created_at_ns plus the ruled bound and is labelled as such — a derived
      // number presented as a canister fact is worse than no number.
      `created ${new Date(created).toISOString()} · expires ≈ between ` +
        `${new Date(created + RULED_LIFETIME_MIN_DAYS * 86_400_000).toISOString()} and ` +
        `${new Date(created + RULED_LIFETIME_MAX_DAYS * 86_400_000).toISOString()} ` +
        "(DERIVED from created_at_ns and the ruled 1–30 day lifetime bound; the Vault returns no expiry field)",
    ]),
    el("p", {}, ["commitment_hash:"]),
    el("code", { "data-testid": `operator-commitment-${view.proposal_id}` }, [commitment]),
  ];

  // F-02: the commitment binds WHAT was proposed; it does not prove the bytes
  // are the reviewed build, because the view redacts them. So for the two
  // code-bearing variants the proposal's expected_wasm_hash is shown NEXT TO
  // the release pin, with an explicit match mark, before the signer approves.
  const expected = expectedWasmHashOf(view);
  if (expected !== null) {
    const matched = Object.entries(deps.pins).filter(([, sha]) => sha === expected.hash);
    const ok = matched.length > 0;
    rows.push(
      el("p", {}, [`expected_wasm_hash (${expected.tag}):`]),
      el("code", {}, [expected.hash]),
      el(
        "p",
        {
          class: ok ? "muted" : "error",
          "data-testid": `operator-pin-match-${view.proposal_id}`,
        },
        [
          ok
            ? `✓ MATCHES the pinned ${matched.map(([pkg]) => pkg).join(", ")} build in deployment/mainnet/release_hashes.toml.`
            : "✗ does NOT match any [wasm.*] pin in deployment/mainnet/release_hashes.toml. " +
              "The commitment proves what was proposed, not that it is the reviewed build. Do not approve on this alone.",
        ],
      ),
    );
  }

  if ("Pending" in view.outcome) {
    const typed = el("input", {
      type: "text",
      placeholder: "paste the full 64-hex commitment hash",
      "data-testid": `operator-approve-input-${view.proposal_id}`,
      size: 70,
    });
    const approve = el(
      "button",
      {
        class: "primary",
        "data-testid": `operator-approve-${view.proposal_id}`,
        onclick: () => {
          // The binding happens BEFORE any actor is touched (CUST-SSA-001): a
          // mismatched hash returns here and never reaches the agent.
          const bound = bindApproval(view, typed.value);
          if (bound.kind === "refused") {
            ctx.state.status = null;
            const note = el("p", { class: "error", "data-testid": `operator-approve-refused-${view.proposal_id}` }, [
              bound.reason,
            ]);
            typed.after(note);
            return;
          }
          void run(
            `approve(\n  ${bound.proposalId} : nat64,\n  blob "${commitment.replace(/../g, (h) => `\\${h}`)}",\n)`,
            () => actors.vault.approve(bound.proposalId, bound.commitmentHash),
            (outcome) => JSON.stringify(outcome, (_k, v) => (typeof v === "bigint" ? v.toString(10) : v)),
            `approve-${view.proposal_id}`,
          ).then(paint);
        },
      },
      ["Approve"],
    );
    rows.push(
      el("p", { class: "muted" }, [
        "To approve, paste the FULL commitment hash above. It is compared byte for byte; a " +
          "mismatch sends nothing. The bytes sent are the ones on this view, never the text you typed.",
      ]),
      el("div", { class: "row" }, [typed, approve]),
      localResultFor(state, `approve-${view.proposal_id}`),
    );
    if (view.proposer.toText() === me.toText()) {
      rows.push(
        el("div", { class: "row" }, [
          el(
            "button",
            {
              "data-testid": `operator-cancel-${view.proposal_id}`,
              onclick: () =>
                void run(
                  `cancel_proposal(${view.proposal_id} : nat64)`,
                  () => actors.vault.cancelProposal(view.proposal_id),
                  () => "null",
                  `cancel-${view.proposal_id}`,
                ).then(paint),
            },
            ["Cancel my proposal"],
          ),
          localResultFor(state, `cancel-${view.proposal_id}`),
        ]),
      );
    }
  }
  if (view.result.length === 1) {
    rows.push(el("p", { class: "muted" }, [`result: ${view.result[0]}`]));
  }
  // SSA C-8 — a Pending card renders the local result beneath the control that
  // sent it (above). Once the row is terminal that control is gone, so the
  // retained result is re-anchored HERE, on the same card, rather than being
  // lost when the row transitions. The anchor states WHAT was sent and the
  // status observed NOW; it never claims the call produced that status — the
  // outcome may have come from another signer, or from a call whose transport
  // failed. Do not reintroduce causal wording here.
  if (!("Pending" in view.outcome) && localResultProposalId(state) === view.proposal_id) {
    const source = state.localResult!.source;
    rows.push(
      el("p", { class: "muted", "data-testid": `operator-retained-result-anchor-${view.proposal_id}` }, [
        `Result of the ${source.startsWith("approve-") ? "approve" : "cancel"} call you sent for ` +
          `#${view.proposal_id}. Current proposal status: ${outcomeTag(view)}.`,
      ]),
      localResultFor(state, source),
    );
  }
  return el("div", { class: "proposal" }, rows);
}

// ── Propose ──────────────────────────────────────────────────────────────────

function proposePanel(
  state: OperatorState,
  actors: { vault: VaultCanister; upgrader: UpgraderCanister },
  deps: OperatorDeps,
  run: RunFn,
  paint: () => void,
): HTMLElement {
  const rows: HTMLElement[] = [
    el("h3", {}, ["Propose"]),
    el("p", { class: "muted" }, [
      `Every proposal is sent with lifetime = null — the ruled default. The ruled bound is ` +
        `${RULED_LIFETIME_MIN_DAYS}–${RULED_LIFETIME_MAX_DAYS} days; this page offers no custom ` +
        "lifetime field, and an explicit lifetime is refused by the Vault while the bounds are unruled.",
    ]),
  ];

  // O-3: the result belongs to the control that caused it. One `send` per
  // form, tagged with that form's id, so five near-identical forms cannot
  // report each other's outcome — and the tag survives the repaint.
  const sendFor =
    (source: string): SendFn =>
    (built, digests) => {
      if ("refused" in built) {
        state.notice = { kind: "error", text: built.refused };
        state.localResult = { source, kind: "error", text: built.refused };
        state.preview = null;
        state.rawResult = null;
        paint();
        return;
      }
      void run(
        candidPreview(built.ok, digests),
        () => actors.vault.propose(built.ok),
        (id) => `proposal_id = ${id}`,
        source,
      ).then(paint);
    };

  const withLocal = (form: HTMLElement, source: string): HTMLElement => {
    form.append(localResultFor(state, source));
    return form;
  };

  rows.push(withLocal(createCanisterForm(sendFor("propose-create")), "propose-create"));
  rows.push(withLocal(codeForm("InstallCode", deps, sendFor("propose-InstallCode")), "propose-InstallCode"));
  rows.push(withLocal(codeForm("Upgrade", deps, sendFor("propose-Upgrade")), "propose-Upgrade"));
  rows.push(withLocal(updateSettingsForm(sendFor("propose-settings")), "propose-settings"));
  rows.push(withLocal(updateSignerSetForm(sendFor("propose-signerset")), "propose-signerset"));
  return el("div", { class: "panel" }, rows);
}

type SendFn = (built: BuildResult<VaultActionKind>, digests?: { wasmSha256?: string }) => void;

function createCanisterForm(send: SendFn): HTMLElement {
  const role = el("select", { "data-testid": "operator-create-role" },
    BORN_UNDER_VAULT_ROLES.map((r) => el("option", { value: r }, [r])),
  );
  return el("div", { class: "form" }, [
    el("h4", {}, ["Management.CreateCanister"]),
    el("p", { class: "muted" }, [
      "Allocates a new canister under the Vault for one of the nine BORN_UNDER_VAULT roles. " +
        "The disposition is fixed at BornUnderVault. Cycles come from the Vault's own balance — " +
        "check `dfx canister status cpdab-saaaa-aaaar-qca2q-cai` shows at least 20T before " +
        // UNBACKED: an Owner ruling precondition for J-18, not a measurement
        // made in this tree — and the copy says who must check it, and how.
        "raising J-18 creations; the Vault exposes no cycle-balance query, so this page cannot check it for you.",
    ]),
    el("div", { class: "row" }, [
      role,
      el("button", {
        class: "primary",
        "data-testid": "operator-create-submit",
        onclick: () => send(buildCreateCanister(role.value)),
      }, ["Propose CreateCanister"]),
    ]),
  ]);
}

function codeForm(kind: "InstallCode" | "Upgrade", deps: OperatorDeps, send: SendFn): HTMLElement {
  const role = el("select", { "data-testid": `operator-${kind}-role` },
    BORN_UNDER_VAULT_ROLES.map((r) => el("option", { value: r }, [r])),
  );
  const target = el("input", { type: "text", placeholder: "target principal", size: 34, "data-testid": `operator-${kind}-target` });
  const typedHash = el("input", { type: "text", placeholder: "expected_wasm_hash (64 hex)", size: 70, "data-testid": `operator-${kind}-hash` });
  const argHash = el("input", { type: "text", placeholder: "expected_arg_hash (64 hex)", size: 70, "data-testid": `operator-${kind}-arghash` });
  const wasmFile = el("input", { type: "file", "data-testid": `operator-${kind}-wasm` });
  const argFile = el("input", { type: "file", "data-testid": `operator-${kind}-arg` });
  const ack = el("input", { type: "checkbox", "data-testid": `operator-${kind}-unpinned-ack` });
  const local = el("p", { class: "muted", "data-testid": `operator-${kind}-local` }, ["No file selected."]);

  let wasmBytes: Uint8Array = new Uint8Array();
  let localHash = "";

  wasmFile.addEventListener("change", () => {
    void (async () => {
      const file = wasmFile.files?.[0];
      if (file === undefined) return;
      wasmBytes = new Uint8Array(await file.arrayBuffer());
      localHash = (await deps.sha256Hex(wasmBytes)).toLowerCase();
      local.textContent = `local sha256 of ${file.name} (${wasmBytes.length} bytes): ${localHash}`;
    })();
  });

  const unpinnedNote = UNPINNED_ROLES.join(", ");
  return el("div", { class: "form" }, [
    el("h4", {}, [`Management.${kind}`]),
    el("p", { class: "muted" }, [
      "The file you pick is hashed LOCALLY and must equal BOTH the hash you type and the " +
        "[wasm.*] pin in deployment/mainnet/release_hashes.toml before a proposal is built. " +
        `Exception, by ruling: ${unpinnedNote} carries no pin (installed at A-7 under D1) and needs ` +
        "the acknowledgement below — record the Owner ruling id in your operator log, because the " +
        "Vault has no on-chain note field to carry it.",
    ]),
    el("div", { class: "row" }, [role, target]),
    el("div", { class: "row" }, [typedHash]),
    el("div", { class: "row" }, [argHash]),
    el("div", { class: "row" }, ["wasm: ", wasmFile]),
    el("div", { class: "row" }, ["arg:  ", argFile]),
    local,
    el("label", { class: "row" }, [ack, ` unpinned role (${unpinnedNote}) — Owner-ruled, recorded off-chain`]),
    el("div", { class: "row" }, [
      el("button", {
        class: "primary",
        "data-testid": `operator-${kind}-submit`,
        onclick: () => {
          void (async () => {
            const parsedTarget = parsePrincipal(target.value);
            if ("refused" in parsedTarget) return send(parsedTarget as BuildResult<VaultActionKind>);
            const argBytes =
              argFile.files?.[0] === undefined
                ? new Uint8Array()
                : new Uint8Array(await argFile.files[0].arrayBuffer());
            const input = {
              target: parsedTarget.ok,
              role: role.value,
              typedWasmHash: typedHash.value,
              localWasmHash: localHash,
              wasmBytes,
              argHash: argHash.value,
              argBytes,
              pins: deps.pins,
              unpinnedRoleAcknowledged: (ack as HTMLInputElement).checked,
            };
            send(kind === "InstallCode" ? buildInstallCode(input) : buildUpgrade(input), {
              wasmSha256: localHash,
            });
          })();
        },
      }, [`Propose ${kind}`]),
    ]),
    el("p", { class: "muted" }, [
      `pin for the selected role is read from the build-time map; ${
        Object.keys(deps.pins).length
      } [wasm.*] rows are compiled in.`,
    ]),
  ]);
}

function updateSettingsForm(send: SendFn): HTMLElement {
  const target = el("input", { type: "text", placeholder: "target principal", size: 34, "data-testid": "operator-settings-target" });
  const controllers = el("textarea", {
    placeholder: "final controller set, one principal per line",
    rows: 3,
    cols: 60,
    "data-testid": "operator-settings-controllers",
  });
  const observed = el("textarea", {
    placeholder: "paste the output of: dfx canister info <target>",
    rows: 4,
    cols: 70,
    "data-testid": "operator-settings-observed",
  });
  const warn = el("p", { class: "muted", "data-testid": "operator-settings-warning" }, [""]);
  const VAULT_TEXT = "cpdab-saaaa-aaaar-qca2q-cai";
  observed.addEventListener("input", () => {
    // SSA H-02: there is NO controller read model on the Vault and a browser
    // cannot query the management canister, so the ONLY controller facts this
    // page has are the ones the operator pastes. It is treated as exactly that:
    // operator-supplied text, used for one warning, never as a verified read.
    const text = (observed as HTMLTextAreaElement).value;
    warn.textContent =
      text.trim() === ""
        ? ""
        : text.includes(VAULT_TEXT)
          ? `The pasted dfx output names the Vault (${VAULT_TEXT}) as a controller of the target. (Operator-pasted text, not a verified read.)`
          : `WARNING: the pasted dfx output does NOT name the Vault (${VAULT_TEXT}) as a controller of the target. ` +
            "A Management.UpdateSettings proposal raised now will pass quorum and FAIL at execution. " +
            "The Owner must first run `dfx canister update-settings --add-controller cpdab-… <target>`.";
  });
  return el("div", { class: "form" }, [
    el("h4", {}, ["Management.UpdateSettings (controller set)"]),
    el("p", { class: "muted" }, [
      "The only cutover-related Vault action. Ring closure is a THREE-step order and this is step 2: " +
        "(1) the Owner adds the Vault as a controller of the target with dfx; (2) this proposal sets " +
        "the final controller set; (3) removing the bootstrap controller from the Vault/Upgrader " +
        "themselves is an Owner dfx action, not a Vault action — there is deliberately no button for it.",
    ]),
    el("div", { class: "row" }, [target]),
    el("div", { class: "row" }, [controllers]),
    el("p", { class: "muted" }, ["Target's current controllers (paste `dfx canister info <target>`):"]),
    el("div", { class: "row" }, [observed]),
    warn,
    el("div", { class: "row" }, [
      el("button", {
        class: "primary",
        "data-testid": "operator-settings-submit",
        onclick: () => {
          const parsedTarget = parsePrincipal(target.value);
          if ("refused" in parsedTarget) return send(parsedTarget as BuildResult<VaultActionKind>);
          const list = parsePrincipalList((controllers as HTMLTextAreaElement).value);
          if ("refused" in list) return send(list as BuildResult<VaultActionKind>);
          send(buildUpdateSettings({ target: parsedTarget.ok, controllers: list.ok }));
        },
      }, ["Propose UpdateSettings"]),
    ]),
  ]);
}

function updateSignerSetForm(send: SendFn): HTMLElement {
  const signers = el("textarea", {
    placeholder: "new signer set, one principal per line",
    rows: 4,
    cols: 60,
    "data-testid": "operator-signerset-signers",
  });
  const threshold = el("input", { type: "number", min: 1, value: 2, "data-testid": "operator-signerset-threshold" });
  return el("div", { class: "form" }, [
    el("h4", {}, ["UpdateSignerSet"]),
    el("p", { class: "muted" }, [
      "A TOP-LEVEL action, not a Management variant. The proposed principals are shown IN FULL on " +
        "the view a peer approves from — check them there, principal by principal, before approving.",
    ]),
    el("div", { class: "row" }, [signers]),
    el("div", { class: "row" }, ["threshold ", threshold]),
    el("div", { class: "row" }, [
      el("button", {
        class: "primary",
        "data-testid": "operator-signerset-submit",
        onclick: () => {
          const list = parsePrincipalList((signers as HTMLTextAreaElement).value);
          if ("refused" in list) return send(list as BuildResult<VaultActionKind>);
          send(
            buildUpdateSignerSet({
              signers: list.ok,
              threshold: Number.parseInt((threshold as HTMLInputElement).value, 10),
            }),
          );
        },
      }, ["Propose UpdateSignerSet"]),
    ]),
  ]);
}

function maintenancePanel(
  actors: { vault: VaultCanister; upgrader: UpgraderCanister },
  run: RunFn,
): HTMLElement {
  return el("div", { class: "panel" }, [
    el("h3", {}, ["Maintenance"]),
    el("p", { class: "muted" }, [
      // MEASURED: s5a_m1_gate_a_measure_sweep_cost_vault_plane
      `The expiry sweep is bounded so it cannot itself become a denial of service; the Vault ` +
        `clamps the count to ${SWEEP_LIMIT}. Repeat until it returns an empty list. Sweeping is ` +
        "the ONLY thing that terminalizes an expired proposal and the only thing that releases " +
        "its accounted payload budget.",
    ]),
    el("div", { class: "row" }, [
      el("button", {
        "data-testid": "operator-sweep",
        onclick: () =>
          void run(
            `sweep_expired_proposals(${SWEEP_LIMIT} : nat32)`,
            () => actors.vault.sweepExpiredProposals(SWEEP_LIMIT),
            (ids) => `reaped = [${ids.map((i) => i.toString(10)).join(", ")}]`,
          ),
      }, [`Sweep expired proposals (${SWEEP_LIMIT})`]),
    ]),
  ]);
}

// ── Upgrader — membership rotation (UPG-ROT-UI) ──────────────────────────────

/** `Error -> string`, written once so no call site invents its own phrasing. */
function errText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Raw JSON for the evidence file: bigints decimal, blobs hex, principals text. */
function rawJson(value: unknown): string {
  return JSON.stringify(
    value,
    (_k, v) =>
      typeof v === "bigint"
        ? v.toString(10)
        : v instanceof Uint8Array
          ? bytesToHex(v)
          : typeof v === "object" && v !== null && "toText" in v &&
              typeof (v as { toText: unknown }).toText === "function"
            ? (v as { toText(): string }).toText()
            : v,
    2,
  );
}

/** A "copy raw JSON" button. Clipboard access is optional and never assumed. */
function copyButton(testid: string, text: () => string | null): HTMLElement {
  return el(
    "button",
    {
      "data-testid": testid,
      onclick: () => {
        const value = text();
        if (value === null) return;
        // The canonical evidence remains the dfx read-back by the machine
        // identity; this is a convenience, so a browser without clipboard
        // permission must degrade silently rather than break the ceremony.
        void navigator.clipboard?.writeText(value)?.catch(() => undefined);
      },
    },
    ["Copy raw JSON"],
  );
}

type RunRecoveryFn = <T>(
  preview: string,
  call: () => Promise<UpgraderResult<T>>,
  describe: (value: T) => string,
) => Promise<void>;

function isRecoveryMember(state: OperatorState, me: Principal): boolean {
  if (state.recoveryMembers === null) return false;
  return state.recoveryMembers.some((m) => m.toText() === me.toText());
}

/**
 * The Upgrader rotation surface — the II half of the step-7 quorum.
 *
 * WHY IT EXISTS (UPG-ROT-UI V1 §1). The old recovery roster is
 * `[Owner II, STSHProtocol II, machine dfx]` at threshold 2. II cannot sign
 * through dfx, so before this section the plane was reachable only as the
 * machine identity — one of a threshold of two, and the rotation could be
 * neither proposed nor approved.
 *
 * WHAT IT IS NOT. It is not a recovery-action dispatcher. `propose_recovery`,
 * `cancel_recovery_proposal`, `sweep_expired_recovery_proposals`,
 * `trigger_vault_upgrade`, `reconcile_vault_upgrade` and
 * `refresh_controller_invariant_now` are all absent from the actor, so no
 * control here can reach them. `approve_recovery` IS shared between the two
 * planes on the wire, and the rotation-only boundary is this: approval is
 * reachable solely from a successfully fetched `get_rotation_proposal` view,
 * which returns nothing for a recovery-ACTION proposal.
 */
function upgraderRotationPanel(
  state: OperatorState,
  actors: { vault: VaultCanister; upgrader: UpgraderCanister },
  me: Principal,
  runRecovery: RunRecoveryFn,
  loadRotation: (idText: string) => Promise<void>,
  paint: () => void,
): HTMLElement {
  const rows: HTMLElement[] = [
    el("h3", {}, ["Upgrader — membership rotation"]),
    el("p", { class: "muted", "data-testid": "operator-rotation-commitment-warning" }, [
      "The commitment proves what was proposed, not that it is the reviewed roster. Compare the " +
        "three principals against the ceremony record before approving.",
    ]),
    el("p", { class: "muted" }, [
      "This plane has its OWN membership, held by the Upgrader and never synced from the Vault. " +
        "Being a Vault signer does not make you a recovery member, and the gate below reads the " +
        "Upgrader directly.",
    ]),
  ];

  if (!state.recoveryLoaded) {
    rows.push(
      el("p", { class: "muted", "data-testid": "operator-rotation-loading" }, [
        "Reading the Upgrader recovery membership…",
      ]),
    );
    return el("div", { class: "panel", "data-testid": "operator-rotation" }, rows);
  }

  if (!isRecoveryMember(state, me)) {
    // FAIL CLOSED, and one message for every reason (SSA C-3). A null read is
    // the indistinguishable unauthorized answer; a FAILED read is reported
    // separately in the notice bar but lands here too, because "we could not
    // establish that you are a member" and "you are not one" must both end
    // with no controls.
    rows.push(
      el("p", { class: "error", "data-testid": "operator-rotation-not-member" }, [
        state.recoveryMembers === null
          ? "The Upgrader did not answer the recovery-membership query for this principal — " +
            "unauthorized, or the read failed. The rotation controls are OFF; nothing is " +
            "constructible here."
          : "Your principal is not in the Upgrader recovery membership. The rotation controls " +
            "are OFF; the Upgrader would refuse them regardless.",
      ]),
    );
    return el("div", { class: "panel", "data-testid": "operator-rotation" }, rows);
  }

  rows.push(
    el("h4", {}, ["Recovery members"]),
    el(
      "ul",
      { "data-testid": "operator-rotation-member-list" },
      (state.recoveryMembers ?? []).map((m) =>
        el("li", {}, [`${m.toText()}${m.toText() === me.toText() ? "  ← you" : ""}`]),
      ),
    ),
    rotationProposeForm(state, actors, runRecovery, paint),
    rotationLookupForm(state, actors, me, runRecovery, loadRotation, paint),
    rotationReadbackRow(state, actors),
  );
  return el("div", { class: "panel", "data-testid": "operator-rotation" }, rows);
}

function rotationProposeForm(
  state: OperatorState,
  actors: { vault: VaultCanister; upgrader: UpgraderCanister },
  runRecovery: RunRecoveryFn,
  paint: () => void,
): HTMLElement {
  const members = el("textarea", {
    placeholder: "new recovery roster, one principal per line",
    rows: 4,
    cols: 60,
    "data-testid": "operator-rotation-members",
  });
  const count = el("input", {
    type: "text",
    size: 4,
    placeholder: "count",
    "data-testid": "operator-rotation-count",
  });
  return el("div", { class: "form" }, [
    el("h4", {}, ["Propose propose_membership_rotation"]),
    el("p", { class: "muted" }, [
      `No defaults and no pre-fill from any config: type all ${ROTATION_ROSTER_SIZE} principals. ` +
        `Then type the count (${ROTATION_ROSTER_SIZE}) to confirm the roster you are about to ` +
        "submit. The lifetime sent is null — the canister's RULED DEFAULT, not 'no expiry'.",
    ]),
    el("div", { class: "row" }, [members]),
    el("div", { class: "row" }, ["confirm member count: ", count]),
    el("div", { class: "row" }, [
      el(
        "button",
        {
          class: "primary",
          "data-testid": "operator-rotation-propose",
          onclick: () => {
            const built = buildRotationRoster(
              (members as HTMLTextAreaElement).value,
              (count as HTMLInputElement).value,
            );
            if ("refused" in built) {
              // Returns BEFORE the actor is invoked: nothing reaches the wire.
              state.notice = { kind: "error", text: built.refused };
              state.preview = null;
              state.rawResult = null;
              paint();
              return;
            }
            void runRecovery(
              rotationCandidPreview(built.ok),
              () => actors.upgrader.proposeMembershipRotation(built.ok),
              (id) => `proposal_id = ${id}`,
            ).then(paint);
          },
        },
        ["Propose rotation"],
      ),
    ]),
  ]);
}

function rotationLookupForm(
  state: OperatorState,
  actors: { vault: VaultCanister; upgrader: UpgraderCanister },
  me: Principal,
  runRecovery: RunRecoveryFn,
  loadRotation: (idText: string) => Promise<void>,
  paint: () => void,
): HTMLElement {
  const id = el("input", {
    type: "text",
    size: 10,
    placeholder: "proposal id",
    "data-testid": "operator-rotation-id",
  });
  const rows: HTMLElement[] = [
    el("h4", {}, ["View + approve a rotation proposal"]),
    el("p", { class: "muted" }, [
      "Approval exists only on a proposal that was FETCHED here, by id. There is deliberately " +
        "no form that takes an id and a hash and sends them.",
    ]),
    el("div", { class: "row" }, [
      id,
      el(
        "button",
        {
          "data-testid": "operator-rotation-load",
          onclick: () => void loadRotation((id as HTMLInputElement).value),
        },
        ["Load proposal"],
      ),
    ]),
  ];
  if (state.rotationNote !== null) {
    rows.push(
      el("p", { class: "error", "data-testid": "operator-rotation-lookup-note" }, [
        state.rotationNote,
      ]),
    );
  }
  const view = state.rotation;
  if (view !== null) {
    rows.push(rotationCard(view, state, actors, me, runRecovery, paint));
  }
  return el("div", { class: "form" }, rows);
}

function rotationCard(
  view: RotationProposalView,
  state: OperatorState,
  actors: { vault: VaultCanister; upgrader: UpgraderCanister },
  me: Principal,
  runRecovery: RunRecoveryFn,
  paint: () => void,
): HTMLElement {
  const commitment = bytesToHex(view.commitment_hash);
  const rows: HTMLElement[] = [
    el("h4", {}, [`rotation #${view.proposal_id} — ${Object.keys(view.outcome)[0] ?? "(unknown)"}`]),
    // EVERY field of RotationProposalView is rendered. `new_members` is shown
    // IN FULL, in order — never as a count: a count is exactly what a signer
    // cannot check a roster against.
    el("p", { class: "muted", "data-testid": "operator-rotation-meta" }, [
      `proposer ${view.proposer.toText()} · epoch ${view.epoch} · threshold ${view.threshold} · ` +
        `approvals ${view.approvals.length} · created_at_ns ${view.created_at_ns}`,
    ]),
    el("p", {}, ["new_members (in order):"]),
    el(
      "ol",
      { "data-testid": "operator-rotation-new-members" },
      view.new_members.map((m) => el("li", {}, [m.toText()])),
    ),
    el("p", {}, ["approvals:"]),
    el(
      "ul",
      { "data-testid": "operator-rotation-approvals" },
      view.approvals.map((a) =>
        el("li", {}, [`${a.toText()}${a.toText() === me.toText() ? "  ← you" : ""}`]),
      ),
    ),
    el("p", { class: "muted", "data-testid": "operator-rotation-expiry" }, [
      describeRotationExpiry(view),
    ]),
    el("p", {}, ["commitment_hash:"]),
    el("code", { "data-testid": `operator-rotation-commitment-${view.proposal_id}` }, [commitment]),
  ];

  if ("Pending" in view.outcome) {
    const typed = el("input", {
      type: "text",
      placeholder: "paste the full 64-hex commitment hash",
      "data-testid": "operator-rotation-approve-input",
      size: 70,
    });
    rows.push(
      el("p", { class: "muted" }, [
        "To approve, paste the FULL commitment hash above. It is compared byte for byte; a " +
          "mismatch sends nothing. The bytes sent are the ones on this view, never the text you " +
          "typed, and the page never recomputes a rotation hash of its own.",
      ]),
      el("div", { class: "row" }, [
        typed,
        el(
          "button",
          {
            class: "primary",
            "data-testid": "operator-rotation-approve",
            onclick: () => {
              // Same binding as the Vault plane, same code (CUST-SSA-001).
              // The refusal returns here, before the actor is invoked.
              const bound = bindApproval(view, (typed as HTMLInputElement).value);
              if (bound.kind === "refused") {
                state.notice = { kind: "error", text: bound.reason };
                state.preview = null;
                state.rawResult = null;
                paint();
                return;
              }
              void runRecovery(
                rotationApprovePreview(bound.proposalId, bound.commitmentHash),
                () => actors.upgrader.approveRecovery(bound.proposalId, bound.commitmentHash),
                () => "null",
              ).then(paint);
            },
          },
          ["Approve rotation"],
        ),
      ]),
    );
  } else {
    rows.push(
      el("p", { class: "muted", "data-testid": "operator-rotation-terminal" }, [
        "This proposal is not Pending. No approval control is rendered; the Upgrader would " +
          "answer AlreadyTerminal.",
      ]),
    );
  }
  return el("div", { class: "proposal" }, rows);
}

/**
 * Read-back helpers for the evidence file.
 *
 * The ledger row needs `readback_command` + `readback_output_sha256`, and the
 * CANONICAL evidence is the dfx read-back by the machine identity. This is a
 * convenience for the signer sitting at the browser, and says so.
 */
function rotationReadbackRow(
  state: OperatorState,
  actors: { vault: VaultCanister; upgrader: UpgraderCanister },
): HTMLElement {
  const out = el("pre", { "data-testid": "operator-rotation-readback" }, [
    state.rotationReadback ?? "(nothing read yet)",
  ]);
  const show = (label: string, fn: () => Promise<unknown>) =>
    el(
      "button",
      {
        "data-testid": `operator-rotation-read-${label}`,
        onclick: () => {
          void (async () => {
            try {
              out.textContent = `${label}:\n${rawJson(await fn())}`;
            } catch (error) {
              out.textContent = `${label}: ${errText(error)}`;
            }
          })();
        },
      },
      [label],
    );
  return el("div", { class: "form" }, [
    el("h4", {}, ["Read-back (convenience, not the record)"]),
    el("p", { class: "muted" }, [
      "The CANONICAL evidence for the rotation ledger is the dfx read-back by the machine " +
        "identity, saved unedited to a file. What is copied here is the same data as the browser " +
        "saw it, for cross-checking — not the record.",
    ]),
    el("div", { class: "row" }, [
      show("get_recovery_summary", () => actors.upgrader.getRecoverySummary()),
      show("get_recovery_membership", () => actors.upgrader.getRecoveryMembership()),
      copyButton("operator-rotation-copy", () => out.textContent),
    ]),
    out,
  ]);
}

// ── Admin / status ───────────────────────────────────────────────────────────

function statusPanel(
  state: OperatorState,
  ctx: AppContext,
  actors: { vault: VaultCanister; upgrader: UpgraderCanister },
  deps: OperatorDeps,
  refresh: () => Promise<void>,
  report: (kind: "info" | "error" | "success", text: string) => void,
  paint: () => void,
): HTMLElement {
  const out = el("pre", { "data-testid": "operator-status-output" }, ["(nothing read yet)"]);
  const show = (label: string, fn: () => Promise<unknown>) =>
    el("button", {
      "data-testid": `operator-status-${label}`,
      onclick: () => {
        void (async () => {
          try {
            const value = await fn();
            out.textContent = `${label}:\n${JSON.stringify(
              value,
              (_k, v) =>
                typeof v === "bigint"
                  ? v.toString(10)
                  : v instanceof Uint8Array
                    ? bytesToHex(v)
                    : typeof v === "object" && v !== null && "toText" in v && typeof (v as { toText: unknown }).toText === "function"
                      ? (v as { toText(): string }).toText()
                      : v,
              2,
            )}`;
          } catch (error) {
            out.textContent = `${label}: ${error instanceof Error ? error.message : String(error)}`;
          }
        })();
      },
    }, [label]);

  return el("div", { class: "panel" }, [
    el("h3", {}, ["Status"]),
    el("p", { class: "muted" }, [
      "Read-only. A signer-gated query answers an unauthorized caller with an indistinguishable " +
        "empty result, so an empty panel is not evidence of an empty Vault. Nothing here is cached.",
    ]),
    el("div", { class: "row" }, [
      show("get_governance_summary", () => actors.vault.getGovernanceSummary()),
      show("get_signers", () => actors.vault.getSigners()),
      show("get_governed_targets", () => actors.vault.getGovernedTargets()),
      show("get_build_info", () => actors.vault.getBuildInfo()),
      show("get_action_catalogue", () => actors.vault.getActionCatalogue()),
    ]),
    el("div", { class: "row" }, [
      show("get_creation_receipts", () => actors.vault.getCreationReceipts(state.receiptsCursor, PAGE_LIMIT)),
      show("get_audit_events", () => actors.vault.getAuditEvents(state.auditCursor, PAGE_LIMIT)),
    ]),
    el("p", { class: "muted" }, [
      "Upgrader (recovery plane). `get_controller_invariant_proof` is the AUTHORITATIVE answer to " +
        "\"is the no-human-controller property proven right now?\" — read `current_proof_ok`. The " +
        "legacy `get_controller_invariant` read carries no freshness and is deliberately not offered here.",
    ]),
    el("div", { class: "row" }, [
      show("get_controller_invariant_proof", () => actors.upgrader.getControllerInvariantProof()),
      show("upgrader.get_recovery_summary", () => actors.upgrader.getRecoverySummary()),
      show("upgrader.get_build_info", () => actors.upgrader.getBuildInfo()),
      show("upgrader.get_recovery_membership", () => actors.upgrader.getRecoveryMembership()),
      show("upgrader.get_audit_events", () => actors.upgrader.getAuditEvents(null, PAGE_LIMIT)),
    ]),
    out,
    el("div", { class: "row" }, [
      el("button", {
        "data-testid": "operator-reload",
        onclick: () => {
          void refresh().then(paint);
        },
      }, ["Reload proposals + signers"]),
    ]),
    // Deliberately a STUB, not wiring to canisters that do not exist yet: the
    // nine born-under-vault canisters are created at J-18 and installed at A-7.
    el("div", { class: "panel", "data-testid": "operator-pool-stats-stub" }, [
      el("h4", {}, ["Pool / token stats — after A-7"]),
      el("p", { class: "muted" }, [
        "Solvency attestation, payout_memo_key_ready and supply reconciliation belong here. They " +
          "are NOT wired: the pool and token canisters do not exist until J-18 creates them and " +
          "A-7 installs them. This section is a placeholder so adding them later is a wiring " +
          "change, not a redesign — it is not showing you zeros for canisters that are missing.",
      ]),
    ]),
    el("p", { class: "muted" }, [
      `Vault ${ctx.config.vaultCanisterId} · Upgrader ${ctx.config.upgraderCanisterId} · ` +
        `${Object.keys(deps.pins).length} release pins compiled in`,
    ]),
  ]);
}

/** Exported for the vitest arms — pure helpers, no DOM. */
export { actionSummary, expectedWasmHashOf, isRecoveryMember, isSigner };
