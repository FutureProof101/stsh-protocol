/**
 * Scan page (Campaign B / L3b — §9).
 *
 * Runs the validated scan pipeline (strict spent-set download, full public
 * sweep into the local Merkle mirror, per-candidate validation, ONE atomic
 * cache update). The login + cache-unlock preconditions are enforced by the
 * app shell's route gate (same pattern as shield) — this page only renders
 * for an unlocked session.
 *
 * WALLET-AUTH G1b (D-6): this page also carries the VERIFIED SWEEP action.
 * It is a button and only a button — there is no timer, no on-mount trigger and
 * no retry loop behind it, because a verified sweep is a run of ingress
 * messages that the user pays for in visibility and the canisters pay for in
 * cycles (parent brief §8: periodic verified scanning stays forbidden). The
 * button's own copy says what that costs before it is pressed.
 *
 * K3-007: the "Historical pool commitments" line is the mirror head's
 * leaf_count — an ADVISORY pool-wide figure, never an anonymity-set estimate
 * (it includes spent notes, zero dummies, and repeated/self-churn outputs).
 */

import { clear, el } from "../dom";
import { formatStsh } from "../format";
import type { AppContext } from "../context";
import { spendableNotes } from "../../storage/noteCache";
import { VERIFIED_SCAN_STRINGS } from "../verifiedScanCopy";
import { cooldownWords, recordSweepStarted, sweepCooldownRemainingMs } from "../sweepCooldown";

/** The exact K3-007 advisory label (S-47 — never an anonymity guarantee). */
export function advisoryPoolCommitmentLine(leafCount: bigint): string {
  return (
    `Historical pool commitments: ${leafCount} — advisory; includes spent, dummy ` +
    "and repeated/self-churn outputs; not an anonymity guarantee."
  );
}

export function renderScan(root: HTMLElement, ctx: AppContext): void {
  clear(root);
  root.append(
    el("a", { class: "back-link", href: "#/account" }, ["← Home"]),
    el("h2", {}, ["Sync"]),
    el("p", { class: "page-sub" }, ["Sync rebuilds your private balance from the chain, on this device."]),
  );

  const scanBtn = el("button", { class: "primary", disabled: ctx.state.scanning || ctx.state.busy }, [
    ctx.state.scanning ? "Syncing…" : "Sync now",
  ]);
  scanBtn.addEventListener("click", () => void ctx.scan());

  const progress = el("div", { class: "preview" });
  if (ctx.state.scanning) {
    const p = ctx.state.scanProgress;
    progress.append(
      el("p", { class: "muted" }, [
        p ? `Syncing… ${p.found} note${p.found === 1 ? "" : "s"} found so far.` : "Syncing…",
      ]),
      el("button", { class: "small", onclick: () => ctx.cancelSessionTasks?.() }, [
        "Cancel scan",
      ]),
    );
  } else {
    const spendable = spendableNotes(ctx.state.notes);
    if (spendable.length > 0) {
      const confirmed = ctx.state.lastScanOk === true;
      progress.append(
        el("p", { class: confirmed ? "success" : "muted" }, [
          `${confirmed ? "Up to date" : "Not synced"}: ` +
            `${spendable.length} private note${spendable.length === 1 ? "" : "s"}, ${formatStsh(
              spendable.reduce((s, n) => s + n.value, 0n),
            )} STSH.`,
        ]),
      );
    }
    if (ctx.state.isAdmin === true && ctx.state.quarantineTotal > 0) {
      progress.append(
        el("p", { class: "muted admin-only" }, [
          `${ctx.state.quarantineTotal} invalid or legacy candidate(s) quarantined (bounded diagnostics only).`,
        ]),
      );
    }
  }

  root.append(scanBtn, progress);

  root.append(
    el("p", { class: "muted" }, [
      "Need a verified note sweep? It is in ",
      el("a", { href: "#/settings" }, ["Settings > Advanced recovery"]),
      ".",
    ]),
  );

  if (ctx.state.isAdmin === true && ctx.state.mirrorHead !== null) {
    root.append(
      el("p", { class: "muted admin-only", "data-testid": "pool-commitment-count" }, [
        advisoryPoolCommitmentLine(ctx.state.mirrorHead.leafCount),
      ]),
    );
  }
}

/**
 * The verified sweep section (D-6).
 *
 * Four things, in the order a user meets them:
 *
 *   1. the ACTION, with the lease copy beside it, so the cost in visibility is
 *      stated BEFORE the press rather than explained after it;
 *   2. the OBSERVATION from the last completed sweep, with its residual in the
 *      same paragraph — never a badge, never a tick beside the balance;
 *   3. the REFUSAL, when the floor rejected a sweep, with the explicit reset
 *      behind its own warning and its own confirmation;
 *   4. nothing else. There is no "verify automatically" toggle to add later by
 *      accident.
 */
export function renderVerifiedSweep(root: HTMLElement, ctx: AppContext): void {
  if (ctx.verifiedScan === undefined) return;

  const section = el("section", { class: "preview", "data-testid": "verified-sweep" });
  section.append(el("h3", {}, ["Verified note sweep"]));

  // WALLET-UX: one sweep per hour per signed-in principal (UI courtesy; the
  // canister-side per-caller window is the real limit — see sweepCooldown.ts).
  const principalText = ctx.state.principal?.toText();
  const waitMs = sweepCooldownRemainingMs(principalText);
  const locked = ctx.state.cacheUnlocked === false;
  const busy = ctx.state.scanning || ctx.state.verifiedScanning || ctx.state.busy;
  const sweepBtn = el(
    "button",
    { disabled: busy || waitMs > 0 || locked, "data-testid": "verified-sweep-button" },
    [
      ctx.state.verifiedScanning
        ? "Verifying…"
        : waitMs > 0
          ? `Available again in ${cooldownWords(waitMs)}`
          : "Run verified note sweep",
    ],
  );
  // ONE listener, on a user gesture. `ctx.verifiedScan` mints the
  // `"verifiedScan"` lease inside that gesture and the worker consumes its
  // single-use token before it builds anything.
  sweepBtn.addEventListener("click", () => {
    recordSweepStarted(principalText);
    void ctx.verifiedScan?.();
  });

  section.append(
    el("p", { class: "muted", "data-testid": "verified-sweep-lease" }, [
      VERIFIED_SCAN_STRINGS.lease,
    ]),
    el("p", { class: "muted", "data-testid": "verified-sweep-limit" }, [
      "One verified note sweep per hour in this wallet.",
    ]),
    ...(locked
      ? [
          el("p", { class: "muted" }, [
            "Open your private balance first. ",
            el("a", { href: "#/balance" }, ["Open"]),
          ]),
        ]
      : []),
    sweepBtn,
  );

  const observed = ctx.state.verifiedScan;
  if (observed !== null) {
    section.append(
      el("p", { class: "success", "data-testid": "verified-sweep-observation" }, [
        VERIFIED_SCAN_STRINGS.observation,
      ]),
      el("p", { class: "muted", "data-testid": "verified-sweep-evidence" }, [
        `Accepted prefix: ${observed.accepted_leaf_count} leaf/leaves at root ` +
          `${observed.accepted_root.slice(0, 16)}…; ${observed.spent_count} spent ` +
          `nullifier(s). Evidence: ${observed.evidence_kind}.`,
      ]),
    );
  }

  const refused = ctx.state.verifiedRollback;
  if (refused !== null) {
    const resetBtn = el(
      "button",
      { disabled: busy, "data-testid": "verified-sweep-reset" },
      ["Reset this wallet's verified history for this deployment"],
    );
    // The confirmation is taken HERE, at the press, and passed down. The
    // action refuses an unconfirmed call, so a future caller that skips the
    // dialog is refused rather than silently obeyed.
    resetBtn.addEventListener("click", () => {
      const confirmed = globalThis.confirm?.(VERIFIED_SCAN_STRINGS.rollbackRefused) ?? false;
      void ctx.resetVerifiedHistory?.({ confirmed });
    });
    section.append(
      el("p", { class: "error", "data-testid": "verified-sweep-rollback" }, [
        VERIFIED_SCAN_STRINGS.rollbackRefused,
      ]),
      el("p", { class: "muted", "data-testid": "verified-sweep-rollback-detail" }, [
        refused.sameCountDifferentRoot
          ? `Same accepted leaf count (${refused.floorLeafCount}), different accepted root.`
          : `Previously ${refused.floorLeafCount} accepted leaf/leaves; now ` +
            `${refused.observedLeafCount}.`,
      ]),
      resetBtn,
    );
  }

  root.append(section);
}
