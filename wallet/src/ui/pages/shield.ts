/**
 * Shield page (wallet-build Commit 6; L3a integration; WALLET-UX layout).
 *
 * Amount -> live fixed-denomination decomposition preview (anti-drift law #1:
 * deposit is fixed-denomination only) -> Shield (II icrc2_approve with
 * allowance CAS, then per-note shield_deposit — L0-A). The app shell gates this
 * page on login + an unlocked note cache.
 *
 * WALLET-UX: the amount is built from denomination chips (typing still works),
 * so an amount the pool cannot accept is hard to produce; the cost is shown as
 * a three-line breakdown; the ruled disclosures (U-2 shape + allowance) are
 * folded under "What's visible on-chain" but always rendered once an amount is
 * planned. The shield journal (in-flight intents and their repair actions)
 * moved to Activity — `renderJournalPanel` is exported for it.
 */

import { clear, el } from "../dom";
import { formatStsh, parseStsh, planShield, shieldAmountErrorLines } from "../format";
import type { AppContext } from "../context";
import { shieldPrivacyWarnings } from "../privacyWarnings";
import type { ShieldJournalEntryState } from "../../storage/noteCache";
import { shieldDepositPreview } from "../../crypto/fees";
import { breakdown, breakdownRow, chip, details, pageHead, progressCard, requestFeeBasis, warningCallout } from "../components";

const E8S = 100_000_000n;
const STEP = 1_000n * E8S;
const CHIPS: Array<{ label: string; units: bigint }> = [
  { label: "+1,000", units: 1_000n * E8S },
  { label: "+10,000", units: 10_000n * E8S },
  { label: "+100,000", units: 100_000n * E8S },
  { label: "+1M", units: 1_000_000n * E8S },
  { label: "+10M", units: 10_000_000n * E8S },
];

export function renderShield(root: HTMLElement, ctx: AppContext): void {
  clear(root);
  root.append(
    ...pageHead({
      title: "Shield STSH",
      sub: "Move public STSH into your private balance.",
      back: { href: "#/account", label: "Home" },
    }),
    // Addendum 2 item 7: stated before anything else on the page, so it is
    // visible without scrolling and before Approve & Shield. One idea per line.
    el("div", { class: "exit-disclosure", "data-testid": "shield-exit-disclosure" }, [
      el("p", {}, ["Shielded funds leave only by public payout."]),
      el("p", {}, ["Recipient, amount and your account are visible when they do."]),
      el("p", {}, ["Private withdraw: later release."]),
    ]),
  );

  const basisState = requestFeeBasis(ctx);
  const basis = ctx.state.spendFeeBasis ?? null;

  if (ctx.state.balance !== null && ctx.state.balance !== undefined) {
    root.append(el("p", { class: "muted" }, [`Public balance: ${formatStsh(ctx.state.balance)} STSH`]));
  }

  const input = el("input", {
    type: "text",
    inputmode: "numeric",
    placeholder: "0",
    "aria-label": "Amount in STSH (e.g. 123)",
    class: "amount amount-lg",
  }) as HTMLInputElement;
  const hint = el("p", { class: "muted" }, ["Shield in steps of 1,000 STSH."]);
  const preview = el("div", { class: "preview plain" });
  // U-2: the deposit side gets the same warnings surface the spend page has.
  const warningsBox = el("div", { class: "warnings" });
  // WALLET-UI addendum 1 (W-4): the U-2 pre-approval disclosures must be
  // visible before the user can press Shield, not one click away behind a
  // closed fold — `open: true` so it renders expanded the moment it appears.
  const disclosure = details("What's visible on-chain", [warningsBox], {
    testid: "shield-disclosure",
    open: true,
  });
  disclosure.hidden = true;
  const submit = el("button", { class: "primary wide", disabled: true }, ["Shield"]) as HTMLButtonElement;

  let planned: bigint | null = null;

  const currentUnits = (): bigint | null => {
    const raw = input.value.trim().replace(/,/g, "");
    if (raw === "") return 0n;
    try {
      return parseStsh(raw);
    } catch {
      return null;
    }
  };

  const update = () => {
    clear(preview);
    clear(warningsBox);
    planned = null;
    disclosure.hidden = true;
    submit.disabled = true;
    submit.textContent = "Shield";
    const raw = input.value.trim();
    if (raw === "") return;
    const amount = currentUnits();
    if (amount === null) {
      preview.append(el("p", { class: "error" }, ["Enter a whole number of STSH, for example 12000."]));
      return;
    }
    if (amount === 0n) return;
    if (amount % STEP !== 0n) {
      const lower = (amount / STEP) * STEP;
      const upper = lower + STEP;
      preview.append(
        el("p", { class: "error" }, [
          lower > 0n
            ? `Shield in steps of 1,000 STSH. Try ${formatStsh(lower)} or ${formatStsh(upper)}.`
            : `Shield in steps of 1,000 STSH. Try ${formatStsh(upper)}.`,
        ]),
      );
      return;
    }
    try {
      const plan = planShield(amount);
      // WALLET-SHIELD-LAYER1 (Owner Addendum A item 5): an amount that alone
      // exceeds the public balance is refused HERE, before the click — the
      // button is disabled, not merely an error after the canister answers.
      // An unknown balance (null: not loaded yet) never blocks.
      const balance = ctx.state.balance ?? null;
      const overBalance = balance !== null && plan.total > balance;
      planned = overBalance ? null : amount;
      submit.disabled = overBalance || ctx.state.busy === true;
      submit.textContent = `Shield ${formatStsh(plan.total)} STSH`;
      if (overBalance) {
        preview.append(
          el("p", { class: "error", "data-testid": "shield-over-balance" }, ["More than your public balance."]),
        );
      }

      const shape = el("div", { class: "note-chips" });
      const largestFirst = [...plan.buckets].sort((x, y) => (x.denom < y.denom ? 1 : x.denom > y.denom ? -1 : 0));
      for (const b of largestFirst) shape.append(chip(`${b.count} × ${formatStsh(b.denom)}`, "accent"));
      preview.append(
        el("div", { class: "bd-title" }, [
          `You'll hold ${plan.notes.length} private note${plan.notes.length === 1 ? "" : "s"}`,
        ]),
        shape,
      );

      const rows = [breakdownRow("Shielded", `${formatStsh(plan.total)} STSH`)];
      let feeWarning: HTMLElement | null = null;
      if (basis !== null) {
        try {
          let protocol = 0n;
          for (const d of plan.notes) protocol += shieldDepositPreview(d, basis.ledgerFee, basis.params).protocolFee;
          const ledger = basis.ledgerFee * BigInt(plan.notes.length + 1);
          const withFees = plan.total + protocol + ledger;
          rows.push(
            breakdownRow("Protocol fee", `${formatStsh(protocol)} STSH`),
            breakdownRow("Ledger fees (up to)", `${formatStsh(ledger)} STSH`),
            breakdownRow("From your public balance (about)", `${formatStsh(withFees)} STSH`, {
              strong: true,
            }),
          );
          // Item 5, fee tier: the amount fits but the ESTIMATED total with fees
          // may not. A warning, not a block — the fee figure is an upper
          // estimate and the ledger is the authority — but the user is told
          // before approving, because the notes deposit one at a time.
          if (!overBalance && balance !== null && withFees > balance) {
            feeWarning = el("div", { class: "warning medium", "data-testid": "shield-fee-over-balance" }, [
              "With fees this may be more than your public balance. The last note may not go through. A smaller amount is safer.",
            ]);
          }
        } catch {
          rows.push(breakdownRow("Fees", "Shown when you confirm"));
        }
      } else {
        rows.push(breakdownRow("Fees", basisState === "requested" ? "Loading…" : "Shown when you confirm"));
      }
      preview.append(breakdown(rows));
      if (feeWarning !== null) preview.append(feeWarning);

      // U-2: what this deposit PUBLISHES, said plainly, before the user
      // approves anything. Same warning shape and rendering as the spend page.
      for (const w of shieldPrivacyWarnings({
        bucketCount: plan.notes.length,
        totalDenominations: plan.buckets.length,
      })) {
        warningsBox.append(warningCallout(w));
      }
      disclosure.hidden = false;
    } catch (err) {
      // Addendum 2 item 6: never the raw base-unit figure; STSH, and what fits.
      const raw = err instanceof Error ? err.message : String(err);
      const lines = shieldAmountErrorLines(raw) ?? [raw];
      for (const line of lines) preview.append(el("p", { class: "error" }, [line]));
    }
  };

  const chips = el("div", { class: "chip-row" });
  for (const c of CHIPS) {
    const b = el("button", { type: "button", class: "chip-btn" }, [c.label]);
    b.addEventListener("click", () => {
      const cur = currentUnits() ?? 0n;
      const next = (cur / STEP) * STEP + c.units;
      input.value = (next / E8S).toString(10);
      update();
    });
    chips.append(b);
  }
  const clearBtn = el("button", { type: "button", class: "chip-btn ghost" }, ["Clear"]);
  clearBtn.addEventListener("click", () => {
    input.value = "";
    update();
  });
  chips.append(clearBtn);

  input.addEventListener("input", update);
  submit.addEventListener("click", () => {
    if (planned !== null) void ctx.shield(planned);
  });

  const busyLine = ctx.state.busy === true ? progressCard("Shielding…", ctx.state.status?.msg ?? null) : null;

  root.append(
    el("label", { class: "field" }, [el("span", { class: "field-label" }, ["Amount (STSH)"]), input]),
    chips,
    hint,
    preview,
    disclosure,
    ...(busyLine !== null ? [busyLine] : []),
    submit,
    el("p", { class: "muted" }, [
      "You'll confirm with Internet Identity. Then each note is deposited in turn. Progress shows here and in ",
      el("a", { href: "#/activity" }, ["Activity"]),
      ".",
    ]),
    details("How shielding works", [
      el("p", { class: "muted" }, [
        // L07-02 / CC-02: says only what is true — deposits of DIFFERENT
        // totals decompose to different shapes, and the approved total is a
        // publicly-readable approval while it stands.
        "Deposits use fixed denominations (1,000 / 10,000 / 100,000 / 1,000,000 / 10,000,000 " +
          "STSH): two deposits of the SAME denomination decompose to the same shape, so the " +
          "denomination alone does not distinguish them — but the depositor, timing and " +
          "commitment are still each recorded on-chain, and the amount you approve for this " +
          "deposit — and its total — is publicly readable while the " +
          "approval stands. Because 1,000 STSH is the smallest denomination, only " +
          "whole multiples of 1,000 STSH can be shielded — smaller amounts, and amounts that " +
          "are not a multiple of 1,000 STSH, cannot be deposited at all. Smaller denominations " +
          "may be opened later.",
      ]),
    ]),
  );
}

const STATUS_LABELS: Record<ShieldJournalEntryState["status"], string> = {
  planned: "Not sent yet",
  deposited: "Confirming",
  unknown: "Needs a check",
  failed: "Failed",
  accepted: "Done",
};

/** A shield journal status in plain words. */
export function shieldStatusLabel(status: ShieldJournalEntryState["status"]): string {
  return STATUS_LABELS[status];
}

/**
 * In-flight shield intents and their repair actions (rendered on Activity).
 * The actions are unchanged; only their labels are plain words.
 */
export function renderJournalPanel(ctx: AppContext): HTMLElement {
  const panel = el("div", { class: "journal", "data-testid": "shield-journal" });
  const entries = ctx.state.shieldEntries ?? [];
  const open = entries.filter((e) => e.status !== "accepted" && e.status !== "failed");
  if (entries.length === 0) return panel;

  if (open.length > 0) {
    panel.append(el("h3", {}, ["Shielding in progress"]));
    const list = el("ul");
    for (const e of open) {
      const pool = e.poolStatus !== undefined ? ` (pool: ${e.poolStatus})` : "";
      const item = el("li", { "data-status": e.status }, [
        el("span", {}, [`Shield ${formatStsh(BigInt(e.denom))} STSH`]),
        chip(STATUS_LABELS[e.status] + pool, e.status === "unknown" ? "warn" : "accent"),
      ]);
      if (e.status === "unknown") {
        // Manual resolution for a dispatched-ambiguous intent (A-S21 pattern):
        // the confirmation is explicit — the user attests to external
        // verification before the entry is archived.
        const abandon = el("button", { class: "danger small" }, ["Abandon (verified externally)"]);
        abandon.addEventListener("click", () => {
          const confirmed = window.confirm(
            "Abandon this shield intent? Only do this after verifying its real outcome " +
              "against the chain externally. The record is archived, never erased.",
          );
          void ctx.abandonAmbiguousShieldEntry({
            commitmentHex: e.commitmentHex,
            confirmedExternalReconcile: confirmed,
          });
        });
        item.append(abandon);
      }
      list.append(item);
    }
    panel.append(list);
  }

  const hasPlanned = entries.some((e) => e.status === "planned");
  const active = open.length > 0;
  const buttons: HTMLElement[] = [];
  if (active) {
    const reconcile = el("button", { class: "small" }, ["Check status"]);
    reconcile.addEventListener("click", () => {
      void ctx.reconcileShieldJournal({ resubmit: true });
    });
    buttons.push(reconcile);
  }
  if (hasPlanned) {
    const cancel = el("button", { class: "small" }, ["Cancel unsent deposits"]);
    cancel.addEventListener("click", () => {
      void ctx.cancelPlannedShield();
    });
    buttons.push(cancel);
  }
  if (!active) {
    const revoke = el("button", { class: "ghost small" }, ["Revoke leftover approval"]);
    revoke.addEventListener("click", () => {
      void ctx.revokeShieldAllowance();
    });
    buttons.push(revoke);
  }
  if (buttons.length > 0) panel.append(el("div", { class: "row" }, buttons));
  if (!active) {
    // O-6 (Owner, verbatim): what the revoke button is for, in one line.
    panel.append(
      el("p", { class: "muted", "data-testid": "revoke-explainer" }, [
        "A stopped shield left the pool allowed to take tokens from your public balance. " +
          "Cancel that permission. Your balance does not change.",
      ]),
    );
  }
  return panel;
}
