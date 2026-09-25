/**
 * Send from private balance (the `spend` route) — Campaign B / L3c §10; WL-23
 * adds WL-2a + WL-3; WALLET-UX layout; WALLET-UI Addendum 2 modes.
 *
 * Two things a user can do from one note, chosen up front:
 *
 *   - Public payout: a PUBLIC payout to any principal. The recipient gets
 *     public STSH; the II signer is public (AR-2), and with a single deposit
 *     the signed spend links deposit and payout (CTO correction 2026-09-23). The
 *     user enters the recipient's NET amount — the wallet computes the GROSS
 *     public_amount (net + live ledger fee) and shows both figures (S-24).
 *   - Re-shield: a self-spend into a fresh note. Nothing leaves the pool;
 *     still II-signed.
 *
 * `#payout-toggle` remains the one source of truth for the mode (the segmented
 * control drives it), so every rule that reads it is unchanged.
 *
 * WALLET-UX: the user no longer picks a note by leaf number. "Custom amount"
 * picks the smallest note that can pay the entered figure; "Whole note" sends
 * the most a chosen note can pay. The select stays as a visible, overridable
 * "Pay from" choice.
 *
 * WL-3: the payout is bounded by what the note can ACTUALLY exit with once the
 * exit protocol fee is funded from the note — never by the note's face value.
 * Both the preview and the submit guard compare the GROSS against that
 * maximum, and both read it from the same derivation.
 *
 * WL-2a: the rapid-roundtrip warning is wired here, from the note's local
 * origin anchor.
 */

import { Principal } from "@dfinity/principal";

import { clear, el } from "../dom";
import { formatStsh, parseStsh } from "../format";
import {
  classifyNoteOrigin,
  elapsedMs,
  privacyWarnings,
  shieldJournalAnchorNs,
} from "../privacyWarnings";
import type { AppContext } from "../context";
import { maxPublicAmount, maxRecipientNet, unshieldProtocolFee } from "../../crypto/fees";
import { spendableNotes, type ScannedNote } from "../../storage/noteCache";
import { breakdown, breakdownRow, chip, details, pageHead, progressCard, requestFeeBasis, segmented, warningCallout } from "../components";

const bytesToHex = (b: Uint8Array): string =>
  [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

type AmountMode = "custom" | "whole";

export function renderSpend(root: HTMLElement, ctx: AppContext): void {
  clear(root);
  root.append(
    ...pageHead({
      // WALLET-UI (Addendum 1 ruling 1; SSA Q2 stricter reading): the title
      // makes no identity claim, and the sub states the qualifier in BOTH
      // modes. DS-53 (disclosure sweep d6b6632b, verbatim): the linkability of
      // a single deposit is stated, not left out.
      title: "Send from private balance",
      sub: "Your Internet Identity signs every spend, publicly and permanently. One deposit means your spend is linkable.",
      back: { href: "#/account", label: "Home" },
    }),
    el("p", { class: "soon-line" }, [
      chip("Coming soon", "neutral"),
      " Private to private: sending straight into someone else's private balance.",
    ]),
  );

  const spendable = spendableNotes(ctx.state.notes);
  if (spendable.length === 0) {
    root.append(
      el("div", { class: "empty" }, [
        el("p", {}, ["No private STSH to send yet."]),
        el("p", { class: "muted" }, [
          "Shield some STSH first, or sync if you have shielded before.",
        ]),
        el("div", { class: "row" }, [
          el("button", { onclick: () => ctx.navigate("shield") }, ["Shield STSH"]),
          el("button", { class: "ghost", onclick: () => ctx.navigate("scan") }, ["Go to Scan"]),
        ]),
      ]),
    );
    return;
  }

  // WL-3: the live basis every exit figure is derived from. Loaded lazily, and
  // NOTHING is quoted until it is present — a missing basis fails closed.
  // (Throttled: a failed load re-renders this page, which must not re-ask
  // in a loop.)
  requestFeeBasis(ctx);

  // Pay-from selector (spendable only), largest first so a glance shows the
  // biggest single payment available.
  const ordered = [...spendable].sort((a, b) => (a.value < b.value ? 1 : a.value > b.value ? -1 : 0));
  const noteSelect = el("select", { class: "note-select", "aria-label": "Pay from" });
  ordered.forEach((n) => {
    noteSelect.append(
      el("option", { value: String(n.leafIndex) }, [`${formatStsh(n.value)} STSH note`]),
    );
  });

  // The mode switch's source of truth. Visually replaced by the segmented
  // control, still a real checkbox for every rule (and test) that reads it.
  const payoutToggle = el("input", {
    type: "checkbox",
    id: "payout-toggle",
    class: "sr-only",
    "aria-label": "Send to someone (public payout)",
  }) as HTMLInputElement;
  payoutToggle.checked = true;

  const destInput = el("input", {
    class: "amount",
    placeholder: "Recipient principal ID",
    "aria-label": "Recipient principal ID",
  }) as HTMLInputElement;
  const netInput = el("input", {
    class: "amount",
    inputmode: "decimal",
    placeholder: "Recipient net amount (STSH)",
    "aria-label": "Amount they receive (STSH)",
  }) as HTMLInputElement;
  const maxPreview = el("p", { class: "muted max-exit" }, []);
  const summary = el("div", { class: "spend-summary" });
  const warningsBox = el("div", { class: "warnings" });

  // WALLET-SHIELD-LAYER1 (Owner Addendum A item 7): "Whole note" is the
  // default amount mode; "Custom amount" is the option.
  let amountMode: AmountMode = "whole";
  const modeSlot = el("div", { class: "mode-slot" });
  const amountModeSlot = el("div", { class: "mode-slot" });
  const wholeChips = el("div", { class: "chip-row" });
  const sendFields = el("div", { class: "send-fields" });
  const sendHelper = el("p", { class: "mode-helper", "data-testid": "mode-helper-send" }, [
    // DS-54 (verbatim, appended): the single-deposit case.
    "Pay a public account. Recipient, amount and your account are visible on-chain. Which note paid is hidden. " +
      "If you deposited only once, the payout is linkable to that deposit.",
  ]);
  // Addendum 2 item 1: the fee figure is the LIVE protocol spend fee from
  // the governance params (law 5: no hardcoded fee), filled in renderDerived.
  const selfFeeLine = el("p", { class: "mode-helper", "data-testid": "mode-helper-self-fee" }, []);
  const selfExplainer = el("div", { class: "explainer" }, [
    el("p", { class: "mode-helper", "data-testid": "mode-helper-self" }, [
      "This note becomes a new note. Nothing leaves the pool. Nobody is paid.",
    ]),
    el("p", { class: "mode-helper" }, ["Your account signs it. The note amount is not shown."]),
    selfFeeLine,
    // The "helps separate a later send from when you shielded" claim is
    // withdrawn on the same finding as DS-55: a re-shield is II-signed like
    // every spend, so it does not unlink you (DS-55's own wording).
    el("p", { class: "muted" }, ["It does not unlink you."]),
    el("p", { class: "muted" }, [
      "It does not protect a copied account key; for that, see Settings > Security and recovery.",
    ]),
  ]);

  const selectedNote = (): ScannedNote | undefined =>
    ordered[(noteSelect as HTMLSelectElement).selectedIndex];

  const selectLeaf = (leaf: bigint) => {
    const idx = ordered.findIndex((n) => n.leafIndex === leaf);
    if (idx >= 0) (noteSelect as HTMLSelectElement).selectedIndex = idx;
  };

  /**
   * WL-2a: classify the SELECTED note's origin from local state only.
   * Journal provenance is checked first and always wins.
   */
  const originOf = (note: ScannedNote | undefined) => {
    if (note === undefined) return undefined;
    const anchor = shieldJournalAnchorNs(
      ctx.state.shieldEntries ?? [],
      note.commitment === undefined ? undefined : bytesToHex(note.commitment),
    );
    const classification = classifyNoteOrigin({
      ...(anchor !== undefined ? { journalAnchorNs: anchor } : {}),
      ...(note.firstSeenAtNs !== undefined ? { firstSeenAtNs: note.firstSeenAtNs } : {}),
      ...(note.firstSeenVia !== undefined ? { firstSeenVia: note.firstSeenVia } : {}),
      nowNs: BigInt(Date.now()) * 1_000_000n,
    });
    return { anchor, classification };
  };

  /** Custom amount: pick the smallest note that can pay the entered net. */
  const autoPick = () => {
    const basis = ctx.state.spendFeeBasis;
    if (basis === null || amountMode !== "custom") return;
    let net: bigint;
    try {
      net = parseStsh(netInput.value || "0");
    } catch {
      return;
    }
    if (net <= 0n) return;
    const fits = [...ordered]
      .reverse()
      .find((n) => {
        try {
          return maxRecipientNet(n.value, basis.ledgerFee, basis.params) >= net;
        } catch {
          return false;
        }
      });
    if (fits !== undefined) selectLeaf(fits.leafIndex);
  };

  const renderDerived = () => {
    clear(warningsBox);
    clear(summary);
    const hasPayout = payoutToggle.checked;
    destInput.disabled = !hasPayout;
    netInput.disabled = !hasPayout || amountMode === "whole";
    sendFields.hidden = !hasPayout;
    selfExplainer.hidden = hasPayout;
    spendBtn.textContent = hasPayout ? "Send" : "Re-shield";

    const note = selectedNote();
    const origin = originOf(note);
    const warnings = privacyWarnings({
      // R-7 item 1 part A: a public payout publishes a user-chosen NET figure;
      // a self-change-only spend publishes no amount at all.
      amountKind: hasPayout ? "specific-amount" : "fixed-denomination",
      publicPayout: hasPayout,
      ...(origin?.classification !== undefined ? { noteOrigin: origin.classification } : {}),
      // R-7 item 5: `msSinceDeposit` comes from the shield-journal anchor ONLY.
      ...(origin?.anchor !== undefined
        ? { msSinceDeposit: elapsedMs(origin.anchor, BigInt(Date.now()) * 1_000_000n) }
        : {}),
    });
    for (const w of warnings) {
      warningsBox.append(warningCallout(w));
    }

    const basis = ctx.state.spendFeeBasis;
    selfFeeLine.textContent =
      basis === null || basis === undefined
        ? "Fee: loading the live fee."
        : `Fee ${formatStsh(basis.params.protocolPrivateSpendFeeStsh)} STSH, taken from the note.`;
    if (note === undefined) return;
    if (basis === null) {
      maxPreview.textContent = hasPayout
        ? "Loading the live fee. The wallet will not quote a maximum until it has one."
        : "";
      return;
    }
    if (hasPayout) {
      // The gross is what the pool checks and what the proof binds; the
      // recipient sees the gross minus the live ledger fee.
      const gross = maxPublicAmount(note.value, basis.params);
      const maxNet = maxRecipientNet(note.value, basis.ledgerFee, basis.params);
      maxPreview.textContent =
        `Most this ${formatStsh(note.value)} STSH note can send: ${formatStsh(maxNet)} STSH ` +
        `to the recipient (${formatStsh(gross)} STSH leaves the pool, including the ledger fee). ` +
        `Fees are paid from the note, so its full value can never leave.`;
      if (amountMode === "whole") netInput.value = formatStsh(maxNet).replace(/,/g, "");
      let entered = 0n;
      try {
        entered = parseStsh(netInput.value || "0");
      } catch {
        entered = -1n;
      }
      const enteredGross = entered + basis.ledgerFee;
      if (entered > 0n && enteredGross <= gross) {
        const protocol = unshieldProtocolFee(enteredGross, basis.params);
        const change = note.value - enteredGross - protocol;
        summary.append(
          breakdown([
            breakdownRow("They receive", `${formatStsh(entered)} STSH`, { strong: true }),
            breakdownRow("Ledger fee", `${formatStsh(basis.ledgerFee)} STSH`),
            breakdownRow("Protocol fee", `${formatStsh(protocol)} STSH`),
            breakdownRow("Back to your private balance", `${formatStsh(change > 0n ? change : 0n)} STSH`),
            breakdownRow("Leaves the pool", `${formatStsh(enteredGross)} STSH`),
          ]),
        );
      } else if (entered !== 0n) {
        summary.append(
          el("p", { class: "error" }, [
            entered < 0n
              ? "Enter an amount in STSH, for example 250."
              : `This note can send at most ${formatStsh(maxNet)} STSH. Choose a larger note or a smaller amount.`,
          ]),
        );
      }
    } else {
      maxPreview.textContent = "";
      const fee = basis.params.protocolPrivateSpendFeeStsh;
      summary.append(
        breakdown([
          breakdownRow("Note", `${formatStsh(note.value)} STSH`),
          breakdownRow("Protocol fee", `${formatStsh(fee)} STSH`),
          breakdownRow("New private note", `${formatStsh(note.value > fee ? note.value - fee : 0n)} STSH`, {
            strong: true,
          }),
        ]),
      );
    }
  };

  const spendBtn = el("button", { class: "primary wide", disabled: ctx.state.busy }, ["Send"]) as HTMLButtonElement;

  const paintModes = () => {
    clear(modeSlot);
    modeSlot.append(
      segmented(
        [
          { value: "self", label: "Re-shield" },
          { value: "send", label: "Public payout" },
        ],
        payoutToggle.checked ? "send" : "self",
        (v) => {
          payoutToggle.checked = v === "send";
          payoutToggle.dispatchEvent(new Event("change"));
        },
        "What to do",
      ),
    );
    clear(amountModeSlot);
    amountModeSlot.append(
      segmented(
        [
          { value: "whole", label: "Whole note" },
          { value: "custom", label: "Custom amount" },
        ],
        amountMode,
        (v) => {
          amountMode = v;
          if (v === "custom") netInput.value = "";
          paintModes();
          renderDerived();
        },
        "Amount",
      ),
    );
    clear(wholeChips);
    wholeChips.hidden = amountMode !== "whole";
    const seen = new Set<string>();
    for (const n of ordered) {
      const key = n.value.toString();
      if (seen.has(key)) continue;
      seen.add(key);
      const b = el("button", { type: "button", class: "chip-btn" }, [`${formatStsh(n.value)} note`]);
      b.addEventListener("click", () => {
        selectLeaf(n.leafIndex);
        renderDerived();
      });
      wholeChips.append(b);
    }
  };

  payoutToggle.addEventListener("change", () => {
    paintModes();
    renderDerived();
  });
  netInput.addEventListener("input", () => {
    autoPick();
    renderDerived();
  });
  noteSelect.addEventListener("change", renderDerived);

  spendBtn.addEventListener("click", () => {
    const selected = selectedNote();
    if (selected === undefined) return;
    const hasPayout = payoutToggle.checked;
    let payout;
    if (hasPayout) {
      const basis = ctx.state.spendFeeBasis;
      if (basis === null) {
        ctx.state.status = {
          kind: "error",
          msg: "The live exit fee is not known yet — refusing to submit a payout it cannot price.",
        };
        ctx.refresh();
        return;
      }
      let destination: Principal;
      try {
        destination = Principal.fromText(destInput.value.trim());
      } catch {
        ctx.state.status = { kind: "error", msg: "Recipient principal is invalid." };
        ctx.refresh();
        return;
      }
      const net = parseStsh(netInput.value || "0");
      // WL-3: the bound is on the GROSS against the derived maximum — never
      // the recipient net against it, and never the note's face value.
      const gross = net + basis.ledgerFee;
      const max = maxPublicAmount(selected.value, basis.params);
      if (net <= 0n || gross > max) {
        ctx.state.status = {
          kind: "error",
          msg:
            `Net payout must be positive and at most ` +
            `${formatStsh(maxRecipientNet(selected.value, basis.ledgerFee, basis.params))} STSH ` +
            `for this note — the exit protocol fee and the ledger fee are funded from it, so the ` +
            `full ${formatStsh(selected.value)} STSH cannot leave.`,
        };
        ctx.refresh();
        return;
      }
      payout = { destination, subaccount: null, recipientNet: net };
    }
    void ctx.spend({
      inputLeafIndex: selected.leafIndex,
      ...(payout !== undefined ? { payout } : {}),
    });
  });

  // WL-2c: the delay belongs next to the action it delays.
  const delayBox = el("input", { type: "checkbox", id: "spend-delay-toggle" }) as HTMLInputElement;
  delayBox.checked = ctx.state.submissionDelayEnabled === true;
  delayBox.addEventListener("change", () => {
    if (typeof ctx.setSubmissionDelayEnabled === "function") ctx.setSubmissionDelayEnabled(delayBox.checked);
  });

  sendFields.append(
    sendHelper,
    el("label", { class: "field" }, [el("span", { class: "field-label" }, ["To"]), destInput]),
    amountModeSlot,
    wholeChips,
    el("label", { class: "field" }, [el("span", { class: "field-label" }, ["Amount they receive"]), netInput]),
  );

  paintModes();

  // Addendum 2 item 5: say what is happening and how long it takes, not a
  // bare greyed button. The stage comes from existing state only: before the
  // dispatch boundary the work is local and cancellable; after it, the spend
  // is submitted. (Durations are the wallet's expectation, not a guarantee.)
  const busy = ctx.state.busy === true ? spendProgress(ctx) : null;

  root.append(
    payoutToggle,
    modeSlot,
    sendFields,
    selfExplainer,
    el("label", { class: "field" }, [el("span", { class: "field-label" }, ["Pay from"]), noteSelect]),
    maxPreview,
    summary,
    warningsBox,
    el("label", { class: "radio" }, [delayBox, " Add a random delay (up to 2 minutes) before sending"]),
    // Addendum 2 item 2: the action stays on screen (sticky to the bottom of
    // the viewport) however long the warnings above it are; the warnings stay
    // where they are, before it in reading order.
    el("div", { class: "sticky-actions", "data-testid": "spend-actions" }, [
      ...(busy !== null ? [busy] : []),
      spendBtn,
    ]),
    el("p", { class: "muted" }, [
      "The proof is generated on this device against an accepted pool root. Your note is locked " +
        "and saved before anything is sent, so an interrupted send can be recovered.",
    ]),
  );
  renderDerived();
}

/**
 * Addendum 2 item 5: the in-flight spend, as stages with expected durations.
 * Reads only `busy`, `spendLocallyCancellable`, `submissionDelayEnabled` and
 * the status line — no new state, no spendFlow change.
 */
export const SPEND_STAGES = {
  prove: "1. Build the proof on this device. About 1 to 2 minutes.",
  delay: "Random delay before sending. Up to 2 minutes.",
  submit: "2. Send and confirm. Usually under a minute.",
} as const;

function spendProgress(ctx: AppContext): HTMLElement {
  const local = ctx.state.spendLocallyCancellable === true;
  const stage = (text: string, state: "now" | "next" | "done") =>
    el("li", { class: `stage stage-${state}`, "data-stage-state": state }, [text]);
  const stages = el("ol", { class: "stages", "data-testid": "spend-stages" }, [
    stage(SPEND_STAGES.prove, local ? "now" : "done"),
    ...(ctx.state.submissionDelayEnabled === true ? [stage(SPEND_STAGES.delay, local ? "next" : "done")] : []),
    stage(SPEND_STAGES.submit, local ? "next" : "now"),
  ]);
  return progressCard(
    local ? "Building proof…" : "Sending…",
    ctx.state.status?.msg ?? (local ? "Keep this page open." : null),
    [
      stages,
      ...(local
        ? [el("button", { class: "small", onclick: () => ctx.cancelSessionTasks?.() }, ["Cancel local work"])]
        : []),
    ],
  );
}
