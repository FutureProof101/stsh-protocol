/**
 * Home (the `account` route) — WALLET-UX.
 *
 * Answers two questions at a glance: what do I have (private balance first,
 * public balance second) and what can I do (Shield, Send privately). The
 * public transfer flow (Lane A2, brief §3) lives here unchanged, folded under
 * "Send public STSH"; an unresolved transfer is lifted to the top instead.
 *
 * One-slot honesty: while an unresolved intent exists for this account there
 * is NO new-transfer form — the user resolves (retry / reconcile) first. A
 * frozen (`TooOld`-ambiguous) intent explains itself and requires an explicit
 * post-reconcile confirmation before it can be abandoned (archived, not
 * erased).
 *
 * The device wipe (A-1b) and the key-compromise disclosure (R-7 CC-01, R-8
 * AC-9) moved to Settings > Security and recovery; `renderSecuritySections`
 * is exported for that page and renders them unchanged.
 *
 * WALLET-V13 O-1 (Owner W13-1; Addendum 1 E-2): signed out, Home shows ONLY
 * the Account card (log-in button) and "About STSH". The DS-51/DS-52 copy
 * moved, verbatim, into About STSH (`renderAboutStsh`, shared with Settings).
 */

import { clear, el } from "../dom";
import { formatStsh } from "../tokenFormat";
import type { AppContext } from "../context";
import { DEVICE_STORAGE_UNAVAILABLE, TRANSFER_SERVICES_UNCONFIGURED } from "../context";
import type { TransferIntentRecord } from "../../storage/transferJournal";
import { spendableNotes } from "../../storage/noteCache";
import { chip, copyButton, details } from "../components";
import {
  COMPROMISE_MIGRATION_HEADING,
  COMPROMISE_MIGRATION_STEPS,
  COMPROMISE_NO_IN_PRODUCT_CUTOFF,
  COMPROMISE_SELF_SPEND_IS_NOT_A_REMEDY,
  LAST_DEVICE_REVOCATION_IS_FINAL,
} from "../recoveryCopy";

export function renderAccount(root: HTMLElement, ctx: AppContext): void {
  clear(root);

  if (ctx.policy.kind === "blocked") {
    root.append(
      el("h2", {}, ["STSH Wallet"]),
      el("p", { class: "status-msg error", "data-testid": "origin-blocked" }, [ctx.policy.reason]),
    );
  }

  if (ctx.state.principal === null) {
    renderWelcome(root, ctx);
    return;
  }

  // Anything that needs the user before anything else does.
  const intent = ctx.pendingIntent;
  if (intent !== null) {
    const box = el("section", { class: "attention" });
    if (intent.state === "frozen") renderFrozenIntent(box, ctx, intent);
    else renderUnresolvedIntent(box, ctx, intent);
    root.append(box);
  }
  const needsCheck = attentionCount(ctx);
  if (needsCheck > 0) {
    root.append(
      el("a", { class: "attention-link", href: "#/activity" }, [
        `${needsCheck} item${needsCheck === 1 ? "" : "s"} in Activity need${needsCheck === 1 ? "s" : ""} your attention →`,
      ]),
    );
  }

  root.append(renderBalances(ctx));

  root.append(
    el("div", { class: "actions" }, [
      el("button", { class: "primary", "data-testid": "home-shield", onclick: () => ctx.navigate("shield") }, [
        "Shield",
      ]),
      el("button", { "data-testid": "home-send-private", onclick: () => ctx.navigate("spend") }, [
        "Send",
      ]),
    ]),
  );

  // Your address — what someone needs to send you public STSH.
  const principalText = ctx.state.principal.toText();
  root.append(
    el("section", { class: "address" }, [
      el("div", { class: "section-label" }, ["Your address"]),
      el("div", { class: "address-row" }, [
        el("p", { class: "principal", "data-testid": "principal" }, [principalText]),
        copyButton(principalText),
      ]),
      // O-6 (Owner, verbatim): no private receive address exists at launch (T2).
      el("p", { class: "muted", "data-testid": "address-copy" }, [
        "Share it to receive public STSH. Private receiving: later release.",
      ]),
    ]),
  );

  if (intent === null) {
    const form = el("div", { class: "fold-stack" });
    renderTransferForm(form, ctx);
    root.append(details("Send public STSH", [form], { testid: "public-send" }));
  }

  root.append(
    el("div", { class: "soon-row" }, [
      el("span", {}, ["Staking"]),
      chip("Coming soon", "neutral"),
    ]),
  );
}

/** Signed-out Home: the Account card (one way in) and About STSH — nothing else (WALLET-V13 O-1). */
function renderWelcome(root: HTMLElement, ctx: AppContext): void {
  root.append(
    el("div", { class: "welcome", "data-testid": "home-account" }, [
      el("h2", {}, ["Your private STSH wallet"]),
      el("div", { class: "row" }, [
        el(
          "button",
          {
            class: "primary",
            "data-testid": "login",
            disabled: ctx.policy.kind === "blocked" || ctx.state.busy,
            onclick: () => void ctx.login(),
          },
          ["Log in with Internet Identity"],
        ),
      ]),
    ]),
    renderAboutStsh(),
  );
}

/**
 * "About STSH" — its own card on signed-out Home and on Settings (signed in or
 * out). WALLET-V13 (Addendum 1 E-2): it carries the DS-51/DS-52 disclosure copy
 * that used to sit on signed-out Home — moved verbatim, not reworded — and the
 * stsh.fi link that used to sit under Settings > More.
 */
export function renderAboutStsh(): HTMLElement {
  return el("section", { class: "settings-section about-stsh", "data-testid": "about-stsh" }, [
    el("h3", {}, ["About STSH"]),
    // DS-51 (disclosure sweep d6b6632b, verbatim): the old "which note pays
    // stays private" clause overclaimed for a single-deposit user.
    el("p", { class: "page-sub" }, ["Shield STSH into a private balance, then pay anyone with public STSH."]),
    el("p", { class: "page-sub", "data-testid": "welcome-linkability" }, [
      "Your Internet Identity signs every send, permanently. With one deposit, your deposit and send are linkable.",
    ]),
    el("ul", { class: "points" }, [
      el("li", {}, ["Sign in with Internet Identity: a passkey on this device, no seed phrase."]),
      el("li", {}, ["Your private balance is rebuilt from the chain on any device you sign in on."]),
      // DS-52 (verbatim): "Which note paid stays private." -> the qualified form.
      el("li", {}, [
        "Payments you send arrive as public STSH, signed by your Internet Identity and " +
          "recorded permanently. Which of your own notes paid stays private.",
      ]),
    ]),
    el("a", { class: "link-row", href: "https://stsh.fi", target: "_blank", rel: "noopener" }, [
      el("span", {}, ["stsh.fi"]),
      el("span", { class: "link-row-arrow", "aria-hidden": "true" }, ["↗"]),
    ]),
  ]);
}

/** The two balances, private first. */
function renderBalances(ctx: AppContext): HTMLElement {
  const s = ctx.state;
  const priv = el("div", { class: "bal bal-private" });
  const head = el("div", { class: "bal-head" }, [el("span", { class: "bal-label" }, ["Private balance"])]);
  if (!s.cacheUnlocked) {
    // WALLET-CACHE-II-ONLY: sign-in opens the private balance. What shows here
    // while it is not open depends on WHY — and "Locked" is only ever true
    // when this device's opt-in passcode is on.
    const gate = s.cacheGate ?? "none";
    if (gate === "passcode") {
      head.append(chip("Locked", "neutral"));
      priv.append(
        head,
        el("p", { class: "bal-value is-muted" }, ["Locked"]),
        el("div", { class: "row" }, [
          el("button", { class: "small", "data-testid": "home-unlock", onclick: () => ctx.navigate("balance") }, [
            "Unlock",
          ]),
        ]),
      );
    } else if (gate === "migrate") {
      head.append(chip("One step", "accent"));
      priv.append(
        head,
        el("p", { class: "muted" }, ["Enter your old passphrase once."]),
        el("div", { class: "row" }, [
          el("button", { class: "small", "data-testid": "home-unlock", onclick: () => ctx.navigate("balance") }, [
            "Continue",
          ]),
        ]),
      );
    } else if (gate === "opening") {
      head.append(chip("Opening", "neutral"));
      priv.append(head, el("p", { class: "bal-value is-muted" }, ["…"]));
    } else if (gate === "error") {
      priv.append(
        head,
        el("p", { class: "muted" }, ["Couldn't open your private balance."]),
        el("div", { class: "row" }, [
          el(
            "button",
            { class: "small", "data-testid": "home-retry-open", disabled: s.busy, onclick: () => void ctx.retryPrivateOpen?.() },
            ["Try again"],
          ),
        ]),
      );
    } else {
      head.append(chip("Getting ready", "neutral"));
      priv.append(
        head,
        el("p", { class: "muted", "data-testid": "home-preparing" }, [
          "Your wallet is getting ready. First shield or sync opens it.",
        ]),
        el("div", { class: "row" }, [
          el("button", { class: "small", "data-testid": "home-sync", disabled: s.busy, onclick: () => void ctx.scan() }, [
            "Sync",
          ]),
        ]),
      );
    }
  } else {
    const spendable = spendableNotes(s.notes);
    const total = spendable.reduce((sum, n) => sum + n.value, 0n);
    if (s.scanning) {
      const p = s.scanProgress;
      head.append(chip(p !== null ? `Syncing · ${p.found} found` : "Syncing", "accent"));
    } else if (s.lastScanOk === true) {
      head.append(chip("Up to date", "good"));
    } else {
      // O-6 (Owner): "Not confirmed" read as an error. It only means no sync has
      // finished this session — so say that, neutrally, and offer the fix here.
      head.append(chip("Not synced", "neutral"));
    }
    priv.append(
      head,
      el("p", { class: "bal-value" }, [`${formatStsh(total)} STSH`]),
      el("a", { class: "bal-link", href: "#/balance" }, [
        `${spendable.length} private note${spendable.length === 1 ? "" : "s"} →`,
      ]),
      ...(s.scanning || s.lastScanOk === true
        ? []
        : [
            el("div", { class: "row" }, [
              el(
                "button",
                { class: "small", "data-testid": "home-sync", disabled: s.busy, onclick: () => void ctx.scan() },
                ["Sync"],
              ),
            ]),
          ]),
    );
  }

  const pub = el("div", { class: "bal bal-public" }, [
    el("div", { class: "bal-head" }, [el("span", { class: "bal-label" }, ["Public balance"])]),
    el("p", { class: "total", "data-testid": "balance" }, [
      s.balance === null ? "—" : `${formatStsh(s.balance)} STSH`,
    ]),
    el("div", { class: "row" }, [
      el(
        "button",
        {
          class: "ghost small",
          "data-testid": "refresh-balance",
          disabled: s.busy,
          onclick: () => void ctx.refreshBalance(),
        },
        ["Refresh"],
      ),
    ]),
  ]);

  return el("section", { class: "balances" }, [priv, pub]);
}

/** Shield/spend journal entries that are waiting on the user. */
export function attentionCount(ctx: AppContext): number {
  const shield = (ctx.state.shieldEntries ?? []).filter((e) => e.status === "unknown" || e.status === "planned").length;
  const spend = (ctx.state.spendEntries ?? []).filter(
    (e) => e.status === "payout-pending" || e.status === "recovery-required",
  ).length;
  return shield + spend;
}

/** The exact phrase the user must type before the wipe button enables. */
export const WIPE_CONFIRM_PHRASE = "WIPE";

/**
 * Settings > Security and recovery: the device wipe and the key-compromise
 * disclosure. WALLET-V13 (Addendum 1 E-1, revised): signed in only — a lost or
 * seized device is handled by revoking it from another enrolled device. The
 * wipe RESULT is rendered by `renderWipeResult`, outside this gate.
 */
export function renderSecuritySections(root: HTMLElement, ctx: AppContext): void {
  renderDangerZone(root, ctx);
  renderKeyCompromiseDisclosure(root);
}

/**
 * CC-01 (R-7 item 2) — the key-compromise disclosure must be REACHABLE.
 *
 * Scope, deliberately: this is STATIC advisory text, not a revoke ceremony.
 * Every one of these strings is true today with no device enumeration and no
 * canister call — they say what the user must do themselves, and that the
 * product cannot do it for them.
 */
function renderKeyCompromiseDisclosure(root: HTMLElement): void {
  root.append(
    el("h3", { class: "danger-zone", "data-testid": "compromise-heading" }, [
      COMPROMISE_MIGRATION_HEADING,
    ]),
    el(
      "ol",
      { "data-testid": "compromise-steps" },
      COMPROMISE_MIGRATION_STEPS.map((step) => el("li", {}, [step])),
    ),
    el("p", { class: "muted", "data-testid": "compromise-self-spend" }, [
      COMPROMISE_SELF_SPEND_IS_NOT_A_REMEDY,
    ]),
    // O-7: a permanence disclosure is advisory (copper), not a failed action.
    el("p", { class: "status-msg advisory", "data-testid": "compromise-no-cutoff" }, [
      COMPROMISE_NO_IN_PRODUCT_CUTOFF,
    ]),
    // R-8 AC-9 / AMBER-4: permanence of revoking the last device.
    el("p", { class: "status-msg advisory", "data-testid": "last-device-final" }, [
      LAST_DEVICE_REVOCATION_IS_FINAL,
    ]),
  );
}

/**
 * Panic wipe (A-1b / R14-2). Two deliberate steps, never one click: the entry
 * button only REVEALS the consequences, and the wipe itself is gated on the
 * user typing the confirmation phrase. `window.confirm` is deliberately not
 * used — it cannot carry this much copy, cannot be styled, and cannot be
 * driven by a test.
 */
function renderDangerZone(root: HTMLElement, ctx: AppContext): void {
  root.append(el("h3", { class: "danger-zone" }, ["Wipe this device"]));

  const panel = el("div", { class: "wipe-panel", "data-testid": "panic-wipe-panel", hidden: true });

  const phrase = el("input", {
    type: "text",
    placeholder: WIPE_CONFIRM_PHRASE,
    "aria-label": `Type ${WIPE_CONFIRM_PHRASE} to enable the button`,
    "data-testid": "panic-wipe-phrase",
  }) as HTMLInputElement;

  const confirmBtn = el(
    "button",
    {
      class: "danger",
      "data-testid": "panic-wipe-confirm",
      disabled: true,
      onclick: () => void ctx.panicWipe(),
    },
    ["Wipe all local data now"],
  ) as HTMLButtonElement;

  phrase.addEventListener("input", () => {
    confirmBtn.disabled = phrase.value !== WIPE_CONFIRM_PHRASE || ctx.state.busy;
  });

  panel.append(
    el("p", { class: "status-msg advisory", "data-testid": "wipe-explainer" }, [
      "This erases everything this wallet stores on THIS device. It sends no message and " +
        "changes nothing on chain.",
    ]),
    el("p", {}, ["Recoverable — Internet Identity login plus a rescan restores all of it:"]),
    el("ul", { "data-testid": "wipe-recoverable" }, [
      el("li", {}, ["Your whole note set: value, spent/unspent state, spendability."]),
      el("li", {}, ["Commitments and nullifiers, and therefore your balance."]),
    ]),
    el("p", {}, ["Destroyed, and NOT recoverable anywhere:"]),
    el("ul", { "data-testid": "wipe-destroyed" }, [
      el("li", {}, ["Shield and spend intent records (request payloads, intent fingerprints)."]),
      el("li", {}, ["Output material: output nonces, encrypted outputs, output leaves."]),
      el("li", {}, ["Public-payout provenance: destination, subaccount, amounts."]),
      el("li", {}, ["Fee history and timing/outcome history, including failure reasons."]),
    ]),
    el("p", { class: "muted", "data-testid": "wipe-liveness-caveat" }, [
      "A send in progress when you wipe cannot be completed here until it settles on chain. ",
      "Your balance stays right. That amount is locked until then.",
    ]),
    el("p", {}, [`Type ${WIPE_CONFIRM_PHRASE} to enable the button:`]),
    el("div", { class: "row" }, [phrase]),
    el("div", { class: "row" }, [confirmBtn]),
  );

  root.append(
    el("p", { class: "muted" }, [
      "Erases all local wallet data on this device — for a lost, seized or handed-on machine.",
    ]),
    el("div", { class: "row" }, [
      el(
        "button",
        {
          "data-testid": "panic-wipe-open",
          disabled: ctx.state.busy,
          onclick: () => {
            panel.removeAttribute("hidden");
          },
        },
        ["Wipe local data on this device…"],
      ),
    ]),
    panel,
  );
}

/**
 * The wipe result (A-1b) — hoisted out of `renderDangerZone` by WALLET-V13
 * (SSA pre-review addendum, F-1). `panicWipe` logs the user out (principal =
 * null) and THEN sets `state.wipeReport`, which session teardown deliberately
 * never clears. So the result is keyed on the report, not on the session:
 * Settings renders it signed in or out, and an INCOMPLETE wipe's per-surface
 * NOT CLEARED list is never hidden by the login gate. Content unchanged.
 */
export function renderWipeResult(ctx: AppContext): HTMLElement | null {
  const report = ctx.state.wipeReport;
  if (report === null || report === undefined) return null;
  return el("section", { class: "settings-section security", "data-testid": "settings-wipe-result" }, [
    el("h3", {}, ["Wipe result"]),
    el(
      "p",
      {
        class: report.complete ? "status-msg success" : "status-msg error",
        "data-testid": "wipe-outcome",
      },
      [
        report.complete
          ? "Every local surface was cleared and re-checked after deletion."
          : "The wipe did NOT complete. The surfaces below marked NOT CLEARED still hold data.",
      ],
    ),
    el(
      "ul",
      { "data-testid": "wipe-report" },
      report.surfaces.map((s) =>
        el("li", { "data-testid": `wipe-surface-${s.surface}` }, [
          `${s.surface}: ${s.cleared ? "cleared" : "NOT CLEARED"} — ${s.detail}`,
        ]),
      ),
    ),
  ]);
}

function intentSummary(intent: TransferIntentRecord): HTMLElement {
  return el("ul", { class: "intent-summary" }, [
    el("li", {}, [`To: ${intent.toOwner}`]),
    el("li", {}, [`Amount: ${formatStsh(BigInt(intent.amount))} STSH`]),
    el("li", {}, [`Fee: ${formatStsh(BigInt(intent.fee))} STSH`]),
    el("li", {}, [`Created: ${new Date(intent.createdAtMs).toISOString()}`]),
    el("li", {}, [`Wire attempts: ${intent.attempts}`]),
  ]);
}

function renderUnresolvedIntent(
  root: HTMLElement,
  ctx: AppContext,
  intent: TransferIntentRecord,
): void {
  root.append(
    el("h3", {}, ["Unresolved transfer"]),
    el("p", { class: "muted", "data-testid": "pending-intent" }, [
      "This transfer has no confirmed result yet. ",
      "Retry is safe. It can't charge you twice. ",
      "New transfers wait until this one is settled.",
    ]),
    intentSummary(intent),
    el("div", { class: "row" }, [
      el(
        "button",
        {
          class: "primary",
          "data-testid": "retry-intent",
          disabled: ctx.state.busy,
          onclick: () => void ctx.retryPendingIntent(),
        },
        ["Retry transfer"],
      ),
    ]),
  );
}

function renderFrozenIntent(
  root: HTMLElement,
  ctx: AppContext,
  intent: TransferIntentRecord,
): void {
  const confirmBox = el("input", { type: "checkbox", "data-testid": "abandon-confirm" });
  const abandonBtn = el(
    "button",
    {
      "data-testid": "abandon-intent",
      disabled: true,
      onclick: () =>
        void ctx.abandonFrozenIntent({
          confirmedExternalReconcile: (confirmBox as HTMLInputElement).checked,
        }),
    },
    ["Abandon frozen transfer"],
  );
  confirmBox.addEventListener("change", () => {
    (abandonBtn as HTMLButtonElement).disabled = !(confirmBox as HTMLInputElement).checked;
  });

  root.append(
    el("h3", {}, ["Transfer needs a manual check"]),
    el("p", { class: "status-msg advisory", "data-testid": "frozen-intent" }, [
      "The ledger can no longer say if this transfer went through. ",
      "The wallet will not drop it or send it again. ",
      "Check your balance from a block explorer or another device. ",
      "This record is saved on this device only.",
    ]),
    intentSummary(intent),
    el("label", { class: "row" }, [
      confirmBox,
      " I checked the ledger myself. Archive this transfer (the record is kept).",
    ]),
    el("div", { class: "row" }, [abandonBtn]),
  );
}

function renderTransferForm(root: HTMLElement, ctx: AppContext): void {
  // J-17e / SSA F-6: a logged-in session whose mutation actors or transfer
  // journal could not be built is reachable now. Rendering the Send form
  // anyway gives the user an enabled button that refuses on click — so the
  // form is REPLACED by the refusal, and no recipient/amount input is offered
  // for a transfer that cannot be attempted.
  if (ctx.mutationActors === null) {
    root.append(
      el("p", { class: "muted", "data-testid": "transfer-unavailable" }, [
        TRANSFER_SERVICES_UNCONFIGURED,
      ]),
    );
    return;
  }
  if (ctx.journalAvailable === false) {
    root.append(
      el("p", { class: "muted", "data-testid": "transfer-unavailable" }, [
        DEVICE_STORAGE_UNAVAILABLE,
      ]),
    );
    return;
  }
  const toInput = el("input", {
    type: "text",
    placeholder: "Recipient principal",
    "aria-label": "Recipient principal",
    "data-testid": "to-input",
  }) as HTMLInputElement;
  const amountInput = el("input", {
    type: "text",
    inputmode: "decimal",
    placeholder: "Amount (STSH)",
    "aria-label": "Amount (STSH)",
    "data-testid": "amount-input",
  }) as HTMLInputElement;

  root.append(
    el("p", { class: "muted" }, [
      "Sends from your public balance. Both sides of this transfer are public.",
    ]),
    el("div", { class: "row" }, [toInput]),
    el("div", { class: "row" }, [amountInput]),
    el("p", { class: "muted" }, ["The ledger fee is checked when you send."]),
    el("p", { class: "muted" }, ["Saved on this device first, so a retry can't charge you twice."]),
    el("div", { class: "row" }, [
      el(
        "button",
        {
          class: "primary",
          "data-testid": "send",
          disabled: ctx.state.busy,
          onclick: () =>
            void ctx.transfer({ toText: toInput.value, amountText: amountInput.value }),
        },
        ["Send"],
      ),
    ]),
  );
}
