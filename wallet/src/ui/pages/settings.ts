/**
 * Settings — WALLET-UX.
 *
 * Everything a user needs occasionally, in one place: account, Extra security
 * (the opt-in passcode, WALLET-CACHE-II-ONLY, and — WALLET-V12 O-4 / Owner
 * O-8 — "Approve new devices"), the submission-delay default, sync and verification,
 * vesting, and Security and recovery (the device wipe A-1b and the
 * key-compromise disclosure R-7 CC-01 / R-8 AC-9, moved here from the account
 * page and rendered unchanged).
 *
 * WALLET-V13 O-1 (Owner W13-1; Addendum 1 E-1 revised, E-2): logged OUT, this
 * page shows ONLY the Account card (log-in button) and "About STSH". Every
 * other section — Extra security, Privacy, How it works, More, Security and
 * recovery — renders only when `state.principal !== null`. The one exception
 * is not a section: the wipe RESULT (`state.wipeReport`) is the tail of an
 * action the user started while logged in (the wipe logs them out mid-flow),
 * so it is keyed on the report, not on the session.
 *
 * The Admin section renders only for a principal the Vault reports in its
 * signer set (`state.isAdmin`, fail-closed). It is presentation only: the
 * operator surface and the Vault enforce their own authority regardless.
 */

import { clear, el } from "../dom";
import type { AppContext } from "../context";
import { renderAboutStsh, renderSecuritySections, renderWipeResult } from "./account";
import { renderVerifiedSweep } from "./scan";
import { chip, copyButton, details, pageHead, shortPrincipal } from "../components";
import {
  DEVICE_APPROVAL_NO_HANDOFF_LINE,
  DEVICE_APPROVAL_NOT_THIS_DEVICE_LINE,
  DEVICE_APPROVAL_OFF_LINE,
  DEVICE_APPROVAL_ON_LINE,
  DEVICE_APPROVAL_TOGGLE_LABEL,
  DEVICE_APPROVAL_UNAVAILABLE_LINE,
  DEVICE_APPROVAL_ZERO_DEVICES_LINE,
  deviceApprovalPendingLine,
} from "../deviceApprovalCopy";

function section(title: string, children: Array<Node | string>, opts: { testid?: string; className?: string } = {}): HTMLElement {
  const attrs: Record<string, string> = { class: `settings-section ${opts.className ?? ""}`.trim() };
  if (opts.testid !== undefined) attrs["data-testid"] = opts.testid;
  return el("section", attrs, [el("h3", {}, [title]), ...children]);
}

function linkRow(label: string, href: string, note?: string): HTMLElement {
  return el("a", { class: "link-row", href }, [
    el("span", {}, [label]),
    ...(note !== undefined ? [el("span", { class: "muted" }, [note])] : []),
    el("span", { class: "link-row-arrow", "aria-hidden": "true" }, ["→"]),
  ]);
}

/**
 * The passcode section (WALLET-CACHE-II-ONLY O-3, Addendum 1).
 *
 * The wallet opens with the Internet Identity the user signed in with; a
 * passcode is an opt-in second factor for THIS device (D-1b v2 §2). The tick
 * box shows the REAL setting — read from this device's key envelope — once the
 * app knows it (`ctx.passcode`); until then it is disabled and unticked, and
 * the line under it says why. It is never a control that does nothing.
 */
function renderPasscodeSection(ctx: AppContext): HTMLElement {
  const pc = ctx.passcode;
  const open = ctx.state.cacheUnlocked === true;
  const box = el("input", {
    type: "checkbox",
    id: "passcode-toggle",
    "data-testid": "passcode-toggle",
  }) as HTMLInputElement;
  box.checked = pc?.enabled ?? false;
  box.disabled = pc === undefined || !open || ctx.state.busy === true;

  const err = el("p", { class: "error" }, []);
  const onForm = el("div", { class: "fold-stack", hidden: true, "data-testid": "passcode-on-form" });
  const p1 = el("input", {
    type: "password",
    autocomplete: "new-password",
    placeholder: "New passcode",
    "aria-label": "New passcode",
    "data-testid": "passcode-new",
  }) as HTMLInputElement;
  const p2 = el("input", {
    type: "password",
    autocomplete: "new-password",
    placeholder: "Repeat passcode",
    "aria-label": "Repeat passcode",
    "data-testid": "passcode-repeat",
  }) as HTMLInputElement;
  const turnOn = el("button", { class: "primary", type: "button", "data-testid": "passcode-enable" }, [
    "Turn on passcode",
  ]);
  turnOn.addEventListener("click", () => {
    if (p1.value.length < 8) {
      err.textContent = "Use at least 8 characters.";
      return;
    }
    if (p1.value !== p2.value) {
      err.textContent = "The two passcodes do not match.";
      return;
    }
    err.textContent = "";
    if (pc !== undefined) void pc.enable(p1.value);
  });
  onForm.append(p1, p2, el("div", { class: "row" }, [turnOn]));

  const offForm = el("div", { class: "fold-stack", hidden: true, "data-testid": "passcode-off-form" });
  const cur = el("input", {
    type: "password",
    autocomplete: "current-password",
    placeholder: "Current passcode",
    "aria-label": "Current passcode",
    "data-testid": "passcode-current",
  }) as HTMLInputElement;
  const turnOff = el("button", { type: "button", "data-testid": "passcode-disable" }, ["Turn off passcode"]);
  turnOff.addEventListener("click", () => {
    if (pc !== undefined) void pc.disable(cur.value);
  });
  offForm.append(cur, el("div", { class: "row" }, [turnOff]));

  box.addEventListener("change", () => {
    if (pc === undefined) return;
    onForm.hidden = !(box.checked && !pc.enabled);
    offForm.hidden = !(!box.checked && pc.enabled);
    if (!onForm.hidden) p1.focus();
    if (!offForm.hidden) cur.focus();
  });

  return el("div", { class: "settings-block", "data-testid": "settings-passcode" }, [
      el("h4", {}, ["Passcode"]),
      el("p", {}, ["Signing in opens your wallet."]),
      el("p", {}, ["For extra safety, add a passcode on this device."]),
      el("label", { class: "radio" }, [box, " Require a passcode to open notes on this device"]),
      onForm,
      offForm,
      err,
      el("p", { class: "muted", "data-testid": "passcode-state" }, [
        pc === undefined
          ? "Open your private balance to change this."
          : pc.enabled
            ? "On. You'll enter it each time you sign in here."
            : "Off.",
      ]),
      details("More", [
        el("p", { class: "muted" }, [
          "Forgot it? Wipe this device below and sign in again. Your private balance comes back " +
            "from the chain. This device's activity history does not.",
        ]),
      ]),
  ]);
}

/**
 * WALLET-V12 O-4 — "Approve new devices" (Owner O-8; SSA F-3; CTO Addendum 1
 * E-3). The tick box shows the canister's REAL setting once read; until then it
 * is disabled with the reason. Default OFF (canister: no row = off).
 *
 *   ON  — device-signed from THIS active device; never from zero devices.
 *   OFF — from this active device: device-signed and IMMEDIATE. Without one:
 *         the II-only request, which takes effect 24 h later ("Turns off at…").
 *
 * No device-to-device handoff ships in this release (E-3 option ii).
 */
function renderDeviceApprovalBlock(ctx: AppContext): HTMLElement {
  const control = ctx.deviceApprovalControl;
  const da = ctx.state.deviceApproval;
  if (control !== undefined && da === undefined) void control.load();

  const box = el("input", {
    type: "checkbox",
    id: "device-approval-toggle",
    "data-testid": "device-approval-toggle",
  }) as HTMLInputElement;
  const lines: string[] = [];
  let enabled = false;
  if (control === undefined || da === undefined || da === null) {
    box.checked = false;
    lines.push(DEVICE_APPROVAL_UNAVAILABLE_LINE);
  } else if (da.activeDevices === 0) {
    // S5: the canister refuses to set the flag with zero active devices.
    box.checked = da.state.kind !== "off";
    lines.push(DEVICE_APPROVAL_ZERO_DEVICES_LINE);
  } else {
    box.checked = da.state.kind !== "off";
    if (da.state.kind === "off") {
      lines.push(DEVICE_APPROVAL_OFF_LINE);
      if (da.thisDeviceActive) enabled = true;
      else lines.push(DEVICE_APPROVAL_NOT_THIS_DEVICE_LINE);
    } else if (da.state.kind === "on") {
      lines.push(DEVICE_APPROVAL_ON_LINE, DEVICE_APPROVAL_NO_HANDOFF_LINE);
      enabled = true; // device-signed OFF here, or the II-only request
    } else {
      lines.push(deviceApprovalPendingLine(da.state.effectiveAtNs), DEVICE_APPROVAL_NO_HANDOFF_LINE);
      // A held device can still turn it off at once; the II-only request is
      // already in and cannot be sped up.
      enabled = da.thisDeviceActive;
    }
  }
  box.disabled = !enabled || ctx.state.busy === true;
  box.addEventListener("change", () => {
    if (control === undefined) return;
    if (box.checked) void control.turnOn();
    else void control.turnOff();
  });

  return el("div", { class: "settings-block", "data-testid": "settings-device-approval" }, [
    el("h4", {}, ["New devices"]),
    el("label", { class: "radio" }, [box, ` ${DEVICE_APPROVAL_TOGGLE_LABEL}`]),
    ...lines.map((line) => el("p", { class: "muted", "data-testid": "device-approval-state" }, [line])),
  ]);
}

export function renderSettings(root: HTMLElement, ctx: AppContext): void {
  clear(root);
  root.append(...pageHead({ title: "Settings" }));
  const s = ctx.state;

  // Account.
  if (s.principal !== null) {
    const text = s.principal.toText();
    root.append(
      section("Account", [
        el("div", { class: "address-row" }, [
          el("span", { class: "principal" }, [shortPrincipal(text)]),
          copyButton(text, "Copy address"),
        ]),
        el("p", { class: "muted" }, ["Signed in with Internet Identity."]),
        // Addendum 1 ruling 2: every automatic call, disclosed once, here.
        // No automatic scan and no automatic Vault signer check.
        // O-6: three lines up front; the full list is behind "More" (moved,
        // not deleted). SSA B3: the sign-in open is disclosed.
        el("div", { class: "muted auto-calls", "data-testid": "settings-automatic-calls" }, [
          el("p", {}, ["Sign-in reads your public balance and opens your private balance here."]),
          el("p", {}, ["A funded new device makes one key request at sign-in."]),
          el("p", {}, ["Pages read live fees. Sync, Send and Shield run only when you press."]),
          details("More", [
            el("p", {}, ["What this wallet does on its own:"]),
            el("ul", {}, [
              el("li", {}, ["Sign-in: reads your public balance."]),
              el("li", {}, [
                "Sign-in: fetches this device's encrypted key and opens your private balance. No new key request.",
              ]),
              el("li", {}, [
                "Sign-in, funded account with no device key yet: one key request, to start the wallet's preparation clock.",
              ]),
              el("li", {}, [
                "Opening your private balance: looks up interrupted spends. Read only; any repair waits for you.",
              ]),
              el("li", {}, ["Shield and Send pages: read the live fees."]),
              el("li", {}, ["Settings: reads your new-device approval setting and device list."]),
              el("li", {}, ["Verify this build: reads the pool's circuit and key."]),
            ]),
            el("p", {}, ["Sync, Send, Shield, the verified sweep and the operator check run only when you press them."]),
          ]),
        ]),
        el("div", { class: "row" }, [
          el(
            "button",
            { "data-testid": "logout", disabled: s.busy === true, onclick: () => void ctx.logout() },
            ["Log out"],
          ),
        ]),
      ], { testid: "settings-account" }),
    );
  } else {
    root.append(
      section("Account", [
        el("p", { class: "muted" }, ["Not logged in."]),
        el("div", { class: "row" }, [
          el("button", { class: "primary", onclick: () => void ctx.login() }, ["Log in with Internet Identity"]),
        ]),
      ], { testid: "settings-account" }),
    );
  }

  // WALLET-V13 O-1 / SSA F-1: the wipe result, keyed on the report and NOT on
  // the session — after a wipe `principal` is null but the user must still see
  // which local surfaces were NOT cleared. Moved out of the (gated) Security
  // and recovery card unchanged.
  const wipeResult = renderWipeResult(ctx);
  if (wipeResult !== null) root.append(wipeResult);

  // Advanced recovery — signed in only (Account > Recovery).
  if (s.principal !== null) {
    const recovery = section(
      "Advanced recovery",
      [
        el("p", { class: "muted" }, [
          "A verified sweep re-checks your private balance against signed replies. Rarely needed.",
        ]),
      ],
      { testid: "settings-recovery" },
    );
    renderVerifiedSweep(recovery, ctx);
    root.append(recovery);
  }

  // WALLET-V13 O-1: signed in only.
  if (s.principal !== null) {
    root.append(
      section("Extra security", [renderPasscodeSection(ctx), renderDeviceApprovalBlock(ctx)], {
        testid: "settings-extra-security",
      }),
    );

    // Privacy.
    const delay = el("input", { type: "checkbox", id: "submission-delay-toggle" }) as HTMLInputElement;
    delay.checked = s.submissionDelayEnabled === true;
    delay.addEventListener("change", () => {
      if (typeof ctx.setSubmissionDelayEnabled === "function") ctx.setSubmissionDelayEnabled(delay.checked);
    });
    root.append(
      section("Privacy", [
        el("label", { class: "radio" }, [delay, " Wait a random time (up to 2 minutes) before sending"]),
        el("p", { class: "muted" }, ["It blurs timing, not who signs. Off by default. You can cancel or send early."]),
        linkRow("Sync", "#/scan", "Rebuild your private balance from the chain"),
      ]),
    );

    root.append(
      section(
        "How it works",
        [
          // DS-55 / DS-56 (disclosure sweep d6b6632b, verbatim).
          el("p", {}, ["Re-shield: your note becomes a new note. Your account signs it. It does not unlink you."]),
          el("p", {}, ["Public payout: part of a note goes to a public account."]),
          el("p", {}, ["Recipient and amount are public. Your account signs the call."]),
          el("p", {}, ["Withdraw is not built. Whether it can hide the sending account is not yet decided."]),
        ],
        { testid: "settings-how-it-works" },
      ),
    );

    // Other views.
    root.append(
      section("More", [
        linkRow("Vesting schedule", "#/vesting", "For token allocations"),
        el("div", { class: "soon-row" }, [el("span", {}, ["Staking"]), chip("Coming soon", "neutral")]),
      ]),
    );
  }

  // About STSH — its own card, shown signed in or out (WALLET-V13 O-1; Addendum 1
  // E-2: it carries the DS-51/DS-52 copy that used to sit on signed-out Home).
  root.append(renderAboutStsh());

  if (s.principal !== null) {
    // Security and recovery — signed in only (WALLET-V13, Addendum 1 E-1 revised).
    const security = el("section", { class: "settings-section security", "data-testid": "settings-security" }, [
      el("h3", {}, ["Security and recovery"]),
      // O-6 (CTO, 2026-09-23): II alone opens the private balance now — say what
      // that means for a shared computer.
      el("p", { "data-testid": "security-ii-access" }, [
        "Anyone with your Internet Identity login has your private balance. Log out on shared computers.",
      ]),
    ]);
    renderSecuritySections(security, ctx);
    root.append(security);
  }

  // Operator check — ONLY on an explicit press (Addendum 1 ruling 2: no
  // automatic Vault get_signers for non-operators). Presentation only.
  if (s.principal !== null && s.isAdmin !== true && typeof ctx.checkOperatorAccess === "function") {
    const check = el("button", { class: "ghost small", "data-testid": "check-operator-access" }, [
      "Check operator access",
    ]) as HTMLButtonElement;
    check.addEventListener("click", () => {
      check.disabled = true;
      void ctx.checkOperatorAccess?.();
    });
    root.append(
      section(
        "Operators",
        [el("p", { class: "muted" }, ["Vault signer? This checks the Vault's signer list once."]), check],
        { testid: "settings-operator-check" },
      ),
    );
  }

  // Admin — Vault signers only (fail-closed: unread signer set = not admin).
  if (s.isAdmin === true) {
    root.append(
      section(
        "Admin",
        [
          el("p", { class: "muted" }, ["Visible only to Vault signers. Verify this build is below."]),
          linkRow("Vault operator console", "#/operator"),
        ],
        { testid: "settings-admin", className: "admin-only" },
      ),
    );
  }
}
