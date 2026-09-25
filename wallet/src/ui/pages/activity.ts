/**
 * Activity — WALLET-UX.
 *
 * One timeline, newest first, built ONLY from records this device already
 * holds: the encrypted shield and spend journals (inside the note cache) and
 * the unresolved public-transfer slot. Nothing here is fetched, and nothing
 * leaves the device: private actions are shown to their owner, from their own
 * encrypted history, and nowhere else.
 *
 * Items that need the user (an unresolved transfer, a shield that needs a
 * check, a payout the pool still owes) are pinned above the timeline with the
 * existing repair actions. The actions themselves are unchanged.
 */

import { clear, el } from "../dom";
import { formatStsh } from "../format";
import type { AppContext } from "../context";
import type { ShieldJournalEntryState, SpendJournalEntryState } from "../../storage/noteCache";
import { renderJournalPanel, shieldStatusLabel } from "./shield";
import { chip, pageHead, shortPrincipal } from "../components";

type Tone = "neutral" | "good" | "warn" | "bad" | "accent";

interface Item {
  atMs: number;
  title: string;
  detail: string;
  status: string;
  tone: Tone;
}

const nsToMs = (ns: string | undefined): number => {
  if (ns === undefined || ns === "") return 0;
  try {
    return Number(BigInt(ns) / 1_000_000n);
  } catch {
    return 0;
  }
};

const shieldTone: Record<ShieldJournalEntryState["status"], Tone> = {
  planned: "neutral",
  deposited: "accent",
  unknown: "warn",
  failed: "bad",
  accepted: "good",
};

function spendStatus(e: SpendJournalEntryState): { text: string; tone: Tone } {
  switch (e.status) {
    case "finalized":
      return { text: "Done", tone: "good" };
    case "failed":
      return { text: "Failed", tone: "bad" };
    case "payout-pending":
      return { text: "Payout pending", tone: "warn" };
    case "recovery-required":
      return { text: "Needs recovery", tone: "warn" };
    case "planned":
      return { text: "Not sent yet", tone: "neutral" };
    default:
      return { text: "Confirming", tone: "accent" };
  }
}

function toItems(ctx: AppContext): Item[] {
  const items: Item[] = [];
  for (const e of ctx.state.shieldEntries ?? []) {
    items.push({
      atMs: nsToMs(e.createdAtNs),
      title: `Shielded ${formatStsh(BigInt(e.denom))} STSH`,
      detail: "Public balance → private balance",
      status: shieldStatusLabel(e.status),
      tone: shieldTone[e.status],
    });
  }
  for (const e of ctx.state.spendEntries ?? []) {
    const s = spendStatus(e);
    if (e.publicPayout !== undefined) {
      items.push({
        atMs: nsToMs(e.createdAtNs),
        title: `Sent ${formatStsh(BigInt(e.publicPayout.recipientNet))} STSH from private balance`,
        detail: `To ${shortPrincipal(e.publicPayout.destinationText)} · they received public STSH`,
        status: s.text,
        tone: s.tone,
      });
    } else {
      items.push({
        atMs: nsToMs(e.createdAtNs),
        title: "Refreshed a note",
        detail: "Moved to a fresh private note",
        status: s.text,
        tone: s.tone,
      });
    }
  }
  return items.sort((a, b) => b.atMs - a.atMs);
}

const when = (ms: number): string =>
  ms === 0
    ? ""
    : new Date(ms).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

export function renderActivity(root: HTMLElement, ctx: AppContext): void {
  clear(root);
  root.append(...pageHead({ title: "Activity", sub: "What you've shielded and sent from this wallet." }));

  if (ctx.state.principal === null) {
    root.append(
      el("div", { class: "empty" }, [
        el("p", {}, ["Log in to see your activity."]),
        el("div", { class: "row" }, [
          el("button", { class: "primary", onclick: () => void ctx.login() }, ["Log in with Internet Identity"]),
        ]),
      ]),
    );
    return;
  }

  // Needs attention.
  const attention: HTMLElement[] = [];
  if (ctx.pendingIntent !== null) {
    attention.push(
      el("div", { class: "attention-item" }, [
        el("span", {}, [
          `Public transfer of ${formatStsh(BigInt(ctx.pendingIntent.amount))} STSH has no confirmed outcome yet.`,
        ]),
        el("a", { href: "#/account" }, ["Resolve on Home →"]),
      ]),
    );
  }
  const journal = renderJournalPanel(ctx);
  if (journal.childNodes.length > 0) attention.push(journal);
  if (attention.length > 0) {
    root.append(el("section", { class: "attention" }, [el("div", { class: "section-label" }, ["Needs attention"]), ...attention]));
  }

  if (!ctx.state.cacheUnlocked) {
    // WALLET-CACHE-II-ONLY O-4: sign-in opens it. "Locked" is true only when
    // this device's opt-in passcode is on; otherwise say what actually opens it.
    const gate = ctx.state.cacheGate ?? "none";
    const [line, action]: [string, HTMLElement | null] =
      gate === "passcode"
        ? [
            "Enter your passcode to see your private activity.",
            el("button", { class: "primary", onclick: () => ctx.navigate("balance") }, ["Unlock"]),
          ]
        : gate === "migrate"
          ? [
              "Enter your old passphrase once to see it.",
              el("button", { class: "primary", onclick: () => ctx.navigate("balance") }, ["Continue"]),
            ]
          : gate === "opening"
            ? ["Opening your private balance…", null]
            : gate === "error"
              ? [
                  "Couldn't open your private balance.",
                  el("button", { class: "primary", onclick: () => void ctx.retryPrivateOpen?.() }, ["Try again"]),
                ]
              : [
                  "Your wallet is getting ready. First shield or sync opens it.",
                  el("button", { class: "primary", onclick: () => void ctx.scan() }, ["Sync now"]),
                ];
    root.append(
      el("div", { class: "empty" }, [
        el("p", { "data-testid": "activity-gate" }, [line]),
        ...(action !== null ? [el("div", { class: "row" }, [action])] : []),
      ]),
    );
    return;
  }

  const items = toItems(ctx);
  if (items.length === 0) {
    root.append(
      el("div", { class: "empty" }, [
        el("p", {}, ["Nothing here yet."]),
        el("p", { class: "muted" }, ["Shields and private sends will appear here."]),
        el("div", { class: "row" }, [
          el("button", { class: "primary", onclick: () => ctx.navigate("shield") }, ["Shield STSH"]),
        ]),
      ]),
    );
  } else {
    const list = el("ul", { class: "timeline", "data-testid": "activity-list" });
    for (const it of items) {
      list.append(
        el("li", { class: "tl-item" }, [
          el("div", { class: "tl-main" }, [
            el("span", { class: "tl-title" }, [it.title]),
            el("span", { class: "tl-detail" }, [it.detail]),
          ]),
          el("div", { class: "tl-side" }, [chip(it.status, it.tone), el("span", { class: "tl-when" }, [when(it.atMs)])]),
        ]),
      );
    }
    root.append(list);
  }

  root.append(
    el("p", { class: "muted" }, ["This history lives only on this device, encrypted."]),
    el("p", { class: "muted" }, ["Public transfers are on the ledger, not here."]),
    el("p", { class: "muted" }, ["Wiping this device erases it. Your balance is not affected."]),
  );
}
