/**
 * Private balance (the `balance` route) — L3b; WALLET-UX layout.
 *
 * Total of validated spendable notes, the breakdown by denomination, and the
 * two actions that change it. Non-spendable notes are listed in plain words
 * and never counted. Pool-level diagnostics are admin-only (Settings).
 */

import { clear, el } from "../dom";
import { formatStsh, summarizeBalance } from "../format";
import type { AppContext } from "../context";
import { noteLifecycle, spendableNotes } from "../../storage/noteCache";
import { advisoryPoolCommitmentLine } from "./scan";
import { chip, pageHead } from "../components";
import { SPEND_WAITING_NOTE_COPY } from "../spendAdmissionCopy";

const LIFECYCLE_WORDS: Record<string, string> = {
  pending: "waiting to confirm",
  spent: "spent",
  dummy: "empty placeholder",
  quarantined: "set aside (could not be validated)",
};

export function renderBalance(root: HTMLElement, ctx: AppContext): void {
  clear(root);
  const spendable = spendableNotes(ctx.state.notes);
  const summary = summarizeBalance(spendable);

  root.append(
    ...pageHead({
      title: "Private balance",
      // DS-57 (disclosure sweep d6b6632b, verbatim).
      sub: "Held in private notes. Your deposits are public, so observers may infer this total.",
      back: { href: "#/account", label: "Home" },
    }),
  );

  const syncLine = el("div", { class: "row" }, [
    ctx.state.scanning === true
      ? chip("Syncing", "accent")
      : ctx.state.lastScanOk === true
        ? chip("Up to date", "good")
        : chip("Not synced", "neutral"),
    el("a", { href: "#/scan" }, ["Sync now"]),
  ]);

  if (summary.noteCount === 0) {
    root.append(
      syncLine,
      el("div", { class: "empty" }, [
        el("p", {}, ["No private STSH yet."]),
        el("p", { class: "muted" }, [
          "Shield STSH to start, or sync to find notes from another device.",
        ]),
        el("div", { class: "row" }, [
          el("button", { class: "primary", onclick: () => ctx.navigate("shield") }, ["Shield a deposit"]),
          el("button", { onclick: () => ctx.navigate("scan") }, ["Sync"]),
        ]),
      ]),
    );
  } else {
    root.append(
      el("p", { class: "total" }, [`${formatStsh(summary.total)} STSH`]),
      el("p", { class: "muted" }, [`${summary.noteCount} spendable note${summary.noteCount === 1 ? "" : "s"}`]),
      syncLine,
    );

    const table = el("table", { class: "denoms" }, [
      el("thead", {}, [
        el("tr", {}, [el("th", {}, ["Note size"]), el("th", {}, ["Count"]), el("th", {}, ["Subtotal"])]),
      ]),
    ]);
    const tbody = el("tbody");
    for (const b of summary.buckets) {
      tbody.append(
        el("tr", {}, [
          el("td", {}, [`${formatStsh(b.denom)} STSH`]),
          el("td", {}, [String(b.count)]),
          el("td", {}, [`${formatStsh(b.subtotal)} STSH`]),
        ]),
      );
    }
    table.append(tbody);
    root.append(
      table,
      el("div", { class: "actions" }, [
        el("button", { class: "primary", onclick: () => ctx.navigate("spend") }, ["Send"]),
        el("button", { onclick: () => ctx.navigate("shield") }, ["Shield more"]),
      ]),
    );

    // Informational lifecycle counts — never part of the balance.
    const counts = new Map<string, number>();
    for (const n of ctx.state.notes) {
      const s = noteLifecycle(n);
      counts.set(s, (counts.get(s) ?? 0) + 1);
    }
    const nonSpendable = [...counts.entries()].filter(([s]) => s !== "spendable");
    if (nonSpendable.length > 0) {
      root.append(
        el("p", { class: "muted" }, [
          "Not in your balance: " +
            nonSpendable.map(([s, c]) => `${c} ${LIFECYCLE_WORDS[s] ?? s}`).join(", ") +
            ".",
        ]),
      );
    }
  }

  // WALLET-V12 (Addendum 1): a note locked by an in-flight or refused spend
  // (retried later with the SAME id) gets one plain line, so it does not look
  // broken.
  if (ctx.state.notes.some((n) => noteLifecycle(n) === "pending")) {
    root.append(
      el("p", { class: "muted", "data-testid": "spend-waiting-note" }, [SPEND_WAITING_NOTE_COPY]),
    );
  }

  if (ctx.state.isAdmin === true && ctx.state.mirrorHead !== null && ctx.state.mirrorHead !== undefined) {
    root.append(
      el("p", { class: "muted admin-only", "data-testid": "pool-commitment-count" }, [
        advisoryPoolCommitmentLine(ctx.state.mirrorHead.leafCount),
      ]),
    );
  }
}
