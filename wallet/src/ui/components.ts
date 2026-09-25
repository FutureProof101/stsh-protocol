/**
 * WALLET-UX: the few presentational building blocks every page shares.
 *
 * Presentation only. Nothing here reads session state, calls an actor, or
 * decides whether an action is allowed; pages pass in what to show and the
 * handlers to call.
 */

import { el } from "./dom";

/** A page header: optional back link, title, one-line subtitle. */
export function pageHead(opts: { title: string; sub?: string; back?: { href: string; label: string } }): HTMLElement[] {
  const out: HTMLElement[] = [];
  if (opts.back !== undefined) {
    out.push(el("a", { class: "back-link", href: opts.back.href }, [`← ${opts.back.label}`]));
  }
  out.push(el("h2", {}, [opts.title]));
  if (opts.sub !== undefined) out.push(el("p", { class: "page-sub" }, [opts.sub]));
  return out;
}

/** A small status chip. `tone` picks the colour; the text carries the meaning. */
export function chip(text: string, tone: "neutral" | "good" | "warn" | "bad" | "accent" = "neutral"): HTMLElement {
  return el("span", { class: `chip chip-${tone}` }, [text]);
}

/** A label/value line in a breakdown. `strong` marks the line that matters most. */
export function breakdownRow(label: string, value: string, opts: { strong?: boolean; testid?: string } = {}): HTMLElement {
  const attrs: Record<string, string> = { class: opts.strong === true ? "bd-row bd-strong" : "bd-row" };
  if (opts.testid !== undefined) attrs["data-testid"] = opts.testid;
  return el("div", attrs, [el("span", { class: "bd-label" }, [label]), el("span", { class: "bd-value" }, [value])]);
}

/** A breakdown block: a titled list of label/value rows. */
export function breakdown(rows: HTMLElement[], title?: string): HTMLElement {
  const box = el("div", { class: "breakdown" });
  if (title !== undefined) box.append(el("div", { class: "bd-title" }, [title]));
  box.append(...rows);
  return box;
}

/**
 * A collapsible section. Closed by default: the content is still in the
 * document (so it can be read, searched and audited), it is just not in the way.
 */
export function details(summary: string, children: Array<Node | string>, opts: { open?: boolean; testid?: string; className?: string } = {}): HTMLDetailsElement {
  const attrs: Record<string, string | boolean> = { class: opts.className ?? "fold" };
  if (opts.open === true) attrs.open = true;
  if (opts.testid !== undefined) attrs["data-testid"] = opts.testid;
  return el("details", attrs, [el("summary", {}, [summary]), el("div", { class: "fold-body" }, children)]) as HTMLDetailsElement;
}

/**
 * WALLET-CACHE-II-ONLY O-6/O-7 — one privacy advisory: its short lines first,
 * the full disclosure behind "More" (moved, never deleted — it stays in the
 * DOM). The level class is kept; the stylesheet renders every advisory level in
 * copper or amber, never the red that means a failed action.
 */
export function warningCallout(w: { level: string; msg: string; short: readonly string[] }): HTMLElement {
  return el("div", { class: `warning ${w.level}` }, [
    ...w.short.map((line) => el("p", { class: "warning-line" }, [line])),
    details("More", [el("p", {}, [w.msg])], { className: "fold warning-more" }),
  ]);
}

/** A copy-to-clipboard button for a principal or other identifier. */
export function copyButton(text: string, label = "Copy"): HTMLButtonElement {
  const btn = el("button", { class: "ghost small", type: "button" }, [label]) as HTMLButtonElement;
  btn.addEventListener("click", () => {
    const done = () => {
      btn.textContent = "Copied";
      setTimeout(() => {
        btn.textContent = label;
      }, 1600);
    };
    try {
      const p = navigator.clipboard?.writeText(text);
      if (p !== undefined) void p.then(done, () => undefined);
    } catch {
      // Clipboard blocked: the value is still selectable on screen.
    }
  });
  return btn;
}

/** A row of choice buttons behaving as a single-select segmented control. */
export function segmented<T extends string>(
  options: Array<{ value: T; label: string }>,
  selected: T,
  onSelect: (value: T) => void,
  ariaLabel: string,
): HTMLElement {
  const group = el("div", { class: "segmented", role: "radiogroup", "aria-label": ariaLabel });
  for (const o of options) {
    const btn = el(
      "button",
      {
        type: "button",
        role: "radio",
        "aria-checked": o.value === selected ? "true" : "false",
        class: o.value === selected ? "seg is-on" : "seg",
      },
      [o.label],
    );
    btn.addEventListener("click", () => onSelect(o.value));
    group.append(btn);
  }
  return group;
}

/** A "working on it" card for a long operation, carrying the live status line. */
export function progressCard(title: string, line: string | null, extra: HTMLElement[] = []): HTMLElement {
  return el("div", { class: "progress-card", role: "status", "aria-live": "polite" }, [
    el("div", { class: "progress-head" }, [el("span", { class: "spinner", "aria-hidden": "true" }), el("strong", {}, [title])]),
    ...(line !== null ? [el("p", { class: "muted" }, [line])] : []),
    ...extra,
  ]);
}

/**
 * Ask for the live fee basis from a page render WITHOUT a render loop.
 *
 * `loadSpendFeeBasis` re-renders the route when it fails, and the route asks
 * again on render. This allows one request per context per 30 seconds and
 * reports whether a request has already been made (so a page can stop saying
 * "Loading…" and fall back to "shown when you confirm").
 */
const feeBasisRequests = new WeakMap<object, number>();
export function requestFeeBasis(ctx: { state: { spendFeeBasis?: unknown }; loadSpendFeeBasis?: () => Promise<void> }): "loaded" | "requested" | "unavailable" {
  if (ctx.state.spendFeeBasis !== null && ctx.state.spendFeeBasis !== undefined) return "loaded";
  if (typeof ctx.loadSpendFeeBasis !== "function") return "unavailable";
  const last = feeBasisRequests.get(ctx);
  const now = Date.now();
  if (last !== undefined && now - last < 30_000) return "unavailable";
  feeBasisRequests.set(ctx, now);
  void ctx.loadSpendFeeBasis();
  return "requested";
}

/** Shorten a principal for display in lists; the full value is always one click away. */
export function shortPrincipal(text: string): string {
  return text.length <= 20 ? text : `${text.slice(0, 11)}…${text.slice(-7)}`;
}
