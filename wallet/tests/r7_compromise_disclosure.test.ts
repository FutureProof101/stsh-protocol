/**
 * R-7 item 2 (CC-01) — the key-compromise disclosure must be REACHABLE.
 *
 * The four `recoveryCopy.ts` strings were written and unit-tested but rendered
 * nowhere: `COMPROMISE_MIGRATION_HEADING`'s only reference in the whole tree
 * was its own declaration. These tests assert the rendered account page, and
 * — separately, so the wiring cannot regress silently while a render test is
 * deleted — that the heading has more than one reference in `wallet/src`.
 *
 * The expected values here are imported BY REFERENCE from `recoveryCopy.ts` on
 * purpose: the finding is not "the words are wrong" (they were reviewed and
 * ruled correct), it is "the reviewed words never reach a user." Comparing the
 * DOM to the reviewed constant is exactly the property under test.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// WALLET-UX: this disclosure moved from the account page to Settings > Security and recovery.
import { renderSettings } from "../src/ui/pages/settings";
import {
  COMPROMISE_MIGRATION_HEADING,
  COMPROMISE_MIGRATION_STEPS,
  COMPROMISE_NO_IN_PRODUCT_CUTOFF,
  COMPROMISE_SELF_SPEND_IS_NOT_A_REMEDY,
} from "../src/ui/recoveryCopy";
import type { AppContext } from "../src/ui/context";

const ctxWith = (loggedIn: boolean): AppContext =>
  ({
    policy: { kind: "allowed" },
    state: {
      principal: loggedIn ? { toText: () => "aaaaa-aa" } : null,
      balance: null,
      notes: [],
      busy: false,
      status: null,
      wipeReport: null,
      shieldEntries: [],
    },
    pendingIntent: null,
    login: async () => {},
    logout: async () => {},
    refreshBalance: async () => {},
    panicWipe: async () => {},
    transfer: async () => {},
    refresh: () => {},
    navigate: () => {},
  }) as unknown as AppContext;

const render = (loggedIn: boolean): HTMLElement => {
  const root = document.createElement("div");
  renderSettings(root, ctxWith(loggedIn));
  return root;
};

describe("R-7 AC-2 — the compromise disclosure is on the Settings page", () => {
  it("AC-2a: renders the heading and every migration step, in order", () => {
    const root = render(true);
    expect(root.textContent ?? "").toContain(COMPROMISE_MIGRATION_HEADING);
    const steps = Array.from(
      (root.querySelector('[data-testid="compromise-steps"]') as HTMLElement).querySelectorAll("li"),
    ).map((li) => li.textContent ?? "");
    expect(steps).toEqual([...COMPROMISE_MIGRATION_STEPS]);
  });

  it("AC-2b: renders both caveats — the self-spend non-remedy and the no-cutoff line", () => {
    const t = render(true).textContent ?? "";
    expect(t).toContain(COMPROMISE_SELF_SPEND_IS_NOT_A_REMEDY);
    expect(t).toContain(COMPROMISE_NO_IN_PRODUCT_CUTOFF);
  });

  // WALLET-V13 O-1 (Addendum 1 E-1, revised): moved behind login — same
  // assertion, logged-in fixture. The logged-out absence is asserted in
  // wallet_v13_logged_out_gating.test.ts.
  it("is reachable once logged in (WALLET-V13: gated behind login)", () => {
    expect(render(true).textContent ?? "").toContain(COMPROMISE_MIGRATION_HEADING);
  });
});

describe("R-7 AC-2c — reachability, proven from the source tree, not from a render", () => {
  const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "../src");

  const tsFiles = (dir: string): string[] =>
    readdirSync(dir).flatMap((name) => {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) return tsFiles(full);
      return name.endsWith(".ts") && !name.endsWith(".test.ts") ? [full] : [];
    });

  it("AC-2c: COMPROMISE_MIGRATION_HEADING has more than one referencing file", () => {
    const files = tsFiles(SRC);
    expect(files.length).toBeGreaterThan(0);
    const referencing = files.filter((f) =>
      readFileSync(f, "utf8").includes("COMPROMISE_MIGRATION_HEADING"),
    );
    // The declaration alone is what CC-01 found. A real call site is a second
    // file; failing loudly names what was found.
    expect(
      referencing.length,
      `COMPROMISE_MIGRATION_HEADING is referenced only by: ${referencing.join(", ")}`,
    ).toBeGreaterThan(1);
  });
});
