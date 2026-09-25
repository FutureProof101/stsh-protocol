/**
 * L04-07 (R-8) — the last-device warning must be RENDERED, not merely exported.
 *
 * The canister refuses a second bootstrap for an identity that has revoked its
 * way to zero devices, and the authorisation that lifts that refusal has to be
 * signed by a device that is still ACTIVE — i.e. BEFORE the last revocation.
 * A user who learns this from the refusal learns it at the one moment they can
 * no longer act on it.
 *
 * Same shape as `r7_compromise_disclosure.test.ts`, and for the same reason
 * that file gives: the expected value is imported BY REFERENCE, because the
 * property under test is not "the words are right" but "the reviewed words
 * reach a user."
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// WALLET-UX: this disclosure moved from the account page to Settings > Security and recovery.
import { renderSettings } from "../src/ui/pages/settings";
import { LAST_DEVICE_REVOCATION_IS_FINAL } from "../src/ui/recoveryCopy";
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

/**
 * The LITERAL the rendered DOM must carry (CTO ruling
 * cto-ruling-r8-landed-diff-fix-wave-2026-09-06 item 5, closing SSA AMBER-4).
 *
 * The by-reference assertions below prove the reviewed words REACH a user;
 * they cannot notice the words being replaced, because the expected value
 * moves with them. This literal is the other half: the copy's two load-bearing
 * claims — permanence, and that the signed approval is not something this
 * wallet version offers — are pinned here, so rewriting the string back to an
 * instruction the wallet cannot carry out is a RED and not a silent edit.
 */
const REQUIRED_LAST_DEVICE_LITERAL =
  "Revoking your last device is permanent: once no device is left, this identity cannot " +
  "set up a new one. Re-enabling setup needs a signed approval from a device that is " +
  "still active, which this wallet version does not yet offer.";

/**
 * The V1 sentence AMBER-4 removed. It told the user to "authorise that from a
 * device that is still active BEFORE you revoke it" — an instruction to call
 * `authorize_re_bootstrap`, which has no wallet binding at all. Forbidden in
 * the rendered DOM by content, so the dead-end advice cannot come back under a
 * different variable name.
 */
const FORBIDDEN_INSTRUCTION = "authorise that from a";

describe("R-8 AC-9 — the last-device warning is on the Settings page", () => {
  it("renders the warning verbatim in the Settings DOM", () => {
    expect(render(true).textContent ?? "").toContain(LAST_DEVICE_REVOCATION_IS_FINAL);
  });

  it("renders the RULED literal — not merely whatever the module currently exports", () => {
    expect(LAST_DEVICE_REVOCATION_IS_FINAL).toBe(REQUIRED_LAST_DEVICE_LITERAL);
    expect(render(true).textContent ?? "").toContain(REQUIRED_LAST_DEVICE_LITERAL);
  });

  it("does not instruct an action this wallet cannot perform (AMBER-4)", () => {
    expect(LAST_DEVICE_REVOCATION_IS_FINAL).not.toContain(FORBIDDEN_INSTRUCTION);
    expect(render(true).textContent ?? "").not.toContain(FORBIDDEN_INSTRUCTION);
  });

  it("the wallet still has no authorize_re_bootstrap binding — the copy's premise", () => {
    const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "../src");
    const tsFiles = (dir: string): string[] =>
      readdirSync(dir).flatMap((name) => {
        const full = join(dir, name);
        if (statSync(full).isDirectory()) return tsFiles(full);
        return name.endsWith(".ts") ? [full] : [];
      });
    // The QUOTED name, not the bare word: a canister method can only be
    // invoked through its name as a string literal (the actor/IDL surface), and
    // `recoveryCopy.ts`'s own JSDoc discusses the endpoint in prose — which is
    // documentation, not a binding, and must not read as one.
    const binding = tsFiles(SRC).filter((f) =>
      readFileSync(f, "utf8").includes('"authorize_re_bootstrap"'),
    );
    // If this ever fails, the wallet HAS grown the binding — at which point the
    // copy above is understating the product and must be revisited, which is
    // exactly the signal this arm exists to raise.
    expect(
      binding,
      `authorize_re_bootstrap now has a wallet binding in: ${binding.join(", ")} — the ` +
        "last-device copy says this version does not offer it; update the copy.",
    ).toEqual([]);
  });

  // WALLET-V13 O-1 (Addendum 1 E-1, revised): moved behind login — same
  // assertion, logged-in fixture. The logged-out absence is asserted in
  // wallet_v13_logged_out_gating.test.ts.
  it("is reachable once logged in (WALLET-V13: gated behind login)", () => {
    expect(render(true).textContent ?? "").toContain(LAST_DEVICE_REVOCATION_IS_FINAL);
  });

  it("has more than one referencing file — a declaration alone is not a disclosure", () => {
    const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "../src");
    const tsFiles = (dir: string): string[] =>
      readdirSync(dir).flatMap((name) => {
        const full = join(dir, name);
        if (statSync(full).isDirectory()) return tsFiles(full);
        return name.endsWith(".ts") && !name.endsWith(".test.ts") ? [full] : [];
      });
    const referencing = tsFiles(SRC).filter((f) =>
      readFileSync(f, "utf8").includes("LAST_DEVICE_REVOCATION_IS_FINAL"),
    );
    expect(
      referencing.length,
      `LAST_DEVICE_REVOCATION_IS_FINAL is referenced only by: ${referencing.join(", ")}`,
    ).toBeGreaterThan(1);
  });
});
