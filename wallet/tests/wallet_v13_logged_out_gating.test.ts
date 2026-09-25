/**
 * WALLET-V13 O-1 — logged-out gating of Settings and Home (Owner W13-1;
 * Addendum 1: E-1 revised = full gate, E-2 = DS-51/DS-52 copy moves into
 * "About STSH"; SSA pre-review addendum F-1 = the wipe result survives the
 * logout the wipe itself causes).
 *
 * Every expected string is a LITERAL written here from the brief/rulings.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { Principal } from "@dfinity/principal";

import { renderAccount } from "../src/ui/pages/account";
import { renderSettings } from "../src/ui/pages/settings";
import { resolveConfig } from "../src/session/config";
import type { AppContext, AppState } from "../src/ui/context";
import type { Enumeration, PanicWipeDeps, WipeReport } from "../src/storage/panicWipe";

const NONE: Enumeration = { kind: "ok", items: [] };
const EMPTY_INVENTORY = { indexedDb: NONE, localStorage: NONE, sessionStorage: NONE, cacheStorage: NONE };

const INCOMPLETE: WipeReport = {
  complete: false,
  surfaces: [
    { surface: "session", cleared: true, detail: "session epoch advanced" },
    { surface: "indexeddb:stsh-wallet-transfers", cleared: false, detail: "deletion BLOCKED by another open connection" },
  ],
  before: EMPTY_INVENTORY,
  after: EMPTY_INVENTORY,
};

// The app-level arm drives the REAL `panicWipe` in app.ts; only the storage
// sweep is mocked. The mock keeps the real ordering: end the session (principal
// -> null) and log out FIRST, then return an INCOMPLETE report.
vi.mock("../src/storage/panicWipe", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/storage/panicWipe")>();
  return {
    ...real,
    runPanicWipe: async (deps: PanicWipeDeps): Promise<WipeReport> => {
      deps.endSession();
      await deps.logout();
      return INCOMPLETE;
    },
  };
});

const noop = async (): Promise<void> => undefined;

function ctx(state: Partial<AppState>, over: Partial<AppContext> = {}): AppContext {
  return {
    config: resolveConfig({}),
    policy: { kind: "production", iiUrl: undefined, derivationOrigin: undefined },
    state: {
      principal: Principal.fromText("aaaaa-aa"),
      balance: 0n,
      busy: false,
      status: null,
      cacheUnlocked: true,
      cacheGate: "open",
      passcodeRequired: false,
      shieldEntries: [],
      spendEntries: [],
      notes: [],
      scanning: false,
      lastScanOk: null,
      scanProgress: null,
      mirrorHead: null,
      quarantineTotal: 0,
      wipeReport: null,
      spendFeeBasis: null,
      submissionDelayEnabled: false,
      pendingDelay: null,
      pendingRecovery: [],
      verifiedScan: null,
      verifiedRollback: null,
      verifiedScanning: false,
      ...state,
    } as AppState,
    readActors: null,
    mutationActors: null,
    shieldedActors: null,
    operatorActors: null,
    journalAvailable: true,
    pendingIntent: null,
    navigate: () => undefined,
    refresh: () => undefined,
    login: noop,
    logout: noop,
    refreshBalance: noop,
    transfer: noop,
    retryPendingIntent: noop,
    abandonFrozenIntent: noop,
    unlockNoteCache: noop,
    shield: noop,
    reconcileShieldJournal: noop,
    revokeShieldAllowance: noop,
    cancelPlannedShield: noop,
    abandonAmbiguousShieldEntry: noop,
    scan: noop,
    spend: noop,
    recoverSpends: noop,
    loadSpendFeeBasis: noop,
    applySpendRecovery: noop,
    setSubmissionDelayEnabled: () => undefined,
    checkOperatorAccess: noop,
    panicWipe: noop as never,
    ...over,
  } as AppContext;
}

/** The headings of the top-level cards, in render order. */
const cards = (root: HTMLElement): string[] =>
  Array.from(root.querySelectorAll(":scope > section, :scope > div.welcome")).map(
    (c) => c.querySelector("h2, h3")?.textContent ?? "",
  );

const has = (root: HTMLElement, id: string): boolean => root.querySelector(`[data-testid="${id}"]`) !== null;

const DS51 = "Shield STSH into a private balance, then pay anyone with public STSH.";
const DS51_LINK =
  "Your Internet Identity signs every send, permanently. With one deposit, your deposit and send are linkable.";
const DS52 = "Which of your own notes paid stays private.";

/** Every section and control W13-1 hides logged out. */
const GATED_TESTIDS = [
  "settings-extra-security",
  "settings-passcode",
  "settings-device-approval",
  "settings-how-it-works",
  "settings-security",
  "security-ii-access",
  "panic-wipe-open",
  "panic-wipe-panel",
  "compromise-heading",
  "compromise-steps",
  "last-device-final",
  "settings-recovery",
  "settings-operator-check",
  "settings-admin",
];

describe("WALLET-V13 AC-2 — Settings, logged OUT: exactly Account + About STSH", () => {
  const render = (): HTMLElement => {
    const root = document.createElement("div");
    renderSettings(root, ctx({ principal: null }));
    return root;
  };

  it("renders exactly two cards: Account, then About STSH", () => {
    expect(cards(render())).toEqual(["Account", "About STSH"]);
  });

  it("the Account card is the log-in card", () => {
    const account = render().querySelector('[data-testid="settings-account"]') as HTMLElement;
    expect(account.textContent).toContain("Not logged in.");
    expect(account.querySelector("button")?.textContent).toBe("Log in with Internet Identity");
  });

  it("About STSH carries the relocated DS-51/DS-52 copy, verbatim, and the stsh.fi link", () => {
    const about = render().querySelector('[data-testid="about-stsh"]') as HTMLElement;
    const t = about.textContent ?? "";
    expect(t).toContain(DS51);
    expect(t).toContain(DS51_LINK);
    expect(t).toContain(DS52);
    expect(about.querySelector('a[href="https://stsh.fi"]')).not.toBeNull();
  });

  it("hides Extra security, Privacy, How it works, More and Security and recovery (E-1 revised: no carve-out)", () => {
    const root = render();
    for (const id of GATED_TESTIDS) expect(has(root, id), id).toBe(false);
    expect(root.querySelector("#submission-delay-toggle"), "Privacy").toBeNull();
    expect(root.querySelector('a[href="#/vesting"]'), "More: Vesting").toBeNull();
    expect(root.querySelector('a[href="#/scan"]'), "Privacy: Sync").toBeNull();
    const t = root.textContent ?? "";
    for (const gone of ["Extra security", "Privacy", "How it works", "Security and recovery", "Staking", "Lost or seized"]) {
      expect(t, gone).not.toContain(gone);
    }
  });

  it("a wipe result, when present, is shown logged out — without the gated card", () => {
    const root = document.createElement("div");
    renderSettings(root, ctx({ principal: null, wipeReport: INCOMPLETE }));
    expect(cards(root)).toEqual(["Account", "Wipe result", "About STSH"]);
    expect(root.querySelector('[data-testid="wipe-outcome"]')?.textContent).toMatch(/did NOT complete/);
    expect(has(root, "settings-security")).toBe(false);
    expect(has(root, "panic-wipe-open")).toBe(false);
  });
});

describe("WALLET-V13 AC-2 — Settings, logged IN: every section, Security and recovery fully restored", () => {
  const render = (): HTMLElement => {
    const root = document.createElement("div");
    renderSettings(root, ctx({}));
    return root;
  };

  it("renders every section in order", () => {
    expect(cards(render())).toEqual([
      "Account",
      "Advanced recovery",
      "Extra security",
      "Privacy",
      "How it works",
      "More",
      "About STSH",
      "Security and recovery",
      "Operators",
    ]);
  });

  it("Security and recovery carries the II line, the wipe entry, the compromise disclosure and the last-device warning", () => {
    const security = render().querySelector('[data-testid="settings-security"]') as HTMLElement;
    for (const id of ["security-ii-access", "panic-wipe-open", "panic-wipe-panel", "compromise-heading", "compromise-steps", "last-device-final"]) {
      expect(security.querySelector(`[data-testid="${id}"]`), id).not.toBeNull();
    }
  });

  it("More keeps Vesting and Staking; About STSH is its own card, not a row in More", () => {
    const root = render();
    const more = Array.from(root.querySelectorAll(":scope > section")).find(
      (c) => c.querySelector("h3")?.textContent === "More",
    ) as HTMLElement;
    expect(more.querySelector('a[href="#/vesting"]')).not.toBeNull();
    expect(more.textContent).toContain("Staking");
    expect(more.querySelector('a[href="https://stsh.fi"]')).toBeNull();
    expect(root.querySelector('[data-testid="about-stsh"] a[href="https://stsh.fi"]')).not.toBeNull();
  });
});

describe("WALLET-V13 AC-2 — Home, logged OUT: exactly Account + About STSH", () => {
  const render = (): HTMLElement => {
    const root = document.createElement("div");
    renderAccount(root, ctx({ principal: null }));
    return root;
  };

  it("renders the Account card (log-in button) and About STSH, nothing else", () => {
    const root = render();
    expect(cards(root)).toEqual(["Your private STSH wallet", "About STSH"]);
    const account = root.querySelector('[data-testid="home-account"]') as HTMLElement;
    expect(account.querySelector('[data-testid="login"]')?.textContent).toBe("Log in with Internet Identity");
    // The only explanatory copy is inside About STSH.
    expect(account.textContent).toBe("Your private STSH wallet" + "Log in with Internet Identity");
  });

  it("the DS-51/DS-52 copy sits inside About STSH, not loose on Home", () => {
    const root = render();
    const about = root.querySelector('[data-testid="about-stsh"]') as HTMLElement;
    expect(about.querySelector('[data-testid="welcome-linkability"]')?.textContent).toBe(DS51_LINK);
    expect(about.textContent).toContain(DS51);
    expect(about.textContent).toContain(DS52);
    expect(root.querySelectorAll('[data-testid="welcome-linkability"]')).toHaveLength(1);
  });

  it("no longer points logged-out users at Security and recovery", () => {
    const t = render().textContent ?? "";
    expect(t).not.toContain("Lost or handed-on device?");
    expect(t).not.toContain("works without signing in");
  });
});

describe("WALLET-V13 AC-2 (SSA-mandated) — the wipe result survives the wipe's own logout", () => {
  afterEach(() => {
    window.location.hash = "";
    document.body.innerHTML = "";
  });

  it("logged in -> incomplete wipe -> principal null AND the per-surface report visible on Settings", async () => {
    const { mountApp } = await import("../src/ui/app");
    const { PRODUCTION_ORIGIN } = await import("../src/session/config");
    const { memoryJournalStore } = await import("./helpers/memoryJournalStore");
    const { memoryHarness } = await import("./helpers/cacheL4");
    const { unusedIcrc2 } = await import("./helpers/tokenStubs");
    const USER = Principal.fromUint8Array(new Uint8Array(10).fill(0x51));
    const session = { identity: { getPrincipal: () => USER } as never, principal: USER };
    let loggedOut = 0;
    window.location.hash = "#/settings";
    const root = document.createElement("div");
    document.body.append(root);
    const app = await mountApp(root, {}, {
      origin: PRODUCTION_ORIGIN,
      loadLaunchOrigin: async () => PRODUCTION_ORIGIN,
      buildReadActors: async () => ({
        token: { balanceOf: async () => 0n, metadata: async () => ({ symbol: "STSH", decimals: 8, fee: 0n }), fee: async () => 0n },
        staking: null,
        vesting: { getSchedule: async () => null, claimableAmount: async () => 0n },
      }),
      buildMutationActors: async () => ({ token: { transfer: async () => { throw new Error("x"); }, ...unusedIcrc2 } }),
      createJournalStore: async () => memoryJournalStore(),
      createAuth: async () => ({
        restore: async () => session,
        login: async () => session,
        logout: async () => void (loggedOut += 1),
        verify: () => "valid" as const,
      }),
      createCacheStore: async () => (await memoryHarness()).store,
    } as never);
    await new Promise((r) => setTimeout(r, 0));

    // Logged in: the wipe entry is reachable on Settings.
    expect(app.state.principal?.toText()).toBe(USER.toText());
    const pick = (id: string) => root.querySelector<HTMLElement>(`[data-testid="${id}"]`);
    expect(pick("settings-security")).not.toBeNull();
    pick("panic-wipe-open")!.click();
    const phrase = pick("panic-wipe-phrase") as HTMLInputElement;
    phrase.value = "WIPE";
    phrase.dispatchEvent(new Event("input"));
    const confirm = pick("panic-wipe-confirm") as HTMLButtonElement;
    expect(confirm.disabled).toBe(false);
    confirm.click();
    await vi.waitFor(() => expect(app.state.wipeReport).not.toBeNull());
    await new Promise((r) => setTimeout(r, 0));

    // The wipe logged the user out...
    expect(app.state.principal).toBeNull();
    expect(loggedOut).toBe(1);
    // ...Settings is now the logged-out page (the gated card is gone)...
    expect(pick("settings-security")).toBeNull();
    expect(pick("panic-wipe-open")).toBeNull();
    // ...and the INCOMPLETE report, with its NOT CLEARED surface, is still shown.
    expect(pick("wipe-outcome")?.textContent).toMatch(/did NOT complete/);
    expect(pick("wipe-report")).not.toBeNull();
    expect(pick("wipe-surface-indexeddb:stsh-wallet-transfers")?.textContent).toMatch(/NOT CLEARED/);
    expect(pick("wipe-surface-session")?.textContent).toMatch(/: cleared/);
  });
});
