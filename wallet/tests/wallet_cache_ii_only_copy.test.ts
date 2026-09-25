/**
 * WALLET-CACHE-II-ONLY — the plain-language copy pass (O-4, O-6), the
 * advisory restyle (O-7), the Home chip rename, and SSA C4 (no short line may
 * drop a qualifier the full disclosure carries).
 *
 * Every expected string is a LITERAL written here from the brief/rulings, not
 * imported from the module under test.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";

import { privacyWarnings, shieldPrivacyWarnings, type SpendPrivacyInput } from "../src/ui/privacyWarnings";
import { renderAccount, renderSecuritySections } from "../src/ui/pages/account";
import { renderActivity } from "../src/ui/pages/activity";
import { renderSettings } from "../src/ui/pages/settings";
import { renderShield, renderJournalPanel } from "../src/ui/pages/shield";
import { renderSpend } from "../src/ui/pages/spend";
import { renderScan } from "../src/ui/pages/scan";
import { renderBalance } from "../src/ui/pages/balance";
import { resolveConfig } from "../src/session/config";
import type { AppContext, AppState } from "../src/ui/context";

const WALLET = join(dirname(fileURLToPath(import.meta.url)), "..");
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
    panicWipe: noop as never,
    ...over,
  } as AppContext;
}

const NOTE = {
  leafIndex: 3n,
  value: 100_000_000_000n,
  rho: new Uint8Array(32),
  rseed: new Uint8Array(32),
  recipientPk: new Uint8Array(32),
  commitment: new Uint8Array(32).fill(0xab),
  state: "spendable" as const,
};

const words = (line: string): number => line.trim().split(/\s+/).length;

describe("Home — the private-balance chip (Owner: 'Not confirmed' read as an error)", () => {
  it("no sync yet this session: 'Not synced' with a Sync control on the card", async () => {
    const calls: string[] = [];
    const root = document.createElement("div");
    renderAccount(root, ctx({ lastScanOk: null, notes: [NOTE] }, { scan: async () => void calls.push("scan") }));
    const card = root.querySelector(".bal-private")!;
    expect(card.textContent).toContain("Not synced");
    expect(root.textContent).not.toContain("Not confirmed");
    const sync = card.querySelector('[data-testid="home-sync"]') as HTMLButtonElement;
    expect(sync).not.toBeNull();
    sync.click();
    expect(calls).toEqual(["scan"]);
  });

  it("after a sync: 'Up to date', and no Sync prompt", () => {
    const root = document.createElement("div");
    renderAccount(root, ctx({ lastScanOk: true, notes: [NOTE] }));
    const card = root.querySelector(".bal-private")!;
    expect(card.textContent).toContain("Up to date");
    expect(card.querySelector('[data-testid="home-sync"]')).toBeNull();
  });

  it("a device with no key yet: the ruled gate line and a Sync control — no 'Locked', no passphrase", () => {
    const root = document.createElement("div");
    renderAccount(root, ctx({ cacheUnlocked: false, cacheGate: "preparing" }));
    const card = root.querySelector(".bal-private")!;
    expect(card.textContent).toContain("Your wallet is getting ready. First shield or sync opens it.");
    expect(card.textContent).not.toContain("Locked");
    expect(card.querySelector('[data-testid="home-sync"]')).not.toBeNull();
    expect(root.querySelector('input[type="password"]')).toBeNull();
  });

  it("the address card uses the Owner's verbatim lines", () => {
    const root = document.createElement("div");
    renderAccount(root, ctx({}));
    expect(root.querySelector('[data-testid="address-copy"]')?.textContent).toBe(
      "Share it to receive public STSH. Private receiving: later release.",
    );
    expect(root.querySelector(".address .section-label")?.textContent).toBe("Your address");
  });
});

describe("O-6 additions (Owner/CTO 2026-09-23)", () => {
  it("Activity: one line under 'Revoke leftover approval'", () => {
    const panel = renderJournalPanel(
      ctx({
        shieldEntries: [
          {
            commitmentHex: "ab".repeat(32),
            denom: "100000000000",
            nonceHex: "00".repeat(16),
            protoFee: "0",
            ledgerFee: "0",
            encryptedPayloadHex: "",
            status: "accepted",
            createdAtNs: "1",
          },
        ],
      }),
    );
    expect(panel.textContent).toContain("Revoke leftover approval");
    expect(panel.querySelector('[data-testid="revoke-explainer"]')?.textContent).toBe(
      "A stopped shield left the pool allowed to take tokens from your public balance. Cancel that permission. Your balance does not change.",
    );
  });

  it("Settings → Security: the Internet Identity line", () => {
    const root = document.createElement("div");
    renderSettings(root, ctx({}));
    expect(root.querySelector('[data-testid="security-ii-access"]')?.textContent).toBe(
      "Anyone with your Internet Identity login has your private balance. Log out on shared computers.",
    );
  });

  it("Settings: the automatic-calls disclosure is three lines up front, the full list behind More", () => {
    const root = document.createElement("div");
    renderSettings(root, ctx({}));
    const auto = root.querySelector('[data-testid="settings-automatic-calls"]')!;
    const upFront = Array.from(auto.children).filter((c) => c.tagName === "P");
    expect(upFront).toHaveLength(3);
    for (const p of upFront) expect(words(p.textContent ?? "")).toBeLessThanOrEqual(15);
    const more = auto.querySelector("details")!;
    expect(more.open).toBe(false);
    expect(more.textContent).toContain("Sign-in: reads your public balance.");
  });
});

describe("SSA C4 + CTO correction — short lines keep every qualifier", () => {
  const matrix: SpendPrivacyInput[] = [];
  for (const amountKind of ["fixed-denomination", "specific-amount"] as const) {
    for (const publicPayout of [true, false]) {
      for (const noteOrigin of [
        undefined,
        { kind: "self-shield" as const, msSinceArrival: 1_000 },
        { kind: "incoming-receipt" as const, msSinceArrival: 1_000 },
        { kind: "unknown" as const },
      ]) {
        matrix.push({ amountKind, publicPayout, msSinceDeposit: 60_000, ...(noteOrigin ? { noteOrigin } : {}) });
      }
    }
  }

  it("the public-payout short lines carry BOTH halves (signed + public + permanent; which note paid) and the one-deposit limit", () => {
    const payout = privacyWarnings({ amountKind: "specific-amount", publicPayout: true }).find((w) =>
      w.msg.startsWith("Public payout"),
    )!;
    const short = payout.short.join(" ");
    expect(short).toMatch(/public and permanent/i);
    expect(short).toMatch(/signing account/i);
    expect(short).toContain("Which of your own notes paid stays private.");
    expect(short).toContain("If you deposited only once, the payout is linkable to that deposit.");
    // The full text keeps its original two halves AND gains the DS-54 limit.
    expect(payout.msg).toMatch(/nobody learns which note funded this payout/i);
    expect(payout.msg).toContain("If you deposited only once, the payout is linkable to that deposit.");
  });

  it("the allowance short line keeps 'while the approval stands'", () => {
    const allowance = shieldPrivacyWarnings({ bucketCount: 2, totalDenominations: 1 }).find((w) => w.level === "high")!;
    expect(allowance.short.join(" ")).toMatch(/while the approval stands/i);
    expect(allowance.msg).toMatch(/while the approval stands/i);
  });

  it("the rapid-roundtrip short line keeps 'both events are public'", () => {
    const w = privacyWarnings({
      amountKind: "fixed-denomination",
      publicPayout: true,
      noteOrigin: { kind: "self-shield", msSinceArrival: 1_000 },
    }).find((x) => /Rapid roundtrip: you shielded/.test(x.msg))!;
    expect(w.short.join(" ")).toMatch(/both events are public/i);
  });

  it("the specific-amount short line keeps 'exact amount is published on-chain'", () => {
    const w = privacyWarnings({ amountKind: "specific-amount", publicPayout: true })[0]!;
    expect(w.short.join(" ")).toMatch(/exact amount is published on-chain/i);
  });

  it("the countermeasure short line does not claim to hide the signer", () => {
    const w = privacyWarnings({ amountKind: "fixed-denomination", publicPayout: true, msSinceDeposit: 1 }).find(
      (x) => x.level === "low",
    )!;
    expect(w.short.join(" ")).toMatch(/not who signs/i);
    expect(w.short.join(" ")).toMatch(/off by default/i);
  });

  it("every short line, on every input, is one line of at most fifteen words", () => {
    for (const input of matrix) {
      for (const w of privacyWarnings(input)) {
        expect(w.short.length).toBeGreaterThan(0);
        for (const line of w.short) expect(words(line), line).toBeLessThanOrEqual(15);
      }
    }
    for (const w of shieldPrivacyWarnings({ bucketCount: 3, totalDenominations: 2 })) {
      for (const line of w.short) expect(words(line), line).toBeLessThanOrEqual(15);
    }
  });

  it("moved, not deleted: the full disclosure is in the page behind More", () => {
    const root = document.createElement("div");
    renderSpend(root, ctx({ notes: [NOTE] }));
    const warnings = root.querySelector(".warnings")!;
    expect(warnings.querySelectorAll("details.warning-more").length).toBeGreaterThan(0);
    expect(warnings.textContent).toContain("That submission is signed by your wallet identity and is recorded permanently");
  });
});

describe("O-7 — advisory callouts are copper, failed actions stay red", () => {
  const css = readFileSync(join(WALLET, "src/styles.css"), "utf8");
  const ruleOf = (selector: string): string => {
    const i = css.indexOf(`${selector} {`);
    expect(i, `${selector} rule`).toBeGreaterThanOrEqual(0);
    return css.slice(i, css.indexOf("}", i));
  };

  it(".warning.high (every level-high privacy advisory) no longer uses the red", () => {
    expect(ruleOf(".warning.high::before")).toMatch(/var\(--accent\)/);
    expect(ruleOf(".warning.high::before")).not.toMatch(/var\(--high\)/);
    expect(ruleOf(".warning.high")).not.toMatch(/0\.68 0\.19 25/);
  });

  it("red is still the failed-action colour", () => {
    expect(ruleOf(".error")).toMatch(/var\(--high\)/);
    expect(ruleOf(".status-msg.error::before")).toMatch(/var\(--high\)/);
  });

  it("the permanence disclosures render as advisory, testids intact", () => {
    const root = document.createElement("div");
    renderSecuritySections(root, ctx({}));
    for (const id of ["compromise-no-cutoff", "last-device-final"]) {
      const node = root.querySelector(`[data-testid="${id}"]`)!;
      expect(node, id).not.toBeNull();
      expect(node.className).toBe("status-msg advisory");
    }
  });

  it("the shield page's genuine input refusals stay red (.error)", () => {
    const root = document.createElement("div");
    renderShield(root, ctx({ balance: 1_000_000_000n }));
    const input = root.querySelector('input[aria-label="Amount in STSH (e.g. 123)"]') as HTMLInputElement;
    for (const value of ["abc", "1500", "10000"]) {
      input.value = value;
      input.dispatchEvent(new Event("input"));
      const errors = root.querySelectorAll(".preview p.error");
      expect(errors.length, value).toBeGreaterThan(0);
    }
  });

  it("card headings in Settings use the copper accent", () => {
    expect(ruleOf(".settings-section > h3:first-child")).toMatch(/color:\s*var\(--accent\)/);
  });
});

describe("O-4/O-6 — no limbo phrasing and no engineering nouns on the shopper pages", () => {
  const BANNED =
    /note cache|note-cache|first use sets it|coming next|for now|until .* ships|envelope|\bKDF\b|layer-?1|eligibility|journal|reconcil/i;

  const pages: Array<[string, (root: HTMLElement) => void]> = [
    ["Home (open)", (r) => renderAccount(r, ctx({ notes: [NOTE] }))],
    ["Home (preparing)", (r) => renderAccount(r, ctx({ cacheUnlocked: false, cacheGate: "preparing" }))],
    ["Home (passcode)", (r) => renderAccount(r, ctx({ cacheUnlocked: false, cacheGate: "passcode" }))],
    ["Home (signed out)", (r) => renderAccount(r, ctx({ principal: null }))],
    ["Activity (preparing)", (r) => renderActivity(r, ctx({ cacheUnlocked: false, cacheGate: "preparing" }))],
    ["Activity (open)", (r) => renderActivity(r, ctx({}))],
    ["Settings", (r) => renderSettings(r, ctx({}))],
    ["Shield", (r) => renderShield(r, ctx({}))],
    ["Send", (r) => renderSpend(r, ctx({ notes: [NOTE] }))],
    ["Sync", (r) => renderScan(r, ctx({ notes: [NOTE] }))],
    ["Balance", (r) => renderBalance(r, ctx({ notes: [NOTE] }))],
  ];

  for (const [name, render] of pages) {
    it(`${name}`, () => {
      const root = document.createElement("div");
      render(root);
      const text = root.textContent ?? "";
      const hit = BANNED.exec(text);
      expect(hit?.[0] ?? null, `banned phrase on ${name}`).toBeNull();
    });
  }
});

describe("O-6 — the release panel lives under Settings → 'Verify this build', collapsed", () => {
  it("is folded on Settings, hidden everywhere else, and still the ONE panel", async () => {
    const { mountApp } = await import("../src/ui/app");
    const { PRODUCTION_ORIGIN } = await import("../src/session/config");
    const { memoryJournalStore } = await import("./helpers/memoryJournalStore");
    const { memoryHarness } = await import("./helpers/cacheL4");
    const { unusedIcrc2 } = await import("./helpers/tokenStubs");
    const USER = Principal.fromUint8Array(new Uint8Array(10).fill(0x51));
    const session = {
      identity: { getPrincipal: () => USER } as never,
      principal: USER,
    };
    window.location.hash = "#/account";
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
        logout: async () => undefined,
        verify: () => "valid" as const,
      }),
      createCacheStore: async () => (await memoryHarness()).store,
    } as never);
    const fold = root.querySelector('[data-testid="verify-build"]') as HTMLDetailsElement;
    expect(fold).not.toBeNull();
    expect(fold.querySelector("summary")?.textContent).toBe("Verify this build");
    expect(fold.querySelectorAll('[data-release-panel="wallet"]')).toHaveLength(1);
    expect(root.querySelectorAll('[data-release-panel="wallet"]')).toHaveLength(1);
    expect(fold.hidden, "not on Home").toBe(true);

    window.location.hash = "#/settings";
    await new Promise((r) => setTimeout(r, 0));
    expect(app.state.principal?.toText()).toBe(USER.toText());
    expect(fold.hidden, "shown on Settings").toBe(false);
    expect(fold.open, "collapsed by default").toBe(false);
    window.location.hash = "";
  });
});

describe("Disclosure sweep d6b6632b — DS-51..DS-61 wallet rows, verbatim", () => {
  // WALLET-V13 (Addendum 1 E-2): the DS-51/DS-52 copy moved, verbatim, from
  // signed-out Home into the "About STSH" card (still on signed-out Home, and
  // on Settings). Same assertions, retargeted to the card.
  it("DS-51 / DS-52 (About STSH card, Home signed out)", () => {
    const root = document.createElement("div");
    renderAccount(root, ctx({ principal: null }));
    const t = root.querySelector('[data-testid="about-stsh"]')?.textContent ?? "";
    expect(t).toContain(
      "Your Internet Identity signs every send, permanently. With one deposit, your deposit and send are linkable.",
    );
    expect(t).toContain("Which of your own notes paid stays private.");
    expect(t).not.toMatch(/which note pays stays private/i);
    expect(t).not.toMatch(/Which note paid stays private\./);
  });

  it("DS-53 / DS-54 (Send)", () => {
    const root = document.createElement("div");
    renderSpend(root, ctx({ notes: [NOTE] }));
    const t = root.textContent ?? "";
    expect(t).toContain(
      "Your Internet Identity signs every spend, publicly and permanently. One deposit means your spend is linkable.",
    );
    expect(t).toContain("If you deposited only once, the payout is linkable to that deposit.");
  });

  it("DS-55 / DS-56 (Settings, How it works)", () => {
    const root = document.createElement("div");
    renderSettings(root, ctx({}));
    const t = root.textContent ?? "";
    expect(t).toContain("Re-shield: your note becomes a new note. Your account signs it. It does not unlink you.");
    expect(t).toContain("Withdraw is not built. Whether it can hide the sending account is not yet decided.");
    expect(t).not.toMatch(/sending account is hidden too/i);
  });

  it("DS-57 (Private balance)", () => {
    const root = document.createElement("div");
    renderBalance(root, ctx({ notes: [NOTE] }));
    expect(root.textContent).toContain(
      "Held in private notes. Your deposits are public, so observers may infer this total.",
    );
    expect(root.textContent).not.toContain("Not shown on the public ledger");
  });

  it("DS-61 (Staking source line)", () => {
    const src = readFileSync(join(WALLET, "src/ui/pages/staking.ts"), "utf8");
    expect(src).toContain("reviewed staking-canister fixes land");
    expect(src).not.toContain("audited staking-canister fixes land");
  });
});

// ── WALLET-V12 — Extra security (O-4 / SSA F-6), spend waiting line (Addendum 1) ─
//
// F-6: the passcode block moved INTO the new "Extra security" section (its
// own strings and testids unchanged — asserted, not deleted); the section
// gains the second, independent "Approve new devices" toggle.

describe("WALLET-V12 — Settings → Extra security", () => {
  const control = () => {
    const calls: string[] = [];
    return {
      calls,
      control: {
        load: async () => {
          calls.push("load");
        },
        turnOn: async () => {
          calls.push("turnOn");
        },
        turnOff: async () => {
          calls.push("turnOff");
        },
        requestClear: async () => {
          calls.push("requestClear");
        },
      },
    };
  };
  const lines = (root: HTMLElement) =>
    Array.from(root.querySelectorAll('[data-testid="device-approval-state"]')).map((p) => p.textContent ?? "");
  const box = (root: HTMLElement) =>
    root.querySelector('[data-testid="device-approval-toggle"]') as HTMLInputElement;

  it("one section holds BOTH toggles; the passcode block's copy is unchanged", () => {
    const root = document.createElement("div");
    renderSettings(root, ctx({}));
    const sec = root.querySelector('[data-testid="settings-extra-security"]')!;
    expect(sec.querySelector("h3")?.textContent).toBe("Extra security");
    const pass = sec.querySelector('[data-testid="settings-passcode"]')!;
    expect(pass.textContent).toContain("Signing in opens your wallet.");
    expect(pass.textContent).toContain("Require a passcode to open notes on this device");
    expect(sec.querySelector('[data-testid="passcode-toggle"]')).not.toBeNull();
    const approval = sec.querySelector('[data-testid="settings-device-approval"]')!;
    expect(approval.textContent).toContain("Approve new devices from a device I already have");
  });

  it("unknown setting: the toggle is disabled with its reason, and Settings asks for ONE read", () => {
    const { calls, control: c } = control();
    const root = document.createElement("div");
    renderSettings(root, ctx({}, { deviceApprovalControl: c }));
    expect(box(root).disabled).toBe(true);
    expect(box(root).checked).toBe(false);
    expect(lines(root)).toEqual(["Open your private balance to change this."]);
    expect(calls).toEqual(["load"]);
  });

  it("OFF on an enrolled device: ticking calls turnOn exactly once", () => {
    const { calls, control: c } = control();
    const root = document.createElement("div");
    renderSettings(
      root,
      ctx(
        { deviceApproval: { state: { kind: "off" }, thisDeviceActive: true, activeDevices: 1 } },
        { deviceApprovalControl: c },
      ),
    );
    expect(box(root).checked).toBe(false);
    expect(box(root).disabled).toBe(false);
    expect(lines(root)).toEqual(["Off."]);
    box(root).checked = true;
    box(root).dispatchEvent(new Event("change"));
    expect(calls).toEqual(["turnOn"]);
  });

  it("ON: the two honest lines (A1/SSA ON line + CTO Addendum 1 E-3 line); unticking calls turnOff", () => {
    const { calls, control: c } = control();
    const root = document.createElement("div");
    renderSettings(
      root,
      ctx(
        { deviceApproval: { state: { kind: "on" }, thisDeviceActive: false, activeDevices: 1 } },
        { deviceApprovalControl: c },
      ),
    );
    expect(box(root).checked).toBe(true);
    expect(lines(root)).toEqual([
      "New devices need approval from one you already have.",
      "New devices can't be added while this is on (in this release).",
    ]);
    box(root).checked = false;
    box(root).dispatchEvent(new Event("change"));
    expect(calls).toEqual(["turnOff"]);
  });

  it("OFF but this browser is not an enrolled device: disabled, one-line reason", () => {
    const root = document.createElement("div");
    renderSettings(
      root,
      ctx(
        { deviceApproval: { state: { kind: "off" }, thisDeviceActive: false, activeDevices: 2 } },
        { deviceApprovalControl: control().control },
      ),
    );
    expect(box(root).disabled).toBe(true);
    expect(lines(root)).toEqual(["Off.", "Turn this on from a device you already use."]);
  });

  it("every device-approval line is one idea, at most 15 words; none claims more than new-device enrolment", () => {
    const all = [
      "New devices need approval from one you already have.",
      "New devices can't be added while this is on (in this release).",
      "Set up this device first to use this.",
      "Turn this on from a device you already use.",
      "This wallet only adds devices approved from a device you already use.",
      "On your other device, turn off “Approve new devices” in Settings. It's instant.",
      "Or request turn-off here. It takes 24 hours.",
    ];
    for (const line of all) {
      expect(words(line), line).toBeLessThanOrEqual(15);
      expect(line, "I-4: no hijack/theft/secure claim").not.toMatch(/secure|safe|protect|hijack|steal|theft/i);
    }
  });
});

describe("WALLET-V12 — a spend-locked note says it is waiting (Addendum 1)", () => {
  it("a pending note adds exactly one line; none without it", () => {
    const root = document.createElement("div");
    renderBalance(root, ctx({ notes: [NOTE, { ...NOTE, leafIndex: 4n, state: "pending" as const }] }));
    expect(root.querySelector('[data-testid="spend-waiting-note"]')?.textContent).toBe(
      "Waiting for the last spend to settle.",
    );
    const plain = document.createElement("div");
    renderBalance(plain, ctx({ notes: [NOTE] }));
    expect(plain.querySelector('[data-testid="spend-waiting-note"]')).toBeNull();
  });

  it("the spend admission lines are advisory-length plain copy (O-6)", () => {
    for (const line of [
      "Set up this device first, then try again.",
      "Too many failed spends this hour. Try again in 59 minutes.",
      "Three spends are already in progress. Wait for one to finish.",
      "Spending is paused while a service recovers. Try again shortly.",
      "This spend already went through.",
      "Waiting for the last spend to settle.",
    ]) {
      expect(words(line), line).toBeLessThanOrEqual(15);
    }
  });
});
