/**
 * Vesting page — READ-ONLY display (Campaign A / Wave 1, Lane A3, brief §4).
 *
 * No `[Claim]` control (C-A4): the canister pre-increments `claimed` before
 * its await and `claimable_amount` reports 0 for BOTH paid and stuck-unknown
 * claims, so this wallet cannot verify settlement. Honesty requirement
 * (A-S15): the claimable figure is labelled as canister-reported and NOT
 * presented as proof that a prior payout settled.
 */

import { Principal } from "@dfinity/principal";

import type { AppContext } from "../context";
import { READ_SERVICES_UNAVAILABLE } from "../context";
import { clear, el } from "../dom";
import { formatStsh } from "../tokenFormat";

function nsToIsoDate(ns: bigint): string {
  return new Date(Number(ns / 1_000_000n)).toISOString().slice(0, 10);
}

export function renderVesting(root: HTMLElement, ctx: AppContext): void {
  clear(root);
  root.append(
    el("h2", {}, ["Vesting"]),
    el("p", { class: "muted" }, [
      "Read-only display. Claiming from this wallet arrives once the vesting canister exposes a " +
        "public claim-status query — “claim available soon”.",
    ]),
  );

  const beneficiaryInput = el("input", {
    type: "text",
    placeholder: "Beneficiary principal",
    "aria-label": "Beneficiary principal",
    "data-testid": "vesting-beneficiary",
  }) as HTMLInputElement;
  if (ctx.state.principal !== null) beneficiaryInput.value = ctx.state.principal.toText();

  const results = el("div", { class: "results" });
  // AC-3 request-identity fence: only the LATEST load may touch `results`,
  // checked in the success AND error paths (see pages/staking.ts).
  let requestSeq = 0;

  async function load(): Promise<void> {
    const token = ++requestSeq; // incremented at load() start, before validation
    clear(results);
    let beneficiary: Principal;
    try {
      beneficiary = Principal.fromText(beneficiaryInput.value.trim());
    } catch {
      results.append(
        el("p", { class: "status-msg error" }, [`Invalid principal: "${beneficiaryInput.value}"`]),
      );
      return;
    }
    // J-17c: refusal, not an empty/zero render. The vesting canister does not
    // exist until A-7; with no reader the page says so and shows NO figures,
    // so an absent ledger can never read as a zero balance.
    if (ctx.readActors === null) {
      results.append(
        el(
          "p",
          { class: "status-msg error", "data-testid": "vesting-unavailable" },
          [READ_SERVICES_UNAVAILABLE],
        ),
      );
      return;
    }
    const reader = ctx.readActors.vesting;
    results.append(el("p", { class: "muted" }, ["Loading…"]));
    try {
      const [schedule, claimable] = await Promise.all([
        reader.getSchedule(beneficiary),
        reader.claimableAmount(beneficiary),
      ]);
      if (token !== requestSeq) return; // stale success — discard
      clear(results);
      results.append(
        el("p", { class: "muted", "data-testid": "vesting-beneficiary-shown" }, [
          `Showing vesting data for ${beneficiary.toText()}`,
        ]),
      );
      if (schedule === null) {
        results.append(el("p", { class: "muted" }, ["No vesting schedule for this principal."]));
        return;
      }
      results.append(
        el("h3", {}, ["Schedule"]),
        el("ul", {}, [
          el("li", {}, [`Total: ${formatStsh(schedule.totalAmount)} STSH`]),
          el("li", {}, [`Recorded as claimed: ${formatStsh(schedule.claimed)} STSH`]),
          el("li", {}, [`Start: ${nsToIsoDate(schedule.startNs)}`]),
          el("li", {}, [`Cliff ends: ${nsToIsoDate(schedule.cliffEndNs)}`]),
          el("li", {}, [`Vesting ends: ${nsToIsoDate(schedule.vestingEndNs)}`]),
        ]),
        el("h3", {}, ["Currently claimable"]),
        el("p", { "data-testid": "vesting-claimable" }, [
          `${formatStsh(claimable)} STSH — canister-reported currently claimable. This figure ` +
            "does not confirm prior payout settlement: a claim whose transfer outcome is still " +
            "unknown also reports 0.",
        ]),
      );
    } catch (err) {
      if (token !== requestSeq) return; // stale ERROR — must not wipe newer results
      clear(results);
      results.append(
        el("p", { class: "status-msg error" }, [
          `Could not load vesting data: ${err instanceof Error ? err.message : String(err)}`,
        ]),
      );
    }
  }

  root.append(
    el("div", { class: "row" }, [
      beneficiaryInput,
      el(
        "button",
        { class: "primary", "data-testid": "vesting-load", onclick: () => void load() },
        ["Load schedule"],
      ),
    ]),
    results,
  );
}
