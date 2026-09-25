/**
 * Staking page — READ-ONLY display (Campaign A / Wave 1, Lane A3, brief §4).
 *
 * No stake/unstake/claim controls: mutations are Lane A4, HELD behind the
 * reviewed P-STK pre-lane; reward claiming is disabled at source (H-A1).
 * Honesty requirements (A-S15): a position with `op_id != null` reads
 * "pending operator reconciliation" and must NOT look like an ordinary active
 * position; pending rewards are an aggregate, display-only figure.
 *
 * Positions are public canister state — the query works anonymously. When
 * logged in the holder defaults to the session principal; any principal can
 * be viewed read-only.
 */

import { Principal } from "@dfinity/principal";

import type { StakePositionView } from "../../actors/staking";
import type { AppContext } from "../context";
import { READ_SERVICES_UNAVAILABLE } from "../context";
import { clear, el } from "../dom";
import { formatStsh } from "../tokenFormat";

/**
 * WALLET-READ-ACTORS (P-2): the staking page's OWN refusal when the read actors
 * exist but no staking reader was built. Staking is NOT INSTALLED at launch
 * (D1, 2026-08-14), so on mainnet this — not the global J-17c notice — is what
 * `#/staking` shows. Rendered on this page only.
 */
const STAKING_NOT_DEPLOYED =
  "Staking is not deployed at launch (D1) — staking views are unavailable.";

function stakingNotDeployed(): HTMLElement {
  return el(
    "p",
    { class: "status-msg error", "data-testid": "staking-not-deployed" },
    [STAKING_NOT_DEPLOYED],
  );
}

function nsToIsoDate(ns: bigint): string {
  return new Date(Number(ns / 1_000_000n)).toISOString().slice(0, 10);
}

function positionStatus(p: StakePositionView): { label: string; className: string } {
  if (p.opId !== null) {
    // DEF-052 in-flight lock/unlock: visibly distinct from an active position.
    return {
      label: `Pending operator reconciliation (op #${p.opId})`,
      className: "warn",
    };
  }
  if (p.closed) return { label: "Closed", className: "muted" };
  return { label: "Active", className: "" };
}

export function renderStaking(root: HTMLElement, ctx: AppContext): void {
  clear(root);
  // WALLET-READ-ACTORS (P-2): readers exist but staking was not built (D1 —
  // no staking canister at launch). Refuse at MOUNT: no intro, no holder
  // input, no load button, no results container. The all-null case
  // (`ctx.readActors === null`, a token/vesting failure) is NOT this branch —
  // it keeps the controls and the J-17c click-time refusal below.
  if (ctx.readActors !== null && ctx.readActors.staking === null) {
    root.append(el("h2", {}, ["Staking"]), stakingNotDeployed());
    return;
  }
  root.append(
    el("h2", {}, ["Staking"]),
    el("p", { class: "muted" }, [
      "Read-only display. Staking mutations (stake / unstake) arrive in a later lane after the " +
        "reviewed staking-canister fixes land; reward claiming is not yet enabled on the canister.",
    ]),
  );

  const holderInput = el("input", {
    type: "text",
    placeholder: "Principal to view",
    "data-testid": "staking-holder",
  }) as HTMLInputElement;
  if (ctx.state.principal !== null) holderInput.value = ctx.state.principal.toText();

  const results = el("div", { class: "results" });
  // AC-3 request-identity fence: a monotonic token per page instance. Only the
  // LATEST load may touch `results` — checked in the success AND error paths,
  // so a slow response (or late failure) for principal A can never replace or
  // wipe principal B's rendered data.
  let requestSeq = 0;

  async function load(): Promise<void> {
    const token = ++requestSeq; // incremented at load() start, before validation
    clear(results);
    let holder: Principal;
    try {
      holder = Principal.fromText(holderInput.value.trim());
    } catch {
      results.append(
        el("p", { class: "status-msg error" }, [`Invalid principal: "${holderInput.value}"`]),
      );
      return;
    }
    // J-17c: refusal, not an empty/zero render. The staking canister does not
    // exist until A-7; with no reader the page says so and shows NO figures,
    // so an absent ledger can never read as a zero balance.
    if (ctx.readActors === null) {
      results.append(
        el(
          "p",
          { class: "status-msg error", "data-testid": "staking-unavailable" },
          [READ_SERVICES_UNAVAILABLE],
        ),
      );
      return;
    }
    const reader = ctx.readActors.staking;
    // P-2(e): re-guard for the type checker (and for a reader set that changed
    // after mount) — never a `!` or a cast. Same D1 copy, no load attempted.
    if (reader === null) {
      results.append(stakingNotDeployed());
      return;
    }
    results.append(el("p", { class: "muted" }, ["Loading…"]));
    try {
      const [positions, pendingRewards] = await Promise.all([
        reader.getStakePositions(holder),
        reader.getPendingRewards(holder),
      ]);
      if (token !== requestSeq) return; // stale success — discard
      clear(results);
      renderPositions(results, holder, positions, pendingRewards);
    } catch (err) {
      if (token !== requestSeq) return; // stale ERROR — must not wipe newer results
      clear(results);
      results.append(
        el("p", { class: "status-msg error" }, [
          `Could not load staking data: ${err instanceof Error ? err.message : String(err)}`,
        ]),
      );
    }
  }

  root.append(
    el("div", { class: "row" }, [
      holderInput,
      el(
        "button",
        { class: "primary", "data-testid": "staking-load", onclick: () => void load() },
        ["Load positions"],
      ),
    ]),
    results,
  );
}

function renderPositions(
  root: HTMLElement,
  holder: Principal,
  positions: StakePositionView[],
  pendingRewards: bigint,
): void {
  root.append(
    // The data is unambiguously tied to the principal it was RESOLVED for —
    // not whatever the input reads by the time it renders (AC-3).
    el("p", { class: "muted", "data-testid": "staking-holder-shown" }, [
      `Showing staking data for ${holder.toText()}`,
    ]),
    el("h3", {}, ["Pending rewards (aggregate)"]),
    el("p", { "data-testid": "pending-rewards" }, [
      `${formatStsh(pendingRewards)} STSH — read-only; claiming is not yet enabled.`,
    ]),
  );

  if (positions.length === 0) {
    root.append(el("p", { class: "muted" }, ["No staking positions for this principal."]));
    return;
  }

  const tbody = el("tbody");
  for (const p of positions) {
    const status = positionStatus(p);
    tbody.append(
      el("tr", { "data-testid": `position-${p.positionId}` }, [
        el("td", {}, [String(p.positionId)]),
        el("td", {}, [`${formatStsh(p.amount)} STSH`]),
        el("td", {}, [String(p.lockDays)]),
        el("td", {}, [nsToIsoDate(p.lockEndNs)]),
        el("td", {}, [formatStsh(p.votingWeight)]),
        el("td", { class: status.className, "data-testid": `position-status-${p.positionId}` }, [
          status.label,
        ]),
      ]),
    );
  }

  root.append(
    el("h3", {}, ["Positions"]),
    el("table", { class: "denoms" }, [
      el("thead", {}, [
        el("tr", {}, [
          el("th", {}, ["#"]),
          el("th", {}, ["Amount"]),
          el("th", {}, ["Lock days"]),
          el("th", {}, ["Lock ends"]),
          el("th", {}, ["Voting weight"]),
          el("th", {}, ["Status"]),
        ]),
      ]),
      tbody,
    ]),
  );
}
