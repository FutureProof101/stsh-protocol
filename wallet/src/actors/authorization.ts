/**
 * WL-2b — no private event may trigger a public action.
 *
 * THE INVARIANT
 *
 *   No private event may cause the wallet to issue a state-changing canister
 *   call without an explicit user gesture authorising that action.
 *
 * A private event is anything the wallet learns without the user asking for a
 * public consequence: the scanner discovering or validating an incoming note,
 * a note-cache read or balance recomputation, a journal read, a cache unlock.
 * The danger is not that such a call is wrong — it is that its TIMING is caused
 * by a private fact, so anyone watching the chain learns when that private fact
 * happened. Convention cannot hold that line.
 *
 * TWO LEVELS, BECAUSE ONE CANNOT WORK
 *
 * A gesture authorises an OPERATION ("shield this amount"), and one operation
 * legitimately makes several wire calls — a shield approves once and then
 * deposits once per note. That count is decided inside the flow, long after the
 * gesture fires, so a gesture cannot mint a per-call token and cannot even name
 * how many are needed. But per-OPERATION authority alone is ambient for the
 * operation's duration: anything that interleaves during one of its awaits
 * could ride it.
 *
 * So:
 *
 *   - the GESTURE mints an operation LEASE, naming actions, not a count;
 *   - the FLOW draws a SINGLE-USE token from the lease at the point each wire
 *     call is about to be made — N is known where the tokens are drawn, not
 *     where the gesture fires;
 *   - the WRAPPER consumes exactly one token immediately before the wire call.
 *
 * NON-AMBIENT, and this is the load-bearing property: there is no "is anything
 * open for this action" lookup anywhere in this module. A caller that was not
 * HANDED a token cannot obtain one, and a token names one action and dies on
 * first use. Two concurrent operations hold two leases and neither can draw
 * from the other.
 *
 * THE DEADLINE
 *
 * A lease also expires. Without one, an operation that stalls — a hung await,
 * a device asleep mid-flow — leaves a live authorization behind that could fire
 * a public call arbitrarily later, at a time the user never chose. Expiry is
 * checked on BOTH draw and consume: a token drawn before the deadline but not
 * yet spent does NOT outlive its lease, because honouring it would leave
 * exactly the hazard the deadline exists to close.
 *
 * Nothing here crosses a wire or is persisted. Leases and tokens are runtime
 * objects with no serialization and they die with the operation.
 */

import { MAX_NOTES_PER_OPERATION } from "../crypto/notes";
import { DELAY_MAX_MS } from "../ui/submissionDelay";

/** The six state-changing methods, named exactly as the wrappers expose them. */
export type StateChangingAction =
  | "shieldDeposit"
  | "retryDepositCommitment"
  | "privateSpend"
  | "retryPrivateSpendPayout"
  | "transfer"
  | "approve";

/**
 * R-1 (WALLET-AUTH Gate 1, CTO ruling 2026-09-19) — the ONE read action.
 *
 * Every other entry in `AuthorizedAction` names a state-changing call. This one
 * does not, and it is here anyway, because of what the verified read path
 * actually does on the wire. A verified sweep is not a query: it is a run of
 * ingress messages (`actors/replicated.ts`), so it is attributable to the
 * caller and metered against the target canister, and it changes the wallet's
 * observable footprint. The lease is the object the UI copy points at when it
 * tells the user what a verified sweep costs them in visibility.
 *
 * What the lease does NOT do: it does not attach the user's principal to the
 * requests. The scan agent stays anonymous (parent brief §6 gotcha 6); the
 * lease authorises the ACTION, not an identity on the wire.
 *
 * The six state-changing actions' semantics are untouched by its addition
 * (parent brief §8).
 */
export type ReadLeaseAction = "verifiedScan";

/** Everything a lease may name: the six state-changing calls plus the read lease. */
export type AuthorizedAction = StateChangingAction | ReadLeaseAction;

// ── The deadline and its four declared components ────────────────────────────
//
// PROVENANCE — PENDING-WL-1. All three variable constants below are PROVISIONAL
// under `reviews/CTO_RULING_WL-23_lease_budgets_2026-08-22.md`, which ruled them
// after this seat reported that it could not honestly measure them here: the
// wallet's harness mocks every actor, so there is no per-call latency to
// observe, and the only proof timing available is native node while the shipped
// prover is browser WASM. WL-1 (browser-runtime rehearsal) carries a BINDING
// owed row to measure both on representative hardware and RE-PIN these values —
// the same one-ruled-event shape as the `[wallet_bundle]` digest.
//
// The SECURITY POSTURE does not rest on these magnitudes. It rests on the
// mechanism: single-use tokens, expiry on draw AND consume, an injected
// monotonic clock. The deadline is defence-in-depth on top of consume-expiry,
// which is why a provisional magnitude is acceptable where a provisional
// mechanism would not be.

/** Wire calls one operation may make: 1 approve + at most 16 deposits. */
export const MAX_OPERATION_CALLS = 1 + MAX_NOTES_PER_OPERATION;

/**
 * PROVISIONAL (PENDING-WL-1). Reasoned engineering allowance, NOT a
 * measurement: IC update-call consensus + certification ≈ 2 s nominal, ×3 for
 * subnet load and one boundary-node retry. Ceiling-shaped, and cited as such.
 */
export const PER_CALL_BUDGET_MS = 6_000;

/**
 * PROVISIONAL (PENDING-WL-1). The builder's measured native-node worst case for
 * a full spend flow including one real proof was 1,462 ms; ×~7 for a
 * browser-WASM worker on slow hardware. The native figure is a PROXY and is
 * labelled a proxy — it does not bound a browser.
 */
export const PROOF_BUDGET_MS = 10_000;

/** The one named margin, stated once. */
export const SLACK_MS = 30_000;

/**
 * The lease deadline, DERIVED — never a literal.
 *
 * `DELAY_MAX_MS` (the user may sit in the randomised submission delay for its
 * whole bound) + one proof + every wire call + slack.
 */
export const LEASE_DEADLINE_MS =
  DELAY_MAX_MS + PROOF_BUDGET_MS + PER_CALL_BUDGET_MS * MAX_OPERATION_CALLS + SLACK_MS;

// ── The verified-sweep budget (SSA C-3 / C-12) ───────────────────────────────
//
// `LEASE_DEADLINE_MS` is derived from a SPEND: a randomised submission delay,
// one proof, seventeen update calls. None of those appear in a verified sweep,
// so reusing that number here would be a coincidence dressed as a derivation.
// The verified sweep gets its own, derived from its own measurement.

/**
 * Gate 0's measured mean wall clock per replicated call on a local dfx 0.28.0
 * replica: 11,194 ms for the full 9-call sweep of a 2,000-leaf tree at page
 * size 500 (`reviews/PACKET_HARDEN03_WALLET_AUTH_GATE0_563f8a4_2026-09-17.md`
 * §G0-4). It is a MEAN OVER THE WHOLE SWEEP — head reads, both `count` calls
 * and the nullifier pages are already inside it, which is why the ceiling below
 * needs no separate overhead term.
 */
export const GATE0_PER_REPLICATED_CALL_MS = 1_244;

/**
 * Mainnet subnet `pzp6e` is 34 nodes against the replica's single node, and the
 * Gate 0 packet records the cycles ratio as ≈2.6×. Applied to latency as well
 * as cost: consensus over more nodes is the dominant term in both. Expressed in
 * tenths so the arithmetic stays integral and the factor stays readable.
 */
export const SUBNET_NODE_FACTOR_TENTHS = 26;

/** Per replicated call on mainnet, rounded UP — a budget, never an estimate. */
export const PER_PAGE_BUDGET_MS = Math.ceil(
  (GATE0_PER_REPLICATED_CALL_MS * SUBNET_NODE_FACTOR_TENTHS) / 10,
);

/**
 * The verified sweep's own lease deadline.
 *
 * PROVISIONAL, and labelled so for the same reason the three constants above it
 * are: the only measurement behind it is a single-node local replica. It is a
 * ten-minute allowance for an explicitly user-initiated, user-watched sweep —
 * long enough that a legitimate sweep of a launch-era tree cannot be killed by
 * the deadline, short enough that a stalled one does not leave an authorisation
 * alive for an hour. SSA C-8 rescoped the mainnet re-measure to a transport
 * exercise, and puts the affordability re-measure at real tree size in the
 * post-launch T2 tranche; this value is re-pinned there, not guessed again.
 */
export const VERIFIED_SWEEP_DEADLINE_MS = 600_000;

/**
 * Per-action deadlines. Absent means `LEASE_DEADLINE_MS`, so the six
 * state-changing actions are bit-for-bit unaffected by this table's existence.
 */
const ACTION_DEADLINE_MS: Partial<Record<AuthorizedAction, number>> = {
  verifiedScan: VERIFIED_SWEEP_DEADLINE_MS,
};

/**
 * The deadline a lease runs under: the TIGHTEST of the deadlines its actions
 * declare. Fail-closed on purpose — a lease naming a mix can never be given
 * more time than the strictest action it covers. For a lease naming only the
 * six state-changing actions this is exactly `LEASE_DEADLINE_MS`, unchanged.
 */
export function leaseDeadlineFor(actions: readonly AuthorizedAction[]): number {
  let deadline = Number.POSITIVE_INFINITY;
  for (const action of actions) {
    const own = ACTION_DEADLINE_MS[action] ?? LEASE_DEADLINE_MS;
    if (own < deadline) deadline = own;
  }
  return Number.isFinite(deadline) ? deadline : LEASE_DEADLINE_MS;
}

// ── Typed failures ───────────────────────────────────────────────────────────

/** A state-changing call was attempted with no valid single-use token. */
export class ActionNotAuthorizedError extends Error {
  constructor(readonly action: AuthorizedAction, detail: string) {
    super(
      `refusing to call ${action}: ${detail}. A state-changing canister call must be ` +
        `authorised by an explicit user gesture (WL-2b) — nothing the wallet learns ` +
        `privately may put a transaction on chain by itself.`,
    );
    this.name = "ActionNotAuthorizedError";
  }
}

/**
 * The operation's lease passed its deadline. Fail closed on draw AND consume.
 *
 * `partial` is the load-bearing field, and it exists because an operation is
 * NOT one call. A shield is up to one approve plus up to sixteen deposits, each
 * with its own token, so a lease can expire BETWEEN them — after the approve
 * has landed, or after some deposits have. Telling that user "nothing was
 * submitted" would be false in a reachable state, and worse than useless: it
 * invites a blind restart and hides the journal state that actually needs
 * reconciling.
 *
 * So the lease counts what it has consumed, and the message follows the fact:
 *
 *   partial === false  no token was ever consumed on this lease. Nothing
 *                      reached the wire. Safe to say so, and safe to restart.
 *   partial === true   at least one call was already dispatched. The operation
 *                      may be incomplete; it must be RECONCILED, not retried.
 */
export class LeaseExpiredError extends Error {
  constructor(
    readonly action: AuthorizedAction | null,
    detail: string,
    /** Whether any call on this lease had already been dispatched. */
    readonly partial: boolean = false,
  ) {
    super(
      partial
        ? `the authorization for this operation expired part-way through (${detail}). ` +
            `Some of this operation was ALREADY submitted, so it may be incomplete — do not ` +
            `simply start again, or you could repeat work that already happened. Reconcile it ` +
            `first: the wallet's journal knows what was dispatched and can finish or safely ` +
            `abandon it.`
        : `the authorization for this operation has expired (${detail}). Nothing was submitted; ` +
            `start the action again so it is authorised at the moment you ask for it.`,
    );
    this.name = "LeaseExpiredError";
  }
}

// ── The lease and its tokens ─────────────────────────────────────────────────

/**
 * A single-use permit for ONE wire call. Opaque on purpose: it carries no
 * method the holder can use to mint another, and it is meaningless to any
 * authority but the one that issued it.
 */
export interface CallToken {
  readonly action: AuthorizedAction;
}

export interface OperationLease {
  /** Draw a single-use token for `action`. Throws if expired or not permitted. */
  draw(action: AuthorizedAction): CallToken;
  /** End the lease now. Every undrawn and unconsumed token dies with it. */
  close(): void;
}

/**
 * The wallet's authorization authority: it mints leases and it is the only
 * thing that can consume a token. The ACTOR WRAPPERS hold it (a required
 * constructor parameter — an optional one would be a real unguarded path), and
 * a wrapper consumes the token it was HANDED. It never asks "is anything open".
 */
export interface AuthorizationAuthority {
  /**
   * Mint an operation lease. CALL THIS ONLY FROM A USER-GESTURE HANDLER — it is
   * the whole trust anchor of the invariant.
   */
  mintLease(actions: readonly AuthorizedAction[]): OperationLease;
  /**
   * Consume one token immediately before its wire call. Throws unless the token
   * was minted by THIS authority, is for THIS action, has not been consumed,
   * and its lease is open and unexpired.
   */
  consume(token: CallToken | undefined, action: AuthorizedAction): void;
}

interface LeaseRecord {
  actions: readonly AuthorizedAction[];
  mintedAt: number;
  closed: boolean;
  /**
   * Tokens consumed on this lease so far. A consumed token means a wire call
   * was DISPATCHED — its outcome may be success, failure or unknown, but it
   * left. That is exactly the fact the expiry message must not contradict.
   */
  consumedCount: number;
}

export interface AuthorityDeps {
  /**
   * MONOTONIC milliseconds. Never wall-clock: a clock that steps backwards
   * would silently extend a lease, and one that steps forward would expire a
   * live operation. Injected, so tests drive it and nothing in this lane
   * asserts a real elapsed duration.
   */
  now(): number;
  /** Overrides the deadline for tests that bind the boundary. */
  deadlineMs?: number;
}

export function createAuthorizationAuthority(deps: AuthorityDeps): AuthorizationAuthority {
  const overrideMs = deps.deadlineMs;
  // The token -> lease binding lives in a WeakMap the caller cannot reach, so a
  // forged object is not a token and a token cannot be re-pointed at another
  // lease. `consumed` is a set, not a flag on the token, for the same reason.
  const leaseOf = new WeakMap<CallToken, LeaseRecord>();
  const consumed = new WeakSet<CallToken>();

  /** Expired when `now - mintedAt >= deadline` — the boundary is INCLUSIVE. */
  const expired = (lease: LeaseRecord): boolean =>
    deps.now() - lease.mintedAt >= (overrideMs ?? leaseDeadlineFor(lease.actions));

  return {
    mintLease(actions: readonly AuthorizedAction[]): OperationLease {
      if (actions.length === 0) {
        throw new Error("a lease naming no action authorises nothing");
      }
      const record: LeaseRecord = {
        actions: [...actions],
        mintedAt: deps.now(),
        closed: false,
        consumedCount: 0,
      };
      return {
        draw(action: AuthorizedAction): CallToken {
          if (record.closed) {
            throw new ActionNotAuthorizedError(action, "this operation's lease is already closed");
          }
          if (expired(record)) {
            throw new LeaseExpiredError(
              action,
              "the lease deadline passed before the token was drawn",
              record.consumedCount > 0,
            );
          }
          if (!record.actions.includes(action)) {
            throw new ActionNotAuthorizedError(
              action,
              `the operation's lease covers [${record.actions.join(", ")}]`,
            );
          }
          const token: CallToken = { action };
          leaseOf.set(token, record);
          return token;
        },
        close(): void {
          record.closed = true;
        },
      };
    },

    consume(token: CallToken | undefined, action: AuthorizedAction): void {
      if (token === undefined) {
        throw new ActionNotAuthorizedError(action, "no authorization token was supplied");
      }
      const record = leaseOf.get(token);
      if (record === undefined) {
        throw new ActionNotAuthorizedError(
          action,
          "the supplied token was not issued by this wallet's authorization authority",
        );
      }
      if (consumed.has(token)) {
        throw new ActionNotAuthorizedError(
          action,
          "this token was already spent on a call (tokens are single-use)",
        );
      }
      if (token.action !== action) {
        throw new ActionNotAuthorizedError(
          action,
          `the token authorises ${token.action}, not ${action}`,
        );
      }
      if (record.closed) {
        throw new ActionNotAuthorizedError(action, "the operation's lease was closed");
      }
      // Checked on CONSUME as well as on draw: a token drawn while the lease
      // was live must not survive it, or a stalled operation could resume and
      // fire a public call long after the user's gesture.
      if (expired(record)) {
        throw new LeaseExpiredError(
          action,
          "the lease deadline passed between drawing this token and using it",
          record.consumedCount > 0,
        );
      }
      consumed.add(token);
      record.consumedCount += 1;
    },
  };
}

/**
 * The wallet's authority instance.
 *
 * Module-level, and that is NOT the ambient shape D2 rejected: it holds no open
 * authorization and answers no "is anything open" question. It can only verify
 * and consume a token that a caller was HANDED, so possessing a reference to it
 * grants nothing. The actors need it at construction and the gesture handlers
 * need it to mint leases; one instance is what makes those the same authority.
 *
 * The clock is `performance.now()` — MONOTONIC by specification, unlike
 * `Date.now()`, which can step backwards over an NTP correction and would
 * silently extend a lease.
 */
export const walletAuthorizationAuthority = createAuthorizationAuthority({
  now: () => (typeof performance === "undefined" ? 0 : performance.now()),
});
