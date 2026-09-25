/**
 * Vanilla hash router (Campaign A A1.5 base; Campaign B L3a adds `shield`,
 * L3b adds `scan` + the shielded `balance`).
 *
 * WALLET-UX: the nav is three destinations — Home (the `account` route, which
 * stays the default so every existing deep link and the DEFAULT_ROUTE pin keep
 * their meaning), Activity and Settings. The task routes (shield, spend, scan,
 * balance) and the public-ledger views (staking, vesting) still RESOLVE, they
 * are simply reached from Home or Settings instead of from the nav.
 *
 * `parseRoute` is pure and unit-tested; `HashRouter` is the thin
 * window/hashchange binding.
 */

export type Route =
  | "account"
  | "activity"
  | "settings"
  | "staking"
  | "vesting"
  | "shield"
  | "scan"
  | "balance"
  | "spend"
  | "operator"
  | "not-available";

/** The routes exposed in the nav. */
export const NAV_ROUTES: readonly Route[] = ["account", "activity", "settings"];
export const DEFAULT_ROUTE: Route = "account";

/**
 * WALLET-UX: routes that resolve and are linked from inside pages (Home's
 * actions, Settings' rows) rather than from the nav.
 */
export const TASK_ROUTES: readonly Route[] = ["shield", "spend", "scan", "balance", "staking", "vesting"];

/**
 * J-17b: routes that RESOLVE but are deliberately absent from the nav.
 *
 * `#/operator` is the Vault signing surface. It is reachable by typing the
 * hash, not by a link every wallet user sees: it is useful to exactly the
 * handful of principals in the Vault's signer set, the page itself hides its
 * controls from anyone else, and the Vault refuses them server-side regardless.
 * A nav entry would advertise a custody surface to every visitor and teach
 * nobody anything. (WALLET-UX: Settings links to it only for a principal the
 * Vault reports as a signer.)
 */
export const REACH_ONLY_ROUTES: readonly Route[] = ["operator"];

/** Campaign-B routes that must resolve to the not-available view (none open). */
const NOT_AVAILABLE_SEGMENTS: readonly string[] = [];

/** Parse a location hash (e.g. "#/staking") into a route. */
export function parseRoute(hash: string): Route {
  const segment = hash.replace(/^#\/?/, "").split("/")[0]?.toLowerCase() ?? "";
  if ((NAV_ROUTES as readonly string[]).includes(segment)) return segment as Route;
  if ((TASK_ROUTES as readonly string[]).includes(segment)) return segment as Route;
  if ((REACH_ONLY_ROUTES as readonly string[]).includes(segment)) return segment as Route;
  if (NOT_AVAILABLE_SEGMENTS.includes(segment)) return "not-available";
  return DEFAULT_ROUTE;
}

/** The canonical href for a route. */
export function routeHref(route: Route): string {
  return `#/${route}`;
}

/** Minimal hashchange-driven router. `onRoute` is called with the active route. */
export class HashRouter {
  private handler = () => this.onRoute(parseRoute(window.location.hash));

  constructor(private readonly onRoute: (route: Route) => void) {}

  /** Begin listening and render the current route immediately. */
  start(): void {
    window.addEventListener("hashchange", this.handler);
    this.handler();
  }

  stop(): void {
    window.removeEventListener("hashchange", this.handler);
  }

  navigate(route: Route): void {
    window.location.hash = routeHref(route);
  }
}
