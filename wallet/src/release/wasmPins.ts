/**
 * J-17b — the `[wasm.*]` release pins the operator page checks an InstallCode /
 * Upgrade artifact against, and the role→package alias that maps a
 * BORN_UNDER_VAULT role onto the package a pin is recorded under.
 *
 * WHY BUILD TIME, AND WHY ONLY `[wasm.*]` (SSA G-01):
 *
 * - The pins are extracted from `deployment/mainnet/release_hashes.toml` by a
 *   Vite build step into `src/generated/releasePins.json`, which the browser
 *   imports. The record is not shipped and no TOML parser is added — the wallet
 *   installs from the committed lockfile only.
 * - `[wallet_bundle]` is NEVER read here. That section records the digest of the
 *   bundle this very code is compiled into; feeding it back in would make the
 *   emitted bytes depend on their own recorded digest and the record-only
 *   rebind would never reproduce. Only `[wasm.*]` rows are eligible.
 *
 * The scanner is `record.ts`'s, reused rather than re-written: its `SECTION_RE`
 * retains the quotes in `[wasm."stsh-verifier"]`, which is exactly the section a
 * naive `split('.')` mangles into a package named `"stsh` (H-03).
 */

import { ReleaseRecordError, SECTION_RE, STRING_KV_RE } from "./record";

/** A package name -> its pinned sha256 (lowercase 64-hex). */
export type WasmPins = Readonly<Record<string, string>>;

const SHA256_HEX = /^[0-9a-f]{64}$/;

/**
 * The nine `BORN_UNDER_VAULT_ROLES` (scripts/verify_custody_manifest/src/lib.rs)
 * mapped onto the package a `[wasm.*]` row is recorded under.
 *
 * Eight are 1:1. `verifier` is the outlier — the dfx canister name is
 * `verifier` but the cargo package, and therefore the pin's section, is
 * `stsh-verifier` (SSA G-02).
 */
export const ROLE_PACKAGE_ALIAS: Readonly<Record<string, string>> = {
  shielded_pool: "shielded_pool",
  treasury: "treasury",
  vesting: "vesting",
  nullifier_registry: "nullifier_registry",
  stsh_token: "stsh_token",
  merkle_tree: "merkle_tree",
  verifier: "stsh-verifier",
  smoke_alarm_monitor: "smoke_alarm_monitor",
  vetkeys: "vetkeys",
};

/** The nine roles, in the order `BORN_UNDER_VAULT_ROLES` declares them. */
export const BORN_UNDER_VAULT_ROLES: readonly string[] = Object.keys(ROLE_PACKAGE_ALIAS);

/**
 * Roles with NO `[wasm.*]` pin, by ruling rather than by omission.
 *
 * `vetkeys` is a workspace-EXCLUDED crate installed at A-7 under D1; it is not
 * one of the ten `INLINE_PAYLOAD_ARTIFACTS` and the record carries no row for
 * it. The operator page therefore cannot check its bytes against a pin, and the
 * proposal is only buildable behind an explicit acknowledgement — never
 * silently, which is what an "absent pin means skip the check" fallback would
 * be for every other role too.
 */
export const UNPINNED_ROLES: readonly string[] = ["vetkeys"];

/**
 * Extract every `[wasm.<pkg>] sha256` pair from the record's text.
 *
 * Throws `ReleaseRecordError` on a duplicate section, a duplicate `sha256`
 * within one section, a section with no `sha256`, or a value that is not
 * lowercase 64-hex. Every one of those fails the build; there is no fallback
 * and no partial result.
 */
export function extractWasmPins(toml: string): WasmPins {
  const pins: Record<string, string> = {};
  const seenSections = new Set<string>();
  let pkg: string | null = null;
  for (const raw of toml.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const sec = SECTION_RE.exec(line);
    if (sec !== null) {
      const name = sec[1];
      if (name === "wasm" || !name.startsWith("wasm.")) {
        pkg = null;
        continue;
      }
      // `wasm.stsh_token` -> `stsh_token`; `wasm."stsh-verifier"` -> `stsh-verifier`.
      const rest = name.slice("wasm.".length).trim();
      const unquoted =
        rest.length >= 2 && rest.startsWith('"') && rest.endsWith('"')
          ? rest.slice(1, -1)
          : rest;
      if (unquoted === "" || unquoted.includes(".")) {
        throw new ReleaseRecordError(
          `release record has an uninterpretable wasm section: ${JSON.stringify(name)}`,
        );
      }
      if (seenSections.has(unquoted)) {
        throw new ReleaseRecordError(
          `release record declares [wasm.${unquoted}] more than once; refusing to guess`,
        );
      }
      seenSections.add(unquoted);
      pkg = unquoted;
      continue;
    }
    if (pkg === null) continue;
    const kv = STRING_KV_RE.exec(line);
    if (kv === null || kv[1] !== "sha256") continue;
    if (pins[pkg] !== undefined) {
      throw new ReleaseRecordError(
        `[wasm.${pkg}] declares sha256 more than once; refusing to guess`,
      );
    }
    if (!SHA256_HEX.test(kv[2])) {
      throw new ReleaseRecordError(
        `[wasm.${pkg}].sha256 is not lowercase 64-hex: ${JSON.stringify(kv[2])}`,
      );
    }
    pins[pkg] = kv[2];
  }
  for (const section of seenSections) {
    if (pins[section] === undefined) {
      throw new ReleaseRecordError(`[wasm.${section}] pins no sha256`);
    }
  }
  if (Object.keys(pins).length === 0) {
    throw new ReleaseRecordError("release record pins no [wasm.*] sha256 at all");
  }
  // Emitted sorted so the generated JSON is a function of the record's CONTENT,
  // not of the order the sections happen to appear in.
  const sorted: Record<string, string> = {};
  for (const key of Object.keys(pins).sort()) sorted[key] = pins[key];
  return sorted;
}

/** What the page knows about a role's pin. */
export type RolePin =
  | { kind: "pinned"; pkg: string; sha256: string }
  | { kind: "unpinned-by-ruling"; pkg: string }
  | { kind: "unknown-role" };

/**
 * Resolve a BORN_UNDER_VAULT role to its pin. An unknown role is `unknown-role`
 * — never "unpinned": the page hard-refuses anything it cannot name (G-02).
 */
export function pinForRole(role: string, pins: WasmPins): RolePin {
  const pkg = ROLE_PACKAGE_ALIAS[role];
  if (pkg === undefined) return { kind: "unknown-role" };
  if (UNPINNED_ROLES.includes(role)) return { kind: "unpinned-by-ruling", pkg };
  const sha256 = pins[pkg];
  if (sha256 === undefined) return { kind: "unknown-role" };
  return { kind: "pinned", pkg, sha256 };
}
