/**
 * Runtime read of the ONE injected release-record value (I1).
 *
 * The value is a compile-time `define`, so in a correctly built bundle the
 * identifier below is replaced by a string literal. The `typeof` guard exists
 * for the degenerate case of a host that loaded the module without the define
 * (a hand-rolled bundler, a bare `tsc` output); it returns `null`, and the
 * panel then says the value is unavailable. It is NOT a fallback: the
 * production build fails outright before reaching here (see loadRecord.ts).
 */

declare const __STSH_CANISTER_BUILD_SOURCE__: string | undefined;

const FULL_COMMIT_ID = /^[0-9a-f]{40}$/;

/**
 * The canister build source recorded in `[build].source_sha`, or `null` if the
 * bundle carries no injected value.
 *
 * SSA addendum A.1: this is the CANISTER build source. It is NOT the commit
 * that produced the UI you are looking at, and the panel copy says so.
 */
export function canisterBuildSource(): string | null {
  const v = typeof __STSH_CANISTER_BUILD_SOURCE__ === "string"
    ? __STSH_CANISTER_BUILD_SOURCE__
    : null;
  if (v === null || !FULL_COMMIT_ID.test(v)) return null;
  return v;
}
