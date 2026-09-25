/**
 * J-25 — selection of the ONE release-record value this site's build injects.
 *
 * DELIBERATE DUPLICATE of wallet/src/release/record.ts, byte-for-byte in its
 * logic. The two frontends are separate npm packages with separate tsconfig
 * roots and separate lockfiles; importing across the boundary would put wallet
 * sources inside this package's compilation and its `npm ci` tree. The drift
 * risk is closed by a test on each side that selects from the REAL record and
 * asserts both sides agree on the same value (see src/release.test.ts).
 *
 * I1 (brief V3 §2): exactly one value, `[build].source_sha`, is parsed out of
 * `deployment/mainnet/release_hashes.toml` at BUILD time and validated as a
 * full 40-hex commit id. The build FAILS on a missing or malformed value.
 *
 * Why a hand-rolled section scanner rather than a TOML library: neither frontend has
 * a TOML dependency and the gate installs from the committed lockfile only
 * (`npm ci`), so one cannot be added here. The scanner is deliberately narrow —
 * it understands section headers and `key = "value"` and nothing else, which is
 * all the record's `[build]` block uses.
 *
 * SELECTION IS SECTION-BOUND (SSA addendum C.3 / D). `source_sha` also appears
 * under `[wallet_bundle]`, and that one is the WALLET pin: selecting it would
 * make an emitted bundle depend on the wallet's own recorded digest, and the
 * record-only child R would then never reproduce (I2). Only the `[build]`
 * occurrence is eligible, and a second `[build]` occurrence is an error rather
 * than a last-one-wins.
 */

/** Thrown for any condition that must FAIL THE BUILD rather than degrade. */
export class ReleaseRecordError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReleaseRecordError";
  }
}

/** The define name the emitted bundle carries. Referenced by vite + vitest. */
export const BUILD_SOURCE_DEFINE = "__STSH_CANISTER_BUILD_SOURCE__";

const FULL_COMMIT_ID = /^[0-9a-f]{40}$/;

/** `[section]` or `[a.b]` / `[a."b"]`, ignoring a trailing comment. */
const SECTION_RE = /^\[\s*([^\]]+?)\s*\]\s*(?:#.*)?$/;
/** `key = "value"`, ignoring a trailing comment. Only double-quoted scalars. */
const STRING_KV_RE = /^([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"\s*(?:#.*)?$/;

/**
 * Select `[build].source_sha` from the release record's text.
 *
 * Throws `ReleaseRecordError` when the section is absent, the key is absent,
 * the key appears twice in `[build]`, or the value is not a full 40-hex commit
 * id. Every one of those is a build failure, never a fallback.
 */
export function selectBuildSourceSha(toml: string): string {
  let section = "";
  let found: string | null = null;
  const lines = toml.split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const sec = SECTION_RE.exec(line);
    if (sec !== null) {
      section = sec[1];
      continue;
    }
    if (section !== "build") continue;
    const kv = STRING_KV_RE.exec(line);
    if (kv === null || kv[1] !== "source_sha") continue;
    if (found !== null) {
      throw new ReleaseRecordError(
        "release record declares [build].source_sha more than once; refusing to guess",
      );
    }
    found = kv[2];
  }
  if (found === null) {
    throw new ReleaseRecordError(
      "release record has no [build].source_sha; the canister build source cannot be identified",
    );
  }
  if (!FULL_COMMIT_ID.test(found)) {
    throw new ReleaseRecordError(
      `[build].source_sha is not a full 40-hex commit id: ${JSON.stringify(found)}`,
    );
  }
  return found;
}

/**
 * The COMPLETE set of release-record-derived values injected into the bundle.
 *
 * I2 depends on this being the whole injection surface: nothing else from the
 * record reaches the emitted assets, so perturbing any `[wallet_bundle]` field
 * cannot change a byte. The pin-independence test asserts exactly that by
 * comparing this map across a perturbed record.
 */
export function buildReleaseDefines(toml: string): Record<string, string> {
  return { [BUILD_SOURCE_DEFINE]: JSON.stringify(selectBuildSourceSha(toml)) };
}
