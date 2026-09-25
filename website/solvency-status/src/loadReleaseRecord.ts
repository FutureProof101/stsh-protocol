/**
 * Node-side (build-time) loader for the release record. Imported by
 * `vite.config.ts` and `vitest.config.ts` ONLY — never by browser code, which
 * receives the single injected define instead.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { buildReleaseDefines, ReleaseRecordError } from "./releaseRecord";

const RECORD_REL = "deployment/mainnet/release_hashes.toml";

/**
 * Locate `deployment/mainnet/release_hashes.toml` by walking UP from the
 * current working directory.
 *
 * Not `import.meta.url`: under vitest's jsdom environment that is an http URL,
 * not a file one. Not a fixed relative path either: `npm run build` runs from
 * `wallet/` while other invocations run from the repository root. The walk is
 * deterministic and stops at the filesystem root, and a record that is not
 * found is an error, never a default.
 */
function findRecord(): string {
  let dir = process.cwd();
  for (;;) {
    const candidate = resolve(dir, RECORD_REL);
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) {
      throw new ReleaseRecordError(
        `cannot locate ${RECORD_REL} from ${process.cwd()} or any ancestor`,
      );
    }
    dir = parent;
  }
}

export const RELEASE_RECORD_PATH = findRecord();

/** The repository root — the directory holding the located record. */
export const REPO_ROOT = resolve(RELEASE_RECORD_PATH, "../../..");

/**
 * Read the record and produce the build defines. Any failure is rethrown as a
 * `ReleaseRecordError` so the build stops with the reason (I1) — there is no
 * placeholder, no HEAD fallback and no constant.
 */
export function releaseDefines(path: string = RELEASE_RECORD_PATH): Record<string, string> {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    throw new ReleaseRecordError(
      `cannot read the release record at ${path}: ${(e as Error).message}`,
    );
  }
  return buildReleaseDefines(text);
}
