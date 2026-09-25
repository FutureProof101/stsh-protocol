/**
 * L4 low-memory / mobile test — Argon2id needs a 64 MiB WASM allocation, which
 * can fail on constrained mobile browsers. The ruled behavior is FAIL CLOSED:
 * a typed KdfUnavailableError, no PBKDF2 fallback, no reduced-parameter retry,
 * and nothing persisted. Isolated in its own file because it mocks hash-wasm.
 */

import { describe, expect, it, vi } from "vitest";
import { Ed25519KeyIdentity } from "@dfinity/identity";

vi.mock("hash-wasm", () => ({
  argon2id: vi.fn(async () => {
    throw new RangeError("WebAssembly.Memory(): could not allocate memory");
  }),
}));

import { argon2id } from "hash-wasm"; // the mock above
import {
  ARGON2ID_ITERATIONS,
  ARGON2ID_KEY_BYTES,
  ARGON2ID_MEMORY_KIB,
  ARGON2ID_PARALLELISM,
  KdfUnavailableError,
  PrincipalNoteCache,
} from "../src/storage/noteCache";
import { memoryHarness, testBinding } from "./helpers/cacheL4";

const PRINCIPAL = Ed25519KeyIdentity.generate(new Uint8Array(32).fill(21))
  .getPrincipal()
  .toText();

describe("L4 low-memory device (KDF allocation failure)", () => {
  it("open() fails closed with a typed error; nothing is persisted; parameters are never downgraded", async () => {
    const h = await memoryHarness();

    const failure = await PrincipalNoteCache.open(
      h.store,
      "any passphrase",
      testBinding(PRINCIPAL),
    ).then(
      () => null,
      (e: unknown) => e,
    );

    expect(failure).toBeInstanceOf(KdfUnavailableError);
    expect((failure as KdfUnavailableError).name).toBe("KdfUnavailableError");
    // Fail closed: no record was created for the principal.
    expect(await h.readSlot(PRINCIPAL)).toBeNull();

    // Exactly ONE attempt, with exactly the PINNED parameters — no silent
    // retry at weaker settings, no PBKDF2 fallback.
    expect(argon2id).toHaveBeenCalledTimes(1);
    expect(argon2id).toHaveBeenCalledWith(
      expect.objectContaining({
        memorySize: ARGON2ID_MEMORY_KIB,
        iterations: ARGON2ID_ITERATIONS,
        parallelism: ARGON2ID_PARALLELISM,
        hashLength: ARGON2ID_KEY_BYTES,
        outputType: "binary",
      }),
    );
  });
});
