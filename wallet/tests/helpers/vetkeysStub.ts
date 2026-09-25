/**
 * A `VetkeysCanister` stub for tests that do not exercise vetKeys themselves.
 *
 * The interface widened with W-VETKEYS Layer 1 (register/revoke/envelope/list),
 * and `getEncryptedVetkey` now returns `{ encryptedKey, remaining }`. Rather
 * than teach every flow test about the whole surface, this stub supplies
 * loudly-failing defaults: an unused method THROWS with its own name, so a test
 * that unexpectedly starts calling one fails saying which — instead of silently
 * receiving an empty array and asserting on nothing.
 */

import type { VetkeysCanister } from "../../src/crypto/vetkeys";

export function vetkeysStub(overrides: Partial<VetkeysCanister> = {}): VetkeysCanister {
  const unused = (name: string) => async (): Promise<never> => {
    throw new Error(`vetkeysStub: ${name} was called but not stubbed by this test`);
  };
  return {
    getVetkeyVerificationKey: unused("getVetkeyVerificationKey"),
    getEncryptedVetkey: unused("getEncryptedVetkey"),
    getConfig: unused("getConfig"),
    registerDevice: unused("registerDevice"),
    revokeDevice: unused("revokeDevice"),
    getWrappedSecret: unused("getWrappedSecret"),
    listDevices: unused("listDevices"),
    ...overrides,
  } as VetkeysCanister;
}
