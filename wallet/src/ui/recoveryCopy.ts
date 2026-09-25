/**
 * STSH — the binding user-facing wording for revocation and key compromise
 * (D-1b v3 §1 as CORRECTED by v4 §1; SSA GREEN 2026-08-27).
 *
 * This file exists as its own module because the wording is a RULING, not a
 * design choice, and because a string test can then assert it directly. Two
 * things must never be conflated, and this is where that is enforced:
 *
 *   SERVICE CUTOFF — revoking a device stops the canister serving it: its
 *   envelope is deleted, its reads are refused, and it can no longer approve
 *   anything. That is real, and it is all revocation is.
 *
 *   CRYPTOGRAPHIC RECOVERY — an attacker who copied a device's envelope BEFORE
 *   revocation and can still use that device's private key recovers the RAW
 *   vetKey. That key trial-decrypts every payload addressed to the principal,
 *   INCLUDING FUTURE ones, and the derivation namespace cannot be rotated.
 *   Revocation does not touch this.
 *
 * WHY SELF-SPEND IS NOT A REMEDY (v4 §1, SSA RED-5): a same-principal
 * spend-to-self re-addresses the value to the SAME IBE identity, so the
 * captured vetKey decrypts the new payload too. Fresh note randomness does not
 * repair a compromised outer identity. Nothing in this product may describe it
 * as a fix.
 */

/** What revoking a device actually does. Service cutoff, named as such. */
export const REVOCATION_SERVICE_CUTOFF =
  "Revoking this device is a service cutoff: the key service deletes this device's " +
  "stored key envelope, stops answering its requests, and will not accept it to approve " +
  "another device. It takes effect immediately.";

/**
 * What revoking a device does NOT do. This paragraph is the honest half and
 * must never be softened or dropped.
 */
export const REVOCATION_NOT_CRYPTOGRAPHIC_RECOVERY =
  "Revoking a device is not cryptographic recovery. If someone copied this device's key " +
  "envelope before you revoked it and can still use the device's private key, they can " +
  "recover your account key — which reads every note addressed to this identity, " +
  "including notes you receive in future. Revoking the device does not undo that.";

/**
 * The remedy that actually works, per the ruling: move to a FRESH Internet
 * Identity. Numbered because the order is load-bearing — value must land and be
 * verified under the new identity before anything is retired.
 */
export const COMPROMISE_MIGRATION_STEPS: readonly string[] = [
  "Create a new Internet Identity on a device you trust, and set up this wallet on it.",
  "Send all of your value from this identity to the new one.",
  "Open the new identity and confirm the notes are there before you rely on it.",
  "Once the new identity has everything, revoke every device on the old identity and stop " +
    "using it to receive anything.",
];

/** The heading that introduces the ceremony above. */
export const COMPROMISE_MIGRATION_HEADING =
  "If you think your account key was copied, move to a new identity";

/**
 * Why the ceremony is the migration rather than a self-send. Stated to the user
 * because a plausible-sounding wrong action is worse than no suggestion.
 */
export const COMPROMISE_SELF_SPEND_IS_NOT_A_REMEDY =
  "Sending funds to yourself on the same identity does not help: the new notes are " +
  "addressed to the same identity, so a copied account key reads those too.";

/**
 * Shown when the product cannot yet carry the user through the ceremony. The
 * ruling forbids implying a protection that does not exist, so this says the
 * plain thing instead.
 */
export const COMPROMISE_NO_IN_PRODUCT_CUTOFF =
  "This wallet has no way to cut off a copied account key. The only safe path is to move " +
  "your value to a new identity, as described above.";

/**
 * L04-07 (R-8) — the LAST-DEVICE warning.
 *
 * The canister's rule, said plainly: once every device of an identity is
 * revoked, that identity cannot enrol another one. Revocation retains the
 * device record, so the key service can tell "revoked to zero" apart from
 * "never enrolled" and refuses the second bootstrap — which is the point, since
 * otherwise whoever holds the Internet Identity (including whoever took it)
 * could simply enrol a fresh device and undo the revocation.
 *
 * The escape hatch has to be created BEFORE the last revocation, by a device
 * that is still active. A user who is not told this in advance discovers it at
 * the exact moment it is too late to act on, which is why the warning belongs
 * on the account surface and not in a confirmation dialog nobody reaches.
 *
 * WHAT IT MUST NOT DO (SSA landed-diff R-8 V1, AMBER-4; CTO ruling
 * cto-ruling-r8-landed-diff-fix-wave-2026-09-06 item 5): instruct an action
 * this wallet cannot perform. The V1 copy ended "authorise that from a device
 * that is still active BEFORE you revoke it" — but `authorize_re_bootstrap`
 * has NO wallet binding (`wallet/src` contains zero references to it), so the
 * sentence pointed the user at a canister call they have no way to make. A
 * warning that ends in a dead end is worse than one that stops at the fact,
 * because the user believes a remedy exists. The copy now states the
 * permanence and names the requirement WITHOUT instructing it, and says
 * plainly that this version does not offer it.
 */
export const LAST_DEVICE_REVOCATION_IS_FINAL =
  "Revoking your last device is permanent: once no device is left, this identity cannot " +
  "set up a new one. Re-enabling setup needs a signed approval from a device that is " +
  "still active, which this wallet version does not yet offer.";

/** Migration is not complete until BOTH halves are true. */
export interface MigrationProgress {
  /** Every spendable note and pending obligation has left the old principal. */
  oldValueSpent: boolean;
  /** The NEW identity has scanned and recovered the migrated notes. */
  newIdentityRecoveryVerified: boolean;
}

/**
 * Whether the fresh-identity migration may be reported complete.
 *
 * Both conditions, deliberately: reporting completion after the spend but
 * before recovery is verified is how a user retires the old identity while the
 * value is unreachable under the new one.
 */
export function migrationIsComplete(progress: MigrationProgress): boolean {
  return progress.oldValueSpent && progress.newIdentityRecoveryVerified;
}

/** The status line for an in-progress migration — never claims more than is true. */
export function migrationStatusLine(progress: MigrationProgress): string {
  if (migrationIsComplete(progress)) {
    return "Migration complete: your value is on the new identity and has been verified there.";
  }
  if (progress.oldValueSpent && !progress.newIdentityRecoveryVerified) {
    return (
      "Migration is not complete yet: the funds have been sent, but the new identity has " +
      "not confirmed it can see them. Open the new identity and check before you retire " +
      "this one."
    );
  }
  if (!progress.oldValueSpent && progress.newIdentityRecoveryVerified) {
    return (
      "Migration is not complete yet: some value is still on this identity. Finish sending " +
      "it to the new identity."
    );
  }
  return "Migration has not started.";
}
