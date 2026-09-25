/**
 * STSH W-VETKEYS — this device's identity, persisted locally.
 *
 * WHAT IS STORED: the device id, the two PUBLIC keys as SPKI, and the WebCrypto
 * `CryptoKey` HANDLES for the private halves. The handles are NON-EXTRACTABLE,
 * so what IndexedDB holds is a reference the browser will use on this origin
 * and never hand back as bytes — which is exactly what the HARD RULE in
 * ./noteCache.ts permits ("non-extractable WebCrypto CryptoKey handles").
 *
 * WHAT IS NOT STORED, EVER: the vetKey, the master note secret, the passcode,
 * any cache key, or the envelope. The envelope lives canister-side; everything
 * else is memory-only and dropped on lock/logout.
 *
 * WHY THIS EXISTS AT ALL: the Layer-1 fast path needs to know WHICH registered
 * device this browser is, across sessions. Without that, every login would look
 * like a new device and would have to derive.
 */

// R-7 item 6: declared once in the registry, imported here — never locally.
// This database was invisible to `panicWipe`'s by-name list precisely because
// its name lived privately in this file.
import { DEVICE_STORE_DB_NAME } from "./dbRegistry";

const DB_VERSION = 1;
const STORE = "device";
/** One record per principal: a shared browser profile may hold several. */
type Key = string;

export interface StoredDeviceIdentity {
  deviceId: string;
  encSpki: Uint8Array;
  signSpki: Uint8Array;
  encPrivate: CryptoKey;
  signPrivate: CryptoKey;
  encPublic: CryptoKey;
  signPublic: CryptoKey;
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DEVICE_STORE_DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE)) {
        request.result.createObjectStore(STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function transact<T>(
  db: IDBDatabase,
  mode: IDBTransactionMode,
  fn: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    const request = fn(tx.objectStore(STORE));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    tx.onabort = () => reject(tx.error);
  });
}

/**
 * Load this browser's device identity for `principalText`, or null.
 *
 * Keyed by principal: two identities used in one browser profile are two
 * devices as far as the canister is concerned, and mixing them would mean
 * offering one principal's envelope to the other.
 */
export async function loadDeviceIdentity(
  principalText: Key,
): Promise<StoredDeviceIdentity | null> {
  const db = await open();
  try {
    const value = await transact<StoredDeviceIdentity | undefined>(db, "readonly", (store) =>
      store.get(principalText),
    );
    return value ?? null;
  } finally {
    db.close();
  }
}

/** Persist this browser's device identity for `principalText`. */
export async function saveDeviceIdentity(
  principalText: Key,
  identity: StoredDeviceIdentity,
): Promise<void> {
  // A defensive check, not a formality: storing an EXTRACTABLE private key
  // would turn this store into a place a private half can be read out of, which
  // the HARD RULE forbids. Refusing here is cheap; discovering it later is not.
  if (identity.encPrivate.extractable || identity.signPrivate.extractable) {
    throw new Error(
      "refusing to persist an extractable device private key — device keys must be " +
        "generated non-extractable",
    );
  }
  const db = await open();
  try {
    await transact(db, "readwrite", (store) => store.put(identity, principalText));
  } finally {
    db.close();
  }
}

/** Forget this device's identity (logout-with-forget, or after revocation). */
export async function clearDeviceIdentity(principalText: Key): Promise<void> {
  const db = await open();
  try {
    await transact(db, "readwrite", (store) => store.delete(principalText));
  } finally {
    db.close();
  }
}
