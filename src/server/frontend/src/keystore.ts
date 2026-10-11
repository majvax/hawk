// What this browser keeps for end-to-end encryption, in IndexedDB:
//
// - the signed-in account's identity key, as a non-extractable CryptoKey:
//   scripts on this page can sign with it but never read it out;
// - enrollment codes this browser made, until the machine using them shows
//   up and its key has been checked against the code;
// - other accounts' identity keys as first seen (trust on first use), so a
//   key that changes later is noticed instead of silently trusted.
//
// Everything here is per browser and per origin. Nothing in it is needed to
// recover the account: the identity key is also stored on the relay,
// encrypted under the password.

const DB_NAME = "hawk-keys";
const DB_VERSION = 1;

export interface StoredIdentity {
  userId: number;
  email: string;
  privateKey: CryptoKey;
  publicKey: Uint8Array<ArrayBuffer>;
}

interface PendingEnrollment {
  codeHash: string;
  code: string;
  createdAt: number;
}

interface Contact {
  email: string;
  publicKey: Uint8Array<ArrayBuffer>;
  // Compared out of band with the person, rather than just first seen.
  verified: boolean;
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      db.createObjectStore("identity");
      db.createObjectStore("enrollments", { keyPath: "codeHash" });
      db.createObjectStore("contacts", { keyPath: "email" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("can't open this browser's key store"));
  });
}

async function run<T>(store: string, mode: IDBTransactionMode, action: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const transaction = db.transaction(store, mode);
      const request = action(transaction.objectStore(store));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () => reject(transaction.error ?? new Error("key store request failed"));
      transaction.onabort = () => reject(transaction.error ?? new Error("key store request aborted"));
    });
  } finally {
    db.close();
  }
}

// --- Identity ----------------------------------------------------------------------

export async function loadIdentity(userId: number): Promise<StoredIdentity | null> {
  const stored = (await run("identity", "readonly", (store) => store.get("self"))) as StoredIdentity | undefined;
  return stored !== undefined && stored.userId === userId ? stored : null;
}

export async function saveIdentity(identity: StoredIdentity): Promise<void> {
  await run("identity", "readwrite", (store) => store.put(identity, "self"));
}

export async function forgetIdentity(): Promise<void> {
  await run("identity", "readwrite", (store) => store.delete("self"));
}

// --- Enrollment codes ------------------------------------------------------------------

// Longer than an enrollment code lives, so a slow install still gets checked.
const ENROLLMENT_KEEP_MS = 7 * 24 * 60 * 60 * 1000;

export async function savePendingEnrollment(codeHash: string, code: string): Promise<void> {
  const entry: PendingEnrollment = { codeHash, code, createdAt: Date.now() };
  await run("enrollments", "readwrite", (store) => store.put(entry));
}

export async function pendingEnrollment(codeHash: string): Promise<string | null> {
  const entry = (await run("enrollments", "readonly", (store) => store.get(codeHash))) as PendingEnrollment | undefined;
  if (entry === undefined || Date.now() - entry.createdAt > ENROLLMENT_KEEP_MS) return null;
  return entry.code;
}

export async function forgetPendingEnrollment(codeHash: string): Promise<void> {
  await run("enrollments", "readwrite", (store) => store.delete(codeHash));
}

// --- Other accounts' keys ------------------------------------------------------------------

export type PinStatus =
  | { kind: "new" } // first seen just now, and pinned
  | { kind: "known"; verified: boolean } // the same key as before
  | { kind: "changed"; pinned: Uint8Array<ArrayBuffer> }; // not the key first seen: someone may be in the middle

function sameKey(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

// Checks `publicKey` against the one first seen for `email`, pinning it if
// there was none.
export async function checkContact(email: string, publicKey: Uint8Array<ArrayBuffer>): Promise<PinStatus> {
  const contact = (await run("contacts", "readonly", (store) => store.get(email))) as Contact | undefined;
  if (contact === undefined) {
    await run("contacts", "readwrite", (store) => store.put({ email, publicKey, verified: false } satisfies Contact));
    return { kind: "new" };
  }
  if (sameKey(contact.publicKey, publicKey)) return { kind: "known", verified: contact.verified };
  return { kind: "changed", pinned: contact.publicKey };
}

// The person confirmed out of band that this is their key, replacing
// whatever was pinned for them.
export async function trustContact(email: string, publicKey: Uint8Array<ArrayBuffer>, verified: boolean): Promise<void> {
  await run("contacts", "readwrite", (store) => store.put({ email, publicKey, verified } satisfies Contact));
}
