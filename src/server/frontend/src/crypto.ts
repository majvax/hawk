// The WebCrypto building blocks end-to-end encryption is made of, in the
// exact forms the relay (relay/src/e2e.rs) and the machine
// (src/service/e2e.cpp) expect: P-256 keys as uncompressed points, ECDSA
// signatures as r || s, AES-256-GCM, HKDF and HMAC over SHA-256.

const subtle = (): SubtleCrypto => {
  // Only exposed in a secure context (HTTPS or localhost).
  if (globalThis.crypto?.subtle === undefined) {
    throw new Error("this page must be served over HTTPS for end-to-end encryption");
  }
  return globalThis.crypto.subtle;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const utf8 = (text: string): Uint8Array<ArrayBuffer> => encoder.encode(text);
export const fromUtf8 = (bytes: Uint8Array): string => decoder.decode(bytes);

export function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function randomBytes(count: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(count));
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return difference === 0;
}

// --- Base64 ------------------------------------------------------------------

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// --- Hashes and key derivation ----------------------------------------------------

export async function sha256(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle().digest("SHA-256", data));
}

export async function hkdf(
  ikm: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
  info: string,
  length: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const key = await subtle().importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle().deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: utf8(info) }, key, length * 8);
  return new Uint8Array(bits);
}

export async function pbkdf2(
  password: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const key = await subtle().importKey("raw", utf8(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle().deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
  return new Uint8Array(bits);
}

export async function hmac(key: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const imported = await subtle().importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle().sign("HMAC", imported, data));
}

// --- AES-256-GCM -----------------------------------------------------------------

export async function aesKey(raw: Uint8Array<ArrayBuffer>, usages: KeyUsage[] = ["encrypt", "decrypt"]): Promise<CryptoKey> {
  return subtle().importKey("raw", raw, "AES-GCM", false, usages);
}

export async function aesEncrypt(
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  plaintext: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, plaintext));
}

// Throws when the ciphertext or its associated data were tampered with.
export async function aesDecrypt(
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv, additionalData: aad }, key, ciphertext));
}

// iv(12) || ciphertext, under a fresh random IV: for one-off seals like
// the wrapped identity key.
export async function seal(
  key: CryptoKey,
  plaintext: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const iv = randomBytes(12);
  return concat(iv, await aesEncrypt(key, iv, plaintext, aad));
}

export async function unseal(
  key: CryptoKey,
  sealed: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (sealed.length < 12 + 16) throw new Error("sealed data is too short");
  return aesDecrypt(key, sealed.slice(0, 12), sealed.slice(12), aad);
}

// --- P-256 -----------------------------------------------------------------------

const ECDSA = { name: "ECDSA", namedCurve: "P-256" } as const;
const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;

export function isPublicKey(bytes: Uint8Array): boolean {
  return bytes.length === 65 && bytes[0] === 0x04;
}

// A new identity key. Extractable only so its private half can be wrapped
// under the password once; what's kept in the browser is a non-extractable
// copy (see keys.ts).
export async function generateSigningKey(): Promise<CryptoKeyPair> {
  return subtle().generateKey(ECDSA, true, ["sign", "verify"]);
}

export async function exportPublicKey(key: CryptoKey): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle().exportKey("raw", key));
}

export async function exportPrivateKey(key: CryptoKey): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle().exportKey("pkcs8", key));
}

export async function importSigningKey(pkcs8: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return subtle().importKey("pkcs8", pkcs8, ECDSA, false, ["sign"]);
}

export async function sign(key: CryptoKey, statement: string): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle().sign({ name: "ECDSA", hash: "SHA-256" }, key, utf8(statement)));
}

export async function verify(publicKey: Uint8Array<ArrayBuffer>, statement: string, signature: Uint8Array<ArrayBuffer>): Promise<boolean> {
  if (!isPublicKey(publicKey) || signature.length !== 64) return false;
  try {
    const key = await subtle().importKey("raw", publicKey, ECDSA, false, ["verify"]);
    return await subtle().verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, utf8(statement));
  } catch {
    return false;
  }
}

// A one-off key-exchange key; the private half never leaves this tab.
export async function generateExchangeKey(): Promise<CryptoKeyPair> {
  return subtle().generateKey(ECDH, false, ["deriveBits"]);
}

// The x coordinate of the shared point, 32 bytes.
export async function exchange(privateKey: CryptoKey, peer: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  if (!isPublicKey(peer)) throw new Error("not a P-256 public key");
  const peerKey = await subtle().importKey("raw", peer, ECDH, false, []);
  return new Uint8Array(await subtle().deriveBits({ name: "ECDH", public: peerKey }, privateKey, 256));
}

// --- Statements and fingerprints ---------------------------------------------------

// A signed statement: a context line, then key=value lines, joined with
// "\n". Verifiers parse the signed text itself.
export function statement(context: string, fields: [string, string][]): string {
  return [context, ...fields.map(([key, value]) => `${key}=${value}`)].join("\n");
}

// The fields of a statement with this context; null if it has another
// context, a malformed line or a repeated key.
export function parseStatement(text: string, context: string): Map<string, string> | null {
  const [first, ...lines] = text.split("\n");
  if (first !== context) return null;
  const fields = new Map<string, string>();
  for (const line of lines) {
    const at = line.indexOf("=");
    if (at < 0) return null;
    const key = line.slice(0, at);
    if (fields.has(key)) return null;
    fields.set(key, line.slice(at + 1));
  }
  return fields;
}

// What people compare out of band to be sure a key is the one they expect:
// the first 16 bytes of its SHA-256, as 8 groups of 4 hex digits. The
// machine prints its own the same way.
export async function fingerprint(publicKey: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = await sha256(publicKey);
  const hex = Array.from(digest.slice(0, 16), (byte) => byte.toString(16).padStart(2, "0").toUpperCase()).join("");
  return hex.match(/.{4}/g)?.join(" ") ?? hex;
}
