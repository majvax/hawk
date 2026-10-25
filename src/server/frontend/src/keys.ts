// The account side of end-to-end encryption: turning a password into what
// the relay is sent, and the identity key every signature comes from.
//
// The password never leaves this tab. It's stretched (PBKDF2) into a master
// key, and two keys are drawn from that with HKDF:
//
// - the auth key, which is what's sent as "password" and what the relay
//   hashes, so a relay that keeps or leaks it learns nothing it could unlock
//   the identity key with;
// - the wrapping key, which encrypts the identity key's private half before
//   it's stored on the relay, so any browser can recover it with the
//   password, and the relay can't.
//
// Once unlocked, the identity key is kept in this browser as a
// non-extractable key (keystore.ts) until logout.

import * as api from "./api.js";
import {
  aesKey,
  exportPrivateKey,
  exportPublicKey,
  fromBase64,
  generateSigningKey,
  hkdf,
  importSigningKey,
  pbkdf2,
  seal,
  sha256,
  toBase64,
  toBase64Url,
  unseal,
  utf8,
} from "./crypto.js";
import { type StoredIdentity, forgetIdentity, loadIdentity, saveIdentity } from "./keystore.js";
import { getPasskey, passkeysUsable } from "./webauthn.js";

export type Identity = StoredIdentity;

// What new and upgraded accounts are stretched with; mirrors
// relay api::DEFAULT_ITERATIONS. Existing accounts keep theirs.
const DEFAULT_ITERATIONS = 600_000;
const WRAP_AAD = utf8("hawk-user-key-v1");
const NO_SALT = new Uint8Array(0);

// Mirrors relay auth::normalize_email, so the salt is the same whatever
// case the email is typed in.
const normalizeEmail = (email: string): string => email.trim().toLowerCase();

interface Stretched {
  authKey: string;
  wrapKey: CryptoKey;
}

async function stretch(password: string, email: string, iterations: number): Promise<Stretched> {
  const salt = await sha256(utf8(`hawk-login-salt-v1\0${normalizeEmail(email)}`));
  const master = await pbkdf2(password, salt, iterations);
  const authKey = toBase64Url(await hkdf(master, NO_SALT, "hawk-auth-v1", 32));
  const wrapKey = await aesKey(await hkdf(master, NO_SALT, "hawk-wrap-v1", 32));
  return { authKey, wrapKey };
}

// Keeps the identity key in this browser, non-extractable from here on.
async function remember(user: api.User, pkcs8: Uint8Array<ArrayBuffer>, publicKey: Uint8Array<ArrayBuffer>): Promise<Identity> {
  const identity: Identity = { userId: user.id, email: user.email, privateKey: await importSigningKey(pkcs8), publicKey };
  await saveIdentity(identity);
  return identity;
}

// A fresh identity key, wrapped under `wrapKey` for the relay to store.
async function newIdentityKey(wrapKey: CryptoKey): Promise<{
  pkcs8: Uint8Array<ArrayBuffer>;
  publicKey: Uint8Array<ArrayBuffer>;
  upload: Omit<api.KeyUpload, "iterations">;
}> {
  const pair = await generateSigningKey();
  const pkcs8 = await exportPrivateKey(pair.privateKey);
  const publicKey = await exportPublicKey(pair.publicKey);
  const wrapped = await seal(wrapKey, pkcs8, WRAP_AAD);
  return { pkcs8, publicKey, upload: { publicKey: toBase64(publicKey), wrappedKey: toBase64(wrapped) } };
}

// Fetches the account's wrapped identity key and opens it. A wrong
// password fails here, on the GCM tag.
async function unwrapStored(user: api.User, wrapKey: CryptoKey): Promise<Identity> {
  const stored = await api.getAccountKey();
  let pkcs8: Uint8Array<ArrayBuffer>;
  try {
    pkcs8 = await unseal(wrapKey, fromBase64(stored.wrappedKey), WRAP_AAD);
  } catch {
    throw new Error("wrong password");
  }
  return remember(user, pkcs8, fromBase64(stored.publicKey));
}

// A legacy account, whose password the relay checks as is: proves it with
// the password one last time, and moves it to a derived auth key and a new
// identity key.
async function upgrade(user: api.User, password: string): Promise<Identity> {
  const { authKey, wrapKey } = await stretch(password, user.email, DEFAULT_ITERATIONS);
  const key = await newIdentityKey(wrapKey);
  await api.upgradeAccount(password, authKey, { ...key.upload, iterations: DEFAULT_ITERATIONS });
  return remember(user, key.pkcs8, key.publicKey);
}

export type Entered = { user: api.User; identity: Identity };

// What a correct password leads to: in, or for an account with a second
// factor, a code to enter first, or a passkey to use when the account has
// one this page can ask for. Both keep what the password unlocked in memory
// until then.
export type LoginStep =
  | { kind: "entered"; entered: Entered }
  | {
      kind: "code";
      finish: (code: string) => Promise<Entered>;
      withPasskey: (() => Promise<Entered>) | null;
      // The account has a passkey, but not one this page can use (the
      // desktop app, a dashboard outside the relay's domain).
      passkeyElsewhere: boolean;
    };

export async function logIn(email: string, password: string): Promise<LoginStep> {
  const params = await api.loginParams(email);
  const legacy = params.kdf === "legacy";
  const stretched = legacy ? null : await stretch(password, email, params.iterations);
  const enter = (user: api.User): Promise<Entered> =>
    (stretched === null ? upgrade(user, password) : unwrapStored(user, stretched.wrapKey)).then((identity) => ({
      user,
      identity,
    }));
  const result = await api.login(email, stretched?.authKey ?? password);
  if (!("mfaRequired" in result)) return { kind: "entered", entered: await enter(result) };
  const { ticket, passkeyRpId } = result;
  const usable = passkeysUsable(passkeyRpId);
  return {
    kind: "code",
    finish: async (code) => enter(await api.loginMfa(ticket, { code })),
    withPasskey: usable
      ? async () => {
          const passkey = await getPasskey(await api.loginPasskeyChallenge(ticket));
          return enter(await api.loginMfa(ticket, { passkey }));
        }
      : null,
    passkeyElsewhere: passkeyRpId !== null && !usable,
  };
}

// The derived auth key, which is what confirms an action with the password
// (adding the first second factor).
export async function authKeyFor(user: api.User, password: string): Promise<string> {
  const params = await api.loginParams(user.email);
  if (params.kdf === "legacy") return password;
  return (await stretch(password, user.email, params.iterations)).authKey;
}

// Signed in, but this browser doesn't hold the identity key (cleared site
// data, or a session from before keys existed): the password opens it.
export async function unlock(user: api.User, password: string): Promise<Identity> {
  const params = await api.loginParams(user.email);
  if (params.kdf === "legacy") return upgrade(user, password);
  const { wrapKey } = await stretch(password, user.email, params.iterations);
  return unwrapStored(user, wrapKey);
}

export async function signUp(
  token: string,
  email: string,
  password: string,
): Promise<{ user: api.User; identity: Identity }> {
  const { authKey, wrapKey } = await stretch(password, email, DEFAULT_ITERATIONS);
  const key = await newIdentityKey(wrapKey);
  const user = await api.signup(token, email, authKey, { ...key.upload, iterations: DEFAULT_ITERATIONS });
  return { user, identity: await remember(user, key.pkcs8, key.publicKey) };
}

// Re-wraps the identity key under the new password; the key itself, and
// everything signed with it, stays as it was.
export async function changePassword(user: api.User, current: string, next: string): Promise<void> {
  const params = await api.loginParams(user.email);
  const old = await stretch(current, user.email, params.iterations);
  const stored = await api.getAccountKey();
  let pkcs8: Uint8Array<ArrayBuffer>;
  try {
    pkcs8 = await unseal(old.wrapKey, fromBase64(stored.wrappedKey), WRAP_AAD);
  } catch {
    throw new Error("current password is incorrect");
  }
  const renewed = await stretch(next, user.email, params.iterations);
  const wrapped = await seal(renewed.wrapKey, pkcs8, WRAP_AAD);
  await api.changePassword(old.authKey, renewed.authKey, toBase64(wrapped));
}

export const currentIdentity = (user: api.User): Promise<Identity | null> => loadIdentity(user.id);

export async function logOut(): Promise<void> {
  try {
    await forgetIdentity();
  } finally {
    await api.logout();
  }
}
