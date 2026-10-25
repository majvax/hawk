// Passkeys (WebAuthn) as a second factor (relay/src/passkeys.rs). The relay
// sends its challenge as JSON with every binary field in base64url, and
// takes the browser's answer back the same way; navigator.credentials wants
// and gives ArrayBuffers. The conversions here are pure and tested; the
// browser's own parseCreationOptionsFromJSON / toJSON are used where they
// exist, with these as the fallback.

type Json = string | number | boolean | null | Json[] | { [key: string]: Json };
type JsonObject = { [key: string]: Json };

// What the relay sends: the options for navigator.credentials.create and
// .get, under publicKey, in their JSON form.
export interface CreationOptionsJson {
  publicKey: JsonObject;
}

export interface RequestOptionsJson {
  publicKey: JsonObject;
}

export function bytesToBase64Url(bytes: ArrayBuffer | ArrayBufferView): string {
  const view =
    bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let binary = "";
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Standard base64 is taken too, and padding is optional.
export function base64UrlToBytes(text: string): Uint8Array<ArrayBuffer> {
  const standard = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(standard + "=".repeat((4 - (standard.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// The relay leaves out what it doesn't set, but a nested null would still be
// a TypeError to the browser.
export function withoutNulls<T extends Json>(value: T): T {
  if (Array.isArray(value)) return value.map((item) => withoutNulls(item)) as T;
  if (value === null || typeof value !== "object") return value;
  const out: JsonObject = {};
  for (const [key, item] of Object.entries(value)) if (item !== null) out[key] = withoutNulls(item);
  return out as T;
}

const text = (value: Json | undefined): string => (typeof value === "string" ? value : "");

function descriptors(list: Json | undefined): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return list.map((item) => {
    const descriptor = item as JsonObject;
    const transports = Array.isArray(descriptor.transports) ? (descriptor.transports as AuthenticatorTransport[]) : undefined;
    return {
      type: "public-key",
      id: base64UrlToBytes(text(descriptor.id)),
      ...(transports === undefined ? {} : { transports }),
    };
  });
}

// The fallback for PublicKeyCredential.parseCreationOptionsFromJSON: the
// same fields, with the binary ones decoded.
export function creationOptionsFromJson(json: CreationOptionsJson): PublicKeyCredentialCreationOptions {
  const options = withoutNulls(json.publicKey);
  const user = options.user as JsonObject;
  return {
    ...(options as unknown as PublicKeyCredentialCreationOptions),
    challenge: base64UrlToBytes(text(options.challenge)),
    user: { ...(user as unknown as PublicKeyCredentialUserEntity), id: base64UrlToBytes(text(user.id)) },
    excludeCredentials: descriptors(options.excludeCredentials),
  };
}

// The fallback for PublicKeyCredential.parseRequestOptionsFromJSON.
export function requestOptionsFromJson(json: RequestOptionsJson): PublicKeyCredentialRequestOptions {
  const options = withoutNulls(json.publicKey);
  return {
    ...(options as unknown as PublicKeyCredentialRequestOptions),
    challenge: base64UrlToBytes(text(options.challenge)),
    allowCredentials: descriptors(options.allowCredentials),
  };
}

// The parts of a PublicKeyCredential the answers are made of, so tests can
// hand in plain objects.
export interface CredentialLike {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  response: {
    clientDataJSON: ArrayBuffer;
    attestationObject?: ArrayBuffer;
    getTransports?: () => string[];
    authenticatorData?: ArrayBuffer;
    signature?: ArrayBuffer;
    userHandle?: ArrayBuffer | null;
  };
  getClientExtensionResults?: () => AuthenticationExtensionsClientOutputs;
}

// The fallback for PublicKeyCredential.toJSON: the registration's or the
// assertion's fields, binary as base64url, as the relay reads them.
export function credentialToJson(credential: CredentialLike): JsonObject {
  const { response } = credential;
  const out: JsonObject = { clientDataJSON: bytesToBase64Url(response.clientDataJSON) };
  if (response.attestationObject !== undefined) {
    out.attestationObject = bytesToBase64Url(response.attestationObject);
    out.transports = response.getTransports?.() ?? [];
  }
  if (response.authenticatorData !== undefined) out.authenticatorData = bytesToBase64Url(response.authenticatorData);
  if (response.signature !== undefined) out.signature = bytesToBase64Url(response.signature);
  if (response.userHandle !== undefined && response.userHandle !== null) {
    out.userHandle = bytesToBase64Url(response.userHandle);
  }
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: out,
    clientExtensionResults: (credential.getClientExtensionResults?.() ?? {}) as JsonObject,
  };
}

// Whether a page on `hostname` may use passkeys for `rpId`: the browser
// only allows the RP ID itself or a domain under it.
export function hostWithin(hostname: string, rpId: string): boolean {
  const host = hostname.toLowerCase();
  const id = rpId.toLowerCase();
  return host === id || host.endsWith(`.${id}`);
}

export interface PasskeyEnvironment {
  inApp: boolean;
  hostname: string;
  secure: boolean;
  supported: boolean;
}

function environment(): PasskeyEnvironment {
  return {
    inApp: "__TAURI_INTERNALS__" in window, // as desktop.ts tells
    hostname: window.location.hostname,
    secure: window.isSecureContext,
    supported: typeof window.PublicKeyCredential === "function" && navigator.credentials !== undefined,
  };
}

// Whether to offer passkeys here at all: the relay has them on (`rpId`), this
// browser has WebAuthn, and this page is under the RP ID. Never in the
// desktop app: its page lives at tauri.localhost (or tauri://localhost),
// which no relay's passkeys can be bound to.
export function passkeysUsable(rpId: string | null, env: PasskeyEnvironment = environment()): boolean {
  return rpId !== null && !env.inApp && env.secure && env.supported && hostWithin(env.hostname, rpId);
}

// Thrown when the user closed the browser's prompt, or let it time out.
export class PasskeyCancelled extends Error {
  constructor() {
    super("cancelled: no passkey was used");
  }
}

// The browser's errors in words; NotAllowedError (cancelled, timed out, or
// no matching passkey on this device) becomes PasskeyCancelled.
export function passkeyError(error: unknown): Error {
  if (!(error instanceof DOMException)) return error instanceof Error ? error : new Error("the passkey didn't work");
  switch (error.name) {
    case "NotAllowedError":
    case "AbortError":
      return new PasskeyCancelled();
    case "InvalidStateError":
      return new Error("this passkey is already registered on your account");
    case "SecurityError":
      return new Error("this page isn't allowed to use this server's passkeys");
    default:
      return new Error(error.message || "the passkey didn't work");
  }
}

interface ParsingCredential {
  parseCreationOptionsFromJSON?: (options: JsonObject) => PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON?: (options: JsonObject) => PublicKeyCredentialRequestOptions;
}

function serialize(credential: Credential | null): JsonObject {
  if (credential === null) throw new PasskeyCancelled();
  const withJson = credential as Credential & { toJSON?: () => JsonObject };
  if (typeof withJson.toJSON === "function") {
    try {
      return withJson.toJSON();
    } catch {
      // some browsers have it but choke on extension results: do it by hand
    }
  }
  return credentialToJson(credential as unknown as CredentialLike);
}

// Makes a passkey for the relay's challenge; resolves to its answer as JSON.
export async function createPasskey(json: CreationOptionsJson): Promise<JsonObject> {
  const parser = window.PublicKeyCredential as unknown as ParsingCredential;
  let publicKey: PublicKeyCredentialCreationOptions;
  try {
    publicKey = parser.parseCreationOptionsFromJSON?.(withoutNulls(json.publicKey)) ?? creationOptionsFromJson(json);
  } catch {
    publicKey = creationOptionsFromJson(json);
  }
  try {
    return serialize(await navigator.credentials.create({ publicKey }));
  } catch (error) {
    throw passkeyError(error);
  }
}

// Asks one of the account's passkeys to answer the relay's challenge.
export async function getPasskey(json: RequestOptionsJson): Promise<JsonObject> {
  const parser = window.PublicKeyCredential as unknown as ParsingCredential;
  let publicKey: PublicKeyCredentialRequestOptions;
  try {
    publicKey = parser.parseRequestOptionsFromJSON?.(withoutNulls(json.publicKey)) ?? requestOptionsFromJson(json);
  } catch {
    publicKey = requestOptionsFromJson(json);
  }
  try {
    return serialize(await navigator.credentials.get({ publicKey }));
  } catch (error) {
    throw passkeyError(error);
  }
}
