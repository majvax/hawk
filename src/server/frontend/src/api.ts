// Typed wrappers over the relay's /api routes (relay/src/api.rs). Served by
// the relay, the session lives in an HttpOnly cookie and nothing here
// touches it; a standalone dashboard keeps a bearer token instead (relay.ts).
// Nothing here sees a password either: keys.ts derives what's sent from it.

import { type ActivityFilter, type ActivityPage, activityQuery } from "./activity.js";
import { apiUrl, relayPageUrl, sessionToken, setSessionToken } from "./relay.js";

export interface User {
  id: number;
  email: string;
  isAdmin: boolean;
  mfa: boolean; // has a second factor
  emailVerified: boolean; // always true on a relay that doesn't send email
  // The admin requires a second factor and this account has none: setting
  // one up is all the relay allows until it does.
  mfaSetupRequired: boolean;
}

export interface AdminUserRow {
  id: number;
  email: string;
  isAdmin: boolean;
  disabled: boolean;
  createdAt: number; // unix seconds
  mfa: boolean;
  emailVerified: boolean;
}

export interface InviteInfo {
  grantsAdmin: boolean;
  expiresAt: number;
}

export interface PendingInvite {
  id: number;
  createdAt: number;
  expiresAt: number;
}

export interface CreatedInvite extends PendingInvite {
  token: string; // shown once; the server keeps only its hash
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    // The action needs a second factor proved in the last few minutes.
    readonly stepUp = false,
  ) {
    super(message);
  }
}

// Asks the user for a code and steps the session up; resolves false when
// they cancel. Set by the signed-in console (see StepUpProvider).
let stepUpHandler: (() => Promise<boolean>) | null = null;

export function setStepUpHandler(handler: (() => Promise<boolean>) | null): void {
  stepUpHandler = handler;
}

async function send<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  const token = sessionToken();
  if (token !== null) headers.authorization = `Bearer ${token}`;
  const response = await fetch(apiUrl(path), {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  // A sign-in from a standalone dashboard: the session to keep.
  const issued = response.headers.get("x-hawk-session");
  if (issued !== null) setSessionToken(issued);
  if (response.status === 401 && token !== null) setSessionToken(null);
  if (!response.ok) {
    let message = `request failed (${response.status})`;
    let stepUp = false;
    try {
      const payload = (await response.json()) as { error?: string; stepUp?: boolean };
      if (payload.error !== undefined) message = payload.error;
      stepUp = payload.stepUp === true;
    } catch {
      // not JSON; keep the generic message
    }
    throw new ApiError(response.status, message, stepUp);
  }
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
}

// A request that, when the relay wants a fresh second factor first, asks
// for one and tries once more.
async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  try {
    return await send<T>(method, path, body);
  } catch (error) {
    if (!(error instanceof ApiError && error.stepUp) || stepUpHandler === null) throw error;
    if (!(await stepUpHandler())) throw new ApiError(error.status, "cancelled: this needs a code from your authenticator");
    return send<T>(method, path, body);
  }
}

// Resolves to null when not logged in.
export async function getSession(): Promise<User | null> {
  try {
    return await request<User>("GET", "/api/session");
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null;
    throw error;
  }
}

// How to derive this account's keys from its password. "legacy" accounts
// still log in with the password itself until they're upgraded.
export interface LoginParams {
  kdf: "pbkdf2-sha256" | "legacy";
  iterations: number;
}

// An identity key as stored on the relay: the public half, and the private
// half encrypted under the password (base64).
export interface KeyUpload {
  publicKey: string;
  wrappedKey: string;
  iterations: number;
}

export const loginParams = (email: string) => request<LoginParams>("POST", "/api/login/params", { email });
// A correct password on an account with a second factor gets a ticket to
// trade for a session with a code, rather than a session.
export type LoginResult = User | { mfaRequired: true; ticket: string };
// `password` is the derived auth key, or for a legacy account the password.
export const login = (email: string, password: string) =>
  request<LoginResult>("POST", "/api/login", { email, password });
// `code`: from an authenticator app, or a recovery code.
export const loginMfa = (ticket: string, code: string) => request<User>("POST", "/api/login/mfa", { ticket, code });
export const logout = () => request<void>("POST", "/api/logout").finally(() => setSessionToken(null));
export const getInvite = (token: string) => request<InviteInfo>("GET", `/api/invites/${encodeURIComponent(token)}`);
export const signup = (token: string, email: string, password: string, key: KeyUpload) =>
  request<User>("POST", "/api/signup", { token, email, password, ...key });
export const getAccountKey = () => request<{ publicKey: string; wrappedKey: string }>("GET", "/api/account/key");
export const upgradeAccount = (currentPassword: string, password: string, key: KeyUpload) =>
  request<void>("POST", "/api/account/upgrade", { currentPassword, password, ...key });
export const lookupUserKey = (email: string) =>
  request<{ userId: number; email: string; publicKey: string | null }>("POST", "/api/users/lookup", { email });

export interface Session {
  id: number;
  userAgent: string | null; // null for sessions from before this was recorded
  ip: string | null;
  createdAt: number;
  expiresAt: number;
  current: boolean; // the session this dashboard is using
}

// Both passwords as derived auth keys, and the identity key re-wrapped
// under the new one.
export const changePassword = (currentPassword: string, newPassword: string, wrappedKey: string) =>
  request<void>("POST", "/api/account/password", { currentPassword, newPassword, wrappedKey });
export const listSessions = () => request<Session[]>("GET", "/api/sessions");

// Proves a second factor for this session for the next few minutes.
export const stepUp = (code: string) => send<{ until: number }>("POST", "/api/account/step-up", { code });
export const verifyEmail = (token: string) => request<void>("POST", "/api/account/verify-email", { token });
export const resendVerification = () => request<void>("POST", "/api/account/verify-email/resend");

export interface Factor {
  id: number;
  label: string;
  createdAt: number;
  lastUsedAt: number | null;
}

export interface Factors {
  factors: Factor[];
  recoveryCodesLeft: number;
  required: boolean; // the admin requires a second factor
}

export const listFactors = () => request<Factors>("GET", "/api/account/mfa");
// A fresh authenticator seed: base32 to type in, and the otpauth:// URI for a QR code.
export const totpSetup = () => request<{ secret: string; uri: string }>("POST", "/api/account/mfa/totp/setup");
// `password` (the derived auth key) is needed for the first factor only.
export const addTotp = (secret: string, code: string, label: string, password?: string) =>
  request<{ recoveryCodes: string[] | null }>("POST", "/api/account/mfa/totp", { secret, code, label, password });
export const removeFactor = (id: number) => request<void>("DELETE", `/api/account/mfa/${id}`);
export const regenerateRecoveryCodes = () =>
  request<{ recoveryCodes: string[] }>("POST", "/api/account/mfa/recovery-codes");
export const revokeSession = (id: number) => request<void>("DELETE", `/api/sessions/${id}`);
export const revokeOtherSessions = () => request<void>("POST", "/api/sessions/revoke-others");

// "Firefox on Windows" from a User-Agent string; good enough to tell
// sessions apart, not a full parser.
export function describeUserAgent(userAgent: string | null): string {
  if (userAgent === null) return "Unknown browser";
  const browsers: [RegExp, string][] = [
    [/Edg\//, "Edge"],
    [/OPR\/|Opera/, "Opera"],
    [/Firefox\//, "Firefox"],
    [/Chrome\/|CriOS\//, "Chrome"],
    [/Safari\//, "Safari"],
  ];
  const systems: [RegExp, string][] = [
    [/Windows/, "Windows"],
    [/Android/, "Android"],
    [/iPhone|iPad|iPod/, "iOS"],
    [/Mac OS X|Macintosh/, "macOS"],
    [/CrOS/, "ChromeOS"],
    [/Linux/, "Linux"],
  ];
  const browser = browsers.find(([pattern]) => pattern.test(userAgent))?.[1];
  const system = systems.find(([pattern]) => pattern.test(userAgent))?.[1];
  if (browser === undefined && system === undefined) return userAgent.slice(0, 60);
  return [browser ?? "Unknown browser", system].filter(Boolean).join(" on ");
}

// The audit log: what this account did or had done to it, and everything on
// the machines it owns; the admin's covers everyone.
export const listActivity = (filter: ActivityFilter) =>
  request<ActivityPage>("GET", `/api/audit${activityQuery(filter)}`);
export const listAllActivity = (filter: ActivityFilter) =>
  request<ActivityPage>("GET", `/api/admin/audit${activityQuery(filter)}`);

export const listUsers = () => request<AdminUserRow[]>("GET", "/api/admin/users");
export const setUserDisabled = (id: number, disabled: boolean) =>
  request<void>("POST", `/api/admin/users/${id}/disabled`, { disabled });
export const listInvites = () => request<PendingInvite[]>("GET", "/api/admin/invites");
export const createInvite = () => request<CreatedInvite>("POST", "/api/admin/invites");
export const deleteInvite = (id: number) => request<void>("DELETE", `/api/admin/invites/${id}`);
export const resetUserMfa = (id: number) => request<void>("POST", `/api/admin/users/${id}/reset-mfa`);
export const getPolicy = () => request<{ requireMfa: boolean }>("GET", "/api/admin/policy");
export const setPolicy = (requireMfa: boolean) =>
  request<{ requireMfa: boolean }>("PUT", "/api/admin/policy", { requireMfa });

export interface EnrollmentCode {
  code: string; // made in this browser; the relay only ever sees its hash
  expiresAt: number;
  relayPin: string | null; // the relay's TLS key pin; null when serving without TLS
}

// A statement and its signer's signature (base64), as the relay stores it.
export interface SignedStatement {
  statement: string;
  signature: string;
}

// When and how long a share grants access. All optional: an open-ended
// share starts now and lasts until revoked.
export interface ShareTerms {
  role: "view" | "control" | "dev";
  startsAt: number | null; // unix seconds; null: right away
  expiresAt: number | null; // unix seconds; null: until revoked
  singleView: boolean; // used up once the viewer stops watching
  analytics: boolean; // may read the machine's health and processes
}

export interface Share extends ShareTerms {
  userId: number;
  email: string;
  publicKey: string | null; // the recipient's identity key; null until they set one up
  grant: SignedStatement | null; // what the owner signed; null for a share from before grants
}

const machinePath = (id: string) => `/api/machines/${encodeURIComponent(id)}`;

export const registerEnrollmentCode = (codeHash: string, ownerBinding: string) =>
  request<Omit<EnrollmentCode, "code">>("POST", "/api/machines/enroll", { codeHash, ownerBinding });
export const endorseMachine = (id: string, signature: string) =>
  request<void>("POST", `${machinePath(id)}/endorsement`, { signature });
export const renameMachine = (id: string, name: string) => request<void>("PATCH", machinePath(id), { name });
export const removeMachine = (id: string) => request<void>("DELETE", machinePath(id));
export const listShares = (id: string) => request<Share[]>("GET", `${machinePath(id)}/shares`);
export const shareMachine = (id: string, email: string, terms: ShareTerms, grant: SignedStatement) =>
  request<void>("PUT", `${machinePath(id)}/shares`, { email, ...terms, grant });
export const unshareMachine = (id: string, userId: number, revocation: SignedStatement | null) =>
  request<void>("DELETE", `${machinePath(id)}/shares/${userId}`, { revocation });

export function inviteUrl(token: string): string {
  return relayPageUrl(`/invite/${token}`);
}

const pad = (value: number): string => String(value).padStart(2, "0");

// "2026-10-08 14:32", local time: fixed width, so columns of them line up.
export function formatTime(unixSeconds: number): string {
  const date = new Date(unixSeconds * 1000);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

// "4m ago", "3h ago", "12d ago".
export function formatAgo(unixSeconds: number, now = Date.now()): string {
  const seconds = Math.max(0, Math.floor(now / 1000 - unixSeconds));
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}

// "02:14:07", or "3d 02:14:07" past a day.
export function formatElapsed(seconds: number): string {
  const total = Math.max(0, Math.floor(seconds));
  const days = Math.floor(total / 86_400);
  const clock = `${pad(Math.floor((total % 86_400) / 3600))}:${pad(Math.floor((total % 3600) / 60))}:${pad(total % 60)}`;
  return days > 0 ? `${days}d ${clock}` : clock;
}

// Short form for share windows: just the time today, the date otherwise.
export function formatShortTime(unixSeconds: number): string {
  const date = new Date(unixSeconds * 1000);
  const time = date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if (date.toDateString() === new Date().toDateString()) return time;
  return `${date.toLocaleDateString([], { weekday: "short", day: "numeric", month: "short" })} ${time}`;
}

// "until 14:30 · one viewing": a share's time limits, empty if it has none.
export function describeShareTerms(terms: Pick<ShareTerms, "startsAt" | "expiresAt" | "singleView">): string {
  const parts: string[] = [];
  const now = Date.now() / 1000;
  if (terms.startsAt !== null && terms.startsAt > now) parts.push(`from ${formatShortTime(terms.startsAt)}`);
  if (terms.expiresAt !== null) parts.push(`until ${formatShortTime(terms.expiresAt)}`);
  if (terms.singleView) parts.push("one viewing");
  return parts.join(" · ");
}
