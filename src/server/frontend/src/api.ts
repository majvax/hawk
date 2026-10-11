// Typed wrappers over the relay's /api routes (relay/src/api.rs). The
// session lives in an HttpOnly cookie, so nothing here touches tokens.
// Nothing here sees a password either: keys.ts derives what's sent from it.

export interface User {
  id: number;
  email: string;
  isAdmin: boolean;
}

export interface AdminUserRow extends User {
  disabled: boolean;
  createdAt: number; // unix seconds
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
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    let message = `request failed (${response.status})`;
    try {
      const payload = (await response.json()) as { error?: string };
      if (payload.error !== undefined) message = payload.error;
    } catch {
      // not JSON; keep the generic message
    }
    throw new ApiError(response.status, message);
  }
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
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
// `password` is the derived auth key, or for a legacy account the password.
export const login = (email: string, password: string) => request<User>("POST", "/api/login", { email, password });
export const logout = () => request<void>("POST", "/api/logout");
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

export const listUsers = () => request<AdminUserRow[]>("GET", "/api/admin/users");
export const setUserDisabled = (id: number, disabled: boolean) =>
  request<void>("POST", `/api/admin/users/${id}/disabled`, { disabled });
export const listInvites = () => request<PendingInvite[]>("GET", "/api/admin/invites");
export const createInvite = () => request<CreatedInvite>("POST", "/api/admin/invites");
export const deleteInvite = (id: number) => request<void>("DELETE", `/api/admin/invites/${id}`);

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
  return `${window.location.origin}/invite/${token}`;
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
