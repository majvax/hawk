// Typed wrappers over the relay's /api routes (relay/src/api.rs). The
// session lives in an HttpOnly cookie, so nothing here touches tokens.

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

export const login = (email: string, password: string) => request<User>("POST", "/api/login", { email, password });
export const logout = () => request<void>("POST", "/api/logout");
export const getInvite = (token: string) => request<InviteInfo>("GET", `/api/invites/${encodeURIComponent(token)}`);
export const signup = (token: string, email: string, password: string) =>
  request<User>("POST", "/api/signup", { token, email, password });

export interface Session {
  id: number;
  userAgent: string | null; // null for sessions from before this was recorded
  ip: string | null;
  createdAt: number;
  expiresAt: number;
  current: boolean; // the session this dashboard is using
}

export const changePassword = (currentPassword: string, newPassword: string) =>
  request<void>("POST", "/api/account/password", { currentPassword, newPassword });
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
  code: string; // shown once; the server keeps only its hash
  expiresAt: number;
  relayPin: string | null; // the relay's TLS key pin; null when serving without TLS
}

// When and how long a share grants access. All optional: an open-ended
// share starts now and lasts until revoked.
export interface ShareTerms {
  role: "view" | "control";
  startsAt: number | null; // unix seconds; null: right away
  expiresAt: number | null; // unix seconds; null: until revoked
  singleView: boolean; // used up once the viewer stops watching
}

export interface Share extends ShareTerms {
  userId: number;
  email: string;
}

const machinePath = (id: string) => `/api/machines/${encodeURIComponent(id)}`;

export const createEnrollmentCode = () => request<EnrollmentCode>("POST", "/api/machines/enroll");
export const renameMachine = (id: string, name: string) => request<void>("PATCH", machinePath(id), { name });
export const removeMachine = (id: string) => request<void>("DELETE", machinePath(id));
export const listShares = (id: string) => request<Share[]>("GET", `${machinePath(id)}/shares`);
export const shareMachine = (id: string, email: string, terms: ShareTerms) =>
  request<void>("PUT", `${machinePath(id)}/shares`, { email, ...terms });
export const unshareMachine = (id: string, userId: number) =>
  request<void>("DELETE", `${machinePath(id)}/shares/${userId}`);

export function inviteUrl(token: string): string {
  return `${window.location.origin}/invite/${token}`;
}

export function formatTime(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString();
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
