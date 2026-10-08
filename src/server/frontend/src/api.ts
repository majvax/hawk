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

export const listUsers = () => request<AdminUserRow[]>("GET", "/api/admin/users");
export const setUserDisabled = (id: number, disabled: boolean) =>
  request<void>("POST", `/api/admin/users/${id}/disabled`, { disabled });
export const listInvites = () => request<PendingInvite[]>("GET", "/api/admin/invites");
export const createInvite = () => request<CreatedInvite>("POST", "/api/admin/invites");
export const deleteInvite = (id: number) => request<void>("DELETE", `/api/admin/invites/${id}`);

export interface EnrollmentCode {
  code: string; // shown once; the server keeps only its hash
  expiresAt: number;
}

export interface Share {
  userId: number;
  email: string;
  role: "view" | "control";
}

const machinePath = (id: string) => `/api/machines/${encodeURIComponent(id)}`;

export const createEnrollmentCode = () => request<EnrollmentCode>("POST", "/api/machines/enroll");
export const renameMachine = (id: string, name: string) => request<void>("PATCH", machinePath(id), { name });
export const removeMachine = (id: string) => request<void>("DELETE", machinePath(id));
export const listShares = (id: string) => request<Share[]>("GET", `${machinePath(id)}/shares`);
export const shareMachine = (id: string, email: string, role: Share["role"]) =>
  request<void>("PUT", `${machinePath(id)}/shares`, { email, role });
export const unshareMachine = (id: string, userId: number) =>
  request<void>("DELETE", `${machinePath(id)}/shares/${userId}`);

export function inviteUrl(token: string): string {
  return `${window.location.origin}/invite/${token}`;
}

export function formatTime(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString();
}
