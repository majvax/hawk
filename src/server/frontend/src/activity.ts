// The audit log as the Activity views show it (relay/src/audit.rs): what each
// kind of event is called, which kinds a filter means, and the particulars
// worth a column. Pure, so it's tested on its own.

// What the relay recorded beyond who, where and when. Only these fields
// exist; none of them is a secret.
export interface ActivityDetails {
  reason?: string;
  seconds?: number;
  shellUp?: number;
  shellDown?: number;
  filesUp?: number;
  filesDown?: number;
  elevated?: boolean;
  recoveryCode?: boolean;
  name?: string;
  startsAt?: number;
  expiresAt?: number;
  singleView?: boolean;
  analytics?: boolean;
  requireMfa?: boolean;
}

export interface ActivityEvent {
  id: number;
  at: number; // unix seconds
  kind: string;
  userId: number | null; // who did it; null for an unknown account
  userEmail: string | null;
  subjectId: number | null; // the account it was done to, if another
  subjectEmail: string | null;
  machineId: string | null;
  machineName: string | null;
  role: string | null;
  ip: string | null;
  userAgent: string | null;
  details: ActivityDetails;
}

export interface ActivityPage {
  events: ActivityEvent[]; // newest first
  next: number | null; // pass as `before` for the next page
}

export interface ActivityFilter {
  machine?: string;
  user?: number;
  category?: Category;
  since?: number;
  until?: number;
  before?: number;
  limit?: number;
}

export type Category = "all" | "sessions" | "actions" | "account" | "machines";

export const CATEGORIES: readonly (readonly [Category, string])[] = [
  ["all", "Everything"],
  ["sessions", "Views"],
  ["actions", "Actions"],
  ["account", "Account"],
  ["machines", "Machines & shares"],
];

const LABELS: Record<string, [Exclude<Category, "all">, string]> = {
  sign_in: ["account", "Signed in"],
  sign_in_failed: ["account", "Sign-in failed"],
  mfa_failed: ["account", "Wrong second-factor code"],
  step_up: ["account", "Confirmed with a code"],
  signed_up: ["account", "Account created"],
  password_changed: ["account", "Password changed"],
  mfa_added: ["account", "Authenticator added"],
  mfa_removed: ["account", "Authenticator removed"],
  recovery_codes_regenerated: ["account", "New recovery codes"],
  mfa_reset: ["account", "Two-factor reset by the admin"],
  user_disabled: ["account", "Account disabled"],
  user_enabled: ["account", "Account enabled"],
  invite_created: ["account", "Invite created"],
  invite_revoked: ["account", "Invite revoked"],
  mfa_policy_changed: ["account", "Two-factor policy changed"],
  machine_enrolled: ["machines", "Machine enrolled"],
  machine_renamed: ["machines", "Machine renamed"],
  machine_removed: ["machines", "Machine removed"],
  share_granted: ["machines", "Shared"],
  share_revoked: ["machines", "Share revoked"],
  view_started: ["sessions", "View started"],
  view_ended: ["sessions", "View ended"],
  view_rejected: ["sessions", "Refused by the machine"],
  view_elevated: ["sessions", "Took control"],
  shell_used: ["actions", "Used a shell"],
  files_used: ["actions", "Used files"],
  clipboard_image_pasted: ["actions", "Pasted a picture"],
  power: ["actions", "Power action"],
  ctrl_alt_del: ["actions", "Ctrl+Alt+Del"],
  config_changed: ["actions", "Changed the config"],
  update_install: ["actions", "Installed an update"],
};

// "View started"; an unknown kind (a newer relay) as it's spelled.
export function eventLabel(kind: string): string {
  return LABELS[kind]?.[1] ?? kind.replaceAll("_", " ");
}

export function eventCategory(kind: string): Category {
  return LABELS[kind]?.[0] ?? "all";
}

// The kinds a category asks the relay for; empty for everything.
export function kindsFor(category: Category): string[] {
  if (category === "all") return [];
  return Object.entries(LABELS)
    .filter(([, [of]]) => of === category)
    .map(([kind]) => kind);
}

// The query string for /api/audit: only what's set.
export function activityQuery(filter: ActivityFilter): string {
  const params = new URLSearchParams();
  if (filter.machine !== undefined) params.set("machine", filter.machine);
  if (filter.user !== undefined) params.set("user", String(filter.user));
  const kinds = kindsFor(filter.category ?? "all");
  if (kinds.length > 0) params.set("kind", kinds.join(","));
  if (filter.since !== undefined) params.set("since", String(Math.floor(filter.since)));
  if (filter.until !== undefined) params.set("until", String(Math.floor(filter.until)));
  if (filter.before !== undefined) params.set("before", String(filter.before));
  if (filter.limit !== undefined) params.set("limit", String(filter.limit));
  const query = params.toString();
  return query === "" ? "" : `?${query}`;
}

// "1.2 MB", "340 B".
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

// "1h 04m", "3m 12s", "8s".
export function formatDuration(seconds: number): string {
  const total = Math.max(0, Math.round(seconds));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const rest = total % 60;
  if (hours > 0) return `${hours}h ${String(minutes).padStart(2, "0")}m`;
  if (minutes > 0) return `${minutes}m ${String(rest).padStart(2, "0")}s`;
  return `${rest}s`;
}

// The particulars of an event in a few words, for its Details column.
export function describeDetails(event: ActivityEvent): string {
  const { details } = event;
  const parts: string[] = [];
  if (event.subjectEmail !== null && event.subjectId !== event.userId) parts.push(event.subjectEmail);
  if (event.role !== null && event.kind !== "view_ended") parts.push(`as ${event.role}`);
  if (details.reason !== undefined) parts.push(details.reason);
  if (details.name !== undefined && event.kind !== "machine_renamed") parts.push(`"${details.name}"`);
  if (details.name !== undefined && event.kind === "machine_renamed") parts.push(`to "${details.name}"`);
  if (details.seconds !== undefined) parts.push(formatDuration(details.seconds));
  const traffic: [number | undefined, string][] = [
    [details.shellUp, "shell ↑"],
    [details.shellDown, "shell ↓"],
    [details.filesUp, "files ↑"],
    [details.filesDown, "files ↓"],
  ];
  for (const [bytes, label] of traffic) if (bytes !== undefined) parts.push(`${label} ${formatBytes(bytes)}`);
  if (details.elevated === false) parts.push("not elevated");
  if (details.recoveryCode === true) parts.push("with a recovery code");
  if (details.singleView === true) parts.push("one viewing");
  if (details.analytics === true) parts.push("with analytics");
  if (details.requireMfa !== undefined) parts.push(details.requireMfa ? "required" : "optional");
  return parts.join(" · ");
}
