// Which relay this dashboard talks to, and how it proves who's signed in.
//
// Served by the relay itself (the default), that's the page's own origin and
// an HttpOnly cookie, and nothing here does anything. Built standalone (for
// the desktop app or a static host, VITE_HAWK_STANDALONE=1), the user enters
// the relay's address, and the session is a bearer token the relay hands
// back at sign-in, kept in localStorage per relay. The relay only does that
// for origins its owner listed in HAWK_ALLOWED_ORIGINS.

import { PROTOCOL_VERSION } from "./protocol.js";

export const STANDALONE: boolean =
  import.meta.env.VITE_HAWK_STANDALONE === "1" || "__TAURI_INTERNALS__" in window;

const RELAYS_KEY = "hawk.relays";
const ACTIVE_KEY = "hawk.relay";
const TOKEN_PREFIX = "hawk.session:";

function read(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string | null): void {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // storage blocked: the session lasts as long as the page
  }
}

// "relay.example.com:8443" or a pasted "wss://…/v1/ws" both become
// "https://relay.example.com:8443": the origin the relay is reached at.
export function normalizeRelay(input: string): string | null {
  let text = input.trim();
  if (text === "") return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) text = `https://${text}`;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  const scheme = { "https:": "https:", "wss:": "https:", "http:": "http:", "ws:": "http:" }[url.protocol];
  if (scheme === undefined || url.host === "") return null;
  return `${scheme}//${url.host}`;
}

export function rememberedRelays(): string[] {
  try {
    const parsed: unknown = JSON.parse(read(RELAYS_KEY) ?? "[]");
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

// The relay in use, or null when a standalone dashboard hasn't been given
// one yet. Always "" (the page's own origin) when served by a relay.
export function activeRelay(): string | null {
  if (!STANDALONE) return "";
  return read(ACTIVE_KEY);
}

export function useRelay(relay: string): void {
  const relays = rememberedRelays().filter((known) => known !== relay);
  write(RELAYS_KEY, JSON.stringify([relay, ...relays].slice(0, 10)));
  write(ACTIVE_KEY, relay);
}

export function forgetRelay(relay: string): void {
  write(RELAYS_KEY, JSON.stringify(rememberedRelays().filter((known) => known !== relay)));
  write(TOKEN_PREFIX + relay, null);
  if (read(ACTIVE_KEY) === relay) write(ACTIVE_KEY, null);
}

// Back to the relay picker, keeping the list.
export function leaveRelay(): void {
  write(ACTIVE_KEY, null);
}

const base = (): string => activeRelay() ?? "";

export function apiUrl(path: string): string {
  return base() + path;
}

export function socketUrl(path: string): string {
  const origin = base() === "" ? window.location.origin : base();
  return origin.replace(/^http/, "ws") + path;
}

// The page people open in a browser: invite links, docs.
export function relayPageUrl(path: string): string {
  return (base() === "" ? window.location.origin : base()) + path;
}

// For the status bar and the sign-in screen.
export function relayHost(): string {
  if (activeRelay() === null) return "no relay yet";
  const relay = base();
  return relay === "" ? window.location.host : relay.replace(/^https?:\/\//, "");
}

export function relayIsTls(): boolean {
  const relay = base();
  return relay === "" ? window.location.protocol === "https:" : relay.startsWith("https:");
}

export function sessionToken(): string | null {
  const relay = activeRelay();
  return relay === null || relay === "" ? null : read(TOKEN_PREFIX + relay);
}

export function setSessionToken(token: string | null): void {
  const relay = activeRelay();
  if (relay !== null && relay !== "") write(TOKEN_PREFIX + relay, token);
}

// Subprotocols for the dashboard socket: a browser can't put a header on a
// WebSocket, so the token rides as "hawk.bearer.<token>". The relay answers
// with plain "hawk".
export function socketProtocols(): string[] | undefined {
  const token = sessionToken();
  return token === null ? undefined : ["hawk", `hawk.bearer.${token}`];
}

// The relay's protocol against ours, in words, or null when they match.
export async function checkRelayProtocol(): Promise<string | null> {
  let protocol: number;
  try {
    const response = await fetch(apiUrl("/api/version"));
    if (response.status === 404) return "This relay is older than this dashboard: update the relay.";
    if (!response.ok) return null;
    protocol = ((await response.json()) as { protocol: number }).protocol;
  } catch {
    return null; // unreachable: the usual reconnect handles that
  }
  if (protocol < PROTOCOL_VERSION) return "This relay is older than this dashboard: update the relay.";
  if (protocol > PROTOCOL_VERSION) return "This relay is newer than this dashboard: update the dashboard.";
  return null;
}
