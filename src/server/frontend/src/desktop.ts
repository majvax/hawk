// What the dashboard does differently inside the desktop app
// (src/app/src/main.rs): links open in the browser, and the app's own
// updates and settings. Everything here is a no-op in a browser.

export const IN_APP: boolean = "__TAURI_INTERNALS__" in window;

export interface AppUpdate {
  version: string;
  current: string;
  notes: string | null;
}

export interface AppSettings {
  policy: "notify" | "auto" | "off";
  channel: "stable" | "beta";
  feedUrl: string;
  publicKey: string;
}

async function core(): Promise<typeof import("@tauri-apps/api/core")> {
  return import("@tauri-apps/api/core");
}

// A new tab means nothing in the app's window: links that would open one
// (docs, invite links) open in the default browser instead.
export function openLinksInBrowser(): void {
  if (!IN_APP) return;
  document.addEventListener("click", (event) => {
    const link = (event.target as Element | null)?.closest?.("a[target=_blank]");
    if (!(link instanceof HTMLAnchorElement) || !/^https?:/.test(link.href)) return;
    event.preventDefault();
    void core().then(({ invoke }) => invoke("plugin:opener|open_url", { url: link.href }));
  });
}

// Calls `handler` when the app found an update at start (policy "notify").
export function onAppUpdate(handler: (update: AppUpdate) => void): () => void {
  if (!IN_APP) return () => {};
  let stop: (() => void) | null = null;
  let cancelled = false;
  void import("@tauri-apps/api/event").then(({ listen }) =>
    listen<AppUpdate>("update-available", (event) => handler(event.payload)).then((unlisten) => {
      if (cancelled) unlisten();
      else stop = unlisten;
    }),
  );
  return () => {
    cancelled = true;
    stop?.();
  };
}

export async function checkAppUpdate(): Promise<AppUpdate | null> {
  return (await core()).invoke<AppUpdate | null>("check_update");
}

// Downloads, verifies and installs the update, then restarts the app.
export async function installAppUpdate(): Promise<void> {
  await (await core()).invoke("install_update");
}

export async function appSettings(): Promise<AppSettings> {
  return (await core()).invoke<AppSettings>("settings");
}

export async function saveAppSettings(settings: AppSettings): Promise<void> {
  await (await core()).invoke("set_settings", { settings });
}

export async function appVersion(): Promise<string> {
  return (await core()).invoke<string>("app_version");
}
