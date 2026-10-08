// The accent colour: what marks a live session, captured input and the
// connect button. Each viewer picks their own; it's kept in this browser
// only, like any other display preference.

export interface AccentPreset {
  id: string;
  label: string;
  color: string;
}

// Chosen to stay clear of the status colours (emerald ok, amber warn,
// crimson error, slate idle), so an accent never reads as a status.
export const ACCENT_PRESETS: readonly AccentPreset[] = [
  { id: "cyan", label: "Cyan", color: "#00d5df" },
  { id: "rose", label: "Rose", color: "#fb7185" },
  { id: "green", label: "Green", color: "#a3e635" },
  { id: "violet", label: "Violet", color: "#a78bfa" },
  { id: "blue", label: "Blue", color: "#60a5fa" },
  { id: "orange", label: "Orange", color: "#fb923c" },
];

export const DEFAULT_ACCENT = ACCENT_PRESETS[0]!.color;

const STORAGE_KEY = "hawk.accent";
const HEX = /^#[0-9a-f]{6}$/i;

export function isAccent(value: string): boolean {
  return HEX.test(value);
}

export function loadAccent(): string {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored !== null && isAccent(stored)) return stored.toLowerCase();
  } catch {
    // storage blocked: fall back to the default
  }
  return DEFAULT_ACCENT;
}

export function saveAccent(color: string): void {
  try {
    if (color === DEFAULT_ACCENT) window.localStorage.removeItem(STORAGE_KEY);
    else window.localStorage.setItem(STORAGE_KEY, color);
  } catch {
    // storage blocked: the choice lasts for this page only
  }
}

// WCAG relative luminance of a #rrggbb colour.
function luminance(color: string): number {
  const channel = (offset: number): number => {
    const value = parseInt(color.slice(offset, offset + 2), 16) / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

// Sets the accent, and the text colour that reads on top of it: near-black
// on a light accent, white on a dark one, whichever contrasts more.
export function applyAccent(color: string): void {
  const root = document.documentElement.style;
  const light = luminance(color);
  const onBlack = (light + 0.05) / 0.05;
  const onWhite = 1.05 / (light + 0.05);
  root.setProperty("--accent", color);
  root.setProperty("--on-accent", onBlack >= onWhite ? "#08090a" : "#ffffff");
}
