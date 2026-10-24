import { MAX_TEXT_UNITS, MODIFIER_ALT, MODIFIER_CTRL, MODIFIER_SHIFT, MODIFIER_WIN } from "./protocol.js";

// Typing from a phone's on-screen keyboard. Those keyboards send text, not
// keys: `keydown` mostly arrives as "Unidentified" (key code 229) while a
// word is being composed, autocorrect rewrites what was typed, and an IME
// turns letters into other letters. So the text box they type into is read
// instead: each change is compared with what it held before, and the
// difference is replayed on the machine as Backspaces and typed text.
//
// A machine new enough types text as characters (a `text` event), so what
// comes out doesn't depend on its keyboard layout. An older one only takes
// physical keys, so there text is turned into the keys that type it on a
// US keyboard, and characters no US key types are left out.

// One key press, with Shift held for it or not.
export interface Stroke {
  code: string;
  shift: boolean;
}

const SHIFTED_DIGITS = ")!@#$%^&*(";

// Punctuation by key: [unshifted, shifted].
const PUNCTUATION: ReadonlyArray<readonly [string, string, string]> = [
  ["Minus", "-", "_"],
  ["Equal", "=", "+"],
  ["BracketLeft", "[", "{"],
  ["BracketRight", "]", "}"],
  ["Backslash", "\\", "|"],
  ["Semicolon", ";", ":"],
  ["Quote", "'", '"'],
  ["Backquote", "`", "~"],
  ["Comma", ",", "<"],
  ["Period", ".", ">"],
  ["Slash", "/", "?"],
];

// What phones put in for the plain ones ("smart punctuation").
const LOOKALIKES: Record<string, string> = {
  "‘": "'",
  "’": "'",
  "“": '"',
  "”": '"',
  " ": " ",
};

// The keys that type `char`, or null when no US key does.
export function strokeFor(char: string): Stroke | null {
  const plain = LOOKALIKES[char] ?? char;
  if (plain.length !== 1) return null;
  if (plain >= "a" && plain <= "z") return { code: `Key${plain.toUpperCase()}`, shift: false };
  if (plain >= "A" && plain <= "Z") return { code: `Key${plain}`, shift: true };
  if (plain >= "0" && plain <= "9") return { code: `Digit${plain}`, shift: false };
  const shiftedDigit = SHIFTED_DIGITS.indexOf(plain);
  if (shiftedDigit >= 0) return { code: `Digit${shiftedDigit}`, shift: true };
  if (plain === " ") return { code: "Space", shift: false };
  if (plain === "\n") return { code: "Enter", shift: false };
  if (plain === "\t") return { code: "Tab", shift: false };
  for (const [code, unshifted, shifted] of PUNCTUATION) {
    if (plain === unshifted) return { code, shift: false };
    if (plain === shifted) return { code, shift: true };
  }
  return null;
}

// What typing `text` takes: runs of characters as text events (each at
// most MAX_TEXT_UNITS long, never cutting a surrogate pair), with line
// breaks and tabs as their keys. Other controls are dropped. `asText` false
// (an older machine): every character as its US key, or left out.
export type Typing = { kind: "text"; text: string } | ({ kind: "key" } & Stroke);

export function typingFor(text: string, asText: boolean): Typing[] {
  const out: Typing[] = [];
  let run = "";
  const flush = (): void => {
    if (run !== "") out.push({ kind: "text", text: run });
    run = "";
  };
  // A "\r\n" (or a lone "\r") pasted in is one line break.
  for (const char of text.replace(/\r\n?/g, "\n")) {
    if (char === "\n" || char === "\t") {
      flush();
      out.push({ kind: "key", code: char === "\t" ? "Tab" : "Enter", shift: false });
      continue;
    }
    if (isControl(char)) continue;
    if (!asText) {
      const stroke = strokeFor(char);
      if (stroke !== null) out.push({ kind: "key", ...stroke });
      continue;
    }
    if (run.length + char.length > MAX_TEXT_UNITS) flush();
    run += char;
  }
  flush();
  return out;
}

function isControl(char: string): boolean {
  const point = char.codePointAt(0) ?? 0;
  return point < 0x20 || (point >= 0x7f && point <= 0x9f);
}

// How the text box went from `before` to `after`: so many characters
// deleted from the end of what they share, then `inserted` typed. Counted
// in characters, not UTF-16 units, as Backspace deletes them.
export function textChange(before: string, after: string): { deleted: number; inserted: string } {
  const a = [...before];
  const b = [...after];
  let same = 0;
  while (same < a.length && same < b.length && a[same] === b[same]) same += 1;
  return { deleted: a.length - same, inserted: b.slice(same).join("") };
}

// What the text box holds when nothing has been typed: a few characters for
// a Backspace to delete, since a box with nothing in it sends no change at
// all when one is pressed. Never typed on the machine.
export const PADDING = "________";

// Named keys a phone keyboard does report on `keydown`, by `KeyboardEvent.key`,
// and the physical key each one is.
export const NAMED_KEYS: Readonly<Record<string, string>> = {
  Enter: "Enter",
  Backspace: "Backspace",
  Tab: "Tab",
  Escape: "Escape",
  Delete: "Delete",
  ArrowUp: "ArrowUp",
  ArrowDown: "ArrowDown",
  ArrowLeft: "ArrowLeft",
  ArrowRight: "ArrowRight",
  Home: "Home",
  End: "End",
  PageUp: "PageUp",
  PageDown: "PageDown",
};

// The modifiers the extra-keys row latches for the next key.
export type Modifier = "ControlLeft" | "AltLeft" | "MetaLeft" | "ShiftLeft";

// Whether these held modifiers make the next character a shortcut, which
// needs the real key: Ctrl, Alt or Win. Shift alone doesn't, the character
// has its case already.
export function isShortcut(modifiers: Iterable<string>): boolean {
  for (const modifier of modifiers) if (modifier !== "ShiftLeft") return true;
  return false;
}

const MODIFIER_BITS: Readonly<Record<string, number>> = {
  ControlLeft: MODIFIER_CTRL,
  AltLeft: MODIFIER_ALT,
  ShiftLeft: MODIFIER_SHIFT,
  MetaLeft: MODIFIER_WIN,
};

// The shortcut `char` makes with `modifiers`, for a machine that finds the
// key itself: null unless it's a shortcut (Ctrl, Alt or Win) and `char` is
// one character a key could type (one UTF-16 unit, not a control). Without
// Shift latched a letter goes lower case: a phone capitalising the first
// letter of the box shouldn't turn Ctrl+C into Ctrl+Shift+C.
export function chordFor(
  char: string,
  modifiers: Iterable<string>,
): { kind: "chord"; text: string; modifiers: number } | null {
  let bits = 0;
  for (const modifier of modifiers) bits |= MODIFIER_BITS[modifier] ?? 0;
  if ((bits & (MODIFIER_CTRL | MODIFIER_ALT | MODIFIER_WIN)) === 0) return null;
  if (char.length !== 1 || isControl(char)) return null;
  const lower = char.toLowerCase();
  const text = (bits & MODIFIER_SHIFT) === 0 && lower.length === 1 ? lower : char;
  return { kind: "chord", text, modifiers: bits };
}
