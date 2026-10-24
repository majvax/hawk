import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";

import type { InputEvent } from "./protocol.js";
import { PADDING } from "./touchKeyboard.js";

// The on-screen keyboard's text box, run without a DOM, as in
// useRemoteInput.test.ts: React's hooks are stood in for and the box is a
// plain object that records its listeners.
let cleanups: Array<() => void> = [];
void mock.module("react", () => ({
  useState: <T>(initial: T | (() => T)) => [typeof initial === "function" ? (initial as () => T)() : initial, () => {}],
  useRef: <T>(current: T) => ({ current }),
  useCallback: <T>(fn: T) => fn,
  useEffect: (effect: () => (() => void) | void) => {
    const cleanup = effect();
    if (typeof cleanup === "function") cleanups.push(cleanup);
  },
}));

const { useTouchKeyboard } = await import("./useTouchInput.js");

type Listener = (event: unknown) => void;

class Target {
  listeners = new Map<string, Set<Listener>>();
  addEventListener(type: string, listener: Listener): void {
    let set = this.listeners.get(type);
    if (set === undefined) this.listeners.set(type, (set = new Set()));
    set.add(listener);
  }
  removeEventListener(type: string, listener: Listener): void {
    this.listeners.get(type)?.delete(listener);
  }
  fire(type: string, event: unknown = {}): void {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

const fakeDocument = Object.assign(new Target(), { activeElement: null as unknown });
const fakeWindow = Object.assign(new Target(), {
  setTimeout: globalThis.setTimeout.bind(globalThis),
  clearTimeout: globalThis.clearTimeout.bind(globalThis),
});

class Box extends Target {
  value = "";
  setSelectionRange(): void {}
  focus(): void {
    fakeDocument.activeElement = this;
    this.fire("focus");
  }
  blur(): void {
    fakeDocument.activeElement = null;
    this.fire("blur");
  }
  // The keyboard changing the text, as the browser reports it.
  type(after: string): void {
    this.value = after;
    this.fire("input");
  }
}

function rig(asText = true) {
  const box = new Box();
  const sent: InputEvent[] = [];
  const keyboard = useTouchKeyboard(
    { current: box as unknown as HTMLTextAreaElement },
    true,
    (event) => sent.push(event),
    asText,
  );
  box.focus();
  // What the machine typed: each key down, Shift and the rest held shown,
  // and text in quotes.
  const typed = (): string[] => {
    const held = new Set<string>();
    const out: string[] = [];
    for (const event of sent) {
      if (event.kind === "text") out.push(JSON.stringify(event.text));
      if (event.kind === "chord") out.push(`chord ${event.modifiers} ${JSON.stringify(event.text)}`);
      if (event.kind !== "key") continue;
      if (!event.down) {
        held.delete(event.code);
        continue;
      }
      if (/^(Control|Alt|Shift|Meta)Left$/.test(event.code)) held.add(event.code);
      else out.push([...held, event.code].join("+"));
    }
    return out;
  };
  return { box, sent, keyboard, typed };
}

function balanced(sent: InputEvent[]): boolean {
  const down = new Set<string>();
  for (const event of sent) {
    if (event.kind !== "key") continue;
    if (event.down) down.add(event.code);
    else down.delete(event.code);
  }
  return down.size === 0;
}

const keydown = (key: string, extra: Record<string, unknown> = {}) => ({
  key,
  code: "",
  keyCode: 0,
  isComposing: false,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  metaKey: false,
  preventDefault: () => {},
  ...extra,
});

describe("useTouchKeyboard", () => {
  const saved = { window: globalThis.window, document: globalThis.document };
  beforeEach(() => {
    (globalThis as Record<string, unknown>).window = fakeWindow;
    (globalThis as Record<string, unknown>).document = fakeDocument;
  });
  afterEach(() => {
    for (const cleanup of cleanups) cleanup();
    cleanups = [];
    (globalThis as Record<string, unknown>).window = saved.window;
    (globalThis as Record<string, unknown>).document = saved.document;
  });

  test("typed text goes as text, and the box goes back to its padding", () => {
    const { box, typed } = rig();
    expect(box.value).toBe(PADDING);
    box.type(`${PADDING}H`);
    expect(box.value).toBe(PADDING);
    box.type(`${PADDING}é!`);
    expect(typed()).toEqual(['"H"', '"é!"']);
  });

  test("Backspace on an empty-looking box still deletes on the machine", () => {
    const { box, typed } = rig();
    box.type(PADDING.slice(0, -1));
    expect(typed()).toEqual(["Backspace"]);
    expect(box.value).toBe(PADDING);
  });

  test("Enter from the text, or from a keyboard that names it, is the key", () => {
    const { box, typed } = rig();
    box.type(`${PADDING}\n`);
    box.fire("keydown", keydown("Enter", { keyCode: 13 }));
    expect(typed()).toEqual(["Enter", "Enter"]);
  });

  test("a keydown that doesn't say which key is left to the text", () => {
    const { box, typed } = rig();
    box.fire("keydown", keydown("Unidentified", { keyCode: 229 }));
    box.fire("keydown", keydown("Backspace", { isComposing: true }));
    expect(typed()).toEqual([]);
  });

  test("a word being composed is typed as it goes and corrected in place", () => {
    const { box, typed } = rig();
    box.fire("compositionstart");
    box.type(`${PADDING}t`);
    box.type(`${PADDING}te`);
    box.type(`${PADDING}teh`);
    // Not reset mid-word: the IME is still working on it.
    expect(box.value).toBe(`${PADDING}teh`);
    box.type(`${PADDING}the`);
    box.fire("compositionend");
    expect(box.value).toBe(PADDING);
    expect(typed()).toEqual(['"t"', '"e"', '"h"', "Backspace", "Backspace", '"he"']);
  });

  test("an IME's word replaces the letters it was typed with", () => {
    const { box, typed } = rig();
    box.fire("compositionstart");
    box.type(`${PADDING}ni`);
    box.type(`${PADDING}你`);
    box.fire("compositionend");
    expect(typed()).toEqual(['"ni"', "Backspace", "Backspace", '"你"']);
  });

  test("an older machine gets US keys, and nothing for what has none", () => {
    const { box, typed, sent } = rig(false);
    box.type(`${PADDING}café!`);
    expect(typed()).toEqual(["KeyC", "KeyA", "KeyF", "ShiftLeft+Digit1"]);
    expect(sent.some((event) => event.kind === "text")).toBe(false);
    expect(balanced(sent)).toBe(true);
  });

  test("Ctrl latched makes the next character a chord the machine finds the key for", () => {
    const { box, keyboard, typed, sent } = rig();
    keyboard.latch("ControlLeft");
    box.type(`${PADDING}a`);
    box.type(`${PADDING}a`);
    expect(typed()).toEqual(['chord 1 "a"', '"a"']);
    // Nothing pressed as keys, so nothing to leave held.
    expect(sent.some((event) => event.kind === "key")).toBe(false);
  });

  test("an auto-capitalised letter is still Ctrl+C, not Ctrl+Shift+C", () => {
    const { box, keyboard, typed } = rig();
    keyboard.latch("ControlLeft");
    box.type(`${PADDING}C`);
    expect(typed()).toEqual(['chord 1 "c"']);
  });

  test("a chord mid-composition leaves nothing for a correction to delete", () => {
    const { box, keyboard, typed } = rig();
    box.fire("compositionstart");
    keyboard.latch("ControlLeft");
    box.type(`${PADDING}c`);
    // The box starts over, the composition with it.
    expect(box.value).toBe(PADDING);
    box.type(`${PADDING}x`);
    expect(typed()).toEqual(['chord 1 "c"', '"x"']);
    expect(box.value).toBe(PADDING);
  });

  test("a shortcut takes only the first character of what came at once", () => {
    const { box, keyboard, typed } = rig();
    keyboard.latch("AltLeft");
    keyboard.latch("ShiftLeft");
    box.type(`${PADDING}fé`);
    expect(typed()).toEqual(['chord 6 "f"', '"é"']);
  });

  test("Ctrl+Enter is still the Enter key", () => {
    const { box, keyboard, typed, sent } = rig();
    keyboard.latch("ControlLeft");
    box.type(`${PADDING}\n`);
    expect(typed()).toEqual(["ControlLeft+Enter"]);
    expect(balanced(sent)).toBe(true);
  });

  test("an older machine gets the shortcut's US key", () => {
    const { box, keyboard, typed, sent } = rig(false);
    keyboard.latch("ControlLeft");
    box.type(`${PADDING}c`);
    box.type(`${PADDING}c`);
    expect(typed()).toEqual(["ControlLeft+KeyC", "KeyC"]);
    expect(balanced(sent)).toBe(true);
  });

  test("Shift alone latched leaves text as it was typed", () => {
    const { box, keyboard, typed } = rig();
    keyboard.latch("ShiftLeft");
    box.type(`${PADDING}a`);
    keyboard.press("Tab");
    expect(typed()).toEqual(['"a"', "Tab"]);
  });

  test("modifiers latched together, then an extra key", () => {
    const { keyboard, typed } = rig();
    keyboard.latch("ControlLeft");
    keyboard.latch("ShiftLeft");
    keyboard.press("Escape");
    expect(typed()).toEqual(["ControlLeft+ShiftLeft+Escape"]);
  });

  test("a modifier tapped twice is pressed on its own", () => {
    const { keyboard, typed, sent } = rig();
    keyboard.latch("MetaLeft");
    keyboard.latch("MetaLeft");
    expect(sent.filter((event) => event.kind === "key")).toEqual([
      { kind: "key", code: "MetaLeft", down: true },
      { kind: "key", code: "MetaLeft", down: false },
    ]);
    keyboard.press("Tab");
    expect(typed()).toEqual(["Tab"]);
  });

  test("a hardware keyboard's shortcuts go as they are", () => {
    const { box, typed } = rig();
    box.fire("keydown", keydown("c", { code: "KeyC", ctrlKey: true }));
    box.fire("keydown", keydown("Tab", { code: "Tab", shiftKey: true }));
    // Plain letters are left to the text.
    box.fire("keydown", keydown("a", { code: "KeyA" }));
    expect(typed()).toEqual(["ControlLeft+KeyC", "ShiftLeft+Tab"]);
  });
});
