import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";

import type { InputEvent } from "./protocol.js";

// The hook's keyboard handling, run without a DOM: React's hooks are
// stood in for (the effect runs at once, its cleanup on demand) and the
// canvas is a plain object that records its listeners.
let cleanups: Array<() => void> = [];
void mock.module("react", () => ({
  useState: <T>(initial: T) => [initial, () => {}],
  useRef: <T>(current: T) => ({ current }),
  useCallback: <T>(fn: T) => fn,
  useEffect: (effect: () => (() => void) | void) => {
    const cleanup = effect();
    if (typeof cleanup === "function") cleanups.push(cleanup);
  },
}));

const { isSasShortcut, useRemoteInput } = await import("./useRemoteInput.js");

const keys = { ctrlKey: false, altKey: false, shiftKey: false, metaKey: false };

describe("isSasShortcut", () => {
  test("takes Ctrl+Alt+End", () => {
    expect(isSasShortcut({ ...keys, code: "End", ctrlKey: true, altKey: true })).toBe(true);
  });

  test("leaves End alone otherwise", () => {
    expect(isSasShortcut({ ...keys, code: "End" })).toBe(false);
    expect(isSasShortcut({ ...keys, code: "End", ctrlKey: true })).toBe(false);
    expect(isSasShortcut({ ...keys, code: "End", altKey: true })).toBe(false);
    expect(isSasShortcut({ ...keys, code: "End", ctrlKey: true, altKey: true, shiftKey: true })).toBe(false);
    expect(isSasShortcut({ ...keys, code: "Delete", ctrlKey: true, altKey: true })).toBe(false);
  });
});

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
  requestAnimationFrame: () => 0,
  cancelAnimationFrame: () => {},
});

class Canvas extends Target {
  focus(): void {
    fakeDocument.activeElement = this;
    this.fire("focus");
  }
  blur(): void {
    fakeDocument.activeElement = null;
    this.fire("blur");
  }
}

// Modifiers as the browser reports them on each event, from what's held.
function keyEvent(code: string, held: Set<string>, repeat = false) {
  return {
    code,
    repeat,
    ctrlKey: held.has("ControlLeft"),
    altKey: held.has("AltLeft"),
    shiftKey: false,
    metaKey: false,
    preventDefault: () => {},
  };
}

interface Rig {
  canvas: Canvas;
  sent: InputEvent[];
  sas: { count: number };
  down: (code: string, repeat?: boolean) => void;
  up: (code: string) => void;
}

function rig(withSas: boolean): Rig {
  const canvas = new Canvas();
  const sent: InputEvent[] = [];
  const sas = { count: 0 };
  const held = new Set<string>();
  useRemoteInput(
    { current: canvas as unknown as HTMLCanvasElement },
    true,
    (event) => sent.push(event),
    null,
    withSas ? () => (sas.count += 1) : null,
  );
  canvas.focus();
  return {
    canvas,
    sent,
    sas,
    down: (code, repeat = false) => {
      held.add(code);
      canvas.fire("keydown", keyEvent(code, held, repeat));
    },
    up: (code) => {
      held.delete(code);
      canvas.fire("keyup", keyEvent(code, held));
    },
  };
}

const keyLog = (sent: InputEvent[]): string[] =>
  sent.flatMap((event) => (event.kind === "key" ? [`${event.code} ${event.down ? "down" : "up"}`] : []));

// Every key the machine was told is down was told it's up again.
function balanced(sent: InputEvent[]): boolean {
  const down = new Set<string>();
  for (const event of sent) {
    if (event.kind !== "key") continue;
    if (event.down) down.add(event.code);
    else down.delete(event.code);
  }
  return down.size === 0;
}

describe("Ctrl+Alt+End", () => {
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

  test("presses Ctrl+Alt+Del once and never sends End", () => {
    const { down, up, sent, sas } = rig(true);
    down("ControlLeft");
    down("AltLeft");
    down("End");
    down("End", true);
    down("End", true);
    up("End");
    up("AltLeft");
    up("ControlLeft");
    expect(sas.count).toBe(1);
    expect(keyLog(sent)).toEqual(["ControlLeft down", "AltLeft down", "AltLeft up", "ControlLeft up"]);
  });

  test("leaves nothing held whatever order the keys come up in", () => {
    const { down, up, sent, sas } = rig(true);
    down("ControlLeft");
    down("AltLeft");
    down("End");
    up("ControlLeft");
    up("AltLeft");
    // End still down, now without the modifiers: its repeats are plain End.
    down("End", true);
    up("End");
    expect(sas.count).toBe(1);
    expect(balanced(sent)).toBe(true);
    expect(keyLog(sent).filter((key) => key.startsWith("End"))).toEqual(["End down", "End up"]);
  });

  test("an End already held when Ctrl+Alt join it still comes up", () => {
    const { down, up, sent, sas } = rig(true);
    down("End");
    down("ControlLeft");
    down("AltLeft");
    down("End", true); // a repeat with the modifiers: swallowed, no press
    up("End");
    up("AltLeft");
    up("ControlLeft");
    expect(sas.count).toBe(0);
    expect(balanced(sent)).toBe(true);
  });

  test("losing focus mid-shortcut lets go of Ctrl and Alt", () => {
    const { canvas, down, sent, sas } = rig(true);
    down("ControlLeft");
    down("AltLeft");
    down("End");
    canvas.blur();
    expect(sas.count).toBe(1);
    expect(balanced(sent)).toBe(true);
    expect(keyLog(sent).some((key) => key.startsWith("End"))).toBe(false);
  });

  test("without Ctrl+Alt+Del allowed, the keys go through as they are", () => {
    const { down, up, sent } = rig(false);
    down("ControlLeft");
    down("AltLeft");
    down("End");
    up("End");
    up("AltLeft");
    up("ControlLeft");
    expect(keyLog(sent)).toEqual([
      "ControlLeft down",
      "AltLeft down",
      "End down",
      "End up",
      "AltLeft up",
      "ControlLeft up",
    ]);
  });
});
