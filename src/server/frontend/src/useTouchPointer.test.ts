import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";

import type { InputEvent } from "./protocol.js";
import { HOLD_MS, MAX_ZOOM } from "./touchGestures.js";

// useTouchInput run without a DOM, as in useTouchInput.test.ts: React's
// hooks are stood in for, and the screen, the zoomed box and the canvas are
// plain objects. The canvas's on-screen box is worked out from the zoomed
// box's CSS transform, as a browser would, so where a touch lands on the
// machine is checked against geometry done here, not the hook's own sums.
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

const { useTouchInput } = await import("./useTouchInput.js");

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
  count(): number {
    let total = 0;
    for (const set of this.listeners.values()) total += set.size;
    return total;
  }
}

// Timers and frames run by hand.
const timers = new Map<number, { at: number; fn: () => void }>();
const frames = new Map<number, () => void>();
let nextId = 1;
let clock = 1000;
const fakeWindow = Object.assign(new Target(), {
  setTimeout: (fn: () => void, ms: number) => {
    const id = nextId++;
    timers.set(id, { at: clock + ms, fn });
    return id;
  },
  clearTimeout: (id: number) => timers.delete(id),
  requestAnimationFrame: (fn: () => void) => {
    const id = nextId++;
    frames.set(id, fn);
    return id;
  },
  cancelAnimationFrame: (id: number) => frames.delete(id),
});
const fakePerformance = { now: () => clock };

function advance(ms: number): void {
  clock += ms;
  for (const [id, timer] of [...timers]) {
    if (timer.at <= clock) {
      timers.delete(id);
      timer.fn();
    }
  }
}
function flushFrames(): void {
  for (const [id, fn] of [...frames]) {
    frames.delete(id);
    fn();
  }
}

class FakeResizeObserver {
  observe(): void {}
  disconnect(): void {}
}

// The screen's box on the page, and the picture laid out in it unzoomed: a
// 16:9 picture letterboxed in a 400 × 300 screen.
const SCREEN = { left: 10, top: 20, width: 400, height: 300 };
const PICTURE = { left: 0, top: 37.5, width: 400, height: 225 };

function parseTransform(transform: string): { scale: number; x: number; y: number } {
  if (transform === "") return { scale: 1, x: 0, y: 0 };
  const match = /^translate\((-?[\d.e+-]+)px, (-?[\d.e+-]+)px\) scale\(([\d.e+-]+)\)$/.exec(transform);
  if (match === null) throw new Error(`unexpected transform ${transform}`);
  return { x: Number(match[1]), y: Number(match[2]), scale: Number(match[3]) };
}

function rig(mode: "trackpad" | "direct" | "view") {
  const screen = Object.assign(new Target(), {
    clientWidth: SCREEN.width,
    clientHeight: SCREEN.height,
    getBoundingClientRect: () => ({ ...SCREEN }),
  });
  const view = { style: { transform: "" } };
  const canvas = {
    offsetLeft: PICTURE.left,
    offsetTop: PICTURE.top,
    offsetWidth: PICTURE.width,
    offsetHeight: PICTURE.height,
    // transform-origin 0 0: scaled about the screen's top-left, then moved.
    getBoundingClientRect: () => {
      const t = parseTransform(view.style.transform);
      return {
        left: SCREEN.left + t.x + t.scale * PICTURE.left,
        top: SCREEN.top + t.y + t.scale * PICTURE.top,
        width: t.scale * PICTURE.width,
        height: t.scale * PICTURE.height,
      };
    },
  };
  const cursor = { style: { transform: "" } };
  const sent: InputEvent[] = [];
  const touch = useTouchInput(
    { current: screen as unknown as HTMLDivElement },
    { current: view as unknown as HTMLDivElement },
    { current: canvas as unknown as HTMLCanvasElement },
    { current: cursor as unknown as HTMLDivElement },
    true,
    mode,
    (event) => sent.push(event),
  );
  const finger = (id: number, x: number, y: number) => ({
    pointerType: "touch",
    pointerId: id,
    clientX: x,
    clientY: y,
    preventDefault: () => {},
  });
  const down = (id: number, x: number, y: number) => screen.fire("pointerdown", finger(id, x, y));
  const move = (id: number, x: number, y: number) => screen.fire("pointermove", finger(id, x, y));
  const up = (id: number, x: number, y: number) => screen.fire("pointerup", finger(id, x, y));
  const tap = (x: number, y: number) => {
    down(9, x, y);
    advance(50);
    up(9, x, y);
    advance(400);
  };
  // Two fingers either side of (x, y), `from` apart, spread to `to` apart
  // in small steps about the same midpoint, then lifted.
  const pinch = (x: number, y: number, from: number, to: number, steps = 8) => {
    down(1, x - from / 2, y);
    down(2, x + from / 2, y);
    for (let i = 1; i <= steps; i += 1) {
      const gap = from + ((to - from) * i) / steps;
      advance(16);
      move(1, x - gap / 2, y);
      move(2, x + gap / 2, y);
    }
    up(1, x - to / 2, y);
    up(2, x + to / 2, y);
    advance(400);
  };
  const moves = () => sent.filter((event) => event.kind === "mouse_move");
  const lastMove = () => moves().at(-1) as { x: number; y: number } | undefined;
  return { screen, view, canvas, cursor, sent, touch, down, move, up, tap, pinch, moves, lastMove };
}

// Where a client point is on the machine's screen, from the transform alone.
function expected(transform: string, clientX: number, clientY: number): { x: number; y: number } {
  const t = parseTransform(transform);
  const contentX = (clientX - SCREEN.left - t.x) / t.scale;
  const contentY = (clientY - SCREEN.top - t.y) / t.scale;
  return { x: (contentX - PICTURE.left) / PICTURE.width, y: (contentY - PICTURE.top) / PICTURE.height };
}

describe("useTouchInput", () => {
  const saved = {
    window: globalThis.window,
    performance: globalThis.performance,
    ResizeObserver: globalThis.ResizeObserver,
  };
  beforeEach(() => {
    timers.clear();
    frames.clear();
    (globalThis as Record<string, unknown>).window = fakeWindow;
    (globalThis as Record<string, unknown>).performance = fakePerformance;
    (globalThis as Record<string, unknown>).ResizeObserver = FakeResizeObserver;
  });
  afterEach(() => {
    for (const cleanup of cleanups) cleanup();
    cleanups = [];
    (globalThis as Record<string, unknown>).window = saved.window;
    (globalThis as Record<string, unknown>).performance = saved.performance;
    (globalThis as Record<string, unknown>).ResizeObserver = saved.ResizeObserver;
  });

  test("unzoomed, a direct tap lands where the finger is on the picture", () => {
    const { tap, lastMove, view } = rig("direct");
    expect(view.style.transform).toBe("");
    tap(110, 100);
    expect(lastMove()).toEqual({ kind: "mouse_move", x: 0.25, y: (80 - 37.5) / 225 });
  });

  test("zoomed about a point, that point stays put and taps land under the finger", () => {
    const { tap, pinch, lastMove, view, sent } = rig("direct");
    pinch(110, 100, 60, 120);
    // A pinch sends the machine nothing.
    expect(sent).toEqual([]);
    const t = parseTransform(view.style.transform);
    expect(t.scale).toBeCloseTo(2, 6);
    // Across, the picture fills the screen at any zoom, so the point under
    // the fingers is where it was before. Down, it's re-centred for as long
    // as it's shorter than the screen, so the fingers drift on it there.
    tap(110, 100);
    expect(lastMove()?.x).toBeCloseTo(0.25, 6);
    // Anywhere else: what the transform puts there.
    for (const [x, y] of [
      [310, 250],
      [12, 22],
      [405, 315],
      [210, 170],
    ] as const) {
      tap(x, y);
      const want = expected(view.style.transform, x, y);
      expect(lastMove()?.x).toBeCloseTo(Math.min(1, Math.max(0, want.x)), 6);
      expect(lastMove()?.y).toBeCloseTo(Math.min(1, Math.max(0, want.y)), 6);
    }
    // Every tap was a whole click.
    const buttons = sent.filter((event) => event.kind === "mouse_button");
    expect(buttons.length).toBe(10);
  });

  test("at the most zoom, the picture covers the screen and corner taps stay on it", () => {
    const { tap, pinch, lastMove, view } = rig("direct");
    // Far more than the maximum, at the picture's bottom-right corner.
    pinch(405, 255, 30, 400, 20);
    pinch(405, 255, 30, 400, 20);
    const t = parseTransform(view.style.transform);
    expect(t.scale).toBe(MAX_ZOOM);
    // Nothing past the picture's edge: it was kept covering the screen,
    // so the screen's corners are on the picture without the hook's clamp.
    const corners = [
      expected(view.style.transform, SCREEN.left, SCREEN.top),
      expected(view.style.transform, SCREEN.left + SCREEN.width, SCREEN.top + SCREEN.height),
    ];
    for (const corner of corners) {
      for (const value of [corner.x, corner.y]) {
        expect(value).toBeGreaterThanOrEqual(-1e-9);
        expect(value).toBeLessThanOrEqual(1 + 1e-9);
      }
    }
    tap(SCREEN.left, SCREEN.top);
    const topLeft = lastMove();
    tap(SCREEN.left + SCREEN.width, SCREEN.top + SCREEN.height);
    const bottomRight = lastMove();
    if (topLeft === undefined || bottomRight === undefined) throw new Error("no moves");
    expect(topLeft.x).toBeCloseTo(corners[0]?.x ?? NaN, 6);
    expect(bottomRight.y).toBeCloseTo(corners[1]?.y ?? NaN, 6);
    // One sixth of the picture across, a sixth of 400 / 225 of it down.
    expect(bottomRight.x - topLeft.x).toBeCloseTo(1 / MAX_ZOOM, 6);
    expect(bottomRight.y - topLeft.y).toBeCloseTo(SCREEN.height / (MAX_ZOOM * PICTURE.height), 6);
  });

  test("pinching in past no zoom leaves no transform at all", () => {
    const { pinch, view, touch } = rig("direct");
    pinch(210, 170, 60, 180);
    expect(view.style.transform).not.toBe("");
    pinch(210, 170, 200, 20);
    pinch(210, 170, 200, 20);
    expect(view.style.transform).toBe("");
    pinch(210, 170, 60, 180);
    touch.resetZoom();
    expect(view.style.transform).toBe("");
  });

  test("zoomed in trackpad mode, the drawn pointer sits on the machine's pointer", () => {
    const { pinch, cursor, view, down, move, up, lastMove } = rig("trackpad");
    pinch(210, 170, 60, 180);
    down(3, 200, 200);
    for (let i = 1; i <= 10; i += 1) {
      advance(16);
      move(3, 200 + 6 * i, 200 + 3 * i);
    }
    up(3, 260, 230);
    flushFrames();
    const pointer = lastMove();
    if (pointer === undefined) throw new Error("no move");
    const placed = /^translate\((-?[\d.e+-]+)px, (-?[\d.e+-]+)px\)$/.exec(cursor.style.transform);
    if (placed === null) throw new Error(`cursor at ${cursor.style.transform}`);
    // The pointer, as a client point, back through the transform.
    const at = expected(view.style.transform, SCREEN.left + Number(placed[1]), SCREEN.top + Number(placed[2]));
    expect(at.x).toBeCloseTo(pointer.x, 6);
    expect(at.y).toBeCloseTo(pointer.y, 6);
  });

  test("view only: fingers zoom and pan, and the machine gets nothing", () => {
    const { pinch, down, move, up, tap, view, sent } = rig("view");
    pinch(210, 170, 60, 180);
    down(1, 200, 200);
    advance(HOLD_MS + 100);
    move(1, 150, 150);
    up(1, 150, 150);
    tap(100, 100);
    expect(view.style.transform).not.toBe("");
    expect(sent).toEqual([]);
  });

  test("the view closing mid-drag lets go of the button and takes every listener with it", () => {
    const { screen, down, move, sent } = rig("direct");
    const before = fakeWindow.count();
    down(1, 100, 100);
    advance(16);
    move(1, 150, 150);
    expect(sent.filter((event) => event.kind === "mouse_button")).toEqual([
      { kind: "mouse_button", button: "left", down: true },
    ]);
    for (const cleanup of cleanups) cleanup();
    cleanups = [];
    expect(sent.at(-1)).toEqual({ kind: "mouse_button", button: "left", down: false });
    expect(screen.count()).toBe(0);
    expect(fakeWindow.count()).toBe(before - 1);
    expect(timers.size).toBe(0);
    expect(frames.size).toBe(0);
  });

  test("closing before a hold is due leaves no timer to press anything later", () => {
    const { down, sent } = rig("trackpad");
    down(1, 100, 100);
    expect(timers.size).toBe(1);
    for (const cleanup of cleanups) cleanup();
    cleanups = [];
    advance(HOLD_MS * 2);
    expect(sent.some((event) => event.kind === "mouse_button")).toBe(false);
  });

  test("the window losing focus mid hold-drag lets go", () => {
    const { down, move, sent } = rig("trackpad");
    down(1, 100, 100);
    advance(HOLD_MS + 10);
    move(1, 140, 100);
    expect(sent.filter((event) => event.kind === "mouse_button").at(-1)).toEqual({
      kind: "mouse_button",
      button: "left",
      down: true,
    });
    fakeWindow.fire("blur");
    expect(sent.filter((event) => event.kind === "mouse_button").at(-1)).toEqual({
      kind: "mouse_button",
      button: "left",
      down: false,
    });
  });

  test("a pointercancel mid-drag lets go without a click", () => {
    const { screen, down, move, sent } = rig("direct");
    down(1, 100, 100);
    advance(16);
    move(1, 150, 150);
    screen.fire("pointercancel", { pointerType: "touch", pointerId: 1 });
    const buttons = sent.filter((event) => event.kind === "mouse_button");
    expect(buttons).toEqual([
      { kind: "mouse_button", button: "left", down: true },
      { kind: "mouse_button", button: "left", down: false },
    ]);
  });

  test("a long press's menu is dropped, a right click's isn't", () => {
    const { screen, down, up } = rig("view");
    const menu = () => {
      let prevented = false;
      screen.fire("contextmenu", { preventDefault: () => (prevented = true) });
      return prevented;
    };
    down(1, 100, 100);
    expect(menu()).toBe(true);
    up(1, 100, 100);
    screen.fire("pointerdown", { pointerType: "mouse", pointerId: 2, clientX: 0, clientY: 0, preventDefault: () => {} });
    expect(menu()).toBe(false);
  });

  test("the mouse and pen are left alone", () => {
    const { screen, sent } = rig("direct");
    for (const pointerType of ["mouse", "pen"]) {
      const event = { pointerType, pointerId: 1, clientX: 100, clientY: 100, preventDefault: () => {} };
      screen.fire("pointerdown", event);
      screen.fire("pointermove", { ...event, clientX: 200 });
      screen.fire("pointerup", event);
      screen.fire("pointercancel", event);
    }
    advance(HOLD_MS * 2);
    expect(sent).toEqual([]);
  });
});
