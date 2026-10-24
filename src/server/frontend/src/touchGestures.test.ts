import { describe, expect, test } from "bun:test";

import {
  DOUBLE_TAP_MS,
  type GestureAction,
  HOLD_MS,
  MAX_ZOOM,
  NO_ZOOM,
  PINCH_SLOP_PX,
  TAP_SLOP_PX,
  TouchGestures,
  type TouchMode,
  WHEEL_NOTCH_PX,
  WHEEL_STEP,
  acceleration,
  clampView,
  followPoint,
  zoomView,
} from "./touchGestures.js";
import { WHEEL_DELTA } from "./protocol.js";

// Runs a recognizer and keeps every action it returned, in order.
class Fingers {
  readonly gestures: TouchGestures;
  readonly actions: GestureAction[] = [];
  now = 1000;

  constructor(mode: TouchMode) {
    this.gestures = new TouchGestures(mode);
  }

  at(ms: number): this {
    this.now += ms;
    return this;
  }
  down(id: number, x: number, y: number): this {
    this.actions.push(...this.gestures.down(id, x, y, this.now));
    return this;
  }
  move(id: number, x: number, y: number): this {
    this.actions.push(...this.gestures.move(id, x, y, this.now));
    return this;
  }
  up(id: number, x: number, y: number): this {
    this.actions.push(...this.gestures.up(id, x, y, this.now));
    return this;
  }
  cancel(id: number): this {
    this.actions.push(...this.gestures.cancel(id, this.now));
    return this;
  }
  tick(ms = 0): this {
    this.now += ms;
    this.actions.push(...this.gestures.tick(this.now));
    return this;
  }
  // Moves a finger in steps, `ms` apart, so speed is what a real drag has.
  drag(id: number, from: [number, number], to: [number, number], steps = 10, ms = 16): this {
    for (let i = 1; i <= steps; i += 1) {
      this.at(ms).move(id, from[0] + ((to[0] - from[0]) * i) / steps, from[1] + ((to[1] - from[1]) * i) / steps);
    }
    return this;
  }

  kinds(): string[] {
    return this.actions.map((action) =>
      action.kind === "button" ? `${action.button} ${action.down ? "down" : "up"}` : action.kind,
    );
  }
  of<K extends GestureAction["kind"]>(kind: K): Extract<GestureAction, { kind: K }>[] {
    return this.actions.filter((action): action is Extract<GestureAction, { kind: K }> => action.kind === kind);
  }
  // Every button pressed was let go again.
  balanced(): boolean {
    const held = new Set<string>();
    for (const action of this.actions) {
      if (action.kind !== "button") continue;
      if (action.down) {
        if (held.has(action.button)) return false;
        held.add(action.button);
      } else {
        if (!held.has(action.button)) return false;
        held.delete(action.button);
      }
    }
    return held.size === 0;
  }
}

const sum = (moves: { dx: number; dy: number }[]): { dx: number; dy: number } =>
  moves.reduce((total, move) => ({ dx: total.dx + move.dx, dy: total.dy + move.dy }), { dx: 0, dy: 0 });

describe("trackpad", () => {
  test("a tap clicks where the pointer is", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).at(80).up(1, 102, 101);
    expect(f.kinds()).toEqual(["left down", "left up"]);
  });

  test("a wobble within the slop is still a tap", () => {
    const f = new Fingers("trackpad")
      .down(1, 100, 100)
      .at(30)
      .move(1, 100 + TAP_SLOP_PX - 1, 100)
      .at(30)
      .up(1, 100 + TAP_SLOP_PX - 1, 100);
    expect(f.kinds()).toEqual(["left down", "left up"]);
  });

  test("a drag moves the pointer by how far the finger went, and doesn't click", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).drag(1, [100, 100], [130, 140], 20, 40).up(1, 130, 140);
    expect(f.of("button")).toEqual([]);
    const total = sum(f.of("move"));
    // Slow (under 0.1 px/ms): no acceleration, so the travel is the finger's.
    expect(total.dx).toBeCloseTo(30, 5);
    expect(total.dy).toBeCloseTo(40, 5);
  });

  test("a flick goes further than a slow drag over the same distance", () => {
    const slow = new Fingers("trackpad").down(1, 0, 0).drag(1, [0, 0], [200, 0], 20, 50).up(1, 200, 0);
    const fast = new Fingers("trackpad").down(1, 0, 0).drag(1, [0, 0], [200, 0], 20, 4).up(1, 200, 0);
    expect(sum(fast.of("move")).dx).toBeGreaterThan(sum(slow.of("move")).dx * 1.5);
  });

  test("acceleration is one when slow and capped when fast", () => {
    expect(acceleration(1, 100)).toBe(1);
    expect(acceleration(1000, 1)).toBe(4);
    expect(acceleration(10, 10)).toBeGreaterThan(1);
  });

  test("hold then drag holds the left button down along the drag", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).tick(HOLD_MS);
    expect(f.kinds()).toEqual(["left down"]);
    f.drag(1, [100, 100], [160, 100]).up(1, 160, 100);
    expect(f.kinds()[0]).toBe("left down");
    expect(f.kinds().at(-1)).toBe("left up");
    expect(sum(f.of("move")).dx).toBeGreaterThan(0);
    expect(f.balanced()).toBe(true);
  });

  test("the hold counts even when no tick came before the next event", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).at(HOLD_MS + 10).move(1, 140, 100).up(1, 140, 100);
    expect(f.kinds()).toEqual(["left down", "move", "left up"]);
  });

  test("a hold lifted without moving is a click", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).tick(HOLD_MS + 50).at(100).up(1, 100, 100);
    expect(f.kinds()).toEqual(["left down", "left up"]);
  });

  test("moving before the hold is due never holds", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).at(50).move(1, 130, 100).tick(HOLD_MS * 2).up(1, 130, 100);
    expect(f.of("button")).toEqual([]);
    expect(f.gestures.deadline()).toBeNull();
  });

  test("the hold deadline is there only while one finger is undecided", () => {
    const f = new Fingers("trackpad").down(1, 100, 100);
    expect(f.gestures.deadline()).toBe(f.now + HOLD_MS);
    f.at(10).down(2, 200, 100);
    expect(f.gestures.deadline()).toBeNull();
  });

  test("two fingers tapped together right-click", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).at(20).down(2, 160, 100);
    f.at(80).up(1, 100, 100).at(20).up(2, 160, 100);
    expect(f.kinds()).toEqual(["right down", "right up"]);
  });

  test("two fingers held too long are no tap", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).at(20).down(2, 160, 100);
    f.at(600).up(1, 100, 100).up(2, 160, 100);
    expect(f.of("button")).toEqual([]);
  });

  test("a two-finger tap whose second finger then drags is no click", () => {
    const f = new Fingers("trackpad")
      .down(1, 100, 100)
      .down(2, 160, 100)
      .at(50)
      .up(1, 100, 100)
      .move(2, 200, 100)
      .up(2, 200, 100);
    expect(f.of("button")).toEqual([]);
  });

  test("two fingers dragged down scroll up, in quarter notches, and click nothing", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).down(2, 160, 100);
    // A move for each finger in turn, as browsers report them.
    for (let y = 100; y <= 100 + WHEEL_NOTCH_PX * 2; y += 4) f.at(16).move(1, 100, y).move(2, 160, y);
    f.up(1, 100, 100 + WHEEL_NOTCH_PX * 2).up(2, 160, 100 + WHEEL_NOTCH_PX * 2);
    const wheels = f.of("wheel");
    expect(wheels.length).toBeGreaterThan(1);
    for (const wheel of wheels) {
      expect(wheel.dx).toBe(0);
      expect(wheel.dy % WHEEL_STEP).toBe(0);
      expect(wheel.dy).toBeGreaterThan(0);
    }
    // Two notches of midpoint travel, less what was under the slop and
    // less than a step left over.
    const total = wheels.reduce((n, wheel) => n + wheel.dy, 0);
    expect(total).toBeGreaterThan(WHEEL_DELTA);
    expect(total).toBeLessThanOrEqual(WHEEL_DELTA * 2);
    expect(f.of("button")).toEqual([]);
  });

  test("scrolling sideways is the wheel tilted the other way", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).down(2, 100, 160);
    for (let x = 100; x <= 300; x += 10) f.at(16).move(1, x, 100).move(2, x, 160);
    const wheels = f.of("wheel");
    expect(wheels.every((wheel) => wheel.dy === 0)).toBe(true);
    expect(wheels.reduce((n, wheel) => n + wheel.dx, 0)).toBeLessThan(0);
  });

  test("small scroll movements add up instead of being lost", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).down(2, 160, 100);
    // Past the slop, then a pixel at a time.
    f.at(16).move(1, 100, 120).move(2, 160, 120);
    let y = 120;
    for (let i = 0; i < 60; i += 1) {
      y += 1;
      f.at(16).move(1, 100, y).move(2, 160, y);
    }
    const total = f.of("wheel").reduce((n, wheel) => n + wheel.dy, 0);
    const expected = ((y - 100) * WHEEL_DELTA) / WHEEL_NOTCH_PX;
    expect(total).toBeGreaterThan(expected - WHEEL_STEP * 2);
    expect(total).toBeLessThanOrEqual(expected);
  });

  test("a second finger landing while the pointer moves turns it into a scroll", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).drag(1, [100, 100], [140, 100]).down(2, 200, 100);
    const moves = f.of("move").length;
    for (let y = 100; y <= 200; y += 10) f.at(16).move(1, 140, y).move(2, 200, y);
    expect(f.of("move").length).toBe(moves);
    expect(f.of("wheel").length).toBeGreaterThan(0);
  });

  test("lifting one finger mid-scroll ends it: the other doesn't move the pointer or click", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).down(2, 160, 100);
    for (let y = 100; y <= 200; y += 10) f.at(16).move(1, 100, y).move(2, 160, y);
    f.up(1, 100, 200);
    const before = f.actions.length;
    f.drag(2, [160, 200], [260, 250]).up(2, 260, 250);
    expect(f.actions.length).toBe(before);
    // Fresh again afterwards.
    f.at(100).down(3, 50, 50).at(50).up(3, 50, 50);
    expect(f.kinds().slice(-2)).toEqual(["left down", "left up"]);
  });

  test("a third finger is ignored", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).down(2, 160, 100).down(3, 300, 300);
    f.at(50).up(3, 300, 300).up(1, 100, 100).up(2, 160, 100);
    expect(f.kinds()).toEqual(["right down", "right up"]);
  });

  test("a second finger while dragging with the button held is ignored", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).tick(HOLD_MS).drag(1, [100, 100], [150, 100]);
    f.down(2, 300, 300).move(2, 300, 400).up(2, 300, 400);
    f.drag(1, [150, 100], [200, 100]).up(1, 200, 100);
    expect(f.kinds().filter((kind) => kind !== "move")).toEqual(["left down", "left up"]);
  });
});

describe("direct", () => {
  test("a tap clicks where the finger is", () => {
    const f = new Fingers("direct").down(1, 40, 50).at(60).up(1, 41, 50);
    expect(f.actions).toEqual([
      { kind: "point", x: 41, y: 50 },
      { kind: "button", button: "left", down: true },
      { kind: "button", button: "left", down: false },
    ]);
  });

  test("a drag presses where it started, follows the finger and lets go at the end", () => {
    const f = new Fingers("direct").down(1, 40, 50).drag(1, [40, 50], [140, 50], 5).up(1, 140, 50);
    expect(f.actions[0]).toEqual({ kind: "point", x: 40, y: 50 });
    expect(f.actions[1]).toEqual({ kind: "button", button: "left", down: true });
    expect(f.actions.at(-1)).toEqual({ kind: "button", button: "left", down: false });
    const points = f.of("point");
    expect(points.at(-1)).toEqual({ kind: "point", x: 140, y: 50 });
    expect(f.balanced()).toBe(true);
  });

  test("a long press right-clicks where it is, once", () => {
    const f = new Fingers("direct").down(1, 40, 50).tick(HOLD_MS);
    expect(f.actions).toEqual([
      { kind: "point", x: 40, y: 50 },
      { kind: "button", button: "right", down: true },
      { kind: "button", button: "right", down: false },
    ]);
    f.tick(HOLD_MS).drag(1, [40, 50], [100, 100]).up(1, 100, 100);
    expect(f.actions.length).toBe(3);
  });

  test("two fingers scroll without pressing anything", () => {
    const f = new Fingers("direct").down(1, 100, 100).at(30).down(2, 160, 100);
    for (let y = 100; y >= 0; y -= 10) f.at(16).move(1, 100, y).move(2, 160, y);
    f.up(1, 100, 0).up(2, 160, 0);
    expect(f.of("button")).toEqual([]);
    expect(f.of("point")).toEqual([]);
    // Fingers going up: content follows them, the wheel turns down.
    expect(f.of("wheel").reduce((n, wheel) => n + wheel.dy, 0)).toBeLessThan(0);
  });

  test("a second finger mid-drag is ignored, so the drag ends cleanly", () => {
    const f = new Fingers("direct").down(1, 40, 50).drag(1, [40, 50], [100, 50]).down(2, 200, 200);
    f.drag(2, [200, 200], [200, 300]).up(2, 200, 300).up(1, 100, 50);
    expect(f.of("wheel")).toEqual([]);
    expect(f.balanced()).toBe(true);
  });
});

describe("pinch", () => {
  test("fingers apart zoom in by the ratio of their gap, about their midpoint", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).down(2, 200, 100);
    f.at(16).move(1, 50, 100).at(16).move(2, 250, 100);
    const zooms = f.of("zoom");
    expect(zooms.length).toBeGreaterThan(0);
    const factor = zooms.reduce((n, zoom) => n * zoom.factor, 1);
    expect(factor).toBeCloseTo(2, 5);
    expect(zooms[0]?.fromX).toBe(150);
    expect(zooms.at(-1)?.toX).toBe(150);
    expect(f.of("wheel")).toEqual([]);
    expect(f.of("button")).toEqual([]);
  });

  test("a pinch decides first, then moving both fingers pans", () => {
    const f = new Fingers("direct").down(1, 100, 100).down(2, 200, 100);
    f.at(16).move(1, 100 - PINCH_SLOP_PX, 100);
    f.at(16).move(1, 100 - PINCH_SLOP_PX, 200).move(2, 200, 200);
    expect(f.of("wheel")).toEqual([]);
    const last = f.of("zoom").at(-1);
    expect(last?.toY).toBe(200);
  });

  test("watching only, two fingers dragged pan instead of scrolling", () => {
    const f = new Fingers("view").down(1, 100, 100).down(2, 200, 100);
    for (let y = 100; y <= 200; y += 10) f.at(16).move(1, 100, y).move(2, 200, y);
    expect(f.of("wheel")).toEqual([]);
    expect(f.of("zoom").length).toBeGreaterThan(0);
  });

  test("watching only, nothing reaches the machine", () => {
    const f = new Fingers("view").down(1, 100, 100).at(50).up(1, 100, 100);
    f.at(500).down(2, 100, 100).tick(HOLD_MS * 2).up(2, 100, 100);
    f.at(500).down(3, 100, 100).drag(3, [100, 100], [200, 200]).up(3, 200, 200);
    f.at(500).down(4, 100, 100).down(5, 200, 100).at(50).up(4, 100, 100).up(5, 200, 100);
    expect(f.actions.every((action) => action.kind === "pan")).toBe(true);
    expect(f.of("pan").length).toBeGreaterThan(0);
  });

  test("lifting a finger mid-pinch stops it; the other doesn't pan or click", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).down(2, 200, 100);
    f.at(16).move(1, 50, 100).up(1, 50, 100);
    const before = f.actions.length;
    f.drag(2, [200, 100], [300, 300]).up(2, 300, 300);
    expect(f.actions.length).toBe(before);
  });
});

describe("two-finger double tap", () => {
  const twoTap = (f: Fingers): Fingers => f.down(1, 100, 100).down(2, 160, 100).at(60).up(1, 100, 100).up(2, 160, 100);

  test("resets the zoom when zoomed, without a right click", () => {
    const f = new Fingers("trackpad");
    f.gestures.zoomed = true;
    twoTap(f);
    expect(f.actions).toEqual([]);
    expect(f.gestures.deadline()).toBe(f.now + DOUBLE_TAP_MS);
    twoTap(f.at(100));
    expect(f.actions).toEqual([{ kind: "reset_zoom" }]);
    f.tick(DOUBLE_TAP_MS * 2);
    expect(f.actions).toEqual([{ kind: "reset_zoom" }]);
  });

  test("zoomed, a single two-finger tap right-clicks once the window passes", () => {
    const f = new Fingers("trackpad");
    f.gestures.zoomed = true;
    twoTap(f).tick(DOUBLE_TAP_MS);
    expect(f.kinds()).toEqual(["right down", "right up"]);
  });

  test("in direct mode the delayed right click lands between the fingers", () => {
    const f = new Fingers("direct");
    f.gestures.zoomed = true;
    twoTap(f).tick(DOUBLE_TAP_MS);
    expect(f.actions[0]).toEqual({ kind: "point", x: 130, y: 100 });
  });

  test("not zoomed, every two-finger tap right-clicks at once", () => {
    const f = new Fingers("trackpad");
    twoTap(f);
    twoTap(f.at(100));
    expect(f.kinds()).toEqual(["right down", "right up", "right down", "right up"]);
  });

  test("watching only, resets the zoom", () => {
    const f = new Fingers("view");
    twoTap(f);
    twoTap(f.at(100));
    expect(f.actions).toEqual([{ kind: "reset_zoom" }]);
  });

  test("too far apart, two taps are two taps", () => {
    const f = new Fingers("view");
    twoTap(f);
    twoTap(f.at(DOUBLE_TAP_MS + 200));
    expect(f.actions).toEqual([]);
  });
});

describe("no stuck buttons", () => {
  test("pointercancel mid-drag lets go without a click", () => {
    const f = new Fingers("direct").down(1, 40, 50).drag(1, [40, 50], [100, 50]).cancel(1);
    expect(f.kinds().at(-1)).toBe("left up");
    expect(f.balanced()).toBe(true);
  });

  test("pointercancel on a held trackpad drag lets go", () => {
    const f = new Fingers("trackpad").down(1, 40, 50).tick(HOLD_MS).cancel(1);
    expect(f.kinds()).toEqual(["left down", "left up"]);
  });

  test("pointercancel on a tap is no click", () => {
    const f = new Fingers("trackpad").down(1, 40, 50).at(30).cancel(1).tick(HOLD_MS * 2);
    expect(f.actions).toEqual([]);
  });

  test("pointercancel of one of two fingers ends the gesture", () => {
    const f = new Fingers("trackpad").down(1, 100, 100).down(2, 160, 100).cancel(1);
    f.at(30).up(2, 160, 100);
    expect(f.actions).toEqual([]);
  });

  test("reset lets go of a held button", () => {
    const f = new Fingers("trackpad").down(1, 40, 50).tick(HOLD_MS);
    f.actions.push(...f.gestures.reset());
    expect(f.balanced()).toBe(true);
    // The finger's later lift is nobody's.
    f.up(1, 40, 50);
    expect(f.kinds()).toEqual(["left down", "left up"]);
  });

  test("changing mode mid-drag lets go", () => {
    const f = new Fingers("direct").down(1, 40, 50).drag(1, [40, 50], [100, 50]);
    f.actions.push(...f.gestures.setMode("trackpad"));
    f.up(1, 100, 50);
    expect(f.balanced()).toBe(true);
  });

  test("random finger soup always ends with nothing held", () => {
    let seed = 7;
    const random = (): number => {
      seed = (seed * 1103515245 + 12345) % 2147483648;
      return seed / 2147483648;
    };
    for (const mode of ["trackpad", "direct", "view"] as const) {
      for (let round = 0; round < 200; round += 1) {
        const f = new Fingers(mode);
        const down = new Map<number, [number, number]>();
        for (let step = 0; step < 30; step += 1) {
          f.at(Math.floor(random() * 300));
          const id = 1 + Math.floor(random() * 3);
          const x = Math.floor(random() * 400);
          const y = Math.floor(random() * 400);
          const roll = random();
          if (!down.has(id)) {
            f.down(id, x, y);
            down.set(id, [x, y]);
          } else if (roll < 0.5) {
            f.move(id, x, y);
          } else if (roll < 0.85) {
            f.up(id, x, y);
            down.delete(id);
          } else if (roll < 0.95) {
            f.cancel(id);
            down.delete(id);
          } else {
            f.tick();
          }
        }
        for (const [id, [x, y]] of down) f.up(id, x, y);
        f.tick(DOUBLE_TAP_MS * 2);
        expect(f.balanced()).toBe(true);
      }
    }
  });
});

describe("view", () => {
  const picture = { left: 0, top: 100, width: 400, height: 225 }; // 16:9 in a 400×425 box

  test("zooming keeps the point under the fingers where it was", () => {
    const view = zoomView(NO_ZOOM, 2, 100, 200, 100, 200);
    expect(view.scale).toBe(2);
    // The content point (100, 200) is still on screen at (100, 200).
    expect(100 * view.scale + view.x).toBe(100);
    expect(200 * view.scale + view.y).toBe(200);
  });

  test("zooming while moving the fingers pans", () => {
    const view = zoomView({ scale: 2, x: -100, y: -200 }, 1, 100, 200, 150, 260);
    expect(view).toEqual({ scale: 2, x: -50, y: -140 });
  });

  test("zoom stays between 1 and the maximum", () => {
    expect(zoomView(NO_ZOOM, 0.2, 0, 0, 0, 0).scale).toBe(1);
    expect(zoomView({ scale: 5, x: 0, y: 0 }, 10, 0, 0, 0, 0).scale).toBe(MAX_ZOOM);
  });

  test("unzoomed, the picture sits where the layout put it", () => {
    expect(clampView(NO_ZOOM, 400, 425, picture)).toEqual({ scale: 1, x: 0, y: 0 });
    expect(clampView({ scale: 1, x: 30, y: -40 }, 400, 425, picture)).toEqual({ scale: 1, x: 0, y: 0 });
  });

  test("zoomed, the picture can't be panned off into the black", () => {
    // 2×: the picture is 800×450, so wider and taller than the box.
    const left = clampView({ scale: 2, x: 500, y: 0 }, 400, 425, picture);
    expect(left.x).toBe(0);
    const right = clampView({ scale: 2, x: -5000, y: 0 }, 400, 425, picture);
    expect(right.x).toBe(400 - 800);
    // Its top edge (200 zoomed) can't come below the box's.
    const top = clampView({ scale: 2, x: 0, y: 500 }, 400, 425, picture);
    expect(top.y).toBe(-200);
    const bottom = clampView({ scale: 2, x: 0, y: -5000 }, 400, 425, picture);
    expect(bottom.y).toBe(425 - 2 * (100 + 225));
  });

  test("an axis that still fits is centred", () => {
    // 1.5×: 337.5 tall in a 425 box.
    const view = clampView({ scale: 1.5, x: 0, y: 0 }, 400, 425, picture);
    expect(view.y + 1.5 * 100).toBeCloseTo((425 - 337.5) / 2, 5);
  });

  test("the picture follows a point near the edge", () => {
    const view = { scale: 2, x: -100, y: -100 };
    expect(followPoint(view, 200, 200, 400, 400, 48)).toEqual(view);
    expect(followPoint(view, 390, 200, 400, 400, 48)).toEqual({ scale: 2, x: -138, y: -100 });
    expect(followPoint(view, 200, 10, 400, 400, 48)).toEqual({ scale: 2, x: -100, y: -62 });
  });
});
