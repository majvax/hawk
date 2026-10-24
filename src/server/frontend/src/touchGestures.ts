import { WHEEL_DELTA } from "./protocol.js";

// Touch gestures on the live view, worked out from pointer positions and
// times alone: no DOM, no timers of its own, so every case can be run in a
// test. The hook feeds it each touch (and calls `tick` when `deadline`
// comes, for a press held still) and carries out the actions it returns.
//
// Three ways to read the fingers:
// - trackpad: the screen is a laptop's touchpad. A drag moves the
//   machine's pointer by how far the finger went (faster for a quick
//   flick), a tap clicks where the pointer is, two fingers tapped together
//   right-click, a finger held still then dragged holds the left button
//   down, and two fingers dragged scroll.
// - direct: the finger is the pointer. A tap clicks where it lands, a drag
//   holds the left button down along it, a long press right-clicks, and
//   two fingers dragged scroll.
// - view: nothing goes to the machine (watching only, or control not
//   possible): one finger pans the zoomed picture.
// In every mode, two fingers pinched apart or together zoom the picture on
// this screen (never the machine's), and moving them while pinching pans
// it.

export type TouchMode = "trackpad" | "direct" | "view";

export type GestureAction =
  // trackpad: move the pointer by this much, in CSS pixels of the picture
  // as shown, acceleration included.
  | { kind: "move"; dx: number; dy: number }
  // direct: put the pointer under this point, in client coordinates.
  | { kind: "point"; x: number; y: number }
  | { kind: "button"; button: "left" | "right"; down: boolean }
  // In WHEEL_DELTA units, signed as the protocol has them: positive is up
  // / right.
  | { kind: "wheel"; dx: number; dy: number }
  // Scale the picture by `factor` about the client point `from`, which
  // ends up at `to` (the fingers' midpoint before and after).
  | { kind: "zoom"; factor: number; fromX: number; fromY: number; toX: number; toY: number }
  // view: move the picture by this much, in client pixels.
  | { kind: "pan"; dx: number; dy: number }
  | { kind: "reset_zoom" };

// How far a finger can wander and still be tapping (or holding still).
export const TAP_SLOP_PX = 10;
// A press held still this long is a hold: the left button in trackpad mode
// (to drag), a right click in direct mode.
export const HOLD_MS = 450;
// Two fingers tapping: both down and up within this long.
export const TWO_TAP_MS = 300;
// A second two-finger tap within this long of the first is a double tap.
export const DOUBLE_TAP_MS = 350;
// Two fingers become a pinch once the gap between them changes this much,
// or a scroll once their midpoint moves this far, whichever comes first.
export const PINCH_SLOP_PX = 24;
export const SCROLL_SLOP_PX = 12;
// Finger travel for one wheel notch, about three lines of text on screen.
export const WHEEL_NOTCH_PX = 48;
// Scrolling goes out in quarter notches: smooth where the machine's apps
// scroll by less than a notch, and not a packet per pixel.
export const WHEEL_STEP = WHEEL_DELTA / 4;

// Trackpad acceleration: a slow finger moves the pointer as far as it
// went, a fast one up to MAX_GAIN times as far, in between in proportion to
// its speed (in pixels per millisecond) past ACCEL_FROM.
const ACCEL_FROM = 0.15;
const ACCEL = 1.5;
const MAX_GAIN = 4;

export function acceleration(distance: number, ms: number): number {
  const speed = distance / Math.max(1, ms);
  return Math.min(MAX_GAIN, 1 + ACCEL * Math.max(0, speed - ACCEL_FROM));
}

interface Finger {
  x: number;
  y: number;
  startX: number;
  startY: number;
}

type Phase =
  | "idle"
  // One finger down, not yet a tap, a drag or a hold.
  | "one"
  // One finger moving: the pointer (trackpad), a left drag (direct), a pan
  // (view).
  | "drag"
  // One finger held still: the left button is down (trackpad), or the
  // right click went (direct).
  | "hold"
  // Two fingers down, not yet a tap, a scroll or a pinch.
  | "two"
  // One of a two-finger tap is up; the other's lift finishes it.
  | "two_tap"
  | "scroll"
  | "pinch"
  // Over: whatever fingers are still down do nothing until all are up.
  | "spent";

export class TouchGestures {
  // Whether the picture is zoomed in: a two-finger tap then waits to see
  // whether a second follows (which resets the zoom) before right-clicking.
  zoomed = false;

  private phase: Phase = "idle";
  private readonly fingers = new Map<number, Finger>();
  // Fingers past the two a gesture uses, or landing once it's decided.
  private readonly ignored = new Set<number>();
  private held: "left" | null = null;
  private downAt = 0;
  private lastAt = 0;
  // Two fingers: when the second landed, the gap and midpoint then and at
  // the last move, and whether it can still be a tap.
  private twoAt = 0;
  private twoTap = false;
  private gap = 0;
  private midX = 0;
  private midY = 0;
  // Scroll: the axes it's locked to, and travel not yet sent.
  private scrollX = true;
  private scrollY = true;
  private wheelX = 0;
  private wheelY = 0;
  // A two-finger tap, for the double tap that resets the zoom.
  private lastTwoTap = -Infinity;
  // A right click waiting out the double-tap window (zoomed), and where.
  private rightAt: number | null = null;
  private rightX = 0;
  private rightY = 0;

  constructor(private mode: TouchMode) {}

  // A new mode starts clean: whatever was held is let go.
  setMode(mode: TouchMode): GestureAction[] {
    const out = this.reset();
    this.mode = mode;
    return out;
  }

  // Lets go of everything, as if every finger had been lifted somewhere
  // that didn't count.
  reset(): GestureAction[] {
    const out = this.releaseHeld();
    this.fingers.clear();
    this.ignored.clear();
    this.phase = "idle";
    this.rightAt = null;
    return out;
  }

  // When `tick` next has something to do, or null.
  deadline(): number | null {
    const hold = this.phase === "one" && this.mode !== "view" ? this.downAt + HOLD_MS : null;
    if (hold === null) return this.rightAt;
    return this.rightAt === null ? hold : Math.min(hold, this.rightAt);
  }

  tick(now: number): GestureAction[] {
    const out: GestureAction[] = [];
    if (this.rightAt !== null && now >= this.rightAt) {
      this.rightAt = null;
      out.push(...this.rightClick(this.rightX, this.rightY));
    }
    if (this.phase === "one" && this.mode !== "view" && now - this.downAt >= HOLD_MS) {
      const finger = this.only();
      if (finger !== null) {
        this.phase = "hold";
        if (this.mode === "trackpad") {
          this.held = "left";
          out.push({ kind: "button", button: "left", down: true });
        } else {
          out.push(...this.rightClick(finger.startX, finger.startY));
        }
      }
    }
    return out;
  }

  down(id: number, x: number, y: number, now: number): GestureAction[] {
    const out = this.tick(now);
    const finger = { x, y, startX: x, startY: y };
    if (this.fingers.size === 0) {
      this.fingers.set(id, finger);
      this.phase = "one";
      this.downAt = now;
      this.lastAt = now;
      return out;
    }
    // A second finger turns one finger into two, unless the one is holding
    // a button down (a drag keeps going) or the gesture is over.
    const second = this.fingers.size === 1 && (this.phase === "one" || (this.phase === "drag" && this.held === null));
    if (!second) {
      this.ignored.add(id);
      return out;
    }
    const first = this.only();
    if (first === null) return out;
    this.fingers.set(id, finger);
    // The first finger's start is where the two-finger gesture starts too.
    first.startX = first.x;
    first.startY = first.y;
    this.twoTap = this.phase === "one";
    this.phase = "two";
    this.twoAt = now;
    this.gap = Math.hypot(x - first.x, y - first.y);
    this.midX = (x + first.x) / 2;
    this.midY = (y + first.y) / 2;
    return out;
  }

  move(id: number, x: number, y: number, now: number): GestureAction[] {
    const out = this.tick(now);
    const finger = this.fingers.get(id);
    if (finger === undefined) return out;
    const dx = x - finger.x;
    const dy = y - finger.y;
    if (dx === 0 && dy === 0) return out;
    finger.x = x;
    finger.y = y;
    const sinceLast = now - this.lastAt;
    this.lastAt = now;

    switch (this.phase) {
      case "one": {
        const fromX = x - finger.startX;
        const fromY = y - finger.startY;
        if (Math.hypot(fromX, fromY) <= TAP_SLOP_PX) return out;
        this.phase = "drag";
        // Everything since the press counts, so a slow start isn't lost.
        if (this.mode === "trackpad") {
          const gain = acceleration(Math.hypot(fromX, fromY), now - this.downAt);
          out.push({ kind: "move", dx: fromX * gain, dy: fromY * gain });
        } else if (this.mode === "direct") {
          this.held = "left";
          out.push(
            { kind: "point", x: finger.startX, y: finger.startY },
            { kind: "button", button: "left", down: true },
            { kind: "point", x, y },
          );
        } else {
          out.push({ kind: "pan", dx: fromX, dy: fromY });
        }
        return out;
      }
      case "drag":
        if (this.mode === "trackpad") {
          const gain = acceleration(Math.hypot(dx, dy), sinceLast);
          out.push({ kind: "move", dx: dx * gain, dy: dy * gain });
        } else if (this.mode === "direct") {
          out.push({ kind: "point", x, y });
        } else {
          out.push({ kind: "pan", dx, dy });
        }
        return out;
      case "hold":
        // Dragging with the left button down; a long press in direct mode
        // has had its right click, and the rest of it is nothing.
        if (this.mode === "trackpad") {
          const gain = acceleration(Math.hypot(dx, dy), sinceLast);
          out.push({ kind: "move", dx: dx * gain, dy: dy * gain });
        }
        return out;
      case "two_tap":
        if (Math.hypot(x - finger.startX, y - finger.startY) > TAP_SLOP_PX) this.phase = "spent";
        return out;
      case "two":
      case "scroll":
      case "pinch":
        out.push(...this.moveTwo(now));
        return out;
      default:
        return out;
    }
  }

  up(id: number, x: number, y: number, now: number): GestureAction[] {
    if (this.ignored.delete(id)) return this.tick(now);
    const out = this.move(id, x, y, now);
    if (!this.fingers.has(id)) return out;
    this.fingers.delete(id);

    switch (this.phase) {
      case "one":
        // A tap: a click where the pointer is, or where the finger was.
        if (this.mode === "trackpad") {
          out.push({ kind: "button", button: "left", down: true }, { kind: "button", button: "left", down: false });
        } else if (this.mode === "direct") {
          out.push(
            { kind: "point", x, y },
            { kind: "button", button: "left", down: true },
            { kind: "button", button: "left", down: false },
          );
        }
        break;
      case "drag":
      case "hold":
        out.push(...this.releaseHeld());
        break;
      case "two": {
        // The first of two fingers up: a tap if both were quick and still.
        const other = this.only();
        if (this.twoTap && now - this.twoAt <= TWO_TAP_MS && other !== null) {
          this.phase = "two_tap";
          this.rightX = (x + other.x) / 2;
          this.rightY = (y + other.y) / 2;
          return out;
        }
        break;
      }
      case "two_tap":
        if (now - this.twoAt <= TWO_TAP_MS * 2) out.push(...this.twoFingerTap(now));
        break;
      default:
        break;
    }
    this.phase = this.fingers.size === 0 ? "idle" : "spent";
    if (this.phase === "idle") this.ignored.clear();
    return out;
  }

  // The browser took a finger away (pointercancel): nothing it was doing
  // counts, and a button it held is let go without a click.
  cancel(id: number, now: number): GestureAction[] {
    const out = this.tick(now);
    if (this.ignored.delete(id)) return out;
    if (!this.fingers.delete(id)) return out;
    out.push(...this.releaseHeld());
    this.phase = this.fingers.size === 0 ? "idle" : "spent";
    if (this.phase === "idle") this.ignored.clear();
    return out;
  }

  private only(): Finger | null {
    if (this.fingers.size !== 1) return null;
    for (const finger of this.fingers.values()) return finger;
    return null;
  }

  private releaseHeld(): GestureAction[] {
    if (this.held === null) return [];
    const button = this.held;
    this.held = null;
    return [{ kind: "button", button, down: false }];
  }

  private rightClick(x: number, y: number): GestureAction[] {
    const out: GestureAction[] = [];
    if (this.mode === "view") return out;
    if (this.mode === "direct") out.push({ kind: "point", x, y });
    out.push({ kind: "button", button: "right", down: true }, { kind: "button", button: "right", down: false });
    return out;
  }

  private twoFingerTap(now: number): GestureAction[] {
    const double = now - this.lastTwoTap <= DOUBLE_TAP_MS;
    this.lastTwoTap = double ? -Infinity : now;
    if (this.mode === "view") return double ? [{ kind: "reset_zoom" }] : [];
    if (!this.zoomed) return this.rightClick(this.rightX, this.rightY);
    // Zoomed: the first tap's right click waits, and a second tap takes
    // its place with a zoom reset.
    if (double && this.rightAt !== null) {
      this.rightAt = null;
      return [{ kind: "reset_zoom" }];
    }
    this.rightAt = now + DOUBLE_TAP_MS;
    return [];
  }

  private moveTwo(now: number): GestureAction[] {
    const [a, b] = [...this.fingers.values()];
    if (a === undefined || b === undefined) return [];
    const gap = Math.hypot(b.x - a.x, b.y - a.y);
    const midX = (a.x + b.x) / 2;
    const midY = (a.y + b.y) / 2;
    if (this.twoTap) {
      const still = (f: Finger): boolean => Math.hypot(f.x - f.startX, f.y - f.startY) <= TAP_SLOP_PX;
      if (!still(a) || !still(b) || now - this.twoAt > TWO_TAP_MS) this.twoTap = false;
    }

    if (this.phase === "two") {
      const startGap = Math.hypot(b.startX - a.startX, b.startY - a.startY);
      const startMidX = (a.startX + b.startX) / 2;
      const startMidY = (a.startY + b.startY) / 2;
      const pinching = Math.abs(gap - startGap) > PINCH_SLOP_PX;
      const travelX = midX - startMidX;
      const travelY = midY - startMidY;
      const scrolling = Math.hypot(travelX, travelY) > SCROLL_SLOP_PX;
      if (!pinching && !scrolling) return [];
      this.twoTap = false;
      // Watching only, there's nothing to scroll: two fingers zoom and pan.
      if (pinching || this.mode === "view") {
        this.phase = "pinch";
        this.gap = startGap;
        this.midX = startMidX;
        this.midY = startMidY;
      } else {
        this.phase = "scroll";
        // Mostly one way locks to that axis, so a slightly slanted swipe
        // doesn't scroll sideways too.
        this.scrollX = Math.abs(travelX) * 2 > Math.abs(travelY);
        this.scrollY = Math.abs(travelY) * 2 > Math.abs(travelX);
        this.wheelX = 0;
        this.wheelY = 0;
        this.midX = startMidX;
        this.midY = startMidY;
      }
    }

    if (this.phase === "pinch") {
      const factor = this.gap > 0 && gap > 0 ? gap / this.gap : 1;
      const action: GestureAction = { kind: "zoom", factor, fromX: this.midX, fromY: this.midY, toX: midX, toY: midY };
      this.gap = gap;
      this.midX = midX;
      this.midY = midY;
      return [action];
    }

    if (this.phase === "scroll") {
      // Content follows the fingers, as on a phone: fingers moving down
      // show what's above, which is the wheel turned up.
      if (this.scrollX) this.wheelX -= ((midX - this.midX) * WHEEL_DELTA) / WHEEL_NOTCH_PX;
      if (this.scrollY) this.wheelY += ((midY - this.midY) * WHEEL_DELTA) / WHEEL_NOTCH_PX;
      this.midX = midX;
      this.midY = midY;
      const dx = Math.trunc(this.wheelX / WHEEL_STEP) * WHEEL_STEP;
      const dy = Math.trunc(this.wheelY / WHEEL_STEP) * WHEEL_STEP;
      if (dx === 0 && dy === 0) return [];
      this.wheelX -= dx;
      this.wheelY -= dy;
      return [{ kind: "wheel", dx, dy }];
    }
    return [];
  }
}

// --- The zoomed picture ---------------------------------------------------

// How the picture is zoomed: scaled by `scale` about the top-left corner of
// the screen's box, then moved by `x`, `y` (CSS pixels). The identity is no
// zoom at all.
export interface View {
  scale: number;
  x: number;
  y: number;
}

export const NO_ZOOM: View = { scale: 1, x: 0, y: 0 };
export const MAX_ZOOM = 6;

export interface Box {
  left: number;
  top: number;
  width: number;
  height: number;
}

// Scales `view` by `factor` (kept within 1..=MAX_ZOOM) so that the point
// under `from` lands under `to`, both relative to the screen's box.
export function zoomView(view: View, factor: number, fromX: number, fromY: number, toX: number, toY: number): View {
  const scale = Math.min(MAX_ZOOM, Math.max(1, view.scale * factor));
  const contentX = (fromX - view.x) / view.scale;
  const contentY = (fromY - view.y) / view.scale;
  return { scale, x: toX - scale * contentX, y: toY - scale * contentY };
}

// Keeps the picture (`picture`, its box in the screen unzoomed) covering
// the screen (`width` × `height`) where it's big enough to, and centred
// where it isn't: no panning off into the black around it.
export function clampView(view: View, width: number, height: number, picture: Box): View {
  const axis = (offset: number, size: number, start: number, extent: number): number => {
    const scaled = view.scale * extent;
    if (scaled <= size) return (size - scaled) / 2 - view.scale * start;
    return Math.min(0 - view.scale * start, Math.max(size - view.scale * (start + extent), offset));
  };
  return {
    scale: view.scale,
    x: axis(view.x, width, picture.left, picture.width),
    y: axis(view.y, height, picture.top, picture.height),
  };
}

// Moves the view so the point (`x`, `y`, relative to the screen's box,
// zoomed) is at least `margin` in from every edge: the picture following
// the pointer around.
export function followPoint(view: View, x: number, y: number, width: number, height: number, margin: number): View {
  const shift = (at: number, size: number): number => {
    const room = Math.min(margin, size / 2);
    if (at < room) return room - at;
    if (at > size - room) return size - room - at;
    return 0;
  };
  return { scale: view.scale, x: view.x + shift(x, width), y: view.y + shift(y, height) };
}
