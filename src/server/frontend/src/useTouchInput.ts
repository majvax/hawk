import { type RefObject, useCallback, useEffect, useRef, useState } from "react";

import type { InputEvent, MouseButton } from "./protocol.js";
import {
  type GestureAction,
  type TouchMode,
  type View,
  NO_ZOOM,
  TouchGestures,
  clampView,
  followPoint,
  zoomView,
} from "./touchGestures.js";
import { type Modifier, NAMED_KEYS, PADDING, chordFor, isShortcut, textChange, typingFor } from "./touchKeyboard.js";

// How close to the edge of the screen the pointer gets, zoomed in trackpad
// mode, before the picture moves along with it.
const FOLLOW_MARGIN_PX = 48;
const KEY_CODE = /^[A-Za-z0-9]{1,31}$/;

export interface TouchInput {
  // A finger has been on the screen (so this is a touch device, whatever
  // the browser said about its pointer).
  touched: boolean;
  // The picture is zoomed in on this screen.
  zoomed: boolean;
  resetZoom: () => void;
}

const clamp01 = (value: number): number => Math.min(1, Math.max(0, value));

// Touches on the live view: gestures (touchGestures.ts) turned into the
// machine's pointer, buttons and wheel, and pinches into a zoom of the
// picture on this screen.
//
// `screen` is the box the picture is shown in, which takes the touches;
// `view` holds the picture and is what's zoomed (scaled and moved with a
// CSS transform). Pointer positions are read off the canvas's on-screen box,
// which the transform is part of, so they stay right at any zoom. `cursor`
// is drawn where the machine's pointer is in trackpad mode: the stream
// doesn't carry the machine's own cursor, and there's no finger on it.
//
// `mode` "view" sends nothing: watching only, the fingers zoom and pan.
// `onControl` runs as a finger lands with control (to take the focus, as a
// click does).
//
// Mouse and pen are left to useRemoteInput, as they always were.
export function useTouchInput(
  screenRef: RefObject<HTMLDivElement>,
  viewRef: RefObject<HTMLDivElement>,
  canvasRef: RefObject<HTMLCanvasElement>,
  cursorRef: RefObject<HTMLDivElement>,
  watching: boolean,
  mode: TouchMode,
  sendInput: (event: InputEvent) => void,
  onControl: (() => void) | null = null,
): TouchInput {
  const [touched, setTouched] = useState(false);
  const [zoomed, setZoomed] = useState(false);
  const sendInputRef = useRef(sendInput);
  sendInputRef.current = sendInput;
  const onControlRef = useRef(onControl);
  onControlRef.current = onControl;
  // Kept across a change of mode: switching to trackpad shouldn't lose the
  // zoom, or the pointer.
  const viewState = useRef<View>(NO_ZOOM);
  const pointer = useRef({ x: 0.5, y: 0.5 });
  const applyRef = useRef<(view: View) => void>(() => {});

  const resetZoom = useCallback((): void => applyRef.current(NO_ZOOM), []);

  useEffect(() => {
    const screen = screenRef.current;
    const viewBox = viewRef.current;
    const canvas = canvasRef.current;
    if (!watching || screen === null || viewBox === null || canvas === null) {
      viewState.current = NO_ZOOM;
      if (viewBox !== null) viewBox.style.transform = "";
      setZoomed(false);
      return;
    }

    const send = (event: InputEvent): void => sendInputRef.current(event);
    const gestures = new TouchGestures(mode);
    const buttonsHeld = new Set<MouseButton>();

    // One move per repaint at most, as with the mouse. In trackpad mode the
    // first press goes where the drawn pointer is, moved there or not.
    let movePending = mode === "trackpad";
    let moveFrame: number | null = null;
    const flushMove = (): void => {
      if (moveFrame !== null) window.cancelAnimationFrame(moveFrame);
      moveFrame = null;
      if (!movePending) return;
      movePending = false;
      send({ kind: "mouse_move", ...pointer.current });
    };

    // Where the machine's pointer is, relative to the screen's box.
    const pointerAt = (): { x: number; y: number; width: number; height: number } => {
      const picture = canvas.getBoundingClientRect();
      const box = screen.getBoundingClientRect();
      return {
        x: picture.left - box.left + pointer.current.x * picture.width,
        y: picture.top - box.top + pointer.current.y * picture.height,
        width: box.width,
        height: box.height,
      };
    };
    const placeCursor = (): void => {
      const cursor = cursorRef.current;
      if (cursor === null) return;
      const at = pointerAt();
      cursor.style.transform = `translate(${at.x}px, ${at.y}px)`;
    };

    const apply = (next: View): void => {
      // The canvas's box within `view`, before the zoom.
      const picture = {
        left: canvas.offsetLeft,
        top: canvas.offsetTop,
        width: canvas.offsetWidth,
        height: canvas.offsetHeight,
      };
      let view = clampView(next, screen.clientWidth, screen.clientHeight, picture);
      if (view.scale <= 1.001) view = NO_ZOOM;
      viewState.current = view;
      const zoomedIn = view !== NO_ZOOM;
      viewBox.style.transform = zoomedIn ? `translate(${view.x}px, ${view.y}px) scale(${view.scale})` : "";
      gestures.zoomed = zoomedIn;
      setZoomed(zoomedIn);
      placeCursor();
    };
    applyRef.current = apply;

    let timer: number | null = null;
    const schedule = (): void => {
      if (timer !== null) window.clearTimeout(timer);
      timer = null;
      const at = gestures.deadline();
      if (at === null) return;
      timer = window.setTimeout(
        () => {
          timer = null;
          run(gestures.tick(performance.now()));
        },
        Math.max(0, at - performance.now()),
      );
    };

    const run = (actions: GestureAction[]): void => {
      for (const action of actions) {
        switch (action.kind) {
          case "move": {
            const picture = canvas.getBoundingClientRect();
            pointer.current = {
              x: clamp01(pointer.current.x + action.dx / Math.max(1, picture.width)),
              y: clamp01(pointer.current.y + action.dy / Math.max(1, picture.height)),
            };
            movePending = true;
            moveFrame ??= window.requestAnimationFrame(flushMove);
            if (viewState.current !== NO_ZOOM) {
              const at = pointerAt();
              apply(followPoint(viewState.current, at.x, at.y, at.width, at.height, FOLLOW_MARGIN_PX));
            } else {
              placeCursor();
            }
            break;
          }
          case "point": {
            const picture = canvas.getBoundingClientRect();
            pointer.current = {
              x: clamp01((action.x - picture.left) / Math.max(1, picture.width)),
              y: clamp01((action.y - picture.top) / Math.max(1, picture.height)),
            };
            // Pressed or not, a direct touch lands where the finger is.
            movePending = true;
            flushMove();
            placeCursor();
            break;
          }
          case "button":
            flushMove();
            if (action.down) buttonsHeld.add(action.button);
            else buttonsHeld.delete(action.button);
            send({ kind: "mouse_button", button: action.button, down: action.down });
            break;
          case "wheel":
            flushMove();
            send({ kind: "wheel", dx: action.dx, dy: action.dy });
            break;
          case "zoom": {
            const box = screen.getBoundingClientRect();
            apply(
              zoomView(
                viewState.current,
                action.factor,
                action.fromX - box.left,
                action.fromY - box.top,
                action.toX - box.left,
                action.toY - box.top,
              ),
            );
            break;
          }
          case "pan":
            apply({ ...viewState.current, x: viewState.current.x + action.dx, y: viewState.current.y + action.dy });
            break;
          case "reset_zoom":
            apply(NO_ZOOM);
            break;
        }
      }
      schedule();
    };

    // Whether the last press on the screen was a finger's: a long press's
    // menu is the browser's to drop, a right click's is left as it was.
    let fingers = false;
    const onPointerDown = (event: PointerEvent): void => {
      fingers = event.pointerType === "touch";
      if (!fingers) return;
      // No page scroll or zoom, no text selection, no focus moving away
      // from the on-screen keyboard's box.
      event.preventDefault();
      setTouched(true);
      if (mode !== "view") onControlRef.current?.();
      run(gestures.down(event.pointerId, event.clientX, event.clientY, performance.now()));
    };
    const onPointerMove = (event: PointerEvent): void => {
      if (event.pointerType !== "touch") return;
      run(gestures.move(event.pointerId, event.clientX, event.clientY, performance.now()));
    };
    const onPointerUp = (event: PointerEvent): void => {
      if (event.pointerType !== "touch") return;
      event.preventDefault();
      run(gestures.up(event.pointerId, event.clientX, event.clientY, performance.now()));
    };
    const onPointerCancel = (event: PointerEvent): void => {
      if (event.pointerType !== "touch") return;
      run(gestures.cancel(event.pointerId, performance.now()));
    };
    // A long press would otherwise bring up the browser's own menu.
    const onContextMenu = (event: Event): void => {
      if (fingers) event.preventDefault();
    };
    // Safari's own pinch, where touch-action alone doesn't stop it.
    const onGesture = (event: Event): void => event.preventDefault();
    // The window going away mid-gesture takes its pointerup with it.
    const onWindowBlur = (): void => run(gestures.reset());

    // The screen changing size (rotation, full screen, a new resolution)
    // keeps the zoom, kept within the new bounds.
    const resized = new ResizeObserver(() => apply(viewState.current));
    resized.observe(screen);
    resized.observe(canvas);

    screen.addEventListener("pointerdown", onPointerDown);
    screen.addEventListener("pointermove", onPointerMove);
    screen.addEventListener("pointerup", onPointerUp);
    screen.addEventListener("pointercancel", onPointerCancel);
    screen.addEventListener("contextmenu", onContextMenu);
    screen.addEventListener("gesturestart", onGesture);
    window.addEventListener("blur", onWindowBlur);
    apply(viewState.current);

    return () => {
      screen.removeEventListener("pointerdown", onPointerDown);
      screen.removeEventListener("pointermove", onPointerMove);
      screen.removeEventListener("pointerup", onPointerUp);
      screen.removeEventListener("pointercancel", onPointerCancel);
      screen.removeEventListener("contextmenu", onContextMenu);
      screen.removeEventListener("gesturestart", onGesture);
      window.removeEventListener("blur", onWindowBlur);
      resized.disconnect();
      applyRef.current = () => {};
      if (timer !== null) window.clearTimeout(timer);
      if (moveFrame !== null) window.cancelAnimationFrame(moveFrame);
      // Nothing stays pressed on the machine once these fingers stop
      // counting (control lost, mode changed, view closed).
      gestures.reset();
      for (const button of buttonsHeld) send({ kind: "mouse_button", button, down: false });
    };
  }, [screenRef, viewRef, canvasRef, cursorRef, watching, mode]);

  return { touched, zoomed, resetZoom };
}

export interface TouchKeyboard {
  // The row of extra keys is showing.
  open: boolean;
  // The on-screen keyboard's box has the focus, so the keyboard is up.
  typing: boolean;
  // Modifiers held for the next key.
  latched: ReadonlySet<Modifier>;
  // Shows the keys and brings up the keyboard; again, puts both away.
  toggle: () => void;
  close: () => void;
  // One of the extra keys, with whatever is latched.
  press: (code: string) => void;
  // Holds a modifier for the next key. Latched already, it's pressed on its
  // own (Win alone opens Start) and let go.
  latch: (modifier: Modifier) => void;
}

// The phone's on-screen keyboard and a row of the keys it doesn't have.
// `input` is a text box kept out of sight: focusing it is the only way to
// bring the keyboard up. What's typed into it is replayed on the machine
// (touchKeyboard.ts): as characters where the machine takes `text` events
// (`asText`), whatever its layout; as US keys on an older one, leaving out
// what no US key types.
export function useTouchKeyboard(
  inputRef: RefObject<HTMLTextAreaElement>,
  enabled: boolean,
  sendInput: (event: InputEvent) => void,
  asText: boolean,
): TouchKeyboard {
  const [open, setOpen] = useState(false);
  const [typing, setTyping] = useState(false);
  const [latched, setLatched] = useState<ReadonlySet<Modifier>>(new Set());
  const latchedRef = useRef(latched);
  latchedRef.current = latched;
  const asTextRef = useRef(asText);
  asTextRef.current = asText;
  const sendInputRef = useRef(sendInput);
  sendInputRef.current = sendInput;

  // What's latched, used up by whatever goes next.
  const takeLatched = useCallback((): Modifier[] => {
    const held = [...latchedRef.current];
    if (held.length > 0) {
      latchedRef.current = new Set();
      setLatched(latchedRef.current);
    }
    return held;
  }, []);

  // A key, pressed and let go, with what's latched and anything else held.
  const stroke = useCallback(
    (code: string, held: readonly string[] = []): void => {
      const send = sendInputRef.current;
      const modifiers = [...new Set([...takeLatched(), ...held])].filter((modifier) => modifier !== code);
      for (const modifier of modifiers) send({ kind: "key", code: modifier, down: true });
      send({ kind: "key", code, down: true });
      send({ kind: "key", code, down: false });
      for (const modifier of modifiers.reverse()) send({ kind: "key", code: modifier, down: false });
    },
    [takeLatched],
  );

  useEffect(() => {
    const input = inputRef.current;
    if (!enabled || input === null) {
      setOpen(false);
      setTyping(false);
      latchedRef.current = new Set();
      setLatched(latchedRef.current);
      return;
    }

    let before = "";
    let composing = false;
    // A shortcut went out of what was just typed: its character never
    // reached the machine as text, so it mustn't stay in the box for a
    // later correction to Backspace over.
    let shortcutTaken = false;
    const resetBox = (): void => {
      input.value = PADDING;
      input.setSelectionRange(PADDING.length, PADDING.length);
      before = PADDING;
    };

    const type = (text: string): void => {
      // Ctrl, Alt or Win latched makes the next character a shortcut,
      // which only works as a key: the machine finds the one that types it
      // in its own layout (a chord); an older one gets its US key. The rest
      // is typed as usual.
      if (isShortcut(latchedRef.current)) {
        shortcutTaken = true;
        const [first = "", ...rest] = [...text];
        const chord = asTextRef.current ? chordFor(first, latchedRef.current) : null;
        if (chord !== null) {
          sendInputRef.current(chord);
        } else {
          // Enter, Tab, or an older machine: the key itself.
          for (const step of typingFor(first, false)) {
            if (step.kind === "key") stroke(step.code, step.shift ? ["ShiftLeft"] : []);
          }
        }
        // Pressed with it, or nothing to press it with: used up either way.
        takeLatched();
        if (rest.length > 0) type(rest.join(""));
        return;
      }
      for (const step of typingFor(text, asTextRef.current)) {
        if (step.kind === "key") {
          stroke(step.code, step.shift ? ["ShiftLeft"] : []);
          continue;
        }
        // Shift alone latched: the character has its case already.
        takeLatched();
        sendInputRef.current({ kind: "text", text: step.text });
      }
    };

    // What changed in the box since last time, replayed on the machine.
    const sync = (): void => {
      const after = input.value;
      const { deleted, inserted } = textChange(before, after);
      before = after;
      for (let i = 0; i < deleted; i += 1) stroke("Backspace");
      if (inserted !== "") type(inserted);
      // After a shortcut, the box starts over even mid-word: setting it
      // ends the IME's composition, which then has nothing to correct.
      if (shortcutTaken) {
        shortcutTaken = false;
        composing = false;
        resetBox();
        return;
      }
      // Back to the padding between words, never in the middle of one an
      // IME is still working on.
      if (!composing && after !== PADDING) resetBox();
    };

    const onKeyDown = (event: KeyboardEvent): void => {
      // A keyboard composing (or not saying which key) is read off the text.
      if (event.isComposing || event.keyCode === 229) return;
      const hardware = event.ctrlKey || event.altKey || event.metaKey;
      const code = NAMED_KEYS[event.key] ?? (hardware && KEY_CODE.test(event.code) ? event.code : undefined);
      if (code === undefined) return;
      event.preventDefault();
      const held: string[] = [];
      if (event.ctrlKey) held.push("ControlLeft");
      if (event.altKey) held.push("AltLeft");
      if (event.metaKey) held.push("MetaLeft");
      if (event.shiftKey) held.push("ShiftLeft");
      stroke(code, held);
    };
    const onCompositionStart = (): void => {
      composing = true;
    };
    const onCompositionEnd = (): void => {
      composing = false;
      sync();
    };
    const onFocus = (): void => {
      resetBox();
      setTyping(true);
    };
    const onBlur = (): void => {
      composing = false;
      setTyping(false);
    };

    input.addEventListener("input", sync);
    input.addEventListener("keydown", onKeyDown);
    input.addEventListener("compositionstart", onCompositionStart);
    input.addEventListener("compositionend", onCompositionEnd);
    input.addEventListener("focus", onFocus);
    input.addEventListener("blur", onBlur);
    resetBox();
    setTyping(document.activeElement === input);

    return () => {
      input.removeEventListener("input", sync);
      input.removeEventListener("keydown", onKeyDown);
      input.removeEventListener("compositionstart", onCompositionStart);
      input.removeEventListener("compositionend", onCompositionEnd);
      input.removeEventListener("focus", onFocus);
      input.removeEventListener("blur", onBlur);
      if (document.activeElement === input) input.blur();
    };
  }, [inputRef, enabled, stroke, takeLatched]);

  const toggle = useCallback((): void => {
    const input = inputRef.current;
    if (input === null) return;
    // Focused straight from the tap: phones only raise the keyboard for a
    // focus the viewer asked for.
    if (!open || document.activeElement !== input) {
      setOpen(true);
      input.focus({ preventScroll: true });
      return;
    }
    setOpen(false);
    input.blur();
  }, [inputRef, open]);

  const close = useCallback((): void => {
    setOpen(false);
    latchedRef.current = new Set();
    setLatched(latchedRef.current);
    inputRef.current?.blur();
  }, [inputRef]);

  const press = useCallback((code: string): void => stroke(code), [stroke]);

  const latch = useCallback(
    (modifier: Modifier): void => {
      if (latchedRef.current.has(modifier)) {
        stroke(modifier);
        return;
      }
      latchedRef.current = new Set([...latchedRef.current, modifier]);
      setLatched(latchedRef.current);
    },
    [stroke],
  );

  return { open, typing, latched, toggle, close, press, latch };
}
