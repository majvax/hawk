import { type RefObject, useCallback, useEffect, useRef, useState } from "react";

import { type InputEvent, type MouseButton, WHEEL_DELTA } from "./protocol.js";

// Each button a machine is sent, by its bit in `PointerEvent.buttons`. The
// rest (back, forward, a pen's eraser) are left alone.
const BUTTON_BITS: ReadonlyArray<readonly [MouseButton, number]> = [
  ["left", 1],
  ["right", 2],
  ["middle", 4],
];

// A `KeyboardEvent.code` names a physical key, so it's always letters and
// digits ("KeyA", "F11", "ShiftLeft"). Anything else is some browser's own
// idea and the relay drops it anyway.
const KEY_CODE = /^[A-Za-z0-9]{1,31}$/;

// Wheel deltas reach us in whatever unit the browser feels like. A notch is
// about 100 pixels in Chrome and Firefox, three lines where lines are used,
// and a page is near enough one notch for scrolling to feel right.
// How long the V of a Ctrl+V waits after the text it pastes. The text and
// the keystroke reach the machine down different pipes, so without the wait
// the paste can beat the text and paste what was there before.
const PASTE_KEY_DELAY_MS = 200;
// How long to wait for the browser's paste event after Ctrl+V before
// sending the keystroke on its own.
const PASTE_EVENT_WAIT_MS = 250;

function wheelUnits(delta: number, mode: number): number {
  const notches = mode === 1 ? delta / 3 : mode === 2 ? delta : delta / 100;
  return Math.round(notches * WHEEL_DELTA);
}

export interface RemoteInput {
  // Whether the viewer's mouse and keyboard are going to the machine, which
  // is while the screen has focus.
  active: boolean;
  // Hand the machine back its own input (the "stop controlling" button).
  release: () => void;
}

// Sends what the viewer does over a focused <canvas> to the machine it is
// showing: pointer positions as a fraction of the screen, buttons, the
// wheel, and physical keys.
//
// Taking control is deliberate — the screen has to be clicked, and loses
// control again when something else is clicked or `enabled` goes false —
// because the page swallows keystrokes while it has them, and a viewer
// scrolling past a live screen shouldn't lose what they type. Everything
// held down is released at that point, so no key stays stuck on the machine
// (the relay also tells it to let go when a viewer stops watching).
//
// What the browser keeps for itself can't be forwarded: Ctrl+W, Ctrl+N,
// Alt+Tab and the like reach the viewer's own machine (unless the viewer
// has a keyboard lock, which the dashboard takes in full screen), and
// Ctrl+Alt+Del is the secure attention sequence, which nothing but Windows
// itself can send.
// With `onSas`, Ctrl+Alt+End stands in for it, as in Remote Desktop: the
// machine has Windows press Ctrl+Alt+Del instead (and End isn't sent).
//
// With `onPaste`, Ctrl+V pastes this computer's clipboard: the browser hands
// the page its text with the paste the viewer just pressed for, `onPaste`
// puts it on the machine's clipboard, and the V follows a moment later.
// `onPaste` returns false when it didn't send anything (no text, too long),
// and the machine then pastes whatever it already had.
//
// With `onPasteImage` too, a clipboard holding a picture and no text sends
// the picture (PNG, as browsers hand them over). That takes longer than a
// moment, so the V waits for it to land, and isn't sent at all when it
// doesn't (too large, refused): the note under the screen says why.
export function useRemoteInput(
  canvasRef: RefObject<HTMLCanvasElement>,
  enabled: boolean,
  sendInput: (event: InputEvent) => void,
  onPaste: ((text: string) => boolean) | null = null,
  onSas: (() => void) | null = null,
  onPasteImage: ((image: File) => Promise<boolean>) | null = null,
): RemoteInput {
  const [active, setActive] = useState(false);
  const sendInputRef = useRef(sendInput);
  sendInputRef.current = sendInput;
  const onPasteRef = useRef(onPaste);
  onPasteRef.current = onPaste;
  const onSasRef = useRef(onSas);
  onSasRef.current = onSas;
  const onPasteImageRef = useRef(onPasteImage);
  onPasteImageRef.current = onPasteImage;
  const pasting = onPaste !== null;

  const release = useCallback((): void => canvasRef.current?.blur(), [canvasRef]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!enabled || canvas === null) {
      setActive(false);
      return;
    }

    const send = (event: InputEvent): void => sendInputRef.current(event);
    const keysHeld = new Set<string>();
    const buttonsHeld = new Set<MouseButton>();

    // One move per repaint at most: a mouse reports far more often than the
    // screen is redrawn, and only the newest position matters.
    let pendingMove: { x: number; y: number } | null = null;
    let moveFrame: number | null = null;
    const flushMove = (): void => {
      if (moveFrame !== null) window.cancelAnimationFrame(moveFrame);
      moveFrame = null;
      if (pendingMove === null) return;
      send({ kind: "mouse_move", ...pendingMove });
      pendingMove = null;
    };

    // Brings the machine's buttons in line with `buttons` (a
    // `PointerEvent.buttons` mask). Buttons are tracked by mask rather than
    // by pointerdown / pointerup because a second button pressed while one
    // is already down only shows up as a pointermove.
    const syncButtons = (buttons: number): void => {
      for (const [button, bit] of BUTTON_BITS) {
        const down = (buttons & bit) !== 0;
        if (down === buttonsHeld.has(button)) continue;
        if (down) buttonsHeld.add(button);
        else buttonsHeld.delete(button);
        send({ kind: "mouse_button", button, down });
      }
    };
    const buttonsDiffer = (buttons: number): boolean =>
      BUTTON_BITS.some(([button, bit]) => ((buttons & bit) !== 0) !== buttonsHeld.has(button));

    const releaseHeld = (): void => {
      for (const code of keysHeld) send({ kind: "key", code, down: false });
      keysHeld.clear();
      syncButtons(0);
    };

    // Where the pointer is within the screen, 0..=1. The canvas is drawn at
    // the frame's own size and scaled by CSS, so its box is the whole screen.
    const position = (event: PointerEvent): { x: number; y: number } => {
      const rect = canvas.getBoundingClientRect();
      const clamp = (value: number): number => Math.min(1, Math.max(0, value));
      return {
        x: clamp((event.clientX - rect.left) / Math.max(1, rect.width)),
        y: clamp((event.clientY - rect.top) / Math.max(1, rect.height)),
      };
    };

    const onPointerMove = (event: PointerEvent): void => {
      pendingMove = position(event);
      if (buttonsDiffer(event.buttons)) {
        // A chorded press or release: it has to land where the pointer is.
        flushMove();
        syncButtons(event.buttons);
        return;
      }
      moveFrame ??= window.requestAnimationFrame(flushMove);
    };

    const onPointerDown = (event: PointerEvent): void => {
      // preventDefault keeps the click from selecting or dragging the
      // canvas, but it also stops the browser focusing it, so focus here.
      event.preventDefault();
      canvas.focus();
      // The button has to land where the pointer already is, and a captured
      // pointer keeps reporting once it leaves the canvas, so a drag can
      // run off the edge of the screen and come back.
      pendingMove = position(event);
      flushMove();
      canvas.setPointerCapture(event.pointerId);
      syncButtons(event.buttons);
    };

    const onPointerUp = (event: PointerEvent): void => {
      event.preventDefault();
      pendingMove = position(event);
      flushMove();
      syncButtons(event.buttons);
      if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
    };

    // The browser took the pointer away (pointercancel, e.g. a touch it
    // decided was a scroll) or capture was lost without a pointerup: no
    // release is coming for whatever is down, so let go of it now.
    const onPointerLost = (): void => syncButtons(0);

    const onWheel = (event: WheelEvent): void => {
      event.preventDefault(); // don't scroll the dashboard behind the screen
      // Windows counts a wheel up, the browser counts it down.
      const dx = wheelUnits(event.deltaX, event.deltaMode);
      const dy = -wheelUnits(event.deltaY, event.deltaMode);
      if (dx !== 0 || dy !== 0) send({ kind: "wheel", dx, dy });
    };

    // A Ctrl+V waiting for its paste event, and the V taps still to come.
    let pasteWait: number | null = null;
    // Set once torn down: a picture that lands after that taps nothing.
    let disposed = false;
    const pasteTaps = new Set<number>();
    const tapV = (delay: number): void => {
      const timer = window.setTimeout(() => {
        pasteTaps.delete(timer);
        // A quick Ctrl+V lets go of Ctrl before the wait is over: hold it
        // for the V here, or the machine just gets a "v".
        const ctrlHeld = keysHeld.has("ControlLeft") || keysHeld.has("ControlRight");
        if (!ctrlHeld) send({ kind: "key", code: "ControlLeft", down: true });
        send({ kind: "key", code: "KeyV", down: true });
        send({ kind: "key", code: "KeyV", down: false });
        if (!ctrlHeld) send({ kind: "key", code: "ControlLeft", down: false });
      }, delay);
      pasteTaps.add(timer);
    };

    const onPaste = (event: ClipboardEvent): void => {
      if (pasteWait === null || document.activeElement !== canvas) return;
      event.preventDefault();
      window.clearTimeout(pasteWait);
      pasteWait = null;
      const text = event.clipboardData?.getData("text/plain") ?? "";
      const image = [...(event.clipboardData?.files ?? [])].find((file) => file.type === "image/png");
      const pasteImage = onPasteImageRef.current;
      if (text === "" && image !== undefined && pasteImage !== null) {
        void pasteImage(image).then((sent) => {
          if (sent && !disposed) tapV(0);
        });
        return;
      }
      const sent = text !== "" && (onPasteRef.current?.(text) ?? false);
      tapV(sent ? PASTE_KEY_DELAY_MS : 0);
    };

    const onKeyDown = (event: KeyboardEvent): void => {
      if (onSasRef.current !== null && isSasShortcut(event)) {
        event.preventDefault();
        if (!event.repeat) onSasRef.current();
        return;
      }
      const isPaste = event.code === "KeyV" && event.ctrlKey && !event.altKey && !event.shiftKey && !event.metaKey;
      if (pasting && isPaste) {
        // Left to the browser, which answers with a paste event (above)
        // carrying this computer's clipboard; the V is sent from there.
        if (event.repeat || pasteWait !== null) {
          event.preventDefault();
          return;
        }
        pasteWait = window.setTimeout(() => {
          // No paste event (the browser kept it): paste the machine's own.
          pasteWait = null;
          tapV(0);
        }, PASTE_EVENT_WAIT_MS);
        return;
      }
      event.preventDefault(); // Tab, F-keys and space are the machine's now
      if (!KEY_CODE.test(event.code)) return;
      // Repeats are passed on as they come: that's what makes a held key
      // repeat on the machine, which has no idea it is being held.
      keysHeld.add(event.code);
      send({ kind: "key", code: event.code, down: true });
    };

    const onKeyUp = (event: KeyboardEvent): void => {
      event.preventDefault();
      if (!KEY_CODE.test(event.code)) return;
      // A pasting V was tapped on its own; this one was never sent down.
      if (pasting && event.code === "KeyV" && !keysHeld.has("KeyV")) return;
      // Nor was the End of a Ctrl+Alt+End.
      if (event.code === "End" && !keysHeld.has("End")) return;
      keysHeld.delete(event.code);
      send({ kind: "key", code: event.code, down: false });
    };

    // Losing focus (or the whole window) means the viewer has moved on:
    // whatever they were holding has to be let go, or it stays down on the
    // machine with nobody pressing it.
    const onFocus = (): void => setActive(true);
    const onBlur = (): void => {
      setActive(false);
      releaseHeld();
    };
    // Switching away from the browser altogether keeps the focus on the
    // canvas, but the keyup for whatever is held never arrives, so let go of
    // it here too rather than leave it down on the machine.
    const onWindowBlur = (): void => releaseHeld();

    canvas.addEventListener("pointermove", onPointerMove);
    canvas.addEventListener("pointerdown", onPointerDown);
    canvas.addEventListener("pointerup", onPointerUp);
    canvas.addEventListener("pointercancel", onPointerLost);
    canvas.addEventListener("lostpointercapture", onPointerLost);
    canvas.addEventListener("contextmenu", preventDefault);
    canvas.addEventListener("wheel", onWheel, { passive: false });
    canvas.addEventListener("keydown", onKeyDown);
    canvas.addEventListener("keyup", onKeyUp);
    canvas.addEventListener("focus", onFocus);
    canvas.addEventListener("blur", onBlur);
    window.addEventListener("blur", onWindowBlur);
    if (pasting) document.addEventListener("paste", onPaste);
    setActive(document.activeElement === canvas);

    return () => {
      canvas.removeEventListener("pointermove", onPointerMove);
      canvas.removeEventListener("pointerdown", onPointerDown);
      canvas.removeEventListener("pointerup", onPointerUp);
      canvas.removeEventListener("pointercancel", onPointerLost);
      canvas.removeEventListener("lostpointercapture", onPointerLost);
      canvas.removeEventListener("contextmenu", preventDefault);
      canvas.removeEventListener("wheel", onWheel);
      canvas.removeEventListener("keydown", onKeyDown);
      canvas.removeEventListener("keyup", onKeyUp);
      canvas.removeEventListener("focus", onFocus);
      canvas.removeEventListener("blur", onBlur);
      window.removeEventListener("blur", onWindowBlur);
      document.removeEventListener("paste", onPaste);
      if (pasteWait !== null) window.clearTimeout(pasteWait);
      for (const timer of pasteTaps) window.clearTimeout(timer);
      disposed = true;
      if (moveFrame !== null) window.cancelAnimationFrame(moveFrame);
      releaseHeld();
      setActive(false);
    };
  }, [canvasRef, enabled, pasting]);

  return { active, release };
}

// Ctrl+Alt+End, the stand-in for Ctrl+Alt+Del.
export function isSasShortcut(
  event: Pick<KeyboardEvent, "code" | "ctrlKey" | "altKey" | "shiftKey" | "metaKey">,
): boolean {
  return event.code === "End" && event.ctrlKey && event.altKey && !event.shiftKey && !event.metaKey;
}

function preventDefault(event: Event): void {
  event.preventDefault();
}
