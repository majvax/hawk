// Clipboard pictures, the dashboard's side (src/service/clipboard_images.hpp
// has the machine's, and the message table). A picture is PNG, the one
// image format browsers read from and write to their clipboard, of up to
// 8 MB: far more than clipboard text, so it travels in 64 KB chunks over an
// image channel of its own, a few unacknowledged at a time either way. The
// relay queues the machine's chunks behind the picture and the events, and
// ours wait behind no more than that window, so a large copy never holds up
// input or video.

import { MAX_CLIPBOARD_IMAGE_BYTES, MAX_CLIPBOARD_IMAGE_PIXELS, MAX_CLIPBOARD_IMAGE_SIDE } from "./protocol.js";

export const IMAGE_OP = {
  hello: 1,
  ack: 2,
  cancel: 3,
  chunk: 4,
  image: 17,
  skipped: 18,
  progress: 19,
  done: 20,
  error: 21,
} as const;

export const IMAGE_CHUNK_SIZE = 64 * 1024;
const WINDOW_CHUNKS = 4;
// A paste the machine hasn't confirmed by then (a chunk lost on the way,
// a machine gone quiet) is given up on.
const PASTE_TIMEOUT_MS = 60_000;
// A picture from the machine that stopped coming (a chunk the relay dropped
// for a viewer not keeping up, a machine that gave up on it) stops counting
// as on its way: the machine itself gives up after 20 s without an ack.
const RECEIVE_STALL_MS = 30_000;

export interface ImageSize {
  width: number;
  height: number;
}

const PNG_START = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52];

// The width and height a PNG's header says; null for anything that doesn't
// start like one.
export function pngSize(png: Uint8Array): ImageSize | null {
  if (png.length < 24 || PNG_START.some((byte, i) => png[i] !== byte)) return null;
  const view = new DataView(png.buffer, png.byteOffset, png.byteLength);
  return { width: view.getUint32(16), height: view.getUint32(20) };
}

// Why a picture can't go to the machine, or null when it can. Never cut to
// fit: a picture past the limits is skipped.
export function imageProblem(png: Uint8Array): string | null {
  const size = pngSize(png);
  if (size === null) return "that isn't a PNG picture";
  if (png.length > MAX_CLIPBOARD_IMAGE_BYTES) {
    return `the picture is ${formatBytes(png.length)}; the most the machine takes is ${formatBytes(MAX_CLIPBOARD_IMAGE_BYTES)}`;
  }
  if (
    size.width === 0 ||
    size.height === 0 ||
    size.width > MAX_CLIPBOARD_IMAGE_SIDE ||
    size.height > MAX_CLIPBOARD_IMAGE_SIDE ||
    size.width * size.height > MAX_CLIPBOARD_IMAGE_PIXELS
  ) {
    return `a ${size.width}×${size.height} picture is larger than the machine takes (8K at most)`;
  }
  return null;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// Whether this browser lets the page put a picture on its clipboard
// (Chromium; Firefox from 127). Elsewhere one from the machine is shown to
// save or copy by hand.
export function canWriteImages(): boolean {
  if (typeof ClipboardItem === "undefined" || typeof navigator.clipboard?.write !== "function") return false;
  const supports = (ClipboardItem as { supports?: (type: string) => boolean }).supports;
  return supports === undefined || supports("image/png");
}

// Whether it hands the page pictures from its clipboard at all. Even then
// it may refuse, or offer only text; Ctrl+V on the screen still works.
export function canReadImages(): boolean {
  return typeof navigator.clipboard?.read === "function";
}

// Sends one sealed image-channel message: a request (hello, ack, cancel)
// or a chunk to paste. False when there's no view to send it on.
export interface ImageSender {
  request: (op: number, header: object) => boolean;
  put: (op: number, header: object, data: Uint8Array) => boolean;
}

// A picture from the machine: the answer to a read, or a copy made there
// (sync mode).
export interface ReceivedImage {
  png: Uint8Array<ArrayBuffer>;
  width: number;
  height: number;
  pushed: boolean;
}

export interface ImageEvents {
  received: (image: ReceivedImage) => void;
  // The machine's clipboard holds a picture too large to send.
  skipped: (pushed: boolean) => void;
}

export type PasteResult = { ok: true } | { ok: false; message: string };

interface Incoming {
  id: string;
  size: number;
  pushed: boolean;
  parts: Uint8Array<ArrayBuffer>[];
  received: number;
  lastChunk: number;
}

interface Pasting {
  id: string;
  png: Uint8Array;
  next: number; // the next offset to send
  acked: number; // what the machine has
  resolve: (result: PasteResult) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface Header {
  id?: unknown;
  offset?: unknown;
  size?: unknown;
  received?: unknown;
  pushed?: unknown;
  message?: unknown;
}

export class ClipboardImageManager {
  private sender: ImageSender | null = null;
  private incoming: Incoming | null = null;
  private pasting: Pasting | null = null;

  constructor(
    private readonly events: ImageEvents,
    private readonly timeoutMs = PASTE_TIMEOUT_MS,
  ) {}

  // Whether a picture from the machine is on its way.
  get receiving(): boolean {
    if (this.incoming !== null && Date.now() - this.incoming.lastChunk > RECEIVE_STALL_MS) this.incoming = null;
    return this.incoming !== null;
  }

  // A secured view whose machine sends pictures to this viewer: says
  // hello, so it does. null once there's none; a paste still going fails.
  attach(sender: ImageSender | null): void {
    this.sender = sender;
    this.incoming = null;
    if (sender === null) {
      this.finish({ ok: false, message: "the view closed before the picture got there" });
      return;
    }
    sender.request(IMAGE_OP.hello, {});
  }

  // Puts a PNG on the machine's clipboard: settles once it's there, or
  // with why not. A paste still going is given up for this one.
  paste(png: Uint8Array): Promise<PasteResult> {
    const problem = imageProblem(png);
    if (problem !== null) return Promise.resolve({ ok: false, message: problem });
    if (this.sender === null) return Promise.resolve({ ok: false, message: "there's no view to send it on" });
    this.finish({ ok: false, message: "another picture was pasted after it" });
    return new Promise((resolve) => {
      this.pasting = {
        id: crypto.randomUUID(),
        png,
        next: 0,
        acked: 0,
        resolve,
        timer: setTimeout(() => this.finish({ ok: false, message: "the machine didn't take it in time" }), this.timeoutMs),
      };
      this.pump();
    });
  }

  // One opened message from the machine.
  handle(op: number, rawHeader: unknown, data: Uint8Array<ArrayBuffer>): void {
    const header = (typeof rawHeader === "object" && rawHeader !== null ? rawHeader : {}) as Header;
    const id = typeof header.id === "string" ? header.id : "";
    switch (op) {
      case IMAGE_OP.image:
        this.receive(id, header, data);
        break;
      case IMAGE_OP.skipped:
        this.events.skipped(header.pushed === true);
        break;
      case IMAGE_OP.progress:
        if (this.pasting?.id === id && typeof header.received === "number") {
          this.pasting.acked = Math.max(this.pasting.acked, Math.min(header.received, this.pasting.next));
          this.pump();
        }
        break;
      case IMAGE_OP.done:
        if (this.pasting?.id === id) this.finish({ ok: true });
        break;
      case IMAGE_OP.error:
        if (this.pasting?.id === id) {
          this.finish({ ok: false, message: typeof header.message === "string" ? header.message : "the machine refused it" });
        }
        break;
    }
  }

  // The view moved to another machine, or closed.
  close(): void {
    this.attach(null);
  }

  // --- internals -----------------------------------------------------------------

  private receive(id: string, header: Header, data: Uint8Array<ArrayBuffer>): void {
    const { offset, size } = header;
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size)) return;
    if (typeof offset !== "number" || typeof size !== "number" || size <= 0 || size > MAX_CLIPBOARD_IMAGE_BYTES) {
      return;
    }
    if (offset === 0) {
      // A newer picture replaces one still coming.
      this.incoming = { id, size, pushed: header.pushed === true, parts: [], received: 0, lastChunk: Date.now() };
    }
    const incoming = this.incoming;
    // Anything of another picture is a leftover of one replaced since.
    if (incoming?.id !== id || incoming.size !== size) return;
    // Chunks of one picture come in order, so one that isn't the next means
    // some went missing on the way: it can't be put together any more.
    if (offset !== incoming.received) {
      this.incoming = null;
      this.sender?.request(IMAGE_OP.cancel, { id });
      return;
    }
    incoming.lastChunk = Date.now();
    if (incoming.received + data.length > size) {
      this.incoming = null;
      this.sender?.request(IMAGE_OP.cancel, { id });
      return;
    }
    incoming.parts.push(data);
    incoming.received += data.length;
    this.sender?.request(IMAGE_OP.ack, { id, received: incoming.received });
    if (incoming.received < size) return;

    this.incoming = null;
    const png = new Uint8Array(size);
    let at = 0;
    for (const part of incoming.parts) {
      png.set(part, at);
      at += part.length;
    }
    const dimensions = pngSize(png);
    if (dimensions === null) return;
    this.events.received({ png, ...dimensions, pushed: incoming.pushed });
  }

  // Sends chunks while the window has room.
  private pump(): void {
    const pasting = this.pasting;
    if (pasting === null) return;
    const size = pasting.png.length;
    while (pasting.next < size && pasting.next - pasting.acked < WINDOW_CHUNKS * IMAGE_CHUNK_SIZE) {
      const offset = pasting.next;
      const data = pasting.png.subarray(offset, offset + IMAGE_CHUNK_SIZE);
      if (this.sender?.put(IMAGE_OP.chunk, { id: pasting.id, offset, size }, data) !== true) {
        this.finish({ ok: false, message: "there's no view to send it on" });
        return;
      }
      pasting.next = offset + data.length;
    }
  }

  private finish(result: PasteResult): void {
    const pasting = this.pasting;
    if (pasting === null) return;
    this.pasting = null;
    clearTimeout(pasting.timer);
    // Given up on here: the machine needn't hold what it has of it.
    if (!result.ok) this.sender?.request(IMAGE_OP.cancel, { id: pasting.id });
    pasting.resolve(result);
  }
}
