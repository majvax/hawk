import { describe, expect, test } from "bun:test";
import {
  ClipboardImageManager,
  IMAGE_CHUNK_SIZE,
  IMAGE_OP,
  type ImageSender,
  type ReceivedImage,
  imageProblem,
  pngSize,
} from "./clipboardImages.js";
import { MAX_CLIPBOARD_IMAGE_BYTES } from "./protocol.js";
import { hkdf } from "./crypto.js";

// Enough of a PNG for its header to be read: the signature, then IHDR with
// the width and height, then `length` bytes in all.
function fakePng(width: number, height: number, length = 64): Uint8Array<ArrayBuffer> {
  const png = new Uint8Array(Math.max(length, 24));
  png.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]);
  const view = new DataView(png.buffer);
  view.setUint32(16, width);
  view.setUint32(20, height);
  for (let i = 24; i < png.length; i++) png[i] = i % 251;
  return png;
}

interface Sent {
  op: number;
  header: Record<string, unknown>;
  data?: Uint8Array;
}

function recorder(): { sender: ImageSender; requests: Sent[]; puts: Sent[] } {
  const requests: Sent[] = [];
  const puts: Sent[] = [];
  return {
    requests,
    puts,
    sender: {
      request: (op, header) => {
        requests.push({ op, header: header as Record<string, unknown> });
        return true;
      },
      put: (op, header, data) => {
        puts.push({ op, header: header as Record<string, unknown>, data });
        return true;
      },
    },
  };
}

function manager(timeoutMs?: number): {
  images: ClipboardImageManager;
  received: ReceivedImage[];
  skipped: boolean[];
} {
  const received: ReceivedImage[] = [];
  const skipped: boolean[] = [];
  const images = new ClipboardImageManager(
    { received: (image) => received.push(image), skipped: (pushed) => skipped.push(pushed) },
    timeoutMs,
  );
  return { images, received, skipped };
}

describe("pngSize and imageProblem", () => {
  test("read the header, and refuse anything that isn't a PNG", () => {
    expect(pngSize(fakePng(640, 480))).toEqual({ width: 640, height: 480 });
    expect(pngSize(new Uint8Array(100))).toBeNull();
    expect(imageProblem(fakePng(640, 480))).toBeNull();
    expect(imageProblem(new TextEncoder().encode("GIF89a and then some more bytes"))).toContain("isn't a PNG");
  });

  test("skip pictures past the limits rather than cut them", () => {
    expect(imageProblem(fakePng(100, 100, MAX_CLIPBOARD_IMAGE_BYTES + 1))).toContain("8.0 MB");
    expect(imageProblem(fakePng(100, 100, MAX_CLIPBOARD_IMAGE_BYTES))).toBeNull();
    expect(imageProblem(fakePng(20000, 10))).toContain("larger than the machine takes");
    expect(imageProblem(fakePng(8000, 8000))).toContain("larger than the machine takes");
    expect(imageProblem(fakePng(7680, 4320))).toBeNull();
    expect(imageProblem(fakePng(0, 10))).not.toBeNull();
  });
});

describe("ClipboardImageManager", () => {
  test("says hello once attached, so the machine sends it pictures", () => {
    const { images } = manager();
    const { sender, requests } = recorder();
    images.attach(sender);
    expect(requests).toEqual([{ op: IMAGE_OP.hello, header: {} }]);
  });

  test("pastes in a window of chunks, and settles once the machine has it", async () => {
    const { images } = manager();
    const { sender, puts } = recorder();
    images.attach(sender);
    const png = fakePng(10, 10, IMAGE_CHUNK_SIZE * 6 + 100);
    const result = images.paste(png);
    // Four chunks, then nothing until the machine acknowledges some.
    expect(puts.map((put) => put.header.offset)).toEqual([0, 1, 2, 3].map((n) => n * IMAGE_CHUNK_SIZE));
    const id = puts[0]?.header.id as string;
    expect(puts.every((put) => put.op === IMAGE_OP.chunk && put.header.id === id && put.header.size === png.length)).toBe(
      true,
    );
    images.handle(IMAGE_OP.progress, { id, received: IMAGE_CHUNK_SIZE * 2 }, new Uint8Array());
    expect(puts).toHaveLength(6);
    images.handle(IMAGE_OP.progress, { id, received: IMAGE_CHUNK_SIZE * 6 }, new Uint8Array());
    expect(puts).toHaveLength(7);
    expect(puts[6]?.data?.length).toBe(100);
    // Every byte went, in order.
    const joined = new Uint8Array(puts.reduce((sum, put) => sum + (put.data?.length ?? 0), 0));
    let at = 0;
    for (const put of puts) {
      joined.set(put.data ?? new Uint8Array(), at);
      at += put.data?.length ?? 0;
    }
    expect(joined).toEqual(png);
    images.handle(IMAGE_OP.done, { id: "someone else's" }, new Uint8Array());
    images.handle(IMAGE_OP.done, { id }, new Uint8Array());
    expect(await result).toEqual({ ok: true });
  });

  test("passes the machine's refusal on, and refuses what's past the limits itself", async () => {
    const { images } = manager();
    const { sender, puts } = recorder();
    images.attach(sender);
    const result = images.paste(fakePng(10, 10));
    images.handle(IMAGE_OP.error, { id: puts[0]?.header.id, message: "nope" }, new Uint8Array());
    expect(await result).toEqual({ ok: false, message: "nope" });

    const tooLarge = await images.paste(fakePng(10, 10, MAX_CLIPBOARD_IMAGE_BYTES + 1));
    expect(tooLarge.ok).toBe(false);
    expect(puts).toHaveLength(1);
  });

  test("tells the machine to let go of a paste given up on", async () => {
    const { images } = manager(10);
    const { sender, requests, puts } = recorder();
    images.attach(sender);
    const result = await images.paste(fakePng(10, 10));
    expect(result.ok).toBe(false);
    expect(requests.at(-1)).toEqual({ op: IMAGE_OP.cancel, header: { id: puts[0]?.header.id } });
  });

  test("gives up on a paste when the view goes or the machine stays quiet", async () => {
    const { images } = manager(10);
    const { sender } = recorder();
    images.attach(sender);
    const dropped = images.paste(fakePng(10, 10));
    images.attach(null);
    expect((await dropped).ok).toBe(false);
    expect((await images.paste(fakePng(10, 10))).ok).toBe(false);

    images.attach(sender);
    const quiet = await images.paste(fakePng(10, 10));
    expect(quiet).toEqual({ ok: false, message: "the machine didn't take it in time" });
  });

  test("puts a picture from the machine together, acknowledging each chunk", () => {
    const { images, received } = manager();
    const { sender, requests } = recorder();
    images.attach(sender);
    requests.length = 0;
    const png = fakePng(320, 200, IMAGE_CHUNK_SIZE + 10);
    const first = png.slice(0, IMAGE_CHUNK_SIZE);
    const second = png.slice(IMAGE_CHUNK_SIZE);
    images.handle(IMAGE_OP.image, { id: "7", offset: 0, size: png.length, pushed: true }, first);
    expect(images.receiving).toBe(true);
    // Another picture's chunk is a leftover: ignored, and not acknowledged.
    images.handle(IMAGE_OP.image, { id: "6", offset: 5, size: png.length, pushed: true }, second);
    images.handle(IMAGE_OP.image, { id: "7", offset: IMAGE_CHUNK_SIZE, size: png.length, pushed: true }, second);
    expect(requests).toEqual([
      { op: IMAGE_OP.ack, header: { id: "7", received: IMAGE_CHUNK_SIZE } },
      { op: IMAGE_OP.ack, header: { id: "7", received: png.length } },
    ]);
    expect(images.receiving).toBe(false);
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({ width: 320, height: 200, pushed: true });
    expect(received[0]?.png).toEqual(png);
  });

  test("a newer picture replaces one still coming, and a too-large one is reported", () => {
    const { images, received, skipped } = manager();
    const { sender } = recorder();
    images.attach(sender);
    const old = fakePng(1, 1, IMAGE_CHUNK_SIZE * 2);
    images.handle(IMAGE_OP.image, { id: "1", offset: 0, size: old.length }, old.slice(0, IMAGE_CHUNK_SIZE));
    const fresh = fakePng(2, 2, 100);
    images.handle(IMAGE_OP.image, { id: "2", offset: 0, size: fresh.length }, fresh);
    images.handle(IMAGE_OP.image, { id: "1", offset: IMAGE_CHUNK_SIZE, size: old.length }, old.slice(IMAGE_CHUNK_SIZE));
    expect(received.map((image) => image.width)).toEqual([2]);

    images.handle(IMAGE_OP.skipped, { pushed: false }, new Uint8Array());
    expect(skipped).toEqual([false]);
  });

  test("refuses a picture that claims more than the limit", () => {
    const { images, received } = manager();
    const { sender, requests } = recorder();
    images.attach(sender);
    requests.length = 0;
    images.handle(IMAGE_OP.image, { id: "1", offset: 0, size: MAX_CLIPBOARD_IMAGE_BYTES + 1 }, fakePng(1, 1));
    expect(images.receiving).toBe(false);
    expect(requests).toEqual([]);
    expect(received).toEqual([]);
  });

  test("a chunk missing on the way cancels the picture rather than hang it", () => {
    const { images, received } = manager();
    const { sender, requests } = recorder();
    images.attach(sender);
    requests.length = 0;
    const png = fakePng(10, 10, IMAGE_CHUNK_SIZE * 3);
    images.handle(IMAGE_OP.image, { id: "9", offset: 0, size: png.length }, png.slice(0, IMAGE_CHUNK_SIZE));
    // The second chunk was dropped by the relay: the third arrives next.
    images.handle(IMAGE_OP.image, { id: "9", offset: IMAGE_CHUNK_SIZE * 2, size: png.length }, png.slice(IMAGE_CHUNK_SIZE * 2));
    expect(images.receiving).toBe(false);
    expect(requests.at(-1)).toEqual({ op: IMAGE_OP.cancel, header: { id: "9" } });
    // Whatever else of it still comes is ignored.
    images.handle(IMAGE_OP.image, { id: "9", offset: IMAGE_CHUNK_SIZE, size: png.length }, png.slice(IMAGE_CHUNK_SIZE, IMAGE_CHUNK_SIZE * 2));
    expect(received).toEqual([]);
    // Overlapping and repeated chunks go the same way.
    images.handle(IMAGE_OP.image, { id: "10", offset: 0, size: png.length }, png.slice(0, IMAGE_CHUNK_SIZE));
    images.handle(IMAGE_OP.image, { id: "10", offset: IMAGE_CHUNK_SIZE / 2, size: png.length }, png.slice(0, IMAGE_CHUNK_SIZE));
    expect(images.receiving).toBe(false);
    expect(received).toEqual([]);
  });

  test("a picture that stops coming stops counting as on its way", () => {
    const { images } = manager();
    const { sender } = recorder();
    images.attach(sender);
    const realNow = Date.now;
    try {
      let now = 1_000_000;
      Date.now = () => now;
      const png = fakePng(10, 10, IMAGE_CHUNK_SIZE * 2);
      images.handle(IMAGE_OP.image, { id: "1", offset: 0, size: png.length }, png.slice(0, IMAGE_CHUNK_SIZE));
      now += 29_000;
      expect(images.receiving).toBe(true);
      now += 2_000;
      expect(images.receiving).toBe(false);
    } finally {
      Date.now = realNow;
    }
  });

  test("ignores malformed headers and chunks with no start", () => {
    const { images, received } = manager();
    const { sender, requests } = recorder();
    images.attach(sender);
    requests.length = 0;
    const png = fakePng(4, 4, 100);
    for (const header of [
      null,
      "x",
      {},
      { id: "1", offset: "0", size: 100 },
      { id: "1", offset: 0, size: "100" },
      { id: "1", offset: 0, size: 0 },
      { id: "1", offset: 0, size: -5 },
      { id: "1", offset: 0, size: Number.NaN },
      { id: "1", offset: 0, size: Number.POSITIVE_INFINITY },
      { id: "1", offset: 50, size: 100 }, // no start
    ]) {
      images.handle(IMAGE_OP.image, header, png);
    }
    expect(images.receiving).toBe(false);
    expect(received).toEqual([]);
    expect(requests).toEqual([]);
  });

  test("a size lie (more data than declared) cancels, and so does a size that changes", () => {
    const { images, received } = manager();
    const { sender, requests } = recorder();
    images.attach(sender);
    requests.length = 0;
    images.handle(IMAGE_OP.image, { id: "1", offset: 0, size: 50 }, fakePng(4, 4, 100));
    expect(requests).toEqual([{ op: IMAGE_OP.cancel, header: { id: "1" } }]);
    const png = fakePng(4, 4, 200);
    images.handle(IMAGE_OP.image, { id: "2", offset: 0, size: 200 }, png.slice(0, 100));
    // Same id, other size: a leftover, ignored; the real rest completes it.
    images.handle(IMAGE_OP.image, { id: "2", offset: 100, size: 300 }, png.slice(100));
    images.handle(IMAGE_OP.image, { id: "2", offset: 100, size: 200 }, png.slice(100));
    expect(received).toHaveLength(1);
    // More chunks than declared, after it's done: nothing.
    images.handle(IMAGE_OP.image, { id: "2", offset: 200, size: 200 }, png.slice(0, 10));
    expect(received).toHaveLength(1);
    expect(images.receiving).toBe(false);
  });

  test("a complete picture that isn't a PNG is dropped", () => {
    const { images, received } = manager();
    const { sender } = recorder();
    images.attach(sender);
    images.handle(IMAGE_OP.image, { id: "1", offset: 0, size: 64 }, new Uint8Array(64));
    expect(received).toEqual([]);
  });

  test("a view closing mid-transfer drops the picture and fails the paste", async () => {
    const { images, received } = manager();
    const { sender } = recorder();
    images.attach(sender);
    const png = fakePng(4, 4, IMAGE_CHUNK_SIZE * 2);
    images.handle(IMAGE_OP.image, { id: "1", offset: 0, size: png.length }, png.slice(0, IMAGE_CHUNK_SIZE));
    const paste = images.paste(fakePng(4, 4, IMAGE_CHUNK_SIZE * 6));
    images.close();
    expect((await paste).ok).toBe(false);
    expect(images.receiving).toBe(false);
    images.handle(IMAGE_OP.image, { id: "1", offset: IMAGE_CHUNK_SIZE, size: png.length }, png.slice(IMAGE_CHUNK_SIZE));
    expect(received).toEqual([]);
  });

  test("progress past what was sent, or for another paste, doesn't open the window", () => {
    const { images } = manager();
    const { sender, puts } = recorder();
    images.attach(sender);
    void images.paste(fakePng(4, 4, IMAGE_CHUNK_SIZE * 10));
    expect(puts).toHaveLength(4);
    const id = puts[0]?.header.id as string;
    images.handle(IMAGE_OP.progress, { id: "other", received: IMAGE_CHUNK_SIZE * 4 }, new Uint8Array());
    expect(puts).toHaveLength(4);
    images.handle(IMAGE_OP.progress, { id, received: Number.MAX_SAFE_INTEGER }, new Uint8Array());
    expect(puts).toHaveLength(8); // clamped to what was sent: four more
    images.handle(IMAGE_OP.progress, { id, received: 0 }, new Uint8Array()); // backwards: nothing
    expect(puts).toHaveLength(8);
    const offsets = puts.map((put) => put.header.offset);
    expect(offsets).toEqual([0, 1, 2, 3, 4, 5, 6, 7].map((i) => i * IMAGE_CHUNK_SIZE));
    images.close();
  });
});

describe("session keys", () => {
  // The image key is a 9th 32-byte key: the first 256 bytes must be what a
  // machine or dashboard from before pictures derives, so mixed versions
  // still agree on the other eight.
  test("288 bytes of HKDF start with the 256 an older side derives", async () => {
    const ikm = new Uint8Array(32).map((_, i) => i * 7 + 1);
    const salt = new Uint8Array(32).map((_, i) => 255 - i);
    const short = await hkdf(ikm, salt, "hawk-session-v1", 256);
    const long = await hkdf(ikm, salt, "hawk-session-v1", 288);
    expect(long.length).toBe(288);
    expect(long.slice(0, 256)).toEqual(short);
    expect(long.slice(256)).not.toEqual(long.slice(224, 256));
  });
});
