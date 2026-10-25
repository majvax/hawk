// The end-process request and answer on a ViewSession: sealed on the input
// key with its own AAD, answered on the reply key and numbered with the
// other replies. The session's keys are set by hand here, as the handshake
// would leave them.
import { describe, expect, test } from "bun:test";

import { aesDecrypt, aesEncrypt, fromBase64, toBase64 } from "./crypto.js";
import { canEndProcesses } from "./protocol.js";

// e2e.ts reaches relay.ts, which looks at `window` as it loads.
(globalThis as { window?: unknown }).window ??= globalThis;
const { ViewSession } = await import("./e2e.js");
type ViewSession = (typeof ViewSession)["prototype"];

const utf8 = (text: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(text) as Uint8Array<ArrayBuffer>;
const AAD = utf8("hawk-end-process-v1");

async function aesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function session(): Promise<{ view: ViewSession; input: CryptoKey; reply: CryptoKey }> {
  const input = await aesKey();
  const reply = await aesKey();
  const view = Object.create(ViewSession.prototype) as ViewSession;
  Object.assign(view, { inputKey: input, replyKey: reply, inputCounter: 0n, replyCounter: 0n });
  return { view, input, reply };
}

function nonce(counter: bigint): { prefix: Uint8Array<ArrayBuffer>; iv: Uint8Array<ArrayBuffer> } {
  const prefix = new Uint8Array(8);
  new DataView(prefix.buffer).setBigUint64(0, counter);
  const iv = new Uint8Array(12);
  iv.set(prefix);
  return { prefix, iv };
}

// What the machine sends: counter || AES-GCM(reply key, op || json).
async function answer(key: CryptoKey, counter: bigint, op: number, json: string, aad = AAD): Promise<string> {
  const { prefix, iv } = nonce(counter);
  const body = utf8(json);
  const plain = new Uint8Array(1 + body.length);
  plain[0] = op;
  plain.set(body, 1);
  const sealed = await aesEncrypt(key, iv, plain, aad);
  const out = new Uint8Array(8 + sealed.length);
  out.set(prefix);
  out.set(sealed, 8);
  return toBase64(out);
}

describe("end process", () => {
  test("the request names the process, sealed on the input key under its own AAD", async () => {
    const { view, input } = await session();
    const sealed = await view.sealEndProcess({ pid: 1234, started: 1_700_000_000_123 });
    expect(sealed).not.toBeNull();
    const bytes = fromBase64(sealed as string);
    const counter = new DataView(bytes.buffer).getBigUint64(0);
    expect(counter).toBe(1n);
    const plain = await aesDecrypt(input, nonce(counter).iv, bytes.slice(8), AAD);
    expect(JSON.parse(new TextDecoder().decode(plain))).toEqual({ pid: 1234, started: 1_700_000_000_123 });
    // Under any other channel's AAD it doesn't open.
    await expect(aesDecrypt(input, nonce(counter).iv, bytes.slice(8), utf8("hawk-sas-v1"))).rejects.toThrow();
  });

  test("an answer opens once, in order, and only under its own AAD", async () => {
    const { view, reply } = await session();
    const ended = await answer(reply, 3n, 1, JSON.stringify({ pid: 5, started: 9, name: "notepad.exe", error: "" }));
    expect(await view.openEndProcess(ended)).toEqual({ ended: true, pid: 5, started: 9, name: "notepad.exe", error: "" });
    expect(await view.openEndProcess(ended)).toBeNull(); // replayed
    expect(await view.openEndProcess(await answer(reply, 2n, 2, "{}"))).toBeNull(); // older
    expect(await view.openEndProcess(await answer(reply, 4n, 2, "{}", utf8("hawk-sas-v1")))).toBeNull();
    const refused = await answer(reply, 5n, 2, JSON.stringify({ pid: 4, started: 0, error: "it's Windows itself" }));
    expect(await view.openEndProcess(refused)).toEqual({
      ended: false,
      pid: 4,
      started: 0,
      name: "",
      error: "it's Windows itself",
    });
  });

  test("a malformed answer is nothing, and fields of the wrong type are blanks", async () => {
    const { view, reply } = await session();
    expect(await view.openEndProcess(await answer(reply, 1n, 7, "{}"))).toBeNull(); // unknown status
    expect(await view.openEndProcess(await answer(reply, 2n, 1, "not json"))).toBeNull();
    expect(await view.openEndProcess(await answer(reply, 3n, 1, "null"))).toBeNull();
    expect(await view.openEndProcess("short")).toBeNull();
    const odd = await answer(reply, 4n, 2, JSON.stringify({ pid: "5", name: 7, error: ["<b>x</b>"] }));
    expect(await view.openEndProcess(odd)).toEqual({ ended: false, pid: 0, started: 0, name: "", error: "" });
  });

  test("without a secured view there's nothing to seal or open with", async () => {
    const view = Object.create(ViewSession.prototype) as ViewSession;
    Object.assign(view, { inputKey: null, replyKey: null, inputCounter: 0n, replyCounter: 0n });
    expect(view.sealEndProcess({ pid: 1, started: 1 })).toBeNull();
    expect(await view.openEndProcess("AAAA")).toBeNull();
  });

  test("control, dev and the owner may; a view share may not", () => {
    expect(canEndProcesses("owner")).toBe(true);
    expect(canEndProcesses("control")).toBe(true);
    expect(canEndProcesses("dev")).toBe(true);
    expect(canEndProcesses("view")).toBe(false);
  });
});
