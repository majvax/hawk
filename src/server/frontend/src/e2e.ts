// End-to-end encryption between this browser and a machine. The relay
// carries everything but can read none of it, and nothing it says is taken
// on trust:
//
// - Enrollment: the code is made here and only its hash goes to the relay.
//   The machine and this browser each MAC their own key with the code, so
//   each can check the other's key really came from the code's holder.
// - Endorsement: once the machine's key checks out, the owner signs it.
//   Everyone the machine is shared with trusts the key through that
//   signature, and the owner's key through trust on first use (keystore.ts).
// - Grants: the owner signs who may watch, in what role and when. The
//   machine checks those signatures itself, against the owner key it pinned
//   at enrollment, so the relay can't let anyone else in.
// - Viewing: each view is a fresh ECDH exchange, signed by the viewer's
//   identity key and by the machine's key. The machine sends back the
//   stream key wrapped for this viewer; frames are AES-GCM under it, and
//   input is sealed under a key only this viewer and the machine share.
//
// The formats match relay/src/e2e.rs and src/service/e2e.cpp.

import type { EnrollmentCode, ShareTerms, SignedStatement } from "./api.js";
import * as api from "./api.js";
import {
  aesDecrypt,
  aesEncrypt,
  aesKey,
  concat,
  equalBytes,
  exchange,
  exportPublicKey,
  fromBase64,
  generateExchangeKey,
  hkdf,
  hmac,
  parseStatement,
  randomBytes,
  sha256,
  sign,
  statement,
  toBase64,
  unseal,
  utf8,
  verify,
} from "./crypto.js";
import type { Identity } from "./keys.js";
import { checkContact, forgetPendingEnrollment, pendingEnrollment, savePendingEnrollment } from "./keystore.js";
import type { InputEvent, Machine, ParsedVideoFrame, PowerAction, Role } from "./protocol.js";

const NO_SALT = new Uint8Array(0);

// --- Enrollment ------------------------------------------------------------------------

// Crockford base32: no I, L, O or U, so a code read aloud or typed by hand
// survives.
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
// 25 symbols, 125 bits: enough that the relay, which sees the code's hash
// and both bindings, can't guess it.
const CODE_LENGTH = 25;

// Mirrors the machine's canonical form: alphanumerics only, uppercase, and
// the letters people mistake for digits read as those digits.
function canonicalCode(code: string): string {
  return code
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
}

async function enrollmentKey(code: string): Promise<Uint8Array<ArrayBuffer>> {
  return hkdf(utf8(canonicalCode(code)), NO_SALT, "hawk-enroll-v1", 32);
}

export async function codeHash(code: string): Promise<string> {
  return toBase64(await sha256(utf8(canonicalCode(code))));
}

async function binding(code: string, context: string, publicKey: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return hmac(await enrollmentKey(code), concat(utf8(`${context}\0`), publicKey));
}

// Makes a one-time enrollment code and registers its hash, with the owner's
// key bound to it, on the relay.
export async function createEnrollment(identity: Identity): Promise<EnrollmentCode> {
  // 256 is a multiple of 32, so masking keeps every symbol equally likely.
  const symbols = Array.from(randomBytes(CODE_LENGTH), (byte) => ALPHABET[byte & 31]).join("");
  const code = symbols.match(/.{5}/g)?.join("-") ?? symbols;
  const hash = await codeHash(code);
  const ownerBinding = await binding(code, "hawk-enroll-owner-v1", identity.publicKey);
  await savePendingEnrollment(hash, code);
  const registered = await api.registerEnrollmentCode(hash, toBase64(ownerBinding));
  return { code, ...registered };
}

// What the owner signs to vouch for their machine's key.
function machineStatement(machineId: string, machineKey: Uint8Array): string {
  return statement("hawk-machine-v1", [
    ["machine", machineId],
    ["key", toBase64(machineKey)],
  ]);
}

export async function endorse(identity: Identity, machine: Machine): Promise<void> {
  if (machine.publicKey === null) throw new Error("this machine has no key; enroll it again");
  const signature = await sign(identity.privateKey, machineStatement(machine.id, fromBase64(machine.publicKey)));
  await api.endorseMachine(machine.id, toBase64(signature));
}

export type EnrollmentCheck = "endorsed" | "unknown" | "mismatch";

// For an owned machine not endorsed yet: if this browser made its
// enrollment code, checks the key the machine answered with against the
// code, and endorses it when it matches. "unknown" means another browser
// made the code; the owner can still compare fingerprints by hand.
export async function checkEnrollment(identity: Identity, machine: Machine): Promise<EnrollmentCheck> {
  if (machine.enrollCodeHash === null || machine.enrollBinding === null || machine.publicKey === null) return "unknown";
  const code = await pendingEnrollment(machine.enrollCodeHash);
  if (code === null) return "unknown";
  const expected = await binding(code, "hawk-enroll-machine-v1", fromBase64(machine.publicKey));
  if (!equalBytes(expected, fromBase64(machine.enrollBinding))) return "mismatch";
  await endorse(identity, machine);
  await forgetPendingEnrollment(machine.enrollCodeHash);
  return "endorsed";
}

// --- Grants and revocations -------------------------------------------------------------------

const optionalTime = (time: number | null): string => (time === null ? "-" : String(time));

function issuedOf(signed: SignedStatement | null, context: string): number {
  const issued = signed === null ? undefined : parseStatement(signed.statement, context)?.get("issued");
  return issued === undefined ? 0 : Number(issued) || 0;
}

// Later than anything signed before for this share, even if another of
// the owner's devices had a clock running ahead: the machine only honours
// the newest.
function nextIssued(previous: SignedStatement | null): number {
  return Math.max(Date.now(), issuedOf(previous, "hawk-grant-v1") + 1);
}

async function signed(identity: Identity, text: string): Promise<SignedStatement> {
  return { statement: text, signature: toBase64(await sign(identity.privateKey, text)) };
}

export function signGrant(
  identity: Identity,
  machineId: string,
  viewerKey: string,
  terms: ShareTerms,
  previous: SignedStatement | null,
): Promise<SignedStatement> {
  return signed(
    identity,
    statement("hawk-grant-v1", [
      ["machine", machineId],
      ["viewer", viewerKey],
      ["role", terms.role],
      ["not_before", optionalTime(terms.startsAt)],
      ["not_after", optionalTime(terms.expiresAt)],
      ["single_view", terms.singleView ? "1" : "0"],
      ["analytics", terms.analytics ? "1" : "0"],
      ["issued", String(nextIssued(previous))],
    ]),
  );
}

export function signRevocation(
  identity: Identity,
  machineId: string,
  viewerKey: string,
  grant: SignedStatement | null,
): Promise<SignedStatement> {
  return signed(
    identity,
    statement("hawk-revoke-v1", [
      ["machine", machineId],
      ["viewer", viewerKey],
      ["issued", String(nextIssued(grant))],
    ]),
  );
}

// --- Trusting a machine's key -------------------------------------------------------------------

export type MachineTrust =
  | { ok: true; machineKey: Uint8Array<ArrayBuffer> }
  | { ok: false; reason: "re-enroll" | "unendorsed" | "owner-key-changed" | "bad-endorsement" };

// The machine's key, if the owner vouched for it with a key this browser
// trusts: its own, for the owner, or the one first seen for that owner.
export async function trustMachine(identity: Identity, machine: Machine): Promise<MachineTrust> {
  if (machine.publicKey === null || machine.ownerPublicKey === null) return { ok: false, reason: "re-enroll" };
  if (machine.endorsement === null) return { ok: false, reason: "unendorsed" };
  const ownerKey = fromBase64(machine.ownerPublicKey);
  if (machine.role === "owner") {
    if (!equalBytes(ownerKey, identity.publicKey)) return { ok: false, reason: "owner-key-changed" };
  } else if ((await checkContact(machine.ownerEmail, ownerKey)).kind === "changed") {
    return { ok: false, reason: "owner-key-changed" };
  }
  const machineKey = fromBase64(machine.publicKey);
  if (!(await verify(ownerKey, machineStatement(machine.id, machineKey), fromBase64(machine.endorsement)))) {
    return { ok: false, reason: "bad-endorsement" };
  }
  return { ok: true, machineKey };
}

// --- A viewing session ------------------------------------------------------------------------

// Mirrors the machine's frame layout: kind, flags, timestamp (LE), key id
// (BE), IV, then ciphertext and tag. Everything before the IV is
// authenticated as associated data; the relay reads only the flags.
const FRAME_KIND_ENCRYPTED = 0x02;
const FRAME_KEYFRAME_FLAG = 0x01;
// The frame carries an Opus packet of the machine's sound.
export const FRAME_AUDIO_FLAG = 0x02;
const FRAME_AAD_SIZE = 14;
const FRAME_HEADER_SIZE = FRAME_AAD_SIZE + 12;

const STREAM_KEY_AAD = utf8("hawk-stream-key-v1");
const INPUT_AAD = utf8("hawk-input-v1");
const CLIPBOARD_AAD = utf8("hawk-clipboard-v1");
// The first byte of a sealed clipboard message; UTF-8 text follows it.
const CLIPBOARD_SET = 1;
const CLIPBOARD_GET = 2;
const CLIPBOARD_TEXT = 3;
const CLIPBOARD_PUSH = 4;
// Clipboard pictures: the image channel either way, and chunks of one to
// paste, sealed apart so the relay can hold those to control.
const CLIPBOARD_IMAGE_AAD = utf8("hawk-clipboard-image-v1");
const CLIPBOARD_IMAGE_PUT_AAD = utf8("hawk-clipboard-image-put-v1");
// The image channel's answers, sealed on the reply key with clipboard text.
const CLIPBOARD_IMAGE_REPLY_AAD = utf8("hawk-clipboard-image-reply-v1");
const FILE_AAD = utf8("hawk-file-v1");
const SHELL_AAD = utf8("hawk-shell-v1");
const METRICS_AAD = utf8("hawk-metrics-v1");
const POWER_AAD = utf8("hawk-power-v1");
// Asking for the device list and choosing a device are sealed apart, so
// the relay can't pass one off as the other.
const AUDIO_LIST_AAD = utf8("hawk-audio-list-v1");
const AUDIO_SELECT_AAD = utf8("hawk-audio-select-v1");
const AUDIO_AAD = utf8("hawk-audio-v1");
// Likewise reading the config and changing it.
const CONFIG_GET_AAD = utf8("hawk-config-get-v1");
const CONFIG_SET_AAD = utf8("hawk-config-set-v1");
const QUALITY_AAD = utf8("hawk-quality-v1");
// Ctrl+Alt+Del, and the machine's answer to it on the reply key.
const SAS_AAD = utf8("hawk-sas-v1");
// The first byte of that answer; must match kSasSent and kSasFailed in
// src/service/e2e.cpp.
const SAS_SENT = 1;
const SAS_FAILED = 2;
// A process to end, and the machine's answer to it on the reply key.
const END_PROCESS_AAD = utf8("hawk-end-process-v1");
// The first byte of that answer; must match kEndProcessEnded and
// kEndProcessFailed in src/service/e2e.cpp.
const END_PROCESS_ENDED = 1;
const END_PROCESS_FAILED = 2;
const CONFIG_AAD = utf8("hawk-config-v1");
// The byte a sealed power request carries; must match PowerAction in
// src/service/power.hpp.
const POWER_ACTIONS: Record<PowerAction, number> = { lock: 1, sign_out: 2, restart: 3, shut_down: 4 };

// The machine's answer to a process to end.
export interface EndProcessAnswer {
  ended: boolean;
  pid: number;
  started: number;
  name: string; // its image name, when the machine could read it
  error: string; // why not, when it wasn't ended
}

// One file- or shell-channel message from the machine, opened.
export interface ChannelMessage {
  op: number;
  header: unknown;
  data: Uint8Array<ArrayBuffer>;
}
// Stream keys kept around after a newer one arrives, for frames already in
// flight under the old one.
const KEEP_STREAM_KEYS = 2;

// counter || ciphertext from the machine, opened: null for anything that
// doesn't open, or whose counter isn't past `last`.
async function openChannel(
  key: CryptoKey,
  sealed: string,
  aad: Uint8Array<ArrayBuffer>,
  last: bigint,
): Promise<{ counter: bigint; message: ChannelMessage } | null> {
  try {
    const bytes = fromBase64(sealed);
    if (bytes.length < 8 + 16) return null;
    const counter = new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(0);
    if (counter <= last) return null;
    const iv = concat(bytes.slice(0, 8), new Uint8Array(4));
    const plain = await aesDecrypt(key, iv, bytes.slice(8), aad);
    if (plain.length < 3) return null;
    const headerSize = ((plain[1] ?? 0) << 8) | (plain[2] ?? 0);
    if (plain.length < 3 + headerSize) return null;
    const header: unknown = JSON.parse(new TextDecoder().decode(plain.slice(3, 3 + headerSize)));
    return { counter, message: { op: plain[0] ?? 0, header, data: plain.slice(3 + headerSize) } };
  } catch {
    return null;
  }
}

export class ViewSession {
  readonly join: SignedStatement;
  role: Role | null = null;
  private settle: (accepted: boolean) => void = () => {};
  // Settles once the machine's answer checked out (true), or the session
  // was given up (false). Frames that arrive first wait on it: the stream
  // key they're under comes with the answer, and the first of them is
  // usually the keyframe decoding has to start from.
  private readonly ready = new Promise<boolean>((resolve) => {
    this.settle = resolve;
  });
  private inputKey: CryptoKey | null = null;
  private wrapKey: CryptoKey | null = null;
  // Opens what the machine sends this viewer alone (clipboard text).
  private replyKey: CryptoKey | null = null;
  // And file-channel messages, which the relay queues apart from the rest,
  // so they have a key and a counter of their own.
  private fileKey: CryptoKey | null = null;
  private fileCounter = 0n;
  // And shell output, likewise.
  private shellKey: CryptoKey | null = null;
  private shellCounter = 0n;
  // And the machine's analytics, likewise.
  private metricsKey: CryptoKey | null = null;
  private metricsCounter = 0n;
  // And the machine's output devices, likewise.
  private audioKey: CryptoKey | null = null;
  private audioCounter = 0n;
  // And the machine's config, likewise.
  private configKey: CryptoKey | null = null;
  private configCounter = 0n;
  // And clipboard pictures, likewise.
  private imageKey: CryptoKey | null = null;
  private imageCounter = 0n;
  private readonly streamKeys = new Map<number, CryptoKey>();
  // Numbers input events and clipboard requests alike: the machine keeps
  // one counter for both.
  private inputCounter = 0n;
  private replyCounter = 0n;

  private constructor(
    private readonly machineId: string,
    private readonly machineKey: Uint8Array<ArrayBuffer>,
    private readonly exchangeKey: CryptoKeyPair,
    join: SignedStatement,
  ) {
    this.join = join;
  }

  // A signed request to join `machineId`'s stream, with a fresh exchange key.
  static async start(identity: Identity, machineId: string, machineKey: Uint8Array<ArrayBuffer>): Promise<ViewSession> {
    const exchangeKey = await generateExchangeKey();
    const text = statement("hawk-join-v1", [
      ["machine", machineId],
      ["viewer", toBase64(identity.publicKey)],
      ["ephemeral", toBase64(await exportPublicKey(exchangeKey.publicKey))],
      ["time", String(Date.now())],
    ]);
    return new ViewSession(machineId, machineKey, exchangeKey, await signed(identity, text));
  }

  get accepted(): boolean {
    return this.inputKey !== null;
  }

  // Checks the machine's answer to the join and derives this session's
  // keys from it. Throws if anything about it doesn't hold up.
  async accept(answer: { statement: string; signature: string; wrappedKey: string }): Promise<void> {
    if (!(await verify(this.machineKey, answer.statement, fromBase64(answer.signature)))) {
      throw new Error("the machine's answer isn't signed by its key");
    }
    const fields = parseStatement(answer.statement, "hawk-accept-v1");
    const joinHash = await sha256(utf8(this.join.statement));
    const role = fields?.get("role");
    const ephemeral = fields?.get("ephemeral");
    if (
      fields === null ||
      fields.get("machine") !== this.machineId ||
      fields.get("join") !== toBase64(joinHash) ||
      ephemeral === undefined ||
      (role !== "owner" && role !== "control" && role !== "view" && role !== "dev")
    ) {
      throw new Error("the machine's answer doesn't match this request");
    }
    const shared = await exchange(this.exchangeKey.privateKey, fromBase64(ephemeral));
    // HKDF output is a prefix of any longer output: a machine that derives
    // fewer keys agrees on the ones it has.
    const keys = await hkdf(shared, joinHash, "hawk-session-v1", 288);
    this.inputKey = await aesKey(keys.slice(0, 32), ["encrypt"]);
    this.wrapKey = await aesKey(keys.slice(32, 64), ["decrypt"]);
    this.replyKey = await aesKey(keys.slice(64, 96), ["decrypt"]);
    this.fileKey = await aesKey(keys.slice(96, 128), ["decrypt"]);
    this.shellKey = await aesKey(keys.slice(128, 160), ["decrypt"]);
    this.metricsKey = await aesKey(keys.slice(160, 192), ["decrypt"]);
    this.audioKey = await aesKey(keys.slice(192, 224), ["decrypt"]);
    this.configKey = await aesKey(keys.slice(224, 256), ["decrypt"]);
    this.imageKey = await aesKey(keys.slice(256, 288), ["decrypt"]);
    this.role = role;
    // A dev viewer doesn't watch the screen, and is never given its key.
    if (answer.wrappedKey !== "") await this.addStreamKey(answer.wrappedKey);
    this.settle(true);
  }

  // Ends the session: frames still waiting for the answer are dropped.
  abandon(): void {
    this.settle(false);
  }

  async addStreamKey(wrappedKey: string): Promise<void> {
    if (this.wrapKey === null) throw new Error("stream key before the session was accepted");
    const plain = await unseal(this.wrapKey, fromBase64(wrappedKey), STREAM_KEY_AAD);
    if (plain.length !== 36) throw new Error("malformed stream key");
    const id = new DataView(plain.buffer).getUint32(0);
    this.streamKeys.set(id, await aesKey(plain.slice(4), ["decrypt"]));
    while (this.streamKeys.size > KEEP_STREAM_KEYS + 1) {
      const oldest = this.streamKeys.keys().next().value;
      if (oldest === undefined) break;
      this.streamKeys.delete(oldest);
    }
  }

  // The access unit inside an encrypted frame; null for a frame this
  // session can't open (a key it was never given, or tampering).
  async openFrame(buffer: ArrayBuffer): Promise<ParsedVideoFrame | null> {
    if (!(await this.ready) || buffer.byteLength < FRAME_HEADER_SIZE + 16) return null;
    const bytes = new Uint8Array(buffer);
    if (bytes[0] !== FRAME_KIND_ENCRYPTED) return null;
    const view = new DataView(buffer);
    const key = this.streamKeys.get(view.getUint32(10));
    if (key === undefined) return null;
    try {
      const data = await aesDecrypt(
        key,
        bytes.slice(FRAME_AAD_SIZE, FRAME_HEADER_SIZE),
        bytes.slice(FRAME_HEADER_SIZE),
        bytes.slice(0, FRAME_AAD_SIZE),
      );
      return {
        isKeyframe: ((bytes[1] ?? 0) & FRAME_KEYFRAME_FLAG) !== 0,
        isAudio: ((bytes[1] ?? 0) & FRAME_AUDIO_FLAG) !== 0,
        timestamp: Number(view.getBigInt64(2, true)),
        data,
      };
    } catch {
      return null;
    }
  }

  // Seals one input event for the machine: counter || ciphertext, base64.
  // The counter numbers events in the order they're sealed, which is the
  // order they must be sent in; the machine refuses any it has seen.
  sealInput(event: InputEvent): Promise<string> | null {
    return this.sealRequest(utf8(JSON.stringify(event)), INPUT_AAD);
  }

  // Seals a clipboard request: text to paste into the machine, or (with
  // no text) a request to read its clipboard. Numbered from the same
  // counter as input, so it must be sent in the same order too.
  sealClipboard(text: string | null): Promise<string> | null {
    const op = new Uint8Array([text === null ? CLIPBOARD_GET : CLIPBOARD_SET]);
    return this.sealRequest(text === null ? op : concat(op, utf8(text)), CLIPBOARD_AAD);
  }

  // Clipboard text the machine sealed for this viewer: `pushed` for a copy
  // made on the machine (sync mode), otherwise the answer to a request.
  // null for anything that doesn't open, or that was seen before.
  async openClipboard(sealed: string): Promise<{ text: string; pushed: boolean } | null> {
    const key = this.replyKey;
    if (key === null) return null;
    try {
      const bytes = fromBase64(sealed);
      if (bytes.length < 8 + 16) return null;
      const counter = new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(0);
      if (counter <= this.replyCounter) return null;
      const iv = concat(bytes.slice(0, 8), new Uint8Array(4));
      const plain = await aesDecrypt(key, iv, bytes.slice(8), CLIPBOARD_AAD);
      if (counter <= this.replyCounter) return null; // another one got there first
      const op = plain[0];
      if (op !== CLIPBOARD_TEXT && op !== CLIPBOARD_PUSH) return null;
      this.replyCounter = counter;
      return { text: new TextDecoder().decode(plain.slice(1)), pushed: op === CLIPBOARD_PUSH };
    } catch {
      return null;
    }
  }

  // Seals a file-channel message: op, header length, the JSON header, then
  // file data. Numbered from the input counter like everything sent.
  sealFile(op: number, header: object, data?: Uint8Array): Promise<string> | null {
    return this.sealChannel(op, header, data, FILE_AAD);
  }

  // The same for the shell channel (dev and owner).
  sealShell(op: number, header: object, data?: Uint8Array): Promise<string> | null {
    return this.sealChannel(op, header, data, SHELL_AAD);
  }

  // The same for the image channel's requests (hello, ack, cancel).
  sealClipboardImage(op: number, header: object): Promise<string> | null {
    return this.sealChannel(op, header, undefined, CLIPBOARD_IMAGE_AAD);
  }

  // A chunk of a picture to paste, sealed apart from the requests.
  sealClipboardImagePut(op: number, header: object, data: Uint8Array): Promise<string> | null {
    return this.sealChannel(op, header, data, CLIPBOARD_IMAGE_PUT_AAD);
  }

  // The same for the metrics channel (owner, and shares with analytics).
  sealMetrics(op: number, header: object): Promise<string> | null {
    return this.sealChannel(op, header, undefined, METRICS_AAD);
  }

  // Seals a power action: one byte saying which. Numbered from the input
  // counter like everything sent.
  sealPower(action: PowerAction): Promise<string> | null {
    return this.sealRequest(new Uint8Array([POWER_ACTIONS[action]]), POWER_AAD);
  }

  // Asks for the machine's output devices: nothing but the counter.
  sealAudioList(): Promise<string> | null {
    return this.sealRequest(new Uint8Array(0), AUDIO_LIST_AAD);
  }

  // Chooses the device to capture by its endpoint id; "" for the default.
  sealAudioSelect(id: string): Promise<string> | null {
    return this.sealRequest(utf8(id), AUDIO_SELECT_AAD);
  }

  // Asks for the machine's config: nothing but the counter.
  sealConfigGet(): Promise<string> | null {
    return this.sealRequest(new Uint8Array(0), CONFIG_GET_AAD);
  }

  // Changes it: the version the change was made against, and the new
  // values by key (see machineConfig.ts).
  sealConfigSet(change: { version: string; changes: Record<string, boolean | number | string> }): Promise<string> | null {
    return this.sealRequest(utf8(JSON.stringify(change)), CONFIG_SET_AAD);
  }

  // Picks the stream's quality preset by name (quality.ts).
  sealQuality(preset: string): Promise<string> | null {
    return this.sealRequest(utf8(preset), QUALITY_AAD);
  }

  // Presses Ctrl+Alt+Del: nothing but the counter.
  sealSas(): Promise<string> | null {
    return this.sealRequest(new Uint8Array(0), SAS_AAD);
  }

  // The machine's answer to it: pressed, or why not. On the reply key, so
  // numbered with clipboard text. null for anything that doesn't open, or
  // that was seen before.
  async openSas(sealed: string): Promise<{ sent: boolean; error: string } | null> {
    const key = this.replyKey;
    if (key === null) return null;
    try {
      const bytes = fromBase64(sealed);
      if (bytes.length < 8 + 16) return null;
      const counter = new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(0);
      if (counter <= this.replyCounter) return null;
      const iv = concat(bytes.slice(0, 8), new Uint8Array(4));
      const plain = await aesDecrypt(key, iv, bytes.slice(8), SAS_AAD);
      if (counter <= this.replyCounter) return null; // another one got there first
      const op = plain[0];
      if (op !== SAS_SENT && op !== SAS_FAILED) return null;
      this.replyCounter = counter;
      return { sent: op === SAS_SENT, error: new TextDecoder().decode(plain.slice(1)) };
    } catch {
      return null;
    }
  }

  // Ends a process: its PID and when it started (unix milliseconds, as the
  // process list gives it), so the machine never ends a newer process that
  // was given the same PID.
  sealEndProcess(target: { pid: number; started: number }): Promise<string> | null {
    return this.sealRequest(utf8(JSON.stringify({ pid: target.pid, started: target.started })), END_PROCESS_AAD);
  }

  // The machine's answer to it: ended, or why not, and which process. On
  // the reply key, so numbered with clipboard text and Ctrl+Alt+Del. null
  // for anything that doesn't open, or that was seen before.
  async openEndProcess(sealed: string): Promise<EndProcessAnswer | null> {
    const key = this.replyKey;
    if (key === null) return null;
    try {
      const bytes = fromBase64(sealed);
      if (bytes.length < 8 + 16) return null;
      const counter = new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(0);
      if (counter <= this.replyCounter) return null;
      const iv = concat(bytes.slice(0, 8), new Uint8Array(4));
      const plain = await aesDecrypt(key, iv, bytes.slice(8), END_PROCESS_AAD);
      if (counter <= this.replyCounter) return null; // another one got there first
      const op = plain[0];
      if (op !== END_PROCESS_ENDED && op !== END_PROCESS_FAILED) return null;
      const body = JSON.parse(new TextDecoder().decode(plain.slice(1))) as Record<string, unknown>;
      this.replyCounter = counter;
      return {
        ended: op === END_PROCESS_ENDED,
        pid: typeof body.pid === "number" ? body.pid : 0,
        started: typeof body.started === "number" ? body.started : 0,
        name: typeof body.name === "string" ? body.name : "",
        error: typeof body.error === "string" ? body.error : "",
      };
    } catch {
      return null;
    }
  }

  // A file-channel message from the machine; null for anything that
  // doesn't open or was seen before. Must be called in the order the
  // messages arrived.
  async openFile(sealed: string): Promise<ChannelMessage | null> {
    const key = this.fileKey;
    if (key === null) return null;
    const opened = await openChannel(key, sealed, FILE_AAD, this.fileCounter);
    if (opened === null || opened.counter <= this.fileCounter) return null;
    this.fileCounter = opened.counter;
    return opened.message;
  }

  // The same for the shell channel.
  async openShell(sealed: string): Promise<ChannelMessage | null> {
    const key = this.shellKey;
    if (key === null) return null;
    const opened = await openChannel(key, sealed, SHELL_AAD, this.shellCounter);
    if (opened === null || opened.counter <= this.shellCounter) return null;
    this.shellCounter = opened.counter;
    return opened.message;
  }

  // The same for the metrics channel.
  async openMetrics(sealed: string): Promise<ChannelMessage | null> {
    const key = this.metricsKey;
    if (key === null) return null;
    const opened = await openChannel(key, sealed, METRICS_AAD, this.metricsCounter);
    if (opened === null || opened.counter <= this.metricsCounter) return null;
    this.metricsCounter = opened.counter;
    return opened.message;
  }

  // The same for the machine's output devices.
  async openAudio(sealed: string): Promise<ChannelMessage | null> {
    const key = this.audioKey;
    if (key === null) return null;
    const opened = await openChannel(key, sealed, AUDIO_AAD, this.audioCounter);
    if (opened === null || opened.counter <= this.audioCounter) return null;
    this.audioCounter = opened.counter;
    return opened.message;
  }

  // The same for the machine's config.
  async openConfig(sealed: string): Promise<ChannelMessage | null> {
    const key = this.configKey;
    if (key === null) return null;
    const opened = await openChannel(key, sealed, CONFIG_AAD, this.configCounter);
    if (opened === null || opened.counter <= this.configCounter) return null;
    this.configCounter = opened.counter;
    return opened.message;
  }

  // The same for clipboard pictures.
  async openClipboardImage(sealed: string): Promise<ChannelMessage | null> {
    const key = this.imageKey;
    if (key === null) return null;
    const opened = await openChannel(key, sealed, CLIPBOARD_IMAGE_AAD, this.imageCounter);
    if (opened === null || opened.counter <= this.imageCounter) return null;
    this.imageCounter = opened.counter;
    return opened.message;
  }

  // The image channel's answers (progress, done, error, skipped): on the
  // reply key, so numbered with clipboard text and opened in the same order.
  async openClipboardImageReply(sealed: string): Promise<ChannelMessage | null> {
    const key = this.replyKey;
    if (key === null) return null;
    const opened = await openChannel(key, sealed, CLIPBOARD_IMAGE_REPLY_AAD, this.replyCounter);
    if (opened === null || opened.counter <= this.replyCounter) return null;
    this.replyCounter = opened.counter;
    return opened.message;
  }

  // op, header length, the JSON header, then bytes.
  private sealChannel(op: number, header: object, data: Uint8Array | undefined, aad: Uint8Array<ArrayBuffer>) {
    const json = utf8(JSON.stringify(header));
    if (json.length > 0xffff) return null;
    const preamble = new Uint8Array([op, json.length >> 8, json.length & 0xff]);
    return this.sealRequest(concat(preamble, json, data ?? new Uint8Array(0)), aad);
  }

  private sealRequest(plain: Uint8Array<ArrayBuffer>, aad: Uint8Array<ArrayBuffer>): Promise<string> | null {
    const key = this.inputKey;
    if (key === null) return null;
    this.inputCounter += 1n;
    const counter = new Uint8Array(8);
    new DataView(counter.buffer).setBigUint64(0, this.inputCounter);
    const iv = concat(counter, new Uint8Array(4));
    return aesEncrypt(key, iv, plain, aad).then((sealed) => toBase64(concat(counter, sealed)));
  }
}
