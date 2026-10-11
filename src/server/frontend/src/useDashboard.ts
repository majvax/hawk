import { type RefObject, useCallback, useEffect, useRef, useState } from "react";

import { getSession } from "./api.js";
import { type EnrollmentCheck, type MachineTrust, ViewSession, checkEnrollment, trustMachine } from "./e2e.js";
import {
  FileManager,
  type FileSender,
  type Listing,
  type RemoteFile,
  type Sink,
  type Transfer,
} from "./fileTransfers.js";
import type { Identity } from "./keys.js";
import { MseDecoder, mseSupported } from "./mseDecoder.js";
import type {
  ClipboardAccess,
  DashboardCommand,
  DashboardEvent,
  InputEvent,
  Machine,
  ParsedVideoFrame,
  Role,
} from "./protocol.js";

// "reconnecting": the link dropped and the next attempt is scheduled;
// "closed": the session is over, nothing more will be tried.
export type ConnectionStatus = "connecting" | "open" | "reconnecting" | "closed";

// Reconnect backoff: 1s, 2s, 4s, ... capped at 30s, each with ±25% jitter
// so dashboards don't all hit a restarted relay in the same instant.
const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30_000;

function reconnectDelay(attempt: number): number {
  const delay = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * 2 ** attempt);
  return delay * (0.75 + Math.random() * 0.5);
}

// Main profile, level 4.2: what the host's hardware encoder actually emits
// (profile_idc 77, level_idc 42 in its SPS). The stream is Annex-B with the
// SPS/PPS inline on keyframes, so no description is needed out of band.
const DECODER_CODEC = "avc1.4D402A";

// How frames get decoded: WebCodecs where the browser has an H.264 decoder
// (Chromium), MSE through a hidden <video> otherwise (Firefox for Android).
type Backend = "webcodecs" | "mse" | "none";

async function detectBackend(): Promise<Backend> {
  if (typeof VideoDecoder !== "undefined") {
    try {
      const { supported } = await VideoDecoder.isConfigSupported({ codec: DECODER_CODEC, optimizeForLatency: true });
      if (supported) return "webcodecs";
    } catch {
      // Treated as unsupported.
    }
  }
  return mseSupported(DECODER_CODEC) ? "mse" : "none";
}

const UNSUPPORTED_MESSAGE = "This browser can't play H.264 video. Try an up-to-date Chrome or Firefox.";

// Decode errors in a row, with no picture in between, before giving up on
// a backend.
const MAX_DECODE_FAILURES = 3;

// What either backend looks like to the dashboard.
interface StreamDecoder {
  decode(frame: ParsedVideoFrame): void;
  close(): void;
  // Frames shown and dropped so far, where the browser counts them itself.
  playbackQuality?(): { shown: number; dropped: number } | null;
  debugInfo?(): string;
}

// What the machine's answer to a join depends on. A view that was refused
// or couldn't be trusted is only asked for again on its own once one of
// these changes, so a refusal (which itself updates the machine) can't
// turn into a loop of joins.
function admissionKey(machine: Machine): string {
  return [machine.publicKey, machine.ownerPublicKey, machine.endorsement, machine.role, machine.granted, machine.accessExpiresAt].join("|");
}

function sortByName(machines: Machine[]): Machine[] {
  return [...machines].sort((a, b) => a.name.localeCompare(b.name));
}

// A frame gap this long means the stream has stalled: the host encodes on a
// fixed clock, so an idle screen still sends frames.
const STALL_MS = 3000;

// Frames waiting to be decrypted before new deltas are dropped (until the
// next keyframe): a device too slow to keep up shouldn't build a backlog.
const MAX_PENDING_FRAMES = 30;

// Where the end-to-end handshake for the open view stands.
export type ViewSecurity =
  | { kind: "securing" } // join sent, waiting for the machine's answer
  | { kind: "secured"; role: Role } // the machine answered and its signature checked out
  | { kind: "rejected"; reason: string } // the machine refused this viewer
  | { kind: "untrusted"; reason: Exclude<MachineTrust, { ok: true }>["reason"] }
  | { kind: "failed"; message: string }; // the answer didn't check out

// ?debug in the URL adds the decoder's readout to the stream stats.
const DEBUG = new URLSearchParams(window.location.search).has("debug");

// The open view's clipboard: what the machine lets this viewer do with it,
// and the latest text it sent.
export interface ClipboardState {
  access: ClipboardAccess;
  // Set while a read is on its way.
  waiting: boolean;
  // The latest text from the machine: the answer to a read, or a copy made
  // there (sync mode). `id` changes with every new one.
  latest: { id: number; text: string; pushed: boolean } | null;
}

const NO_CLIPBOARD: ClipboardState = { access: "off", waiting: false, latest: null };

// A read the machine hasn't answered by then (hawk-capture still starting,
// or the request was dropped) stops showing as underway.
const CLIPBOARD_WAIT_MS = 5000;

// The open view's file transfers.
export interface FilesState {
  // Whether the machine lets this viewer send and fetch files.
  enabled: boolean;
  listing: Listing | null;
  listingError: string | null;
  transfers: Transfer[];
}

const NO_FILES: FilesState = { enabled: false, listing: null, listingError: null, transfers: [] };

export interface FileActions {
  list: () => void;
  upload: (files: File[]) => void;
  download: (file: RemoteFile, sink: Sink) => void;
  cancel: (id: string) => void;
  retry: (id: string) => void;
  dismiss: (id: string) => void;
}

export interface StreamStats {
  fps: number; // frames shown over the last second
  received: number; // frames that arrived over the last second
  dropped: number; // decoded but not shown over the last second (MSE only)
  debug: string | null; // the decoder's own readout, with ?debug in the URL
  kbps: number; // video received over the last second
  receiving: boolean; // frames are arriving
}

export interface Dashboard {
  machines: Machine[];
  status: ConnectionStatus;
  // While reconnecting: when the next attempt is due (ms since epoch).
  retryAt: number | null;
  // The machine whose view is open. It stays set while the link or the
  // machine is down, and the stream resumes once both are back.
  viewingId: string | null;
  // Attach to the <canvas> that frames are drawn into.
  canvasRef: RefObject<HTMLCanvasElement>;
  // The size of the picture on the canvas; null until the open view's
  // first frame is drawn.
  picture: { width: number; height: number } | null;
  // Measured once a second while a view is open.
  stats: StreamStats | null;
  // Set when this browser can't decode the stream, or the decoder keeps
  // failing; the view shows it instead of waiting for a picture.
  decodeError: string | null;
  // The open view's end-to-end handshake; null with no view open.
  security: ViewSecurity | null;
  clipboard: ClipboardState;
  files: FilesState;
  fileActions: FileActions;
  // Owned machines whose enrollment this browser checked: "mismatch" means
  // the key the machine answered with isn't bound to the code made here.
  enrollmentChecks: Record<string, EnrollmentCheck>;
  startView: (deviceId: string) => void;
  stopView: () => void;
  // Sends one input event to the machine being watched. The relay drops it
  // unless this user may control that machine, so a view-only viewer can
  // call this all it likes and nothing happens.
  sendInput: (event: InputEvent) => void;
  // Pastes text into the machine's clipboard (control only), or with null
  // asks for what's on it; the answer lands in `clipboard.latest`. Returns
  // false when there's no secured view to send it to.
  sendClipboard: (text: string | null) => boolean;
  // Skip the rest of the backoff and try now.
  reconnectNow: () => void;
}

// Keeps a socket to the relay open for as long as the session lasts. When
// the link drops (relay restart, network loss) it reconnects with a growing
// delay, checking first that the session is still valid; `onSessionEnded`
// runs once it isn't (logged out elsewhere, account disabled).
export function useDashboard(identity: Identity, onSessionEnded: () => void): Dashboard {
  const onSessionEndedRef = useRef(onSessionEnded);
  onSessionEndedRef.current = onSessionEnded;

  const [machines, setMachines] = useState<Machine[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>("connecting");
  const [retryAt, setRetryAt] = useState<number | null>(null);
  const [viewingId, setViewingId] = useState<string | null>(null);
  const [picture, setPicture] = useState<Dashboard["picture"]>(null);
  const [stats, setStats] = useState<StreamStats | null>(null);
  const [decodeError, setDecodeError] = useState<string | null>(null);
  const [security, setSecurity] = useState<ViewSecurity | null>(null);
  const [clipboard, setClipboard] = useState<ClipboardState>(NO_CLIPBOARD);
  // Numbers what the machine sends, so the same text twice still counts
  // as new.
  const clipboardIdRef = useRef(0);
  const [files, setFiles] = useState<FilesState>(NO_FILES);
  const filesEnabledRef = useRef(false);
  // The open view's transfers, kept across a dropped connection so they can
  // resume; replaced when the view moves to another machine.
  const fileManagerRef = useRef<FileManager | null>(null);
  // File messages are opened one at a time, in the order they arrived.
  const fileChainRef = useRef<Promise<void>>(Promise.resolve());
  const fileFrameRef = useRef<number | null>(null);
  // Progress arrives per chunk; the panel is redrawn at most once a frame.
  const publishFiles = useRef((): void => {
    if (fileFrameRef.current !== null) return;
    fileFrameRef.current = window.requestAnimationFrame(() => {
      fileFrameRef.current = null;
      const manager = fileManagerRef.current;
      setFiles(
        manager === null
          ? NO_FILES
          : {
              enabled: filesEnabledRef.current,
              listing: manager.listing,
              listingError: manager.listingError,
              transfers: manager.snapshot(),
            },
      );
    });
  }).current;
  const [enrollmentChecks, setEnrollmentChecks] = useState<Record<string, EnrollmentCheck>>({});

  const socketRef = useRef<WebSocket | null>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const decoderRef = useRef<StreamDecoder | null>(null);
  // null until detectBackend() settles; frames before that are dropped.
  const backendRef = useRef<Backend | null>(null);
  const failuresRef = useRef(0);
  const sawKeyframeRef = useRef(false);
  // Read inside the socket's handlers, which are created once per socket.
  const viewingRef = useRef<string | null>(null);
  // The machine start_view was sent for on the current socket; null after a
  // reconnect until the view is resumed.
  const streamingRef = useRef<string | null>(null);
  const reconnectNowRef = useRef<() => void>(() => {});
  // The open view's end-to-end session; null until a join has been sent.
  const sessionRef = useRef<ViewSession | null>(null);
  // Decryption is asynchronous, but frames must reach the decoder in order,
  // and input must reach the machine in the order it was sealed.
  const frameChainRef = useRef<Promise<void>>(Promise.resolve());
  const pendingFramesRef = useRef(0);
  const inputChainRef = useRef<Promise<void>>(Promise.resolve());
  // Machines are read from socket handlers, which are created once.
  const machinesRef = useRef<Machine[]>([]);
  machinesRef.current = machines;
  const checkedEnrollmentsRef = useRef(new Set<string>());
  // Set when the open view was refused or untrusted: the admissionKey it
  // was refused under.
  const blockedRef = useRef<string | null>(null);
  // Ends the open session, so frames waiting on its answer stop waiting.
  const dropSession = useRef((): void => {
    sessionRef.current?.abandon();
    sessionRef.current = null;
    setClipboard(NO_CLIPBOARD);
    // Transfers wait for the view to come back rather than fail.
    fileManagerRef.current?.attach(null);
  }).current;
  // Counted per frame, read and reset by the once-a-second stats sample.
  const framesRef = useRef(0);
  const bytesRef = useRef(0);
  const receivedRef = useRef(0);
  const lastFrameAtRef = useRef(0);

  const send = useCallback((command: DashboardCommand): boolean => {
    const socket = socketRef.current;
    if (socket?.readyState !== WebSocket.OPEN) return false;
    socket.send(JSON.stringify(command));
    return true;
  }, []);

  // Opens an end-to-end session with the machine: checks its key is the one
  // its owner vouched for, then sends a signed join for it to answer.
  // streamingRef is set at once, so the stream isn't asked for twice while
  // the join is being signed.
  const requestStream = useCallback(
    (deviceId: string, machine?: Machine): void => {
      const target = machine ?? machinesRef.current.find((candidate) => candidate.id === deviceId);
      if (target === undefined || socketRef.current?.readyState !== WebSocket.OPEN) return;
      if (blockedRef.current !== null && blockedRef.current === admissionKey(target)) return;
      blockedRef.current = null;
      streamingRef.current = deviceId;
      dropSession();
      setSecurity({ kind: "securing" });
      void (async () => {
        const trust = await trustMachine(identity, target);
        if (viewingRef.current !== deviceId || streamingRef.current !== deviceId) return;
        if (!trust.ok) {
          streamingRef.current = null;
          blockedRef.current = admissionKey(target);
          setSecurity({ kind: "untrusted", reason: trust.reason });
          return;
        }
        const session = await ViewSession.start(identity, deviceId, trust.machineKey);
        if (viewingRef.current !== deviceId || streamingRef.current !== deviceId) return;
        sessionRef.current = session;
        if (!send({ type: "start_view", deviceId, join: session.join })) streamingRef.current = null;
      })().catch((error: unknown) => {
        if (streamingRef.current === deviceId) streamingRef.current = null;
        setSecurity({ kind: "failed", message: error instanceof Error ? error.message : String(error) });
      });
    },
    [identity, send],
  );

  const teardownDecoder = useCallback((): void => {
    sawKeyframeRef.current = false;
    const decoder = decoderRef.current;
    decoderRef.current = null;
    decoder?.close();
  }, []);

  // Sizes the canvas to the picture, lets `draw` paint it, and counts it.
  const paint = useCallback(
    (width: number, height: number, draw: (context: CanvasRenderingContext2D) => void): void => {
      const canvas = canvasRef.current;
      if (canvas === null || width === 0 || height === 0) return;
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
        setPicture({ width, height });
      }
      const context = canvas.getContext("2d");
      if (context !== null) draw(context);
      failuresRef.current = 0;
      framesRef.current += 1;
      lastFrameAtRef.current = performance.now();
    },
    [],
  );

  const drawFrame = useCallback(
    (frame: VideoFrame): void => {
      paint(frame.displayWidth, frame.displayHeight, (context) => context.drawImage(frame, 0, 0));
      frame.close();
    },
    [paint],
  );

  // The <video> shows the picture itself, under the canvas; the canvas is
  // only sized to it, left transparent, and takes the input.
  const sizeToVideo = useCallback(
    (video: HTMLVideoElement): void => {
      paint(video.videoWidth, video.videoHeight, () => {});
    },
    [paint],
  );

  // Blanks the canvas, so one machine's screen never shows under another's
  // name. The next frame drawn sizes it again.
  const clearPicture = useCallback((): void => {
    const canvas = canvasRef.current;
    if (canvas !== null) {
      canvas.width = 0;
      canvas.height = 0;
    }
    setPicture(null);
  }, []);

  // A decoder failed: drop it, and the next keyframe starts a new one. If
  // that keeps happening, move from WebCodecs to MSE, or give up and say so.
  const onDecodeError = useCallback(
    (failed: StreamDecoder, message: string): void => {
      console.error("video decode error:", message);
      if (decoderRef.current !== failed) return; // already replaced
      teardownDecoder();
      failuresRef.current += 1;
      if (failuresRef.current < MAX_DECODE_FAILURES) return;
      failuresRef.current = 0;
      if (backendRef.current === "webcodecs" && mseSupported(DECODER_CODEC)) {
        backendRef.current = "mse";
      } else {
        setDecodeError(`The video decoder keeps failing (${message}).`);
      }
    },
    [teardownDecoder],
  );

  const ensureDecoder = useCallback((): StreamDecoder | null => {
    if (decoderRef.current !== null) return decoderRef.current;
    let decoder: StreamDecoder;
    switch (backendRef.current) {
      case "webcodecs": {
        const videoDecoder = new VideoDecoder({
          output: drawFrame,
          error: (error) => onDecodeError(decoder, error.message),
        });
        videoDecoder.configure({ codec: DECODER_CODEC, optimizeForLatency: true });
        decoder = {
          decode: (frame) => {
            if (videoDecoder.state !== "configured") return;
            videoDecoder.decode(
              new EncodedVideoChunk({
                type: frame.isKeyframe ? "key" : "delta",
                timestamp: frame.timestamp,
                data: frame.data,
              }),
            );
          },
          close: () => {
            if (videoDecoder.state !== "closed") videoDecoder.close();
          },
        };
        break;
      }
      case "mse": {
        const canvas = canvasRef.current;
        if (canvas === null) return null;
        const mse: StreamDecoder = new MseDecoder(canvas, sizeToVideo, (message) => onDecodeError(mse, message));
        decoder = mse;
        break;
      }
      default:
        return null;
    }
    decoderRef.current = decoder;
    return decoder;
  }, [drawFrame, sizeToVideo, onDecodeError]);

  const decodeFrame = useCallback(
    (frame: ParsedVideoFrame): void => {
      // Decoding can only begin on a keyframe; drop deltas until the first
      // one arrives (e.g. when attaching mid-stream).
      if (!sawKeyframeRef.current && !frame.isKeyframe) return;
      sawKeyframeRef.current = true;
      ensureDecoder()?.decode(frame);
    },
    [ensureDecoder],
  );

  // Decrypts with the open session, in arrival order. Frames from before
  // the session was accepted, or under a key it doesn't have, are dropped.
  const handleFrame = useCallback(
    (buffer: ArrayBuffer): void => {
      // Frames that come before the machine's answer is checked wait for
      // it in the chain below; without a session there's nothing to wait for.
      const session = sessionRef.current;
      if (session === null) return;
      bytesRef.current += buffer.byteLength;
      receivedRef.current += 1;
      const keyframe = buffer.byteLength > 1 && (new Uint8Array(buffer, 1, 1)[0] ?? 0) & 0x01;
      if (pendingFramesRef.current >= MAX_PENDING_FRAMES && !keyframe) {
        sawKeyframeRef.current = false; // a gap: start again at a keyframe
        return;
      }
      pendingFramesRef.current += 1;
      frameChainRef.current = frameChainRef.current
        .then(async () => {
          const frame = await session.openFrame(buffer);
          if (frame !== null && sessionRef.current === session) decodeFrame(frame);
          else if (frame === null) sawKeyframeRef.current = false;
        })
        .catch((error: unknown) => console.error("frame:", error))
        .finally(() => {
          pendingFramesRef.current -= 1;
        });
    },
    [decodeFrame],
  );

  // A new view starts with a clean slate, unless the browser can't decode
  // at all.
  const resetDecodeError = useCallback((): void => {
    failuresRef.current = 0;
    setDecodeError(backendRef.current === "none" ? UNSUPPORTED_MESSAGE : null);
  }, []);

  useEffect(() => {
    let disposed = false;
    void detectBackend().then((backend) => {
      if (disposed) return;
      backendRef.current = backend;
      if (backend === "none") setDecodeError(UNSUPPORTED_MESSAGE);
    });
    return () => {
      disposed = true;
    };
  }, []);

  // A fresh set of transfers for the machine now being viewed (null: none).
  const resetFiles = useCallback(
    (deviceId: string | null): void => {
      fileManagerRef.current?.close();
      fileManagerRef.current = deviceId === null ? null : new FileManager(publishFiles);
      filesEnabledRef.current = false;
      publishFiles();
    },
    [publishFiles],
  );

  // Seals file-channel messages for `session` and sends them in order with
  // input (they share its counter).
  const fileSender = useCallback(
    (session: ViewSession, deviceId: string): FileSender =>
      (op, header, data) => {
        if (sessionRef.current !== session) return false;
        const sealed = session.sealFile(op, header, data);
        if (sealed === null) return false;
        inputChainRef.current = inputChainRef.current
          .then(() => sealed)
          .then((payload) => {
            if (sessionRef.current === session) send({ type: "file", deviceId, sealed: payload });
          })
          .catch((error: unknown) => console.error("sealing file message:", error));
        return true;
      },
    [send],
  );

  // The open view is gone for good: stopped, or the machine was taken away.
  const clearView = useCallback((): void => {
    resetDecodeError();
    setSecurity(null);
    viewingRef.current = null;
    streamingRef.current = null;
    dropSession();
    setViewingId(null);
    teardownDecoder();
    clearPicture();
    resetFiles(null);
  }, [clearPicture, resetDecodeError, resetFiles, teardownDecoder]);

  const handleEvent = useCallback(
    (payload: DashboardEvent): void => {
      const viewing = viewingRef.current;
      switch (payload.type) {
        case "snapshot": {
          setMachines(sortByName(payload.machines));
          // Fresh socket: resume the view that was open, if it's still ours.
          if (viewing === null) break;
          const machine = payload.machines.find((candidate) => candidate.id === viewing);
          if (machine === undefined) clearView();
          else if (machine.online) requestStream(viewing, machine);
          // Offline: wait for it to come back (machine_updated below).
          break;
        }
        case "machine_updated":
          setMachines((prev) =>
            sortByName([...prev.filter((machine) => machine.id !== payload.machine.id), payload.machine]),
          );
          if (viewing === payload.machine.id && payload.machine.online && streamingRef.current === null) {
            requestStream(viewing, payload.machine);
          }
          break;
        case "machine_removed":
          setMachines((prev) => prev.filter((machine) => machine.id !== payload.id));
          if (viewing === payload.id) clearView();
          break;
        case "capture_ended":
          // The machine dropped off. Keep the view open and pick the stream
          // back up when it reconnects; the decoder restarts on a keyframe.
          if (viewing === payload.deviceId) {
            streamingRef.current = null;
            dropSession();
            teardownDecoder();
          }
          break;
        case "view_accepted": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          session.accept(payload).then(
            () => {
              if (sessionRef.current === session && session.role !== null) {
                setSecurity({ kind: "secured", role: session.role });
                // A relay from before the clipboard says nothing: none, then.
                setClipboard({ access: payload.clipboard ?? "off", waiting: false, latest: null });
                filesEnabledRef.current = payload.files === true;
                const manager = fileManagerRef.current;
                if (manager !== null) {
                  manager.attach(payload.files === true ? fileSender(session, payload.deviceId) : null);
                  if (payload.files === true) manager.list();
                }
              }
            },
            (error: unknown) => {
              if (sessionRef.current !== session) return;
              // Nothing from this machine can be trusted: stop asking.
              send({ type: "stop_view", deviceId: payload.deviceId });
              const machine = machinesRef.current.find((candidate) => candidate.id === payload.deviceId);
              blockedRef.current = machine === undefined ? "" : admissionKey(machine);
              streamingRef.current = null;
              dropSession();
              teardownDecoder();
              setSecurity({ kind: "failed", message: error instanceof Error ? error.message : String(error) });
            },
          );
          break;
        }
        case "stream_key": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          // Ahead of the frames under it: the relay sends events first.
          frameChainRef.current = frameChainRef.current
            .then(() => session.addStreamKey(payload.wrappedKey))
            .catch((error: unknown) => console.error("stream key:", error));
          break;
        }
        case "clipboard": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          void session.openClipboard(payload.sealed).then((opened) => {
            if (opened === null || sessionRef.current !== session) return;
            clipboardIdRef.current += 1;
            const latest = { id: clipboardIdRef.current, ...opened };
            setClipboard((prev) => ({ ...prev, waiting: false, latest }));
          });
          break;
        }
        case "file": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          fileChainRef.current = fileChainRef.current
            .then(() => session.openFile(payload.sealed))
            .then((opened) => {
              if (opened === null || sessionRef.current !== session) return;
              fileManagerRef.current?.handle(opened.op, opened.header, opened.data);
            })
            .catch((error: unknown) => console.error("file message:", error));
          break;
        }
        case "view_rejected":
          if (viewing === payload.deviceId) {
            const machine = machinesRef.current.find((candidate) => candidate.id === payload.deviceId);
            blockedRef.current = machine === undefined ? "" : admissionKey(machine);
            streamingRef.current = null;
            dropSession();
            teardownDecoder();
            setSecurity({ kind: "rejected", reason: payload.reason });
          }
          break;
      }
    },
    [clearView, fileSender, requestStream, send, teardownDecoder],
  );

  // Owned machines not vouched for yet: if this browser made the code a
  // machine enrolled with, check its key against the code and endorse it.
  useEffect(() => {
    for (const machine of machines) {
      if (machine.role !== "owner" || machine.endorsement !== null || machine.enrollCodeHash === null) continue;
      if (checkedEnrollmentsRef.current.has(machine.id)) continue;
      checkedEnrollmentsRef.current.add(machine.id);
      checkEnrollment(identity, machine).then(
        (result) => setEnrollmentChecks((prev) => ({ ...prev, [machine.id]: result })),
        (error: unknown) => {
          console.error("checking enrollment:", error);
          checkedEnrollmentsRef.current.delete(machine.id);
        },
      );
    }
  }, [identity, machines]);

  useEffect(() => {
    let disposed = false;
    let attempt = 0;
    let timer: number | undefined;

    const connect = (): void => {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const socket = new WebSocket(`${protocol}//${window.location.host}/v1/dashboard`);
      socket.binaryType = "arraybuffer";
      socketRef.current = socket;
      setStatus("connecting");
      setRetryAt(null);

      socket.addEventListener("open", () => setStatus("open"));
      socket.addEventListener("close", () => {
        if (socketRef.current === socket) socketRef.current = null;
        if (disposed) return; // our own teardown
        streamingRef.current = null;
        dropSession();
        teardownDecoder();
        scheduleReconnect();
      });
      socket.addEventListener("message", (event: MessageEvent) => {
        if (event.data instanceof ArrayBuffer) {
          handleFrame(event.data);
          return;
        }
        const payload = JSON.parse(event.data as string) as DashboardEvent;
        // A snapshot means the relay accepted us; start the backoff over.
        if (payload.type === "snapshot") attempt = 0;
        handleEvent(payload);
      });
    };

    const scheduleReconnect = (): void => {
      const delay = reconnectDelay(attempt);
      attempt += 1;
      setStatus("reconnecting");
      setRetryAt(Date.now() + delay);
      timer = window.setTimeout(() => void reconnect(), delay);
    };

    // Checks the session before opening a socket: a dead session ends the
    // dashboard, an unreachable relay just means trying again later.
    const reconnect = async (): Promise<void> => {
      timer = undefined;
      setStatus("connecting");
      setRetryAt(null);
      let session;
      try {
        session = await getSession();
      } catch {
        if (!disposed) scheduleReconnect();
        return;
      }
      if (disposed) return;
      if (session === null) {
        setStatus("closed");
        onSessionEndedRef.current();
        return;
      }
      connect();
    };

    reconnectNowRef.current = () => {
      if (timer === undefined) return; // connected, or an attempt is underway
      window.clearTimeout(timer);
      void reconnect();
    };
    const onOnline = (): void => reconnectNowRef.current();
    window.addEventListener("online", onOnline);

    // The caller has just confirmed the session, so the first socket opens
    // straight away.
    connect();

    return () => {
      disposed = true;
      window.clearTimeout(timer);
      window.removeEventListener("online", onOnline);
      reconnectNowRef.current = () => {};
      teardownDecoder();
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [handleEvent, handleFrame, teardownDecoder]);

  const startView = useCallback(
    (deviceId: string): void => {
      if (viewingRef.current === deviceId) return;
      if (streamingRef.current !== null) send({ type: "stop_view", deviceId: streamingRef.current });
      streamingRef.current = null;
      teardownDecoder();
      clearPicture();
      resetDecodeError();

      viewingRef.current = deviceId;
      resetFiles(deviceId);
      blockedRef.current = null; // asked for by hand: try again
      setViewingId(deviceId);
      requestStream(deviceId); // while disconnected, the snapshot resumes it
    },
    [clearPicture, requestStream, resetDecodeError, resetFiles, send, teardownDecoder],
  );

  useEffect(() => {
    if (viewingId === null) {
      setStats(null);
      return;
    }
    framesRef.current = 0;
    bytesRef.current = 0;
    receivedRef.current = 0;
    lastFrameAtRef.current = 0;
    let last = performance.now();
    // Per decoder, since a new one starts counting from zero.
    let lastDecoder: StreamDecoder | null = null;
    let lastQuality = { shown: 0, dropped: 0 };
    const timer = window.setInterval(() => {
      const now = performance.now();
      const seconds = Math.max(0.001, (now - last) / 1000);
      last = now;
      // The browser's own counts where it keeps them (MSE), else the
      // frames drawn here (WebCodecs).
      const decoder = decoderRef.current;
      const quality = decoder?.playbackQuality?.() ?? null;
      let shown = framesRef.current;
      let dropped = 0;
      if (quality !== null) {
        if (decoder === lastDecoder) {
          shown = Math.max(0, quality.shown - lastQuality.shown);
          dropped = Math.max(0, quality.dropped - lastQuality.dropped);
        }
        lastQuality = quality;
      }
      lastDecoder = decoder;
      setStats({
        fps: Math.round(shown / seconds),
        received: Math.round(receivedRef.current / seconds),
        dropped: Math.round(dropped / seconds),
        debug: DEBUG ? (decoder?.debugInfo?.() ?? null) : null,
        kbps: Math.round((bytesRef.current * 8) / 1000 / seconds),
        receiving: now - lastFrameAtRef.current < STALL_MS,
      });
      framesRef.current = 0;
      bytesRef.current = 0;
      receivedRef.current = 0;
    }, 1000);
    return () => window.clearInterval(timer);
  }, [viewingId]);

  const sendInput = useCallback(
    (event: InputEvent): void => {
      // Only once the machine has accepted this viewer with a role that
      // may control it: input to anything else goes nowhere.
      const deviceId = streamingRef.current;
      const session = sessionRef.current;
      if (deviceId === null || session === null || (session.role !== "owner" && session.role !== "control")) return;
      const sealed = session.sealInput(event);
      if (sealed === null) return;
      inputChainRef.current = inputChainRef.current
        .then(() => sealed)
        .then((payload) => {
          if (sessionRef.current === session) send({ type: "input", deviceId, sealed: payload });
        })
        .catch((error: unknown) => console.error("sealing input:", error));
    },
    [send],
  );

  const sendClipboard = useCallback(
    (text: string | null): boolean => {
      const deviceId = streamingRef.current;
      const session = sessionRef.current;
      if (deviceId === null || session === null || !session.accepted) return false;
      const sealed = session.sealClipboard(text);
      if (sealed === null) return false;
      if (text === null) {
        setClipboard((prev) => ({ ...prev, waiting: true }));
        window.setTimeout(() => {
          if (sessionRef.current === session) setClipboard((prev) => ({ ...prev, waiting: false }));
        }, CLIPBOARD_WAIT_MS);
      }
      // Through the input chain: both are numbered from one counter, so
      // they must reach the machine in the order they were sealed.
      inputChainRef.current = inputChainRef.current
        .then(() => sealed)
        .then((payload) => {
          if (sessionRef.current === session) send({ type: "clipboard", deviceId, sealed: payload });
        })
        .catch((error: unknown) => console.error("sealing clipboard:", error));
      return true;
    },
    [send],
  );

  const fileActions = useRef<FileActions>({
    list: () => fileManagerRef.current?.list(),
    upload: (picked) => {
      for (const file of picked) fileManagerRef.current?.upload(file);
    },
    download: (file, sink) => fileManagerRef.current?.download(file, sink),
    cancel: (id) => fileManagerRef.current?.cancel(id),
    retry: (id) => fileManagerRef.current?.retry(id),
    dismiss: (id) => fileManagerRef.current?.dismiss(id),
  }).current;

  const stopView = useCallback((): void => {
    if (viewingRef.current === null) return;
    if (streamingRef.current !== null) send({ type: "stop_view", deviceId: streamingRef.current });
    clearView();
  }, [clearView, send]);

  const reconnectNow = useCallback((): void => reconnectNowRef.current(), []);

  return {
    machines,
    status,
    retryAt,
    viewingId,
    canvasRef,
    picture,
    stats,
    decodeError,
    security,
    clipboard,
    files,
    fileActions,
    enrollmentChecks,
    startView,
    stopView,
    sendInput,
    sendClipboard,
    reconnectNow,
  };
}
