import { type RefObject, useCallback, useEffect, useRef, useState } from "react";

import { getSession } from "./api.js";
import { MseDecoder, mseSupported } from "./mseDecoder.js";
import {
  type DashboardCommand,
  type DashboardEvent,
  type InputEvent,
  type Machine,
  type ParsedVideoFrame,
  parseVideoFrame,
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

function sortByName(machines: Machine[]): Machine[] {
  return [...machines].sort((a, b) => a.name.localeCompare(b.name));
}

// A frame gap this long means the stream has stalled: the host encodes on a
// fixed clock, so an idle screen still sends frames.
const STALL_MS = 3000;

// ?debug in the URL adds the decoder's readout to the stream stats.
const DEBUG = new URLSearchParams(window.location.search).has("debug");

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
  startView: (deviceId: string) => void;
  stopView: () => void;
  // Sends one input event to the machine being watched. The relay drops it
  // unless this user may control that machine, so a view-only viewer can
  // call this all it likes and nothing happens.
  sendInput: (event: InputEvent) => void;
  // Skip the rest of the backoff and try now.
  reconnectNow: () => void;
}

// Keeps a socket to the relay open for as long as the session lasts. When
// the link drops (relay restart, network loss) it reconnects with a growing
// delay, checking first that the session is still valid; `onSessionEnded`
// runs once it isn't (logged out elsewhere, account disabled).
export function useDashboard(onSessionEnded: () => void): Dashboard {
  const onSessionEndedRef = useRef(onSessionEnded);
  onSessionEndedRef.current = onSessionEnded;

  const [machines, setMachines] = useState<Machine[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>("connecting");
  const [retryAt, setRetryAt] = useState<number | null>(null);
  const [viewingId, setViewingId] = useState<string | null>(null);
  const [picture, setPicture] = useState<Dashboard["picture"]>(null);
  const [stats, setStats] = useState<StreamStats | null>(null);
  const [decodeError, setDecodeError] = useState<string | null>(null);

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

  const requestStream = useCallback(
    (deviceId: string): void => {
      if (send({ type: "start_view", deviceId })) streamingRef.current = deviceId;
    },
    [send],
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

  const handleFrame = useCallback(
    (buffer: ArrayBuffer): void => {
      const frame = parseVideoFrame(buffer);
      if (frame === null) return;
      bytesRef.current += buffer.byteLength;
      receivedRef.current += 1;

      // Decoding can only begin on a keyframe; drop deltas until the first
      // one arrives (e.g. when attaching mid-stream).
      if (!sawKeyframeRef.current && !frame.isKeyframe) return;
      sawKeyframeRef.current = true;

      ensureDecoder()?.decode(frame);
    },
    [ensureDecoder],
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

  // The open view is gone for good: stopped, or the machine was taken away.
  const clearView = useCallback((): void => {
    resetDecodeError();
    viewingRef.current = null;
    streamingRef.current = null;
    setViewingId(null);
    teardownDecoder();
    clearPicture();
  }, [clearPicture, resetDecodeError, teardownDecoder]);

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
          else if (machine.online) requestStream(viewing);
          // Offline: wait for it to come back (machine_updated below).
          break;
        }
        case "machine_updated":
          setMachines((prev) =>
            sortByName([...prev.filter((machine) => machine.id !== payload.machine.id), payload.machine]),
          );
          if (viewing === payload.machine.id && payload.machine.online && streamingRef.current === null) {
            requestStream(viewing);
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
            teardownDecoder();
          }
          break;
      }
    },
    [clearView, requestStream, teardownDecoder],
  );

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
      setViewingId(deviceId);
      requestStream(deviceId); // while disconnected, the snapshot resumes it
    },
    [clearPicture, requestStream, resetDecodeError, send, teardownDecoder],
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
      // Only while frames are actually flowing: input to a machine this
      // socket isn't watching goes nowhere.
      const deviceId = streamingRef.current;
      if (deviceId === null) return;
      send({ type: "input", deviceId, event });
    },
    [send],
  );

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
    startView,
    stopView,
    sendInput,
    reconnectNow,
  };
}
