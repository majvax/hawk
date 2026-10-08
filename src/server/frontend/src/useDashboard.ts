import { type RefObject, useCallback, useEffect, useRef, useState } from "react";

import { getSession } from "./api.js";
import {
  type DashboardCommand,
  type DashboardEvent,
  type Machine,
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

function sortByName(machines: Machine[]): Machine[] {
  return [...machines].sort((a, b) => a.name.localeCompare(b.name));
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
  startView: (deviceId: string) => void;
  stopView: () => void;
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

  const socketRef = useRef<WebSocket | null>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const decoderRef = useRef<VideoDecoder | null>(null);
  const sawKeyframeRef = useRef(false);
  // Read inside the socket's handlers, which are created once per socket.
  const viewingRef = useRef<string | null>(null);
  // The machine start_view was sent for on the current socket; null after a
  // reconnect until the view is resumed.
  const streamingRef = useRef<string | null>(null);
  const reconnectNowRef = useRef<() => void>(() => {});

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
    if (decoder !== null && decoder.state !== "closed") decoder.close();
  }, []);

  const drawFrame = useCallback((frame: VideoFrame): void => {
    const canvas = canvasRef.current;
    if (canvas === null) {
      frame.close();
      return;
    }
    if (canvas.width !== frame.displayWidth || canvas.height !== frame.displayHeight) {
      canvas.width = frame.displayWidth;
      canvas.height = frame.displayHeight;
    }
    canvas.getContext("2d")?.drawImage(frame, 0, 0);
    frame.close();
  }, []);

  const ensureDecoder = useCallback((): VideoDecoder | null => {
    if (decoderRef.current !== null) return decoderRef.current;
    if (typeof VideoDecoder === "undefined") {
      console.error("WebCodecs VideoDecoder is unavailable in this browser.");
      return null;
    }
    const decoder = new VideoDecoder({
      output: drawFrame,
      error: (error) => console.error("video decode error:", error.message),
    });
    decoder.configure({ codec: DECODER_CODEC, optimizeForLatency: true });
    decoderRef.current = decoder;
    return decoder;
  }, [drawFrame]);

  const handleFrame = useCallback(
    (buffer: ArrayBuffer): void => {
      const frame = parseVideoFrame(buffer);
      if (frame === null) return;

      // Decoding can only begin on a keyframe; drop deltas until the first
      // one arrives (e.g. when attaching mid-stream).
      if (!sawKeyframeRef.current && !frame.isKeyframe) return;
      sawKeyframeRef.current = true;

      const decoder = ensureDecoder();
      if (decoder === null || decoder.state !== "configured") return;
      decoder.decode(
        new EncodedVideoChunk({
          type: frame.isKeyframe ? "key" : "delta",
          timestamp: frame.timestamp,
          data: frame.data,
        }),
      );
    },
    [ensureDecoder],
  );

  // The open view is gone for good: stopped, or the machine was taken away.
  const clearView = useCallback((): void => {
    viewingRef.current = null;
    streamingRef.current = null;
    setViewingId(null);
    teardownDecoder();
  }, [teardownDecoder]);

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

      viewingRef.current = deviceId;
      setViewingId(deviceId);
      requestStream(deviceId); // while disconnected, the snapshot resumes it
    },
    [requestStream, send, teardownDecoder],
  );

  const stopView = useCallback((): void => {
    if (viewingRef.current === null) return;
    if (streamingRef.current !== null) send({ type: "stop_view", deviceId: streamingRef.current });
    clearView();
  }, [clearView, send]);

  const reconnectNow = useCallback((): void => reconnectNowRef.current(), []);

  return { machines, status, retryAt, viewingId, canvasRef, startView, stopView, reconnectNow };
}
