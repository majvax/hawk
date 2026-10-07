import { type RefObject, useCallback, useEffect, useRef, useState } from "react";

import {
  type DashboardCommand,
  type DashboardEvent,
  type DeviceSnapshot,
  parseVideoFrame,
} from "./protocol.js";

export type ConnectionStatus = "connecting" | "open" | "closed";

// Main profile, level 4.2: what the host's hardware encoder actually emits
// (profile_idc 77, level_idc 42 in its SPS). The stream is Annex-B with the
// SPS/PPS inline on keyframes, so no description is needed out of band.
const DECODER_CODEC = "avc1.4D402A";

export interface Dashboard {
  devices: DeviceSnapshot[];
  status: ConnectionStatus;
  viewingId: string | null;
  // Attach to the <canvas> that frames are drawn into.
  canvasRef: RefObject<HTMLCanvasElement>;
  startView: (deviceId: string) => void;
  stopView: () => void;
}

export function useDashboard(): Dashboard {
  const [devices, setDevices] = useState<DeviceSnapshot[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>("connecting");
  const [viewingId, setViewingId] = useState<string | null>(null);

  const socketRef = useRef<WebSocket | null>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const decoderRef = useRef<VideoDecoder | null>(null);
  const sawKeyframeRef = useRef(false);
  // Read inside the socket's message handler, which is created once.
  const viewingRef = useRef<string | null>(null);

  const send = useCallback((command: DashboardCommand): void => {
    const socket = socketRef.current;
    if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify(command));
  }, []);

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

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${window.location.host}/v1/dashboard`);
    socket.binaryType = "arraybuffer";
    socketRef.current = socket;

    socket.addEventListener("open", () => setStatus("open"));
    socket.addEventListener("close", () => setStatus("closed"));

    socket.addEventListener("message", (event: MessageEvent) => {
      if (event.data instanceof ArrayBuffer) {
        handleFrame(event.data);
        return;
      }

      const payload = JSON.parse(event.data as string) as DashboardEvent;
      switch (payload.type) {
        case "snapshot":
          setDevices(payload.devices);
          break;
        case "device_connected":
          setDevices((prev) => [...prev, payload.device]);
          break;
        case "device_disconnected":
          setDevices((prev) => prev.filter((device) => device.id !== payload.id));
          if (viewingRef.current === payload.id) {
            viewingRef.current = null;
            setViewingId(null);
            teardownDecoder();
          }
          break;
        case "capture_ended":
          if (viewingRef.current === payload.deviceId) {
            viewingRef.current = null;
            setViewingId(null);
            teardownDecoder();
          }
          break;
      }
    });

    return () => {
      teardownDecoder();
      socket.close();
    };
  }, [handleFrame, teardownDecoder]);

  const startView = useCallback(
    (deviceId: string): void => {
      if (viewingRef.current === deviceId) return;
      if (viewingRef.current !== null) send({ type: "stop_view", deviceId: viewingRef.current });
      teardownDecoder();

      viewingRef.current = deviceId;
      setViewingId(deviceId);
      send({ type: "start_view", deviceId });
    },
    [send, teardownDecoder],
  );

  const stopView = useCallback((): void => {
    const current = viewingRef.current;
    if (current === null) return;
    send({ type: "stop_view", deviceId: current });
    viewingRef.current = null;
    setViewingId(null);
    teardownDecoder();
  }, [send, teardownDecoder]);

  return { devices, status, viewingId, canvasRef, startView, stopView };
}
