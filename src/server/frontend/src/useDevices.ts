import { useEffect, useRef, useState } from "react";

import type { DashboardEvent, DeviceSnapshot } from "./protocol.js";

export type ConnectionStatus = "connecting" | "open" | "closed";

export function useDevices(): { devices: DeviceSnapshot[]; status: ConnectionStatus } {
  const [devices, setDevices] = useState<DeviceSnapshot[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>("connecting");
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${window.location.host}/v1/dashboard`);
    socketRef.current = socket;

    socket.addEventListener("open", () => setStatus("open"));
    socket.addEventListener("close", () => setStatus("closed"));

    socket.addEventListener("message", (event: MessageEvent<string>) => {
      const payload = JSON.parse(event.data) as DashboardEvent;
      switch (payload.type) {
        case "snapshot":
          setDevices(payload.devices);
          break;
        case "device_connected":
          setDevices((prev) => [...prev, payload.device]);
          break;
        case "device_disconnected":
          setDevices((prev) => prev.filter((device) => device.id !== payload.id));
          break;
      }
    });

    return () => socket.close();
  }, []);

  return { devices, status };
}
