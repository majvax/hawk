import { randomUUID } from "node:crypto";

import type { WebSocket } from "@fastify/websocket";

import type { DeviceCommand, DeviceSnapshot } from "./protocol.js";

interface Device {
  id: string;
  machineId: string;
  connectedAt: Date;
  socket: WebSocket;
  viewers: Set<WebSocket>; // dashboard sockets currently watching this device
}

export type RegistryEvent =
  | { kind: "connected"; device: DeviceSnapshot }
  | { kind: "disconnected"; id: string };

type Listener = (event: RegistryEvent) => void;

export type StartViewResult = "ok" | "unknown_device";

// Tracks devices currently connected to the relay and, for each, which
// dashboards are watching its screen. Not persisted: the registry only ever
// reflects live WebSocket connections, so a server restart naturally drops
// everyone back to "disconnected".
export class DeviceRegistry {
  #devices = new Map<string, Device>();
  #listeners = new Set<Listener>();

  add(machineId: string, socket: WebSocket): string {
    const id = randomUUID();
    const device: Device = { id, machineId, connectedAt: new Date(), socket, viewers: new Set() };
    this.#devices.set(id, device);
    this.#emit({ kind: "connected", device: toSnapshot(device) });
    return id;
  }

  remove(id: string): void {
    const device = this.#devices.get(id);
    if (device === undefined) return;
    // Let anyone watching tear down their decoder; the frames stop here.
    for (const viewer of device.viewers) notifyCaptureEnded(viewer, id);
    this.#devices.delete(id);
    this.#emit({ kind: "disconnected", id });
  }

  snapshot(): DeviceSnapshot[] {
    return [...this.#devices.values()].map(toSnapshot);
  }

  // A dashboard asks to watch a device. The first viewer makes the relay tell
  // the device to start capturing; later viewers just attach to the stream.
  startView(deviceId: string, viewer: WebSocket): StartViewResult {
    const device = this.#devices.get(deviceId);
    if (device === undefined) return "unknown_device";

    const wasIdle = device.viewers.size === 0;
    device.viewers.add(viewer);
    if (wasIdle) sendCommand(device.socket, { type: "start_capture" });
    return "ok";
  }

  // Detach a dashboard. The last viewer leaving stops capture on the device.
  stopView(deviceId: string, viewer: WebSocket): void {
    const device = this.#devices.get(deviceId);
    if (device === undefined) return;
    if (device.viewers.delete(viewer) && device.viewers.size === 0) {
      sendCommand(device.socket, { type: "stop_capture" });
    }
  }

  // Drop a dashboard from every device it was watching (on disconnect).
  removeViewer(viewer: WebSocket): void {
    for (const device of this.#devices.values()) this.stopView(device.id, viewer);
  }

  // Fan a raw video frame (header + H.264 access unit) out to the dashboards
  // watching this device.
  forwardFrame(deviceId: string, frame: Buffer): void {
    const device = this.#devices.get(deviceId);
    if (device === undefined) return;
    for (const viewer of device.viewers) {
      if (viewer.readyState === viewer.OPEN) viewer.send(frame);
    }
  }

  onChange(listener: Listener): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  #emit(event: RegistryEvent): void {
    for (const listener of this.#listeners) listener(event);
  }
}

function sendCommand(socket: WebSocket, command: DeviceCommand): void {
  if (socket.readyState === socket.OPEN) socket.send(JSON.stringify(command));
}

function notifyCaptureEnded(viewer: WebSocket, deviceId: string): void {
  if (viewer.readyState === viewer.OPEN) {
    viewer.send(JSON.stringify({ type: "capture_ended", deviceId }));
  }
}

function toSnapshot(device: Device): DeviceSnapshot {
  return { id: device.id, machineId: device.machineId, connectedAt: device.connectedAt.toISOString() };
}
