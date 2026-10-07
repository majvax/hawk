import { randomUUID } from "node:crypto";

import type { WebSocket } from "@fastify/websocket";

import type { DeviceSnapshot } from "./protocol.js";

interface Device {
  id: string;
  machineId: string;
  connectedAt: Date;
  socket: WebSocket;
}

export type RegistryEvent =
  | { kind: "connected"; device: DeviceSnapshot }
  | { kind: "disconnected"; id: string };

type Listener = (event: RegistryEvent) => void;

// Tracks devices currently connected to the relay. Not persisted: the
// registry only ever reflects live WebSocket connections, so a server
// restart naturally drops everyone back to "disconnected".
export class DeviceRegistry {
  #devices = new Map<string, Device>();
  #listeners = new Set<Listener>();

  add(machineId: string, socket: WebSocket): string {
    const id = randomUUID();
    const device: Device = { id, machineId, connectedAt: new Date(), socket };
    this.#devices.set(id, device);
    this.#emit({ kind: "connected", device: toSnapshot(device) });
    return id;
  }

  remove(id: string): void {
    if (this.#devices.delete(id)) {
      this.#emit({ kind: "disconnected", id });
    }
  }

  snapshot(): DeviceSnapshot[] {
    return [...this.#devices.values()].map(toSnapshot);
  }

  onChange(listener: Listener): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  #emit(event: RegistryEvent): void {
    for (const listener of this.#listeners) listener(event);
  }
}

function toSnapshot(device: Device): DeviceSnapshot {
  return { id: device.id, machineId: device.machineId, connectedAt: device.connectedAt.toISOString() };
}
