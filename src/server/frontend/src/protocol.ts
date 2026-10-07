// Mirrors backend/src/protocol.ts. Kept as a plain duplicate rather than a
// shared package since the frontend only ever reads these shapes.

export interface DeviceSnapshot {
  id: string;
  machineId: string;
  connectedAt: string;
}

export type DashboardEvent =
  | { type: "snapshot"; devices: DeviceSnapshot[] }
  | { type: "device_connected"; device: DeviceSnapshot }
  | { type: "device_disconnected"; id: string };
