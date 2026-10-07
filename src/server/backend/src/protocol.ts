import { z } from "zod";

// Messages sent by a device (the hawk-service client) on connection.
export const HelloMessageSchema = z.object({
  type: z.literal("hello"),
  machine_id: z.string().min(1),
});
export type HelloMessage = z.infer<typeof HelloMessageSchema>;

export interface DeviceSnapshot {
  id: string;
  machineId: string;
  connectedAt: string; // ISO timestamp
}

// Messages pushed to connected dashboards.
export type DashboardEvent =
  | { type: "snapshot"; devices: DeviceSnapshot[] }
  | { type: "device_connected"; device: DeviceSnapshot }
  | { type: "device_disconnected"; id: string };
