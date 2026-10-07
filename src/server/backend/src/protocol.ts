import { z } from "zod";

// Messages sent by a device (the hawk-service client) on connection.
export const HelloMessageSchema = z.object({
  type: z.literal("hello"),
  machine_id: z.string().min(1),
});
export type HelloMessage = z.infer<typeof HelloMessageSchema>;

// Commands the relay sends down to a device to control capture. Mirrors the
// RelayCommand parser in src/service/main.cpp.
export type DeviceCommand = { type: "start_capture" } | { type: "stop_capture" };

// Messages a dashboard sends up to the relay to start/stop watching a
// device's screen.
export const DashboardCommandSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("start_view"), deviceId: z.string().min(1) }),
  z.object({ type: z.literal("stop_view"), deviceId: z.string().min(1) }),
]);
export type DashboardCommand = z.infer<typeof DashboardCommandSchema>;

export interface DeviceSnapshot {
  id: string;
  machineId: string;
  connectedAt: string; // ISO timestamp
}

// Messages pushed to connected dashboards.
export type DashboardEvent =
  | { type: "snapshot"; devices: DeviceSnapshot[] }
  | { type: "device_connected"; device: DeviceSnapshot }
  | { type: "device_disconnected"; id: string }
  // The device went away (or never had a capture running) while a dashboard
  // was viewing it; the viewer should tear its decoder down.
  | { type: "capture_ended"; deviceId: string };
