import type { FastifyInstance, RawServerBase, RawServerDefault } from "fastify";

import { DashboardCommandSchema, type DashboardEvent } from "../protocol.js";
import type { DeviceRegistry } from "../registry.js";

// View into the relay for the frontend: a snapshot on connect, a live stream
// of connect/disconnect events, and per-device capture control. A dashboard
// sends { type: "start_view", deviceId } to begin receiving that device's
// video frames (as binary messages) and "stop_view" to end it.
export function registerDashboardRoutes<RawServer extends RawServerBase = RawServerDefault>(
  app: FastifyInstance<RawServer>,
  registry: DeviceRegistry,
): void {
  app.get("/api/devices", async () => registry.snapshot());

  app.get("/v1/dashboard", { websocket: true }, (socket, request) => {
    const send = (event: DashboardEvent): void => socket.send(JSON.stringify(event));

    send({ type: "snapshot", devices: registry.snapshot() });

    const unsubscribe = registry.onChange((event) => {
      if (event.kind === "connected") {
        send({ type: "device_connected", device: event.device });
      } else {
        send({ type: "device_disconnected", id: event.id });
      }
    });

    socket.on("message", (raw: Buffer | ArrayBuffer | Buffer[], isBinary: boolean) => {
      if (isBinary) return; // dashboards only send JSON control messages

      let parsed: unknown;
      try {
        parsed = JSON.parse(Buffer.isBuffer(raw) ? raw.toString("utf8") : Buffer.from(raw as ArrayBuffer).toString("utf8"));
      } catch {
        request.log.warn("dashboard: received invalid JSON");
        return;
      }

      const command = DashboardCommandSchema.safeParse(parsed);
      if (!command.success) {
        request.log.warn({ issues: command.error.issues }, "dashboard: received invalid command");
        return;
      }

      if (command.data.type === "start_view") {
        if (registry.startView(command.data.deviceId, socket) === "unknown_device") {
          send({ type: "capture_ended", deviceId: command.data.deviceId });
        }
      } else {
        registry.stopView(command.data.deviceId, socket);
      }
    });

    socket.on("close", () => {
      unsubscribe();
      registry.removeViewer(socket);
    });
  });
}
