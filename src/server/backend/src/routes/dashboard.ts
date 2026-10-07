import type { FastifyInstance, RawServerBase, RawServerDefault } from "fastify";

import type { DashboardEvent } from "../protocol.js";
import type { DeviceRegistry } from "../registry.js";

// Read-only view for the frontend: a snapshot on connect, then a live
// stream of connect/disconnect events. No commands flow through here.
export function registerDashboardRoutes<RawServer extends RawServerBase = RawServerDefault>(
  app: FastifyInstance<RawServer>,
  registry: DeviceRegistry,
): void {
  app.get("/api/devices", async () => registry.snapshot());

  app.get("/v1/dashboard", { websocket: true }, (socket) => {
    const send = (event: DashboardEvent): void => socket.send(JSON.stringify(event));

    send({ type: "snapshot", devices: registry.snapshot() });

    const unsubscribe = registry.onChange((event) => {
      if (event.kind === "connected") {
        send({ type: "device_connected", device: event.device });
      } else {
        send({ type: "device_disconnected", id: event.id });
      }
    });

    socket.on("close", unsubscribe);
  });
}
