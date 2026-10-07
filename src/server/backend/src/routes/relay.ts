import type { FastifyInstance, RawServerBase, RawServerDefault } from "fastify";

import { HelloMessageSchema } from "../protocol.js";
import type { DeviceRegistry } from "../registry.js";

const HELLO_TIMEOUT_MS = 5_000;

function toUtf8(raw: Buffer | ArrayBuffer | Buffer[]): string {
  return toBuffer(raw).toString("utf8");
}

function toBuffer(raw: Buffer | ArrayBuffer | Buffer[]): Buffer {
  if (Buffer.isBuffer(raw)) return raw;
  if (Array.isArray(raw)) return Buffer.concat(raw);
  return Buffer.from(raw);
}

// Endpoint devices (the hawk-service client) connect to. The only message
// handled today is the initial "hello" used to register the device; the
// command/control protocol is deliberately not implemented yet.
export function registerRelayRoute<RawServer extends RawServerBase = RawServerDefault>(
  app: FastifyInstance<RawServer>,
  registry: DeviceRegistry,
): void {
  app.get("/v1/ws", { websocket: true }, (socket, request) => {
    let deviceId: string | undefined;

    const helloTimeout = setTimeout(() => {
      request.log.warn("relay: device did not send hello in time, closing");
      socket.close(1002, "expected hello");
    }, HELLO_TIMEOUT_MS);

    socket.on("message", (raw: Buffer | ArrayBuffer | Buffer[], isBinary: boolean) => {
      // Once registered, binary messages are encoded video frames: forward
      // them verbatim (header + H.264 access unit) to watching dashboards.
      if (deviceId !== undefined) {
        if (isBinary) registry.forwardFrame(deviceId, toBuffer(raw));
        return;
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(toUtf8(raw));
      } catch {
        request.log.warn("relay: received invalid JSON, closing connection");
        socket.close(1003, "invalid json");
        return;
      }

      const hello = HelloMessageSchema.safeParse(parsed);
      if (!hello.success) {
        request.log.warn({ issues: hello.error.issues }, "relay: received invalid hello message");
        socket.close(1003, "invalid hello");
        return;
      }

      clearTimeout(helloTimeout);
      deviceId = registry.add(hello.data.machine_id, socket);
      request.log.info({ machineId: hello.data.machine_id }, "relay: device connected");
    });

    socket.on("close", () => {
      clearTimeout(helloTimeout);
      if (deviceId !== undefined) {
        registry.remove(deviceId);
        request.log.info({ deviceId }, "relay: device disconnected");
      }
    });
  });
}
