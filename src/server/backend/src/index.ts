import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Server as HttpsServer } from "node:https";

import fastifyStatic from "@fastify/static";
import fastifyWebsocket from "@fastify/websocket";
import Fastify, { type FastifyInstance, type RawServerBase, type RawServerDefault } from "fastify";

import { DeviceRegistry } from "./registry.js";
import { registerDashboardRoutes } from "./routes/dashboard.js";
import { registerRelayRoute } from "./routes/relay.js";
import { loadTlsConfig } from "./tls.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = Number(process.env.PORT ?? 8080);
const HOST = process.env.HOST ?? "127.0.0.1";
const FRONTEND_DIST = path.join(__dirname, "../../frontend/dist");
const DEFAULT_TLS_CERT = path.join(__dirname, "../../certs/dev-cert.pem");
const DEFAULT_TLS_KEY = path.join(__dirname, "../../certs/dev-key.pem");

async function serve<RawServer extends RawServerBase = RawServerDefault>(
  app: FastifyInstance<RawServer>,
): Promise<void> {
  await app.register(fastifyWebsocket);
  await app.register(fastifyStatic, { root: FRONTEND_DIST });

  const registry = new DeviceRegistry();
  registerRelayRoute(app, registry);
  registerDashboardRoutes(app, registry);

  await app.listen({ port: PORT, host: HOST });
}

async function main(): Promise<void> {
  const tls = loadTlsConfig(DEFAULT_TLS_CERT, DEFAULT_TLS_KEY);

  if (tls === undefined) {
    const app = Fastify({ logger: true });
    app.log.warn(
      "no TLS cert/key found: serving plain http/ws. Run `bun run certs` for a local dev " +
        "cert, or set TLS_CERT_PATH/TLS_KEY_PATH. Never expose this beyond localhost without TLS.",
    );
    await serve(app);
    return;
  }

  const app = Fastify<HttpsServer>({ logger: true, https: tls });
  await serve(app);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
