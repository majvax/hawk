import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Dev server proxies API/WS calls to the backend so the dashboard can be
// run with `bun run dev` without CORS or a separate origin to configure.
// The backend serves wss/https using a self-signed dev cert (see
// backend/scripts/generate-dev-cert.sh), so `secure: false` here just skips
// cert verification on this local dev-only hop — it has no bearing on the
// TLS the real client/dashboard connect over in production.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: "https://127.0.0.1:8080", secure: false },
      "/v1/dashboard": { target: "wss://127.0.0.1:8080", ws: true, secure: false },
    },
  },
  build: {
    outDir: "dist",
  },
});
