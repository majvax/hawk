import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// hawk-setup's window (src/setup): a page of its own, with the dashboard's
// look and components, built into dist-setup for the installer to embed.
export default defineConfig({
  root: "setup",
  base: "./",
  plugins: [react()],
  build: {
    outDir: "../dist-setup",
    emptyOutDir: true,
  },
});
