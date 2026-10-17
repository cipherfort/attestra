// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: the API runs separately (`aap api --port 8765`); Vite proxies /api to it.
// Production: `npm run build` emits static assets that the API/BFF serves from the same origin (ADR-023).
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": "http://127.0.0.1:8765" } },
  build: { outDir: "dist", sourcemap: false, assetsInlineLimit: 0 },
});
