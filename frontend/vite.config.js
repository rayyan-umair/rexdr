/**
 * rexdr - Frontend
 * vite.config.js - Build tool configuration
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Vite configuration for the REXDR React frontend. Dev server
 *           proxies engine API calls to avoid CORS issues during local
 *           development. Production build is served by the Dockerfile's
 *           static server behind the Nginx gateway.
 *
 * --- Part of the REXDR platform. ---
 */

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: "0.0.0.0",
  },
  preview: {
    port: 3000,
    host: "0.0.0.0",
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});