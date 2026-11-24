/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Tauri expects a fixed port and must not have its Rust output obscured.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  envPrefix: ["VITE_", "TAURI_"],
  optimizeDeps: {
    include: [
      "react", "react-dom", "react-dom/client", "zustand", "lucide-react", "@tanstack/react-table", "@tanstack/react-virtual",
      "echarts/core", "echarts/charts", "echarts/components", "echarts/renderers", "@tauri-apps/api/core", "@tauri-apps/api/event",
      "codemirror", "@codemirror/state", "@codemirror/view", "@codemirror/language", "@codemirror/commands",
      "@codemirror/legacy-modes/mode/toml", "@lezer/highlight",
    ],
  },
  build: {
    target: "es2022",
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
  test: {
    environment: "jsdom",
    globals: false,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    css: false,
  },
});
