import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  build: {
    target: "es2022",
    sourcemap: false,
    reportCompressedSize: true,
    chunkSizeWarningLimit: 350,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("/react")) return "react";
          if (id.includes("/@tanstack/")) return "tanstack";
          if (id.includes("/zod/")) return "validation";
          return undefined;
        }
      }
    }
  },
  server: {
    host: "127.0.0.1",
    port: 4173,
    strictPort: true,
    proxy: {
      "/operator": "http://127.0.0.1:8123"
    }
  }
});
