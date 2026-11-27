import { defineConfig } from "vite";
import solidPlugin from "vite-plugin-solid";

export default defineConfig({
  base: "/",
  plugins: [solidPlugin()],
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      "/v1": {
        target: "http://127.0.0.1:7700",
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "esnext",
    sourcemap: false,
  },
});
