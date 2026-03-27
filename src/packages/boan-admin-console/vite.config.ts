import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 18099,
    proxy: {
      "/api/policy": "http://localhost:18090",
      "/api/registry": "http://localhost:18095",
      "/api/audit": "http://localhost:18093",
      "/api/credential": "http://localhost:18092",
    },
  },
});
