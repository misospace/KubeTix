import path from "path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("test"),
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./test-setup.ts"],
    globals: true,
    alias: {
      "@": path.resolve(__dirname, "./"),
    },
  },
});