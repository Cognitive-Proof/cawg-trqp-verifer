import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

// The page talks to the admin router one level up from wherever it's
// served (`<mount>/ui/` → `<mount>/`), so the build uses relative asset
// paths and works under any mount point. The dev server mimics a "/registry"
// mount and proxies everything but the page to a running registry.
const target = process.env.TRQP_URL ?? "http://localhost:8080";

export default defineConfig(({ command }) => ({
  root: fileURLToPath(new URL(".", import.meta.url)),
  base: command === "build" ? "./" : "/registry/ui/",
  build: { outDir: "../dist/ui", emptyOutDir: true },
  server: {
    port: 5175,
    proxy: { "^/registry/(?!ui/)": { target, changeOrigin: true } },
  },
}));
