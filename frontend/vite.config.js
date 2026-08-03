import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import wails from "@wailsio/runtime/plugins/vite";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [svelte(), wails("./bindings")],
  build: {
    // WebKitGTK versions shipped by supported Linux distributions lag the
    // evergreen browsers Vite targets by default. Transpile modern syntax so
    // the application mounts on those embedded WebKit runtimes as well.
    target: "safari13",
    // Let Rolldown derive safe chunk boundaries. The previous forced chunk
    // graph created circular startup imports under Vite 8 and left WebKitGTK
    // with a blank window before the Svelte application could mount.
    chunkSizeWarningLimit: 600,
  },
});
