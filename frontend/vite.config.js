import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import wails from "@wailsio/runtime/plugins/vite";

// https://vitejs.dev/config/
//
// Bundle split policy: the previous single 531 KB chunk delays cold start
// because the whole app (Settings, LogViewer, TunnelDetail, KeyGenerator)
// has to parse before the first paint. We extract each modal/heavy
// component into its own chunk so the initial render only needs the
// tunnel-list path; modals load on demand when the user opens them.
export default defineConfig({
  plugins: [svelte(), wails("./bindings")],
  build: {
    // Bump chunk size warning ceiling because the runtime+Svelte combined
    // chunk is still ~300 KB even after splitting — that's expected for a
    // Svelte+Wails app and not actionable.
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks: {
          // Wails bindings + runtime — heavy and rarely changes; cache
          // separately so app code updates don't bust this chunk.
          "wails-runtime": ["@wailsio/runtime"],
          // CodeMirror — ~250 KB just for the editor framework + every
          // language pack we import. ConfigEditor is the only consumer
          // today but isolating CodeMirror into its own chunk means the
          // editor view shows the chrome immediately and the heavy
          // syntax-highlight code streams in next, instead of blocking
          // the first paint.
          "codemirror": [
            "@codemirror/autocomplete",
            "@codemirror/commands",
            "@codemirror/language",
            "@codemirror/lint",
            "@codemirror/search",
            "@codemirror/state",
            "@codemirror/view",
          ],
          // Heavy modals — loaded only when the user opens them. Keeping
          // them out of the main chunk shaves ~150 KB off the initial
          // load.
          "modal-logs": ["./src/lib/LogViewer.svelte"],
          "modal-settings": ["./src/lib/Settings.svelte"],
          "modal-tunnel-detail": ["./src/lib/TunnelDetail.svelte"],
          "modal-config-editor": ["./src/lib/ConfigEditor.svelte"],
          "modal-keygen": ["./src/lib/KeyGenerator.svelte"],
          "modal-history": ["./src/lib/History.svelte"],
          "modal-route-viz": ["./src/lib/RouteVisualization.svelte"],
          "modal-stats": ["./src/lib/StatsDashboard.svelte"],
          "modal-dnsleak": ["./src/lib/DNSLeakTest.svelte"],
        },
      },
    },
  },
});
