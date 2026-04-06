import { writable } from 'svelte/store';
import { Events } from '@wailsio/runtime';

// Shared ring buffer of log entries received from the Go backend.
// Both the GUI process and the helper process install slog handlers that
// emit a "log" Wails event per record; we buffer the last N here so the
// LogViewer can render them (and survive navigating away from the Logs
// tab without losing history).
export const logs = writable([]);

const MAX_ENTRIES = 1000;

let installed = false;
let unsub = null;

/**
 * Start listening for backend log events. Idempotent — safe to call
 * multiple times; subsequent calls are no-ops until stopLogListener() is
 * invoked. Should be called once from App.svelte onMount.
 */
export function startLogListener() {
  if (installed) return;
  installed = true;
  unsub = Events.On('log', (event) => {
    const e = event.data;
    if (!e) return;
    logs.update((prev) => {
      const next = prev.length >= MAX_ENTRIES
        ? prev.slice(prev.length - MAX_ENTRIES + 1)
        : prev.slice();
      next.push({
        time: e.time,
        level: (e.level || 'info').toLowerCase(),
        source: e.source || 'gui',
        message: e.message || '',
      });
      return next;
    });
  });
}

export function stopLogListener() {
  if (unsub) { unsub(); unsub = null; }
  installed = false;
}

export function clearLogs() {
  logs.set([]);
}
