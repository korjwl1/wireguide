import { writable } from 'svelte/store';
import { Events } from '@wailsio/runtime';

// Shared circular log buffer of entries received from the Go backend.
// Both the GUI process and the helper process install slog handlers that
// emit a "log" Wails event per record; we buffer the last N here so the
// LogViewer can render them (and survive navigating away from the Logs
// tab without losing history).
//
// IMPLEMENTATION — ring buffer:
//   - `entries` is a pre-allocated, fixed-size array. Same reference for
//     the lifetime of the store; we mutate slots in place.
//   - `head` is the next write position (modulo SIZE).
//   - `count` saturates at SIZE.
//   - `version` increments every push so Svelte's reference-equality check
//     fires reactivity — we set a NEW wrapper object on every update,
//     while the inner `entries` array is reused.
// This replaces the previous design that called `prev.slice(...)` on every
// push (O(N) copy of up to 1000 elements per log record, GC pressure
// during log bursts).

const SIZE = 1000;

const initial = {
  entries: new Array(SIZE),
  head: 0,
  count: 0,
  version: 0,
};

export const logs = writable(initial);

/**
 * Returns a fresh array with the logged entries in chronological order
 * (oldest first). Consumers — like LogViewer — should derive this from
 * the store inside a `$:` block; we recompute only when the underlying
 * state changes. Allocates a new array per call, but this is paid only
 * when the LogViewer is mounted, not on every log push.
 *
 * @param {{entries: any[], head: number, count: number}} s
 */
export function orderedLogs(s) {
  if (!s || s.count === 0) return [];
  if (s.count < SIZE) {
    // Buffer hasn't wrapped yet — oldest at index 0, newest at head-1.
    return s.entries.slice(0, s.count);
  }
  // Wrapped — oldest at `head`, newest at `head - 1` (mod SIZE).
  return s.entries.slice(s.head).concat(s.entries.slice(0, s.head));
}

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
    logs.update((s) => {
      s.entries[s.head] = {
        // Monotonic id — LogViewer keys its {#each} on this. Index keys
        // break down once the ring wraps: every push shifts all rows by
        // one, forcing Svelte to rewrite the whole list per log record.
        id: s.version,
        time: e.time,
        level: (e.level || 'info').toLowerCase(),
        source: e.source || 'gui',
        message: e.message || '',
      };
      s.head = (s.head + 1) % SIZE;
      if (s.count < SIZE) s.count += 1;
      // New wrapper object → Svelte subscribers fire. The inner `entries`
      // array is reused (no per-push allocation), but consumers see a
      // fresh top-level state.
      return { entries: s.entries, head: s.head, count: s.count, version: s.version + 1 };
    });
  });
}

export function stopLogListener() {
  if (unsub) { unsub(); unsub = null; }
  installed = false;
}

export function clearLogs() {
  logs.update((s) => {
    // Drop references so the old entries can be GC'd. The array itself
    // stays allocated (we'll fill it again).
    for (let i = 0; i < s.entries.length; i++) s.entries[i] = undefined;
    return { entries: s.entries, head: 0, count: 0, version: s.version + 1 };
  });
}
