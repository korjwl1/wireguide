import { writable, get } from 'svelte/store';
import { patchSettings } from './settings.js';
import { TunnelService } from '../../bindings/github.com/korjwl1/wireguide/internal/app';

// Shared UI view-state, mirrored from persisted Settings. App.onMount
// seeds these from GetSettings; the controls (Settings toggle, tunnel
// list header) update them live and persist via the helpers below.

// compactList mirrors Settings.compact_list — persisted from Settings.svelte.
export const compactList = writable(false);

// Tunnel-list ordering, controlled from the list header.
export const listSort = writable('name_asc');       // "name_asc" | "name_desc"
export const listActiveOnTop = writable(true);

// Draggable width (px) of the tunnel-list column.
export const LIST_PANE_MIN = 190;
export const LIST_PANE_MAX = 460;
export const LIST_PANE_DEFAULT = 240;
export const listPaneWidth = writable(LIST_PANE_DEFAULT);

let saveTimer = null;

// Persist only list preferences; the backend merges them under its file lock.
export function saveListPrefs() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    saveTimer = null;
    try {
      await patchSettings(TunnelService, {
        list_sort: get(listSort),
        list_active_on_top: get(listActiveOnTop),
        list_pane_width: Math.round(get(listPaneWidth)),
      });
    } catch (e) {
      console.warn('saveListPrefs failed (will retry on next change):', e);
    }
  }, 300);
}
