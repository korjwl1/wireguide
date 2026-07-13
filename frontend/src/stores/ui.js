import { writable, get } from 'svelte/store';
import { TunnelService } from '../../bindings/github.com/korjwl1/wireguide/internal/app';

// Shared UI view-state, mirrored from persisted Settings. App.onMount
// seeds these from GetSettings; the controls (Settings toggle, tunnel
// list header) update them live and persist via the helpers below.

// compactList mirrors Settings.compact_list — persisted from Settings.svelte.
export const compactList = writable(false);

// Tunnel-list ordering, controlled from the list header.
export const listSort = writable('name_asc');       // "name_asc" | "name_desc"
export const listActiveOnTop = writable(true);

let saveTimer = null;

// saveListPrefs persists the list-ordering prefs. It re-fetches the
// freshest settings and overlays only its own fields (the same
// spread-fresh pattern TunnelDetail uses for wifi_rules) so it never
// clobbers edits another screen made to settings.json. Debounced.
export function saveListPrefs() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    saveTimer = null;
    try {
      const fresh = await TunnelService.GetSettings();
      await TunnelService.SaveSettings({
        ...fresh,
        list_sort: get(listSort),
        list_active_on_top: get(listActiveOnTop),
      });
    } catch (e) {
      console.warn('saveListPrefs failed (will retry on next change):', e);
    }
  }, 300);
}
