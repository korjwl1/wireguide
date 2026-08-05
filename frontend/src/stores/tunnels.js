import { writable, get } from 'svelte/store';
import { Events } from '@wailsio/runtime';

export const tunnels = writable([]);
export const selectedTunnel = writable(null);
export const connectionStatus = writable({ state: 'disconnected' });

let statusUnsub = null;

// Last-broadcast fingerprint for the notification gate below.
let lastStatusJSON = '';

// Subscribe to backend status events. The tunnel list is not event-driven
// on the backend side — it's refreshed manually via `refreshTunnels()` after
// each mutating operation (connect/disconnect/create/delete/rename).
//
// Every set()/update() here is gated behind a value comparison. Svelte
// stores treat all objects as unequal (safe_not_equal), so returning the
// same reference from update() still notifies every subscriber — at the
// helper's 1 Hz broadcast rate that meant TunnelList re-sorting and every
// dependent `$:` recomputing each second even while idle.
export function subscribeToEvents() {
  unsubscribe();

  statusUnsub = Events.On('status', (event) => {
    const status = event.data;
    const statusJSON = JSON.stringify(status);
    if (statusJSON !== lastStatusJSON) {
      lastStatusJSON = statusJSON;
      connectionStatus.set(status);
    }

    // Sync is_connected flag on tunnel objects. The backend now sends
    // active_tunnels (array of connected tunnel names) to support
    // multiple simultaneous tunnels.
    const activeSet = new Set(status?.active_tunnels || []);

    const list = get(tunnels);
    let changed = false;
    const next = list.map((t) => {
      const conn = activeSet.has(t.name);
      if (t.is_connected === conn) return t;
      changed = true;
      return { ...t, is_connected: conn };
    });
    if (changed) tunnels.set(next);

    const sel = get(selectedTunnel);
    if (sel) {
      const nowConnected = activeSet.has(sel.name);
      if (sel.is_connected !== nowConnected) {
        selectedTunnel.set({ ...sel, is_connected: nowConnected });
      }
    }
  });
}

export function unsubscribe() {
  if (statusUnsub) {
    statusUnsub();
    statusUnsub = null;
  }
}

// Initial load — one-time fetch to populate before first event arrives
export async function initialLoad(TunnelService) {
  try {
    const list = (await TunnelService.ListTunnels()) || [];
    tunnels.set(list);
  } catch (e) {
    console.error('initial load failed:', e);
  }
}

// Manual refresh (after create/delete/import actions)
export async function refreshTunnels(TunnelService) {
  try {
    const list = (await TunnelService.ListTunnels()) || [];
    tunnels.set(list);
    const sel = get(selectedTunnel);
    if (sel) {
      const updated = list.find((t) => t.name === sel.name);
      if (updated) selectedTunnel.set(updated);
    }
  } catch (e) {
    console.error('refresh error:', e);
  }
}

// Immediate status fetch (after Connect/Disconnect)
export async function refreshStatus(TunnelService) {
  try {
    const status = await TunnelService.GetStatus();
    if (status) {
      lastStatusJSON = JSON.stringify(status);
      connectionStatus.set(status);
    }
  } catch (e) {
    console.error('status error:', e);
  }
}
