import { writable, get } from 'svelte/store';
import { Events } from '@wailsio/runtime';

export const tunnels = writable([]);
export const selectedTunnel = writable(null);
export const connectionStatus = writable({ state: 'disconnected' });

let statusUnsub = null;

// Subscribe to backend status events. The tunnel list is not event-driven
// on the backend side — it's refreshed manually via `refreshTunnels()` after
// each mutating operation (connect/disconnect/create/delete/rename).
export function subscribeToEvents() {
  unsubscribe();

  statusUnsub = Events.On('status', (event) => {
    connectionStatus.set(event.data);
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
    if (status) connectionStatus.set(status);
  } catch (e) {
    console.error('status error:', e);
  }
}
