import { writable, get } from 'svelte/store';

export const tunnels = writable([]);
export const selectedTunnel = writable(null);
export const connectionStatus = writable({ state: 'disconnected' });

let pollInterval = null;
let lastTunnelsJSON = '';
let lastStatusJSON = '';

export function startPolling(TunnelService) {
  stopPolling();
  pollInterval = setInterval(async () => {
    try {
      const status = await TunnelService.GetStatus();
      const statusJSON = JSON.stringify(status);
      if (statusJSON !== lastStatusJSON) {
        lastStatusJSON = statusJSON;
        connectionStatus.set(status);
      }

      const list = (await TunnelService.ListTunnels()) || [];
      const listJSON = JSON.stringify(list);
      if (listJSON !== lastTunnelsJSON) {
        lastTunnelsJSON = listJSON;
        tunnels.set(list);
        // Refresh selectedTunnel reference to match new list
        const sel = get(selectedTunnel);
        if (sel) {
          const updated = list.find(t => t.name === sel.name);
          if (updated) selectedTunnel.set(updated);
        }
      }
    } catch (e) {
      console.error('polling error:', e);
    }
  }, 2000); // 2s instead of 1s to reduce re-render pressure
}

export function stopPolling() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
}

export async function refreshTunnels(TunnelService) {
  try {
    const list = (await TunnelService.ListTunnels()) || [];
    lastTunnelsJSON = JSON.stringify(list);
    tunnels.set(list);
  } catch (e) {
    console.error('refresh error:', e);
  }
}
