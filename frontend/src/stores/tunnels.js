import { writable } from 'svelte/store';

export const tunnels = writable([]);
export const selectedTunnel = writable(null);
export const connectionStatus = writable({ state: 'disconnected' });

let pollInterval = null;

export function startPolling(TunnelService) {
  stopPolling();
  pollInterval = setInterval(async () => {
    try {
      const status = await TunnelService.GetStatus();
      connectionStatus.set(status);
      // Also refresh tunnel list to update connected state
      const list = await TunnelService.ListTunnels();
      tunnels.set(list || []);
    } catch (e) {
      console.error('polling error:', e);
    }
  }, 1000);
}

export function stopPolling() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
}

export async function refreshTunnels(TunnelService) {
  try {
    const list = await TunnelService.ListTunnels();
    tunnels.set(list || []);
  } catch (e) {
    console.error('refresh error:', e);
  }
}
