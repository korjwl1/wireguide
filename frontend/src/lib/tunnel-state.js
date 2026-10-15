// Active intent includes setup/teardown. Connection indicators use the actual
// per-tunnel state, matching the tray and Dock/taskbar adapters.
export function tunnelStatus(status, name) {
  if (!name) return null;
  if (status?.tunnels?.length) {
    return status.tunnels.find(row => row.tunnel_name === name) || null;
  }
  return status?.tunnel_name === name ? status : null;
}

export function tunnelState(status, name) {
  return tunnelStatus(status, name)?.state || 'disconnected';
}

export function connectedTunnelNames(status) {
  const rows = status?.tunnels?.length ? status.tunnels : [status];
  return rows.filter(row => row?.state === 'connected' && row.tunnel_name)
    .map(row => row.tunnel_name);
}
