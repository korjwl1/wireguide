package app

import (
	"log/slog"

	"github.com/korjwl1/wireguide/internal/ipc"
)

// ListTunnelsLocal returns stored tunnels WITHOUT asking the helper which one
// is active — callers that already know the active name (e.g. the system
// tray, which tracks it from the status event stream) should use this to
// avoid an IPC round-trip on every refresh. IsConnected is always false in
// the returned slice; the caller is responsible for applying its own
// active-name match.
func (s *TunnelService) ListTunnelsLocal() ([]TunnelInfo, error) {
	names, err := s.tunnelStore.List()
	if err != nil {
		return nil, err
	}
	lastUsed := s.lastUsedByTunnel()
	var result []TunnelInfo
	for _, name := range names {
		cfg, meta, err := s.tunnelStore.LoadWithMeta(name)
		if err != nil {
			slog.Warn("skipping broken tunnel config", "name", name, "error", err)
			continue
		}
		endpoint := ""
		if len(cfg.Peers) > 0 {
			endpoint = cfg.Peers[0].Endpoint
		}
		notes := ""
		latencyProbeTarget := ""
		if meta != nil {
			notes = meta.Notes
			latencyProbeTarget = meta.LatencyProbeTarget
		}
		// Date-added: the stamped creation time (survives edits, issue #17);
		// mtime fallback only for tunnels created before stamping existed.
		// meta is already loaded — no second sidecar read.
		created := int64(0)
		if meta != nil {
			created = meta.CreatedUnix
		}
		if created == 0 {
			created = s.tunnelStore.ModTimeUnix(name)
		}
		result = append(result, TunnelInfo{
			Name:               name,
			Endpoint:           endpoint,
			Notes:              notes,
			LatencyProbeTarget: latencyProbeTarget,
			CreatedAtUnix:      created,
			LastUsedUnix:       lastUsed[name],
		})
	}
	return result, nil
}

// ListTunnels decorates the local summaries with the helper's complete
// active set. A failed probe leaves a useful local list for offline editing.
func (s *TunnelService) ListTunnels() ([]TunnelInfo, error) {
	result, err := s.ListTunnelsLocal()
	if err != nil {
		return nil, err
	}
	var active ipc.ActiveTunnelsResponse
	_ = s.call(ipc.MethodActiveTunnels, nil, &active)
	names := make(map[string]bool, len(active.Names))
	for _, name := range active.Names {
		names[name] = true
	}
	for i := range result {
		result[i].IsConnected = names[result[i].Name]
	}
	return result, nil
}
