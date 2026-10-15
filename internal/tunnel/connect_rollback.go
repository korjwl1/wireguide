package tunnel

import (
	"log/slog"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
)

// rollbackConnect keeps the primary connect error while retaining every
// resource whose OS cleanup failed for the helper's recovery loop.
func (m *Manager) rollbackConnect(cfg *domain.WireGuardConfig, engine *Engine, netMgr network.NetworkManager, primary error) error {
	ifaceName := engine.InterfaceName()
	fullTunnel := cfg.IsFullTunnel()
	var allAllowedIPs []string
	for _, peer := range cfg.Peers {
		allAllowedIPs = append(allAllowedIPs, peer.AllowedIPs...)
	}
	cleaned := true
	// Undo routes that may have been installed before the failure.
	if err := netMgr.RemoveRoutes(ifaceName, allAllowedIPs, fullTunnel); err != nil {
		cleaned = false
		slog.Warn("rollback: RemoveRoutes failed", "error", err)
	}
	// Strip any endpoint loop protection filters we installed before
	// the failure point — leaving them in force after a failed
	// connect would block re-connects to the same endpoint until
	// the helper restarted (the WFP BLOCK targets remote IP+port +
	// tunnel LUID; on a re-connect the LUID matches again).
	if m.endpointProtector != nil {
		if err := m.endpointProtector.DisableEndpointProtection(ifaceName); err != nil {
			slog.Warn("rollback: DisableEndpointProtection failed", "iface", ifaceName, "error", err)
		}
	}
	var splitCleanupErr error
	if cfg.Interface.IsSplitDNS() {
		splitCleanupErr = m.removeSplitDNS(cfg.Name, netMgr, ifaceName)
	}
	if err := netMgr.Cleanup(ifaceName); err != nil {
		cleaned = false
		slog.Warn("rollback: network Cleanup failed", "iface", ifaceName, "error", err)
	}
	// A rolled-back connect must not leave a journal that crash
	// recovery would later act on (and misread as a live tunnel).
	if cleaned && splitCleanupErr == nil {
		if err := ClearActiveState(m.dataDir, cfg.Name); err != nil {
			slog.Warn("rollback: ClearActiveState failed", "tunnel", cfg.Name, "error", err)
		}
	}
	if !cleaned {
		m.queueNetworkCleanup(cfg.Name, ifaceName, netMgr, primary)
	}
	if cleaned && len(m.AllDNSServers()) == 0 {
		m.clearRecoveredBaseline()
	}
	engine.Close()
	return primary
}
