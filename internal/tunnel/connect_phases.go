package tunnel

import (
	"fmt"
	"log/slog"

	"github.com/korjwl1/wireguide/internal/domain"
)

// connectPhases executes the steps that bring a tunnel up. Called from
// Manager.Connect under the manager's mutex. Returns the created engine on
// success, or an error after rolling back any partial state on failure.
//
// Steps (matching wg-quick's order):
//  1. PreUp script
//  2. Create WireGuard engine (TUN + wgctrl device)
//  3. Set MTU
//  4. Assign address
//  5. Bring interface up
//  6. Install routes (incl. endpoint bypass for every peer)
//  7. Apply DNS (best-effort)
//  8. PostUp script (best-effort)
//  9. Persist crash-recovery state (only after everything else succeeds)
func (m *Manager) connectPhases(cfg *domain.WireGuardConfig, scriptsAllowed bool) (*Engine, error) {
	// 1. PreUp (fatal on failure — user opted in)
	if scriptsAllowed && cfg.Interface.PreUp != "" {
		slog.Info("running PreUp script", "cmd", cfg.Interface.PreUp)
		if err := runScript(cfg.Interface.PreUp); err != nil {
			return nil, fmt.Errorf("PreUp script failed: %w", err)
		}
	}

	// 2. Engine
	engine, err := NewEngine(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating engine: %w", err)
	}
	ifaceName := engine.InterfaceName()

	// rollback helper closes the engine and restores network state if any
	// later phase fails. Best-effort — we log rather than propagate cleanup
	// errors because we already have a primary failure to report.
	rollback := func(primary error) error {
		_ = m.netMgr.Cleanup(ifaceName)
		engine.Close()
		return primary
	}

	// 3. MTU — pass the user-configured value straight through. If it's 0
	// (unset), the platform adapter does wg-quick's upstream-MTU-minus-80
	// auto-detection. Do NOT default to 1420 here: that would shadow the
	// auto-detection and force the wrong MTU on links like PPPoE (1492)
	// or USB-tether (often 1500 but varies) or jumbo-frame LANs.
	if err := m.netMgr.SetMTU(ifaceName, cfg.Interface.MTU); err != nil {
		return nil, rollback(fmt.Errorf("setting MTU: %w", err))
	}

	// 4. Address
	if err := m.netMgr.AssignAddress(ifaceName, cfg.Interface.Address); err != nil {
		return nil, rollback(fmt.Errorf("assigning address: %w", err))
	}

	// 5. Bring up
	if err := m.netMgr.BringUp(ifaceName); err != nil {
		return nil, rollback(fmt.Errorf("bringing up interface: %w", err))
	}

	// 6. Routes + endpoint bypass.
	//
	// IMPORTANT: we pass the peer endpoint IPs that NewEngine already
	// resolved, NOT the hostname strings from the config. If AddRoutes had
	// to resolve hostnames itself, it would do so AFTER installing the /1
	// split routes — which would route the DNS query through the tunnel
	// itself, looping back to an endpoint that has no bypass yet. This is
	// the chicken-and-egg that wg-quick sidesteps by resolving endpoints
	// via the `wg` tool BEFORE touching the route table.
	var allAllowedIPs []string
	for _, peer := range cfg.Peers {
		allAllowedIPs = append(allAllowedIPs, peer.AllowedIPs...)
	}
	fullTunnel := cfg.IsFullTunnel()
	endpointIPs := engine.ResolvedEndpointIPs()
	if err := m.netMgr.AddRoutes(ifaceName, allAllowedIPs, fullTunnel, endpointIPs); err != nil {
		return nil, rollback(fmt.Errorf("adding routes: %w", err))
	}

	// 7. DNS (non-fatal — tunnel still works without custom DNS)
	if err := m.netMgr.SetDNS(ifaceName, cfg.Interface.DNS); err != nil {
		slog.Warn("failed to set DNS", "error", err)
	}

	// 8. PostUp (non-fatal — tunnel is already live)
	if scriptsAllowed && cfg.Interface.PostUp != "" {
		slog.Info("running PostUp script", "cmd", cfg.Interface.PostUp)
		if err := runScript(cfg.Interface.PostUp); err != nil {
			slog.Warn("PostUp script failed", "error", err)
		}
	}

	// 9. Crash recovery state — persisted AFTER all fallible phases so a
	// mid-connect failure doesn't leave an orphan state file pointing at a
	// tunnel that was never actually brought up. Non-fatal: if we can't
	// write the recovery file (disk full, permissions) the tunnel is still
	// up, we just won't be able to recover automatically next boot.
	if err := SaveActiveState(m.dataDir, &ActiveTunnelState{
		TunnelName:    cfg.Name,
		InterfaceName: ifaceName,
		DNSServers:    cfg.Interface.DNS,
		FullTunnel:    fullTunnel,
	}); err != nil {
		slog.Warn("failed to persist crash recovery state", "error", err)
	}

	slog.Info("tunnel connected",
		"name", cfg.Name,
		"interface", ifaceName,
		"full_tunnel", fullTunnel)
	return engine, nil
}

// disconnectPhases runs the teardown sequence for an active tunnel. Called
// from Manager.Disconnect under the manager's mutex. All steps are best-effort
// — we log errors rather than returning them because partial teardown is
// better than none.
func (m *Manager) disconnectPhases(cfg *domain.WireGuardConfig, engine *Engine) {
	ifaceName := engine.InterfaceName()

	// PreDown script (non-fatal)
	if m.scriptsAllowed && cfg.Interface.PreDown != "" {
		slog.Info("running PreDown script", "cmd", cfg.Interface.PreDown)
		if err := runScript(cfg.Interface.PreDown); err != nil {
			slog.Warn("PreDown script failed", "error", err)
		}
	}

	// Routes
	var allAllowedIPs []string
	for _, peer := range cfg.Peers {
		allAllowedIPs = append(allAllowedIPs, peer.AllowedIPs...)
	}
	_ = m.netMgr.RemoveRoutes(ifaceName, allAllowedIPs, cfg.IsFullTunnel())

	// DNS
	_ = m.netMgr.RestoreDNS(ifaceName)

	// TUN
	engine.Close()

	// Network cleanup
	_ = m.netMgr.Cleanup(ifaceName)

	// Clear crash-recovery state
	_ = ClearActiveState(m.dataDir)

	// PostDown script (non-fatal)
	if m.scriptsAllowed && cfg.Interface.PostDown != "" {
		slog.Info("running PostDown script", "cmd", cfg.Interface.PostDown)
		if err := runScript(cfg.Interface.PostDown); err != nil {
			slog.Warn("PostDown script failed", "error", err)
		}
	}

	slog.Info("tunnel disconnected", "name", cfg.Name)
}
