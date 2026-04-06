package tunnel

import (
	"log/slog"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
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
	// Determine the intended interface name for %i expansion in PreUp.
	// The actual TUN device name is assigned by the OS in step 2, but we
	// need a value now. wg-quick uses the config filename; we use the
	// tunnel name which serves the same purpose.
	intendedIface := cfg.Name

	// 1. PreUp (fatal on failure — user opted in)
	if scriptsAllowed && cfg.Interface.PreUp != "" {
		slog.Info("running PreUp script", "cmd", cfg.Interface.PreUp)
		if err := runScriptWithInterface(cfg.Interface.PreUp, intendedIface); err != nil {
			return nil, newTunnelError(ErrScript, "PreUp script failed", err)
		}
	}

	// Compute fullTunnel early — needed by the rollback closure and later
	// by AddRoutes. It only depends on cfg which is a parameter.
	fullTunnel := cfg.IsFullTunnel()

	// 2. Engine
	engine, err := NewEngine(cfg)
	if err != nil {
		return nil, newTunnelError(ErrEngineCreation, "creating engine", err)
	}
	ifaceName := engine.InterfaceName()

	// rollback helper closes the engine and restores network state if any
	// later phase fails. Best-effort — we log rather than propagate cleanup
	// errors because we already have a primary failure to report.
	rollback := func(primary error) error {
		// Undo routes that may have been installed before the failure.
		if err := m.netMgr.RemoveRoutes(ifaceName, nil, fullTunnel); err != nil {
			slog.Warn("rollback: RemoveRoutes failed", "error", err)
		}
		_ = m.netMgr.Cleanup(ifaceName)
		engine.Close()
		// If PreUp was executed, run PostDown to undo its side effects.
		// PostDown is the correct counterpart: wg-quick runs PostDown after
		// teardown to reverse what PreUp set up.
		if scriptsAllowed && cfg.Interface.PostDown != "" {
			slog.Info("rollback: running PostDown script", "cmd", cfg.Interface.PostDown)
			if err := runScriptWithInterface(cfg.Interface.PostDown, ifaceName); err != nil {
				slog.Warn("rollback: PostDown script failed", "error", err)
			}
		}
		return primary
	}

	// 3. MTU — pass the user-configured value straight through. If it's 0
	// (unset), the platform adapter does wg-quick's upstream-MTU-minus-80
	// auto-detection. Do NOT default to 1420 here: that would shadow the
	// auto-detection and force the wrong MTU on links like PPPoE (1492)
	// or USB-tether (often 1500 but varies) or jumbo-frame LANs.
	if err := m.netMgr.SetMTU(ifaceName, cfg.Interface.MTU); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "setting MTU", err))
	}

	// 4. Address
	if err := m.netMgr.AssignAddress(ifaceName, cfg.Interface.Address); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "assigning address", err))
	}

	// 5. Bring up
	if err := m.netMgr.BringUp(ifaceName); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "bringing up interface", err))
	}

	// 6. Routes + endpoint bypass.
	//
	// If Table=off, the user wants to manage routing themselves — skip
	// route installation entirely, matching wg-quick behaviour.
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
	endpointIPs := engine.ResolvedEndpointIPs()
	if err := m.netMgr.AddRoutes(ifaceName, allAllowedIPs, fullTunnel, endpointIPs, cfg.Interface.Table, cfg.Interface.FwMark); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "adding routes", err))
	}

	// 7. DNS — fatal when DNS servers are explicitly configured (matching
	// wg-quick's behaviour). A silent DNS failure leaves the user on their
	// ISP's resolver, which is a privacy leak for VPN users.
	if err := m.netMgr.SetDNS(ifaceName, cfg.Interface.DNS); err != nil {
		if len(cfg.Interface.DNS) > 0 {
			return nil, rollback(newTunnelError(ErrNetwork, "setting DNS", err))
		}
		slog.Warn("failed to set DNS", "error", err)
	}

	// 8. PostUp (non-fatal — tunnel is already live)
	if scriptsAllowed && cfg.Interface.PostUp != "" {
		slog.Info("running PostUp script", "cmd", cfg.Interface.PostUp)
		if err := runScriptWithInterface(cfg.Interface.PostUp, ifaceName); err != nil {
			slog.Warn("PostUp script failed", "error", err)
		}
	}

	// 9. Crash recovery state — persisted AFTER all fallible phases so a
	// mid-connect failure doesn't leave an orphan state file pointing at a
	// tunnel that was never actually brought up. Non-fatal: if we can't
	// write the recovery file (disk full, permissions) the tunnel is still
	// up, we just won't be able to recover automatically next boot.
	// Capture pre-modification DNS snapshot for precise crash recovery.
	var preModDNS map[string][]string
	if provider, ok := m.netMgr.(network.DNSSnapshotProvider); ok {
		preModDNS = provider.SavedDNSSnapshot()
	}

	if err := SaveActiveState(m.dataDir, &ActiveTunnelState{
		TunnelName:    cfg.Name,
		InterfaceName: ifaceName,
		DNSServers:    cfg.Interface.DNS,
		FullTunnel:    fullTunnel,
		Table:         cfg.Interface.Table,
		FwMark:        cfg.Interface.FwMark,
		PreModDNS:     preModDNS,
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
func (m *Manager) disconnectPhases(cfg *domain.WireGuardConfig, engine *Engine, scriptsAllowed bool) {
	ifaceName := engine.InterfaceName()

	// PreDown script (non-fatal)
	if scriptsAllowed && cfg.Interface.PreDown != "" {
		slog.Info("running PreDown script", "cmd", cfg.Interface.PreDown)
		if err := runScriptWithInterface(cfg.Interface.PreDown, ifaceName); err != nil {
			slog.Warn("PreDown script failed", "error", err)
		}
	}

	// Routes
	var allAllowedIPs []string
	for _, peer := range cfg.Peers {
		allAllowedIPs = append(allAllowedIPs, peer.AllowedIPs...)
	}
	_ = m.netMgr.RemoveRoutes(ifaceName, allAllowedIPs, cfg.IsFullTunnel())

	// TUN
	engine.Close()

	// Network cleanup (also restores DNS internally)
	_ = m.netMgr.Cleanup(ifaceName)

	// Clear crash-recovery state
	_ = ClearActiveState(m.dataDir)

	// PostDown script (non-fatal)
	if scriptsAllowed && cfg.Interface.PostDown != "" {
		slog.Info("running PostDown script", "cmd", cfg.Interface.PostDown)
		if err := runScriptWithInterface(cfg.Interface.PostDown, ifaceName); err != nil {
			slog.Warn("PostDown script failed", "error", err)
		}
	}

	slog.Info("tunnel disconnected", "name", cfg.Name)
}
