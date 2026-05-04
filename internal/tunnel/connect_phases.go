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
// Steps:
//  1. Create WireGuard engine (TUN + wgctrl device)
//  2. Set MTU
//  3. Assign address
//  4. Bring interface up
//  5. Install routes (incl. endpoint bypass for every peer)
//  6. Apply DNS (best-effort)
//  7. Persist crash-recovery state (only after everything else succeeds)
//
// Note: Pre/PostUp/Down script execution was removed as a security hardening
// measure. The config parser still accepts these fields so existing configs
// import without error, but the scripts are silently ignored.
func (m *Manager) connectPhases(cfg *domain.WireGuardConfig, netMgr network.NetworkManager) (*Engine, error) {
	// Compute fullTunnel early — needed by the rollback closure and later
	// by AddRoutes. It only depends on cfg which is a parameter.
	fullTunnel := cfg.IsFullTunnel()

	// 2. Engine
	factory := m.engineFactory
	if factory == nil {
		factory = NewEngine
	}
	engine, err := factory(cfg)
	if err != nil {
		return nil, newTunnelError(ErrEngineCreation, "creating engine", err)
	}
	ifaceName := engine.InterfaceName()

	// rollback helper closes the engine and restores network state if any
	// later phase fails. Best-effort — we log rather than propagate cleanup
	// errors because we already have a primary failure to report.
	rollback := func(primary error) error {
		// Undo routes that may have been installed before the failure.
		if err := netMgr.RemoveRoutes(ifaceName, nil, fullTunnel); err != nil {
			slog.Warn("rollback: RemoveRoutes failed", "error", err)
		}
		_ = netMgr.Cleanup(ifaceName)
		engine.Close()
		return primary
	}

	// 3. MTU — pass the user-configured value straight through. If it's 0
	// (unset), the platform adapter does wg-quick's upstream-MTU-minus-80
	// auto-detection. Do NOT default to 1420 here: that would shadow the
	// auto-detection and force the wrong MTU on links like PPPoE (1492)
	// or USB-tether (often 1500 but varies) or jumbo-frame LANs.
	if err := netMgr.SetMTU(ifaceName, cfg.Interface.MTU); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "setting MTU", err))
	}

	// 4. Address
	if err := netMgr.AssignAddress(ifaceName, cfg.Interface.Address); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "assigning address", err))
	}

	// 5. Bring up
	if err := netMgr.BringUp(ifaceName); err != nil {
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
	if err := netMgr.AddRoutes(ifaceName, allAllowedIPs, fullTunnel, endpointIPs, cfg.Interface.Table, cfg.Interface.FwMark); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "adding routes", err))
	}

	// 7. DNS — fatal when DNS servers are explicitly configured (matching
	// wg-quick's behaviour). A silent DNS failure leaves the user on their
	// ISP's resolver, which is a privacy leak for VPN users.
	//
	// When multiple tunnels are active, we apply the UNION of all tunnels'
	// DNS servers so a second tunnel doesn't overwrite the first's DNS.
	dnsServers := cfg.Interface.DNS
	if len(dnsServers) > 0 {
		// Collect DNS from already-connected tunnels and merge.
		existingDNS := m.AllDNSServers()
		if len(existingDNS) > 0 {
			seen := make(map[string]struct{})
			var merged []string
			// New tunnel's DNS first, then existing.
			for _, d := range dnsServers {
				if _, ok := seen[d]; !ok {
					seen[d] = struct{}{}
					merged = append(merged, d)
				}
			}
			for _, d := range existingDNS {
				if _, ok := seen[d]; !ok {
					seen[d] = struct{}{}
					merged = append(merged, d)
				}
			}
			dnsServers = merged
		}
	}
	// Pre-DNS crash recovery checkpoint. The DNS modification phase
	// is the first step that leaves persistent state on disk (the
	// per-service DNS overrides written by `networksetup` survive a
	// helper crash). If the helper dies between SetDNS and the
	// FINAL state write below, the user is stuck on the tunnel's
	// DNS — this checkpoint guarantees crash recovery sees a state
	// file and falls back to ResetDNSToSystemDefault (which clears
	// the per-service overrides to DHCP defaults). Empty PreModDNS
	// triggers the fallback path in RecoverFromCrash.
	if err := SaveActiveState(m.dataDir, &ActiveTunnelState{
		TunnelName:    cfg.Name,
		InterfaceName: ifaceName,
		DNSServers:    cfg.Interface.DNS,
		FullTunnel:    fullTunnel,
		Table:         cfg.Interface.Table,
		FwMark:        cfg.Interface.FwMark,
	}); err != nil {
		slog.Warn("failed to persist pre-DNS crash recovery state", "error", err)
	}

	if err := netMgr.SetDNS(ifaceName, dnsServers); err != nil {
		if len(cfg.Interface.DNS) > 0 {
			return nil, rollback(newTunnelError(ErrNetwork, "setting DNS", err))
		}
		slog.Warn("failed to set DNS", "error", err)
	}

	// 8. Final state file with the precise per-service DNS snapshot
	// captured by SetDNS. Lets crash recovery restore exact prior
	// DNS instead of the blunt DHCP-defaults fallback.
	var preModDNS map[string][]string
	if provider, ok := netMgr.(network.DNSSnapshotProvider); ok {
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
func (m *Manager) disconnectPhases(cfg *domain.WireGuardConfig, engine *Engine, netMgr network.NetworkManager) {
	ifaceName := engine.InterfaceName()

	// Routes — remove only THIS tunnel's routes via its own netMgr.
	var allAllowedIPs []string
	for _, peer := range cfg.Peers {
		allAllowedIPs = append(allAllowedIPs, peer.AllowedIPs...)
	}
	if netMgr != nil {
		_ = netMgr.RemoveRoutes(ifaceName, allAllowedIPs, cfg.IsFullTunnel())
	}

	// TUN
	engine.Close()

	// Check if other tunnels remain connected BEFORE cleanup.
	remainingDNS := m.AllDNSServers()
	hasOtherTunnels := len(remainingDNS) > 0

	// Network cleanup — each tunnel has its own netMgr, so Cleanup only
	// affects this tunnel's state (route monitor, bypass routes, DNS snapshot).
	if netMgr != nil {
		if !hasOtherTunnels {
			// Last tunnel — full cleanup including DNS restore.
			_ = netMgr.Cleanup(ifaceName)
		}
	}

	// If other tunnels remain, re-apply their DNS union via one of the
	// remaining tunnels' netMgr instances.
	if hasOtherTunnels {
		m.mu.Lock()
		var remainingNetMgr network.NetworkManager
		var remainingIface string
		for _, e := range m.tunnels {
			if e.state == domain.StateConnected && e.engine != nil && e.cfg != nil && e.cfg.Name != cfg.Name && e.netMgr != nil {
				remainingNetMgr = e.netMgr
				remainingIface = e.engine.InterfaceName()
				break
			}
		}
		m.mu.Unlock()
		if remainingNetMgr != nil && remainingIface != "" {
			if err := remainingNetMgr.SetDNS(remainingIface, remainingDNS); err != nil {
				slog.Warn("failed to re-apply DNS for remaining tunnels", "error", err)
			}
		}
	}

	// Clear crash-recovery state for this specific tunnel
	_ = ClearActiveState(m.dataDir, cfg.Name)

	slog.Info("tunnel disconnected", "name", cfg.Name)
}
