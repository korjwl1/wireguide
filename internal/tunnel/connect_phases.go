package tunnel

import (
	"context"
	"log/slog"
	"time"

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
func (m *Manager) connectPhases(ctx context.Context, cfg *domain.WireGuardConfig, netMgr network.NetworkManager) (*Engine, error) {
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
		if err := netMgr.Cleanup(ifaceName); err != nil {
			slog.Warn("rollback: network Cleanup failed", "iface", ifaceName, "error", err)
		}
		engine.Close()
		return primary
	}

	// checkCtx is the per-phase cancellation gate. The individual exec
	// helpers inside netMgr have their own bounded timeouts (cmdTimeout),
	// so a hard limit on each phase is still ~30s even when ctx isn't
	// cancelled. But if the GUI cancels mid-Connect (user clicked Cancel
	// or app is shutting down), we exit at the next phase boundary
	// instead of grinding through every remaining step.
	checkCtx := func() error {
		if err := ctx.Err(); err != nil {
			return rollback(newTunnelError(ErrCancelled, "connect cancelled mid-phase", err))
		}
		return nil
	}
	if err := checkCtx(); err != nil {
		return nil, err
	}

	// 3. MTU — pass the user-configured value straight through. If it's 0
	// (unset), the platform adapter does wg-quick's upstream-MTU-minus-80
	// auto-detection. Do NOT default to 1420 here: that would shadow the
	// auto-detection and force the wrong MTU on links like PPPoE (1492)
	// or USB-tether (often 1500 but varies) or jumbo-frame LANs.
	if err := netMgr.SetMTU(ifaceName, cfg.Interface.MTU); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "setting MTU", err))
	}
	if err := checkCtx(); err != nil {
		return nil, err
	}

	// 4. Address
	if err := netMgr.AssignAddress(ifaceName, cfg.Interface.Address); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "assigning address", err))
	}
	if err := checkCtx(); err != nil {
		return nil, err
	}

	// 5. Bring up
	if err := netMgr.BringUp(ifaceName); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "bringing up interface", err))
	}
	if err := checkCtx(); err != nil {
		return nil, err
	}

	// 5.5 Endpoint loop protection (Windows full-tunnel only on the
	// firewall side; nil-protector platforms are no-ops). Installed
	// BEFORE engine.Start() — the WG handshake goroutine fires its
	// first sendto immediately after Up(), and on Windows the kernel's
	// ALE flow cache locks in the first-packet decision (permit) for
	// the (local-port, peer-ip, peer-port) 5-tuple. If our BLOCK
	// filter isn't yet installed at that moment, the cached PERMIT
	// can let subsequent loop-recursed packets through even after the
	// BLOCK is installed seconds later. Mandatory ordering: install
	// the firewall *before* anything that could cause WireGuard to
	// transmit.
	if m.endpointProtector != nil && fullTunnel {
		eps := engine.ResolvedEndpoints()
		if err := m.endpointProtector.EnableEndpointProtection(ifaceName, eps); err != nil {
			return nil, rollback(newTunnelError(ErrNetwork, "installing endpoint loop protection", err))
		}
	}
	if err := checkCtx(); err != nil {
		return nil, err
	}

	// 5.7 Now it is safe to start the WireGuard device. This is what
	// transitions wireguard-go's goroutines into the running state
	// (kicks off the first handshake). See engine.go's NewEngine
	// comment for the ALE-flow-cache rationale; the firewall step
	// above is the precondition.
	if err := engine.Start(); err != nil {
		return nil, rollback(newTunnelError(ErrEngineCreation, "starting engine", err))
	}
	if err := checkCtx(); err != nil {
		return nil, err
	}

	// 5.8 Pin the WG UDP socket to the physical underlay's ifIndex
	// (IP_UNICAST_IF on Windows). This is the source-side loop firewall:
	// once pinned, the kernel skips its routing lookup for sends on
	// these sockets and goes straight out the chosen interface — so even
	// if wintun is the longest-prefix match for the peer endpoint in
	// the route table (loop scenario), the encrypted UDP never crosses
	// into wintun. Mirrors what wireguard-windows does in
	// tunnel/defaultroutemonitor.go.
	//
	// We do this here, AFTER engine.Start opened the sockets, AFTER
	// EnableEndpointProtection installed the per-flow/per-packet WFP
	// blocks, but BEFORE AddRoutes installs the /1 split. Order matters
	// because the bind picks "best non-tunnel default" — if /1 split is
	// already in, the lookup still correctly returns the physical NIC
	// (because /1 is via the tunnel adapter LUID, which we exclude),
	// but if the physical default was missing AND /1 isn't in yet,
	// pinning would blackhole. Doing it post-Start, pre-AddRoutes is
	// the safest window.
	engine.SocketPinV4, engine.SocketPinV6 = pinSocketToPhysical(engine.bind, ifaceName)

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
	if err := checkCtx(); err != nil {
		return nil, err
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
	//
	// Also stash the FIRST tunnel's snapshot at Manager scope —
	// when this is the only/first tunnel up, its netMgr.savedDNS
	// IS the original system DNS. Subsequent tunnels' snapshots
	// would already include this tunnel's overrides, so we
	// deliberately ignore them via CapturePreModDNS's first-write-
	// wins guard.
	var preModDNS map[string][]string
	if provider, ok := netMgr.(network.DNSSnapshotProvider); ok {
		preModDNS = provider.SavedDNSSnapshot()
		m.CapturePreModDNS(preModDNS)
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
	t0 := time.Now()
	logStep := func(step string, since time.Time) {
		slog.Info("disconnect step", "tunnel", cfg.Name, "step", step,
			"ms", time.Since(since).Milliseconds())
	}

	// Routes — remove only THIS tunnel's routes via its own netMgr.
	var allAllowedIPs []string
	for _, peer := range cfg.Peers {
		allAllowedIPs = append(allAllowedIPs, peer.AllowedIPs...)
	}
	if netMgr != nil {
		ts := time.Now()
		if err := netMgr.RemoveRoutes(ifaceName, allAllowedIPs, cfg.IsFullTunnel()); err != nil {
			slog.Warn("disconnect: RemoveRoutes failed", "iface", ifaceName, "error", err)
		}
		logStep("RemoveRoutes", ts)
	}

	// Endpoint loop protection — remove AFTER RemoveRoutes so the WFP
	// BLOCK is the last line of defence while the kernel route table
	// is still in the loop-prone /1-split state. On a clean disconnect
	// the route deletes always win, but DisableEndpointProtection here
	// guarantees no orphaned BLOCK survives a subsequent re-connect
	// against a different endpoint IP for the same interface name.
	if m.endpointProtector != nil {
		tsEP := time.Now()
		if err := m.endpointProtector.DisableEndpointProtection(ifaceName); err != nil {
			slog.Warn("disconnect: DisableEndpointProtection failed", "iface", ifaceName, "error", err)
		}
		logStep("DisableEndpointProtection", tsEP)
	}

	// On Windows the wintun adapter doesn't actually disappear when
	// engine.Close calls WintunCloseAdapter — it lingers for seconds
	// (sometimes indefinitely on certain Win11 + competing-driver
	// setups, e.g. with Tailscale also using wintun). During that
	// window Windows still treats the adapter as a viable metric-1
	// interface and forwards every DNS query through its now-dead
	// 8.8.8.8 binding, which is what the user sees as "VPN off →
	// internet permanently broken until I reconnect". Defang the
	// lingering adapter by clearing its DNS and bumping its metric
	// BEFORE we hand the close to wireguard-go.
	if netMgr != nil {
		if pc, ok := netMgr.(network.PreCloseCleaner); ok {
			tsPre := time.Now()
			pc.PreCloseAdapterCleanup(ifaceName)
			logStep("PreCloseAdapterCleanup", tsPre)
		}
	}

	// TUN
	tsEngine := time.Now()
	engine.Close()
	logStep("engine.Close", tsEngine)

	// Check if other tunnels remain connected BEFORE cleanup.
	remainingDNS := m.AllDNSServers()
	hasOtherTunnels := len(remainingDNS) > 0

	// Network cleanup — each tunnel has its own netMgr, so Cleanup only
	// affects this tunnel's state (route monitor, bypass routes, DNS snapshot).
	if netMgr != nil {
		if !hasOtherTunnels {
			// Last tunnel — restore the ORIGINAL system DNS (captured
			// when the first tunnel connected) rather than this
			// netMgr's own savedDNS, which for a non-first tunnel
			// would still hold the previous tunnel's DNS overrides.
			// Cleanup's internal RestoreDNS becomes a no-op because
			// RestoreDNSFromSnapshot clears dnsActive.
			if pre := m.PreModDNSSnapshot(); pre != nil {
				if r, ok := netMgr.(network.DNSStateRestorer); ok {
					if err := r.RestoreDNSFromSnapshot(pre); err != nil {
						slog.Warn("RestoreDNSFromSnapshot failed; falling back to per-netMgr restore", "error", err)
					}
				}
			}
			tsCleanup := time.Now()
			if err := netMgr.Cleanup(ifaceName); err != nil {
				slog.Warn("disconnect: network Cleanup failed", "iface", ifaceName, "error", err)
			}
			logStep("netMgr.Cleanup", tsCleanup)
			m.ClearPreModDNS()
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
	if err := ClearActiveState(m.dataDir, cfg.Name); err != nil {
		slog.Warn("disconnect: ClearActiveState failed", "tunnel", cfg.Name, "error", err)
	}

	slog.Info("tunnel disconnected", "name", cfg.Name,
		"total_ms", time.Since(t0).Milliseconds())
}
