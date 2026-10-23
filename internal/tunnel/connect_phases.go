package tunnel

import (
	"context"
	"log/slog"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
)

// connectPhases executes the steps that bring a tunnel up. Called from
// Manager.ConnectWithContext outside the manager's mutex. Returns the engine on
// success, or an error after rolling back any partial state on failure.
//
// Steps:
//  1. Create WireGuard engine (TUN + wgctrl device)
//  2. Set MTU
//  3. Assign address
//  4. Bring interface up
//  5. Install routes (incl. endpoint bypass for every peer)
//  6. Apply explicitly configured DNS (failure rolls back)
//  7. Persist crash-recovery state (only after everything else succeeds)
//
// Note: Pre/PostUp/Down script execution was removed as a security hardening
// measure. The config parser still accepts these fields so existing configs
// import without error, but the scripts are silently ignored.
func (m *Manager) connectPhases(ctx context.Context, cfg *domain.WireGuardConfig, netMgr network.NetworkManager) (*Engine, error) {
	if validator, ok := netMgr.(interface{ ValidateDNSConfig([]string) error }); ok {
		if err := validator.ValidateDNSConfig(cfg.Interface.DNS); err != nil {
			return nil, newTunnelError(ErrNetwork, "validating DNS support", err)
		}
	}

	// Compute fullTunnel early — needed by the rollback closure and later
	// by AddRoutes. It only depends on cfg which is a parameter.
	fullTunnel := cfg.IsFullTunnel()
	var allAllowedIPs []string
	for _, peer := range cfg.Peers {
		allAllowedIPs = append(allAllowedIPs, peer.AllowedIPs...)
	}

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
	if err := m.prepareInterfaceDNS(ifaceName); err != nil {
		// Nothing has been configured yet. Preserve the former owner's
		// journal and retry entry; rollback of the new owner could erase it.
		engine.Close()
		return nil, newTunnelError(ErrNetwork, "removing previous interface DNS", err)
	}

	// Record interface ownership before the first OS mutation, including
	// failures that happen before the precise pre-DNS checkpoint.
	if err := SaveActiveState(m.dataDir, &ActiveTunnelState{TunnelName: cfg.Name, InterfaceName: ifaceName, FullTunnel: fullTunnel, Table: cfg.Interface.Table, FwMark: cfg.Interface.FwMark}); err != nil {
		engine.Close()
		return nil, newTunnelError(ErrNetwork, "persisting interface recovery state", err)
	}
	rollback := func(primary error) error { return m.rollbackConnect(cfg, engine, netMgr, primary) }

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

	// 5.8 Re-evaluate Windows socket binding before installing routes.
	// The guarded bind applies the initial interface during Open, before
	// the first handshake. IP_UNICAST_IF constrains outer-packet routing
	// to that underlay; no underlay means dropped sends. A failed bind
	// fails Connect, rather than leaving an unprotected socket running.
	var pinErr error
	engine.SocketPinV4, engine.SocketPinV6, pinErr = pinSocketToPhysical(engine.bind, ifaceName)
	if pinErr != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "protecting WireGuard UDP sockets", pinErr))
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
	endpointIPs := engine.ResolvedEndpointIPs()
	var allowEndpointTraffic func(bool)
	networkOwnsTrafficGate := false
	if guard, ok := engine.bind.(interface{ SetEndpointTrafficAllowed(bool) }); ok {
		allowEndpointTraffic = guard.SetEndpointTrafficAllowed
		if setter, ok := netMgr.(network.EndpointTrafficGuardSetter); ok {
			setter.SetEndpointTrafficGuard(allowEndpointTraffic)
			networkOwnsTrafficGate = true
		}
		allowEndpointTraffic(false)
	}
	if err := netMgr.AddRoutes(ifaceName, allAllowedIPs, fullTunnel, endpointIPs, cfg.Interface.Table, cfg.Interface.FwMark); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "adding routes", err))
	}
	if checker, ok := netMgr.(network.EndpointLoopChecker); ok {
		reason, err := checker.EndpointRoutingLoop(endpointIPs)
		if err != nil {
			return nil, rollback(newTunnelError(ErrNetwork, "verifying endpoint routes", err))
		}
		if reason != "" {
			return nil, rollback(newTunnelError(ErrNetwork, reason, nil))
		}
	}
	// A network-owned gate is reopened by its checker while holding the
	// route lock. Reopening it here could override a subsequent repair.
	if allowEndpointTraffic != nil && !networkOwnsTrafficGate {
		allowEndpointTraffic(true)
	}
	if err := checkCtx(); err != nil {
		return nil, err
	}
	var endpointRoutes []string
	if provider, ok := netMgr.(network.EndpointRouteStateProvider); ok {
		endpointRoutes = provider.InstalledEndpointRoutes()
	}

	// 7. DNS — fatal when DNS servers are explicitly configured (matching
	// wg-quick's behaviour). A silent DNS failure leaves the user on their
	// ISP's resolver, which is a privacy leak for VPN users.
	//
	// When multiple tunnels are active, we apply the UNION of all tunnels'
	// DNS servers so a second tunnel doesn't overwrite the first's DNS.
	//
	// Split-DNS tunnels (any "~domain" token) never take part in the union:
	// they install their own supplemental resolver and leave system DNS alone.
	splitDNS := cfg.Interface.IsSplitDNS()
	dnsMode := dnsModeFor(cfg)
	dnsServers := cfg.Interface.DNS
	if len(dnsServers) > 0 && !splitDNS {
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
	state := ActiveTunnelState{
		TunnelName:     cfg.Name,
		InterfaceName:  ifaceName,
		DNSServers:     cfg.Interface.DNS,
		DNSMode:        dnsMode,
		FullTunnel:     fullTunnel,
		Table:          cfg.Interface.Table,
		FwMark:         cfg.Interface.FwMark,
		EndpointRoutes: endpointRoutes,
	}
	// The adapter checkpoints its captured original DNS before its first
	// write, including services discovered later during route repair.
	if setter, ok := netMgr.(network.DNSCheckpointSetter); ok && dnsMode == DNSModeGlobal {
		setter.SetDNSCheckpoint(func(snapshot network.DNSSnapshot) error {
			return m.persistDNSCheckpoint(state, snapshot)
		})
	}
	if err := SaveActiveState(m.dataDir, &state); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "persisting pre-DNS recovery state", err))
	}

	if err := netMgr.SetDNS(ifaceName, dnsServers); err != nil {
		if len(cfg.Interface.DNS) > 0 {
			return nil, rollback(newTunnelError(ErrNetwork, "setting DNS", err))
		}
		slog.Warn("failed to set DNS", "error", err)
	}

	if !splitDNS && len(dnsServers) > 0 {
		m.trackDNSUnion(dnsServers)
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
	var preMod network.DNSSnapshot
	if provider, ok := netMgr.(network.DNSSnapshotProvider); ok && dnsMode == DNSModeGlobal {
		preMod = provider.SavedDNSSnapshot()
		m.CapturePreModDNS(preMod)
		if original, captured := m.PreModDNSSnapshot(); captured {
			preMod = original
		}
	}

	if err := SaveActiveState(m.dataDir, &ActiveTunnelState{
		TunnelName:     cfg.Name,
		InterfaceName:  ifaceName,
		DNSServers:     cfg.Interface.DNS,
		DNSMode:        dnsMode,
		FullTunnel:     fullTunnel,
		Table:          cfg.Interface.Table,
		FwMark:         cfg.Interface.FwMark,
		EndpointRoutes: endpointRoutes,
		PreModDNS:      preMod.Servers,
		PreModSearch:   preMod.Search,
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
// from Manager.Disconnect outside the manager's mutex. All steps are best-effort
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

	// Split-DNS keys live in the dynamic store, outside Cleanup's
	// RestoreDNS path when other global-DNS tunnels remain (Cleanup is
	// skipped entirely then), so remove them for THIS tunnel unconditionally.
	var splitCleanupErr error
	if cfg.Interface.IsSplitDNS() {
		splitCleanupErr = m.removeSplitDNS(cfg.Name, netMgr, ifaceName)
	}

	// Check if other tunnels remain connected BEFORE cleanup.
	remainingDNS := m.AllDNSServers()
	hasOtherTunnels := len(remainingDNS) > 0

	// A failed restore retains both its baseline and recovery journal.
	var cleanupErr error
	if netMgr != nil {
		if hasOtherTunnels {
			if remover, ok := netMgr.(network.InterfaceDNSRemover); ok {
				cleanupErr = remover.RemoveInterfaceDNS(ifaceName)
			}
		} else {
			cleanupErr = m.cleanupNetwork(netMgr, ifaceName)
			if cleanupErr == nil {
				m.clearRecoveredBaseline()
			}
		}
		if cleanupErr != nil {
			m.queueNetworkCleanup(cfg.Name, ifaceName, netMgr, cleanupErr)
			slog.Warn("disconnect: network recovery pending", "iface", ifaceName, "error", cleanupErr)
		}
	}

	// If other tunnels remain, re-apply their DNS union via one of the
	// remaining tunnels' netMgr instances.
	// A split tunnel never contributed to that union, so its disconnect
	// changes nothing for the others.
	if hasOtherTunnels && !cfg.Interface.IsSplitDNS() {
		m.trackDNSUnion(remainingDNS)
		m.mu.Lock()
		var remainingNetMgr network.NetworkManager
		var remainingIface string
		for _, e := range m.tunnels {
			if e.state == domain.StateConnected && e.engine != nil && e.cfg != nil && e.cfg.Name != cfg.Name && e.netMgr != nil && !e.cfg.Interface.IsSplitDNS() {
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
	if splitCleanupErr == nil && cleanupErr == nil {
		if err := ClearActiveState(m.dataDir, cfg.Name); err != nil {
			slog.Warn("disconnect: ClearActiveState failed", "tunnel", cfg.Name, "error", err)
		}
	}

	slog.Info("tunnel disconnected", "name", cfg.Name,
		"total_ms", time.Since(t0).Milliseconds())
}

// dnsModeFor classifies a config's DNS handling for the crash-recovery
// journal: "split" (supplemental resolver only), "global" (system DNS
// override) or "" (the tunnel never touches DNS).
func dnsModeFor(cfg *domain.WireGuardConfig) string {
	switch {
	case cfg.Interface.IsSplitDNS():
		return DNSModeSplit
	case len(cfg.Interface.DNS) > 0:
		return DNSModeGlobal
	}
	return ""
}

// removeSplitDNS removes a tunnel's split-DNS state if the platform manager
// keeps any. Idempotent and best-effort.
func (m *Manager) removeSplitDNS(name string, netMgr network.NetworkManager, ifaceName string) error {
	r, ok := netMgr.(network.SplitDNSRemover)
	if !ok {
		return nil
	}
	if err := r.RemoveSplitDNS(ifaceName); err != nil {
		slog.Warn("RemoveSplitDNS failed", "iface", ifaceName, "error", err)
		m.mu.Lock()
		if m.pendingDNSCleanup == nil {
			m.pendingDNSCleanup = make(map[string]pendingDNSCleanup)
		}
		m.pendingDNSCleanup[ifaceName] = pendingDNSCleanup{name: name, remover: r}
		m.mu.Unlock()
		return err
	}
	return nil
}
