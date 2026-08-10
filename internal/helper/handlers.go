package helper

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/update"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// registerHandlers binds every RPC method to a Helper method. Splitting the
// handlers into named methods (vs inline closures) makes them directly unit
// testable — `handler := &Helper{manager: mockMgr}; handler.handleConnect(...)`.
func (h *Helper) registerHandlers() {
	h.server.Handle(ipc.MethodPing, h.handlePing)
	h.server.Handle(ipc.MethodShutdown, h.handleShutdown)
	h.server.Handle(ipc.MethodForceShutdown, h.handleForceShutdown)
	h.server.Handle(ipc.MethodRequestQuit, h.handleRequestQuit)
	h.server.Handle(ipc.MethodSetLogLevel, h.handleSetLogLevel)
	h.server.Handle(ipc.MethodConnect, h.handleConnect)
	h.server.Handle(ipc.MethodDisconnect, h.handleDisconnect)
	h.server.Handle(ipc.MethodStatus, h.handleStatus)
	h.server.Handle(ipc.MethodIsConnected, h.handleIsConnected)
	h.server.Handle(ipc.MethodActiveName, h.handleActiveName)
	h.server.Handle(ipc.MethodActiveTunnels, h.handleActiveTunnels)
	h.server.Handle(ipc.MethodRename, h.handleRename)
	h.server.Handle(ipc.MethodSetKillSwitch, h.handleSetKillSwitch)
	h.server.Handle(ipc.MethodSetDNSProtection, h.handleSetDNSProtection)
	h.server.Handle(ipc.MethodSetHealthCheck, h.handleSetHealthCheck)
	h.server.Handle(ipc.MethodSetPinInterface, h.handleSetPinInterface)
	h.server.Handle(ipc.MethodReportSSID, h.handleReportSSID)
	h.server.Handle(ipc.MethodAutomationPreview, h.handleAutomationPreview)
}

func (h *Helper) handleSetLogLevel(params json.RawMessage) (interface{}, error) {
	var req ipc.SetLogLevelRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	lvl := parseLevel(req.Level)
	h.logLevel.Set(lvl)
	slog.Info("log level changed", "level", req.Level)
	h.server.Broadcast(ipc.EventSettingsChanged, ipc.SettingsChangedPayload{LogLevel: &req.Level})
	return ipc.Empty{}, nil
}

func (h *Helper) handlePing(params json.RawMessage) (interface{}, error) {
	return ipc.PingResponse{Version: ipc.ProtocolVersion, AppVersion: update.CurrentVersion(), PID: os.Getpid()}, nil
}

func (h *Helper) handleShutdown(params json.RawMessage) (interface{}, error) {
	go func() {
		time.Sleep(100 * time.Millisecond) // let the response go out first
		h.shutdown()
	}()
	return ipc.Empty{}, nil
}

// handleRequestQuit implements `wireguide ctl stop` — bring the whole app
// down, GUI included.
//
// Two cases, because "stop" has to mean the same thing either way:
//
//   - A GUI is attached: broadcast EventQuit and let the GUI terminate
//     itself. Its normal quit path disconnects tunnels and then stops us.
//     We must NOT shut down directly here — the GUI's health monitor would
//     see the helper vanish and respawn it, which on macOS means an admin
//     password prompt seconds after the user asked everything to stop.
//
//   - No GUI attached (helper running solo): nothing will relay the quit,
//     so shut ourselves down on the same grace-free path as MethodShutdown.
//
// Reports which branch ran so `ctl stop` can tell the user whether it
// stopped an app or just a stray helper.
func (h *Helper) handleRequestQuit(params json.RawMessage) (interface{}, error) {
	if h.server.HasControlConn() {
		slog.Info("quit requested via CLI — asking the GUI to terminate")
		h.server.Broadcast(ipc.EventQuit, ipc.Empty{})
		return ipc.RequestQuitResponse{NotifiedGUI: true}, nil
	}
	slog.Info("quit requested via CLI — no GUI attached, shutting the helper down")
	go func() {
		time.Sleep(100 * time.Millisecond) // let the response go out first
		h.shutdown()
	}()
	return ipc.RequestQuitResponse{NotifiedGUI: false}, nil
}

// handleForceShutdown bypasses graceful teardown and exits as fast as
// possible. Used by the GUI's upgrade path when MethodShutdown failed
// (wedged handler, stale state).
//
// We still do a minimum-effort firewall cleanup before exit:
//   - macOS: pf anchors persist past process death, so leaving the kill
//     switch up would lock the user out of the internet.
//   - Linux: nftables wireguide table persists in the kernel, same risk.
//   - Windows: WFP dynamic-session filters are auto-deleted by BFE when
//     the process dies (FWPM_SESSION_FLAG_DYNAMIC contract), so the
//     Cleanup call here is a no-op on the kernel side — still cheap.
//
// Tunnels themselves (TUN device + wireguard-go) are NOT torn down — the
// utun/wg interface disappears when the process dies on Unix, and Wintun
// adapters get cleaned up by our cleanupStaleWintunAdapter on next launch.
// The whole sequence is bounded by a 1-second deadline so a wedged
// firewall.Cleanup can't keep ForceShutdown hostage.
func (h *Helper) handleForceShutdown(params json.RawMessage) (interface{}, error) {
	go func() {
		// First, give the response 50ms to actually reach the client.
		// Then run firewall cleanup with a 1s hard cap, then exit.
		time.Sleep(50 * time.Millisecond)
		slog.Warn("helper ForceShutdown requested, cleaning firewall then exiting")
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := h.firewall.Cleanup(); err != nil {
				slog.Warn("ForceShutdown: firewall.Cleanup failed", "error", err)
			}
			// The utun devices die with this process, but networksetup DNS
			// overrides persist in SystemConfiguration — restore them or a
			// helper upgrade while connected leaves tunnel DNS behind
			// (issue #34). Best-effort under the same deadline.
			if h.manager != nil {
				h.manager.RestoreDNSBestEffort()
			}
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			slog.Warn("ForceShutdown: cleanup timed out; exiting anyway")
		}
		os.Exit(0)
	}()
	return ipc.Empty{}, nil
}

// handleRename atomically renames a tunnel's .conf file. Holds the same
// connectMu that handleConnect/handleDisconnect take, so a Connect arriving
// during the rename blocks until we finish — closing the GUI-side TOCTOU
// where the user could rename a tunnel just as it was being auto-connected.
//
// Active-tunnel rename is rejected: the WireGuard interface name is derived
// from the tunnel name on macOS, so renaming would orphan the running utun.
func (h *Helper) handleRename(params json.RawMessage) (interface{}, error) {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	var req ipc.RenameRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if req.OldName == "" || req.NewName == "" {
		return nil, fmt.Errorf("rename: old and new names are required")
	}
	if req.OldName == req.NewName {
		return ipc.Empty{}, nil
	}

	// Reject if the tunnel is currently active. h.connectMu is held so
	// no Connect/Disconnect can race past this check.
	for _, name := range h.manager.ActiveTunnels() {
		if name == req.OldName {
			return nil, fmt.Errorf("cannot rename connected tunnel %q — disconnect first", req.OldName)
		}
	}

	if h.userTunnelStore == nil {
		return nil, fmt.Errorf("rename: helper has no user tunnel store (running as root without --uid?)")
	}
	if err := h.userTunnelStore.Rename(req.OldName, req.NewName); err != nil {
		return nil, err
	}

	// Sync activeCfgs under h.mu.
	h.mu.Lock()
	if cfg, ok := h.activeCfgs[req.OldName]; ok {
		delete(h.activeCfgs, req.OldName)
		if cfg != nil {
			cfg.Name = req.NewName
		}
		h.activeCfgs[req.NewName] = cfg
	}
	h.mu.Unlock()

	// Sync autoConnectedBy under h.wifiMu — separate from h.mu to preserve
	// lock ordering: wifiMu is acquired before connectMu inside handleSSIDChange,
	// so we must NOT hold both simultaneously here.
	h.wifiMu.Lock()
	if owner, ok := h.autoConnectedBy[req.OldName]; ok {
		delete(h.autoConnectedBy, req.OldName)
		h.autoConnectedBy[req.NewName] = owner
	}
	h.wifiMu.Unlock()

	// Move the cached latency under the new key so the old name doesn't
	// linger as an orphaned map entry (the sibling maps above are already
	// re-keyed; this one was missed).
	h.latencyMu.Lock()
	if lat, ok := h.latencyByTunnel[req.OldName]; ok {
		delete(h.latencyByTunnel, req.OldName)
		h.latencyByTunnel[req.NewName] = lat
	}
	h.latencyMu.Unlock()
	return ipc.Empty{}, nil
}

// doConnectHeld caches cfg BEFORE calling manager.Connect (so the reconnect
// monitor sees the config during Connect), then rolls back on failure.
// Caller MUST hold h.connectMu.
func (h *Helper) doConnectHeld(cfg *domain.WireGuardConfig) error {
	// A firewall cannot permit a not-yet-created tunnel interface, and a
	// pre-enabled base kill switch deliberately blocks DNS and WireGuard UDP.
	// This applies equally to nftables, PF, and WFP (and is fatal before Engine
	// creation when a peer endpoint is a hostname). Suspend it for the bounded
	// Connect transaction, then rebuild the complete permit set from every
	// active tunnel. A failed Connect restores the previous blockade too.
	restoreKillSwitch := h.firewall.IsKillSwitchEnabled()
	if restoreKillSwitch {
		if err := h.firewall.DisableKillSwitch(); err != nil {
			return fmt.Errorf("temporarily disable kill switch for connect: %w", err)
		}
	}

	h.mu.Lock()
	prevCfgs := h.copyActiveCfgs()
	h.activeCfgs[cfg.Name] = cfg
	h.mu.Unlock()

	if err := h.manager.Connect(cfg); err != nil {
		h.mu.Lock()
		delete(h.activeCfgs, cfg.Name)
		if prev, ok := prevCfgs[cfg.Name]; ok {
			h.activeCfgs[cfg.Name] = prev
		}
		h.mu.Unlock()
		if restoreKillSwitch {
			if restoreErr := h.enableKillSwitchForActiveTunnels(); restoreErr != nil {
				return fmt.Errorf("connect: %v; restore kill switch: %w", err, restoreErr)
			}
		}
		return err
	}

	if restoreKillSwitch {
		if err := h.enableKillSwitchForActiveTunnels(); err != nil {
			// Do not report a successful connection while the user's requested
			// blockade is absent. Roll the new tunnel back and make one last
			// attempt to restore the pre-connect kill-switch state.
			disconnectErr := h.manager.DisconnectTunnel(cfg.Name)
			h.mu.Lock()
			delete(h.activeCfgs, cfg.Name)
			if prev, ok := prevCfgs[cfg.Name]; ok {
				h.activeCfgs[cfg.Name] = prev
			}
			h.mu.Unlock()
			restoreErr := h.enableKillSwitchForActiveTunnels()
			h.maybeArmShutdownAfterTeardown("connect rolled back, no GUI attached")
			return fmt.Errorf("restore kill switch after connect: %v (disconnect rollback: %v; blockade restore: %v)",
				err, disconnectErr, restoreErr)
		}
	}
	return nil
}

// enableKillSwitchForActiveTunnels atomically rebuilds the kill-switch model
// from manager state. EnableKillSwitch installs the base set and the first
// tunnel, then AddKillSwitchTunnel folds in every remaining interface. With no
// active tunnel it intentionally installs the base blockade only.
//
// Caller MUST hold h.connectMu so Connect/Disconnect cannot invalidate the
// status snapshot while the firewall rules are being rebuilt.
func (h *Helper) enableKillSwitchForActiveTunnels() error {
	type activeTunnel struct {
		name          string
		interfaceName string
		addresses     []string
	}
	h.mu.Lock()
	activeCfgs := h.copyActiveCfgs()
	h.mu.Unlock()
	var active []activeTunnel
	for _, st := range h.manager.AllStatuses() {
		if st == nil || st.InterfaceName == "" {
			continue
		}
		var addresses []string
		if cfg := activeCfgs[st.TunnelName]; cfg != nil {
			addresses = append([]string(nil), cfg.Interface.Address...)
		}
		active = append(active, activeTunnel{name: st.TunnelName, interfaceName: st.InterfaceName, addresses: addresses})
	}

	if len(active) == 0 {
		return h.firewall.EnableKillSwitch("", nil, nil)
	}

	// Endpoints are already resolved by Engine before routes are installed.
	// Supplying the union to each tunnel is conservative and prevents a peer
	// belonging to another simultaneously active tunnel from being fenced out.
	endpoints := h.manager.ResolvedEndpoints()
	if err := h.firewall.EnableKillSwitch(active[0].interfaceName, active[0].addresses, endpoints); err != nil {
		return err
	}
	for _, tunnel := range active[1:] {
		if err := h.firewall.AddKillSwitchTunnel(tunnel.interfaceName, tunnel.addresses, endpoints); err != nil {
			_ = h.firewall.DisableKillSwitch()
			return fmt.Errorf("add tunnel %q to kill switch: %w", tunnel.name, err)
		}
	}
	return nil
}

func (h *Helper) handleConnect(params json.RawMessage) (interface{}, error) {
	// Serialize Connect calls so two GUIs can't race on activeCfg.
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	var req ipc.ConnectRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if req.Config == nil {
		return nil, fmt.Errorf("config is required")
	}
	// Re-validate config server-side (don't trust client).
	if result := config.Validate(req.Config); !result.IsValid() {
		return nil, fmt.Errorf("invalid config: %s", strings.Join(result.ErrorMessages(), "; "))
	}

	// Log if the config contains scripts — they are parsed but ignored.
	if req.Config.HasScripts() {
		slog.Info("config contains Pre/PostUp/Down scripts; ignoring (not supported in GUI client)",
			"tunnel", req.Config.Name)
	}

	// Check for routing conflicts with existing interfaces (Tailscale etc).
	// Log warnings but don't block — users can override via UI.
	var allowedIPs []string
	for _, peer := range req.Config.Peers {
		allowedIPs = append(allowedIPs, peer.AllowedIPs...)
	}
	if conflicts, err := diag.CheckConflicts(allowedIPs); err == nil && len(conflicts) > 0 {
		for _, c := range conflicts {
			slog.Warn("routing conflict detected",
				"interface", c.InterfaceName,
				"owner", c.Owner,
				"overlaps", c.OverlappingIPs)
		}
	}

	if err := h.doConnectHeld(req.Config); err != nil {
		return nil, err
	}

	h.applyPostConnectFirewall(req.Config)
	return ipc.Empty{}, nil
}

// applyPostConnectFirewall runs the firewall follow-up that must happen
// after a tunnel comes up, shared by manual (handleConnect) and
// automation (automationConnect) connects. Extracting it fixes a real
// gap: the automation engine called doConnectHeld directly, so a tunnel
// brought up by a rule while no GUI was running got NEITHER of these —
// and, worst case, could not pass traffic at all because an
// already-enabled kill switch never learned its endpoints (issue #12).
// Best-effort: logs and continues on error, exactly like manual connect.
func (h *Helper) applyPostConnectFirewall(cfg *domain.WireGuardConfig) {
	// Windows-only: auto-enable DNS protection on full-tunnel.
	//
	// Why Windows-specific: Windows' resolver does "smart multi-homed
	// name resolution" which queries the DNS servers on EVERY active
	// interface in parallel, leaking VPN-tunnel DNS queries to the
	// ISP's DNS at the same time. Even with a kill switch this is a
	// silent privacy leak. WFP DNS-port blocking is the documented
	// fix (see wireguard-windows netquirk.md).
	//
	// macOS and Linux don't have this leak — their resolvers honour
	// the tunnel-interface DNS exclusively when the route table sends
	// the query out the tunnel. Auto-enabling there would override
	// the user's explicit Settings.DNSProtection=false choice (the
	// v0.2.0 behaviour), so we leave non-Windows platforms alone.
	if runtime.GOOS == "windows" && cfg.IsFullTunnel() && len(cfg.Interface.DNS) > 0 {
		status := h.manager.Status()
		if status != nil && status.InterfaceName != "" {
			if err := h.firewall.EnableDNSProtection(status.InterfaceName, cfg.Interface.DNS); err != nil {
				slog.Warn("auto-DNS protection failed (full-tunnel)", "error", err)
			}
		}
	}

	// If the kill switch is already enabled (user toggled it on before
	// connecting, OR it's been on the whole time and we just brought up
	// another tunnel), fold the new tunnel's LUID + endpoints into the
	// existing WFP filter set. The base "block all" filter would
	// otherwise still drop the new tunnel's encapsulated UDP traffic
	// because the only "permit tunnel" filter still references whatever
	// LUID was current at Enable time.
	if h.firewall.IsKillSwitchEnabled() {
		status := h.manager.StatusFor(cfg.Name)
		ifaceName := ""
		if status != nil {
			ifaceName = status.InterfaceName
		}
		if ifaceName != "" {
			eps := h.manager.ResolvedEndpoints()
			if err := h.firewall.AddKillSwitchTunnel(ifaceName, cfg.Interface.Address, eps); err != nil {
				slog.Warn("AddKillSwitchTunnel after connect failed", "error", err)
			}
		}
	}
}

func (h *Helper) handleDisconnect(params json.RawMessage) (interface{}, error) {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	// Parse optional tunnel name from request. len() on a nil slice
	// returns 0, so the previous explicit `params != nil` check was
	// redundant (S1009).
	var tunnelName string
	if len(params) > 0 {
		var req ipc.DisconnectRequest
		if err := json.Unmarshal(params, &req); err == nil {
			tunnelName = req.TunnelName
		}
		// If unmarshal fails (e.g. empty params), disconnect first tunnel (backward compat).
	}

	// Cancel only the in-flight reconnect for the tunnel(s) being
	// torn down — a per-tunnel disconnect of A must not abort a
	// healthy retry for B.
	if h.monitor != nil {
		if tunnelName != "" {
			h.monitor.CancelRetryFor(tunnelName)
		} else {
			h.monitor.CancelRetry()
		}
	}

	// Snapshot interface names BEFORE disconnect so we can remove their
	// kill-switch permits after teardown. After DisconnectTunnel the
	// engine pointer (and its ifaceName) is gone.
	var ifaceSnapshot []string
	if h.firewall.IsKillSwitchEnabled() {
		for _, st := range h.manager.AllStatuses() {
			if st == nil || st.InterfaceName == "" {
				continue
			}
			if tunnelName != "" && st.TunnelName != tunnelName {
				continue
			}
			ifaceSnapshot = append(ifaceSnapshot, st.InterfaceName)
		}
	}

	if tunnelName != "" {
		if err := h.manager.DisconnectTunnel(tunnelName); err != nil {
			return nil, err
		}
		h.mu.Lock()
		delete(h.activeCfgs, tunnelName)
		h.mu.Unlock()
		h.wifiMu.Lock()
		delete(h.autoConnectedBy, tunnelName)
		h.wifiMu.Unlock()
		h.latencyMu.Lock()
		delete(h.latencyByTunnel, tunnelName)
		h.latencyMu.Unlock()
	} else {
		// Legacy "no name" path: tear down EVERY active tunnel via
		// per-tunnel calls so manager.Disconnect()'s "pick the first"
		// semantic doesn't leave half the snapshot still up while we
		// blanket-evict their cached configs. Each successful per-
		// tunnel disconnect drops its cache entry; partial failures
		// leave the still-up tunnels intact in activeCfgs so the
		// reconnect monitor can still recover them.
		toDisconnect := h.manager.ActiveTunnels()
		var firstErr error
		for _, name := range toDisconnect {
			if err := h.manager.DisconnectTunnel(name); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				slog.Warn("legacy disconnect: tunnel teardown failed",
					"tunnel", name, "error", err)
				continue
			}
			h.mu.Lock()
			delete(h.activeCfgs, name)
			h.mu.Unlock()
			h.wifiMu.Lock()
			delete(h.autoConnectedBy, name)
			h.wifiMu.Unlock()
			h.latencyMu.Lock()
			delete(h.latencyByTunnel, name)
			h.latencyMu.Unlock()
		}
		if firstErr != nil {
			return nil, firstErr
		}
	}

	// Strip the just-torn-down tunnels from the kill-switch filter set.
	// Best-effort: log failures but never block the disconnect response.
	for _, iface := range ifaceSnapshot {
		if err := h.firewall.RemoveKillSwitchTunnel(iface); err != nil {
			slog.Warn("RemoveKillSwitchTunnel after disconnect failed",
				"interface", iface, "error", err)
		}
	}
	h.maybeArmShutdownAfterTeardown("tunnel disconnected, no GUI attached")
	return ipc.Empty{}, nil
}

func (h *Helper) handleStatus(params json.RawMessage) (interface{}, error) {
	return h.statusDTO(), nil
}

func (h *Helper) handleIsConnected(params json.RawMessage) (interface{}, error) {
	return ipc.BoolResponse{Value: h.manager.IsConnected()}, nil
}

func (h *Helper) handleActiveName(params json.RawMessage) (interface{}, error) {
	return ipc.StringResponse{Value: h.manager.ActiveTunnel()}, nil
}

func (h *Helper) handleActiveTunnels(params json.RawMessage) (interface{}, error) {
	return ipc.ActiveTunnelsResponse{Names: h.manager.ActiveTunnels()}, nil
}

func (h *Helper) handleSetKillSwitch(params json.RawMessage) (interface{}, error) {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	var req ipc.KillSwitchRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if req.Enabled {
		// Enable should work regardless of tunnel state. If no tunnel is
		// active the firewall installs only the base "block everything
		// not explicitly allowed" set; once a tunnel connects,
		// handleConnect will call AddKillSwitchTunnel to fold its
		// LUID/endpoints in. This matches the user mental model of
		// "the kill switch is on the moment I flip the toggle" instead
		// of the old "kill switch can only be enabled while connected"
		// gate that surprised users into a half-state.
		if err := h.enableKillSwitchForActiveTunnels(); err != nil {
			return nil, err
		}
	} else {
		if err := h.firewall.DisableKillSwitch(); err != nil {
			return nil, err
		}
	}
	h.server.Broadcast(ipc.EventSettingsChanged, ipc.SettingsChangedPayload{KillSwitch: &req.Enabled})
	return ipc.Empty{}, nil
}

func (h *Helper) handleSetDNSProtection(params json.RawMessage) (interface{}, error) {
	var req ipc.DNSProtectionRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if req.Enabled {
		// Accept the toggle even with no active tunnel — the GUI persists
		// the preference and re-sends SetDNSProtection(true) via
		// applyFirewallSettings() after every successful connect. Without
		// a tunnel we have no interface to scope the "allow port 53"
		// permit to, so we just succeed silently and let the next connect
		// install the pf rules with the right interface + DNS list.
		if !h.manager.IsConnected() || len(req.DNSServers) == 0 {
			return ipc.Empty{}, nil
		}
		status := h.manager.Status()
		// DNS protection uses a single tunnel's interface name for the pf
		// rule. This is intentional: the pf rule blocks port 53 globally
		// and only allows it through the tunnel interface. With multiple
		// tunnels, using the first connected tunnel's interface is
		// sufficient because the DNS protection rule is a global "block
		// port 53 except on <tunnel_iface>" anchor — any tunnel interface
		// will work as the exception.
		if err := h.firewall.EnableDNSProtection(status.InterfaceName, req.DNSServers); err != nil {
			return nil, err
		}
	} else {
		if err := h.firewall.DisableDNSProtection(); err != nil {
			return nil, err
		}
	}
	h.server.Broadcast(ipc.EventSettingsChanged, ipc.SettingsChangedPayload{DNSProtection: &req.Enabled})
	return ipc.Empty{}, nil
}

func (h *Helper) handleSetHealthCheck(params json.RawMessage) (interface{}, error) {
	var req ipc.SetHealthCheckRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if h.monitor == nil {
		// Should be impossible — monitor is created unconditionally in Run().
		// If it's nil, helper init was broken; surface that instead of
		// pretending the setting was applied.
		return nil, fmt.Errorf("reconnect monitor not initialised")
	}
	h.monitor.SetHealthCheck(req.Enabled)
	h.server.Broadcast(ipc.EventSettingsChanged, ipc.SettingsChangedPayload{HealthCheck: &req.Enabled})
	return ipc.Empty{}, nil
}

func (h *Helper) handleSetPinInterface(params json.RawMessage) (interface{}, error) {
	var req ipc.SetPinInterfaceRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if err := h.manager.SetPinInterface(req.Enabled); err != nil {
		return nil, err
	}
	h.server.Broadcast(ipc.EventSettingsChanged, ipc.SettingsChangedPayload{PinInterface: &req.Enabled})
	return ipc.Empty{}, nil
}

// handleReportSSID receives the current SSID from the GUI process.
// On macOS 14+ the helper (root LaunchDaemon) cannot read SSID via
// CoreWLAN because Location Services permission is bundle-scoped; the
// GUI holds the permission and forwards changes here.
func (h *Helper) handleReportSSID(params json.RawMessage) (interface{}, error) {
	var req ipc.ReportSSIDRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if h.wifiMon == nil {
		// Should be impossible — wifiMon is created unconditionally in Run().
		// Surfacing the error lets the GUI know Wi-Fi rules won't fire,
		// instead of silently swallowing every SSID update.
		return nil, fmt.Errorf("wifi monitor not initialised")
	}
	// Stamp the gateway BEFORE ReportExternalSSID: its onChanged callback
	// re-evaluates automation synchronously, and the staleness check must
	// see the fresh stamp or it would invalidate the SSID we're delivering.
	gw := wifi.GatewayMAC()
	h.wifiMu.Lock()
	h.ssidStampGW = gw
	h.wifiMu.Unlock()
	h.wifiMon.ReportExternalSSID(req.SSID)
	return ipc.Empty{}, nil
}
