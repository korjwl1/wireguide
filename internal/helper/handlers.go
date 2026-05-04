package helper

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/tunnel"
	"github.com/korjwl1/wireguide/internal/update"
)

// registerHandlers binds every RPC method to a Helper method. Splitting the
// handlers into named methods (vs inline closures) makes them directly unit
// testable — `handler := &Helper{manager: mockMgr}; handler.handleConnect(...)`.
func (h *Helper) registerHandlers() {
	h.server.Handle(ipc.MethodPing, h.handlePing)
	h.server.Handle(ipc.MethodShutdown, h.handleShutdown)
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
}

func (h *Helper) handleSetLogLevel(params json.RawMessage) (interface{}, error) {
	var req ipc.SetLogLevelRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	lvl := parseLevel(req.Level)
	h.logLevel.Set(lvl)
	slog.Info("log level changed", "level", req.Level)
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

	// Sync any cached state that uses the old name. The tunnel is not
	// active per the check above, so activeCfgs shouldn't carry it, but
	// we keep this defensive in case a future flow caches inactive cfgs.
	h.mu.Lock()
	if cfg, ok := h.activeCfgs[req.OldName]; ok {
		delete(h.activeCfgs, req.OldName)
		if cfg != nil {
			cfg.Name = req.NewName
		}
		h.activeCfgs[req.NewName] = cfg
	}
	if owner, ok := h.autoConnectedBy[req.OldName]; ok {
		delete(h.autoConnectedBy, req.OldName)
		h.autoConnectedBy[req.NewName] = owner
	}
	h.mu.Unlock()
	return ipc.Empty{}, nil
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
	if conflicts, err := tunnel.CheckConflicts(allowedIPs); err == nil && len(conflicts) > 0 {
		for _, c := range conflicts {
			slog.Warn("routing conflict detected",
				"interface", c.InterfaceName,
				"owner", c.Owner,
				"overlaps", c.OverlappingIPs)
		}
	}

	// Cache the active config BEFORE dispatching to the manager, so that if
	// the reconnect monitor fires during Connect() it sees the new config
	// (not nil or the previous one). Roll back on failure.
	h.mu.Lock()
	prevCfgs := h.copyActiveCfgs()
	h.activeCfgs[req.Config.Name] = req.Config
	h.mu.Unlock()

	if err := h.manager.Connect(req.Config); err != nil {
		h.mu.Lock()
		delete(h.activeCfgs, req.Config.Name)
		// Restore previous if there was one
		if prev, ok := prevCfgs[req.Config.Name]; ok {
			h.activeCfgs[req.Config.Name] = prev
		}
		h.mu.Unlock()
		return nil, err
	}
	return ipc.Empty{}, nil
}

func (h *Helper) handleDisconnect(params json.RawMessage) (interface{}, error) {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	// Parse optional tunnel name from request.
	var tunnelName string
	if params != nil && len(params) > 0 {
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
		}
		if firstErr != nil {
			return nil, firstErr
		}
	}
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
	var req ipc.KillSwitchRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if req.Enabled {
		status := h.manager.Status()
		if status.State != tunnel.StateConnected {
			return nil, fmt.Errorf("no active tunnel")
		}
		// Use pre-resolved endpoints (resolved before tunnel routes were
		// installed). Doing DNS resolution here would fail because the kill
		// switch is about to block non-tunnel traffic and/or the query would
		// route through the tunnel itself.
		endpoints := h.manager.ResolvedEndpoints()
		if len(endpoints) == 0 {
			return nil, fmt.Errorf("no resolved endpoints available — tunnel may have disconnected")
		}
		// Get interface addresses from ALL active configs for anti-spoof chains.
		// With multiple tunnels, the kill switch must allow traffic from every
		// tunnel's interface addresses, not just the first one.
		var ifaceAddresses []string
		h.mu.Lock()
		for _, cfg := range h.activeCfgs {
			ifaceAddresses = append(ifaceAddresses, cfg.Interface.Address...)
		}
		h.mu.Unlock()
		if err := h.firewall.EnableKillSwitch(status.InterfaceName, ifaceAddresses, endpoints); err != nil {
			return nil, err
		}
	} else {
		if err := h.firewall.DisableKillSwitch(); err != nil {
			return nil, err
		}
	}
	return ipc.Empty{}, nil
}

func (h *Helper) handleSetDNSProtection(params json.RawMessage) (interface{}, error) {
	var req ipc.DNSProtectionRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if req.Enabled {
		status := h.manager.Status()
		if status.State != tunnel.StateConnected {
			return nil, fmt.Errorf("no active tunnel")
		}
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
	return ipc.Empty{}, nil
}

func (h *Helper) handleSetHealthCheck(params json.RawMessage) (interface{}, error) {
	var req ipc.SetHealthCheckRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if h.monitor != nil {
		h.monitor.SetHealthCheck(req.Enabled)
	}
	return ipc.Empty{}, nil
}

func (h *Helper) handleSetPinInterface(params json.RawMessage) (interface{}, error) {
	var req ipc.SetPinInterfaceRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	h.manager.SetPinInterface(req.Enabled)
	return ipc.Empty{}, nil
}
