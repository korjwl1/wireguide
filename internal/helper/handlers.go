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
	prevCfg := h.activeCfg
	h.activeCfg = req.Config
	h.mu.Unlock()

	if err := h.manager.Connect(req.Config); err != nil {
		h.mu.Lock()
		h.activeCfg = prevCfg
		h.mu.Unlock()
		return nil, err
	}
	return ipc.Empty{}, nil
}

func (h *Helper) handleDisconnect(params json.RawMessage) (interface{}, error) {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	// Cancel any in-flight reconnect backoff first — otherwise the monitor
	// could wake up seconds after the user clicked Disconnect and re-connect
	// against their wishes.
	if h.monitor != nil {
		h.monitor.CancelRetry()
	}
	if err := h.manager.Disconnect(); err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.activeCfg = nil
	h.mu.Unlock()
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
		// Get interface addresses from the active config for anti-spoof chains
		var ifaceAddresses []string
		h.mu.Lock()
		if h.activeCfg != nil {
			ifaceAddresses = h.activeCfg.Interface.Address
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
