// Package helper implements the privileged helper process.
// Runs as root/admin, accepts RPC calls from the GUI, manages tunnel + firewall.
package helper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// Helper holds the helper process state.
type Helper struct {
	server   *ipc.Server
	manager  *tunnel.Manager
	firewall firewall.FirewallManager
	monitor  *reconnect.Monitor

	mu             sync.Mutex
	activeCfg      *config.WireGuardConfig // cached for reconnect
	scriptsAllowed bool

	done chan struct{}
}

// Run starts the helper listening on addr. Blocks until shutdown.
// ownerUID: UID to chown socket to (Unix only, use -1 on Windows).
// dataDir: persistent data dir for crash recovery state.
func Run(addr string, ownerUID int, dataDir string) error {
	listener, err := ipc.Listen(addr, ownerUID)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	manager := tunnel.NewManager(dataDir)
	fw := firewall.NewPlatformFirewall()

	// Crash recovery
	if recovered := tunnel.RecoverFromCrash(dataDir); recovered != "" {
		slog.Warn("recovered from previous crash", "tunnel", recovered)
	}

	h := &Helper{
		server:   ipc.NewServer(listener),
		manager:  manager,
		firewall: fw,
		done:     make(chan struct{}),
	}

	// Reconnect monitor — uses cached config
	h.monitor = reconnect.NewMonitor(manager, func() error {
		h.mu.Lock()
		cfg := h.activeCfg
		allowed := h.scriptsAllowed
		h.mu.Unlock()
		if cfg == nil {
			return fmt.Errorf("no cached config for reconnect")
		}
		return manager.Connect(cfg, allowed)
	}, func(state reconnect.State) {
		h.server.Broadcast(ipc.EventReconnect, ipc.ReconnectStateDTO{
			Reconnecting: state.Reconnecting,
			Attempt:      state.Attempt,
			MaxAttempts:  state.MaxAttempts,
			NextRetry:    state.NextRetry,
		})
	}, reconnect.DefaultConfig())
	h.monitor.Start()

	// Register RPC handlers
	h.registerHandlers()

	// Auto-shutdown if GUI disconnects and doesn't reconnect within grace window
	h.server.OnDisconnect(func() {
		slog.Info("control connection lost, waiting for reconnect...")
		go func() {
			time.Sleep(10 * time.Second)
			slog.Info("no reconnect within grace window, shutting down")
			h.shutdown()
		}()
	})

	// Start event emitter (diff loop)
	go h.eventLoop()

	slog.Info("helper listening", "addr", addr, "pid", "daemon")

	// Serve (blocks until shutdown)
	err = h.server.Serve()
	h.cleanup()
	return err
}

func (h *Helper) registerHandlers() {
	h.server.Handle(ipc.MethodPing, func(params json.RawMessage) (interface{}, error) {
		return ipc.PingResponse{Version: ipc.ProtocolVersion}, nil
	})

	h.server.Handle(ipc.MethodShutdown, func(params json.RawMessage) (interface{}, error) {
		go func() {
			time.Sleep(100 * time.Millisecond) // let response go out first
			h.shutdown()
		}()
		return ipc.Empty{}, nil
	})

	h.server.Handle(ipc.MethodConnect, func(params json.RawMessage) (interface{}, error) {
		var req ipc.ConnectRequest
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err
		}
		if req.Config == nil {
			return nil, fmt.Errorf("config is required")
		}
		// Re-validate config server-side (don't trust client)
		if result := config.Validate(req.Config); !result.IsValid() {
			return nil, fmt.Errorf("invalid config: %s", result.ErrorMessages()[0])
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

		if err := h.manager.Connect(req.Config, req.ScriptsAllowed); err != nil {
			return nil, err
		}
		h.mu.Lock()
		h.activeCfg = req.Config
		h.scriptsAllowed = req.ScriptsAllowed
		h.mu.Unlock()
		return ipc.Empty{}, nil
	})

	h.server.Handle(ipc.MethodDisconnect, func(params json.RawMessage) (interface{}, error) {
		if err := h.manager.Disconnect(); err != nil {
			return nil, err
		}
		h.mu.Lock()
		h.activeCfg = nil
		h.mu.Unlock()
		return ipc.Empty{}, nil
	})

	h.server.Handle(ipc.MethodStatus, func(params json.RawMessage) (interface{}, error) {
		return h.statusDTO(), nil
	})

	h.server.Handle(ipc.MethodIsConnected, func(params json.RawMessage) (interface{}, error) {
		return ipc.BoolResponse{Value: h.manager.IsConnected()}, nil
	})

	h.server.Handle(ipc.MethodActiveName, func(params json.RawMessage) (interface{}, error) {
		return ipc.StringResponse{Value: h.manager.ActiveTunnel()}, nil
	})

	h.server.Handle(ipc.MethodSetKillSwitch, func(params json.RawMessage) (interface{}, error) {
		var req ipc.KillSwitchRequest
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err
		}
		if req.Enabled {
			status := h.manager.Status()
			if status.State != tunnel.StateConnected {
				return nil, fmt.Errorf("no active tunnel")
			}
			if err := h.firewall.EnableKillSwitch(status.InterfaceName, status.Endpoint); err != nil {
				return nil, err
			}
		} else {
			if err := h.firewall.DisableKillSwitch(); err != nil {
				return nil, err
			}
		}
		return ipc.Empty{}, nil
	})

	h.server.Handle(ipc.MethodSetDNSProtection, func(params json.RawMessage) (interface{}, error) {
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
	})
}

func (h *Helper) statusDTO() ipc.ConnectionStatusDTO {
	s := h.manager.Status()
	return ipc.ConnectionStatusDTO{
		State:         string(s.State),
		TunnelName:    s.TunnelName,
		InterfaceName: s.InterfaceName,
		RxBytes:       s.RxBytes,
		TxBytes:       s.TxBytes,
		LastHandshake: s.HandshakeAge,
		Duration:      s.Duration,
		Endpoint:      s.Endpoint,
	}
}

// eventLoop periodically broadcasts status changes.
// Uses JSON serialization for change detection (robust against field swaps).
func (h *Helper) eventLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastJSON []byte
	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			dto := h.statusDTO()
			currentJSON, err := json.Marshal(dto)
			if err != nil {
				continue
			}
			if !bytes.Equal(lastJSON, currentJSON) {
				lastJSON = currentJSON
				h.server.Broadcast(ipc.EventStatus, dto)
			}
		}
	}
}

func (h *Helper) shutdown() {
	h.server.Shutdown()
}

func (h *Helper) cleanup() {
	close(h.done)
	h.monitor.Stop()
	h.firewall.Cleanup()
	if h.manager.IsConnected() {
		h.manager.Disconnect()
	}
	slog.Info("helper shutdown complete")
}
