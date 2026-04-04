package tunnel

import (
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/network"
)

// Manager orchestrates tunnel lifecycle: connect, disconnect, status.
type Manager struct {
	mu          sync.Mutex
	engine      *Engine
	netMgr      network.NetworkManager
	dataDir     string
	activeCfg   *config.WireGuardConfig
	connectedAt time.Time
	// scriptsAllowed tracks whether user approved running Pre/PostUp scripts
	scriptsAllowed bool
}

// NewManager creates a tunnel manager.
func NewManager(dataDir string) *Manager {
	return &Manager{
		netMgr:  network.NewPlatformManager(),
		dataDir: dataDir,
	}
}

// Connect establishes a WireGuard tunnel.
func (m *Manager) Connect(cfg *config.WireGuardConfig, scriptsAllowed bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.engine != nil {
		return fmt.Errorf("tunnel %s is already connected", m.activeCfg.Name)
	}

	m.scriptsAllowed = scriptsAllowed

	// Run PreUp script
	if scriptsAllowed && cfg.Interface.PreUp != "" {
		slog.Info("running PreUp script", "cmd", cfg.Interface.PreUp)
		if err := runScript(cfg.Interface.PreUp); err != nil {
			return fmt.Errorf("PreUp script failed: %w", err)
		}
	}

	// Create WireGuard engine (TUN + WG device)
	engine, err := NewEngine(cfg)
	if err != nil {
		return fmt.Errorf("creating engine: %w", err)
	}

	ifaceName := engine.InterfaceName()

	// Configure networking
	mtu := cfg.Interface.MTU
	if mtu <= 0 {
		mtu = 1420
	}
	if err := m.netMgr.SetMTU(ifaceName, mtu); err != nil {
		engine.Close()
		return fmt.Errorf("setting MTU: %w", err)
	}

	if err := m.netMgr.AssignAddress(ifaceName, cfg.Interface.Address); err != nil {
		engine.Close()
		return fmt.Errorf("assigning address: %w", err)
	}

	if err := m.netMgr.BringUp(ifaceName); err != nil {
		engine.Close()
		return fmt.Errorf("bringing up interface: %w", err)
	}

	// Collect all AllowedIPs and determine endpoint for routing
	var allAllowedIPs []string
	var endpoint string
	for _, peer := range cfg.Peers {
		allAllowedIPs = append(allAllowedIPs, peer.AllowedIPs...)
		if peer.Endpoint != "" {
			endpoint = peer.Endpoint
		}
	}

	fullTunnel := cfg.IsFullTunnel()
	if err := m.netMgr.AddRoutes(ifaceName, allAllowedIPs, fullTunnel, endpoint); err != nil {
		engine.Close()
		return fmt.Errorf("adding routes: %w", err)
	}

	if err := m.netMgr.SetDNS(ifaceName, cfg.Interface.DNS); err != nil {
		slog.Warn("failed to set DNS", "error", err)
		// Non-fatal: continue without DNS
	}

	// Save crash recovery state
	SaveActiveState(m.dataDir, &ActiveTunnelState{
		TunnelName:    cfg.Name,
		InterfaceName: ifaceName,
		FullTunnel:    fullTunnel,
	})

	// Run PostUp script
	if scriptsAllowed && cfg.Interface.PostUp != "" {
		slog.Info("running PostUp script", "cmd", cfg.Interface.PostUp)
		if err := runScript(cfg.Interface.PostUp); err != nil {
			slog.Warn("PostUp script failed", "error", err)
		}
	}

	m.engine = engine
	m.activeCfg = cfg
	m.connectedAt = time.Now()

	slog.Info("tunnel connected",
		"name", cfg.Name,
		"interface", ifaceName,
		"full_tunnel", fullTunnel)

	return nil
}

// Disconnect tears down the active tunnel.
func (m *Manager) Disconnect() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.engine == nil {
		return fmt.Errorf("no tunnel is connected")
	}

	cfg := m.activeCfg
	ifaceName := m.engine.InterfaceName()

	// Run PreDown script
	if m.scriptsAllowed && cfg.Interface.PreDown != "" {
		slog.Info("running PreDown script", "cmd", cfg.Interface.PreDown)
		if err := runScript(cfg.Interface.PreDown); err != nil {
			slog.Warn("PreDown script failed", "error", err)
		}
	}

	// Remove routes
	var allAllowedIPs []string
	for _, peer := range cfg.Peers {
		allAllowedIPs = append(allAllowedIPs, peer.AllowedIPs...)
	}
	m.netMgr.RemoveRoutes(ifaceName, allAllowedIPs, cfg.IsFullTunnel())

	// Restore DNS
	m.netMgr.RestoreDNS(ifaceName)

	// Close WireGuard engine (closes TUN)
	m.engine.Close()

	// Cleanup network state
	m.netMgr.Cleanup(ifaceName)

	// Clear crash recovery state
	ClearActiveState(m.dataDir)

	// Run PostDown script
	if m.scriptsAllowed && cfg.Interface.PostDown != "" {
		slog.Info("running PostDown script", "cmd", cfg.Interface.PostDown)
		if err := runScript(cfg.Interface.PostDown); err != nil {
			slog.Warn("PostDown script failed", "error", err)
		}
	}

	slog.Info("tunnel disconnected", "name", cfg.Name)

	m.engine = nil
	m.activeCfg = nil
	m.connectedAt = time.Time{}

	return nil
}

// Status returns the current connection status.
func (m *Manager) Status() *ConnectionStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.engine == nil {
		return &ConnectionStatus{State: StateDisconnected}
	}

	status, err := GetStatus(m.engine.InterfaceName(), m.activeCfg.Name, m.connectedAt)
	if err != nil {
		slog.Warn("failed to get status", "error", err)
		return &ConnectionStatus{
			State:      StateError,
			TunnelName: m.activeCfg.Name,
		}
	}
	return status
}

// IsConnected returns true if a tunnel is active.
func (m *Manager) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.engine != nil
}

// ActiveTunnel returns the name of the currently connected tunnel, or "".
func (m *Manager) ActiveTunnel() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeCfg == nil {
		return ""
	}
	return m.activeCfg.Name
}

func runScript(command string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/C", command)
	default:
		cmd = exec.Command("sh", "-c", command)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}
