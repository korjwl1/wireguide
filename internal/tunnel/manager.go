// Package tunnel orchestrates WireGuard tunnel lifecycle.
//
// The package is split so each file has a single reason to change:
//   - manager.go         (this file)   — Manager struct, state machine, Connect/Disconnect/Status facade
//   - connect_phases.go                — the step-by-step Connect / Disconnect phases and rollback
//   - status.go                        — status type alias + GetStatus query (wgctrl)
//   - engine.go                        — wireguard-go + wgctrl TUN wiring
//   - conflict.go                      — existing-interface conflict detection
//   - recovery.go                      — crash recovery state file
//   - script_executor_unix.go          — Pre/PostUp/Down hooks (Unix)
//   - script_executor_windows.go       — Pre/PostUp/Down hooks (Windows)
package tunnel

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
)

// Manager orchestrates the tunnel lifecycle using a small state machine.
//
//	disconnected ──Connect──▶ connecting ──phases ok──▶ connected
//	                                    ──phases err─▶ disconnected
//	connected    ──Disconnect──▶ disconnecting ──▶ disconnected
//
// Manager.mu is held ONLY for state reads/writes, NEVER during the slow
// phase operations (ifconfig, route, networksetup, Pre/PostUp scripts).
// That keeps Status() / IsConnected() / ActiveTunnel() non-blocking even
// while a long-running Connect or Disconnect is in flight — critical so
// that the 1 Hz status broadcast loop in helper/events.go can surface
// "connecting" and "disconnecting" transitions to the GUI in real time,
// instead of stalling for 1–2 seconds and then flipping straight to
// "connected".
//
// Disconnect races with an in-progress Connect by polling the state every
// 100 ms for up to 10 s rather than fighting over the mutex.
type Manager struct {
	mu sync.Mutex

	state       domain.State
	engine      *Engine
	activeCfg   *domain.WireGuardConfig
	connectedAt time.Time
	// scriptsAllowed tracks whether the user approved running Pre/PostUp scripts.
	scriptsAllowed bool

	netMgr  network.NetworkManager
	dataDir string
}

// Additional transient states used internally. Exposed on the wire as the
// closest public state (connecting/disconnecting both surface as
// "connecting" since the GUI treats them the same way).
const (
	stateDisconnecting domain.State = "disconnecting"
)

// NewManager creates a tunnel manager.
func NewManager(dataDir string) *Manager {
	return &Manager{
		netMgr:  network.NewPlatformManager(),
		dataDir: dataDir,
		state:   domain.StateDisconnected,
	}
}

// setStateLocked mutates state under the lock. Caller MUST hold m.mu.
// Kept as a helper so future additions (logging, metrics) have one place
// to hook.
func (m *Manager) setStateLocked(s domain.State) {
	m.state = s
}

// Connect establishes a WireGuard tunnel. Runs the expensive phase work
// WITHOUT holding m.mu, so Status / IsConnected / ActiveTunnel stay
// responsive for the duration.
func (m *Manager) Connect(cfg *domain.WireGuardConfig, scriptsAllowed bool) error {
	// --- Phase 1: claim the connecting slot under the lock ---
	m.mu.Lock()
	switch m.state {
	case domain.StateConnected:
		name := ""
		if m.activeCfg != nil {
			name = m.activeCfg.Name
		}
		m.mu.Unlock()
		return fmt.Errorf("tunnel %q is already connected", name)
	case domain.StateConnecting, stateDisconnecting:
		m.mu.Unlock()
		return fmt.Errorf("another transition is in progress")
	}
	// Stash the tunnel name early so Status() can show "connecting <name>"
	// while the phases are running.
	m.activeCfg = cfg
	m.scriptsAllowed = scriptsAllowed
	m.setStateLocked(domain.StateConnecting)
	m.mu.Unlock()

	// --- Phase 2: run the slow operations WITHOUT holding the lock ---
	engine, err := m.connectPhases(cfg, scriptsAllowed)

	// --- Phase 3: commit final state under the lock ---
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		// Phases failed — roll back to disconnected. connectPhases has
		// already cleaned up its partial network state via its internal
		// rollback helper.
		m.activeCfg = nil
		m.scriptsAllowed = false
		m.setStateLocked(domain.StateDisconnected)
		return err
	}
	// Re-validate state: a Disconnect may have landed while we were outside
	// the lock. If so, discard the engine we just created.
	if m.state != domain.StateConnecting {
		// A Disconnect landed while we were outside the lock.
		// Clean up the network state that connectPhases just installed.
		m.netMgr.RemoveRoutes(engine.InterfaceName(), nil, cfg.IsFullTunnel())
		m.netMgr.RestoreDNS(engine.InterfaceName())
		m.netMgr.Cleanup(engine.InterfaceName())
		engine.Close()
		m.activeCfg = nil
		m.scriptsAllowed = false
		m.setStateLocked(domain.StateDisconnected)
		return fmt.Errorf("connect aborted: state changed during setup")
	}
	m.engine = engine
	m.connectedAt = time.Now()
	m.setStateLocked(domain.StateConnected)
	return nil
}

// Disconnect tears down the active tunnel. Like Connect, runs the slow
// teardown work outside the lock. If a Connect is currently in progress,
// waits up to 10 seconds for it to finish rather than rejecting the user.
func (m *Manager) Disconnect() error {
	// --- Phase 1: wait for any in-flight transition to settle ---
	deadline := time.Now().Add(10 * time.Second)
	for {
		m.mu.Lock()
		if m.state != domain.StateConnecting && m.state != stateDisconnecting {
			break // lock still held, state is stable
		}
		m.mu.Unlock()
		if time.Now().After(deadline) {
			return fmt.Errorf("disconnect timeout: another transition is in progress")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// m.mu held here, state is Connected / Disconnected / Error.
	if m.state != domain.StateConnected {
		m.mu.Unlock()
		return fmt.Errorf("no tunnel is connected")
	}
	// Snapshot the handles we need outside the lock.
	engine := m.engine
	cfg := m.activeCfg
	scriptsAllowed := m.scriptsAllowed
	m.setStateLocked(stateDisconnecting)
	m.mu.Unlock()

	// --- Phase 2: slow teardown outside the lock ---
	m.disconnectPhases(cfg, engine, scriptsAllowed)

	// --- Phase 3: commit final state ---
	m.mu.Lock()
	m.engine = nil
	m.activeCfg = nil
	m.connectedAt = time.Time{}
	m.scriptsAllowed = false
	m.setStateLocked(domain.StateDisconnected)
	m.mu.Unlock()
	return nil
}

// Status returns the current connection status. Fast — only holds m.mu long
// enough to snapshot the state, then queries wgctrl (which talks to a unix
// socket) outside the lock. Safe to call at 1 Hz from the event broadcast
// loop even when a Connect / Disconnect is in flight.
func (m *Manager) Status() *ConnectionStatus {
	m.mu.Lock()
	state := m.state
	engine := m.engine
	var cfgName string
	if m.activeCfg != nil {
		cfgName = m.activeCfg.Name
	}
	connectedAt := m.connectedAt
	m.mu.Unlock()

	switch state {
	case domain.StateConnecting, stateDisconnecting:
		// Surface transient states as "connecting" on the wire — the GUI
		// already has CSS for that (yellow pulsing badge) and doesn't need
		// to distinguish between "bringing up" vs "tearing down".
		return &ConnectionStatus{
			State:      domain.StateConnecting,
			TunnelName: cfgName,
		}
	case domain.StateDisconnected:
		return &ConnectionStatus{State: domain.StateDisconnected}
	case domain.StateError:
		return &ConnectionStatus{State: domain.StateError, TunnelName: cfgName}
	}

	// StateConnected — talk to wgctrl without holding m.mu. If Disconnect
	// races us and closes the engine right now, the wgctrl call either
	// succeeds with stale data (harmless — next tick will show disconnected)
	// or errors out (we return a minimal "error" status).
	if engine == nil {
		return &ConnectionStatus{State: domain.StateDisconnected}
	}
	status, err := GetStatus(engine.InterfaceName(), cfgName, connectedAt)
	if err != nil {
		slog.Warn("failed to get status", "error", err)
		return &ConnectionStatus{State: domain.StateError, TunnelName: cfgName}
	}
	return status
}

// IsConnected returns true if a tunnel is fully established. Connecting /
// disconnecting are both considered "not yet connected" so that callers
// gating on this (e.g. the reconnect monitor's health check) don't do work
// on a tunnel that's half-up.
func (m *Manager) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state == domain.StateConnected
}

// ResolvedEndpointIPs returns the pre-resolved endpoint IP addresses from the
// active engine. Returns nil if no tunnel is connected.
func (m *Manager) ResolvedEndpointIPs() []string {
	m.mu.Lock()
	engine := m.engine
	m.mu.Unlock()
	if engine == nil {
		return nil
	}
	return engine.ResolvedEndpointIPs()
}

// ResolvedEndpoints returns the pre-resolved endpoint ip:port pairs from the
// active engine. Returns nil if no tunnel is connected.
func (m *Manager) ResolvedEndpoints() []string {
	m.mu.Lock()
	engine := m.engine
	m.mu.Unlock()
	if engine == nil {
		return nil
	}
	return engine.ResolvedEndpoints()
}

// ActiveTunnel returns the name of the currently connected (or connecting)
// tunnel, or "" if none. Returning the name during Connecting lets the GUI
// show "connecting <name>" rather than a blank placeholder.
func (m *Manager) ActiveTunnel() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeCfg == nil {
		return ""
	}
	return m.activeCfg.Name
}
