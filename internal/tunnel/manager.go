// Package tunnel orchestrates WireGuard tunnel lifecycle.
//
// The package is split so each file has a single reason to change:
//   - manager.go         (this file)   — Manager struct, state machine, Connect/Disconnect/Status facade
//   - connect_phases.go                — the step-by-step Connect / Disconnect phases and rollback
//   - status.go                        — status type alias + GetStatus query (wgctrl)
//   - engine.go                        — wireguard-go + wgctrl TUN wiring
//   - conflict.go                      — existing-interface conflict detection
//   - recovery.go                      — crash recovery state file
package tunnel

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
)

// tunnelEntry holds the state for a single tunnel within the multi-tunnel
// manager. Each entry has its own state machine, engine, config, and
// connected timestamp.
type tunnelEntry struct {
	state       domain.State
	engine      *Engine
	cfg         *domain.WireGuardConfig
	connectedAt time.Time
}

// Manager orchestrates the tunnel lifecycle using a small state machine
// per tunnel.
//
//	disconnected ──Connect──▶ connecting ──phases ok──▶ connected
//	                                    ──phases err─▶ disconnected
//	connected    ──Disconnect──▶ disconnecting ──▶ disconnected
//
// Manager.mu is held ONLY for state reads/writes, NEVER during the slow
// phase operations (ifconfig, route, networksetup).
// That keeps Status() / IsConnected() / ActiveTunnel() non-blocking even
// while a long-running Connect or Disconnect is in flight.
type Manager struct {
	mu sync.Mutex

	tunnels map[string]*tunnelEntry // keyed by tunnel name

	netMgr  network.NetworkManager
	dataDir string

	// engineFactory creates the WireGuard engine. Defaults to NewEngine.
	// Overridable in tests to avoid requiring root / TUN device access.
	engineFactory func(cfg *domain.WireGuardConfig) (*Engine, error)
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
		netMgr:        network.NewPlatformManager(),
		dataDir:       dataDir,
		tunnels:       make(map[string]*tunnelEntry),
		engineFactory: NewEngine,
	}
}

// getOrCreateEntry returns the entry for a tunnel, creating a disconnected
// one if it doesn't exist. Caller MUST hold m.mu.
func (m *Manager) getOrCreateEntry(name string) *tunnelEntry {
	e, ok := m.tunnels[name]
	if !ok {
		e = &tunnelEntry{state: domain.StateDisconnected}
		m.tunnels[name] = e
	}
	return e
}

// removeEntry deletes a tunnel entry from the map. Caller MUST hold m.mu.
func (m *Manager) removeEntry(name string) {
	delete(m.tunnels, name)
}

// Connect establishes a WireGuard tunnel. Runs the expensive phase work
// WITHOUT holding m.mu, so Status / IsConnected / ActiveTunnel stay
// responsive for the duration.
//
// Multiple tunnels can be connected simultaneously. Only rejected if THIS
// specific tunnel name is already connected or a transition is in progress.
func (m *Manager) Connect(cfg *domain.WireGuardConfig) error {
	name := cfg.Name

	// --- Phase 1: claim the connecting slot under the lock ---
	m.mu.Lock()
	entry := m.getOrCreateEntry(name)
	switch entry.state {
	case domain.StateConnected:
		m.mu.Unlock()
		return newTunnelError(ErrAlreadyConnected, fmt.Sprintf("tunnel %q is already connected", name), nil)
	case domain.StateConnecting, stateDisconnecting:
		m.mu.Unlock()
		return newTunnelError(ErrTransitionInProgress, fmt.Sprintf("tunnel %q: another transition is in progress", name), nil)
	}
	// Reject if the new config is full-tunnel and any existing connected tunnel
	// is also full-tunnel — two 0.0.0.0/0 routes conflict on the route table.
	if cfg.IsFullTunnel() {
		for otherName, other := range m.tunnels {
			if otherName != name && other.state == domain.StateConnected && other.cfg != nil && other.cfg.IsFullTunnel() {
				m.mu.Unlock()
				return newTunnelError(ErrFullTunnelConflict,
					fmt.Sprintf("cannot connect full-tunnel %q: tunnel %q already routes all traffic (0.0.0.0/0)", name, otherName), nil)
			}
		}
	}

	// Stash the tunnel config early so Status() can show "connecting <name>"
	// while the phases are running.
	entry.cfg = cfg
	entry.state = domain.StateConnecting
	m.mu.Unlock()

	// --- Phase 2: run the slow operations WITHOUT holding the lock ---
	engine, err := m.connectPhases(cfg)

	// --- Phase 3: commit final state under the lock ---
	m.mu.Lock()
	defer m.mu.Unlock()
	entry = m.getOrCreateEntry(name) // re-fetch under lock
	if err != nil {
		// Phases failed — roll back to disconnected. connectPhases has
		// already cleaned up its partial network state via its internal
		// rollback helper.
		m.removeEntry(name)
		return err
	}
	// Re-validate state: a Disconnect may have landed while we were outside
	// the lock. If so, discard the engine we just created.
	if entry.state != domain.StateConnecting {
		// A Disconnect landed while we were outside the lock.
		// Clean up the network state that connectPhases just installed.
		m.netMgr.RemoveRoutes(engine.InterfaceName(), nil, cfg.IsFullTunnel())
		m.netMgr.RestoreDNS(engine.InterfaceName())
		m.netMgr.Cleanup(engine.InterfaceName())
		engine.Close()
		m.removeEntry(name)
		return newTunnelError(ErrStateCorrupt, "connect aborted: state changed during setup", nil)
	}
	entry.engine = engine
	entry.connectedAt = time.Now()
	entry.state = domain.StateConnected
	return nil
}

// Disconnect tears down the first connected tunnel. Kept for backward
// compatibility with callers that only support a single tunnel (reconnect
// monitor, tray, etc.). Use DisconnectTunnel for named disconnects.
func (m *Manager) Disconnect() error {
	m.mu.Lock()
	var name string
	for n, e := range m.tunnels {
		if e.state == domain.StateConnected || e.state == domain.StateConnecting {
			name = n
			break
		}
	}
	m.mu.Unlock()
	if name == "" {
		return newTunnelError(ErrNotConnected, "no tunnel is connected", nil)
	}
	return m.DisconnectTunnel(name)
}

// DisconnectTunnel tears down a specific tunnel by name. Like Connect, runs
// the slow teardown work outside the lock.
func (m *Manager) DisconnectTunnel(name string) error {
	// --- Phase 1: wait for any in-flight transition on THIS tunnel to settle ---
	deadline := time.Now().Add(10 * time.Second)
	for {
		m.mu.Lock()
		entry, ok := m.tunnels[name]
		if !ok {
			m.mu.Unlock()
			return newTunnelError(ErrNotConnected, fmt.Sprintf("tunnel %q is not connected", name), nil)
		}
		if entry.state != domain.StateConnecting && entry.state != stateDisconnecting {
			break // lock still held, state is stable
		}
		m.mu.Unlock()
		if time.Now().After(deadline) {
			return newTunnelError(ErrTimeout, fmt.Sprintf("disconnect timeout for tunnel %q: transition in progress", name), nil)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// m.mu held here, state is Connected / Disconnected / Error.
	entry := m.tunnels[name]
	if entry.state != domain.StateConnected {
		m.mu.Unlock()
		return newTunnelError(ErrNotConnected, fmt.Sprintf("tunnel %q is not connected", name), nil)
	}
	// Snapshot the handles we need outside the lock.
	engine := entry.engine
	cfg := entry.cfg
	if engine == nil {
		m.removeEntry(name)
		m.mu.Unlock()
		return newTunnelError(ErrStateCorrupt, fmt.Sprintf("engine is nil for tunnel %q despite connected state", name), nil)
	}
	entry.state = stateDisconnecting
	m.mu.Unlock()

	// --- Phase 2: slow teardown outside the lock ---
	m.disconnectPhases(cfg, engine)

	// --- Phase 3: commit final state ---
	m.mu.Lock()
	m.removeEntry(name)
	m.mu.Unlock()
	return nil
}

// DisconnectAll tears down all active tunnels, including those still in the
// connecting state. DisconnectTunnel internally waits for connecting tunnels
// to settle before tearing them down. Used during shutdown.
func (m *Manager) DisconnectAll() {
	m.mu.Lock()
	var names []string
	for n, e := range m.tunnels {
		if e.state == domain.StateConnected || e.state == domain.StateConnecting {
			names = append(names, n)
		}
	}
	m.mu.Unlock()

	for _, name := range names {
		if err := m.DisconnectTunnel(name); err != nil {
			slog.Warn("DisconnectAll: failed to disconnect tunnel", "tunnel", name, "error", err)
		}
	}
}

// Status returns the status of the first connected (or connecting) tunnel.
// For backward compatibility with single-tunnel callers. The returned
// ConnectionStatus includes ActiveTunnels listing all active tunnel names.
func (m *Manager) Status() *ConnectionStatus {
	m.mu.Lock()
	// Find the "primary" tunnel (first connected, or first connecting).
	var primary *tunnelEntry
	var primaryName string
	activeTunnels := m.activeTunnelNamesLocked()
	for _, name := range activeTunnels {
		e := m.tunnels[name]
		if e.state == domain.StateConnected {
			primary = e
			primaryName = name
			break
		}
	}
	if primary == nil {
		for _, name := range activeTunnels {
			e := m.tunnels[name]
			if e.state == domain.StateConnecting || e.state == stateDisconnecting {
				primary = e
				primaryName = name
				break
			}
		}
	}
	// Check for error state tunnels if nothing else found.
	if primary == nil {
		for name, e := range m.tunnels {
			if e.state == domain.StateError {
				primary = e
				primaryName = name
				break
			}
		}
	}

	if primary == nil {
		m.mu.Unlock()
		return &ConnectionStatus{
			State:         domain.StateDisconnected,
			ActiveTunnels: activeTunnels,
		}
	}

	state := primary.state
	engine := primary.engine
	connectedAt := primary.connectedAt
	_ = primaryName // used for logging only
	cfgName := ""
	if primary.cfg != nil {
		cfgName = primary.cfg.Name
	}
	m.mu.Unlock()

	switch state {
	case domain.StateConnecting, stateDisconnecting:
		return &ConnectionStatus{
			State:         domain.StateConnecting,
			TunnelName:    cfgName,
			ActiveTunnels: activeTunnels,
		}
	case domain.StateDisconnected:
		return &ConnectionStatus{
			State:         domain.StateDisconnected,
			ActiveTunnels: activeTunnels,
		}
	case domain.StateError:
		return &ConnectionStatus{
			State:         domain.StateError,
			TunnelName:    cfgName,
			ActiveTunnels: activeTunnels,
		}
	}

	// StateConnected — talk to wgctrl without holding m.mu.
	if engine == nil {
		return &ConnectionStatus{
			State:         domain.StateDisconnected,
			ActiveTunnels: activeTunnels,
		}
	}
	status, err := GetStatus(engine.InterfaceName(), cfgName, connectedAt)
	if err != nil {
		slog.Warn("failed to get status", "error", err)
		return &ConnectionStatus{
			State:         domain.StateError,
			TunnelName:    cfgName,
			ActiveTunnels: activeTunnels,
		}
	}
	status.ActiveTunnels = activeTunnels
	return status
}

// StatusFor returns the status of a specific tunnel by name.
func (m *Manager) StatusFor(name string) *ConnectionStatus {
	m.mu.Lock()
	entry, ok := m.tunnels[name]
	if !ok {
		m.mu.Unlock()
		return &ConnectionStatus{State: domain.StateDisconnected, TunnelName: name}
	}
	state := entry.state
	engine := entry.engine
	connectedAt := entry.connectedAt
	cfgName := ""
	if entry.cfg != nil {
		cfgName = entry.cfg.Name
	}
	m.mu.Unlock()

	switch state {
	case domain.StateConnecting, stateDisconnecting:
		return &ConnectionStatus{State: domain.StateConnecting, TunnelName: cfgName}
	case domain.StateDisconnected:
		return &ConnectionStatus{State: domain.StateDisconnected, TunnelName: cfgName}
	case domain.StateError:
		return &ConnectionStatus{State: domain.StateError, TunnelName: cfgName}
	}

	if engine == nil {
		return &ConnectionStatus{State: domain.StateDisconnected, TunnelName: cfgName}
	}
	status, err := GetStatus(engine.InterfaceName(), cfgName, connectedAt)
	if err != nil {
		return &ConnectionStatus{State: domain.StateError, TunnelName: cfgName}
	}
	return status
}

// AllStatuses returns the status of every tunnel that has an entry.
func (m *Manager) AllStatuses() []*ConnectionStatus {
	m.mu.Lock()
	type snap struct {
		name        string
		state       domain.State
		engine      *Engine
		connectedAt time.Time
		cfgName     string
	}
	var snaps []snap
	for name, e := range m.tunnels {
		cfgName := ""
		if e.cfg != nil {
			cfgName = e.cfg.Name
		}
		snaps = append(snaps, snap{name, e.state, e.engine, e.connectedAt, cfgName})
	}
	m.mu.Unlock()

	var out []*ConnectionStatus
	for _, s := range snaps {
		switch s.state {
		case domain.StateConnecting, stateDisconnecting:
			out = append(out, &ConnectionStatus{State: domain.StateConnecting, TunnelName: s.cfgName})
		case domain.StateDisconnected:
			out = append(out, &ConnectionStatus{State: domain.StateDisconnected, TunnelName: s.cfgName})
		case domain.StateError:
			out = append(out, &ConnectionStatus{State: domain.StateError, TunnelName: s.cfgName})
		case domain.StateConnected:
			if s.engine == nil {
				out = append(out, &ConnectionStatus{State: domain.StateDisconnected, TunnelName: s.cfgName})
				continue
			}
			st, err := GetStatus(s.engine.InterfaceName(), s.cfgName, s.connectedAt)
			if err != nil {
				out = append(out, &ConnectionStatus{State: domain.StateError, TunnelName: s.cfgName})
			} else {
				out = append(out, st)
			}
		}
	}
	return out
}

// IsConnected returns true if ANY tunnel is fully established.
func (m *Manager) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.tunnels {
		if e.state == domain.StateConnected {
			return true
		}
	}
	return false
}

// IsTunnelConnected returns true if the named tunnel is fully established.
func (m *Manager) IsTunnelConnected(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.tunnels[name]
	return ok && e.state == domain.StateConnected
}

// ResolvedEndpointIPs returns the union of pre-resolved endpoint IP addresses
// from all active engines. Returns nil if no tunnel is connected.
func (m *Manager) ResolvedEndpointIPs() []string {
	m.mu.Lock()
	var engines []*Engine
	for _, e := range m.tunnels {
		if e.engine != nil {
			engines = append(engines, e.engine)
		}
	}
	m.mu.Unlock()

	if len(engines) == 0 {
		return nil
	}
	var all []string
	for _, eng := range engines {
		all = append(all, eng.ResolvedEndpointIPs()...)
	}
	return all
}

// ResolvedEndpoints returns the union of pre-resolved endpoint ip:port pairs
// from all active engines. Returns nil if no tunnel is connected.
func (m *Manager) ResolvedEndpoints() []string {
	m.mu.Lock()
	var engines []*Engine
	for _, e := range m.tunnels {
		if e.engine != nil {
			engines = append(engines, e.engine)
		}
	}
	m.mu.Unlock()

	if len(engines) == 0 {
		return nil
	}
	var all []string
	for _, eng := range engines {
		all = append(all, eng.ResolvedEndpoints()...)
	}
	return all
}

// ActiveTunnel returns the name of the first connected (or connecting)
// tunnel, or "" if none. Kept for backward compatibility — callers that
// only support a single tunnel can use this.
func (m *Manager) ActiveTunnel() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := m.activeTunnelNamesLocked()
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// ActiveTunnels returns the names of all connected or connecting tunnels,
// sorted alphabetically for deterministic ordering.
func (m *Manager) ActiveTunnels() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeTunnelNamesLocked()
}

// activeTunnelNamesLocked returns sorted names of all active tunnels.
// Caller MUST hold m.mu.
func (m *Manager) activeTunnelNamesLocked() []string {
	var names []string
	for name, e := range m.tunnels {
		if e.state == domain.StateConnected || e.state == domain.StateConnecting || e.state == stateDisconnecting {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// AllDNSServers returns the union of DNS servers from all connected tunnels'
// configs. Used to re-apply the combined DNS when a tunnel connects or
// disconnects, preventing one tunnel from overwriting another's DNS settings.
func (m *Manager) AllDNSServers() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := make(map[string]struct{})
	var all []string
	for _, e := range m.tunnels {
		if e.state == domain.StateConnected && e.cfg != nil {
			for _, dns := range e.cfg.Interface.DNS {
				if _, ok := seen[dns]; !ok {
					seen[dns] = struct{}{}
					all = append(all, dns)
				}
			}
		}
	}
	return all
}

// SetPinInterface enables or disables -ifscope bypass route pinning on macOS.
func (m *Manager) SetPinInterface(enabled bool) {
	if dm, ok := m.netMgr.(interface{ SetPinInterface(bool) }); ok {
		dm.SetPinInterface(enabled)
	}
}
