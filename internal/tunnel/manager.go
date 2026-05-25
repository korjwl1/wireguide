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
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
)

// tunnelEntry holds the state for a single tunnel within the multi-tunnel
// manager. Each entry has its own state machine, engine, config, connected
// timestamp, and per-tunnel NetworkManager instance.
type tunnelEntry struct {
	state       domain.State
	engine      *Engine
	cfg         *domain.WireGuardConfig
	connectedAt time.Time
	netMgr      network.NetworkManager // per-tunnel network state (routes, DNS, monitor)

	// watchdogCancel stops the runaway-TX watchdog goroutine started
	// after a successful full-tunnel connect. nil for split-tunnel and
	// non-Windows where the watchdog is a no-op.
	watchdogCancel context.CancelFunc
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

	dataDir string

	// pinInterface is the current -ifscope setting. Stored on Manager so
	// it can be propagated to each newly-created per-tunnel NetworkManager.
	pinInterface bool

	// netMgrFactory creates a fresh NetworkManager for each tunnel.
	// Defaults to network.NewPlatformManager. Overridable in tests.
	netMgrFactory func() network.NetworkManager

	// engineFactory creates the WireGuard engine. Defaults to NewEngine.
	// Overridable in tests to avoid requiring root / TUN device access.
	engineFactory func(cfg *domain.WireGuardConfig) (*Engine, error)

	// globalPreModDNS is the system DNS state captured BEFORE any tunnel
	// modified it. Used by the last tunnel to disconnect so we restore
	// the original DHCP defaults rather than the per-netMgr savedDNS,
	// which for a non-first tunnel would have been the previous tunnel's
	// already-applied DNS. Guarded by m.mu.
	globalPreModDNS map[string][]string

	// endpointProtector is the optional always-on loop protection hook
	// (Windows full-tunnel only). Set by the helper after construction
	// via SetEndpointProtector. nil → connectPhases skips the
	// enable/disable calls, mirroring the historical behaviour on
	// platforms that don't have this protection layer.
	endpointProtector EndpointProtector
}

// EndpointProtector is the minimal slice of the firewall manager that
// connect/disconnect needs for installing always-on endpoint loop
// protection. Defined here so the tunnel (domain) package doesn't have
// to import the firewall (infra) package — same pattern as
// FirewallCleaner. The helper passes its live firewall instance, which
// satisfies this interface trivially on every platform.
//
// Implementations are expected to be safe across the disconnect ordering
// already used by disconnectPhases (DisableEndpointProtection runs
// AFTER RemoveRoutes but BEFORE engine.Close, matching the
// kill-switch's RemoveKillSwitchTunnel semantics).
type EndpointProtector interface {
	EnableEndpointProtection(tunnelInterfaceName string, endpoints []string) error
	DisableEndpointProtection(tunnelInterfaceName string) error
}

// Additional transient states used internally. Exposed on the wire as the
// closest public state (connecting/disconnecting both surface as
// "connecting" since the GUI treats them the same way).
const (
	stateDisconnecting domain.State = "disconnecting"
)

// NewManager creates a tunnel manager. Each tunnel gets its own
// NetworkManager instance created via netMgrFactory, so one tunnel's
// route/DNS cleanup cannot affect another.
func NewManager(dataDir string) *Manager {
	return &Manager{
		dataDir:       dataDir,
		tunnels:       make(map[string]*tunnelEntry),
		netMgrFactory: func() network.NetworkManager { return network.NewPlatformManager() },
		engineFactory: NewEngine,
	}
}

// SetEndpointProtector wires the optional always-on loop protection
// callback. Safe to call once at construction time; not safe to call
// concurrently with Connect. Pass nil to disable (the connect path
// then skips the hook entirely).
func (m *Manager) SetEndpointProtector(p EndpointProtector) {
	m.endpointProtector = p
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
// Also cancels any per-entry background goroutine (the runaway-TX
// watchdog) so we never leak a poll loop pointing at a stale entry.
func (m *Manager) removeEntry(name string) {
	if e := m.tunnels[name]; e != nil && e.watchdogCancel != nil {
		e.watchdogCancel()
		e.watchdogCancel = nil
	}
	delete(m.tunnels, name)
}

// Connect establishes a WireGuard tunnel. Runs the expensive phase work
// WITHOUT holding m.mu, so Status / IsConnected / ActiveTunnel stay
// responsive for the duration.
//
// Multiple tunnels can be connected simultaneously. Only rejected if THIS
// specific tunnel name is already connected or a transition is in progress.
func (m *Manager) Connect(cfg *domain.WireGuardConfig) error {
	return m.ConnectWithContext(context.Background(), cfg)
}

// ConnectWithContext is Connect with cancellation. The ctx is checked at every
// phase boundary; in-flight kernel/exec operations inside connectPhases honour
// their own cmdTimeout, so the worst-case latency for a cancellation landing
// mid-phase is bounded by that timeout rather than ctx.
func (m *Manager) ConnectWithContext(ctx context.Context, cfg *domain.WireGuardConfig) error {
	if err := ctx.Err(); err != nil {
		return newTunnelError(ErrCancelled, "connect cancelled before start", err)
	}
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

	// Create a per-tunnel NetworkManager so this tunnel's routes, DNS
	// snapshot, and route monitor are independent of other tunnels.
	netMgr := m.netMgrFactory()
	if m.pinInterface {
		if dm, ok := netMgr.(interface{ SetPinInterface(bool) }); ok {
			dm.SetPinInterface(true)
		}
	}
	entry.netMgr = netMgr
	m.mu.Unlock()

	// Re-check ctx before entering the slow phases. A cancel landing here
	// avoids spawning a TUN device that we'd immediately need to tear down.
	if err := ctx.Err(); err != nil {
		m.mu.Lock()
		m.removeEntry(name)
		m.mu.Unlock()
		return newTunnelError(ErrCancelled, "connect cancelled before phases", err)
	}

	// --- Phase 2: run the slow operations WITHOUT holding the lock ---
	engine, err := m.connectPhases(ctx, cfg, netMgr)

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
		ifaceName := engine.InterfaceName()
		if err := netMgr.RemoveRoutes(ifaceName, nil, cfg.IsFullTunnel()); err != nil {
			slog.Warn("connect race: RemoveRoutes failed", "iface", ifaceName, "error", err)
		}
		if err := netMgr.RestoreDNS(ifaceName); err != nil {
			slog.Warn("connect race: RestoreDNS failed", "iface", ifaceName, "error", err)
		}
		if err := netMgr.Cleanup(ifaceName); err != nil {
			slog.Warn("connect race: network Cleanup failed", "iface", ifaceName, "error", err)
		}
		engine.Close()
		// connectPhases saved the crash-recovery state file before this
		// raced Disconnect. Without ClearActiveState here, the file
		// remains on disk and triggers spurious recovery on next launch.
		if err := ClearActiveState(m.dataDir, name); err != nil {
			slog.Warn("connect race: ClearActiveState failed", "tunnel", name, "error", err)
		}
		m.removeEntry(name)
		return newTunnelError(ErrStateCorrupt, "connect aborted: state changed during setup", nil)
	}
	entry.engine = engine
	entry.connectedAt = time.Now()
	entry.state = domain.StateConnected

	// Start the runaway-TX watchdog for full-tunnel connects. The
	// watchdog is a no-op on non-Windows and on split-tunnel because
	// the loop class is full-tunnel-Windows-only. We launch it under
	// a child context so DisconnectTunnel's cancel reliably stops it
	// without depending on the Manager's lifetime.
	if cfg.IsFullTunnel() {
		watchdogCtx, cancel := context.WithCancel(context.Background())
		entry.watchdogCancel = cancel
		ifaceName := engine.InterfaceName()
		tunnelName := name
		startLoopWatchdog(watchdogCtx, ifaceName, func(bps uint64) {
			slog.Error("loop watchdog tripped — initiating forced disconnect",
				"tunnel", tunnelName, "interface", ifaceName, "bytes_per_sec", bps)
			// Run the disconnect on a fresh goroutine so we don't
			// block the watchdog goroutine, and so we don't hold any
			// implicit lock the caller might have.
			go func() {
				if err := m.DisconnectTunnel(tunnelName); err != nil {
					slog.Error("loop watchdog: forced disconnect failed",
						"tunnel", tunnelName, "error", err)
				}
			}()
		})
	}
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
//
// Concurrent-disconnect contract: if the tunnel goes from
// stateDisconnecting → gone while we're waiting (because the watchdog
// or another caller ran disconnectPhases first), we return nil rather
// than ErrNotConnected. The user's intent was "be disconnected", which
// IS the state at return. We only return ErrNotConnected when the
// tunnel was never observed connected during this call.
func (m *Manager) DisconnectTunnel(name string) error {
	// --- Phase 1: wait for any in-flight transition on THIS tunnel to settle ---
	deadline := time.Now().Add(10 * time.Second)
	observedTransitioning := false
	for {
		m.mu.Lock()
		entry, ok := m.tunnels[name]
		if !ok {
			m.mu.Unlock()
			// If we previously observed this tunnel mid-transition,
			// its disappearance means a concurrent disconnect (likely
			// the watchdog) reached completion. The user got what
			// they asked for; return success, not ErrNotConnected.
			if observedTransitioning {
				return nil
			}
			return newTunnelError(ErrNotConnected, fmt.Sprintf("tunnel %q is not connected", name), nil)
		}
		if entry.state != domain.StateConnecting && entry.state != stateDisconnecting {
			break // lock still held, state is stable
		}
		observedTransitioning = true
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
	netMgr := entry.netMgr
	watchdogCancel := entry.watchdogCancel
	if engine == nil {
		m.removeEntry(name)
		m.mu.Unlock()
		return newTunnelError(ErrStateCorrupt, fmt.Sprintf("engine is nil for tunnel %q despite connected state", name), nil)
	}
	entry.state = stateDisconnecting
	entry.watchdogCancel = nil
	m.mu.Unlock()

	// Cancel the watchdog BEFORE the slow teardown so it can't trip on
	// the disconnect-phase TX burst (DNS flush, route deletes, etc.).
	if watchdogCancel != nil {
		watchdogCancel()
	}

	// --- Phase 2: slow teardown outside the lock ---
	m.disconnectPhases(cfg, engine, netMgr)

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

// The Status/DNS/Pin facade lives alongside this file:
//   manager_status.go — Status/StatusFor/AllStatuses, IsConnected,
//                       Resolved*, ActiveTunnel(s), activeTunnelNamesLocked
//   manager_dns.go    — AllDNSServers, CapturePreModDNS, etc.
//   manager_pin.go    — SetPinInterface
// All those methods share Manager.mu defined here.
