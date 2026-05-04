// Package reconnect handles automatic reconnection and dead connection detection.
package reconnect

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// TunnelManager is the subset of tunnel.Manager that the reconnect monitor
// needs. Defined here (consumer-side interface) so tests can supply a mock
// without importing tunnel internals or spinning up real WireGuard state.
type TunnelManager interface {
	IsConnected() bool
	ActiveTunnel() string
	Status() *tunnel.ConnectionStatus
	AllStatuses() []*tunnel.ConnectionStatus
	Disconnect() error
	DisconnectTunnel(name string) error
}

// Config holds reconnection parameters.
type Config struct {
	HandshakeTimeout time.Duration // Max time without handshake before reconnecting (default: 120s)
	InitialDelay     time.Duration // First retry delay (default: 5s)
	MaxDelay         time.Duration // Max retry delay (default: 60s)
	MaxAttempts      int           // Max reconnection attempts (default: 0 = unlimited)
}

// DefaultConfig returns sensible default reconnection settings.
func DefaultConfig() Config {
	return Config{
		HandshakeTimeout: 120 * time.Second,
		InitialDelay:     5 * time.Second,
		MaxDelay:         60 * time.Second,
		MaxAttempts:      0, // unlimited — health check ensures persistent reconnection
	}
}

// State represents the current reconnection state.
type State struct {
	Reconnecting bool   `json:"reconnecting"`
	Attempt      int    `json:"attempt"`
	MaxAttempts  int    `json:"max_attempts"`
	NextRetry    string `json:"next_retry"`
}

// ReconnectFunc is called to perform the actual reconnection of a specific
// tunnel identified by name.
type ReconnectFunc func(name string) error

// StatusChangedFunc is called when reconnection state changes.
type StatusChangedFunc func(state State)

// FirewallSuspendFunc is called before disconnect during reconnection to
// temporarily disable firewall rules (kill switch / DNS protection). This
// prevents a deadlock when the utun interface name changes (e.g. utun4->utun5)
// and old pf rules block the new interface's traffic.
type FirewallSuspendFunc func() error

// FirewallResumeFunc is called after a successful reconnect to re-enable
// firewall rules with the new interface name and endpoints.
type FirewallResumeFunc func() error

// retryState holds the cancel/done/attempt counters for a single
// in-flight reconnect goroutine. Each tunnel gets its own — mixing
// retries (e.g. "tunnel A is on backoff for stale handshake" vs
// "system woke and triggered an all-tunnel reconnect") into a single
// piece of state caused them to stomp on each other and reset
// backoff to InitialDelay on every cross-cause trigger.
//
// The empty-string key "" represents the legacy "reconnect all
// tunnels" path used by the sleep/wake and network-change triggers.
type retryState struct {
	cancel  context.CancelFunc
	done    chan struct{}
	attempt int
	delay   time.Duration
}

// Monitor watches tunnel health and triggers reconnection.
type Monitor struct {
	mu              sync.Mutex
	cfg             Config
	manager         TunnelManager
	reconnectFn     ReconnectFunc
	statusFn        StatusChangedFunc
	fwSuspendFn     FirewallSuspendFunc
	fwResumeFn      FirewallResumeFunc
	stopCh          chan struct{}
	wg              sync.WaitGroup
	running         bool
	sleepDetector   SleepDetector
	networkDetector NetworkChangeDetector

	// retries holds in-flight reconnect goroutines keyed by tunnel
	// name. Per-tunnel state preserves backoff across cross-cause
	// triggers (sleep/wake, network change, health check) and lets
	// the all-tunnels path coexist with per-tunnel health recovery
	// without canceling each other.
	retries map[string]*retryState

	// healthCheckEnabled controls whether the periodic handshake age
	// check runs in monitorLoop. Can be toggled at runtime via
	// SetHealthCheck. Default: true.
	healthCheckEnabled bool
}

// NewMonitor creates a reconnection monitor.
func NewMonitor(manager TunnelManager, reconnectFn ReconnectFunc, statusFn StatusChangedFunc, cfg Config) *Monitor {
	return &Monitor{
		cfg:                cfg,
		manager:            manager,
		reconnectFn:        reconnectFn,
		statusFn:           statusFn,
		stopCh:             make(chan struct{}),
		sleepDetector:      NewSleepDetector(),
		networkDetector:    NewNetworkChangeDetector(),
		retries:            make(map[string]*retryState),
		healthCheckEnabled: false, // default OFF — enable in Settings
	}
}

// SetFirewallCallbacks configures the firewall suspend/resume callbacks used
// during reconnection. Must be called before Start(). Separated from
// NewMonitor to avoid changing the constructor signature for all callers.
func (m *Monitor) SetFirewallCallbacks(suspend FirewallSuspendFunc, resume FirewallResumeFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fwSuspendFn = suspend
	m.fwResumeFn = resume
}

// SetHealthCheck enables or disables the periodic handshake age check.
// Safe to call while the monitor is running.
func (m *Monitor) SetHealthCheck(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthCheckEnabled = enabled
	slog.Info("health check toggled", "enabled", enabled)
}

// Start begins monitoring the tunnel connection.
func (m *Monitor) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	// Recreate stopCh so Start() works after a previous Stop().
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	m.wg.Add(2)
	go func() {
		defer m.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("monitorLoop panic (recovered)",
					"panic", fmt.Sprintf("%v", r),
					"stack", string(debug.Stack()))
			}
		}()
		m.monitorLoop()
	}()
	go func() {
		defer m.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("triggerLoop panic (recovered)",
					"panic", fmt.Sprintf("%v", r),
					"stack", string(debug.Stack()))
			}
		}()
		m.triggerLoop()
	}()
	slog.Info("reconnect monitor started")
}

// Stop stops the monitor and waits for all goroutines to exit.
func (m *Monitor) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	close(m.stopCh)
	for _, r := range m.retries {
		if r.cancel != nil {
			r.cancel()
		}
	}
	// Snapshot the detectors under the lock, then call Stop() OUTSIDE
	// the lock — sleep/network detector Stop()s wait on cgo run-loop
	// threads and have been seen to take seconds when IOKit is back-
	// pressured. Holding m.mu through that wait deadlocks any
	// concurrent triggerReconnectTunnel / monitorLoop / GetState
	// caller, which then prevents wg.Wait() from ever returning.
	sd := m.sleepDetector
	nd := m.networkDetector
	m.mu.Unlock()
	if sd != nil {
		sd.Stop()
	}
	if nd != nil {
		nd.Stop()
	}

	// Wait for goroutines to exit outside the lock to avoid deadlock.
	// Use a timeout so a stuck goroutine doesn't block helper cleanup forever.
	waitDone := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		slog.Info("reconnect monitor stopped")
	case <-time.After(5 * time.Second):
		slog.Warn("reconnect monitor stop timed out after 5s, proceeding with cleanup")
	}
}

// CancelRetry aborts every in-flight reconnection attempt. Called
// from the all-tunnels disconnect path (legacy tray menu, helper
// shutdown). For per-tunnel disconnects use CancelRetryFor instead —
// a manual disconnect of A shouldn't kill a healthy in-flight retry
// for an unrelated tunnel B.
func (m *Monitor) CancelRetry() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, r := range m.retries {
		if r.cancel != nil {
			r.cancel()
		}
		delete(m.retries, name)
	}
}

// CancelRetryFor aborts the in-flight reconnect attempt for a
// specific tunnel name (or the legacy all-tunnels retry when name is
// ""). Other tunnels' retries are left running.
func (m *Monitor) CancelRetryFor(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.retries[name]; ok {
		if r.cancel != nil {
			r.cancel()
		}
		delete(m.retries, name)
	}
}

// GetState returns the aggregate reconnection state across all
// tunnels. The frontend currently shows a single spinner; reporting
// the maximum attempt count gives the most informative single number.
func (m *Monitor) GetState() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	var maxAttempt int
	reconnecting := false
	for _, r := range m.retries {
		if r.attempt > 0 {
			reconnecting = true
		}
		if r.attempt > maxAttempt {
			maxAttempt = r.attempt
		}
	}
	return State{
		Reconnecting: reconnecting,
		Attempt:      maxAttempt,
		MaxAttempts:  m.cfg.MaxAttempts,
	}
}

func (m *Monitor) monitorLoop() {
	const checkInterval = 30 * time.Second
	const handshakeStaleThreshold = 180 * time.Second // 3 minutes

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.mu.Lock()
			enabled := m.healthCheckEnabled
			m.mu.Unlock()
			if !enabled {
				continue
			}
			if !m.manager.IsConnected() {
				continue
			}
			// Check EACH tunnel's handshake individually. If a specific
			// tunnel is stale, disconnect and reconnect only THAT tunnel.
			statuses := m.manager.AllStatuses()
			for _, status := range statuses {
				if status == nil || status.LastHandshakeTime.IsZero() {
					continue
				}
				if status.State != domain.StateConnected {
					continue
				}
				age := time.Since(status.LastHandshakeTime)
				if age > handshakeStaleThreshold {
					tunnelName := status.TunnelName
					slog.Warn("handshake stale, triggering per-tunnel reconnect",
						"tunnel", tunnelName,
						"last_handshake_age", age.Round(time.Second),
						"threshold", handshakeStaleThreshold)
					m.triggerReconnectTunnel(tunnelName)
				}
			}
		}
	}
}

func (m *Monitor) triggerReconnect() {
	// Reconnect all tunnels — used by sleep/wake detection.
	m.triggerReconnectTunnel("")
}

func (m *Monitor) triggerReconnectTunnel(tunnelName string) {
	m.mu.Lock()

	// Cancel ONLY the previous retry for this same key — per-tunnel
	// triggers preserve other tunnels' backoff state. The empty-string
	// key ("") is the legacy all-tunnels path; an all-tunnels trigger
	// also cancels every per-tunnel retry because those tunnels are
	// about to be torn down by Disconnect().
	var oldEntries []*retryState
	if tunnelName == "" {
		for k, r := range m.retries {
			oldEntries = append(oldEntries, r)
			delete(m.retries, k)
		}
	} else if r, ok := m.retries[tunnelName]; ok {
		oldEntries = append(oldEntries, r)
		delete(m.retries, tunnelName)
	}

	// Create new context + retry slot under the lock so two concurrent
	// triggers for the same key can't both spawn goroutines.
	ctx, cancel := context.WithCancel(context.Background())
	entry := &retryState{
		cancel: cancel,
		done:   make(chan struct{}),
	}
	m.retries[tunnelName] = entry
	m.mu.Unlock()

	// Cancel old goroutines outside the lock. Bound the wait by stopCh
	// in addition to the 5-second timeout — Stop() needs to be able to
	// preempt this so helper cleanup isn't blocked by a hung retry.
	for _, old := range oldEntries {
		if old.cancel != nil {
			old.cancel()
		}
		if old.done != nil {
			select {
			case <-old.done:
			case <-m.stopCh:
				return
			case <-time.After(5 * time.Second):
				slog.Warn("timed out waiting for previous retry goroutine to exit",
					"tunnel", tunnelName)
			}
		}
	}

	go func() {
		defer close(entry.done)
		defer func() {
			if r := recover(); r != nil {
				slog.Error("reconnectWithBackoff panic (recovered)",
					"panic", fmt.Sprintf("%v", r),
					"stack", string(debug.Stack()))
			}
		}()
		m.reconnectWithBackoff(ctx, tunnelName, entry)
	}()
}

// reconnectWithBackoff retries reconnection with exponential backoff.
// If tunnelName is non-empty, only that specific tunnel is disconnected and
// reconnected. If tunnelName is empty, the legacy Disconnect()/reconnectFn("")
// path is used (reconnects all tunnels, used by sleep/wake). The entry's
// `attempt` and `delay` are mutated in place under m.mu so GetState
// can read a consistent snapshot.
func (m *Monitor) reconnectWithBackoff(ctx context.Context, tunnelName string, entry *retryState) {
	m.mu.Lock()
	entry.delay = m.cfg.InitialDelay
	m.mu.Unlock()

	for {
		m.mu.Lock()
		if !m.running {
			m.mu.Unlock()
			return
		}
		entry.attempt++
		attempt := entry.attempt
		delay := entry.delay
		m.mu.Unlock()

		if m.cfg.MaxAttempts > 0 && attempt > m.cfg.MaxAttempts {
			slog.Error("max reconnection attempts reached", "attempts", m.cfg.MaxAttempts, "tunnel", tunnelName)
			m.notifyStatus(State{
				Reconnecting: false,
				Attempt:      attempt - 1,
				MaxAttempts:  m.cfg.MaxAttempts,
			})
			m.mu.Lock()
			if cur, ok := m.retries[tunnelName]; ok && cur == entry {
				delete(m.retries, tunnelName)
			}
			m.mu.Unlock()
			return
		}

		slog.Info("reconnecting", "attempt", attempt, "delay", delay, "tunnel", tunnelName)
		m.notifyStatus(State{
			Reconnecting: true,
			Attempt:      attempt,
			MaxAttempts:  m.cfg.MaxAttempts,
			NextRetry:    delay.String(),
		})

		// Cancelable backoff — responds immediately to CancelRetry()/Stop()
		// instead of waiting out the full delay.
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			slog.Info("reconnection cancelled", "attempt", attempt)
			return
		case <-m.stopCh:
			timer.Stop()
			return
		case <-timer.C:
		}

		// Recheck cancellation after the sleep returned normally — the user
		// may have clicked Disconnect between the timer firing and this line.
		// Without this check a final reconnectFn() would run against the
		// user's explicit wish and silently bring the tunnel back up.
		if ctx.Err() != nil {
			slog.Info("reconnection cancelled before attempt", "attempt", attempt)
			return
		}

		// Suspend firewall rules before disconnect so old pf rules (which
		// reference the old utun interface name) don't block the new
		// connection's traffic when the interface name changes.
		firewallWasSuspended := false
		if m.fwSuspendFn != nil {
			if err := m.fwSuspendFn(); err != nil {
				slog.Warn("failed to suspend firewall for reconnect", "error", err)
			} else {
				firewallWasSuspended = true
			}
		}

		// Disconnect the specific tunnel (or first tunnel for legacy path).
		if tunnelName != "" {
			_ = m.manager.DisconnectTunnel(tunnelName)
		} else {
			_ = m.manager.Disconnect()
		}

		// One more cancellation check before the actual reconnect — manager
		// Disconnect can take a moment and the user's cancel may land here.
		if ctx.Err() != nil {
			slog.Info("reconnection cancelled before reconnectFn", "attempt", attempt)
			// Re-enable firewall even on cancel to avoid leaving the
			// system unprotected.
			if firewallWasSuspended && m.fwResumeFn != nil {
				if err := m.fwResumeFn(); err != nil {
					slog.Warn("failed to resume firewall after cancel", "error", err)
				}
			}
			return
		}

		// Attempt reconnection — pass tunnel name so only the specific
		// tunnel is reconnected when doing per-tunnel health recovery.
		if err := m.reconnectFn(tunnelName); err != nil {
			slog.Warn("reconnection failed", "attempt", attempt, "tunnel", tunnelName, "error", err)
			// Re-enable firewall after failed attempt so the system stays
			// protected between retries.
			if firewallWasSuspended && m.fwResumeFn != nil {
				if err := m.fwResumeFn(); err != nil {
					slog.Warn("failed to resume firewall after failed reconnect", "error", err)
				}
			}
			// Exponential backoff stored on the entry so a sibling
			// trigger (e.g. CancelRetry + new triggerReconnectTunnel)
			// can read it for an informative GetState snapshot, and so
			// future reconnects of THIS tunnel don't reset to
			// InitialDelay if the same goroutine is later reused.
			m.mu.Lock()
			entry.delay = delay * 2
			if entry.delay > m.cfg.MaxDelay {
				entry.delay = m.cfg.MaxDelay
			}
			m.mu.Unlock()
			continue
		}

		// Resume firewall with the new interface name and endpoints.
		if firewallWasSuspended && m.fwResumeFn != nil {
			if err := m.fwResumeFn(); err != nil {
				slog.Warn("failed to resume firewall after successful reconnect", "error", err)
			}
		}

		slog.Info("reconnected successfully", "attempt", attempt, "tunnel", tunnelName)
		m.notifyStatus(State{Reconnecting: false})
		m.mu.Lock()
		// Only clear if this entry is still the current one for the
		// key — a concurrent triggerReconnectTunnel may have already
		// installed a fresh retry slot.
		if cur, ok := m.retries[tunnelName]; ok && cur == entry {
			delete(m.retries, tunnelName)
		}
		m.mu.Unlock()
		return
	}
}

// triggerLoop fans both wake and network-change events into the same
// reconnect path. They share the same response — drop the tunnel and
// rebuild it against the (potentially new) underlying network — so a
// single select keeps the logic visible.
func (m *Monitor) triggerLoop() {
	if m.sleepDetector != nil {
		m.sleepDetector.Start()
	}
	if m.networkDetector != nil {
		m.networkDetector.Start()
	}

	var wakeCh <-chan struct{}
	if m.sleepDetector != nil {
		wakeCh = m.sleepDetector.WakeChan()
	}
	var netCh <-chan struct{}
	if m.networkDetector != nil {
		netCh = m.networkDetector.ChangeChan()
	}

	for {
		select {
		case <-m.stopCh:
			return
		case <-wakeCh:
			slog.Info("system wake detected, triggering reconnect")
			if m.manager.IsConnected() || m.manager.ActiveTunnel() != "" {
				m.triggerReconnect()
			}
		case <-netCh:
			slog.Info("primary interface change detected, triggering reconnect")
			if m.manager.IsConnected() || m.manager.ActiveTunnel() != "" {
				m.triggerReconnect()
			}
		}
	}
}

func (m *Monitor) notifyStatus(state State) {
	if m.statusFn != nil {
		m.statusFn(state)
	}
}
