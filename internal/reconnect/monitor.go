// Package reconnect handles automatic reconnection and dead connection detection.
package reconnect

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/tunnel"
)

// TunnelManager is the subset of tunnel.Manager that the reconnect monitor
// needs. Defined here (consumer-side interface) so tests can supply a mock
// without importing tunnel internals or spinning up real WireGuard state.
type TunnelManager interface {
	IsConnected() bool
	ActiveTunnel() string
	Status() *tunnel.ConnectionStatus
	Disconnect() error
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

// ReconnectFunc is called to perform the actual reconnection.
type ReconnectFunc func() error

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

// Monitor watches tunnel health and triggers reconnection.
type Monitor struct {
	mu            sync.Mutex
	cfg           Config
	manager       TunnelManager
	reconnectFn   ReconnectFunc
	statusFn      StatusChangedFunc
	fwSuspendFn   FirewallSuspendFunc
	fwResumeFn    FirewallResumeFunc
	stopCh        chan struct{}
	wg            sync.WaitGroup
	running       bool
	attempt       int
	sleepDetector SleepDetector

	// retryCancel cancels the current reconnectWithBackoff goroutine.
	// Called from Stop() and from CancelRetry() (manual Disconnect) so that a
	// pending exponential-backoff sleep returns immediately instead of waiting
	// out the full delay.
	retryCancel context.CancelFunc
	retryDone   chan struct{} // closed when reconnectWithBackoff exits
}

// NewMonitor creates a reconnection monitor.
func NewMonitor(manager TunnelManager, reconnectFn ReconnectFunc, statusFn StatusChangedFunc, cfg Config) *Monitor {
	return &Monitor{
		cfg:           cfg,
		manager:       manager,
		reconnectFn:   reconnectFn,
		statusFn:      statusFn,
		stopCh:        make(chan struct{}),
		sleepDetector: NewSleepDetector(),
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
				slog.Error("sleepWakeLoop panic (recovered)",
					"panic", fmt.Sprintf("%v", r),
					"stack", string(debug.Stack()))
			}
		}()
		m.sleepWakeLoop()
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
	if m.retryCancel != nil {
		m.retryCancel()
		m.retryCancel = nil
	}
	if m.sleepDetector != nil {
		m.sleepDetector.Stop()
	}
	m.mu.Unlock()

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

// CancelRetry aborts any in-flight reconnection attempt. Called by the helper
// when the user manually disconnects — we don't want a backoff sleep to wake
// up seconds later and re-connect against the user's wishes.
func (m *Monitor) CancelRetry() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.retryCancel != nil {
		m.retryCancel()
		m.retryCancel = nil
	}
	m.attempt = 0
}

// GetState returns the current reconnection state.
func (m *Monitor) GetState() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return State{
		Reconnecting: m.attempt > 0,
		Attempt:      m.attempt,
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
			if !m.manager.IsConnected() {
				continue
			}
			status := m.manager.Status()
			if status == nil || status.LastHandshakeTime.IsZero() {
				// No handshake data yet — tunnel may still be initializing.
				continue
			}
			age := time.Since(status.LastHandshakeTime)
			if age > handshakeStaleThreshold {
				slog.Warn("handshake stale, triggering reconnect",
					"last_handshake_age", age.Round(time.Second),
					"threshold", handshakeStaleThreshold)
				m.triggerReconnect()
			}
		}
	}
}

func (m *Monitor) triggerReconnect() {
	m.mu.Lock()
	// Save old cancel/done so we can clean up outside the lock.
	oldCancel := m.retryCancel
	oldDone := m.retryDone

	// Create new context and goroutine under the lock — no gap for another
	// goroutine to sneak in and create a duplicate reconnectWithBackoff.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	m.retryCancel = cancel
	m.retryDone = done
	m.attempt = 0
	m.mu.Unlock()

	// Cancel the old retry goroutine outside the lock to avoid deadlock.
	if oldCancel != nil {
		oldCancel()
	}
	if oldDone != nil {
		select {
		case <-oldDone:
		case <-time.After(5 * time.Second):
			slog.Warn("timed out waiting for previous retry goroutine to exit")
		}
	}

	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				slog.Error("reconnectWithBackoff panic (recovered)",
					"panic", fmt.Sprintf("%v", r),
					"stack", string(debug.Stack()))
			}
		}()
		m.reconnectWithBackoff(ctx)
	}()
}

func (m *Monitor) reconnectWithBackoff(ctx context.Context) {
	delay := m.cfg.InitialDelay

	for {
		m.mu.Lock()
		if !m.running {
			m.mu.Unlock()
			return
		}
		m.attempt++
		attempt := m.attempt
		m.mu.Unlock()

		if m.cfg.MaxAttempts > 0 && attempt > m.cfg.MaxAttempts {
			slog.Error("max reconnection attempts reached", "attempts", m.cfg.MaxAttempts)
			m.notifyStatus(State{
				Reconnecting: false,
				Attempt:      attempt - 1,
				MaxAttempts:  m.cfg.MaxAttempts,
			})
			m.mu.Lock()
			m.attempt = 0
			if m.retryCancel != nil {
				m.retryCancel()
				m.retryCancel = nil
			}
			m.mu.Unlock()
			return
		}

		slog.Info("reconnecting", "attempt", attempt, "delay", delay)
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

		// Disconnect first (ignore errors — might already be disconnected)
		_ = m.manager.Disconnect()

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

		// Attempt reconnection
		if err := m.reconnectFn(); err != nil {
			slog.Warn("reconnection failed", "attempt", attempt, "error", err)
			// Re-enable firewall after failed attempt so the system stays
			// protected between retries.
			if firewallWasSuspended && m.fwResumeFn != nil {
				if err := m.fwResumeFn(); err != nil {
					slog.Warn("failed to resume firewall after failed reconnect", "error", err)
				}
			}
			// Exponential backoff
			delay *= 2
			if delay > m.cfg.MaxDelay {
				delay = m.cfg.MaxDelay
			}
			continue
		}

		// Resume firewall with the new interface name and endpoints.
		if firewallWasSuspended && m.fwResumeFn != nil {
			if err := m.fwResumeFn(); err != nil {
				slog.Warn("failed to resume firewall after successful reconnect", "error", err)
			}
		}

		slog.Info("reconnected successfully", "attempt", attempt)
		m.notifyStatus(State{Reconnecting: false})
		m.mu.Lock()
		m.attempt = 0
		if m.retryCancel != nil {
			m.retryCancel()
			m.retryCancel = nil
		}
		m.mu.Unlock()
		return
	}
}

func (m *Monitor) sleepWakeLoop() {
	if m.sleepDetector == nil {
		return
	}
	m.sleepDetector.Start()

	wakeCh := m.sleepDetector.WakeChan()
	for {
		select {
		case <-m.stopCh:
			return
		case <-wakeCh:
			slog.Info("system wake detected, triggering reconnect")
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
