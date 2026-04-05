// Package reconnect handles automatic reconnection and dead connection detection.
package reconnect

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/tunnel"
)

// Config holds reconnection parameters.
type Config struct {
	HandshakeTimeout time.Duration // Max time without handshake before reconnecting (default: 120s)
	InitialDelay     time.Duration // First retry delay (default: 5s)
	MaxDelay         time.Duration // Max retry delay (default: 60s)
	MaxAttempts      int           // Max reconnection attempts (default: 10, 0 = unlimited)
}

// DefaultConfig returns sensible default reconnection settings.
func DefaultConfig() Config {
	return Config{
		HandshakeTimeout: 120 * time.Second,
		InitialDelay:     5 * time.Second,
		MaxDelay:         60 * time.Second,
		MaxAttempts:      10,
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

// Monitor watches tunnel health and triggers reconnection.
type Monitor struct {
	mu            sync.Mutex
	cfg           Config
	manager       *tunnel.Manager
	reconnectFn   ReconnectFunc
	statusFn      StatusChangedFunc
	stopCh        chan struct{}
	running       bool
	attempt       int
	sleepDetector SleepDetector

	// retryCancel cancels the current reconnectWithBackoff goroutine.
	// Called from Stop() and from CancelRetry() (manual Disconnect) so that a
	// pending exponential-backoff sleep returns immediately instead of waiting
	// out the full delay.
	retryCancel context.CancelFunc
}

// NewMonitor creates a reconnection monitor.
func NewMonitor(manager *tunnel.Manager, reconnectFn ReconnectFunc, statusFn StatusChangedFunc, cfg Config) *Monitor {
	return &Monitor{
		cfg:           cfg,
		manager:       manager,
		reconnectFn:   reconnectFn,
		statusFn:      statusFn,
		stopCh:        make(chan struct{}),
		sleepDetector: NewSleepDetector(),
	}
}

// Start begins monitoring the tunnel connection.
func (m *Monitor) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()

	go m.monitorLoop()
	go m.sleepWakeLoop()
	slog.Info("reconnect monitor started")
}

// Stop stops the monitor.
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
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
	slog.Info("reconnect monitor stopped")
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
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkHealth()
		}
	}
}

func (m *Monitor) checkHealth() {
	if !m.manager.IsConnected() {
		return
	}

	status := m.manager.Status()
	if status.State != tunnel.StateConnected {
		return
	}

	// NOTE: we used to call triggerReconnect() on stale handshake age, but
	// that was catastrophically wrong — it tears down the TUN device, clears
	// routes, and rebuilds the tunnel, which severs every in-flight TCP
	// session on top of it (ssh dies with "Connection reset by peer",
	// browsers lose long-polling sockets, etc).
	//
	// WireGuard has its own rekey mechanism (rekey-after-time = 120s) that
	// handles stale sessions without touching the TUN or the route table.
	// Racing it with a full Disconnect+Connect on our side is worse than
	// doing nothing: wg-quick specifically does NOT do this either.
	//
	// We keep the health check alive purely for logging / future hooks, but
	// stale handshake is no longer a trigger for full reconnect. The only
	// legitimate full-reconnect path is sleepWakeLoop — when the laptop
	// wakes from sleep, the network state has genuinely changed and WG's
	// own rekey won't see the new interfaces.
	if !status.LastHandshakeTime.IsZero() {
		age := time.Since(status.LastHandshakeTime)
		if age > m.cfg.HandshakeTimeout {
			slog.Debug("handshake is stale — letting WireGuard rekey itself",
				"tunnel", status.TunnelName,
				"handshake_age", age.Round(time.Second))
		}
	}
}

func (m *Monitor) triggerReconnect() {
	m.mu.Lock()
	// If a previous retry goroutine is still alive, cancel it before starting
	// a new one — otherwise we'd double-dispatch reconnects on overlapping
	// health-check failures.
	if m.retryCancel != nil {
		m.retryCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.retryCancel = cancel
	m.attempt = 0
	m.mu.Unlock()

	go m.reconnectWithBackoff(ctx)
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
			m.retryCancel = nil
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

		// Disconnect first (ignore errors — might already be disconnected)
		_ = m.manager.Disconnect()

		// One more cancellation check before the actual reconnect — manager
		// Disconnect can take a moment and the user's cancel may land here.
		if ctx.Err() != nil {
			slog.Info("reconnection cancelled before reconnectFn", "attempt", attempt)
			return
		}

		// Attempt reconnection
		if err := m.reconnectFn(); err != nil {
			slog.Warn("reconnection failed", "attempt", attempt, "error", err)
			// Exponential backoff
			delay *= 2
			if delay > m.cfg.MaxDelay {
				delay = m.cfg.MaxDelay
			}
			continue
		}

		slog.Info("reconnected successfully", "attempt", attempt)
		m.notifyStatus(State{Reconnecting: false})
		m.mu.Lock()
		m.attempt = 0
		m.retryCancel = nil
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
