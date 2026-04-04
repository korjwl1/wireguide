// Package reconnect handles automatic reconnection and dead connection detection.
package reconnect

import (
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
	if m.sleepDetector != nil {
		m.sleepDetector.Stop()
	}
	slog.Info("reconnect monitor stopped")
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

	// Check handshake timeout
	if !status.LastHandshake.IsZero() {
		age := time.Since(status.LastHandshake)
		if age > m.cfg.HandshakeTimeout {
			slog.Warn("dead connection detected",
				"tunnel", status.TunnelName,
				"handshake_age", age.Round(time.Second))
			m.triggerReconnect()
		}
	}
}

func (m *Monitor) triggerReconnect() {
	m.mu.Lock()
	m.attempt = 0
	m.mu.Unlock()

	go m.reconnectWithBackoff()
}

func (m *Monitor) reconnectWithBackoff() {
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

		select {
		case <-m.stopCh:
			return
		case <-time.After(delay):
		}

		// Disconnect first (ignore errors — might already be disconnected)
		m.manager.Disconnect()

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
