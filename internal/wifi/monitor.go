package wifi

import (
	"log/slog"
	"sync"
	"time"
)

// SSIDChangedFunc is called when the WiFi SSID changes.
type SSIDChangedFunc func(oldSSID, newSSID string)

// Monitor watches for WiFi SSID changes and triggers actions.
type Monitor struct {
	mu        sync.Mutex
	rules     *Rules
	onChanged SSIDChangedFunc
	lastSSID  string
	stopCh    chan struct{}
	running   bool
}

// NewMonitor creates a WiFi monitor.
func NewMonitor(rules *Rules, onChanged SSIDChangedFunc) *Monitor {
	return &Monitor{
		rules:     rules,
		onChanged: onChanged,
		stopCh:    make(chan struct{}),
	}
}

// Start begins monitoring WiFi SSID changes. Safe to call multiple times;
// subsequent calls are no-ops while the monitor is already running.
func (m *Monitor) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()
	go m.poll()
	slog.Info("WiFi monitor started")
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
}

// UpdateRules updates the auto-connect rules.
func (m *Monitor) UpdateRules(rules *Rules) {
	m.mu.Lock()
	m.rules = rules
	m.mu.Unlock()
}

func (m *Monitor) poll() {
	m.mu.Lock()
	m.lastSSID = CurrentSSID()
	m.mu.Unlock()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			current := CurrentSSID()
			m.mu.Lock()
			if current != m.lastSSID {
				slog.Info("WiFi SSID changed", "from", m.lastSSID, "to", current)
				old := m.lastSSID
				m.lastSSID = current
				m.mu.Unlock()
				if m.onChanged != nil {
					m.onChanged(old, current)
				}
			} else {
				m.mu.Unlock()
			}
		}
	}
}
