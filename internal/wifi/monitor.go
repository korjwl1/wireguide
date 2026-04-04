package wifi

import (
	"log/slog"
	"time"
)

// SSIDChangedFunc is called when the WiFi SSID changes.
type SSIDChangedFunc func(oldSSID, newSSID string)

// Monitor watches for WiFi SSID changes and triggers actions.
type Monitor struct {
	rules     *Rules
	onChanged SSIDChangedFunc
	lastSSID  string
	stopCh    chan struct{}
}

// NewMonitor creates a WiFi monitor.
func NewMonitor(rules *Rules, onChanged SSIDChangedFunc) *Monitor {
	return &Monitor{
		rules:     rules,
		onChanged: onChanged,
		stopCh:    make(chan struct{}),
	}
}

// Start begins monitoring WiFi SSID changes.
func (m *Monitor) Start() {
	go m.poll()
	slog.Info("WiFi monitor started")
}

// Stop stops the monitor.
func (m *Monitor) Stop() {
	select {
	case <-m.stopCh:
	default:
		close(m.stopCh)
	}
}

// UpdateRules updates the auto-connect rules.
func (m *Monitor) UpdateRules(rules *Rules) {
	m.rules = rules
}

func (m *Monitor) poll() {
	m.lastSSID = CurrentSSID()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			current := CurrentSSID()
			if current != m.lastSSID {
				slog.Info("WiFi SSID changed", "from", m.lastSSID, "to", current)
				old := m.lastSSID
				m.lastSSID = current
				if m.onChanged != nil {
					m.onChanged(old, current)
				}
			}
		}
	}
}
