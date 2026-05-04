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
	wg        sync.WaitGroup
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
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		m.poll()
	}()
	slog.Info("WiFi monitor started")
}

// Stop stops the monitor and waits for the poll goroutine to exit.
// The wait matters: an in-flight onChanged callback that runs after
// the helper begins teardown can dereference the helper's
// userTunnelStore / manager fields after they've been niled. Joining
// the goroutine here removes that race.
func (m *Monitor) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	close(m.stopCh)
	m.mu.Unlock()
	m.wg.Wait()
}

// UpdateRules updates the auto-connect rules.
func (m *Monitor) UpdateRules(rules *Rules) {
	m.mu.Lock()
	m.rules = rules
	m.mu.Unlock()
}

// ReportExternalSSID is called when an external source (e.g. the GUI process
// on macOS, which holds Location Services permission) provides the current
// SSID. If it differs from the last known value, onChanged is triggered.
func (m *Monitor) ReportExternalSSID(ssid string) {
	m.mu.Lock()
	if ssid == m.lastSSID {
		m.mu.Unlock()
		return
	}
	old := m.lastSSID
	m.lastSSID = ssid
	m.mu.Unlock()
	slog.Info("WiFi SSID updated via GUI report", "from", old, "to", ssid)
	if m.onChanged != nil {
		m.onChanged(old, ssid)
	}
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
