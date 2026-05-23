package wifi

import (
	"log/slog"
	"sync"
	"time"
)

// SSIDChangedFunc is called when the WiFi SSID changes.
type SSIDChangedFunc func(oldSSID, newSSID string)

// Monitor watches for WiFi SSID changes and triggers actions.
//
// Note: rule evaluation lives entirely in the helper (see
// internal/helper/wifi_rules.go) — Monitor only fires the onChanged
// callback. The previous design embedded a *Rules pointer + UpdateRules
// setter here, but no caller ever read m.rules; it was set once with
// nil and never used. Removed to simplify the API.
type Monitor struct {
	mu              sync.Mutex
	onChanged       SSIDChangedFunc
	lastSSID        string
	stopCh          chan struct{}
	running         bool
	wg              sync.WaitGroup
	stopDBusWatcher func() // populated on Linux when NM DBus is reachable
}

// NewMonitor creates a WiFi monitor.
func NewMonitor(onChanged SSIDChangedFunc) *Monitor {
	return &Monitor{
		onChanged: onChanged,
		stopCh:    make(chan struct{}),
	}
}

// Start begins monitoring WiFi SSID changes. Safe to call multiple times;
// subsequent calls are no-ops while the monitor is already running.
//
// Uses polling (5 s tick) — intentional. The helper process runs as a
// root daemon with no main runloop, which means CoreWLAN's event
// delegate (CWEventDelegate) would deadlock on the dispatch_sync(main)
// inside cwStartSSIDMonitor. The event-driven path is used only by the
// GUI process (gui/ssid_reporter.go), which has a Cocoa main runloop
// via Wails. The helper relies on the GUI's ReportExternalSSID anyway
// when the GUI is connected; the 5 s poll is just a fallback.
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

	// Linux-only: wake the poller immediately on NetworkManager
	// DeviceStateChanged so users see SSID transitions react in <1s instead
	// of waiting for the 5s tick. No-op on non-Linux.
	stopDBus := startLinuxDBusWatcher(func() { m.checkNow() })
	// Windows-only: Wlanapi notifications for instant SSID react. No-op on
	// other platforms.
	stopWlan := startWindowsWlanWatcher(func() { m.checkNow() })
	m.stopDBusWatcher = func() {
		if stopDBus != nil {
			stopDBus()
		}
		if stopWlan != nil {
			stopWlan()
		}
	}

	slog.Info("WiFi monitor started (polling)")
}

// checkNow forces an immediate SSID re-read outside the 5s tick. Used by the
// Linux NetworkManager DBus watcher.
func (m *Monitor) checkNow() {
	current := CurrentSSID()
	m.mu.Lock()
	if current == m.lastSSID {
		m.mu.Unlock()
		return
	}
	old := m.lastSSID
	m.lastSSID = current
	m.mu.Unlock()
	slog.Info("WiFi SSID changed (NM event)", "from", old, "to", current)
	if m.onChanged != nil {
		m.onChanged(old, current)
	}
}

// Stop stops the monitor and waits for the poll goroutine to exit.
// The wait matters: an in-flight onChanged callback that runs after the
// helper begins teardown can dereference the helper's userTunnelStore /
// manager fields after they've been niled.
func (m *Monitor) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	close(m.stopCh)
	stopDBus := m.stopDBusWatcher
	m.stopDBusWatcher = nil
	m.mu.Unlock()
	if stopDBus != nil {
		stopDBus()
	}
	m.wg.Wait()
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
