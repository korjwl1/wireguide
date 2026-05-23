package tunnel

import "fmt"

// SetPinInterface enables or disables -ifscope bypass route pinning on macOS.
// The setting is stored on the Manager and propagated to every active
// tunnel's NetworkManager, as well as any future tunnels created via Connect.
//
// Returns an error when there are active tunnels and NONE of their
// NetworkManagers implement the setting — this happens on Linux/Windows where
// the toggle is not meaningful. Callers (and through them, the GUI) should
// see a real "not supported" rather than silent success.
//
// With zero active tunnels, returns nil — the new value is stored and will
// apply at the next Connect, which is the correct behaviour on any platform.
func (m *Manager) SetPinInterface(enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pinInterface = enabled

	var active, applied int
	for _, e := range m.tunnels {
		if e.netMgr == nil {
			continue
		}
		active++
		if dm, ok := e.netMgr.(interface{ SetPinInterface(bool) }); ok {
			dm.SetPinInterface(enabled)
			applied++
		}
	}
	if active > 0 && applied == 0 {
		return fmt.Errorf("SetPinInterface not supported on this platform's NetworkManager")
	}
	return nil
}
