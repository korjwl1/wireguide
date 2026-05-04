//go:build !darwin

package helper

// Non-darwin stubs. The Wi-Fi rules feature is currently
// macOS-only — Linux/Windows will fall through these no-ops and the
// helper just broadcasts the SSID change for any GUI listeners.

func deriveUserAppSupport(uid int) (string, error) {
	return "", nil
}

func (h *Helper) handleSSIDChange(oldSSID, newSSID string) {}
