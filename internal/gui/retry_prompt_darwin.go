//go:build darwin

package gui

import (
	"os/exec"
	"strings"
)

// askHelperRetry shows a native Retry/Quit dialog when the helper
// connection fails. Uses osascript because the Wails app isn't running
// yet at this point in startup. Returns true if the user chose Retry.
func askHelperRetry() bool {
	retryCmd := `display dialog "WireGuide needs its helper service to manage VPN connections.\n\nPlease grant administrator access when prompted." buttons {"Quit", "Retry"} default button "Retry" with title "WireGuide" with icon caution`
	out, err := exec.Command("osascript", "-e", retryCmd).Output()
	if err != nil || strings.Contains(string(out), "Quit") {
		return false
	}
	return true
}
